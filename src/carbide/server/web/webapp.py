"""Console web application: routes, templates, error handling, and the
aiohttp runner embedded in carbide-server's event loop.
"""
import asyncio
import datetime
import logging
import os

from aiohttp import web
from jinja2 import FileSystemLoader, select_autoescape

from ...common.util import bind_failure
from . import actions, views
from .sshmgmt import SensorManager

log = logging.getLogger("carbide.server.web")

HERE = os.path.dirname(os.path.abspath(__file__))


def _ts_filter(value):
    if isinstance(value, datetime.datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return value or "—"


def _short_filter(value):
    text = str(value or "")
    return text[:12] if len(text) > 12 else text


def _nl2br_filter(value):
    return str(value or "").replace("\n", "<br>")


def make_jinja():
    import jinja2
    env = jinja2.Environment(
        loader=FileSystemLoader(os.path.join(HERE, "templates")),
        autoescape=select_autoescape(["html"]))
    env.filters["ts"] = _ts_filter
    env.filters["short"] = _short_filter
    env.filters["nl2br"] = _nl2br_filter
    return env


@web.middleware
async def errors_middleware(request, handler):
    try:
        return await handler(request)
    except web.HTTPException:
        raise
    except Exception as exc:
        log.exception("console handler %s failed", request.path)
        if request.headers.get("HX-Request"):
            return web.Response(status=200, text=(
                '<div class="alert alert-error">'
                f"<span>error: {exc}</span></div>"))
        return views.render(
            request, "error.html", {"message": str(exc)}, status=500)


def create_app(deps: dict) -> web.Application:
    """deps: cfg, db, pool, pod, blobs, api, forensics, eviction, bus,
    logring."""
    app = web.Application(middlewares=[errors_middleware])
    app.update(deps)
    app["jinja"] = make_jinja()
    app["mgmt"] = SensorManager(
        deps["cfg"], deps["cfg"].get("server.sensor_token", ""))
    app["provisions"] = {}
    app.router.add_get("/login", views.login_get)
    app.router.add_post("/login", views.login_post)
    app.router.add_get("/logout", views.logout)
    app.router.add_get("/", views.dashboard)
    app.router.add_get("/sessions", views.sessions_list)
    app.router.add_get("/sessions/{id}", views.session_detail)
    app.router.add_get("/sessions/{id}/transcript",
                       views.transcript_fragment)
    app.router.add_get("/files/{sha}/download", views.file_download)
    app.router.add_get("/snapshots", views.snapshots_list)
    app.router.add_get("/compare", views.compare)
    app.router.add_get("/auth", views.auth_view)
    app.router.add_get("/podman", views.podman_view)
    app.router.add_get("/podman/containers/{id}", views.container_detail)
    app.router.add_get("/podman/containers/{id}/diff",
                       views.container_diff)
    app.router.add_get("/podman/containers/{id}/file",
                       views.container_file)
    app.router.add_get("/sensors", views.sensors_list)
    app.router.add_get("/sensors/new", views.sensor_new)
    app.router.add_get("/sensors/{id}", views.sensor_detail)
    app.router.add_get("/logs", views.logs_view)
    app.router.add_get("/users", views.users_view)
    app.router.add_get("/fragments/containers", views.frag_containers)
    app.router.add_get("/fragments/sensors", views.frag_sensors)
    app.router.add_get("/fragments/recent-sessions",
                       views.frag_recent_sessions)
    app.router.add_get("/fragments/provision/{pid}",
                       views.frag_provision)
    app.router.add_get("/events/stream", views.events_stream)
    app.router.add_get("/logs/stream", views.logs_stream)
    app.router.add_post("/actions/containers/{id}/{op}",
                        actions.container_action)
    app.router.add_post("/actions/affinities/evict",
                        actions.affinity_evict)
    app.router.add_post("/actions/snapshots", actions.snapshot_now)
    app.router.add_post("/actions/sessions/{id}/kill",
                        actions.session_kill)
    app.router.add_post("/sensors/save", actions.sensor_save)
    app.router.add_post("/sensors/{id}/delete", actions.sensor_delete)
    app.router.add_post("/actions/sensors/{id}/push",
                        actions.sensor_push)
    app.router.add_post("/actions/sensors/{id}/restart",
                        actions.sensor_restart)
    app.router.add_post("/actions/sensors/{id}/provision",
                        actions.sensor_provision)
    app.router.add_post("/users/create", actions.user_create)
    app.router.add_post("/users/{id}/disable", actions.user_disable)
    app.router.add_post("/users/{id}/enable", actions.user_enable)
    app.router.add_post("/users/{id}/password", actions.user_password)
    app.router.add_static("/static",
                          os.path.join(HERE, "static"),
                          name="static")
    return app


class WebConsole:
    """Owns the aiohttp runner lifecycle inside ServerApp.run."""

    def __init__(self, app: web.Application, cfg):
        self._app = app
        wcfg = cfg.section("web")
        self._addr = wcfg["bind_addr"]
        self._port = wcfg["port"]
        self._runner = None

    async def run(self):
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self._addr, self._port)
        try:
            await site.start()
        except OSError as exc:
            raise bind_failure("web console", self._addr, self._port, exc)
        log.info("console on http://%s:%s", self._addr, self._port)
        try:
            await asyncio.Event().wait()
        finally:
            await self._runner.cleanup()
