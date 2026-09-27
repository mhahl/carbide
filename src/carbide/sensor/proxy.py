"""Channel bridge: attacker shell/exec channels run against the container
over an asyncssh client session, with every byte recorded.
"""
import asyncio
import logging

import asyncssh

from .scp import ScpCarver

log = logging.getLogger("carbide.sensor.proxy")


def scp_direction(command: str | None) -> str | None:
    """Return "up" for ``scp -t`` (attacker uploading), "down" for ``scp -f``,
    else None."""
    if not command:
        return None
    parts = command.split()
    if not parts or parts[0] not in ("scp", "/usr/bin/scp", "/bin/scp"):
        return None
    if "-t" in parts:
        return "up"
    if "-f" in parts:
        return "down"
    return None


def scp_target(command: str | None) -> str | None:
    """Best-effort ``scp -t/-f`` target path (last non-flag argument)."""
    if not command:
        return None
    parts = command.split()
    if not parts or parts[0] not in ("scp", "/usr/bin/scp", "/bin/scp"):
        return None
    args = [p for p in parts[1:] if not p.startswith("-")]
    return args[-1] if args else None


def scp_evidence_names(prefix: str, target: str | None,
                       files: list[tuple[str, bytes]],
                       saw_dirs: bool) -> list[tuple[str, bytes]]:
    """Name carved files by their container destination.

    The sink protocol only carries basenames, so the ``scp -t/-f`` target
    from the exec command disambiguates: a trailing slash means directory,
    a lone file with no directories means the target itself. A bare
    directory path without trailing slash is indistinguishable from a file
    target; the full command stays in the meta transcript either way.
    """
    if target and target.endswith("/"):
        return [(f"{prefix}:{target}{name}", blob) for name, blob in files]
    if target and len(files) == 1 and not saw_dirs:
        return [(f"{prefix}:{target}", files[0][1])]
    if target:
        return [(f"{prefix}:{target}/{name}", blob)
                for name, blob in files]
    return [(f"{prefix}:{name}", blob) for name, blob in files]


async def bridge_shell_exec(stdin, stdout, stderr, *, container_client,
                            recorder, label: str, touch,
                            scp_max_bytes: int):
    """Bridge one attacker shell/exec channel to the container."""
    chan = stdin.channel
    command = chan.get_command()
    env = dict(chan.get_environment() or {})
    recorder.transcript(label, "meta", "command",
                        (command if command is not None
                         else "<shell>").encode("utf-8", "replace"))
    kwargs: dict = {}
    term_type = chan.get_terminal_type()
    if term_type:
        kwargs["term_type"] = term_type
        try:
            size = chan.get_terminal_size()
            kwargs["term_size"] = (size[0], size[1])
        except Exception:
            pass
    if env:
        kwargs["env"] = env
    if command:
        up = await container_client.create_process(command, **kwargs)
    else:
        up = await container_client.create_process(**kwargs)

    direction = scp_direction(command)
    up_carver = ScpCarver(scp_max_bytes) if direction == "up" else None
    down_carver = ScpCarver(scp_max_bytes) if direction == "down" else None
    # Buffer carves: final names need the whole stream (single file to a
    # bare target lands AT the target, not under it).
    up_files: list[tuple[str, bytes]] = []
    down_files: list[tuple[str, bytes]] = []

    async def pump_in():
        try:
            while True:
                try:
                    data = await stdin.read(65536)
                except asyncssh.TerminalSizeChanged as exc:
                    try:
                        up.change_terminal_size(exc.width, exc.height,
                                                exc.pixwidth, exc.pixheight)
                    except Exception:
                        pass
                    continue
                except asyncssh.SignalReceived as exc:
                    try:
                        up.send_signal(exc.signal)
                    except Exception:
                        pass
                    continue
                except asyncssh.BreakReceived as exc:
                    try:
                        up.send_break(exc.msec)
                    except Exception:
                        pass
                    continue
                if not data:
                    try:
                        up.stdin.write_eof()
                    except Exception:
                        pass
                    return
                touch()
                recorder.transcript(label, "in", "stdin", bytes(data))
                if up_carver is not None:
                    up_files.extend(up_carver.feed(bytes(data)))
                up.stdin.write(data)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            log.debug("pump_in ended: %s", exc)

    async def pump_out(reader, writer, stream, carver, sink):
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    return
                touch()
                blob = bytes(data)
                recorder.transcript(label, "out", stream, blob)
                if carver is not None and sink is not None:
                    sink.extend(carver.feed(blob))
                writer.write(blob)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            log.debug("pump_out(%s) ended: %s", stream, exc)

    tasks = [
        asyncio.create_task(pump_in()),
        asyncio.create_task(pump_out(up.stdout, stdout, "stdout",
                                     down_carver, down_files)),
        asyncio.create_task(pump_out(up.stderr, stderr, "stderr",
                                     None, None)),
    ]
    try:
        await up.wait()
    except Exception as exc:
        log.debug("upstream wait ended: %s", exc)
    finally:
        for task in tasks:
            task.cancel()
    target = scp_target(command)
    for prefix, carver, files in (("scp-upload", up_carver, up_files),
                                  ("scp-download", down_carver,
                                   down_files)):
        if carver is None:
            continue
        for name, blob in scp_evidence_names(prefix, target, files,
                                             carver.saw_dirs):
            recorder.evidence(name, blob)
        raw = carver.flush_raw()
        if raw:
            recorder.evidence(f"{prefix}-raw", raw)
    try:
        code = up.exit_status
    except Exception:
        code = None
    try:
        chan.exit(code if isinstance(code, int) else 0)
    except Exception:
        pass
