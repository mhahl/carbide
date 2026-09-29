"""Unit tests for carbide.common.util.bind_failure (no sockets needed)."""
import errno
import unittest

from carbide.common.util import BindError, bind_failure


def _err(num):
    return OSError(num, errno.errorcode.get(num, "error"))


class BindFailureTest(unittest.TestCase):
    def test_in_use(self):
        err = bind_failure("server API", "127.0.0.1", 8440,
                           _err(errno.EADDRINUSE))
        self.assertIsInstance(err, BindError)
        text = str(err)
        self.assertIn("cannot bind server API on 127.0.0.1:8440", text)
        self.assertIn("already in use", text)
        self.assertNotIn("sshd", text)

    def test_in_use_port_22_names_host_sshd(self):
        err = bind_failure("sensor SSH listener", "0.0.0.0", 22,
                           _err(errno.EADDRINUSE))
        self.assertIn("host's own sshd", str(err))

    def test_in_use_detected_from_message_without_errno(self):
        err = bind_failure("server API", "127.0.0.1", 8440,
                           OSError("Address already in use"))
        self.assertIn("already in use", str(err))

    def test_not_available(self):
        err = bind_failure("sensor SSH listener", "149.28.175.237", 22,
                           _err(errno.EADDRNOTAVAIL))
        text = str(err)
        self.assertIn("not an address on this machine", text)
        self.assertIn("0.0.0.0", text)

    def test_permission(self):
        err = bind_failure("sensor SSH listener", "0.0.0.0", 22,
                           _err(errno.EACCES))
        self.assertIn("need root", str(err))

    def test_asyncio_aggregate_without_errno(self):
        # loop.create_server drops the errno; both suspects are named.
        exc = OSError("could not bind on any address out of "
                      "[('149.28.175.237', 22)]")
        err = bind_failure("sensor SSH listener", "149.28.175.237", 22,
                           exc)
        text = str(err)
        self.assertIn("149.28.175.237", text)
        self.assertIn("port 22 is free", text)

    def test_errno_found_through_chain(self):
        exc = OSError("could not bind on any address out of "
                      "[('::', 8440, 0, 0)]")
        exc.__context__ = _err(errno.EADDRINUSE)
        err = bind_failure("server API", "::", 8440, exc)
        self.assertIn("already in use", str(err))

    def test_unknown_error_passes_detail_through(self):
        err = bind_failure("web console", "127.0.0.1", 8080,
                           OSError("something exotic"))
        text = str(err)
        self.assertIn("cannot bind web console on 127.0.0.1:8080", text)
        self.assertIn("something exotic", text)
