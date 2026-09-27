"""SFTP forwarder tests: double-hop through real asyncssh servers/clients
(backing server -> ForwardingSFTPServer -> downloading client), no
containers needed.
"""
import os
import tempfile
import unittest

import asyncssh

from carbide.sensor.sftp_forward import ForwardingSFTPServer


class Accept(asyncssh.SSHServer):
    def password_auth_supported(self):
        return True

    def validate_password(self, user, pw):
        return True


class SftpForwardTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        with open(os.path.join(self.tmp.name, "f.txt"), "wb") as fh:
            fh.write(b"0123456789")
        key = asyncssh.generate_private_key("ssh-ed25519")
        self.keypath = os.path.join(self.tmp.name, "hk")
        key.write_private_key(self.keypath)
        self.evidence = {}
        self.ops = []
        self.servers = []
        self.conns = []

    async def asyncTearDown(self):
        for conn in self.conns:
            conn.close()
        for server in self.servers:
            server.close()

    async def _backing(self):
        os.chdir(self.tmp.name)
        server = await asyncssh.create_server(
            Accept, "127.0.0.1", 0, server_host_keys=[self.keypath],
            sftp_factory=True, encoding=None)
        self.servers.append(server)
        port = server.sockets[0].getsockname()[1]
        conn = await asyncssh.connect(
            "127.0.0.1", port, username="u", password="p",
            known_hosts=None, encoding=None)
        self.conns.append(conn)
        return await conn.start_sftp_client()

    async def _front(self, bsftp):
        def factory(chan):
            return ForwardingSFTPServer(
                chan, bsftp, self.evidence.__setitem__,
                self.ops.append)

        server = await asyncssh.create_server(
            Accept, "127.0.0.1", 0, server_host_keys=[self.keypath],
            sftp_factory=factory, encoding=None)
        self.servers.append(server)
        port = server.sockets[0].getsockname()[1]
        conn = await asyncssh.connect(
            "127.0.0.1", port, username="u", password="p",
            known_hosts=None, encoding=None)
        self.conns.append(conn)
        return conn

    async def test_get_passthrough_and_evidence(self):
        conn = await self._front(await self._backing())
        async with conn.start_sftp_client() as sftp:
            dest = os.path.join(self.tmp.name, "out.txt")
            await sftp.get("f.txt", dest)
            with open(dest, "rb") as fh:
                self.assertEqual(fh.read(), b"0123456789")
        self.assertEqual(self.evidence.get("sftp-download:f.txt"),
                         b"0123456789")

    async def test_put_passthrough_and_evidence(self):
        conn = await self._front(await self._backing())
        src = os.path.join(self.tmp.name, "up.txt")
        with open(src, "wb") as fh:
            fh.write(b"up-bytes")
        async with conn.start_sftp_client() as sftp:
            await sftp.put(src, "g.txt")
        with open(os.path.join(self.tmp.name, "g.txt"), "rb") as fh:
            self.assertEqual(fh.read(), b"up-bytes")
        self.assertEqual(self.evidence.get("sftp-upload:g.txt"),
                         b"up-bytes")

    async def test_misc_ops_forward(self):
        conn = await self._front(await self._backing())
        async with conn.start_sftp_client() as sftp:
            listed = [n async for n in sftp.scandir(".")]
            self.assertIn("f.txt", [n.filename for n in listed])
            await sftp.mkdir("sub")
            await sftp.rename("f.txt", "sub/f2.txt")
            self.assertTrue(await sftp.exists("sub/f2.txt"))
            await sftp.remove("sub/f2.txt")
            await sftp.rmdir("sub")
        self.assertTrue(any("mkdir" in op for op in self.ops))


if __name__ == "__main__":
    unittest.main()
