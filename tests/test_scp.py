import unittest

from carbide.sensor.proxy import scp_evidence_names, scp_target
from carbide.sensor.scp import ScpCarver


class ScpCarverTest(unittest.TestCase):
    def test_single_file(self):
        c = ScpCarver()
        files = c.feed(b"C0644 12 hello.txt\nhello world")
        self.assertEqual(files, [])
        files = c.feed(b"!")
        self.assertEqual(files, [("hello.txt", b"hello world!")])

    def test_times_line_skipped(self):
        c = ScpCarver()
        files = c.feed(b"T123 0 456 0\nC0600 3 f\nabc")
        self.assertEqual(files, [("f", b"abc")])

    def test_directory(self):
        c = ScpCarver()
        files = c.feed(b"D0755 0 sub\nC0644 2 a\nxy\nE\nC0644 1 b\nz")
        self.assertEqual(files, [("sub/a", b"xy"), ("b", b"z")])

    def test_multiple_files(self):
        c = ScpCarver()
        out = c.feed(b"C0644 1 a\n1C0644 1 b\n2")
        self.assertEqual(out, [("a", b"1"), ("b", b"2")])

    def test_empty_file(self):
        c = ScpCarver()
        self.assertEqual(c.feed(b"C0644 0 e\n"), [("e", b"")])

    def test_flush_raw_keeps_unparsed(self):
        c = ScpCarver()
        self.assertEqual(c.feed(b"garbage without newline"), [])
        self.assertEqual(c.flush_raw(), b"garbage without newline")


class ScpNamingTest(unittest.TestCase):
    def test_target_parsing(self):
        self.assertEqual(scp_target("scp -t /tmp/x"), "/tmp/x")
        self.assertEqual(scp_target("/usr/bin/scp -q -t /tmp/"), "/tmp/")
        self.assertEqual(scp_target("scp -f /etc/passwd"), "/etc/passwd")
        self.assertIsNone(scp_target("scp -t"))
        self.assertIsNone(scp_target("echo hi"))
        self.assertIsNone(scp_target(None))

    def test_lone_file_lands_at_bare_target(self):
        out = scp_evidence_names("scp-upload", "/tmp/via-scp.bin",
                                 [("scp.bin", b"data")], False)
        self.assertEqual(out, [("scp-upload:/tmp/via-scp.bin", b"data")])

    def test_dir_target_prefixes(self):
        out = scp_evidence_names("scp-upload", "/tmp/",
                                 [("a", b"1"), ("b", b"2")], False)
        self.assertEqual(out, [("scp-upload:/tmp/a", b"1"),
                               ("scp-upload:/tmp/b", b"2")])

    def test_multi_file_bare_target_joined(self):
        out = scp_evidence_names("scp-upload", "/tmp",
                                 [("a", b"1"), ("b", b"2")], False)
        self.assertEqual(out, [("scp-upload:/tmp/a", b"1"),
                               ("scp-upload:/tmp/b", b"2")])

    def test_no_target_keeps_basename(self):
        out = scp_evidence_names("scp-upload", None,
                                 [("a", b"1")], False)
        self.assertEqual(out, [("scp-upload:a", b"1")])


if __name__ == "__main__":
    unittest.main()
