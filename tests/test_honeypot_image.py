"""Static guardrails for image/ (honeypot container definition).

The live suite (test_live.py, gated behind CARBIDE_LIVE_TESTS) builds and
boots this image; these tests pin the persona contract cheaply: UBI base,
sshd + httpd + mariadb present, seeded dumps, and working mysql creds in
the honey .my.cnf that agree with the seed SQL.
"""
import os
import re
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGE = os.path.join(ROOT, "image")

requires_sh = unittest.skipUnless(shutil.which("sh") is not None,
                                  "sh not installed")


def read(*parts):
    with open(os.path.join(IMAGE, *parts)) as fh:
        return fh.read()


class HoneypotImageTest(unittest.TestCase):
    def test_base_and_packages(self):
        body = read("Containerfile")
        self.assertIn("FROM registry.access.redhat.com/ubi9/ubi", body)
        for pkg in ("openssh-server", "openssh-clients", "httpd",
                    "mysql-community-server", "mysql-community-client",
                    "curl"):
            self.assertIn(pkg, body)
        self.assertIn("repo.mysql.com", body)
        self.assertNotIn("alpine", body.lower())
        self.assertNotIn("Ubuntu", body)

    def test_persona_and_users(self):
        body = read("Containerfile")
        self.assertIn("useradd -m -s /bin/bash honey", body)
        self.assertIn("PermitRootLogin no", body)
        self.assertIn("Red Hat Enterprise Linux 9", body)

    @requires_sh
    def test_entrypoint_parses(self):
        proc = subprocess.run(
            ["sh", "-n", os.path.join(IMAGE, "entrypoint.sh")],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_entrypoint_services_and_ssh(self):
        body = read("entrypoint.sh")
        for snippet in ("ssh-keygen -A", "CARBIDE_PASSWORD", "SetEnv",
                        "httpd -k start", "initialize-insecure",
                        "/usr/sbin/mysqld --daemonize",
                        "mysql-init.sql", ".carbide-seeded",
                        "exec /usr/sbin/sshd -D -e"):
            self.assertIn(snippet, body)

    def test_dumps_look_real(self):
        wp = read("dumps", "wordpress-2026-08-30.sql")
        self.assertIn("CREATE TABLE `wp_users`", wp)
        self.assertIn("INSERT INTO `wp_users`", wp)
        self.assertIn("CREATE TABLE `wp_posts`", wp)
        shop = read("dumps", "shop-2026-09-01.sql")
        self.assertIn("CREATE TABLE `customers`", shop)
        self.assertIn("INSERT INTO `orders`", shop)
        for dump in (wp, shop):
            self.assertIn("MySQL dump 10.13", dump)
            self.assertNotIn("MariaDB", dump)
            self.assertNotRegex(dump, r"\b(bigint|int)\(\d+\)")

    def test_mysql_seed_and_mycnf_agree(self):
        init = read("mysql-init.sql")
        self.assertIn("CREATE DATABASE IF NOT EXISTS wordpress", init)
        self.assertIn("CREATE DATABASE IF NOT EXISTS shop", init)
        self.assertIn("CREATE USER IF NOT EXISTS 'wp_user'@'localhost'",
                      init)
        match = re.search(r"'wp_user'@'localhost' IDENTIFIED BY '([^']+)'",
                          init)
        self.assertIsNotNone(match)
        mycnf = read("dotfiles", ".my.cnf")
        self.assertIn("user = wp_user", mycnf)
        self.assertIn(f"password = {match.group(1)}", mycnf)

    def test_honey_dotfiles(self):
        history = read("dotfiles", ".bash_history")
        self.assertIn("mysqldump", history)
        self.assertIn("mysql -u wp_user", history)


if __name__ == "__main__":
    unittest.main()
