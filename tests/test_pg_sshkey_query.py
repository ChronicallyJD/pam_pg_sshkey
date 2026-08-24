"""
test_pg_sshkey_query.py

Black-box tests for pg_sshkey_query (src/pg_sshkey_query.py), run as a
subprocess the way a user runs it.  No PostgreSQL needed: every case stops
before or at the connection step.

Tests:
  - missing helper binaries → one clear "error:" line, no traceback, exit 1
  - non-numeric PGPORT       → clear error, no traceback
  - PGDATABASE is honoured like psql / pg_sshkey_connect
  - helpers are found beside the script when not on PATH
  - --cert FILE is forwarded to pg_sshkey_sign and the v3 token is accepted
  - pg_sshkey_connect --cert FILE does the same (stub psql captures PGPASSWORD)

Run:  python3 tests/test_pg_sshkey_query.py

SPDX-License-Identifier: MIT
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONNECT_SRC = ROOT / "src" / "pg_sshkey_connect"
SCRIPT_SRC = ROOT / "src" / "pg_sshkey_query.py"      # no binaries beside it
SCRIPT_BUILT = ROOT / "pg_sshkey_query"               # copied by `make`, beside the tools
NO_TOOLS_PATH = "/usr/bin:/bin"                        # helpers are never here


def run(script, *args, env_extra=None, path=NO_TOOLS_PATH):
    env = {"PATH": path, "HOME": os.environ.get("HOME", "/"), "USER": "tester"}
    env.update(env_extra or {})
    return subprocess.run([sys.executable, str(script), *args],
                          capture_output=True, text=True, env=env)


class TestErrorHandling(unittest.TestCase):

    def test_missing_helper_is_a_clean_error(self):
        # Supply a key file so the run gets past the key check and reaches
        # the helper lookup regardless of whether ~/.ssh/id_ed25519 exists.
        with tempfile.NamedTemporaryFile() as key:
            r = run(SCRIPT_SRC, "-U", "alice", "-i", key.name)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn("error:", r.stderr)
        self.assertIn("pg_sshkey_sign", r.stderr)      # v2 needs only the signer

    def test_non_numeric_pgport_is_a_clean_error(self):
        r = run(SCRIPT_SRC, "-U", "alice", env_extra={"PGPORT": "abc"})
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn("PGPORT", r.stderr)

    def test_pgdatabase_is_honoured(self):
        r = run(SCRIPT_SRC, "-U", "alice", "-v", env_extra={"PGDATABASE": "otherdb"})
        self.assertIn("database:      otherdb", r.stderr)

    def test_explicit_dbname_beats_pgdatabase(self):
        r = run(SCRIPT_SRC, "-U", "alice", "-v", "-d", "explicit", env_extra={"PGDATABASE": "otherdb"})
        self.assertIn("database:      explicit", r.stderr)


@unittest.skipUnless((ROOT / "pg_sshkey_challenge").exists() and SCRIPT_BUILT.exists(),
                     "run `make` first: built tools not found")
class TestHelperLookup(unittest.TestCase):

    def _key(self, td):
        key = Path(td) / "id_ed25519"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
        return key

    def test_v1_helpers_found_beside_script_when_not_on_path(self):
        with tempfile.TemporaryDirectory() as td:
            chal = Path(td) / "chal"; chal.mkdir(mode=0o1733)
            key = self._key(td)
            # port 1 on localhost: connection is refused instantly, so the run
            # proves challenge + sign happened and stops at connect.
            r = run(SCRIPT_BUILT, "--v1", "-U", "alice", "-h", "127.0.0.1", "-p", "1",
                    "-c", str(chal), "-i", str(key))
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertNotIn("Traceback", r.stderr)
            self.assertIn("error: Connection failed", r.stderr)
            nonces = [p for p in chal.iterdir() if len(p.name) == 64]
            self.assertEqual(len(nonces), 1, "pg_sshkey_challenge beside the script was not used")

    def test_v2_default_creates_no_nonce_and_reaches_connect(self):
        with tempfile.TemporaryDirectory() as td:
            chal = Path(td) / "chal"; chal.mkdir(mode=0o1733)
            key = self._key(td)
            r = run(SCRIPT_BUILT, "-U", "alice", "-h", "127.0.0.1", "-p", "1",
                    "-c", str(chal), "-i", str(key), "-v")
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertIn("error: Connection failed", r.stderr)
            self.assertNotIn("generating challenge", r.stderr)
            self.assertEqual(list(chal.iterdir()), [], "v2 must not create a server nonce")

    def test_cert_with_v1_is_refused_before_minting_a_nonce(self):
        with tempfile.TemporaryDirectory() as td:
            chal = Path(td) / "chal"; chal.mkdir(mode=0o1733)
            key = self._key(td)
            cert = Path(td) / "id-cert.pub"; cert.write_text("c")
            r = run(SCRIPT_BUILT, "-U", "alice", "--v1", "-c", str(chal),
                    "-i", str(key), "--cert", str(cert), "-v")
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertIn("--cert cannot be combined with --v1", r.stderr)
            self.assertEqual(list(chal.iterdir()), [], "a refused request must not mint a nonce")


# A pg_sshkey_sign stand-in: records its argv, prints a v3-shaped token.
STUB_SIGN = """#!/bin/sh
printf '%s\\n' "$@" > "$STUB_ARGV"
echo "1700000000:{nonce}:{sig}:{cert}"
"""
# A psql stand-in: records the password it inherited.
STUB_PSQL = """#!/bin/sh
printf '%s' "$PGPASSWORD" > "$STUB_PW"
"""
# The same, printing a 3-field v2 token (the agent tests do not pass --cert).
STUB_SIGN_V2 = """#!/bin/sh
printf '%s\\n' "$@" > "$STUB_ARGV"
echo "1700000000:{nonce}:{sig}"
"""
V3_NONCE = "ab" * 32
V3_SIG = "c2ln" * 22          # base64, no padding needed
V3_CERT = "Y2VydA" * 3 + "=="  # well-formed base64 (padding only at the end)


class TestCertOption(unittest.TestCase):
    """--cert FILE must reach pg_sshkey_sign as '--cert FILE' and the
    4-field v3 token it prints must pass the client's shape check."""

    def _bin(self, td, v2=False):
        b = Path(td) / "bin"; b.mkdir()
        sign = b / "pg_sshkey_sign"
        if v2:
            sign.write_text(STUB_SIGN_V2.format(nonce=V3_NONCE, sig=V3_SIG))
        else:
            sign.write_text(STUB_SIGN.format(nonce=V3_NONCE, sig=V3_SIG, cert=V3_CERT))
        sign.chmod(0o755)
        psql = b / "psql"
        psql.write_text(STUB_PSQL); psql.chmod(0o755)
        return b

    def test_query_forwards_cert_to_sign(self):
        with tempfile.TemporaryDirectory() as td:
            b = self._bin(td)
            key = Path(td) / "id_ed25519"; key.write_text("k")
            cert = Path(td) / "id_ed25519-cert.pub"; cert.write_text("c")
            argv = Path(td) / "argv"
            r = run(SCRIPT_SRC, "-U", "carol", "-h", "127.0.0.1", "-p", "1",
                    "-i", str(key), "--cert", str(cert), "-v",
                    path=f"{b}:{NO_TOOLS_PATH}", env_extra={"STUB_ARGV": str(argv)})
            self.assertNotIn("Traceback", r.stderr)
            self.assertNotIn("unrecognized arguments", r.stderr)
            self.assertTrue(argv.exists(), f"pg_sshkey_sign was not run: {r.stderr}")
            self.assertEqual(argv.read_text().split("\n")[:-1],
                             ["--cert", str(cert), str(key)])
            self.assertNotIn("invalid token", r.stderr)
            self.assertIn("error: Connection failed", r.stderr)
            self.assertIn(f"cert:          {cert}", r.stderr)

    def test_query_without_cert_does_not_pass_cert(self):
        with tempfile.TemporaryDirectory() as td:
            b = self._bin(td)
            key = Path(td) / "id_ed25519"; key.write_text("k")
            argv = Path(td) / "argv"
            r = run(SCRIPT_SRC, "-U", "carol", "-h", "127.0.0.1", "-p", "1",
                    "-i", str(key),
                    path=f"{b}:{NO_TOOLS_PATH}", env_extra={"STUB_ARGV": str(argv)})
            self.assertEqual(argv.read_text().split("\n")[:-1], [str(key)])
            # The stub prints a v3 token; without --cert the v2 shape is required.
            self.assertIn("invalid token", r.stderr)

    def test_query_forwards_agent_to_sign_without_a_key_path(self):
        with tempfile.TemporaryDirectory() as td:
            b = self._bin(td, v2=True)
            pub = Path(td) / "id_ed25519.pub"; pub.write_text("ssh-ed25519 AAAA c\n")
            argv = Path(td) / "argv"
            r = run(SCRIPT_SRC, "-U", "carol", "-h", "127.0.0.1", "-p", "1",
                    "--agent", str(pub), "-v",
                    path=f"{b}:{NO_TOOLS_PATH}", env_extra={"STUB_ARGV": str(argv)})
            self.assertNotIn("Traceback", r.stderr)
            self.assertTrue(argv.exists(), f"pg_sshkey_sign was not run: {r.stderr}")
            self.assertEqual(argv.read_text().split("\n")[:-1],
                             ["--agent", str(pub)])
            self.assertIn(f"key:           {pub} (ssh-agent)", r.stderr)

    def test_query_agent_with_v1_is_refused_before_minting_a_nonce(self):
        with tempfile.TemporaryDirectory() as td:
            b = self._bin(td, v2=True)
            chal = Path(td) / "chal"; chal.mkdir(mode=0o1733)
            pub = Path(td) / "id_ed25519.pub"; pub.write_text("ssh-ed25519 AAAA c\n")
            r = run(SCRIPT_SRC, "-U", "carol", "--v1", "-c", str(chal),
                    "--agent", str(pub), "-v", path=f"{b}:{NO_TOOLS_PATH}")
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertIn("--agent cannot be combined with --v1", r.stderr)
            self.assertEqual(list(chal.iterdir()), [])

    def test_connect_forwards_agent_to_sign_without_a_key_path(self):
        with tempfile.TemporaryDirectory() as td:
            b = self._bin(td, v2=True)
            pub = Path(td) / "id_ed25519.pub"; pub.write_text("ssh-ed25519 AAAA c\n")
            argv = Path(td) / "argv"; pw = Path(td) / "pw"
            env = {"PATH": f"{b}:{NO_TOOLS_PATH}", "HOME": td, "USER": "carol",
                   "STUB_ARGV": str(argv), "STUB_PW": str(pw)}
            r = subprocess.run(["bash", str(CONNECT_SRC), "--agent", str(pub), "-v"],
                               capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(argv.read_text().split("\n")[:-1], ["--agent", str(pub)])
            self.assertIn(f"key:           {pub} (ssh-agent)", r.stderr)

    def test_connect_agent_needs_no_private_key_file(self):
        """The default identity does not exist: only --agent makes this work."""
        with tempfile.TemporaryDirectory() as td:
            b = self._bin(td, v2=True)
            pub = Path(td) / "id_ed25519.pub"; pub.write_text("ssh-ed25519 AAAA c\n")
            env = {"PATH": f"{b}:{NO_TOOLS_PATH}", "HOME": td, "USER": "carol",
                   "STUB_ARGV": str(Path(td) / "argv"), "STUB_PW": str(Path(td) / "pw")}
            without = subprocess.run(["bash", str(CONNECT_SRC), "-v"],
                                     capture_output=True, text=True, env=env)
            self.assertEqual(without.returncode, 1)
            self.assertIn("SSH key not found", without.stderr)
            withagent = subprocess.run(["bash", str(CONNECT_SRC), "--agent", str(pub), "-v"],
                                       capture_output=True, text=True, env=env)
            self.assertEqual(withagent.returncode, 0, withagent.stderr)

    def test_agent_with_identity_is_refused_by_both_clients(self):
        """-i and --agent name two different keys: refuse rather than pick."""
        with tempfile.TemporaryDirectory() as td:
            b = self._bin(td, v2=True)
            key = Path(td) / "id_ed25519"; key.write_text("k")
            pub = Path(td) / "id_ed25519.pub"; pub.write_text("ssh-ed25519 AAAA c\n")
            r = run(SCRIPT_SRC, "-U", "carol", "-i", str(key), "--agent", str(pub),
                    path=f"{b}:{NO_TOOLS_PATH}")
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertIn("--agent replaces -i/--identity", r.stderr)
            env = {"PATH": f"{b}:{NO_TOOLS_PATH}", "HOME": td, "USER": "carol",
                   "STUB_ARGV": str(Path(td) / "argv"), "STUB_PW": str(Path(td) / "pw")}
            c = subprocess.run(["bash", str(CONNECT_SRC), "-i", str(key),
                                "--agent", str(pub)],
                               capture_output=True, text=True, env=env)
            self.assertEqual(c.returncode, 1, c.stderr)
            self.assertIn("--agent replaces -i/--identity", c.stderr)

    def test_connect_forwards_cert_to_sign(self):
        with tempfile.TemporaryDirectory() as td:
            b = self._bin(td)
            key = Path(td) / "id_ed25519"; key.write_text("k")
            cert = Path(td) / "id_ed25519-cert.pub"; cert.write_text("c")
            argv = Path(td) / "argv"; pw = Path(td) / "pw"
            env = {"PATH": f"{b}:{NO_TOOLS_PATH}", "HOME": td, "USER": "carol",
                   "STUB_ARGV": str(argv), "STUB_PW": str(pw)}
            r = subprocess.run(["bash", str(CONNECT_SRC), "-i", str(key),
                                "--cert", str(cert), "-v"],
                               capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(argv.read_text().split("\n")[:-1],
                             ["--cert", str(cert), str(key)])
            self.assertEqual(pw.read_text(),
                             f"1700000000:{V3_NONCE}:{V3_SIG}:{V3_CERT}")
            self.assertIn(f"cert:          {cert}", r.stderr)

    def test_connect_without_cert_rejects_v3_shape(self):
        with tempfile.TemporaryDirectory() as td:
            b = self._bin(td)
            key = Path(td) / "id_ed25519"; key.write_text("k")
            argv = Path(td) / "argv"; pw = Path(td) / "pw"
            env = {"PATH": f"{b}:{NO_TOOLS_PATH}", "HOME": td, "USER": "carol",
                   "STUB_ARGV": str(argv), "STUB_PW": str(pw)}
            r = subprocess.run(["bash", str(CONNECT_SRC), "-i", str(key)],
                               capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, 1)
            self.assertIn("Malformed token", r.stderr)
            self.assertEqual(argv.read_text().split("\n")[:-1], [str(key)])
            self.assertFalse(pw.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
