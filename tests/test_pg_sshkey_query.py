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


if __name__ == "__main__":
    unittest.main(verbosity=2)
