"""
test_python_module.py

Unit tests for pam_pg_sshkey.py.

Tests:
  - get_token() with OpenSSH Ed25519 key
  - get_token() with PKCS#8 Ed25519 key
  - get_token() with PKCS#8 RSA-2048 key
  - get_token() with passphrase-protected key
  - Token format validation (64hex:base64)
  - Token hex portion matches nonce file in challenge dir
  - Two calls produce two different tokens
  - Nonce file exists on disk before authentication
  - Nonce file is readable (mode 0644)
  - Missing key raises KeyError_
  - Unwritable challenge dir raises ChallengeError
  - passing password= to connect() raises ValueError
  - SIGN_PREFIX is exactly b"pg-sshkey-v1\\x00" (13 bytes)
  - Signed message matches what the PAM module verifies

Run:
    python3 -m pytest tests/test_python_module.py -v
    # or without pytest:
    python3 tests/test_python_module.py

SPDX-License-Identifier: MIT
"""

import base64
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

# Allow running from the tests/ directory or the project root
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pam_pg_sshkey
from pam_pg_sshkey import (
    ChallengeError,
    KeyError_,
    _SIGN_PREFIX,
    _SIGN_PREFIX_V2,
    _create_challenge,
    _load_private_key,
    _sign,
    connect_replication,
    get_token,
)

try:
    import psycopg2  # noqa: F401
    HAVE_PSYCOPG2 = True
except ImportError:
    HAVE_PSYCOPG2 = False

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
)

# Passphrase-protected OpenSSH keys use the bcrypt KDF; `cryptography` needs
# the optional `bcrypt` package to read or write them.  Skip (never error)
# those tests when it is absent so the suite result is honest everywhere.
try:
    import bcrypt  # noqa: F401
    HAVE_BCRYPT = True
except ImportError:
    HAVE_BCRYPT = False

needs_bcrypt = unittest.skipUnless(
    HAVE_BCRYPT, "bcrypt not installed (pip install bcrypt / apt install python3-bcrypt)"
)


# ── Helpers ────────────────────────────────────────────────────────────────────

TOKEN_RE = re.compile(r"^[0-9a-f]{64}:[A-Za-z0-9+/]+=*$")
TOKEN_V2_RE = re.compile(r"^[0-9]+:[0-9a-f]{64}:[A-Za-z0-9+/]+=*$")


def _is_valid_token(token: str) -> bool:
    """v1 or v2 shape"""
    return bool(TOKEN_RE.match(token) or TOKEN_V2_RE.match(token))


class TempDir:
    """Context manager providing a fresh temp directory and challenge subdir."""

    def __enter__(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = self._td.name
        self.chaldir = os.path.join(self.root, "challenges")
        os.makedirs(self.chaldir, mode=0o1733)
        return self

    def __exit__(self, *args):
        self._td.cleanup()

    def key_path(self, name: str) -> str:
        return os.path.join(self.root, name)

    def write_key(self, name: str, key_bytes: bytes) -> str:
        path = self.key_path(name)
        with open(path, "wb") as f:
            f.write(key_bytes)
        return path


def make_ed25519_openssh() -> bytes:
    sk = Ed25519PrivateKey.generate()
    return sk.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())


def make_ed25519_pkcs8() -> bytes:
    sk = Ed25519PrivateKey.generate()
    return sk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def make_rsa_pkcs8() -> bytes:
    sk = generate_private_key(65537, 2048)
    return sk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def make_ed25519_encrypted(passphrase: bytes) -> bytes:
    sk = Ed25519PrivateKey.generate()
    return sk.private_bytes(
        Encoding.PEM, PrivateFormat.OpenSSH, BestAvailableEncryption(passphrase)
    )


# ── Tests: _SIGN_PREFIX ────────────────────────────────────────────────────────

class TestSignPrefix(unittest.TestCase):

    def test_prefix_is_correct_bytes(self):
        """SIGN_PREFIX must be b'pg-sshkey-v1\\x00' (12 chars + NUL = 13 bytes)."""
        self.assertEqual(_SIGN_PREFIX, b"pg-sshkey-v1\x00")

    def test_prefix_length_is_13(self):
        self.assertEqual(len(_SIGN_PREFIX), 13)

    def test_prefix_ends_with_nul(self):
        self.assertEqual(_SIGN_PREFIX[-1], 0)


# ── Tests: _load_private_key ───────────────────────────────────────────────────

class TestLoadPrivateKey(unittest.TestCase):

    def test_load_openssh_ed25519(self):
        with TempDir() as d:
            path = d.write_key("id_ed25519", make_ed25519_openssh())
            key = _load_private_key(path, passphrase=None)
            self.assertIsInstance(key, Ed25519PrivateKey)

    def test_load_pkcs8_ed25519(self):
        with TempDir() as d:
            path = d.write_key("ed25519.pem", make_ed25519_pkcs8())
            key = _load_private_key(path, passphrase=None)
            self.assertIsInstance(key, Ed25519PrivateKey)

    def test_load_pkcs8_rsa(self):
        with TempDir() as d:
            path = d.write_key("rsa.pem", make_rsa_pkcs8())
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
            key = _load_private_key(path, passphrase=None)
            self.assertIsInstance(key, RSAPrivateKey)

    @needs_bcrypt
    def test_load_encrypted_with_passphrase(self):
        passphrase = b"correct horse battery staple"
        with TempDir() as d:
            path = d.write_key("encrypted", make_ed25519_encrypted(passphrase))
            key = _load_private_key(path, passphrase=passphrase)
            self.assertIsInstance(key, Ed25519PrivateKey)

    @needs_bcrypt
    def test_load_encrypted_wrong_passphrase_raises(self):
        with TempDir() as d:
            path = d.write_key("encrypted", make_ed25519_encrypted(b"correct"))
            with self.assertRaises(KeyError_):
                _load_private_key(path, passphrase=b"wrong")

    @needs_bcrypt
    def test_load_encrypted_no_passphrase_raises(self):
        with TempDir() as d:
            path = d.write_key("encrypted", make_ed25519_encrypted(b"secret"))
            with self.assertRaises(KeyError_):
                _load_private_key(path, passphrase=None)

    def test_missing_file_raises_keyerror(self):
        with self.assertRaises(KeyError_):
            _load_private_key("/tmp/no_such_key_pam_test.pem", passphrase=None)

    @unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen not installed")
    def test_real_passphrase_key_maps_every_failure_to_keyerror(self):
        """A genuine ssh-keygen passphrase key: loads with bcrypt, and without
        bcrypt the library's UnsupportedAlgorithm must surface as KeyError_
        naming bcrypt, never as a raw cryptography exception."""
        with TempDir() as d:
            path = d.key_path("enc_ed25519")
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "secret",
                            "-C", "t", "-f", path], check=True)
            if HAVE_BCRYPT:
                key = _load_private_key(path, passphrase=b"secret")
                self.assertIsInstance(key, Ed25519PrivateKey)
                with self.assertRaises(KeyError_):
                    _load_private_key(path, passphrase=b"wrong")
            else:
                with self.assertRaises(KeyError_) as ctx:
                    _load_private_key(path, passphrase=b"secret")
                self.assertIn("bcrypt", str(ctx.exception))

    def test_tilde_expansion(self):
        """Key paths starting with ~ must be expanded."""
        # We can't write to ~/ in tests, so just check it errors on missing,
        # not on tilde syntax.
        with self.assertRaises(KeyError_) as ctx:
            _load_private_key("~/no_such_pam_test_key.pem", passphrase=None)
        self.assertNotIn("~", str(ctx.exception).split("not found")[0].split(":")[-1])


# ── Tests: _create_challenge ───────────────────────────────────────────────────

class TestCreateChallenge(unittest.TestCase):

    def test_returns_hex64_and_32_bytes(self):
        with TempDir() as d:
            hex_id, raw = _create_challenge(d.chaldir)
            self.assertEqual(len(hex_id), 64)
            self.assertTrue(all(c in "0123456789abcdef" for c in hex_id))
            self.assertEqual(len(raw), 32)

    def test_hex_matches_raw_bytes(self):
        with TempDir() as d:
            hex_id, raw = _create_challenge(d.chaldir)
            self.assertEqual(hex_id, raw.hex())

    def test_creates_file_in_dir(self):
        with TempDir() as d:
            hex_id, _ = _create_challenge(d.chaldir)
            nonce_path = os.path.join(d.chaldir, hex_id)
            self.assertTrue(os.path.exists(nonce_path))

    def test_file_mode_is_0644(self):
        with TempDir() as d:
            hex_id, _ = _create_challenge(d.chaldir)
            nonce_path = os.path.join(d.chaldir, hex_id)
            mode = oct(os.stat(nonce_path).st_mode & 0o777)
            self.assertEqual(mode, oct(0o644))

    def test_file_mode_is_0644_under_umask_077(self):
        """Restrictive umask (systemd/cron) must not hide the nonce from postgres."""
        old = os.umask(0o077)
        try:
            with TempDir() as d:
                hex_id, _ = _create_challenge(d.chaldir)
                nonce_path = os.path.join(d.chaldir, hex_id)
                mode = oct(os.stat(nonce_path).st_mode & 0o777)
        finally:
            os.umask(old)
        self.assertEqual(mode, oct(0o644))

    def test_successive_challenges_are_unique(self):
        with TempDir() as d:
            h1, r1 = _create_challenge(d.chaldir)
            h2, r2 = _create_challenge(d.chaldir)
            self.assertNotEqual(h1, h2)
            self.assertNotEqual(r1, r2)

    def test_unwritable_dir_raises_challenge_error(self):
        with self.assertRaises(ChallengeError):
            _create_challenge("/proc/1/pam_test_bad_dir")

    def test_autocreates_missing_dir(self):
        with tempfile.TemporaryDirectory() as root:
            newdir = os.path.join(root, "new_chal_dir")
            self.assertFalse(os.path.exists(newdir))
            hex_id, _ = _create_challenge(newdir)
            self.assertTrue(os.path.exists(newdir))
            self.assertTrue(os.path.exists(os.path.join(newdir, hex_id)))


# ── Tests: _sign ──────────────────────────────────────────────────────────────

class TestSign(unittest.TestCase):

    def _make_ed25519(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.generate()

    def test_ed25519_signature_length_is_64(self):
        key = self._make_ed25519()
        sig = _sign(key, b"\x01" * 32)
        self.assertEqual(len(sig), 64)

    def test_ed25519_signature_verifies(self):
        import secrets
        key = self._make_ed25519()
        challenge = secrets.token_bytes(32)
        sig = _sign(key, challenge)
        # Verify using the public key
        key.public_key().verify(sig, _SIGN_PREFIX + challenge)

    def test_rsa_signature_verifies(self):
        import secrets
        from cryptography.hazmat.primitives.asymmetric import padding as p
        from cryptography.hazmat.primitives import hashes as h
        key = generate_private_key(65537, 2048)
        challenge = secrets.token_bytes(32)
        sig = _sign(key, challenge)
        key.public_key().verify(sig, _SIGN_PREFIX + challenge, p.PKCS1v15(), h.SHA256())

    def test_different_challenges_produce_different_sigs(self):
        import secrets
        key = self._make_ed25519()
        sig1 = _sign(key, secrets.token_bytes(32))
        sig2 = _sign(key, secrets.token_bytes(32))
        self.assertNotEqual(sig1, sig2)


# ── Tests: get_token ──────────────────────────────────────────────────────────

class TestGetToken(unittest.TestCase):

    def test_openssh_ed25519_returns_valid_token(self):
        with TempDir() as d:
            path = d.write_key("id_ed25519", make_ed25519_openssh())
            token = get_token(key_path=path, challenge_dir=d.chaldir)
            self.assertTrue(_is_valid_token(token), f"invalid token: {token!r}")

    def test_pkcs8_ed25519_returns_valid_token(self):
        with TempDir() as d:
            path = d.write_key("ed25519.pem", make_ed25519_pkcs8())
            token = get_token(key_path=path, challenge_dir=d.chaldir)
            self.assertTrue(_is_valid_token(token))

    def test_rsa_returns_valid_token(self):
        with TempDir() as d:
            path = d.write_key("rsa.pem", make_rsa_pkcs8())
            token = get_token(key_path=path, challenge_dir=d.chaldir)
            self.assertTrue(_is_valid_token(token))

    def test_token_hex_matches_nonce_file(self):
        with TempDir() as d:
            path = d.write_key("key", make_ed25519_openssh())
            token = get_token(key_path=path, challenge_dir=d.chaldir, version=1)
            hex_part = token.split(":")[0]
            nonce_file = os.path.join(d.chaldir, hex_part)
            self.assertTrue(os.path.exists(nonce_file),
                            f"nonce file {nonce_file} not found")

    def test_successive_tokens_are_unique(self):
        with TempDir() as d:
            path = d.write_key("key", make_ed25519_openssh())
            t1 = get_token(key_path=path, challenge_dir=d.chaldir)
            t2 = get_token(key_path=path, challenge_dir=d.chaldir)
            self.assertNotEqual(t1, t2)

    @needs_bcrypt
    def test_encrypted_key_with_passphrase(self):
        passphrase = b"test passphrase"
        with TempDir() as d:
            path = d.write_key("encrypted", make_ed25519_encrypted(passphrase))
            token = get_token(
                key_path=path, challenge_dir=d.chaldir, passphrase=passphrase
            )
            self.assertTrue(_is_valid_token(token))

    def test_missing_key_raises_keyerror(self):
        with TempDir() as d:
            with self.assertRaises(KeyError_):
                get_token(key_path="/tmp/no_such_key_pam.pem",
                          challenge_dir=d.chaldir)

    def test_bad_challenge_dir_raises_challenge_error(self):
        with TempDir() as d:
            path = d.write_key("key", make_ed25519_openssh())
            with self.assertRaises(ChallengeError):
                get_token(key_path=path,
                          challenge_dir="/proc/1/pam_bad_dir", version=1)

    def test_key_loaded_before_nonce_created(self):
        """If the key is bad, no nonce file should be left on disk."""
        with TempDir() as d:
            files_before = set(os.listdir(d.chaldir))
            try:
                get_token(key_path="/no/such/key.pem", challenge_dir=d.chaldir, version=1)
            except KeyError_:
                pass
            files_after = set(os.listdir(d.chaldir))
            self.assertEqual(files_before, files_after,
                             "stale nonce file created before key was validated")


# ── Tests: import robustness ──────────────────────────────────────────────────

class TestImportWithoutHome(unittest.TestCase):

    def test_import_succeeds_when_home_is_unset(self):
        """DynamicUser services / `docker run --user` have no HOME and no passwd
        entry; importing must still work when key_path is passed explicitly."""
        src = str(Path(__file__).parent.parent / "src")
        r = subprocess.run(
            [sys.executable, "-c",
             "import pam_pg_sshkey, sys; print(pam_pg_sshkey.DEFAULT_KEY_PATH is None)"],
            env={"PATH": os.environ["PATH"], "PYTHONPATH": src},  # no HOME
            cwd=tempfile.gettempdir(),   # not the build dir: ./pam_pg_sshkey.so would shadow the module
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, r.stderr)


# ── Tests: v2 tokens (client-issued challenge; the default) ──────────────────

class TestV2Token(unittest.TestCase):
    """v2: the client picks timestamp + nonce and signs
    "pg-sshkey-v2\\0" + "<ts>:<nonce_hex>".  Nothing is written anywhere and
    no server-side step exists, so remote hosts need no ssh/challenge_cmd."""

    def test_default_token_is_v2_and_writes_nothing(self):
        with TempDir() as d:
            path = d.write_key("key", make_ed25519_openssh())
            before = int(time.time())
            token = get_token(key_path=path, challenge_dir=d.chaldir)
            self.assertTrue(TOKEN_V2_RE.match(token), token)
            ts = int(token.split(":")[0])
            self.assertTrue(before <= ts <= int(time.time()) + 1)
            self.assertEqual(os.listdir(d.chaldir), [])

    def test_signature_covers_prefix_ts_and_nonce(self):
        sk = Ed25519PrivateKey.generate()
        with TempDir() as d:
            path = d.write_key("key", sk.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
            token = get_token(key_path=path)
        ts, nonce, sig_b64 = token.split(":")
        sk.public_key().verify(base64.b64decode(sig_b64),
                               _SIGN_PREFIX_V2 + f"{ts}:{nonce}".encode())

    def test_prefix_v2_is_13_bytes_with_nul(self):
        self.assertEqual(_SIGN_PREFIX_V2, b"pg-sshkey-v2\x00")

    def test_successive_tokens_differ(self):
        with TempDir() as d:
            path = d.write_key("key", make_ed25519_openssh())
            self.assertNotEqual(get_token(key_path=path), get_token(key_path=path))

    def test_rsa_v2(self):
        with TempDir() as d:
            path = d.write_key("rsa.pem", make_rsa_pkcs8())
            self.assertTrue(TOKEN_V2_RE.match(get_token(key_path=path)))

    def test_version_1_still_available(self):
        with TempDir() as d:
            path = d.write_key("key", make_ed25519_openssh())
            token = get_token(key_path=path, challenge_dir=d.chaldir, version=1)
            self.assertTrue(TOKEN_RE.match(token), token)
            self.assertTrue(os.path.exists(os.path.join(d.chaldir, token.split(":")[0])))

    def test_unknown_version_rejected(self):
        with TempDir() as d:
            path = d.write_key("key", make_ed25519_openssh())
            with self.assertRaises(ValueError):
                get_token(key_path=path, version=3)


# ── Tests: challenge_cmd (nonce minted on the server, e.g. over ssh) ─────────

class TestChallengeCmd(unittest.TestCase):
    """The PAM module reads the nonce from the *server's* challenge_dir, so a
    client on another host must create it there.  challenge_cmd runs a
    command (typically `ssh server pg_sshkey_challenge DIR`) that prints the
    64-hex nonce; the token is then signed locally from that hex."""

    HEX = "0123456789abcdef" * 4

    def test_token_uses_hex_from_command_and_creates_no_local_nonce(self):
        with TempDir() as d:
            path = d.write_key("key", make_ed25519_openssh())
            token = get_token(key_path=path, challenge_dir=d.chaldir,
                              challenge_cmd=f"printf '%s\\n' {self.HEX}")
            self.assertTrue(_is_valid_token(token))
            self.assertEqual(token.split(":")[0], self.HEX)
            self.assertEqual(os.listdir(d.chaldir), [], "no nonce may be created locally")

    def test_signature_is_over_the_remote_nonce_bytes(self):
        with TempDir() as d:
            sk = Ed25519PrivateKey.generate()
            path = d.write_key("key", sk.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
            token = get_token(key_path=path, challenge_dir=d.chaldir,
                              challenge_cmd=["printf", "%s", self.HEX])
            sig = base64.b64decode(token.split(":")[1])
            sk.public_key().verify(sig, _SIGN_PREFIX + bytes.fromhex(self.HEX))

    def test_failing_command_raises_challenge_error(self):
        with TempDir() as d:
            path = d.write_key("key", make_ed25519_openssh())
            with self.assertRaises(ChallengeError) as ctx:
                get_token(key_path=path, challenge_cmd="echo boom >&2; exit 3")
            self.assertIn("boom", str(ctx.exception))

    def test_garbage_output_raises_challenge_error(self):
        with TempDir() as d:
            path = d.write_key("key", make_ed25519_openssh())
            with self.assertRaises(ChallengeError):
                get_token(key_path=path, challenge_cmd="echo not-a-nonce")


# ── Tests: connect() guard ────────────────────────────────────────────────────

class TestConnectGuard(unittest.TestCase):

    def test_passing_password_raises_valueerror(self):
        """connect() must raise if caller passes password= explicitly."""
        with self.assertRaises(ValueError):
            pam_pg_sshkey.connect(password="should_not_be_here", user="alice")


# ── Tests: connect_replication() factory/flag selection ───────────────────────

@unittest.skipUnless(HAVE_PSYCOPG2, "psycopg2 not installed")
class TestConnectReplication(unittest.TestCase):
    """psycopg2.connect is stubbed: these pin what is handed to libpq.
    The real server round-trip is proven by tests/e2e (make e2e)."""

    def _call(self, **kw):
        from psycopg2.extras import (LogicalReplicationConnection,
                                     PhysicalReplicationConnection)
        self.Logical, self.Physical = LogicalReplicationConnection, PhysicalReplicationConnection
        with TempDir() as d:
            path = d.write_key("key", make_ed25519_openssh())
            with mock.patch("psycopg2.connect") as m:
                connect_replication(key_path=path, challenge_dir=d.chaldir,
                                    user="replicator", host="publisher", **kw)
                self.assertEqual(m.call_count, 1)
                return m.call_args.kwargs

    def test_default_is_logical(self):
        kw = self._call()
        self.assertIs(kw["connection_factory"], self.Logical)
        self.assertEqual(kw["replication"], "database")

    def test_bool_true_is_physical_and_forwarded_as_libpq_true(self):
        kw = self._call(replication=True)
        self.assertIs(kw["connection_factory"], self.Physical)
        self.assertEqual(kw["replication"], "true")   # not the str 'True'

    def test_libpq_truthy_spellings_are_physical(self):
        for spelling in ("true", "on", "yes", "1"):
            with self.subTest(spelling=spelling):
                kw = self._call(replication=spelling)
                self.assertIs(kw["connection_factory"], self.Physical)
                self.assertEqual(kw["replication"], spelling)

    def test_explicit_factory_is_respected(self):
        class MyConn: ...
        kw = self._call(replication=True, connection_factory=MyConn)
        self.assertIs(kw["connection_factory"], MyConn)

    def test_password_is_a_fresh_token(self):
        kw = self._call()
        self.assertTrue(_is_valid_token(kw["password"]))


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
