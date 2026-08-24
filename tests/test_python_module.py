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
  - get_token(cert_path=...) produces a 4-field v3 token, signed over
    "pg-sshkey-v3\\0<ts>:<nonce>", whose 4th field is the cert file's base64,
    byte-identical to pg_sshkey_sign --cert for the same ts and nonce
  - get_token(agent_pubkey=...) with an sk-ssh-ed25519@openssh.com key: the
    token carries 69 signature bytes (sig64 || flags || counter), is
    byte-identical to pg_sshkey_sign --agent for the same ts and nonce, and
    a reply without user presence, without the trailing five bytes, with the
    wrong algorithm, or that does not verify is refused

Run:
    python3 -m pytest tests/test_python_module.py -v
    # or without pytest:
    python3 tests/test_python_module.py

SPDX-License-Identifier: MIT
"""

import base64
import hashlib
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
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
    _SIGN_PREFIX_V3,
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
    PublicFormat,
    load_ssh_public_key,
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
TOKEN_V3_RE = re.compile(r"^[0-9]+:[0-9a-f]{64}:[A-Za-z0-9+/]+=*:[A-Za-z0-9+/]+=*$")


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


# ── Tests: v3 certificate tokens ─────────────────────────────────────────────

ROOT = Path(__file__).parent.parent
PG_SSHKEY_SIGN = ROOT / "pg_sshkey_sign"


@unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen not installed")
class TestCertToken(unittest.TestCase):
    """v3: "<ts>:<nonce_hex>:<sig>:<cert_b64>", signed with the certified key
    over "pg-sshkey-v3\\0" + "<ts>:<nonce_hex>".  Acceptance by the real module
    is proven through libpam in tests/test_pam_module.c for the tokens that
    pg_sshkey_sign --cert prints; the last test here pins the Python token to
    that output byte for byte (Ed25519 signatures are deterministic)."""

    TS = 1700000000
    NONCE = "0123456789abcdef" * 4

    def _certified_key(self, d: TempDir, key_type: str = "ed25519"):
        """Return (private_key_path, cert_path, cert_b64) for a fresh key
        signed by a fresh CA for principal alice."""
        ca = d.key_path("ca")
        key = d.key_path("user_" + key_type)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", ca], check=True)
        if key_type == "rsa":
            subprocess.run(["ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-m", "PEM",
                            "-N", "", "-f", key], check=True)
        else:
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], check=True)
        subprocess.run(["ssh-keygen", "-q", "-s", ca, "-I", "alice-key", "-n", "alice",
                        "-V", "-1m:+5m", key + ".pub"], check=True)
        cert = key + "-cert.pub"
        fields = Path(cert).read_text().split()
        self.assertTrue(fields[0].endswith("-cert-v01@openssh.com"), fields[0])
        return key, cert, fields[1]

    def test_prefix_v3_is_13_bytes_with_nul(self):
        self.assertEqual(_SIGN_PREFIX_V3, b"pg-sshkey-v3\x00")
        self.assertEqual(len(_SIGN_PREFIX_V3), 13)

    def test_token_has_four_fields_and_cert_is_the_file_base64(self):
        with TempDir() as d:
            key, cert, cert_b64 = self._certified_key(d)
            before = int(time.time())
            token = get_token(key_path=key, cert_path=cert)
            self.assertTrue(TOKEN_V3_RE.match(token), token)
            ts, nonce, sig, cert_field = token.split(":")
            self.assertTrue(before <= int(ts) <= int(time.time()) + 1)
            self.assertEqual(cert_field, cert_b64)
            self.assertEqual(os.listdir(d.chaldir), [])

    def test_signature_verifies_over_v3_message_with_certified_key(self):
        from cryptography.hazmat.primitives.serialization import load_ssh_public_key
        with TempDir() as d:
            key, cert, _ = self._certified_key(d)
            token = get_token(key_path=key, cert_path=cert)
            ts, nonce, sig_b64, _ = token.split(":")
            pub = load_ssh_public_key(Path(key + ".pub").read_bytes())
            pub.verify(base64.b64decode(sig_b64),
                       _SIGN_PREFIX_V3 + f"{ts}:{nonce}".encode("ascii"))
            with self.assertRaises(Exception):
                pub.verify(base64.b64decode(sig_b64),
                           _SIGN_PREFIX_V2 + f"{ts}:{nonce}".encode("ascii"))

    def test_rsa_key_signature_verifies_over_v3_message(self):
        from cryptography.hazmat.primitives.serialization import load_ssh_public_key
        from cryptography.hazmat.primitives.asymmetric import padding as p
        from cryptography.hazmat.primitives import hashes as h
        with TempDir() as d:
            key, cert, cert_b64 = self._certified_key(d, "rsa")
            token = get_token(key_path=key, cert_path=cert)
            self.assertTrue(TOKEN_V3_RE.match(token), token)
            ts, nonce, sig_b64, cert_field = token.split(":")
            self.assertEqual(cert_field, cert_b64)
            pub = load_ssh_public_key(Path(key + ".pub").read_bytes())
            pub.verify(base64.b64decode(sig_b64),
                       _SIGN_PREFIX_V3 + f"{ts}:{nonce}".encode("ascii"),
                       p.PKCS1v15(), h.SHA256())

    def test_cert_path_with_version_1_raises_valueerror(self):
        with TempDir() as d:
            key, cert, _ = self._certified_key(d)
            with self.assertRaises(ValueError):
                get_token(key_path=key, cert_path=cert, version=1, challenge_dir=d.chaldir)
            self.assertEqual(os.listdir(d.chaldir), [], "no nonce may be created")

    def test_cert_path_with_challenge_cmd_raises_valueerror(self):
        with TempDir() as d:
            key, cert, _ = self._certified_key(d)
            with self.assertRaises(ValueError):
                get_token(key_path=key, cert_path=cert, challenge_cmd="echo x")

    def test_plain_public_key_as_cert_is_refused(self):
        with TempDir() as d:
            key, cert, _ = self._certified_key(d)
            with self.assertRaises(KeyError_):
                get_token(key_path=key, cert_path=key + ".pub")
            with self.assertRaises(KeyError_):
                get_token(key_path=key, cert_path=d.key_path("missing-cert.pub"))

    def test_unpadded_cert_field_is_refused(self):
        # the server's decoder drops a final partial group, so refuse it here
        with TempDir() as d:
            key, cert, _ = self._certified_key(d)
            ctype, b64, *rest = open(cert).read().split()
            bad = d.key_path("unpadded-cert.pub")
            with open(bad, "w") as f:
                f.write(f"{ctype} {b64.rstrip('=')[:-1]}\n")
            with self.assertRaises(KeyError_):
                get_token(key_path=key, cert_path=bad)

    @unittest.skipUnless(PG_SSHKEY_SIGN.exists(), "pg_sshkey_sign not built (run make)")
    def test_token_is_identical_to_pg_sshkey_sign_cert(self):
        """Same key, cert, timestamp and nonce: the Python token must equal
        the C signer's, which tests/test_pam_module.c proves the module
        accepts through libpam."""
        with TempDir() as d:
            key, cert, _ = self._certified_key(d)
            r = subprocess.run([str(PG_SSHKEY_SIGN), "--cert", cert, "--at", str(self.TS),
                                "--nonce", self.NONCE, key],
                               capture_output=True, text=True, check=True)
            expected = r.stdout.strip()
            self.assertTrue(TOKEN_V3_RE.match(expected), expected)
            with mock.patch("pam_pg_sshkey.time.time", return_value=self.TS), \
                 mock.patch("pam_pg_sshkey.secrets.token_bytes",
                            return_value=bytes.fromhex(self.NONCE)):
                token = get_token(key_path=key, cert_path=cert)
            self.assertEqual(token, expected)

    @unittest.skipUnless(HAVE_PSYCOPG2, "psycopg2 not installed")
    def test_connect_and_connect_replication_forward_cert_path(self):
        with TempDir() as d:
            key, cert, cert_b64 = self._certified_key(d)
            with mock.patch("psycopg2.connect") as m:
                pam_pg_sshkey.connect(key_path=key, cert_path=cert, user="alice")
                pw = m.call_args.kwargs["password"]
                self.assertTrue(TOKEN_V3_RE.match(pw), pw)
                self.assertEqual(pw.split(":")[3], cert_b64)
            with mock.patch("psycopg2.connect") as m:
                connect_replication(key_path=key, cert_path=cert, user="replicator", host="pub")
                pw = m.call_args.kwargs["password"]
                self.assertTrue(TOKEN_V3_RE.match(pw), pw)
                self.assertEqual(pw.split(":")[3], cert_b64)
                self.assertEqual(m.call_args.kwargs["replication"], "database")


# ── Tests: ssh-agent signing ─────────────────────────────────────────────────

HAVE_SSH_AGENT = bool(shutil.which("ssh-agent") and shutil.which("ssh-add")
                      and shutil.which("ssh-keygen"))
needs_ssh_agent = unittest.skipUnless(
    HAVE_SSH_AGENT, "ssh-agent/ssh-add not installed")


class _AgentFixture(unittest.TestCase):
    """Starts a real ssh-agent on a private socket for each test and points
    SSH_AUTH_SOCK at it; tearDown kills the agent.  No test methods."""

    TS = 1700000000
    NONCE = "0123456789abcdef" * 4

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.dir = self._td.name
        self.sock = os.path.join(self.dir, "agent.sock")
        r = subprocess.run(["ssh-agent", "-a", self.sock],
                           capture_output=True, text=True, check=True)
        m = re.search(r"SSH_AGENT_PID=(\d+)", r.stdout)
        self.assertIsNotNone(m, r.stdout)
        self.agent_pid = int(m.group(1))
        self._env = mock.patch.dict(os.environ, {"SSH_AUTH_SOCK": self.sock})
        self._env.start()

    def tearDown(self):
        self._env.stop()
        try:
            os.kill(self.agent_pid, 15)
        except ProcessLookupError:
            pass
        self._td.cleanup()

    def _keygen(self, name: str, key_type: str = "ed25519",
                passphrase: str = "") -> str:
        path = os.path.join(self.dir, name)
        cmd = ["ssh-keygen", "-q", "-t", key_type, "-N", passphrase, "-f", path]
        if key_type == "rsa":
            cmd += ["-b", "2048"]
        subprocess.run(cmd, check=True)
        return path

    def _add(self, key_path: str) -> None:
        subprocess.run(["ssh-add", "-q", key_path],
                       capture_output=True, check=True)

    def _fixed_token(self, **kw) -> str:
        with mock.patch("pam_pg_sshkey.time.time", return_value=self.TS), \
             mock.patch("pam_pg_sshkey.secrets.token_bytes",
                        return_value=bytes.fromhex(self.NONCE)):
            return get_token(**kw)


@needs_ssh_agent
class TestAgentSigning(_AgentFixture):
    """agent_pubkey=: the token is signed by a real ssh-agent started here;
    the private key file is never read.  The C signer proved this path against
    the real module through libpam; these tests pin the Python token to the
    C signer's byte for byte and verify the signatures independently."""

    @unittest.skipUnless(PG_SSHKEY_SIGN.exists(), "pg_sshkey_sign not built (run make)")
    def test_ed25519_token_matches_pg_sshkey_sign_agent(self):
        """Same agent, pubkey, timestamp and nonce: the Python token must be
        byte-identical to pg_sshkey_sign --agent (Ed25519 is deterministic)."""
        key = self._keygen("id_ed25519")
        self._add(key)
        r = subprocess.run([str(PG_SSHKEY_SIGN), "--agent", key + ".pub",
                            "--at", str(self.TS), "--nonce", self.NONCE],
                           capture_output=True, text=True, check=True)
        expected = r.stdout.strip()
        self.assertTrue(TOKEN_V2_RE.match(expected), expected)
        token = self._fixed_token(agent_pubkey=key + ".pub")
        self.assertEqual(token, expected)

    def test_ed25519_signature_verifies_over_v2_message(self):
        from cryptography.hazmat.primitives.serialization import load_ssh_public_key
        key = self._keygen("ed_verify")
        self._add(key)
        token = get_token(agent_pubkey=key + ".pub")
        self.assertTrue(TOKEN_V2_RE.match(token), token)
        ts, nonce, sig_b64 = token.split(":")
        pub = load_ssh_public_key(Path(key + ".pub").read_bytes())
        pub.verify(base64.b64decode(sig_b64),
                   _SIGN_PREFIX_V2 + f"{ts}:{nonce}".encode("ascii"))

    def test_rsa_signature_verifies_with_pkcs1v15_sha256(self):
        """Proves the SSH_AGENT_RSA_SHA2_256 flag is sent: without it the
        agent signs with SHA-1 and this PKCS1v15+SHA256 verify cannot pass
        (the module refuses the 'ssh-rsa' algo before even returning)."""
        from cryptography.hazmat.primitives.serialization import load_ssh_public_key
        from cryptography.hazmat.primitives.asymmetric import padding as p
        from cryptography.hazmat.primitives import hashes as h
        key = self._keygen("rsa_verify", key_type="rsa")
        self._add(key)
        token = get_token(agent_pubkey=key + ".pub")
        self.assertTrue(TOKEN_V2_RE.match(token), token)
        ts, nonce, sig_b64 = token.split(":")
        pub = load_ssh_public_key(Path(key + ".pub").read_bytes())
        pub.verify(base64.b64decode(sig_b64),
                   _SIGN_PREFIX_V2 + f"{ts}:{nonce}".encode("ascii"),
                   p.PKCS1v15(), h.SHA256())

    @unittest.skipUnless(PG_SSHKEY_SIGN.exists(), "pg_sshkey_sign not built (run make)")
    def test_rsa_token_matches_pg_sshkey_sign_agent(self):
        """RSASSA-PKCS1-v1_5 is deterministic, so the RSA token must also be
        byte-identical to the C signer's."""
        key = self._keygen("rsa_ident", key_type="rsa")
        self._add(key)
        r = subprocess.run([str(PG_SSHKEY_SIGN), "--agent", key + ".pub",
                            "--at", str(self.TS), "--nonce", self.NONCE],
                           capture_output=True, text=True, check=True)
        expected = r.stdout.strip()
        self.assertTrue(TOKEN_V2_RE.match(expected), expected)
        self.assertEqual(self._fixed_token(agent_pubkey=key + ".pub"), expected)

    def test_passphrase_key_signs_through_agent_but_not_from_file(self):
        """The whole point of the agent path: a passphrase-protected key works
        without the passphrase ever reaching this module, while reading the
        same key file directly raises."""
        key = self._keygen("enc_ed25519", passphrase="secret")
        askpass = os.path.join(self.dir, "askpass.sh")
        with open(askpass, "w") as f:
            f.write("#!/bin/sh\necho secret\n")
        os.chmod(askpass, 0o755)
        env = dict(os.environ, SSH_ASKPASS=askpass,
                   SSH_ASKPASS_REQUIRE="force", DISPLAY=":0")
        subprocess.run(["ssh-add", "-q", key], env=env, check=True,
                       capture_output=True, stdin=subprocess.DEVNULL)
        token = get_token(agent_pubkey=key + ".pub")
        self.assertTrue(TOKEN_V2_RE.match(token), token)
        with self.assertRaises(KeyError_):
            get_token(key_path=key)   # no passphrase, no agent: must raise

    def _certified_key(self):
        """(key_path, cert_path, cert_b64) for an agent-held certified key."""
        ca = os.path.join(self.dir, "ca")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", ca],
                       check=True)
        key = self._keygen("user_cert_key")
        subprocess.run(["ssh-keygen", "-q", "-s", ca, "-I", "alice-key",
                        "-n", "alice", "-V", "-1m:+5m", key + ".pub"], check=True)
        cert = key + "-cert.pub"
        return key, cert, Path(cert).read_text().split()[1]

    def test_cert_with_agent_is_v3_with_cert_base64(self):
        from cryptography.hazmat.primitives.serialization import load_ssh_public_key
        key, cert, cert_b64 = self._certified_key()
        self._add(key)
        token = get_token(agent_pubkey=key + ".pub", cert_path=cert)
        self.assertTrue(TOKEN_V3_RE.match(token), token)
        ts, nonce, sig_b64, cert_field = token.split(":")
        self.assertEqual(cert_field, cert_b64)
        pub = load_ssh_public_key(Path(key + ".pub").read_bytes())
        pub.verify(base64.b64decode(sig_b64),
                   _SIGN_PREFIX_V3 + f"{ts}:{nonce}".encode("ascii"))

    @unittest.skipUnless(PG_SSHKEY_SIGN.exists(), "pg_sshkey_sign not built (run make)")
    def test_cert_with_agent_matches_pg_sshkey_sign(self):
        key, cert, _ = self._certified_key()
        self._add(key)
        r = subprocess.run([str(PG_SSHKEY_SIGN), "--agent", key + ".pub",
                            "--cert", cert, "--at", str(self.TS),
                            "--nonce", self.NONCE],
                           capture_output=True, text=True, check=True)
        expected = r.stdout.strip()
        self.assertTrue(TOKEN_V3_RE.match(expected), expected)
        token = self._fixed_token(agent_pubkey=key + ".pub", cert_path=cert)
        self.assertEqual(token, expected)

    @unittest.skipUnless(HAVE_PSYCOPG2, "psycopg2 not installed")
    def test_connect_and_connect_replication_forward_agent_pubkey(self):
        key = self._keygen("forwarded")
        self._add(key)
        with mock.patch("psycopg2.connect") as m:
            pam_pg_sshkey.connect(agent_pubkey=key + ".pub", user="alice")
            self.assertTrue(TOKEN_V2_RE.match(m.call_args.kwargs["password"]))
        with mock.patch("psycopg2.connect") as m:
            connect_replication(agent_pubkey=key + ".pub",
                                user="replicator", host="publisher")
            self.assertTrue(TOKEN_V2_RE.match(m.call_args.kwargs["password"]))
            self.assertEqual(m.call_args.kwargs["replication"], "database")


@needs_ssh_agent
class TestAgentErrors(_AgentFixture):
    """Every agent failure raises the module's own KeyError_ (or ValueError
    for bad argument combinations) with a message that says what to do,
    never a bare socket traceback."""

    def test_dead_socket_path_raises_keyerror_with_fix(self):
        key = self._keygen("dead_sock")
        dead = os.path.join(self.dir, "no_agent_here.sock")
        with mock.patch.dict(os.environ, {"SSH_AUTH_SOCK": dead}):
            with self.assertRaises(KeyError_) as ctx:
                get_token(agent_pubkey=key + ".pub")
        self.assertIn(dead, str(ctx.exception))
        self.assertIn("ssh-add", str(ctx.exception))

    def test_key_not_in_agent_raises_keyerror_naming_ssh_add(self):
        key = self._keygen("never_added")
        with self.assertRaises(KeyError_) as ctx:
            get_token(agent_pubkey=key + ".pub")
        self.assertIn("refused to sign", str(ctx.exception))
        self.assertIn("ssh-add", str(ctx.exception))


# ── Tests: agent argument checks and a fake agent socket ─────────────────────
#
# Nothing below needs ssh-agent, ssh-add or ssh-keygen: the keys come from
# `cryptography` and the agent is a Unix socket served by a thread here.  These
# checks therefore run on every host, unlike the classes above.

def _sshstr(b: bytes) -> bytes:
    """uint32 length prefix + bytes, the ssh wire string."""
    return struct.pack(">I", len(b)) + b


def _rd_sshstr(buf: bytes, pos: int) -> tuple[bytes, int]:
    (n,) = struct.unpack(">I", buf[pos:pos + 4])
    return buf[pos + 4:pos + 4 + n], pos + 4 + n


def agent_request_message(req: bytes) -> bytes:
    """The message field of an SSH_AGENTC_SIGN_REQUEST payload."""
    _blob, pos = _rd_sshstr(req, 1)
    msg, _pos = _rd_sshstr(req, pos)
    return msg


def sign_response(algo: bytes, sig: bytes) -> bytes:
    """An SSH_AGENT_SIGN_RESPONSE payload carrying (algo, sig)."""
    return bytes([14]) + _sshstr(_sshstr(algo) + _sshstr(sig))


def write_pubkey(path: str, key) -> str:
    """Write key's public half as an OpenSSH '<type> <base64>' line."""
    line = key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    Path(path).write_bytes(line + b" test@fake\n")
    return path


# ── Security keys, without hardware ──────────────────────────────────────────
#
# A FIDO key signs SHA256(application) || flags || counter || SHA256(message)
# and its SSH signature carries the flags byte and the 4-byte counter after
# the raw 64 bytes.  tests/sk_helper.py builds the same bytes for the C tests;
# these helpers build them for the fake agent.

SK_ED25519 = b"sk-ssh-ed25519@openssh.com"


def sk_pubkey_blob(key, application: str = "ssh:",
                   key_type: bytes = SK_ED25519) -> bytes:
    """A security key's public blob: string type, string pk32, string app."""
    return (_sshstr(key_type)
            + _sshstr(key.public_key().public_bytes_raw())
            + _sshstr(application.encode("ascii")))


def write_sk_pubkey(path: str, key, application: str = "ssh:",
                    key_type: bytes = SK_ED25519) -> str:
    """Write a security key's public half as an authorized_keys line."""
    blob = sk_pubkey_blob(key, application, key_type)
    Path(path).write_bytes(key_type + b" " + base64.b64encode(blob)
                           + b" sk@fake\n")
    return path


def sk_signed_data(application: str, flags: int, counter: int,
                   message: bytes) -> bytes:
    """What the authenticator signs, byte for byte as sig_verify.c builds it."""
    return (hashlib.sha256(application.encode("ascii")).digest()
            + bytes([flags]) + struct.pack(">I", counter)
            + hashlib.sha256(message).digest())


def sk_sign_response(key, message: bytes, application: str = "ssh:",
                     flags: int = 0x01, counter: int = 7,
                     algo: bytes = SK_ED25519,
                     tail: bytes | None = None) -> bytes:
    """An SSH_AGENT_SIGN_RESPONSE shaped the way a security key answers:
    inside one blob, the algorithm, the 64 raw bytes, then flags and counter."""
    sig = key.sign(sk_signed_data(application, flags, counter, message))
    if tail is None:
        tail = bytes([flags]) + struct.pack(">I", counter)
    return bytes([14]) + _sshstr(_sshstr(algo) + _sshstr(sig) + tail)


class FakeAgent:
    """A Unix socket that answers one sign request with whatever `responder`
    returns.  A responder returning None never answers, which is what an agent
    waiting on a human (ssh-add -c, a smartcard PIN) looks like."""

    def __init__(self, path: str, responder):
        self.path = path
        self.responder = responder
        self.requests: list[bytes] = []
        self._stop = threading.Event()
        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._srv.bind(path)
        self._srv.listen(4)
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _recv_exact(self, conn, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise OSError("short read")
            buf += chunk
        return buf

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            with conn:
                try:
                    (n,) = struct.unpack(">I", self._recv_exact(conn, 4))
                    req = self._recv_exact(conn, n)
                    self.requests.append(req)
                    reply = self.responder(req)
                    if reply is None:
                        self._stop.wait(30)     # answer nothing, ever
                        return
                    conn.sendall(_sshstr(reply))
                except OSError:
                    pass

    def close(self) -> None:
        self._stop.set()
        self._srv.close()


class _FakeAgentFixture(unittest.TestCase):
    """Temp dir, an Ed25519 key pair on disk, and a FakeAgent on request."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.dir = self._td.name
        self.key = Ed25519PrivateKey.generate()
        self.pub = write_pubkey(os.path.join(self.dir, "id_ed25519.pub"), self.key)
        self.sock = os.path.join(self.dir, "agent.sock")

    def tearDown(self):
        agent = getattr(self, "agent", None)
        if agent is not None:
            agent.close()
        self._td.cleanup()

    def start_agent(self, responder, **env) -> FakeAgent:
        self.agent = FakeAgent(self.sock, responder)
        self._env = mock.patch.dict(
            os.environ, dict({"SSH_AUTH_SOCK": self.sock}, **env))
        self._env.start()
        self.addCleanup(self._env.stop)
        return self.agent

    def honest_responder(self, key=None):
        """Signs the message the request actually carries, labelled ssh-ed25519."""
        signer = key if key is not None else self.key
        return lambda req: sign_response(
            b"ssh-ed25519", signer.sign(agent_request_message(req)))


class TestAgentArgumentErrors(unittest.TestCase):
    """Bad argument combinations and unreadable key files are refused before
    any agent is contacted, so these run on hosts with no ssh-agent at all."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.dir = self._td.name
        self.addCleanup(self._td.cleanup)

    def _pub(self, name: str = "id_ed25519.pub") -> str:
        return write_pubkey(os.path.join(self.dir, name),
                            Ed25519PrivateKey.generate())

    def test_agent_pubkey_with_key_path_raises_valueerror(self):
        with self.assertRaises(ValueError):
            get_token(agent_pubkey=self._pub(), key_path="/nonexistent/key")

    def test_agent_pubkey_with_version_1_raises_valueerror(self):
        with self.assertRaises(ValueError):
            get_token(agent_pubkey=self._pub(), version=1)

    def test_agent_pubkey_with_challenge_cmd_raises_valueerror(self):
        """Documented in get_token()'s docstring; the C signer has no such
        combination to offer."""
        with self.assertRaises(ValueError):
            get_token(agent_pubkey=self._pub(), challenge_cmd="echo x")

    def test_agent_pubkey_with_passphrase_raises_valueerror(self):
        """A passphrase cannot reach the agent, so accepting one silently
        would promise a protection the call does not give."""
        with self.assertRaises(ValueError) as ctx:
            get_token(agent_pubkey=self._pub(), passphrase=b"secret")
        self.assertIn("passphrase", str(ctx.exception))

    def test_sk_ecdsa_key_type_is_refused(self):
        """Of the security key types only sk-ssh-ed25519@openssh.com works:
        the server has no ECDSA verifier.  Blob crafted by hand, no hardware
        needed, and no agent is contacted."""
        typ = b"sk-ecdsa-sha2-nistp256@openssh.com"
        blob = (struct.pack(">I", len(typ)) + typ
                + struct.pack(">I", 8) + b"nistp256"
                + struct.pack(">I", 65) + b"\x04" + b"\x00" * 64
                + struct.pack(">I", 4) + b"ssh:")
        pub = os.path.join(self.dir, "sk_ecdsa.pub")
        with open(pub, "w") as f:
            f.write(typ.decode("ascii") + " "
                    + base64.b64encode(blob).decode("ascii") + " test\n")
        with self.assertRaises(KeyError_) as ctx:
            get_token(agent_pubkey=pub)
        msg = str(ctx.exception)
        self.assertIn("sk-ecdsa-sha2-nistp256@openssh.com", msg)
        self.assertIn("sk-ssh-ed25519@openssh.com", msg)
        self.assertIn("ECDSA", msg)

    def test_missing_pubkey_file_raises_keyerror(self):
        with self.assertRaises(KeyError_) as ctx:
            get_token(agent_pubkey=os.path.join(self.dir, "missing.pub"))
        self.assertIn("Cannot read public key", str(ctx.exception))

    def test_no_ssh_auth_sock_raises_keyerror_with_fix(self):
        pub = self._pub("no_sock.pub")
        env = {k: v for k, v in os.environ.items() if k != "SSH_AUTH_SOCK"}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(KeyError_) as ctx:
                get_token(agent_pubkey=pub)
        self.assertIn("SSH_AUTH_SOCK", str(ctx.exception))
        self.assertIn("ssh-add", str(ctx.exception))

    def test_private_key_file_gets_the_c_signers_sentence(self):
        """--agent given the private key is the case docs/troubleshooting.md
        documents, with the C signer's wording.  Python said "key field is not
        base64" for the same file."""
        priv = os.path.join(self.dir, "id_ed25519")
        Path(priv).write_bytes(Ed25519PrivateKey.generate().private_bytes(
            Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
        with self.assertRaises(KeyError_) as ctx:
            get_token(agent_pubkey=priv)
        self.assertEqual(
            str(ctx.exception),
            f"{priv} is not an OpenSSH public key line "
            f"(expected '<type> <base64> [comment]', as ssh-keygen -y writes)")

    def test_non_base64_key_field_still_says_not_base64(self):
        """The padding check moved, the character check did not: a field of
        the right length with a bad character keeps its own message."""
        pub = os.path.join(self.dir, "bad_chars.pub")
        Path(pub).write_text("ssh-ed25519 ....\n")
        with self.assertRaises(KeyError_) as ctx:
            get_token(agent_pubkey=pub)
        self.assertEqual(str(ctx.exception), f"{pub}: key field is not base64")


class TestAgentTimeout(_FakeAgentFixture):
    """An agent that needs a human (ssh-add -c, a smartcard PIN) is healthy and
    slow.  The wait is a module constant, and PG_SSHKEY_AGENT_TIMEOUT_MS
    overrides it, spelled exactly as src/ssh_agent.c reads it."""

    def test_default_timeout_is_60_seconds(self):
        self.assertEqual(pam_pg_sshkey._AGENT_TIMEOUT_SECS, 60)

    def test_env_var_shortens_the_wait_and_still_raises_keyerror(self):
        self.start_agent(lambda req: None, PG_SSHKEY_AGENT_TIMEOUT_MS="200")
        t0 = time.monotonic()
        with self.assertRaises(KeyError_):
            get_token(agent_pubkey=self.pub)
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 5.0,
                        f"the 200 ms timeout was not honoured ({elapsed:.1f}s)")

    def test_bad_env_var_falls_back_to_the_default(self):
        for bad in ("", "0", "-1", "abc", "200x"):
            with self.subTest(value=bad):
                self.assertEqual(
                    pam_pg_sshkey._agent_timeout_secs({"PG_SSHKEY_AGENT_TIMEOUT_MS": bad}),
                    60)
        self.assertEqual(
            pam_pg_sshkey._agent_timeout_secs({"PG_SSHKEY_AGENT_TIMEOUT_MS": "250"}),
            0.25)


class TestAgentSignatureChecks(_FakeAgentFixture):
    """What the agent returns is checked before it becomes a token: the socket
    may be forwarded from another host, and a wrong signature would otherwise
    surface only as 'authentication failed' on the server."""

    def test_empty_signature_is_refused(self):
        """Accepted, the token ends in ':' and the server sees no signature."""
        self.start_agent(lambda req: sign_response(b"ssh-ed25519", b""))
        with self.assertRaises(KeyError_) as ctx:
            get_token(agent_pubkey=self.pub)
        self.assertIn("empty signature", str(ctx.exception))

    def test_signature_from_another_key_is_refused(self):
        """Well formed, right length, right algorithm, wrong key."""
        other = Ed25519PrivateKey.generate()
        self.start_agent(self.honest_responder(other))
        with self.assertRaises(KeyError_) as ctx:
            get_token(agent_pubkey=self.pub)
        msg = str(ctx.exception)
        self.assertIn("does not verify", msg)
        self.assertIn("different key", msg)

    def test_wrong_algorithm_is_refused_even_with_a_valid_signature(self):
        """The signature verifies; only the label is wrong.  The server reads
        the algorithm name, so the name has to be the one it verifies."""
        self.start_agent(lambda req: sign_response(
            b"ecdsa-sha2-nistp256", self.key.sign(agent_request_message(req))))
        with self.assertRaises(KeyError_) as ctx:
            get_token(agent_pubkey=self.pub)
        self.assertIn("ecdsa-sha2-nistp256", str(ctx.exception))

    def test_honest_agent_still_produces_a_verifiable_token(self):
        """The verification must not reject a correct signature."""
        self.start_agent(self.honest_responder())
        token = get_token(agent_pubkey=self.pub)
        self.assertTrue(TOKEN_V2_RE.match(token), token)
        ts, nonce, sig_b64 = token.split(":")
        pub = load_ssh_public_key(Path(self.pub).read_bytes())
        pub.verify(base64.b64decode(sig_b64),
                   _SIGN_PREFIX_V2 + f"{ts}:{nonce}".encode("ascii"))

    def test_certificate_blob_skips_the_verification(self):
        """The key inside a certificate is not the blob, so the blob cannot
        verify the signature; the check has to be skipped, as it is in
        src/ssh_agent.c.  The agent here returns a signature that would fail
        that check, and the token must still come back."""
        typ = b"ssh-ed25519-cert-v01@openssh.com"
        blob = _sshstr(typ) + _sshstr(b"nonce") + _sshstr(b"\x00" * 32)
        cert_pub = os.path.join(self.dir, "id_ed25519-cert.pub")
        Path(cert_pub).write_bytes(
            typ + b" " + base64.b64encode(blob) + b" alice\n")
        self.start_agent(self.honest_responder(Ed25519PrivateKey.generate()))
        token = get_token(agent_pubkey=cert_pub)
        self.assertTrue(TOKEN_V2_RE.match(token), token)

    def test_key_path_none_is_accepted_with_agent_pubkey(self):
        """None is 'not specified': a wrapper that forwards key_path=None must
        not be refused."""
        self.start_agent(self.honest_responder())
        token = get_token(agent_pubkey=self.pub, key_path=None)
        self.assertTrue(TOKEN_V2_RE.match(token), token)


class TestSkAgentSigning(_FakeAgentFixture):
    """sk-ssh-ed25519@openssh.com through the agent.  The signature is not the
    64 bytes a plain Ed25519 key returns: the flags and the counter the
    authenticator signed travel with it, so the token carries 69 bytes.  No
    hardware and no ssh binaries are involved; the fake agent signs the way
    tests/sk_helper.py does."""

    APPLICATION = "ssh:"
    TS = 1700000000
    NONCE = "0123456789abcdef" * 4

    def setUp(self):
        super().setUp()
        self.sk_key = Ed25519PrivateKey.generate()
        self.sk_pub = write_sk_pubkey(os.path.join(self.dir, "id_sk.pub"),
                                      self.sk_key, self.APPLICATION)

    def sk_responder(self, key=None, application=None, **kw):
        """Answers the sign request the way a security key does."""
        signer = self.sk_key if key is None else key
        app = self.APPLICATION if application is None else application
        return lambda req: sk_sign_response(
            signer, agent_request_message(req), application=app, **kw)

    def test_sk_token_carries_sig_flags_and_counter(self):
        """The token's signature field is sig64 || flags || counter, and the
        64 bytes verify over what the authenticator signed."""
        self.start_agent(self.sk_responder(counter=7))
        token = get_token(agent_pubkey=self.sk_pub)
        self.assertTrue(TOKEN_V2_RE.match(token), token)
        ts, nonce, sig_b64 = token.split(":")
        sig = base64.b64decode(sig_b64)
        self.assertEqual(len(sig), 69, sig.hex())
        self.assertEqual(sig[64], 0x01)
        self.assertEqual(struct.unpack(">I", sig[65:69])[0], 7)
        message = _SIGN_PREFIX_V2 + f"{ts}:{nonce}".encode("ascii")
        self.sk_key.public_key().verify(
            sig[:64], sk_signed_data(self.APPLICATION, sig[64], 7, message))

    @unittest.skipUnless(PG_SSHKEY_SIGN.exists(),
                         "pg_sshkey_sign not built (run make)")
    def test_sk_token_matches_pg_sshkey_sign_agent(self):
        """Same fake agent, pubkey, timestamp and nonce: the Python token must
        be byte-identical to pg_sshkey_sign --agent."""
        self.start_agent(self.sk_responder())
        r = subprocess.run([str(PG_SSHKEY_SIGN), "--agent", self.sk_pub,
                            "--at", str(self.TS), "--nonce", self.NONCE],
                           capture_output=True, text=True,
                           env=dict(os.environ, SSH_AUTH_SOCK=self.sock))
        self.assertEqual(r.returncode, 0, r.stderr)
        expected = r.stdout.strip()
        with mock.patch("pam_pg_sshkey.time.time", return_value=self.TS), \
             mock.patch("pam_pg_sshkey.secrets.token_bytes",
                        return_value=bytes.fromhex(self.NONCE)):
            token = get_token(agent_pubkey=self.sk_pub)
        self.assertEqual(token, expected)

    def test_no_user_presence_is_refused(self):
        """Without the presence bit the signature says nothing about whether a
        person touched the key, and the server refuses it."""
        self.start_agent(self.sk_responder(flags=0x00))
        with self.assertRaises(KeyError_) as ctx:
            get_token(agent_pubkey=self.sk_pub)
        self.assertIn("touch the key", str(ctx.exception))

    def test_missing_flags_and_counter_is_refused(self):
        """A 64-byte reply with no trailing five bytes cannot be verified by
        the server, so it must not become a token."""
        self.start_agent(self.sk_responder(tail=b""))
        with self.assertRaises(KeyError_) as ctx:
            get_token(agent_pubkey=self.sk_pub)
        self.assertIn("flags and counter", str(ctx.exception))

    def test_plain_ed25519_algorithm_is_refused(self):
        """The reply's algorithm must be the key type: 'ssh-ed25519' means the
        agent signed the message itself, which this public key cannot verify."""
        self.start_agent(self.sk_responder(algo=b"ssh-ed25519"))
        with self.assertRaises(KeyError_) as ctx:
            get_token(agent_pubkey=self.sk_pub)
        msg = str(ctx.exception)
        self.assertIn("ssh-ed25519", msg)
        self.assertIn("sk-ssh-ed25519@openssh.com", msg)

    def test_signature_from_another_key_is_refused(self):
        """Right shape, right algorithm, right flags, wrong key."""
        self.start_agent(self.sk_responder(key=Ed25519PrivateKey.generate()))
        with self.assertRaises(KeyError_) as ctx:
            get_token(agent_pubkey=self.sk_pub)
        self.assertIn("does not verify", str(ctx.exception))

    def test_wrong_application_is_refused(self):
        """The application string is hashed into what the key signs, and it
        comes from the public key blob, so a reply signed over another one
        cannot verify."""
        self.start_agent(self.sk_responder(application="ssh:other"))
        with self.assertRaises(KeyError_) as ctx:
            get_token(agent_pubkey=self.sk_pub)
        self.assertIn("does not verify", str(ctx.exception))


class TestUnsetSentinel(unittest.TestCase):
    """key_path's default is a sentinel; it must not print as a raw object in
    help() or inspect.signature()."""

    def test_signature_default_reads_as_the_default_key_path(self):
        import inspect
        for fn in (get_token, pam_pg_sshkey.connect, connect_replication):
            with self.subTest(fn=fn.__name__):
                shown = repr(inspect.signature(fn).parameters["key_path"].default)
                self.assertNotIn("object object", shown)
                self.assertEqual(shown, repr(pam_pg_sshkey.DEFAULT_KEY_PATH))

    def test_sentinel_is_still_a_unique_singleton(self):
        self.assertIs(pam_pg_sshkey._UNSET, pam_pg_sshkey._UNSET)
        self.assertIsNot(pam_pg_sshkey._UNSET, None)
        self.assertIsNot(pam_pg_sshkey._UNSET, pam_pg_sshkey.DEFAULT_KEY_PATH)


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
