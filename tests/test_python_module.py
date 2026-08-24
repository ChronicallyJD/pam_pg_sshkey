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
import struct
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

    def test_no_ssh_auth_sock_raises_keyerror_with_fix(self):
        key = self._keygen("no_sock")
        env = {k: v for k, v in os.environ.items() if k != "SSH_AUTH_SOCK"}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(KeyError_) as ctx:
                get_token(agent_pubkey=key + ".pub")
        self.assertIn("SSH_AUTH_SOCK", str(ctx.exception))
        self.assertIn("ssh-add", str(ctx.exception))

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

    def test_sk_key_type_is_refused(self):
        """FIDO/security keys: signature carries authenticator fields the
        server does not verify.  Blob crafted by hand, no hardware needed."""
        typ = b"sk-ssh-ed25519@openssh.com"
        blob = (struct.pack(">I", len(typ)) + typ
                + struct.pack(">I", 32) + b"\x00" * 32
                + struct.pack(">I", 4) + b"ssh:")
        pub = os.path.join(self.dir, "sk.pub")
        with open(pub, "w") as f:
            f.write("sk-ssh-ed25519@openssh.com "
                    + base64.b64encode(blob).decode("ascii") + " test\n")
        with self.assertRaises(KeyError_) as ctx:
            get_token(agent_pubkey=pub)
        self.assertIn("security key", str(ctx.exception))
        self.assertIn("sk-ssh-ed25519@openssh.com", str(ctx.exception))

    def test_agent_pubkey_with_key_path_raises_valueerror(self):
        key = self._keygen("both_args")
        with self.assertRaises(ValueError):
            get_token(agent_pubkey=key + ".pub", key_path=key)

    def test_agent_pubkey_with_version_1_raises_valueerror(self):
        key = self._keygen("v1_combo")
        with self.assertRaises(ValueError):
            get_token(agent_pubkey=key + ".pub", version=1)
        with self.assertRaises(ValueError):
            get_token(agent_pubkey=key + ".pub", challenge_cmd="echo x")

    def test_missing_pubkey_file_raises_keyerror(self):
        with self.assertRaises(KeyError_) as ctx:
            get_token(agent_pubkey=os.path.join(self.dir, "missing.pub"))
        self.assertIn("Cannot read public key", str(ctx.exception))


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
