"""
test_python_module.py

Unit tests for pam_pg_sshkey.py.

Tests:
  - get_token() with OpenSSH Ed25519 key
  - get_token() with PKCS#8 Ed25519 key
  - get_token() with PKCS#8 RSA-2048 key
  - get_token() with passphrase-protected key
  - Token format validation ("<ts>:<64hex>:<base64>")
  - Two calls produce two different tokens
  - Nothing is written to the filesystem while a token is made
  - Missing key raises KeyError_
  - passing password= to connect() raises ValueError
  - SIGN_PREFIX_V2 is exactly b"pg-sshkey-v2\\x00" (13 bytes)
  - Signed message matches what the PAM module verifies
  - The removed nonce parameters (version, challenge_cmd, challenge_dir)
    raise TypeError
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
    KeyError_,
    _SIGN_PREFIX_V2,
    _SIGN_PREFIX_V3,
    _load_private_key,
    _sign_message,
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

TOKEN_V2_RE = re.compile(r"^[0-9]+:[0-9a-f]{64}:[A-Za-z0-9+/]+=*$")
TOKEN_V3_RE = re.compile(r"^[0-9]+:[0-9a-f]{64}:[A-Za-z0-9+/]+=*:[A-Za-z0-9+/]+=*$")


def _is_valid_token(token: str) -> bool:
    """The three-field shape the server takes: "<ts>:<nonce_hex>:<sig>"."""
    return bool(TOKEN_V2_RE.match(token))


class TempDir:
    """Context manager providing a fresh temp directory and an empty subdir to
    watch for stray files."""

    def __enter__(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = self._td.name
        # A directory a v1 client would have written a nonce into.  Tokens are
        # signed in process now, so every test that watches it wants it empty.
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


# ── Tests: _sign_message ─────────────────────────────────────────────────────

class TestSignMessage(unittest.TestCase):
    """_sign_message signs the bytes get_token has already built: the prefix
    followed by "<ts>:<nonce_hex>"."""

    def _message(self) -> bytes:
        import secrets
        return _SIGN_PREFIX_V2 + f"{int(time.time())}:{secrets.token_bytes(32).hex()}".encode()

    def test_ed25519_signature_length_is_64(self):
        key = Ed25519PrivateKey.generate()
        self.assertEqual(len(_sign_message(key, self._message())), 64)

    def test_ed25519_signature_verifies(self):
        key = Ed25519PrivateKey.generate()
        message = self._message()
        key.public_key().verify(_sign_message(key, message), message)

    def test_rsa_signature_verifies(self):
        from cryptography.hazmat.primitives.asymmetric import padding as p
        from cryptography.hazmat.primitives import hashes as h
        key = generate_private_key(65537, 2048)
        message = self._message()
        key.public_key().verify(_sign_message(key, message), message,
                                p.PKCS1v15(), h.SHA256())

    def test_different_messages_produce_different_sigs(self):
        key = Ed25519PrivateKey.generate()
        self.assertNotEqual(_sign_message(key, self._message()),
                            _sign_message(key, self._message()))


# ── Tests: get_token ──────────────────────────────────────────────────────────

class TestGetToken(unittest.TestCase):

    def test_openssh_ed25519_returns_valid_token(self):
        with TempDir() as d:
            path = d.write_key("id_ed25519", make_ed25519_openssh())
            token = get_token(key_path=path)
            self.assertTrue(_is_valid_token(token), f"invalid token: {token!r}")

    def test_pkcs8_ed25519_returns_valid_token(self):
        with TempDir() as d:
            path = d.write_key("ed25519.pem", make_ed25519_pkcs8())
            self.assertTrue(_is_valid_token(get_token(key_path=path)))

    def test_rsa_returns_valid_token(self):
        with TempDir() as d:
            path = d.write_key("rsa.pem", make_rsa_pkcs8())
            self.assertTrue(_is_valid_token(get_token(key_path=path)))

    def test_token_nonce_is_64_hex_and_fresh_each_time(self):
        with TempDir() as d:
            path = d.write_key("key", make_ed25519_openssh())
            nonces = {get_token(key_path=path).split(":")[1] for _ in range(5)}
            self.assertEqual(len(nonces), 5)
            for nonce in nonces:
                self.assertRegex(nonce, r"^[0-9a-f]{64}$")

    def test_successive_tokens_are_unique(self):
        with TempDir() as d:
            path = d.write_key("key", make_ed25519_openssh())
            self.assertNotEqual(get_token(key_path=path), get_token(key_path=path))

    @needs_bcrypt
    def test_encrypted_key_with_passphrase(self):
        passphrase = b"test passphrase"
        with TempDir() as d:
            path = d.write_key("encrypted", make_ed25519_encrypted(passphrase))
            token = get_token(key_path=path, passphrase=passphrase)
            self.assertTrue(_is_valid_token(token))

    def test_missing_key_raises_keyerror(self):
        with self.assertRaises(KeyError_):
            get_token(key_path="/tmp/no_such_key_pam.pem")

    def test_token_writes_nothing_to_disk(self):
        """The token is signed in process: a bad key, and a good one, must
        both leave the filesystem untouched."""
        with TempDir() as d:
            path = d.write_key("key", make_ed25519_openssh())
            before = set(os.listdir(d.root)), set(os.listdir(d.chaldir))
            get_token(key_path=path)
            with self.assertRaises(KeyError_):
                get_token(key_path="/no/such/key.pem")
            self.assertEqual((set(os.listdir(d.root)), set(os.listdir(d.chaldir))),
                             before)


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
    no server-side step exists, so a client on any host can sign its own."""

    def test_default_token_is_v2_and_writes_nothing(self):
        with TempDir() as d:
            path = d.write_key("key", make_ed25519_openssh())
            before = int(time.time())
            token = get_token(key_path=path)
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


# ── Tests: the v1 parameters are gone ────────────────────────────────────────

class TestV1ParametersRemoved(unittest.TestCase):
    """The server takes v2 and v3 tokens only.  The parameters that existed to
    mint or fetch a server-side nonce were removed rather than deprecated, so a
    caller that still passes one gets a TypeError from Python itself."""

    def _key(self, d: TempDir) -> str:
        return d.write_key("key", make_ed25519_openssh())

    def test_version_keyword_raises_typeerror(self):
        with TempDir() as d:
            with self.assertRaises(TypeError):
                get_token(key_path=self._key(d), version=1)

    def test_challenge_cmd_keyword_raises_typeerror(self):
        with TempDir() as d:
            with self.assertRaises(TypeError):
                get_token(key_path=self._key(d), challenge_cmd="echo x")

    def test_challenge_dir_keyword_raises_typeerror(self):
        with TempDir() as d:
            with self.assertRaises(TypeError):
                get_token(key_path=self._key(d), challenge_dir=d.chaldir)

    def test_no_public_function_still_takes_them(self):
        """connect() and connect_replication() forward every other keyword to
        psycopg2, so a removed name reaches libpq as an unknown connection
        option instead of a TypeError.  What matters is that neither function
        names it any more."""
        import inspect
        for fn in (get_token, pam_pg_sshkey.connect, connect_replication):
            for name in ("version", "challenge_cmd", "challenge_dir"):
                with self.subTest(fn=fn.__name__, parameter=name):
                    self.assertNotIn(name, inspect.signature(fn).parameters)

    def test_module_no_longer_exports_the_v1_helpers(self):
        for name in ("_SIGN_PREFIX", "_sign", "_create_challenge",
                     "_remote_challenge", "DEFAULT_TOKEN_VERSION",
                     "DEFAULT_CHALLENGE_DIR", "ChallengeError"):
            with self.subTest(name=name):
                self.assertFalse(hasattr(pam_pg_sshkey, name),
                                 f"{name} is still defined")


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
                connect_replication(key_path=path,
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

    # Not the default "ssh:".  Every check here then reads the application
    # out of the public key blob, so a module that ignored the field and
    # assumed the default fails the whole class instead of passing it.
    APPLICATION = "ssh:corp"
    TS = 1700000000
    NONCE = "0123456789abcdef" * 4

    def setUp(self):
        super().setUp()
        self.sk_key = Ed25519PrivateKey.generate()
        self.sk_pub = write_sk_pubkey(os.path.join(self.dir, "id_sk.pub"),
                                      self.sk_key, self.APPLICATION)

    def serve(self, responder) -> FakeAgent:
        """start_agent, but usable more than once in a check: the previous
        agent is closed and its socket path freed first."""
        agent = getattr(self, "agent", None)
        if agent is not None:
            agent.close()
            os.unlink(self.sock)
        return self.start_agent(responder)

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

    def test_signature_is_bound_to_the_keys_application(self):
        """The application string is hashed into what the key signs, and it
        comes from the public key blob rather than from the reply.  This key
        is scoped to "ssh:corp", so a signature made for the default "ssh:"
        must not pass: a module that ignored the field and assumed the
        default would take it.  tests/test_pam_module.c makes the same claim
        in test_security_key_signature_is_bound_to_its_application."""
        # the key's own application signs a token
        self.serve(self.sk_responder())
        self.assertTrue(TOKEN_V2_RE.match(get_token(agent_pubkey=self.sk_pub)))

        # the default application, which this key is not scoped to, does not,
        # and neither does a third one
        for other in ("ssh:", "ssh:other"):
            with self.subTest(application=other):
                self.serve(self.sk_responder(application=other))
                with self.assertRaises(KeyError_) as ctx:
                    get_token(agent_pubkey=self.sk_pub)
                self.assertIn("does not verify", str(ctx.exception))

    def test_default_application_key_refuses_another_application(self):
        """The binding holds in both directions: a key scoped to the default
        "ssh:" takes a signature made for "ssh:" and refuses one made for
        "ssh:corp".  Without this a module could hard-code either string and
        still pass."""
        pub = write_sk_pubkey(os.path.join(self.dir, "id_sk_default.pub"),
                              self.sk_key, "ssh:")
        self.serve(self.sk_responder(application="ssh:"))
        self.assertTrue(TOKEN_V2_RE.match(get_token(agent_pubkey=pub)))

        self.serve(self.sk_responder(application="ssh:corp"))
        with self.assertRaises(KeyError_) as ctx:
            get_token(agent_pubkey=pub)
        self.assertIn("does not verify", str(ctx.exception))

    def test_flags_and_counter_come_from_the_reply(self):
        """Both trailing bytes are hashed into what the key signs, and both
        are read from the reply.  A key that reports user verification as well
        as presence sends flags 0x05, and the counter is whatever the
        authenticator is at; a module that assumed 0x01, or a fixed counter,
        would refuse a signature the server accepts."""
        self.serve(self.sk_responder(flags=0x05, counter=0x12345678))
        token = get_token(agent_pubkey=self.sk_pub)
        ts, nonce, sig_b64 = token.split(":")
        sig = base64.b64decode(sig_b64)
        self.assertEqual(len(sig), 69, sig.hex())
        self.assertEqual(sig[64], 0x05)
        self.assertEqual(struct.unpack(">I", sig[65:69])[0], 0x12345678)
        message = _SIGN_PREFIX_V2 + f"{ts}:{nonce}".encode("ascii")
        self.sk_key.public_key().verify(
            sig[:64],
            sk_signed_data(self.APPLICATION, 0x05, 0x12345678, message))

    def test_tail_that_disagrees_with_the_signed_bytes_is_refused(self):
        """The flags and the counter travel in the token and the server
        verifies with the bytes the reply carries, so a tail that differs from
        what the key signed cannot verify.  Either field alone breaks it."""
        for name, tail in (("flags", bytes([0x05]) + struct.pack(">I", 7)),
                           ("counter", bytes([0x01]) + struct.pack(">I", 8))):
            with self.subTest(field=name):
                self.serve(self.sk_responder(flags=0x01, counter=7, tail=tail))
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
