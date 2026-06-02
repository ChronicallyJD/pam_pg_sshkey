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
import sys
import tempfile
import unittest
from pathlib import Path

# Allow running from the tests/ directory or the project root
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pam_pg_sshkey
from pam_pg_sshkey import (
    ChallengeError,
    KeyError_,
    _SIGN_PREFIX,
    _create_challenge,
    _load_private_key,
    _sign,
    get_token,
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

TOKEN_RE = re.compile(r"^[0-9a-f]{64}:[A-Za-z0-9+/]+=*$")


def _is_valid_token(token: str) -> bool:
    return bool(TOKEN_RE.match(token))


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

    def test_load_encrypted_with_passphrase(self):
        passphrase = b"correct horse battery staple"
        with TempDir() as d:
            path = d.write_key("encrypted", make_ed25519_encrypted(passphrase))
            key = _load_private_key(path, passphrase=passphrase)
            self.assertIsInstance(key, Ed25519PrivateKey)

    def test_load_encrypted_wrong_passphrase_raises(self):
        with TempDir() as d:
            path = d.write_key("encrypted", make_ed25519_encrypted(b"correct"))
            with self.assertRaises(KeyError_):
                _load_private_key(path, passphrase=b"wrong")

    def test_load_encrypted_no_passphrase_raises(self):
        with TempDir() as d:
            path = d.write_key("encrypted", make_ed25519_encrypted(b"secret"))
            with self.assertRaises(KeyError_):
                _load_private_key(path, passphrase=None)

    def test_missing_file_raises_keyerror(self):
        with self.assertRaises(KeyError_):
            _load_private_key("/tmp/no_such_key_pam_test.pem", passphrase=None)

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
            token = get_token(key_path=path, challenge_dir=d.chaldir)
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
                          challenge_dir="/proc/1/pam_bad_dir")

    def test_key_loaded_before_nonce_created(self):
        """If the key is bad, no nonce file should be left on disk."""
        with TempDir() as d:
            files_before = set(os.listdir(d.chaldir))
            try:
                get_token(key_path="/no/such/key.pem", challenge_dir=d.chaldir)
            except KeyError_:
                pass
            files_after = set(os.listdir(d.chaldir))
            self.assertEqual(files_before, files_after,
                             "stale nonce file created before key was validated")


# ── Tests: connect() guard ────────────────────────────────────────────────────

class TestConnectGuard(unittest.TestCase):

    def test_passing_password_raises_valueerror(self):
        """connect() must raise if caller passes password= explicitly."""
        with self.assertRaises(ValueError):
            pam_pg_sshkey.connect(password="should_not_be_here", user="alice")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
