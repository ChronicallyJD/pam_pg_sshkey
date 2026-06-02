#!/usr/bin/env python3
"""
Connect to PostgreSQL as the current OS user using pam_pg_sshkey SSH-key
authentication and execute SELECT 1.

Requirements:
    pip install psycopg2-binary cryptography

The pam_pg_sshkey PAM module and pg_sshkey_challenge must be installed
(sudo make install).
"""

import base64
import os
import secrets
import sys
import time

from cryptography.hazmat.primitives.serialization import (
    load_ssh_private_key,
    load_pem_private_key,
)
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes

import psycopg2

# Must match SIGN_PREFIX in sig_verify.c exactly
SIGN_PREFIX    = b"pg-sshkey-v1\x00"
CHALLENGE_DIR  = "/var/run/pg_sshkey"
KEY_PATH       = os.path.expanduser("~/.ssh/id_ed25519")


def create_challenge(challenge_dir: str) -> tuple[str, bytes]:
    """Write a 32-byte nonce to challenge_dir/<hex> and return (hex, raw)."""
    raw    = secrets.token_bytes(32)
    hex_id = raw.hex()
    path   = os.path.join(challenge_dir, hex_id)
    fd     = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "w") as f:
        f.write(f"{int(time.time())}\n{hex_id}\n")
    return hex_id, raw


def load_key(key_path: str):
    """Load an SSH or PEM private key (Ed25519 or RSA)."""
    data   = open(key_path, "rb").read()
    header = data.split(b"\n")[0]
    if b"OPENSSH PRIVATE KEY" in header:
        return load_ssh_private_key(data, password=None)
    return load_pem_private_key(data, password=None)


def sign(key, challenge_bytes: bytes) -> bytes:
    """Sign SIGN_PREFIX || challenge with the private key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    message = SIGN_PREFIX + challenge_bytes
    if isinstance(key, Ed25519PrivateKey):
        return key.sign(message)
    return key.sign(message, asym_padding.PKCS1v15(), hashes.SHA256())


def get_token(key_path: str = KEY_PATH,
              challenge_dir: str = CHALLENGE_DIR) -> str:
    """Return a signed token: '<64hex>:<base64_signature>'."""
    key            = load_key(key_path)
    hex_id, raw    = create_challenge(challenge_dir)
    sig            = sign(key, raw)
    return f"{hex_id}:{base64.b64encode(sig).decode()}"


# ── main ──────────────────────────────────────────────────────────────────────

token = get_token()

conn = psycopg2.connect(
    user=os.environ.get("PGUSER", os.environ.get("USER", "")),
    password=token,
)

cur = conn.cursor()
cur.execute("SELECT 1")
print(cur.fetchone()[0])

cur.close()
conn.close()
