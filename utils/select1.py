#!/usr/bin/env python3
"""
Connect to PostgreSQL as the current OS user using pam_pg_sshkey SSH-key
authentication and execute SELECT 1.

The token is "<unix_ts>:<nonce_hex>:<base64_signature>": the client picks the
timestamp and the nonce and signs them, so nothing has to exist on the server
first and this runs from any host.  The server accepts a timestamp within 60
seconds of its own clock and records each nonce on first use.

Requirements:
    pip install psycopg2-binary cryptography

The pam_pg_sshkey PAM module must be installed on the server
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes

import psycopg2

# Domain-separation prefix, must match the PAM module exactly
SIGN_PREFIX_V2 = b"pg-sshkey-v2\x00"

KEY_PATH = os.path.expanduser("~/.ssh/id_ed25519")


def make_challenge() -> str:
    """The client issues its own challenge, "<unix_ts>:<nonce_hex>".
    Nothing is written anywhere; the server bounds the timestamp (60 s either
    way) and records the nonce on first use, so this works from any host."""
    return f"{int(time.time())}:{secrets.token_bytes(32).hex()}"


def load_key(key_path: str):
    """Load an SSH or PEM private key (Ed25519 or RSA)."""
    data   = open(key_path, "rb").read()
    header = data.split(b"\n")[0]
    if b"OPENSSH PRIVATE KEY" in header:
        return load_ssh_private_key(data, password=None)
    return load_pem_private_key(data, password=None)


def sign(key, head: str) -> bytes:
    """Sign SIGN_PREFIX_V2 || "<ts>:<nonce_hex>" with the private key."""
    message = SIGN_PREFIX_V2 + head.encode("ascii")
    if isinstance(key, Ed25519PrivateKey):
        return key.sign(message)
    return key.sign(message, asym_padding.PKCS1v15(), hashes.SHA256())


def get_token(key_path: str = KEY_PATH) -> str:
    """Return a token "<ts>:<nonce_hex>:<base64_sig>" ready to use as the password."""
    key  = load_key(key_path)
    head = make_challenge()
    sig  = sign(key, head)
    return f"{head}:{base64.b64encode(sig).decode()}"


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
