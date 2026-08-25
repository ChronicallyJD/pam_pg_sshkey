"""
pam_pg_sshkey.py

Python module for authenticating to PostgreSQL using pam_pg_sshkey SSH-key
authentication from application code, scripts, and replication clients.

PURPOSE
=======
This module allows any psycopg2-based application, including logical
replication subscribers, to authenticate via SSH keys without wrapping
psql or calling external shell commands. Everything is done in-process
using Python's cryptography library.

USAGE
=====
    from pam_pg_sshkey import get_token, connect, connect_replication

    # Get a signed token and use it yourself:
    token = get_token(key_path="~/.ssh/id_ed25519")
    conn = psycopg2.connect(
        host="publisher.example.com",
        user="replicator",
        dbname="mydb",
        password=token,
    )

    # Or use the convenience wrappers:
    conn = connect(user="alice", dbname="mydb")
    conn = connect_replication(user="replicator", host="publisher.example.com")

    # Sign through the ssh-agent at $SSH_AUTH_SOCK instead of reading the
    # private key file (passphrase-protected keys and forwarded agents work):
    conn = connect(agent_pubkey="~/.ssh/id_ed25519.pub", user="alice", dbname="mydb")

TOKEN FORMAT
============
    "<unix_ts>:<nonce_hex>:<base64_sig>"              (with cert_path:
    "<unix_ts>:<nonce_hex>:<base64_sig>:<base64_cert>")

The client picks the timestamp and the 32-byte nonce and signs them; nothing
is created on the server beforehand, so a token can be made on any host. The
server accepts |now - ts| <= 60 seconds and records each nonce on first use,
which makes every token single-use.

WHY THE TOKEN MUST BE PRE-COMPUTED
====================================
When PostgreSQL receives a connection, it immediately sends AUTH_REQ_PASSWORD
to the client. libpq (which psycopg2 uses internally) responds by checking
whether a password was supplied in the connection parameters. If no password
is present, libpq disconnects immediately with "fe_sendauth: no password
supplied", before any application code runs.

The PAM module on the server receives a NULL token and logs:
    pam_pg_sshkey: failed to get auth token for 'user' (client sent no password)

The token MUST be present in the connection parameters before connect() is
called. This module handles that: get_token() produces the signed token, which
is then passed as the password= parameter.

    token = get_token(...)                  # compute BEFORE connecting
    conn = psycopg2.connect(password=token) # libpq holds it ready for AUTH_REQ_PASSWORD

REPLICATION
===========
For logical replication, pass replication="database" (or replication=True for
physical) to the connection. The pg_hba.conf entry on the publisher must cover
the replication database:

    # /etc/postgresql/16/main/pg_hba.conf  (on the publisher)
    host  replication  replicator  <subscriber_ip>/32  pam  pamservice=postgresql

The replication user must exist and have the REPLICATION attribute:

    CREATE USER replicator REPLICATION;
    -- No password needed: authentication is via SSH key

KEY FORMAT SUPPORT
==================
    ~/.ssh/id_ed25519   OpenSSH format Ed25519 (with or without passphrase)
    ~/.ssh/id_rsa       OpenSSH format RSA
    key.pem             PKCS#8 or traditional PEM (Ed25519 or RSA)

REQUIREMENTS
============
    pip install psycopg2-binary cryptography

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import socket
import struct
import time
import re
from pathlib import Path
from typing import Any

# ── Imports with helpful errors ───────────────────────────────────────────────

try:
    from cryptography.hazmat.primitives.serialization import (
        load_ssh_private_key,
        load_ssh_public_key,
        load_pem_private_key,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
except ImportError as e:
    raise ImportError(
        "The 'cryptography' package is required.\n"
        "Install it with:  pip install cryptography"
    ) from e


# ── Constants ─────────────────────────────────────────────────────────────────

# Domain-separation prefixes, must match the PAM module exactly
_SIGN_PREFIX_V2: bytes = b"pg-sshkey-v2\x00"     # v2: client-issued challenge
_SIGN_PREFIX_V3: bytes = b"pg-sshkey-v3\x00"     # v3: certificate, client-issued challenge

# Token shapes, both with a client-issued challenge:
#   v2 (default)  "<unix_ts>:<nonce_hex>:<sig>", message = PREFIX_V2 +
#                 "<ts>:<nonce_hex>".  The client picks timestamp and nonce;
#                 nothing is created on the server beforehand; works from any
#                 host.  The server accepts |now - ts| <= 60 s and records each
#                 nonce on first use.
#   v3 (cert_path) "<unix_ts>:<nonce_hex>:<sig>:<cert_b64>", message =
#                 PREFIX_V3 + "<ts>:<nonce_hex>", signed by the private key
#                 whose public key the OpenSSH certificate carries.

# Default paths
# Resolved lazily-safe: importing must never fail just because HOME is unset
# (DynamicUser services, `docker run --user`), callers may pass key_path.
try:
    DEFAULT_KEY_PATH: str | None = str(Path.home() / ".ssh" / "id_ed25519")
except RuntimeError:
    DEFAULT_KEY_PATH = None
DEFAULT_KEY_PASSPHRASE: bytes | None = None

# Spellings libpq treats as "physical replication connection"
_PHYSICAL_REPLICATION = frozenset({"true", "on", "yes", "1"})

# How far the server lets a token's timestamp sit from its own clock, in
# seconds.  Must match CHALLENGE_TTL_SECS in challenge_store.h.
CHALLENGE_TTL_SECS: int = 60

# ssh-agent protocol (OpenSSH PROTOCOL.agent).  Every message on the socket is
# uint32 length, then the payload; the payload starts with a type byte.
_SSH_AGENTC_SIGN_REQUEST: int = 13
_SSH_AGENT_SIGN_RESPONSE: int = 14
# RSA flag for the sign request: without it an agent signs with SHA-1,
# which the PAM module refuses.
_SSH_AGENT_RSA_SHA2_256: int = 2
# A security key signs SHA256(application) || flags || counter ||
# SHA256(message), and its SSH signature carries the flags byte and the 4-byte
# counter after the 64 raw bytes.  The sign request carries flags 0: the RSA
# SHA-2 flag does not apply, and the server has no ECDSA verifier, so only the
# Ed25519 security key type works.  Spelled as src/ssh_agent.c reads it.
_SK_ED25519: bytes = b"sk-ssh-ed25519@openssh.com"
_SK_FLAG_USER_PRESENT: int = 0x01
_SK_SIG_LEN: int = 64 + 1 + 4
_AGENT_MAX_MSG: int = 256 * 1024
# How long to wait on the agent socket.  An agent that asks a human (ssh-add -c
# confirmation, a smartcard PIN) is healthy and slow, so the wait is generous.
# PG_SSHKEY_AGENT_TIMEOUT_MS overrides it, spelled as src/ssh_agent.c reads it.
_AGENT_TIMEOUT_SECS: float = 60


def _agent_timeout_secs(env: dict[str, str] | None = None) -> float:
    """Seconds to wait on the agent socket: PG_SSHKEY_AGENT_TIMEOUT_MS if it
    holds a positive integer, else _AGENT_TIMEOUT_SECS."""
    raw = (os.environ if env is None else env).get("PG_SSHKEY_AGENT_TIMEOUT_MS")
    if raw:
        try:
            ms = int(raw)
        except ValueError:
            return _AGENT_TIMEOUT_SECS
        if ms > 0:
            return ms / 1000.0
    return _AGENT_TIMEOUT_SECS


class _UnsetKeyPath:
    """Sentinel: tells "key_path was not passed" apart from an explicit value,
    so agent_pubkey= can refuse an explicit key_path.  It prints as the default
    it stands for, so help() and inspect.signature() read correctly."""

    __slots__ = ()

    def __repr__(self) -> str:
        return repr(DEFAULT_KEY_PATH)


_UNSET: Any = _UnsetKeyPath()


# ── Exceptions ────────────────────────────────────────────────────────────────

class PamPgSshKeyError(Exception):
    """Base exception for all pam_pg_sshkey errors."""

class KeyError_(PamPgSshKeyError):
    """Failed to load or use the private key."""
    # Named with trailing _ to avoid shadowing Python's built-in KeyError


# ── Key loading ───────────────────────────────────────────────────────────────

def _load_private_key(
    key_path: str,
    passphrase: bytes | None,
) -> Ed25519PrivateKey | RSAPrivateKey:
    """
    Load a private key from key_path.

    Supports:
      - OpenSSH format  (-----BEGIN OPENSSH PRIVATE KEY-----)
      - PKCS#8 PEM      (-----BEGIN PRIVATE KEY-----)
      - Traditional PEM (-----BEGIN RSA/EC/... PRIVATE KEY-----)

    passphrase should be the raw bytes passphrase, or None for unencrypted keys.

    Raises KeyError_ with actionable guidance on failure.
    """
    if key_path is None:
        raise KeyError_(
            "No key_path given and no home directory to find ~/.ssh/id_ed25519 in "
            "(HOME is unset). Pass key_path= explicitly."
        )
    path = Path(key_path).expanduser()

    if not path.exists():
        raise KeyError_(
            f"SSH key not found: {key_path}\n\n"
            f"Generate one with:\n"
            f"  ssh-keygen -t ed25519 -f {key_path} -N ''\n\n"
            f"Then register the public key:\n"
            f"  sudo pg_sshkey_addkey <username> {key_path}.pub"
        )

    key_bytes = path.read_bytes()
    header = key_bytes.split(b"\n")[0]

    try:
        if b"OPENSSH PRIVATE KEY" in header:
            key = load_ssh_private_key(key_bytes, password=passphrase)
        else:
            key = load_pem_private_key(key_bytes, password=passphrase)
    except (ValueError, TypeError, UnicodeDecodeError) as e:
        msg = str(e)
        hint = ""
        if "password" in msg.lower() or "encrypted" in msg.lower() or "passphrase" in msg.lower():
            hint = (
                "\n\nKey is encrypted. Provide the passphrase:\n"
                "  get_token(key_path=..., passphrase=b'your_passphrase')\n\n"
                "Or export to an unencrypted PEM file:\n"
                f"  openssl pkey -in {key_path} -out key.pem\n"
                "  # OpenSSL prompts for passphrase once during export"
            )
        raise KeyError_(
            f"Failed to load private key from {key_path}: {msg}{hint}"
        ) from e
    except UnsupportedAlgorithm as e:
        msg = str(e)
        hint = ""
        if "bcrypt" in msg.lower():
            hint = (
                "\n\nPassphrase-protected OpenSSH keys use the bcrypt KDF, which "
                "needs the optional 'bcrypt' package:\n"
                "  pip install bcrypt      # or: apt install python3-bcrypt\n\n"
                "Or export to an unencrypted PEM file:\n"
                f"  openssl pkey -in {key_path} -out key.pem"
            )
        raise KeyError_(
            f"Failed to load private key from {key_path}: {msg}{hint}"
        ) from e

    if not isinstance(key, (Ed25519PrivateKey, RSAPrivateKey)):
        raise KeyError_(
            f"Unsupported key type: {type(key).__name__}\n"
            f"Supported types: Ed25519, RSA"
        )

    return key


# ── Certificate loading ───────────────────────────────────────────────────────

def _load_cert_b64(cert_path: str) -> str:
    """
    Return the base64 field of an OpenSSH certificate file (`*-cert.pub`),
    unchanged.  The first field must end in "-cert-v01@openssh.com"; a plain
    public key or a missing file raises KeyError_.
    """
    path = Path(cert_path).expanduser()
    try:
        fields = path.read_text().split()
    except OSError as e:
        raise KeyError_(f"Cannot read certificate {cert_path}: {e}") from e
    if len(fields) < 2 or not fields[0].endswith("-cert-v01@openssh.com"):
        raise KeyError_(
            f"{cert_path} is not an OpenSSH certificate (expected a "
            f"'*-cert-v01@openssh.com' first field, as ssh-keygen -s writes)"
        )
    b64 = fields[1]
    if len(b64) % 4 != 0 or not re.fullmatch(r"[A-Za-z0-9+/]+=*", b64):
        raise KeyError_(f"{cert_path}: certificate field is not padded base64")
    return b64


# ── ssh-agent signing ─────────────────────────────────────────────────────────

def _agent_pubkey_blob(pubkey_path: str) -> bytes:
    """
    Return the decoded SSH key blob from the second whitespace field of an
    OpenSSH public key file (`.pub` or `-cert.pub`, as ssh-keygen writes).

    Raises KeyError_ on a missing file or a line that is not a public key.
    """
    path = Path(pubkey_path).expanduser()
    try:
        text = path.read_text()
    except OSError as e:
        raise KeyError_(f"Cannot read public key {pubkey_path}: {e}") from e
    lines = text.splitlines()
    fields = lines[0].split() if lines else []
    # A field that is not padded base64 means the line is not a public key at
    # all, most often a private key passed by mistake.  src/ssh_agent.c folds
    # the length check into the same branch and says the same sentence.
    if len(fields) < 2 or len(fields[1]) % 4 != 0:
        raise KeyError_(
            f"{pubkey_path} is not an OpenSSH public key line "
            f"(expected '<type> <base64> [comment]', as ssh-keygen -y writes)"
        )
    b64 = fields[1]
    if not re.fullmatch(r"[A-Za-z0-9+/]+=*", b64):
        raise KeyError_(f"{pubkey_path}: key field is not base64")
    try:
        return base64.b64decode(b64, validate=True)
    except ValueError as e:
        raise KeyError_(f"{pubkey_path}: cannot decode the key field: {e}") from e


def _agent_read_string(buf: bytes, pos: int, what: str) -> tuple[bytes, int]:
    """Read one uint32-length-prefixed string at pos; return (bytes, new_pos)."""
    if pos + 4 > len(buf):
        raise KeyError_(f"ssh-agent: malformed {what}")
    (n,) = struct.unpack(">I", buf[pos:pos + 4])
    if pos + 4 + n > len(buf):
        raise KeyError_(f"ssh-agent: malformed {what}")
    return buf[pos + 4:pos + 4 + n], pos + 4 + n


def _agent_connect() -> socket.socket:
    """Connect to the ssh-agent at $SSH_AUTH_SOCK; KeyError_ with the fix."""
    sock_path = os.environ.get("SSH_AUTH_SOCK")
    if not sock_path:
        raise KeyError_(
            "No ssh-agent: SSH_AUTH_SOCK is not set.\n"
            "Start one and add the key:\n"
            "  eval $(ssh-agent)\n"
            "  ssh-add ~/.ssh/id_ed25519"
        )
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(_agent_timeout_secs())
        s.connect(sock_path)
    except OSError as e:
        s.close()
        raise KeyError_(
            f"Cannot connect to the ssh-agent at {sock_path}: {e}\n"
            f"Start one and add the key:\n"
            f"  eval $(ssh-agent)\n"
            f"  ssh-add <private key>"
        ) from e
    return s


def _agent_round_trip(s: socket.socket, payload: bytes) -> bytes:
    """Send one framed request and return the reply payload (type byte first)."""
    try:
        s.sendall(struct.pack(">I", len(payload)) + payload)
        hdr = b""
        while len(hdr) < 4:
            chunk = s.recv(4 - len(hdr))
            if not chunk:
                raise KeyError_(
                    "ssh-agent: no reply (the agent closed the connection)")
            hdr += chunk
        (n,) = struct.unpack(">I", hdr)
        if n == 0 or n > _AGENT_MAX_MSG:
            raise KeyError_(f"ssh-agent: reply of {n} bytes is out of range")
        reply = b""
        while len(reply) < n:
            chunk = s.recv(n - len(reply))
            if not chunk:
                raise KeyError_("ssh-agent: truncated reply")
            reply += chunk
        return reply
    except OSError as e:
        raise KeyError_(
            f"ssh-agent: connection failed: {e}\n"
            f"Restart the agent and add the key:\n"
            f"  eval $(ssh-agent)\n"
            f"  ssh-add <private key>"
        ) from e


def _agent_sign(agent_pubkey: str, message: bytes) -> bytes:
    """
    Sign message through the ssh-agent at $SSH_AUTH_SOCK with the identity
    whose public key file is agent_pubkey.  The private key is never read.

    Returns the inner signature bytes (Ed25519 raw, or RSASSA-PKCS1-v1_5
    with SHA-256), exactly what the PAM module verifies.  A security key
    returns 69 bytes: the 64 raw bytes, the flags byte and the 4-byte
    counter it signed.  Raises KeyError_ on any agent or key problem.
    """
    blob = _agent_pubkey_blob(agent_pubkey)
    key_type, _ = _agent_read_string(blob, 0, f"key blob in {agent_pubkey}")
    type_str = key_type.decode("ascii", "replace")
    is_sk_ed25519 = key_type == _SK_ED25519
    if key_type.startswith(b"sk-") and not is_sk_ed25519:
        raise KeyError_(
            f"Key type {type_str} is not supported.  Of the security key "
            f"types only sk-ssh-ed25519@openssh.com is: the server has no "
            f"ECDSA verifier."
        )
    is_rsa = key_type.startswith(b"ssh-rsa")

    req = (
        bytes([_SSH_AGENTC_SIGN_REQUEST])
        + struct.pack(">I", len(blob)) + blob
        + struct.pack(">I", len(message)) + message
        + struct.pack(">I", _SSH_AGENT_RSA_SHA2_256 if is_rsa else 0)
    )
    s = _agent_connect()
    try:
        reply = _agent_round_trip(s, req)
    finally:
        s.close()

    if reply[0] != _SSH_AGENT_SIGN_RESPONSE:
        raise KeyError_(
            f"The ssh-agent refused to sign with the key in {agent_pubkey}.\n"
            f"Add the key with: ssh-add <private key>\n"
            f"List the keys it holds with: ssh-add -l"
        )
    sigblob, _ = _agent_read_string(reply, 1, "signature response")
    algo, pos = _agent_read_string(sigblob, 0, "signature blob")
    sig, sig_end = _agent_read_string(sigblob, pos, "signature blob")
    algo_str = algo.decode("ascii", "replace")
    # A security key's signature carries a flags byte and a 4-byte counter
    # after the raw 64 bytes, and both are part of what it signed.  The server
    # needs all 69 bytes, so they travel in the token.
    sk_tail = b""
    if is_sk_ed25519:
        if algo != _SK_ED25519:
            raise KeyError_(
                f"The ssh-agent signed with '{algo_str}'; this key needs "
                f"sk-ssh-ed25519@openssh.com."
            )
        sk_tail = sigblob[sig_end:]
        if len(sig) != 64 or len(sig) + len(sk_tail) != _SK_SIG_LEN:
            raise KeyError_(
                "The ssh-agent returned a security key signature without its "
                "flags and counter; the server cannot verify it."
            )
        if not sk_tail[0] & _SK_FLAG_USER_PRESENT:
            raise KeyError_(
                "The security key reported no user presence: touch the key "
                "when it flashes.  The server refuses a signature without it."
            )
    if not is_sk_ed25519 and is_rsa and algo != b"rsa-sha2-256":
        raise KeyError_(
            f"The ssh-agent signed with '{algo_str}'; the server needs "
            f"rsa-sha2-256.  Use an OpenSSH 7.2 or newer agent, or sign "
            f"from the key file with key_path=."
        )
    if not is_sk_ed25519 and not is_rsa and algo != b"ssh-ed25519":
        raise KeyError_(
            f"The ssh-agent signed with '{algo_str}', which the server does "
            f"not verify.  Use an ed25519 or rsa key."
        )
    if not sig:
        raise KeyError_(
            f"The ssh-agent returned an empty signature for the key in "
            f"{agent_pubkey}."
        )
    if is_sk_ed25519:
        _agent_sk_verify(agent_pubkey, blob, message, sig, sk_tail)
        return sig + sk_tail
    # Verify with the public key the caller named.  The agent can return
    # anything, and a forwarded socket is served by another host; without this
    # a wrong signature only surfaces as "authentication failed" on the server,
    # with nothing to go on.  A certificate blob is skipped: the key inside the
    # certificate is not this blob.
    if not key_type.endswith(b"-cert-v01@openssh.com"):
        _agent_verify(agent_pubkey, key_type, blob, message, sig, is_rsa)
    return sig


def _agent_sk_verify(agent_pubkey: str, blob: bytes, message: bytes,
                     sig: bytes, sk_tail: bytes) -> None:
    """Check a security key's signature the way src/sig_verify.c does: the
    signed data is SHA256(application) || flags || counter || SHA256(message),
    where the application is the third string of the public key blob.
    Raises KeyError_ when it does not verify."""
    what = f"key blob in {agent_pubkey}"
    _key_type, pos = _agent_read_string(blob, 0, what)
    raw_pub, pos = _agent_read_string(blob, pos, what)
    application, _pos = _agent_read_string(blob, pos, what)
    if len(raw_pub) != 32:
        raise KeyError_(
            f"The public key in {agent_pubkey} is not a 32-byte "
            f"sk-ssh-ed25519@openssh.com key."
        )
    signed_data = (hashlib.sha256(application).digest() + sk_tail
                   + hashlib.sha256(message).digest())
    try:
        Ed25519PublicKey.from_public_bytes(raw_pub).verify(sig, signed_data)
    except (InvalidSignature, TypeError, ValueError) as e:
        raise KeyError_(
            f"The security key's signature does not verify with the public "
            f"key in {agent_pubkey}.  The agent may hold a different key "
            f"under that name."
        ) from e


def _agent_verify(agent_pubkey: str, key_type: bytes, blob: bytes,
                  message: bytes, sig: bytes, is_rsa: bool) -> None:
    """Check the agent's signature against the public key in agent_pubkey.
    Raises KeyError_ when it does not verify."""
    line = key_type + b" " + base64.b64encode(blob)
    try:
        pub = load_ssh_public_key(line)
    except (ValueError, UnsupportedAlgorithm) as e:
        raise KeyError_(
            f"Cannot read the public key in {agent_pubkey} to check the "
            f"signature the ssh-agent returned: {e}"
        ) from e
    try:
        if is_rsa:
            pub.verify(sig, message, asym_padding.PKCS1v15(), hashes.SHA256())
        else:
            pub.verify(sig, message)
    except (InvalidSignature, TypeError, ValueError) as e:
        raise KeyError_(
            f"The ssh-agent returned a signature that does not verify with "
            f"the public key in {agent_pubkey}.  The agent may hold a "
            f"different key under that name."
        ) from e


# ── Signing ───────────────────────────────────────────────────────────────────

def _sign_message(key: Ed25519PrivateKey | RSAPrivateKey, message: bytes) -> bytes:
    """Sign an already-built message (Ed25519 raw; RSA PKCS#1 v1.5 / SHA-256)."""
    if isinstance(key, Ed25519PrivateKey):
        return key.sign(message)
    return key.sign(message, asym_padding.PKCS1v15(), hashes.SHA256())


# ── Public API ────────────────────────────────────────────────────────────────

def get_token(
    key_path: str = _UNSET,
    passphrase: bytes | None = DEFAULT_KEY_PASSPHRASE,
    cert_path: str | None = None,
    agent_pubkey: str | None = None,
) -> str:
    """
    Generate a signed authentication token for pam_pg_sshkey.

    This is the core function.  Call it once, then pass the returned string
    as the password= parameter to psycopg2.connect() or any other libpq
    client before the connection is opened.

    The client picks the timestamp and the nonce, so nothing has to exist on
    the server first and a token can be made on any host.  The token is
    single-use (the server records the nonce on the first authentication
    attempt) and expires 60 seconds after its timestamp.

    Args:
        key_path:       Path to the SSH private key file.
                        Supports OpenSSH format, PKCS#8 PEM, and traditional PEM.
                        Defaults to ~/.ssh/id_ed25519.  With agent_pubkey set,
                        a path is rejected (ValueError) and None means
                        "not specified", so a wrapper may forward it.

        passphrase:     Passphrase for encrypted keys, as bytes.
                        None for unencrypted keys.

        cert_path:      OpenSSH certificate for the key (`*-cert.pub` from
                        `ssh-keygen -s`).  Produces a v3 token that the server
                        accepts without an authorized_keys entry when its
                        trusted_ca_keys file lists the signing CA.

        agent_pubkey:   Path to the PUBLIC key file (`.pub`) of an identity the
                        ssh-agent at $SSH_AUTH_SOCK holds.  The token is signed
                        through the agent and the private key is never read, so
                        passphrase-protected keys and forwarded agents work.
                        Cannot be combined with key_path or passphrase
                        (ValueError).  Works with cert_path (v3).  Of the
                        FIDO/security key types only
                        `sk-ssh-ed25519@openssh.com` works, because the server
                        has no ECDSA verifier; its token carries 69 signature
                        bytes (64 raw, the flags byte, the 4-byte counter) and
                        the key must report user presence.  The signature the
                        agent returns is verified against this public key
                        before it becomes a token, except when the file holds
                        a certificate.

    Returns:
        A token string: "<unix_ts>:<64 hex chars>:<base64 signature>", with a
        fourth ":<base64 certificate>" field when cert_path is given.

    Raises:
        KeyError_:      if the key or the certificate cannot be read, the
                        ssh-agent cannot be reached or refuses, or signing
                        fails.
    """
    if agent_pubkey is not None:
        if key_path is not _UNSET and key_path is not None:
            raise ValueError(
                "agent_pubkey takes the PUBLIC key file and signs through the "
                "ssh-agent; do not also pass key_path"
            )
        if passphrase is not None:
            raise ValueError(
                "agent_pubkey signs through the ssh-agent, which holds the "
                "unlocked key; a passphrase has nothing to unlock here"
            )
        key = None
    else:
        if key_path is _UNSET:
            key_path = DEFAULT_KEY_PATH
        # Load the private key first, so a bad key fails before any signing
        key = _load_private_key(key_path, passphrase)

    prefix = _SIGN_PREFIX_V2 if cert_path is None else _SIGN_PREFIX_V3
    head = f"{int(time.time())}:{secrets.token_bytes(32).hex()}"
    message = prefix + head.encode("ascii")
    if agent_pubkey is not None:
        sig = _agent_sign(agent_pubkey, message)
    else:
        sig = _sign_message(key, message)
    token = f"{head}:{base64.b64encode(sig).decode('ascii')}"
    if cert_path is None:
        return token
    # v3: the same message under its own prefix, plus the certificate.
    return f"{token}:{_load_cert_b64(cert_path)}"


def connect(
    key_path: str = _UNSET,
    passphrase: bytes | None = DEFAULT_KEY_PASSPHRASE,
    cert_path: str | None = None,
    agent_pubkey: str | None = None,
    **psycopg2_kwargs: Any,
) -> Any:
    """
    Open a psycopg2 connection authenticated via SSH key.

    Generates a token and passes it as password= before calling
    psycopg2.connect(). All other keyword arguments are forwarded
    to psycopg2.connect() unchanged.

    Args:
        key_path:         SSH private key path.
        passphrase:       Key passphrase (bytes) or None.
        cert_path:        OpenSSH certificate for the key; see get_token().
        agent_pubkey:     Public key of an ssh-agent identity; see get_token().
        **psycopg2_kwargs: Passed directly to psycopg2.connect().
                           Do NOT include password=, it is set by this function.

    Returns:
        A psycopg2 connection object.

    Example:
        conn = connect(user="alice", dbname="mydb", host="dbserver")
        cur = conn.cursor()
        cur.execute("SELECT 1")
        print(cur.fetchone())
        conn.close()
    """
    try:
        import psycopg2
    except ImportError:
        raise ImportError(
            "psycopg2 is not installed.\n"
            "Install it with:  pip install psycopg2-binary"
        )

    if "password" in psycopg2_kwargs:
        raise ValueError(
            "Do not pass password= to pam_pg_sshkey.connect(). "
            "The signed token is set automatically."
        )

    token = get_token(
        key_path=key_path,
        passphrase=passphrase,
        cert_path=cert_path,
        agent_pubkey=agent_pubkey,
    )

    return psycopg2.connect(password=token, **psycopg2_kwargs)


def connect_replication(
    key_path: str = _UNSET,
    passphrase: bytes | None = DEFAULT_KEY_PASSPHRASE,
    replication: str | bool = "database",
    cert_path: str | None = None,
    agent_pubkey: str | None = None,
    **psycopg2_kwargs: Any,
) -> Any:
    """
    Open a psycopg2 replication connection authenticated via SSH key.

    For use by logical or physical replication subscribers. Sets
    replication="database" (logical) or replication=true (physical) and
    picks the matching psycopg2 connection_factory automatically.

    Each call mints a fresh single-use token, so call it again on every
    reconnect.  A token can NOT be stored in a server-side subscription
    (CREATE SUBSCRIPTION ... CONNECTION 'password=...'): PostgreSQL's apply
    and tablesync workers each open their own connection with that same
    string, and the token is consumed by the first one.

    The publisher's pg_hba.conf must have a pam entry covering the
    'replication' database:

        host  replication  replicator  <subscriber_ip>/32  pam  pamservice=postgresql

    The replication user must exist with the REPLICATION attribute:

        CREATE USER replicator REPLICATION;

    Args:
        key_path:            SSH private key path.
        passphrase:          Key passphrase (bytes) or None.
        replication:         "database" for logical (default); True or any
                             libpq truthy spelling ("true", "on", "yes", "1")
                             for physical.  A subscriber signs its own token,
                             so no step on the publisher is needed first.
        cert_path:           OpenSSH certificate for the key; see get_token().
        agent_pubkey:        Public key of an ssh-agent identity; see get_token().
        **psycopg2_kwargs:   Passed to psycopg2.connect() (user, host, dbname, etc.).

    Returns:
        A psycopg2 replication connection object.

    Example (logical replication):
        conn = connect_replication(
            user="replicator",
            host="publisher.example.com",
            dbname="mydb",
        )
        cur = conn.cursor()
        cur.create_replication_slot("my_slot", output_plugin="pgoutput")
        cur.start_replication(slot_name="my_slot", decode=True)
        for msg in cur:
            print(msg.payload)
            msg.cursor.send_feedback(flush_lsn=msg.data_start)

    Example (physical replication):
        conn = connect_replication(
            user="replicator",
            host="publisher.example.com",
            dbname="mydb",
            replication=True,
        )
    """
    try:
        import psycopg2
        from psycopg2.extras import (
            LogicalReplicationConnection,
            PhysicalReplicationConnection,
        )
    except ImportError:
        raise ImportError(
            "psycopg2 is not installed.\n"
            "Install it with:  pip install psycopg2-binary"
        )

    if "password" in psycopg2_kwargs:
        raise ValueError(
            "Do not pass password= to pam_pg_sshkey.connect_replication(). "
            "The signed token is set automatically."
        )

    token = get_token(
        key_path=key_path,
        passphrase=passphrase,
        cert_path=cert_path,
        agent_pubkey=agent_pubkey,
    )

    # libpq accepts replication=true/on/yes/1 for a physical (walsender)
    # connection and replication=database for a logical one.  Normalise the
    # Python bool so libpq never sees the string 'True'.
    if replication is True:
        replication = "true"
    elif replication is False:
        replication = "false"

    if "connection_factory" not in psycopg2_kwargs:
        if replication == "database":
            psycopg2_kwargs["connection_factory"] = LogicalReplicationConnection
        elif isinstance(replication, str) and replication.lower() in _PHYSICAL_REPLICATION:
            psycopg2_kwargs["connection_factory"] = PhysicalReplicationConnection

    return psycopg2.connect(
        password=token,
        replication=replication,
        **psycopg2_kwargs,
    )
