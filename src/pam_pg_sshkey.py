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
    token = get_token(
        key_path="~/.ssh/id_ed25519",
        challenge_dir="/var/run/pg_sshkey",
    )
    conn = psycopg2.connect(
        host="publisher.example.com",
        user="replicator",
        dbname="mydb",
        password=token,
    )

    # Or use the convenience wrappers:
    conn = connect(user="alice", dbname="mydb")
    conn = connect_replication(user="replicator", host="publisher.example.com")

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
import os
import secrets
import stat
import time
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any, Sequence

# ── Imports with helpful errors ───────────────────────────────────────────────

try:
    from cryptography.hazmat.primitives.serialization import (
        load_ssh_private_key,
        load_pem_private_key,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
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
_SIGN_PREFIX: bytes = b"pg-sshkey-v1\x00"        # v1: server-issued nonce file
_SIGN_PREFIX_V2: bytes = b"pg-sshkey-v2\x00"     # v2: client-issued challenge

# Token versions:
#   2 (default)  "<unix_ts>:<nonce_hex>:<sig>", message = PREFIX_V2 + "<ts>:<nonce_hex>".
#                The client picks timestamp and nonce; nothing is created on the
#                server beforehand; works from any host.  The server accepts
#                |now - ts| <= 60 s and records each nonce on first use.
#   1 (legacy)   "<nonce_hex>:<sig>" over a nonce file that must already exist
#                in the SERVER's challenge_dir (local file or challenge_cmd).
DEFAULT_TOKEN_VERSION: int = 2

# Default paths
DEFAULT_CHALLENGE_DIR: str = "/var/run/pg_sshkey"
# Resolved lazily-safe: importing must never fail just because HOME is unset
# (DynamicUser services, `docker run --user`), callers may pass key_path.
try:
    DEFAULT_KEY_PATH: str | None = str(Path.home() / ".ssh" / "id_ed25519")
except RuntimeError:
    DEFAULT_KEY_PATH = None
DEFAULT_KEY_PASSPHRASE: bytes | None = None

# Spellings libpq treats as "physical replication connection"
_PHYSICAL_REPLICATION = frozenset({"true", "on", "yes", "1"})

# Challenge TTL (seconds), must match CHALLENGE_TTL_SECS in challenge_store.h
CHALLENGE_TTL_SECS: int = 60


# ── Exceptions ────────────────────────────────────────────────────────────────

class PamPgSshKeyError(Exception):
    """Base exception for all pam_pg_sshkey errors."""

class ChallengeError(PamPgSshKeyError):
    """Failed to create or read the challenge nonce."""

class KeyError_(PamPgSshKeyError):
    """Failed to load or use the private key."""
    # Named with trailing _ to avoid shadowing Python's built-in KeyError


# ── Challenge creation ────────────────────────────────────────────────────────

def _create_challenge(challenge_dir: str) -> tuple[str, bytes]:
    """
    Generate a 32-byte nonce, write it to challenge_dir/<hex>, and return
    (hex_id, raw_bytes).

    The file is written atomically with mode 0644 so the postgres-owned PAM
    module can read it regardless of which OS user runs this function.

    Raises ChallengeError if the directory is not writable.
    """
    dirpath = Path(challenge_dir)

    if not dirpath.exists():
        try:
            dirpath.mkdir(mode=0o1733, parents=False)
        except OSError as e:
            raise ChallengeError(
                f"Challenge directory does not exist and could not be created: "
                f"{challenge_dir}\n\n"
                f"Fix with (as root):\n"
                f"  sudo mkdir -p {challenge_dir}\n"
                f"  sudo chown postgres:postgres {challenge_dir}\n"
                f"  sudo chmod 1733 {challenge_dir}"
            ) from e

    if not os.access(challenge_dir, os.W_OK | os.X_OK):
        raise ChallengeError(
            f"Cannot write to challenge directory: {challenge_dir}\n\n"
            f"Current permissions:\n"
            f"  {oct(dirpath.stat().st_mode)}\n\n"
            f"Fix with (as root):\n"
            f"  sudo chown postgres:postgres {challenge_dir}\n"
            f"  sudo chmod 1733 {challenge_dir}"
        )

    raw = secrets.token_bytes(32)
    hex_id = raw.hex()
    nonce_path = dirpath / hex_id

    # Write atomically: exclusive create so two simultaneous calls never collide
    try:
        fd = os.open(str(nonce_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        # os.open() applies the umask; a client under umask 077 would leave a
        # 0600 nonce that the postgres-run PAM module cannot read.
        os.fchmod(fd, 0o644)
    except FileExistsError:
        # Astronomically unlikely (32-byte collision) but handle gracefully
        raw = secrets.token_bytes(32)
        hex_id = raw.hex()
        nonce_path = dirpath / hex_id
        fd = os.open(str(nonce_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)

    with os.fdopen(fd, "w") as f:
        f.write(f"{int(time.time())}\n{hex_id}\n")

    return hex_id, raw


# ── Remote challenge ──────────────────────────────────────────────────────────

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

def _remote_challenge(challenge_cmd: str | Sequence[str]) -> tuple[str, bytes]:
    """
    Mint the nonce ON THE SERVER by running challenge_cmd and reading the
    64-hex nonce it prints, typically

        "ssh dbserver pg_sshkey_challenge /var/run/pg_sshkey"

    The PAM module only ever looks in the server's own challenge_dir, so a
    client on another host cannot use a locally created nonce.  A str is run
    through the shell; a sequence is exec'd directly.

    Returns (hex_id, raw_bytes).  Raises ChallengeError on any failure.
    """
    shown = challenge_cmd if isinstance(challenge_cmd, str) else shlex.join(challenge_cmd)
    try:
        r = subprocess.run(
            challenge_cmd,
            shell=isinstance(challenge_cmd, str),
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ChallengeError(f"challenge_cmd could not run ({shown}): {e}") from e

    if r.returncode != 0:
        raise ChallengeError(
            f"challenge_cmd failed (exit {r.returncode}): {shown}\n"
            f"{r.stderr.strip()}"
        )
    hex_id = r.stdout.strip()
    if not _HEX64.match(hex_id):
        raise ChallengeError(
            f"challenge_cmd did not print a 64-hex nonce: {shown}\n"
            f"got: {hex_id[:80]!r}"
        )
    return hex_id, bytes.fromhex(hex_id)


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


# ── Signing ───────────────────────────────────────────────────────────────────

def _sign_message(key: Ed25519PrivateKey | RSAPrivateKey, message: bytes) -> bytes:
    """Sign an already-built message (Ed25519 raw; RSA PKCS#1 v1.5 / SHA-256)."""
    if isinstance(key, Ed25519PrivateKey):
        return key.sign(message)
    return key.sign(message, asym_padding.PKCS1v15(), hashes.SHA256())


def _sign(key: Ed25519PrivateKey | RSAPrivateKey, challenge_bytes: bytes) -> bytes:
    """
    Sign the canonical message: SIGN_PREFIX || challenge_bytes.

    Ed25519: signs the message directly (internal SHA-512 hash).
    RSA:     RSASSA-PKCS1-v1_5 with SHA-256 (matches rsa-sha2-256 in the PAM module).
    """
    message = _SIGN_PREFIX + challenge_bytes

    if isinstance(key, Ed25519PrivateKey):
        return key.sign(message)
    elif isinstance(key, RSAPrivateKey):
        return key.sign(message, asym_padding.PKCS1v15(), hashes.SHA256())
    else:
        raise KeyError_(f"Cannot sign with key type: {type(key).__name__}")


# ── Public API ────────────────────────────────────────────────────────────────

def get_token(
    key_path: str = DEFAULT_KEY_PATH,
    challenge_dir: str = DEFAULT_CHALLENGE_DIR,
    passphrase: bytes | None = DEFAULT_KEY_PASSPHRASE,
    challenge_cmd: str | Sequence[str] | None = None,
    version: int = DEFAULT_TOKEN_VERSION,
) -> str:
    """
    Generate a signed authentication token for pam_pg_sshkey.

    This is the core function.  Call it once, then pass the returned string
    as the password= parameter to psycopg2.connect() or any other libpq
    client before the connection is opened.

    The token is single-use (the nonce is consumed by the PAM module on the
    first authentication attempt) and expires in 60 seconds.

    Args:
        key_path:      Path to the SSH private key file.
                       Supports OpenSSH format, PKCS#8 PEM, and traditional PEM.
        challenge_dir: Directory where nonce files are stored.
                       Must be writable and exist with mode 1733.
        passphrase:    Passphrase for encrypted keys, as bytes.
                       None for unencrypted keys.

    Returns:
        A token string: "<64 hex chars>:<base64 signature>"

        challenge_cmd:  Command that mints the nonce on the SERVER and prints
                        it, e.g. "ssh dbserver pg_sshkey_challenge /var/run/pg_sshkey".
                        Required when the server is another host; challenge_dir
                        is then ignored and nothing is written locally.

        version:        2 (default): client-issued challenge, no server-side
                        step, works from any host.  1: legacy server nonce
                        (challenge_dir / challenge_cmd).

    Raises:
        ChallengeError: if the challenge directory is missing or unwritable.
        KeyError_:      if the key cannot be loaded or signing fails.
    """
    # 1. Load the private key first (fail fast before creating a nonce)
    key = _load_private_key(key_path, passphrase)

    if challenge_cmd is not None:
        version = 1                      # a server-minted nonce is v1 by definition
    if version not in (1, 2):
        raise ValueError(f"unsupported token version {version!r} (1 or 2)")

    if version == 2:
        # v2: issue our own challenge.  Nothing touches the filesystem.
        head = f"{int(time.time())}:{secrets.token_bytes(32).hex()}"
        sig = _sign_message(key, _SIGN_PREFIX_V2 + head.encode("ascii"))
        return f"{head}:{base64.b64encode(sig).decode('ascii')}"

    # v1: the nonce must exist in the SERVER's challenge_dir
    if challenge_cmd is not None:
        hex_id, raw_bytes = _remote_challenge(challenge_cmd)
    else:
        hex_id, raw_bytes = _create_challenge(challenge_dir)

    # Sign: message = "pg-sshkey-v1\0" || challenge_bytes
    sig = _sign(key, raw_bytes)
    sig_b64 = base64.b64encode(sig).decode("ascii")
    return f"{hex_id}:{sig_b64}"


def connect(
    key_path: str = DEFAULT_KEY_PATH,
    challenge_dir: str = DEFAULT_CHALLENGE_DIR,
    passphrase: bytes | None = DEFAULT_KEY_PASSPHRASE,
    challenge_cmd: str | Sequence[str] | None = None,
    version: int = DEFAULT_TOKEN_VERSION,
    **psycopg2_kwargs: Any,
) -> Any:
    """
    Open a psycopg2 connection authenticated via SSH key.

    Generates a token and passes it as password= before calling
    psycopg2.connect(). All other keyword arguments are forwarded
    to psycopg2.connect() unchanged.

    Args:
        key_path:         SSH private key path.
        challenge_dir:    Challenge nonce directory.
        passphrase:       Key passphrase (bytes) or None.
        challenge_cmd:    See get_token(); required when host= is another machine.
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
        challenge_dir=challenge_dir,
        passphrase=passphrase,
        challenge_cmd=challenge_cmd,
        version=version,
    )

    return psycopg2.connect(password=token, **psycopg2_kwargs)


def connect_replication(
    key_path: str = DEFAULT_KEY_PATH,
    challenge_dir: str = DEFAULT_CHALLENGE_DIR,
    passphrase: bytes | None = DEFAULT_KEY_PASSPHRASE,
    replication: str | bool = "database",
    challenge_cmd: str | Sequence[str] | None = None,
    version: int = DEFAULT_TOKEN_VERSION,
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
        challenge_dir:       Challenge nonce directory.
        passphrase:          Key passphrase (bytes) or None.
        replication:         "database" for logical (default); True or any
                             libpq truthy spelling ("true", "on", "yes", "1")
                             for physical.
        challenge_cmd:       See get_token().  A subscriber on another host
                             MUST pass this, e.g.
                             "ssh publisher pg_sshkey_challenge /var/run/pg_sshkey".
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
        challenge_dir=challenge_dir,
        passphrase=passphrase,
        challenge_cmd=challenge_cmd,
        version=version,
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
