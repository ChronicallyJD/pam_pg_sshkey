#!/usr/bin/env python3
"""
pg_sshkey_query.py

Connect to a PostgreSQL database using SSH-key authentication
(pam_pg_sshkey) and run a query.

This script replicates the token-generation flow of pg_sshkey_connect
in pure Python, then uses psycopg2 to open the connection with the
signed token as the password.

WHY THE TOKEN MUST BE PRE-COMPUTED
====================================
PostgreSQL sends AUTH_REQ_PASSWORD immediately when the connection opens.
libpq (and therefore psycopg2) checks for a pre-loaded password at that
exact moment. If no password is available, libpq disconnects immediately
with "fe_sendauth: no password supplied" — before any user code runs.

This means:
  - The token (challenge hex + base64 signature) must be computed BEFORE
    psycopg2.connect() is called.
  - The token is passed as the password= argument to psycopg2.connect(),
    where libpq holds it ready to send the instant AUTH_REQ_PASSWORD arrives.

Usage:
  python3 pg_sshkey_query.py [OPTIONS]

  -U, --username USER     PostgreSQL username        (default: $USER)
  -h, --host HOST         Host or socket directory   (default: local socket)
  -p, --port PORT         Port                       (default: 5432)
  -d, --dbname DBNAME     Database name              (default: username)
  -i, --identity FILE     SSH private key            (default: ~/.ssh/id_ed25519)
  -c, --challenge-dir DIR Challenge nonce directory  (default: /var/run/pg_sshkey)
  -q, --query SQL         Query to run               (default: SELECT 1)
  -v, --verbose           Print each step to stderr

Requirements:
  pip install psycopg2-binary

  pg_sshkey_challenge and pg_sshkey_sign must be installed (make install).

SPDX-License-Identifier: MIT
"""

import argparse
import base64
import os
import subprocess
import sys
import tempfile
from pathlib import Path


# ── Token generation ──────────────────────────────────────────────────────────

def generate_challenge(challenge_dir: str, verbose: bool) -> str:
    """
    Run pg_sshkey_challenge to create a nonce.
    Returns the 64-char hex challenge ID.
    Raises RuntimeError on failure.
    """
    if verbose:
        print(f"[pg_sshkey_query] generating challenge in {challenge_dir}", file=sys.stderr)

    result = subprocess.run(
        ["pg_sshkey_challenge", challenge_dir],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"pg_sshkey_challenge failed (exit {result.returncode}).\n"
            f"stderr: {result.stderr.strip()}\n\n"
            f"Check that {challenge_dir} exists and is writable:\n"
            f"  ls -la {challenge_dir}\n"
            f"  sudo chmod 1733 {challenge_dir}\n"
            f"  sudo chown postgres:postgres {challenge_dir}"
        )

    challenge = result.stdout.strip()

    # Validate: must be exactly 64 lowercase hex characters
    if len(challenge) != 64 or not all(c in "0123456789abcdef" for c in challenge):
        raise RuntimeError(
            f"pg_sshkey_challenge produced invalid output: {challenge!r}\n"
            f"Expected 64 lowercase hex characters."
        )

    if verbose:
        print(f"[pg_sshkey_query] challenge: {challenge}", file=sys.stderr)

    return challenge


def sign_challenge(challenge: str, key_path: str, verbose: bool) -> str:
    """
    Run pg_sshkey_sign to produce a signed token.
    Returns the token string "<challenge_hex>:<base64_signature>".
    Raises RuntimeError on failure.
    """
    if verbose:
        print(f"[pg_sshkey_query] signing with {key_path}", file=sys.stderr)

    if not Path(key_path).exists():
        raise RuntimeError(
            f"SSH key not found: {key_path}\n\n"
            f"Generate one with:\n"
            f"  ssh-keygen -t ed25519 -f {key_path} -N ''\n\n"
            f"Then register the public key:\n"
            f"  sudo pg_sshkey_addkey <username> {key_path}.pub"
        )

    result = subprocess.run(
        ["pg_sshkey_sign", challenge, key_path],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"pg_sshkey_sign failed (exit {result.returncode}).\n"
            f"stderr: {result.stderr.strip()}\n\n"
            f"Key format support:\n"
            f"  ~/.ssh/id_ed25519   OpenSSH Ed25519 (unencrypted) ✓\n"
            f"  key.pem             PKCS#8 PEM (any type) ✓\n\n"
            f"For OpenSSH RSA or passphrase-protected keys, convert first:\n"
            f"  openssl pkey -in {key_path} -out key.pem\n"
            f"  # use key.pem as the identity file"
        )

    token = result.stdout.strip()

    # Validate token format: <64hex>:<base64>
    parts = token.split(":", 1)
    if (len(parts) != 2
            or len(parts[0]) != 64
            or not all(c in "0123456789abcdef" for c in parts[0])
            or len(parts[1]) < 4):
        raise RuntimeError(
            f"pg_sshkey_sign produced invalid token: {token!r}\n"
            f"Expected format: <64 hex chars>:<base64 signature>"
        )

    if verbose:
        print(f"[pg_sshkey_query] token: {token[:72]}...", file=sys.stderr)

    return token


# ── Database connection ───────────────────────────────────────────────────────

def connect_and_query(
    username: str,
    dbname: str,
    token: str,
    host: str | None,
    port: int,
    query: str,
    verbose: bool,
) -> list[tuple]:
    """
    Open a psycopg2 connection with the signed token as the password,
    run the query, and return the results as a list of rows.

    The token must be pre-computed before this function is called.
    psycopg2 passes it to libpq as password=, which holds it ready to
    send the instant PostgreSQL issues AUTH_REQ_PASSWORD.
    """
    try:
        import psycopg2
    except ImportError:
        raise RuntimeError(
            "psycopg2 is not installed.\n"
            "Install it with:\n"
            "  pip install psycopg2-binary"
        )

    # Build connection parameters.
    # host=None means use the Unix socket (same as omitting -h in psql).
    conn_params = {
        "user":     username,
        "dbname":   dbname,
        "password": token,   # pre-computed signed token — libpq sends on AUTH_REQ_PASSWORD
        "port":     port,
        "connect_timeout": 10,
    }
    if host:
        conn_params["host"] = host

    if verbose:
        print(
            f"[pg_sshkey_query] connecting: user={username} "
            f"dbname={dbname} host={host or '<local socket>'} port={port}",
            file=sys.stderr,
        )

    try:
        conn = psycopg2.connect(**conn_params)
    except psycopg2.OperationalError as e:
        msg = str(e).strip()
        hint = ""
        if "no password supplied" in msg:
            hint = (
                "\nThis should not happen with pg_sshkey_query.\n"
                "It means the token was not passed to psycopg2.connect().\n"
                "This is a bug — please report it."
            )
        elif "PAM authentication failed" in msg:
            hint = (
                "\nThe PAM module rejected the token. Possible causes:\n"
                "  1. The challenge expired (> 60 seconds between steps)\n"
                "  2. The authorized_keys file is missing or unreadable:\n"
                f"       sudo pg_sshkey_addkey {username} ~/.ssh/id_ed25519.pub\n"
                "  3. The wrong key was used to sign the challenge\n"
                "  4. The authorized_keys file has wrong permissions:\n"
                "       sudo chown root:postgres /etc/pg_sshkeys/"
                f"{username}/authorized_keys\n"
                "       sudo chmod 640 /etc/pg_sshkeys/"
                f"{username}/authorized_keys\n\n"
                "Check the PostgreSQL log for details:\n"
                "  journalctl -t postgresql --since '1 minute ago' | grep pam_pg_sshkey"
            )
        elif "could not connect to server" in msg:
            hint = (
                "\nPostgreSQL is not running or the socket path is wrong.\n"
                "Check that PostgreSQL is running:\n"
                "  sudo systemctl status postgresql@16-main"
            )
        raise RuntimeError(f"Connection failed: {msg}{hint}") from None

    conn.autocommit = True
    cur = conn.cursor()

    try:
        cur.execute(query)
        if cur.description:
            rows = cur.fetchall()
        else:
            rows = []
    finally:
        cur.close()
        conn.close()

    return rows


# ── Output formatting ─────────────────────────────────────────────────────────

def print_results(rows: list[tuple], query: str) -> None:
    """Print query results in a simple tabular format."""
    if not rows:
        print("(no rows returned)")
        return

    # Determine column widths
    col_count = len(rows[0])
    widths = [max(len(str(row[i])) for row in rows) for i in range(col_count)]

    # Print rows
    for row in rows:
        parts = [str(row[i]).ljust(widths[i]) for i in range(col_count)]
        print("  " + "  |  ".join(parts))

    count = len(rows)
    print(f"\n({count} row{'s' if count != 1 else ''})")


# ── Argument parsing ──────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="pg_sshkey_query",
        add_help=False,
        description=(
            "Connect to PostgreSQL using SSH-key authentication "
            "(pam_pg_sshkey) and run a query."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 pg_sshkey_query.py
  python3 pg_sshkey_query.py -U alice -d mydb
  python3 pg_sshkey_query.py -U alice -q "SELECT version()"
  python3 pg_sshkey_query.py -i ~/.ssh/pg_key.pem -U alice mydb
  python3 pg_sshkey_query.py -v -U alice         # verbose: show each step
""",
    )

    parser.add_argument(
        "-U", "--username",
        default=os.environ.get("PGUSER", os.environ.get("USER", "")),
        metavar="USER",
        help="PostgreSQL username (default: $PGUSER or $USER)",
    )
    parser.add_argument(
        "-h", "--host",
        default=os.environ.get("PGHOST", None),
        metavar="HOST",
        help="PostgreSQL host (default: local Unix socket)",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=int(os.environ.get("PGPORT", "5432")),
        metavar="PORT",
        help="PostgreSQL port (default: 5432)",
    )
    parser.add_argument(
        "--help", action="help",
        help="Show this help message and exit",
    )
    parser.add_argument(
        "-d", "--dbname",
        default=None,
        metavar="DBNAME",
        help="Database name (default: username)",
    )
    parser.add_argument(
        "-i", "--identity",
        default=str(Path.home() / ".ssh" / "id_ed25519"),
        metavar="FILE",
        help="SSH private key file (default: ~/.ssh/id_ed25519)",
    )
    parser.add_argument(
        "-c", "--challenge-dir",
        default="/var/run/pg_sshkey",
        metavar="DIR",
        help="Challenge nonce directory (default: /var/run/pg_sshkey)",
    )
    parser.add_argument(
        "-q", "--query",
        default="SELECT 1",
        metavar="SQL",
        help='Query to execute (default: "SELECT 1")',
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print each step to stderr",
    )
    # Positional dbname (like psql)
    parser.add_argument(
        "dbname_positional",
        nargs="?",
        default=None,
        metavar="DBNAME",
        help="Database name (positional alternative to -d)",
    )

    return parser.parse_args()


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    args = parse_args()

    # Resolve database name: -d flag > positional > username
    dbname = args.dbname or args.dbname_positional or args.username
    if not args.username:
        print(
            "error: no username specified. Use -U or set PGUSER.",
            file=sys.stderr,
        )
        return 1

    if args.verbose:
        print(f"[pg_sshkey_query] username:      {args.username}", file=sys.stderr)
        print(f"[pg_sshkey_query] database:      {dbname}", file=sys.stderr)
        print(f"[pg_sshkey_query] host:          {args.host or '<local socket>'}", file=sys.stderr)
        print(f"[pg_sshkey_query] key:           {args.identity}", file=sys.stderr)
        print(f"[pg_sshkey_query] challenge dir: {args.challenge_dir}", file=sys.stderr)
        print(f"[pg_sshkey_query] query:         {args.query}", file=sys.stderr)

    try:
        # Step 1: generate challenge nonce
        challenge = generate_challenge(args.challenge_dir, args.verbose)

        # Step 2: sign the challenge with the SSH private key
        token = sign_challenge(challenge, args.identity, args.verbose)

        # Step 3: connect and run the query
        # The token is passed as password= BEFORE the connection opens.
        rows = connect_and_query(
            username=args.username,
            dbname=dbname,
            token=token,
            host=args.host,
            port=args.port,
            query=args.query,
            verbose=args.verbose,
        )

        # Step 4: display results
        print_results(rows, args.query)

    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
