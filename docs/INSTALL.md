# pam_pg_sshkey — Installation & Configuration Manual

Version 1.0.8 · June 2026

---

## Table of Contents

1. [Overview](#1-overview)
2. [System Requirements](#2-system-requirements)
3. [Project Layout](#3-project-layout)
4. [Building from Source](#4-building-from-source)
5. [Running the Test Suite](#5-running-the-test-suite)
6. [Installation](#6-installation)
7. [PostgreSQL Configuration](#7-postgresql-configuration)
8. [PAM Configuration](#8-pam-configuration)
9. [Deploying SSH Public Keys](#9-deploying-ssh-public-keys)
10. [Why You Must Use pg_sshkey_connect](#10-why-you-must-use-pg_sshkey_connect)
11. [Connecting as a User](#11-connecting-as-a-user)
12. [Python Integration](#12-python-integration)
13. [Logical Replication with SSH Key Authentication](#13-logical-replication-with-ssh-key-authentication)
14. [Module Reference](#14-module-reference)
15. [File & Directory Permissions Reference](#15-file--directory-permissions-reference)
16. [Logging & Troubleshooting](#16-logging--troubleshooting)
17. [Uninstalling](#17-uninstalling)
18. [Security Hardening Checklist](#18-security-hardening-checklist)

---

## 1. Overview

`pam_pg_sshkey` lets PostgreSQL authenticate database users via **SSH
public-key cryptography** instead of passwords.  The database stores only
public keys; private keys never leave the client machine.

This makes it suitable for automated systems — replication subscribers,
application servers, Python scripts — where storing a plaintext password
is unacceptable.

### Authentication flow

```
Client                                  Server
  │                                        │
  │  pg_sshkey_connect -U alice mydb       │
  │   (or any libpq client with a token)   │
  │                                        │
  │  1. generate nonce ───────────────────►│ writes /var/run/pg_sshkey/<hex>
  │◄─ 2. <64-char hex nonce> ─────────────│
  │                                        │
  │  3. sign nonce with SSH private key    │
  │     → <hex>:<base64_signature>         │
  │                                        │
  │  4. connect with token as password ───►│ PostgreSQL
  │                                        │   → PAM → pam_pg_sshkey.so
  │                                        │       parse token
  │                                        │       load + delete nonce (60s TTL)
  │                                        │       read authorized_keys
  │                                        │       verify Ed25519/RSA signature
  │◄─ 5. authenticated session ────────────│ PAM_SUCCESS
```

Key properties:

- **No shared secret** — the database stores public keys only
- **Replay-proof** — each nonce is single-use with a 60-second TTL
- **Domain-separated** — signed message includes `"pg-sshkey-v1\0"` prefix
- **Standard format** — uses OpenSSH `authorized_keys` files
- **Scriptable** — works from Python, shell, and any libpq-based client

---

## 2. System Requirements

### Supported distributions

| Distribution          | Minimum version | Notes                             |
|-----------------------|-----------------|-----------------------------------|
| Ubuntu                | 22.04 LTS       | Tested on 22.04, 24.04            |
| Debian                | 12 (Bookworm)   | Tested on 12                      |
| RHEL / Rocky / Alma   | 9.x             | Set `PAM_LIB_DIR=/lib64/security` |

### PostgreSQL requirement

PostgreSQL **14 or later** is required.  Verify PAM support is compiled in:

```bash
psql --version                                  # must print 14.x or later
pg_config --configure | grep '\-\-with-pam'     # must print: --with-pam
```

### Build dependencies

```bash
sudo apt update
sudo apt install build-essential libssl-dev libpam0g-dev pkg-config
```

| Package          | Provides                         | Why needed                                      |
|------------------|----------------------------------|-------------------------------------------------|
| `build-essential`| gcc, make, dpkg-dev, libc6-dev   | Compiler, linker, make, gcc -dumpmachine triplet|
| `libssl-dev`     | OpenSSL headers + libcrypto.so   | Ed25519/RSA signing, RAND_bytes, base64         |
| `libpam0g-dev`   | PAM headers + libpam.so          | Compile and link the PAM shared module          |
| `pkg-config`     | pkg-config tool                  | Locates OpenSSL flags automatically             |

### Python dependencies (optional — for utils/ scripts)

```bash
pip install psycopg2-binary cryptography
pip install bcrypt          # only needed for passphrase-protected SSH keys
```

---

## 3. Project Layout

```
pam_pg_sshkey-1.0.8/
│
├── src/                        C source and shell/Python tools
│   ├── pam_pg_sshkey.c         PAM module entry point
│   ├── challenge_store.[ch]    Filesystem-backed nonce store
│   ├── key_parser.[ch]         authorized_keys → EVP_PKEY parser
│   ├── sig_verify.[ch]         Ed25519/RSA signature verification
│   ├── pg_sshkey_challenge.c   Server nonce generator (compiled binary)
│   ├── pg_sshkey_sign.c        Client signing tool (compiled binary)
│   ├── pg_sshkey_connect       Bash wrapper: generate token and exec psql
│   ├── pg_sshkey_addkey        Bash admin script: deploy public keys
│   ├── pg_sshkey_query.py      Python query helper (uses pam_pg_sshkey.py)
│   └── pam_pg_sshkey.py        Python module: token generation for psycopg2
│
├── utils/                      Example programs and integration scripts
│   └── select1.py              Minimal psycopg2 example: SSH-key auth + SELECT 1
│
├── tests/                      Test suites
│   ├── test_framework.h        Single-header C test framework
│   ├── test_challenge_store.c  Unit tests: nonce store
│   ├── test_key_parser.c       Unit tests: authorized_keys parsing
│   ├── test_sig_verify.c       Unit tests: signature verification
│   ├── test_integration.c      Integration tests: full auth flow
│   ├── test_system.c           System tests: compiled tools end-to-end
│   └── test_python_module.py   Unit tests: pam_pg_sshkey.py
│
├── config/
│   └── pam.d/postgresql        Drop-in PAM service configuration
│
├── docs/
│   ├── INSTALL.md              This file
│   └── CHANGELOG.md            Version history
│
└── Makefile
```

### utils/ directory

The `utils/` directory contains example programs that demonstrate how to
use pam_pg_sshkey authentication from application code.  These are
**starting points**, not installed binaries — copy and adapt them for
your own use case.

| File          | Description                                              |
|---------------|----------------------------------------------------------|
| `select1.py`  | Minimal standalone Python script: authenticate via SSH key and run `SELECT 1`. No external dependencies beyond `psycopg2` and `cryptography`. Implements token generation inline — no import of `pam_pg_sshkey.py` required. |

---

## 4. Building from Source

```bash
tar -xzf pam_pg_sshkey-1.0.8.tar.gz
cd pam_pg_sshkey-1.0.8
make
```

Output files built in the project root:

| File                  | Description                                     |
|-----------------------|-------------------------------------------------|
| `pam_pg_sshkey.so`    | PAM module — installed to the security dir      |
| `pg_sshkey_challenge` | Server tool: generate a nonce                   |
| `pg_sshkey_sign`      | Client tool: sign a nonce with an SSH key       |
| `pg_sshkey_connect`   | Client script: full connect wrapper             |
| `pg_sshkey_addkey`    | Admin script: deploy public keys correctly      |
| `pg_sshkey_query`     | Python query helper script                      |

### Common build errors

| Error                                       | Missing package    | Fix                               |
|---------------------------------------------|--------------------|-----------------------------------|
| `fatal error: openssl/evp.h: No such file`  | `libssl-dev`       | `sudo apt install libssl-dev`     |
| `fatal error: security/pam_modules.h: ...`  | `libpam0g-dev`     | `sudo apt install libpam0g-dev`   |
| `pkg-config: command not found`             | `pkg-config`       | `sudo apt install pkg-config`     |
| `gcc: command not found`                    | `build-essential`  | `sudo apt install build-essential`|

---

## 5. Running the Test Suite

```bash
make test
```

| Suite                        | Language | Tests | What is covered                            |
|------------------------------|----------|-------|--------------------------------------------|
| `tests/test_challenge_store` | C        | 17    | Nonce create/load/delete, TTL, path safety |
| `tests/test_key_parser`      | C        | 14    | Base64, authorized_keys parsing            |
| `tests/test_sig_verify`      | C        | 16    | Ed25519 and RSA signature verification     |
| `tests/test_integration`     | C        | 4     | Full auth flow, replay prevention          |
| `tests/test_system`          | C        | 14    | Compiled tools end-to-end                  |
| `tests/test_python_module`   | Python   | 32    | pam_pg_sshkey.py: keys, signing, tokens    |

A clean run prints `0 failed` for every C suite and `OK` for the Python suite.

---

## 6. Installation

### Standard install (Debian/Ubuntu)

```bash
sudo make install
sudo make install-conf
```

`make install` places files at:

| Source                | Destination                                      |
|-----------------------|--------------------------------------------------|
| `pam_pg_sshkey.so`    | `/lib/<arch>/security/pam_pg_sshkey.so`          |
| `pg_sshkey_sign`      | `/usr/local/bin/pg_sshkey_sign`                  |
| `pg_sshkey_challenge` | `/usr/local/bin/pg_sshkey_challenge`             |
| `pg_sshkey_connect`   | `/usr/local/bin/pg_sshkey_connect`               |
| `pg_sshkey_addkey`    | `/usr/local/bin/pg_sshkey_addkey`                |
| `pg_sshkey_query`     | `/usr/local/bin/pg_sshkey_query`                 |
| tmpfiles.d config     | `/usr/lib/tmpfiles.d/pg_sshkey.conf`             |

It also creates:

| Directory           | Owner             | Mode | Purpose                      |
|---------------------|-------------------|------|------------------------------|
| `/etc/pg_sshkeys`   | root:postgres     | 0750 | Root of authorized_keys tree |
| `/var/run/pg_sshkey`| postgres:postgres | 1733 | Challenge nonce files        |

`make install-conf` installs `/etc/pam.d/postgresql`.

### RHEL/Fedora

```bash
sudo dnf install gcc make openssl-devel pam-devel pkgconf
sudo make install PAM_LIB_DIR=/lib64/security
sudo make install-conf
```

### Surviving reboots

`/var/run` is a tmpfs wiped at every boot.  The installed `tmpfiles.d`
config recreates the challenge directory at startup:

```
# /usr/lib/tmpfiles.d/pg_sshkey.conf
d /var/run/pg_sshkey 1733 postgres postgres -
```

Apply immediately without rebooting:

```bash
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/pg_sshkey.conf
```

---

## 7. PostgreSQL Configuration

### pg_hba.conf

Open `/etc/postgresql/<version>/main/pg_hba.conf` and add `pam` lines
**before** any existing `peer` or `md5` catch-alls:

```
# TYPE  DATABASE     USER         ADDRESS           METHOD  OPTIONS
local   all          postgres                       peer
local   all          all                            pam     pamservice=postgresql
host    all          all          127.0.0.1/32      scram-sha-256
host    all          all          ::1/128            scram-sha-256
```

For replication connections — see [§13](#13-logical-replication-with-ssh-key-authentication)
for the full replication-specific configuration.

The six columns are positional — `pam` is the METHOD and
`pamservice=postgresql` is the OPTIONS value in the sixth column.

**Wrong** (five columns — options parsed as method name):
```
local  all  all  pamservice=postgresql
```

**Correct** (six columns — method and options separate):
```
local  all  all  pam  pamservice=postgresql
```

### Create PostgreSQL users

PAM handles authentication only; the role must already exist:

```sql
CREATE USER alice;
-- no password needed or wanted
```

### Validate and reload

```sql
-- Check for parse errors before reloading
SELECT line_number, type, error
FROM pg_hba_file_rules
WHERE error IS NOT NULL;
```

```bash
sudo systemctl reload postgresql@16-main   # adjust version
```

---

## 8. PAM Configuration

`/etc/pam.d/postgresql`:

```
#%PAM-1.0
auth    required    pam_pg_sshkey.so \
            authorized_keys_dir=/etc/pg_sshkeys \
            challenge_dir=/var/run/pg_sshkey

account required    pam_permit.so
```

Add `debug` temporarily to see per-attempt detail in syslog — remove it
after diagnosis.

---

## 9. Deploying SSH Public Keys

Always use `pg_sshkey_addkey` (must run as root).  It creates the
per-user directory, writes the key, and enforces `root:postgres 0640`
permissions.  Creating key files manually almost always produces wrong
ownership (`alice:alice 0600`) that the `postgres`-owned PAM module
cannot read.

```bash
# Add a key from a .pub file
sudo pg_sshkey_addkey alice ~/.ssh/id_ed25519.pub

# Add from stdin
ssh-keygen -y -f ~/.ssh/id_ed25519 | sudo pg_sshkey_addkey alice -

# Append a second key
sudo pg_sshkey_addkey --append alice ~/.ssh/id_rsa.pub

# List current keys
sudo pg_sshkey_addkey --list alice

# Remove all keys
sudo pg_sshkey_addkey --remove alice
```

Verify the PAM module can read the file:

```bash
sudo -u postgres cat /etc/pg_sshkeys/alice/authorized_keys
```

### Generate a key for a new user

```bash
# As the database user — Ed25519, no passphrase (required for automated use)
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""

# Register the public key (as root)
sudo pg_sshkey_addkey alice ~/.ssh/id_ed25519.pub
```

### Accepted key types

| Key type     | authorized_keys token | Digest   |
|--------------|-----------------------|----------|
| Ed25519      | `ssh-ed25519`         | internal |
| RSA (≥ 2048) | `ssh-rsa`             | SHA-256  |
| RSA (≥ 2048) | `rsa-sha2-256`        | SHA-256  |
| RSA (≥ 2048) | `rsa-sha2-512`        | SHA-512  |

---

## 10. Why You Must Use pg_sshkey_connect

### The PostgreSQL password handshake

When a client connects using the `pam` auth method, PostgreSQL immediately
sends `AUTH_REQ_PASSWORD`.  libpq responds by checking whether a password
was supplied in the connection parameters — in `PGPASSWORD`, the connection
string, or `~/.pgpass`.  If none is found, **libpq disconnects immediately**
without sending anything.  The PAM module receives a NULL token and logs:

```
pam_pg_sshkey: failed to get auth token for 'alice' (client sent no password)
```

The token must be computed and placed in the connection parameters **before**
the connection is opened.

### Why you cannot type the token at a prompt

The token is 150+ characters of cryptographic material:

```
3a7fb2c1...d4e9:<64-char hex> : xWKq2XCL...MTCA==<base64 signature>
```

It must be computed fresh for every connection.  It cannot be memorised,
typed, or cached.

### What pg_sshkey_connect does

```
1. pg_sshkey_challenge /var/run/pg_sshkey  → 32-byte nonce written to disk
2. pg_sshkey_sign <hex> ~/.ssh/id_ed25519  → <hex>:<base64_signature>
3. PGPASSWORD=<token> exec psql            → token is pre-loaded for libpq
```

### Summary

| What you run                    | What happens                                         |
|---------------------------------|------------------------------------------------------|
| `psql -U alice`                 | libpq gets AUTH_REQ_PASSWORD, no password, disconnects |
| `pg_sshkey_connect -U alice`    | Token computed first, libpq sends it immediately     |
| `psycopg2.connect(password=token)` | Same as above, from Python                        |

---

## 11. Connecting as a User

### Generate a key and register it

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
sudo pg_sshkey_addkey "$USER" ~/.ssh/id_ed25519.pub
```

### Connect with pg_sshkey_connect

```bash
pg_sshkey_connect                            # $USER to $USER db, local socket
pg_sshkey_connect mydb                       # specific database
pg_sshkey_connect -U alice mydb              # specific user
pg_sshkey_connect -h dbserver -U alice mydb  # remote host
pg_sshkey_connect -v mydb                    # verbose: show each step
pg_sshkey_connect -U alice -- -c "SELECT 1"  # pass flags to psql
```

---

## 12. Python Integration

Two Python files are provided for integrating SSH-key authentication into
Python applications.

### src/pam_pg_sshkey.py — importable module

A full Python module providing `get_token()`, `connect()`, and
`connect_replication()`.  Import it from any psycopg2-based application.

```python
from pam_pg_sshkey import connect

conn = connect(user="alice", dbname="mydb", host="dbserver")
cur  = conn.cursor()
cur.execute("SELECT version()")
print(cur.fetchone()[0])
conn.close()
```

The module must be on `PYTHONPATH` or in the same directory as your script.
After `make install` it can also be copied from `/usr/local/bin/pg_sshkey_query`'s
directory, or installed as a package with pip.

### utils/select1.py — minimal standalone example

A self-contained script that implements token generation inline — no import
of `pam_pg_sshkey.py` required.  Useful as a starting point for understanding
how the authentication works at the Python level, or as a template to
copy into your own project.

```bash
# Install dependencies
pip install psycopg2-binary cryptography

# Copy pam_pg_sshkey.py alongside if you want the module approach, or
# use select1.py standalone — it has no dependency on the module
python3 utils/select1.py
# 1
```

#### How select1.py works

```python
# 1. Write a nonce file to the challenge directory
raw    = secrets.token_bytes(32)
hex_id = raw.hex()
fd     = os.open(f"{CHALLENGE_DIR}/{hex_id}", os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o644)

# 2. Sign: "pg-sshkey-v1\0" || nonce_bytes
key     = load_ssh_private_key(open(KEY_PATH,"rb").read(), password=None)
sig     = key.sign(b"pg-sshkey-v1\x00" + raw)
token   = f"{hex_id}:{base64.b64encode(sig).decode()}"

# 3. Pass the token as password= BEFORE calling connect()
conn = psycopg2.connect(user=os.environ["USER"], password=token)
```

The three steps are the complete authentication mechanism.  Any psycopg2
application, replication subscriber, or other libpq client can authenticate
by following this pattern.

### Key format support (Python)

| Key file                            | Works directly | Notes                       |
|-------------------------------------|----------------|-----------------------------|
| `~/.ssh/id_ed25519` (OpenSSH)       | ✓              | Most common; recommended    |
| `~/.ssh/id_rsa` (OpenSSH RSA)       | ✓              | Requires `bcrypt` package   |
| `key.pem` (PKCS#8 PEM)              | ✓              | Ed25519 and RSA             |

For passphrase-protected keys:

```python
from cryptography.hazmat.primitives.serialization import load_ssh_private_key
key = load_ssh_private_key(open("~/.ssh/id_ed25519","rb").read(),
                            password=b"your_passphrase")
```

---

## 13. Logical Replication with SSH Key Authentication

This section covers setting up PostgreSQL logical replication where the
subscriber authenticates to the publisher using SSH keys via pam_pg_sshkey,
with no plaintext passwords stored anywhere.

### Architecture

```
Subscriber                              Publisher
  │                                        │
  │  Python replication client             │
  │  (or pg_sshkey_connect)                │
  │                                        │
  │  1. generate nonce ───────────────────►│ /var/run/pg_sshkey/<hex>
  │◄─ 2. hex nonce ───────────────────────│
  │                                        │
  │  3. sign with replicator's SSH key     │
  │                                        │
  │  4. connect (replication=database) ───►│ PostgreSQL
  │     password=<token>                   │   → PAM → pam_pg_sshkey.so
  │                                        │       verify signature
  │◄─ 5. replication session ─────────────│ PAM_SUCCESS
```

### Step 1 — Install pam_pg_sshkey on the publisher

The PAM module runs on the **publisher**.  Install it there:

```bash
# On the publisher
tar -xzf pam_pg_sshkey-1.0.8.tar.gz
cd pam_pg_sshkey-1.0.8
make
sudo make install
sudo make install-conf
```

### Step 2 — Create the replication user on the publisher

```sql
-- On the publisher, connect as postgres
CREATE USER replicator REPLICATION LOGIN;
-- No password: SSH key is the only credential
```

### Step 3 — Generate an SSH key on the subscriber

```bash
# On the subscriber, as the OS user that will run the replication process
ssh-keygen -t ed25519 -f ~/.ssh/replicator_key -N ""
# -N "" = no passphrase; required for automated/unattended replication
```

### Step 4 — Register the public key on the publisher

```bash
# On the publisher, as root
sudo pg_sshkey_addkey replicator /path/to/replicator_key.pub
# The public key file can be copied from the subscriber via scp or paste

# Verify postgres can read it
sudo -u postgres cat /etc/pg_sshkeys/replicator/authorized_keys
```

### Step 5 — Configure pg_hba.conf on the publisher

Add lines for the replication database **before** any catch-all entries.
The subscriber will connect over TCP, so use `host` (not `local`):

```
# /etc/postgresql/16/main/pg_hba.conf  (on the publisher)

# TYPE      DATABASE     USER         ADDRESS                  METHOD  OPTIONS
host        replication  replicator   <subscriber_ip>/32       pam     pamservice=postgresql
host        all          replicator   <subscriber_ip>/32       pam     pamservice=postgresql
```

Replace `<subscriber_ip>` with the actual IP of the subscriber machine.
Add a separate line for each subscriber.

Validate and reload:

```sql
SELECT line_number, error FROM pg_hba_file_rules WHERE error IS NOT NULL;
```

```bash
sudo systemctl reload postgresql@16-main
```

### Step 6 — Configure the challenge directory on the publisher

The challenge nonce directory must exist with the correct permissions.
The subscriber creates nonce files in this directory on the publisher
via the `pg_sshkey_challenge` call.  For remote connections, the nonce
files are created locally on the publisher — the subscriber connects to
PostgreSQL which then reads them via the PAM module on the publisher.

> **Important:** For remote replication connections, the subscriber does
> **not** call `pg_sshkey_challenge` on the publisher over the network.
> Instead, the subscriber calls `pg_sshkey_challenge` **locally** (the
> challenge directory must exist and be writable on the subscriber too),
> and the signed token is sent as the password to the publisher.
> The publisher's PAM module verifies the token against the nonce file
> on the publisher — which means the challenge nonce must also be created
> on the publisher.
>
> The correct approach for remote connections is to use `pam_pg_sshkey.py`
> or `select1.py` pattern, which creates the nonce locally and sends the
> signed token as the password.  The PAM module on the publisher verifies
> the signature against the public key in `/etc/pg_sshkeys/replicator/authorized_keys`.
>
> **For this to work over the network, the publisher must have its own
> challenge directory**, and the client must create the nonce on the
> publisher before connecting.  The simplest approach is to run
> `pg_sshkey_challenge` on the publisher via SSH, sign locally, then
> connect with the token.

For fully automated replication without SSH access to the publisher,
use the Python module which handles nonce creation and signing in-process:

```python
# utils/select1.py pattern — works for both local and remote connections
token = get_token(
    key_path="~/.ssh/replicator_key",
    challenge_dir="/var/run/pg_sshkey",   # must be writable on this machine
)
conn = psycopg2.connect(
    host="publisher.example.com",
    user="replicator",
    dbname="mydb",
    password=token,
    # For replication:
    connection_factory=LogicalReplicationConnection,
    replication="database",
)
```

### Step 7 — Configure postgresql.conf on the publisher

Enable logical replication:

```
# /etc/postgresql/16/main/postgresql.conf  (on the publisher)
wal_level = logical
max_replication_slots = 10      # at least 1 per subscriber
max_wal_senders = 10            # at least 1 per subscriber
```

Reload PostgreSQL after changes:

```bash
sudo systemctl reload postgresql@16-main
```

### Step 8 — Create a publication on the publisher

```sql
-- On the publisher, connect as postgres
CREATE PUBLICATION my_publication FOR ALL TABLES;
-- or for specific tables:
CREATE PUBLICATION my_publication FOR TABLE orders, customers;
```

Grant the replication user access to the published tables:

```sql
GRANT SELECT ON ALL TABLES IN SCHEMA public TO replicator;
-- For future tables:
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO replicator;
```

### Step 9 — Create the subscription on the subscriber

The subscription connection string must include the signed token as the
password.  Because the token expires in 60 seconds and is single-use, it
**cannot** be stored in the subscription DSN directly.  Instead, use the
Python replication client below which generates a fresh token for each
connection attempt.

### Step 10 — Python replication client

This is the recommended way to run the subscriber — a Python script using
`pam_pg_sshkey.py` (from `src/`) and `psycopg2`:

```python
#!/usr/bin/env python3
"""
replication_subscriber.py

Logical replication subscriber that authenticates to the publisher
using SSH-key authentication via pam_pg_sshkey.

Usage:
    pip install psycopg2-binary cryptography
    python3 replication_subscriber.py
"""

import sys
sys.path.insert(0, "/path/to/pam_pg_sshkey-1.0.8/src")

from pam_pg_sshkey import get_token
from psycopg2.extras import LogicalReplicationConnection
import psycopg2

PUBLISHER_HOST = "publisher.example.com"
PUBLISHER_DB   = "mydb"
REPL_USER      = "replicator"
SSH_KEY        = "/home/replicator/.ssh/replicator_key"
CHALLENGE_DIR  = "/var/run/pg_sshkey"
SLOT_NAME      = "my_slot"
PUBLICATION    = "my_publication"


def get_connection():
    """Open a fresh replication connection with a newly signed token."""
    token = get_token(key_path=SSH_KEY, challenge_dir=CHALLENGE_DIR)
    return psycopg2.connect(
        host=PUBLISHER_HOST,
        user=REPL_USER,
        dbname=PUBLISHER_DB,
        password=token,
        connection_factory=LogicalReplicationConnection,
    )


def create_slot_if_missing(conn):
    cur = conn.cursor()
    try:
        cur.create_replication_slot(SLOT_NAME, output_plugin="pgoutput")
        print(f"Created replication slot: {SLOT_NAME}")
    except psycopg2.errors.DuplicateObject:
        print(f"Replication slot already exists: {SLOT_NAME}")
    conn.commit()
    cur.close()


def process_message(msg):
    """Handle an incoming replication message."""
    print(f"LSN {msg.data_start}: {msg.payload}")
    msg.cursor.send_feedback(flush_lsn=msg.data_start)


def main():
    print(f"Connecting to {PUBLISHER_HOST} as {REPL_USER}...")
    conn = get_connection()

    create_slot_if_missing(conn)

    cur = conn.cursor()
    cur.start_replication(
        slot_name=SLOT_NAME,
        decode=True,
        options={"proto_version": "1", "publication_names": PUBLICATION},
    )

    print(f"Streaming from publication '{PUBLICATION}'...")
    cur.consume_stream(process_message)


if __name__ == "__main__":
    main()
```

### Step 11 — Create the subscription using psql (alternative)

If you prefer to manage the subscription through SQL rather than a
Python client, use `pg_sshkey_connect` to connect and create it.  Note
that the subscription DSN password field cannot hold a pam_pg_sshkey
token directly (tokens are single-use), so you must use `pg_sshkey_connect`
or the Python client for each connection:

```bash
# Connect to the subscriber's PostgreSQL as superuser
pg_sshkey_connect -U postgres subscriber_db
```

```sql
-- On the subscriber database
CREATE SUBSCRIPTION my_subscription
    CONNECTION 'host=publisher.example.com
                user=replicator
                dbname=mydb
                password=<token>'   -- token generated immediately before this command
    PUBLICATION my_publication;
```

Because tokens expire, the better approach is to use the Python replication
client (Step 10), which generates a fresh token on every reconnect.

### Verify replication is working

On the publisher:

```sql
-- Check replication slots
SELECT slot_name, active, restart_lsn
FROM pg_replication_slots;

-- Check connected walsenders
SELECT usename, application_name, client_addr, state, sent_lsn
FROM pg_stat_replication;
```

On the subscriber:

```sql
-- Check subscription status
SELECT subname, subenabled, received_lsn, latest_end_lsn
FROM pg_stat_subscription;
```

### Replication troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `PAM authentication failed` in publisher log | Wrong key registered, or `authorized_keys` has wrong permissions | `sudo pg_sshkey_addkey --list replicator` |
| `replication` database not in pg_hba.conf | pg_hba.conf only covers `all` databases | Add a `replication` line — see Step 5 |
| `slot does not exist` | Slot was dropped or never created | Re-run `create_replication_slot()` |
| Token expires mid-connection | Slot creation took > 60s | Increase `CHALLENGE_TTL_SECS` and recompile |
| `no pg_hba.conf entry for replication` | Subscriber IP not in pg_hba.conf | Add the subscriber's IP to the `replication` line |
| `must be superuser or replication role` | User lacks `REPLICATION` attribute | `ALTER USER replicator REPLICATION;` |

---

## 14. Module Reference

### pam_pg_sshkey.so options

| Option                       | Default              | Description                         |
|------------------------------|----------------------|-------------------------------------|
| `authorized_keys_dir=<path>` | `/etc/pg_sshkeys`    | Root of per-user key directories    |
| `challenge_dir=<path>`       | `/var/run/pg_sshkey` | Directory holding nonce files       |
| `debug`                      | off                  | Verbose syslog at `LOG_DEBUG` level |

### pg_sshkey_challenge

```
pg_sshkey_challenge <challenge_dir>
```

Creates the directory if absent (mode 1733), generates a 32-byte nonce,
writes it to `<challenge_dir>/<hex>` (mode 0644), prints hex to stdout.
Exit 0 on success, 1 on error.

### pg_sshkey_sign

```
pg_sshkey_sign <challenge_hex> <private_key_path>
```

Signs `"pg-sshkey-v1\0" || challenge_bytes`, prints
`<challenge_hex>:<base64_signature>`.

| Format                               | Key types                   |
|--------------------------------------|-----------------------------|
| OpenSSH (`BEGIN OPENSSH PRIVATE KEY`)| Ed25519, unencrypted only   |
| PKCS#8 PEM (`BEGIN PRIVATE KEY`)     | Ed25519, RSA                |
| Traditional PEM (`BEGIN RSA ...`)    | RSA                         |

For passphrase-protected or RSA OpenSSH keys:
```bash
openssl pkey -in ~/.ssh/id_rsa -out key.pem
pg_sshkey_sign <hex> key.pem
```

### pg_sshkey_connect

```
pg_sshkey_connect [OPTIONS] [DBNAME]

  -U, --username USER     PostgreSQL username   (default: $USER)
  -h, --host HOST         Host                  (default: local socket)
  -p, --port PORT         Port                  (default: 5432)
  -d, --dbname DBNAME     Database              (default: username)
  -i, --identity FILE     SSH private key       (default: ~/.ssh/id_ed25519)
  -c, --challenge-dir DIR Nonce directory       (default: /var/run/pg_sshkey)
  -v, --verbose           Print each step to stderr
  --                      Pass remaining args to psql
```

### pg_sshkey_addkey

```
pg_sshkey_addkey [OPTIONS] <pg_username> [<pubkey_file_or_->]

  -d, --keys-dir DIR      Key root directory    (default: /etc/pg_sshkeys)
  -a, --append            Append instead of replace
      --list              List current keys for the user
      --remove            Remove all keys for the user
```

Must be run as root.

### pam_pg_sshkey.py (Python module)

```python
from pam_pg_sshkey import get_token, connect, connect_replication

# Low-level: get a signed token for use in any libpq connection
token = get_token(
    key_path="~/.ssh/id_ed25519",       # any supported format
    challenge_dir="/var/run/pg_sshkey",
    passphrase=None,                     # or b"your_passphrase"
)

# Convenience wrapper: connect and return a psycopg2 connection
conn = connect(user="alice", dbname="mydb", host="dbserver")

# Replication connection
conn = connect_replication(user="replicator", host="publisher.example.com",
                           dbname="mydb")
```

Requires: `pip install psycopg2-binary cryptography`
For passphrase-protected keys also: `pip install bcrypt`

---

## 15. File & Directory Permissions Reference

| Path                                      | Owner             | Mode | Notes                            |
|-------------------------------------------|-------------------|------|----------------------------------|
| `/lib/<arch>/security/pam_pg_sshkey.so`   | root:root         | 0755 | Loaded by PAM as root            |
| `/usr/local/bin/pg_sshkey_challenge`      | root:root         | 0755 | Run by any user                  |
| `/usr/local/bin/pg_sshkey_sign`           | root:root         | 0755 | Run by any user                  |
| `/usr/local/bin/pg_sshkey_connect`        | root:root         | 0755 | Run by any user                  |
| `/usr/local/bin/pg_sshkey_addkey`         | root:root         | 0755 | Run as root only                 |
| `/etc/pam.d/postgresql`                   | root:root         | 0644 | PAM service config               |
| `/etc/pg_sshkeys/`                        | root:postgres     | 0750 | Root of key tree                 |
| `/etc/pg_sshkeys/<user>/`                 | root:postgres     | 0750 | Per-user directory               |
| `/etc/pg_sshkeys/<user>/authorized_keys`  | root:postgres     | 0640 | Must not be group/world writable |
| `/var/run/pg_sshkey/`                     | postgres:postgres | 1733 | Sticky world-write nonce dir     |
| `/var/run/pg_sshkey/<hex>`                | <client user>     | 0644 | Readable by postgres PAM module  |

### Challenge directory mode 1733 explained

```
drwx-wx-wt  postgres postgres  /var/run/pg_sshkey
```

| Bit         | Who      | Effect                                        |
|-------------|----------|-----------------------------------------------|
| `rwx` owner | postgres | PAM module can read and delete any nonce file |
| `-wx` other | everyone | Any user can create a nonce file and enter    |
| `t` sticky  | everyone | Can only delete files you own                 |

### authorized_keys ownership is critical

The PAM module runs as the `postgres` OS user.  If `authorized_keys` is
owned by the database user (`alice:alice 0600`), `postgres` cannot read
it and authentication fails with a permission error in the log.  Always
use `pg_sshkey_addkey` — it enforces `root:postgres 0640` automatically.

---

## 16. Logging & Troubleshooting

### View auth logs

```bash
journalctl -t postgresql --since "10 minutes ago" | grep pam_pg_sshkey
```

### Log messages reference

| Message | Meaning | Fix |
|---------|---------|-----|
| `authenticated with key ssh-ed25519` | Success | — |
| `failed to get auth token (client sent no password)` | psql run without PGPASSWORD | Use `pg_sshkey_connect` or Python module |
| `malformed token` | Token not in `hex:base64` format | Check `pg_sshkey_sign` output |
| `challenge not found or expired` | Nonce > 60s old or already used | Use a fresh token |
| `cannot read authorized_keys (permission denied)` | File not `root:postgres 0640` | `sudo pg_sshkey_addkey <user> <pubkey>` |
| `no authorized_keys` | File doesn't exist | `sudo pg_sshkey_addkey <user> ~/.ssh/id_ed25519.pub` |
| `no valid keys (empty or unsupported types)` | No Ed25519/RSA keys in file | Check key type; ECDSA not supported |
| `authentication failed` | Signature verification failed | Wrong key registered |
| `conversation failed` | PAM conv returned error | Check challenge dir permissions |
| `invalid authentication method "pamservice=postgresql"` | pg_hba.conf has 5 not 6 columns | See §7 |

### `failed to get auth token (client sent no password)`

```bash
# Wrong
psql -U alice mydb

# Correct
pg_sshkey_connect -U alice mydb

# Or from Python (token must be pre-computed before connect())
token = get_token(...)
conn  = psycopg2.connect(password=token, ...)
```

### `cannot read authorized_keys (permission denied)`

```bash
sudo pg_sshkey_addkey alice ~/.ssh/id_ed25519.pub
sudo -u postgres cat /etc/pg_sshkeys/alice/authorized_keys
```

### Challenge directory missing or wrong permissions

```bash
ls -la /var/run/ | grep pg_sshkey
# Should show: drwx-wx-wt 2 postgres postgres ... pg_sshkey

sudo chown postgres:postgres /var/run/pg_sshkey
sudo chmod 1733 /var/run/pg_sshkey

# After reboot if tmpfiles.d wasn't applied:
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/pg_sshkey.conf
```

---

## 17. Uninstalling

```bash
sudo make uninstall
sudo mv /etc/pam.d/postgresql.bak /etc/pam.d/postgresql
sudo systemctl reload postgresql@16-main
```

---

## 18. Security Hardening Checklist

- [ ] PostgreSQL connections use TLS (`ssl = on`, `sslmode=require`)
- [ ] `authorized_keys` files are `root:postgres 0640`
- [ ] `/var/run/pg_sshkey` is `postgres:postgres 1733`
- [ ] `debug` is **off** in `/etc/pam.d/postgresql`
- [ ] SSH keys have no passphrase (for automated processes)
- [ ] `/etc/pg_sshkeys` is under configuration management
- [ ] Stale nonce files are swept every 2 minutes
- [ ] RSA keys are ≥ 3072 bits; Ed25519 preferred
- [ ] Replication user has only `REPLICATION` and `SELECT` — not superuser
- [ ] Auth failures reviewed in journal for anomalies
