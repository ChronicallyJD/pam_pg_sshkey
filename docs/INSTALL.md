# pam_pg_sshkey — Installation & Configuration Manual

Version 1.0.0 · June 2026

---

## Table of Contents

1. [Overview](#1-overview)
2. [System Requirements](#2-system-requirements)
3. [Building from Source](#3-building-from-source)
4. [Running the Test Suite](#4-running-the-test-suite)
5. [Installation](#5-installation)
6. [PostgreSQL Configuration](#6-postgresql-configuration)
7. [PAM Configuration](#7-pam-configuration)
8. [Deploying SSH Public Keys](#8-deploying-ssh-public-keys)
9. [Client Setup](#9-client-setup)
10. [Challenge Service Integration](#10-challenge-service-integration)
11. [Module Reference](#11-module-reference)
12. [File & Directory Permissions Reference](#12-file--directory-permissions-reference)
13. [Logging & Troubleshooting](#13-logging--troubleshooting)
14. [Uninstalling](#14-uninstalling)
15. [Security Hardening Checklist](#15-security-hardening-checklist)

---

## 1. Overview

`pam_pg_sshkey` is a PAM (Pluggable Authentication Module) that allows
PostgreSQL to authenticate database users via **SSH public-key cryptography**
instead of passwords.

### How authentication works

```
Client                          Server
  │                                │
  │  1. Request challenge ────────►│ pg_sshkey_challenge
  │◄─ 2. Challenge hex ────────────│   creates /var/run/pg_sshkey/<hex>
  │                                │
  │  3. Sign with SSH private key  │
  │     pg_sshkey_sign             │
  │     → <hex>:<base64_signature> │
  │                                │
  │  4. psql password=<token> ────►│ PostgreSQL
  │                                │   → PAM (pam_pg_sshkey.so)
  │                                │       parse token
  │                                │       load + expire nonce (60 s TTL)
  │                                │       read authorized_keys
  │                                │       verify signature
  │◄─ 5. Connected ────────────────│ PAM_SUCCESS → session opened
```

Key properties:

- **No shared secret** — the database stores only public keys, never private keys or passwords.
- **Replay-proof** — each challenge nonce has a 60-second TTL and is deleted on first use.
- **Domain separation** — the signed message includes a protocol prefix (`"pg-sshkey-v1\0"`) preventing cross-protocol signature reuse.
- **Standard key formats** — uses OpenSSH `authorized_keys` files; existing SSH keys work without conversion.

---

## 2. System Requirements

### Supported operating systems

| Distribution        | Minimum version | Notes                                              |
|---------------------|-----------------|-----------------------------------------------------|
| Ubuntu              | 22.04 LTS       | Tested on 22.04, 24.04; ships PostgreSQL 14–16      |
| Debian              | 12 (Bookworm)   | Tested on 12; ships PostgreSQL 15                   |
| RHEL / Rocky / Alma | 9.x             | Set `PAM_LIB_DIR=/lib64/security` at build          |

### Debian / Ubuntu build dependencies

The following packages are required to compile the module and its tools.
All are available from the standard `main` archive — no third-party PPAs
are needed.

| Package          | Provides                                   | Why it is needed                                      |
|------------------|--------------------------------------------|-------------------------------------------------------|
| `build-essential`| `gcc`, `g++`, `make`, `dpkg-dev`, `libc6-dev` | C compiler, linker, make, and the `gcc -dumpmachine` triplet used by the Makefile to locate the PAM module directory |
| `libssl-dev`     | OpenSSL headers + `libcrypto.so`           | Cryptographic primitives: `EVP_PKEY`, `RAND_bytes`, BIO base64, Ed25519 and RSA signing/verification |
| `libpam0g-dev`   | PAM headers (`security/pam_modules.h`) + `libpam.so` | Required to compile and link the PAM shared module |
| `pkg-config`     | `pkg-config` tool                          | Locates OpenSSL compiler and linker flags automatically (`pkg-config --cflags --libs libcrypto`) |

Install all four with a single command:

```bash
sudo apt update
sudo apt install build-essential libssl-dev libpam0g-dev pkg-config
```

#### Verify the packages installed correctly

```bash
# Compiler and make
gcc --version          # should print gcc 10.x or newer
make --version         # should print GNU Make 4.x or newer

# OpenSSL development headers and library
pkg-config --modversion libcrypto     # prints e.g. 3.0.13
ls /usr/include/openssl/evp.h         # must exist

# PAM development headers
ls /usr/include/security/pam_modules.h   # must exist

# Triplet used to install pam_pg_sshkey.so
gcc -dumpmachine       # e.g. x86_64-linux-gnu
# The .so will be installed to /lib/<triplet>/security/
```

#### Ubuntu / Debian version notes

| Release             | OpenSSL version | `libpam0g-dev` package |
|---------------------|-----------------|------------------------|
| Ubuntu 20.04 (Focal)  | 1.1.1f        | `libpam0g-dev`         |
| Ubuntu 22.04 (Jammy)  | 3.0.2         | `libpam0g-dev`         |
| Ubuntu 24.04 (Noble)  | 3.0.13        | `libpam0g-dev`         |
| Debian 11 (Bullseye)  | 1.1.1w        | `libpam0g-dev`         |
| Debian 12 (Bookworm)  | 3.0.11        | `libpam0g-dev`         |

The source code supports both OpenSSL 1.1.1 and 3.x. The RSA key decoder
uses `EVP_PKEY_fromdata` on OpenSSL ≥ 3.0 and falls back to the legacy
`RSA_new` / `RSA_set0_key` path on 1.1.1, selected automatically at
compile time via `#if OPENSSL_VERSION_NUMBER`.

> **Note on `libpam-dev` vs `libpam0g-dev`:** On Debian/Ubuntu the correct
> package is `libpam0g-dev`. The alternative name `libpam-dev` does not
> exist in the standard repositories on these distributions.

### RHEL / Fedora / Rocky / AlmaLinux build dependencies

```bash
sudo dnf install gcc make openssl-devel pam-devel pkgconf
```

| Package        | Provides                          |
|----------------|-----------------------------------|
| `gcc`          | C compiler                        |
| `make`         | GNU Make                          |
| `openssl-devel`| OpenSSL headers + `libcrypto.so`  |
| `pam-devel`    | PAM headers + `libpam.so`         |
| `pkgconf`      | `pkg-config` compatible tool      |

On RHEL/Fedora the PAM module directory is `/lib64/security/` rather than
`/lib/<triplet>/security/`. Pass this at install time:

```bash
sudo make install PAM_LIB_DIR=/lib64/security
```

### PostgreSQL requirement

PostgreSQL **14 or later** is required. Earlier versions are not supported.

The PostgreSQL server binary must have been compiled with `--with-pam`.
Binary packages from the official [PGDG apt repository](https://apt.postgresql.org)
include PAM support by default. Verify with:

```bash
psql --version               # must print 14.x or later
pg_config --configure | grep -o '\-\-with-pam'
# must print: --with-pam
```

---

## 3. Building from Source

### Quick start

```bash
tar -xzf pam_pg_sshkey-1.0.0.tar.gz
cd pam_pg_sshkey-1.0.0
make
```

The Makefile automatically detects OpenSSL flags via `pkg-config`. If
`pkg-config` is not available it falls back to `-lcrypto`.

The following files are produced in the project root:

| File                  | Description                                        |
|-----------------------|----------------------------------------------------|
| `pam_pg_sshkey.so`    | PAM shared module — install to the security dir    |
| `pg_sshkey_challenge` | Server helper: generate a challenge nonce          |
| `pg_sshkey_sign`      | Client helper: sign a nonce with an SSH private key|

### Expected build output

A successful build looks like this (paths will vary by OpenSSL version):

```
cc -Wall -Wextra -Wpedantic -O2 -I/usr/include/security -fPIC \
   -c -o src/pam_pg_sshkey.o src/pam_pg_sshkey.c
cc -Wall -Wextra -Wpedantic -O2 -I/usr/include/security -fPIC \
   -c -o src/challenge_store.o src/challenge_store.c
cc -Wall -Wextra -Wpedantic -O2 -I/usr/include/security -fPIC \
   -c -o src/key_parser.o src/key_parser.c
cc -Wall -Wextra -Wpedantic -O2 -I/usr/include/security -fPIC \
   -c -o src/sig_verify.o src/sig_verify.c
cc -Wall -Wextra -Wpedantic -O2 -shared -fPIC \
   -o pam_pg_sshkey.so src/pam_pg_sshkey.o ... -lcrypto -lpam
cc -Wall -Wextra -Wpedantic -O2 \
   -o pg_sshkey_sign src/pg_sshkey_sign.c -lcrypto
cc -Wall -Wextra -Wpedantic -O2 \
   -o pg_sshkey_challenge src/pg_sshkey_challenge.c ... -lcrypto
```

One expected warning on all versions:

```
src/pam_pg_sshkey.c:125:45: warning: unused parameter 'flags'
```

This is a required but unused parameter in the PAM API signature and is
harmless.

### Override compiler or flags

```bash
# Use Clang instead of GCC
CC=clang make

# Debug build with no optimisation
CFLAGS="-O0 -g3" make

# Static analysis pass
CC=gcc CFLAGS="-O2 -fanalyzer" make
```

### Cross-compile example (ARM64)

```bash
sudo apt install gcc-aarch64-linux-gnu

CC=aarch64-linux-gnu-gcc \
PAM_LIB_DIR=/usr/lib/aarch64-linux-gnu/security \
make
```

### Common build errors and fixes

| Error message | Cause | Fix |
|---|---|---|
| `fatal error: openssl/evp.h: No such file` | `libssl-dev` not installed | `sudo apt install libssl-dev` |
| `fatal error: security/pam_modules.h: No such file` | `libpam0g-dev` not installed | `sudo apt install libpam0g-dev` |
| `pkg-config: command not found` | `pkg-config` not installed | `sudo apt install pkg-config` |
| `gcc: command not found` | `build-essential` not installed | `sudo apt install build-essential` |
| `cannot find -lcrypto` | OpenSSL runtime library missing | `sudo apt install libssl-dev` |
| `cannot find -lpam` | PAM runtime library missing | `sudo apt install libpam0g-dev` |

---

## 4. Running the Test Suite

```bash
make test
```

This builds four test binaries (with AddressSanitizer and UBSan enabled)
and runs them:

| Binary                       | What it tests                                      |
|------------------------------|----------------------------------------------------|
| `tests/test_challenge_store` | challenge_create, challenge_load, TTL, path safety |
| `tests/test_key_parser`      | base64 decode, authorized_keys parsing             |
| `tests/test_sig_verify`      | Ed25519 and RSA signature verification             |
| `tests/test_integration`     | Full flow, replay prevention, wrong-key rejection  |

A clean run prints `0 failed` for each suite.

---

## 5. Installation

### Standard install (Debian/Ubuntu)

```bash
sudo make install
sudo make install-conf
```

`make install` places files at:

| Source              | Destination                                      |
|---------------------|--------------------------------------------------|
| `pam_pg_sshkey.so`  | `/lib/<arch>/security/pam_pg_sshkey.so`          |
| `pg_sshkey_sign`    | `/usr/local/bin/pg_sshkey_sign`                  |
| `pg_sshkey_challenge` | `/usr/local/bin/pg_sshkey_challenge`           |

It also creates two directories if they don't exist:

| Directory           | Owner        | Mode |
|---------------------|--------------|------|
| `/etc/pg_sshkeys`   | root:postgres | 750  |
| `/var/run/pg_sshkey`| postgres:postgres | 750 |

`make install-conf` installs `config/pam.d/postgresql` as
`/etc/pam.d/postgresql`, backing up any existing file as `postgresql.bak`.

### RHEL/Fedora

```bash
sudo make install PAM_LIB_DIR=/lib64/security BIN_DIR=/usr/local/bin
sudo make install-conf
```

### Custom paths

```bash
sudo make install \
  PAM_LIB_DIR=/usr/lib/x86_64-linux-gnu/security \
  BIN_DIR=/opt/pgtools/bin \
  KEY_DIR=/opt/pgkeys \
  CHAL_DIR=/run/pgchallenge
```

If you use non-default paths, update `/etc/pam.d/postgresql` to match
(see [§7](#7-pam-configuration)).

### Verify installation

```bash
ls -la /lib/$(gcc -dumpmachine)/security/pam_pg_sshkey.so
pg_sshkey_challenge --help 2>&1 || true
```

---

## 6. PostgreSQL Configuration

### Step 1 — Edit pg_hba.conf

Open your `pg_hba.conf` (default `/etc/postgresql/<version>/main/pg_hba.conf`
on Debian, `/var/lib/pgsql/<version>/data/pg_hba.conf` on RHEL).

Add a line **before** any existing `password` or `md5` lines:

```
# TYPE  DATABASE  USER  ADDRESS     METHOD  OPTIONS
host    all       all   0.0.0.0/0   pam     pamservice=postgresql
```

The six columns are positional — `pam` is the METHOD and `pamservice=postgresql`
is a space-separated OPTIONS value in the sixth column. They must not be
merged. The common mistake that produces the log error
`invalid authentication method "pamservice=postgresql"` is writing only
five columns and letting PostgreSQL interpret the option as the method name:

```
# WRONG — pamservice=postgresql is parsed as the method, not an option
host  all  all  0.0.0.0/0  pamservice=postgresql
```

To restrict to a specific database or subnet:

```
host    mydb      all   10.0.0.0/8  pam     pamservice=postgresql
```

> **Note on `pamservice`:** The value `postgresql` tells `libpam` to look up
> `/etc/pam.d/postgresql`. If you use a different filename, change this value
> accordingly.

#### Validate before reloading

Check `pg_hba.conf` for errors without a reload:

```sql
-- Run as a superuser
SELECT line_number, type, error
FROM pg_hba_file_rules
WHERE error IS NOT NULL;
```

An empty result means the file parsed cleanly. Any row with a non-null
`error` shows the line number and the parse error.

### Step 2 — Create PostgreSQL users

PAM only handles *authentication*; PostgreSQL still requires the user to exist
in `pg_catalog.pg_roles`:

```sql
-- Connect as superuser
CREATE USER alice;
CREATE USER bob;
```

No password is required (or wanted) for PAM-authenticated users.

### Step 3 — Reload PostgreSQL

Reload (not restart) — `pg_hba.conf` is re-read on reload without dropping
existing connections:

```bash
# Debian/Ubuntu (PGDG packages use a version-specific unit name):
sudo systemctl reload postgresql@14-main   # adjust major version as needed
sudo systemctl reload postgresql@15-main
sudo systemctl reload postgresql@16-main

# RHEL/Fedora:
sudo systemctl reload postgresql-14        # adjust major version as needed

# From inside psql as a superuser (works on any platform):
SELECT pg_reload_conf();
```

### Step 4 — Verify PAM is active

```
$ psql -h localhost -U alice -d postgres
Password for user alice:
```

The prompt appearing means PAM is in the path. (Authentication will fail until
keys are set up — see §8.)

---

## 7. PAM Configuration

The file `/etc/pam.d/postgresql` controls what the `pam_pg_sshkey.so`
module receives.

### Minimal configuration

```
#%PAM-1.0
auth    required    pam_pg_sshkey.so \
            authorized_keys_dir=/etc/pg_sshkeys \
            challenge_dir=/var/run/pg_sshkey

account required    pam_permit.so
```

### With debug logging

```
#%PAM-1.0
auth    required    pam_pg_sshkey.so \
            authorized_keys_dir=/etc/pg_sshkeys \
            challenge_dir=/var/run/pg_sshkey    \
            debug

account required    pam_permit.so
```

Debug mode writes per-authentication details to syslog (facility `authpriv`).
Disable in production.

### Layered with OS password fallback

If you want to support both SSH-key auth and OS password (e.g., during
migration), stack the modules:

```
#%PAM-1.0
auth    sufficient  pam_pg_sshkey.so \
            authorized_keys_dir=/etc/pg_sshkeys \
            challenge_dir=/var/run/pg_sshkey
auth    required    pam_unix.so try_first_pass

account required    pam_permit.so
```

With `sufficient`, a successful SSH-key verification skips `pam_unix.so`.
If SSH-key auth fails, `pam_unix.so` tries the OS password.

> **Important:** `pam_unix.so` exposes OS passwords over the PostgreSQL
> protocol if used without TLS. Only use this combination with
> `sslmode=require` on the client and `ssl = on` / `ssl_cert_file` set
> in `postgresql.conf`.

---

## 8. Deploying SSH Public Keys

### Directory layout

```
/etc/pg_sshkeys/
├── alice/
│   └── authorized_keys
└── bob/
    └── authorized_keys
```

Each `authorized_keys` file uses standard OpenSSH format:

```
ssh-ed25519 AAAA... alice@laptop
ssh-rsa AAAA...     alice@desktop
```

### Adding a user's key

```bash
PGUSER=alice
sudo mkdir -p /etc/pg_sshkeys/$PGUSER
sudo tee /etc/pg_sshkeys/$PGUSER/authorized_keys << 'EOF'
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... alice@laptop
EOF
sudo chown root:postgres /etc/pg_sshkeys/$PGUSER/authorized_keys
sudo chmod 640 /etc/pg_sshkeys/$PGUSER/authorized_keys
```

### Accepted key types

| Key type       | Authorized_keys token  | Digest   |
|----------------|------------------------|----------|
| Ed25519        | `ssh-ed25519`          | internal |
| RSA (≥ 2048)   | `ssh-rsa`              | SHA-256  |
| RSA (≥ 2048)   | `rsa-sha2-256`         | SHA-256  |
| RSA (≥ 2048)   | `rsa-sha2-512`         | SHA-512  |

ECDSA and DSA keys are intentionally not supported.

### Permission requirements

The module refuses to read `authorized_keys` files that are writable by
group or other (`g+w` or `o+w`). Correct permissions:

```
-rw-r----- root postgres /etc/pg_sshkeys/alice/authorized_keys
```

---

## 9. Client Setup

### Prerequisites

The client needs `pg_sshkey_challenge` (to get a nonce from the server) and
`pg_sshkey_sign` (to sign it). In a typical deployment the challenge is
fetched by a sidecar service and handed to the client, but for testing you
can use SSH to call the server helper directly.

### Manual connection (step by step)

```bash
# 1. Get a challenge from the server
CHALLENGE=$(ssh dbserver pg_sshkey_challenge /var/run/pg_sshkey)
echo "Challenge: $CHALLENGE"

# 2. Sign it with your SSH private key
TOKEN=$(pg_sshkey_sign "$CHALLENGE" ~/.ssh/id_ed25519)
echo "Token: $TOKEN"

# 3. Connect to PostgreSQL
PGPASSWORD="$TOKEN" psql -h dbserver -U alice -d mydb
```

### Wrapper script

```bash
#!/usr/bin/env bash
# pg_ssh_connect — fetch challenge, sign, connect
set -euo pipefail
DB_HOST="${1:?Usage: $0 host user [db] [key]}"
DB_USER="${2:?}"
DB_NAME="${3:-$DB_USER}"
KEY="${4:-$HOME/.ssh/id_ed25519}"

CHALLENGE=$(ssh "$DB_HOST" pg_sshkey_challenge /var/run/pg_sshkey)
TOKEN=$(pg_sshkey_sign "$CHALLENGE" "$KEY")
export PGPASSWORD="$TOKEN"
exec psql -h "$DB_HOST" -U "$DB_USER" "$DB_NAME"
```

Save as `pg_ssh_connect`, `chmod +x`, and call:

```bash
pg_ssh_connect dbserver alice mydb
```

### pgpass alternative

`pg_sshkey_sign` can be called in a shell profile or `.pgpass` substitute
script.  Since tokens are single-use and time-limited, they cannot be cached;
each `psql` invocation needs a fresh token.

### libpq connection strings

```bash
psql "host=dbserver user=alice password=$TOKEN dbname=mydb sslmode=require"
```

Or using environment variables:

```bash
export PGHOST=dbserver
export PGUSER=alice
export PGPASSWORD="$TOKEN"
export PGSSLMODE=require
psql mydb
```

---

## 10. Challenge Service Integration

In production you will typically want a dedicated **challenge service** that
clients can call over HTTPS (or another authenticated channel) rather than
SSH. The service:

1. Calls `pg_sshkey_challenge <challenge_dir>` and returns the hex nonce to
   the client.
2. Optionally records which user requested the challenge (for audit logging).

A minimal Go/Python wrapper or Nginx + CGI is sufficient. The PAM module
only cares about the nonce file being present in `challenge_dir` with a
valid timestamp.

### Challenge directory lifecycle

```
pg_sshkey_challenge     →  creates /var/run/pg_sshkey/<hex>
[client signs, sends token]
pam_sm_authenticate     →  loads  /var/run/pg_sshkey/<hex>
                        →  deletes /var/run/pg_sshkey/<hex>
```

Nonces older than 60 seconds are automatically deleted on the next `load`
attempt. A cron job or systemd timer can additionally sweep stale files:

```bash
# /etc/cron.d/pg_sshkey_cleanup
*/2 * * * * postgres find /var/run/pg_sshkey -maxdepth 1 -mmin +2 -delete
```

---

## 11. Module Reference

### pam_pg_sshkey.so options

| Option                        | Default               | Description                                           |
|-------------------------------|-----------------------|-------------------------------------------------------|
| `authorized_keys_dir=<path>`  | `/etc/pg_sshkeys`     | Root of per-user key directories                      |
| `challenge_dir=<path>`        | `/var/run/pg_sshkey`  | Directory holding pending challenge nonce files       |
| `debug`                       | off                   | Verbose syslog output at `LOG_DEBUG` level            |

### pg_sshkey_challenge

```
pg_sshkey_challenge <challenge_dir>
```

Generates a 32-byte cryptographically random nonce, writes it to
`<challenge_dir>/<hex>`, and prints `<hex>` to stdout.

Exit code 0 on success, 1 on error.

### pg_sshkey_sign

```
pg_sshkey_sign <challenge_hex> <private_key_path>
```

Reads a PEM-encoded OpenSSL private key (Ed25519 or RSA) and signs:

```
"pg-sshkey-v1\0" || challenge_bytes
```

Prints `<challenge_hex>:<base64_signature>` to stdout (the PAM token).

Exit code 0 on success, 1 on error.

> **Production note:** `pg_sshkey_sign` reads the private key from a PEM
> file. In production, integrate with `ssh-agent` (via the SSH agent
> protocol over `SSH_AUTH_SOCK`) so the key never leaves the agent process.

---

## 12. File & Directory Permissions Reference

| Path                                          | Owner         | Mode  | Notes                              |
|-----------------------------------------------|---------------|-------|------------------------------------|
| `/lib/<arch>/security/pam_pg_sshkey.so`       | root:root     | 0755  | Loaded by PAM as root              |
| `/usr/local/bin/pg_sshkey_challenge`          | root:root     | 0755  | Run by postgres user               |
| `/usr/local/bin/pg_sshkey_sign`               | root:root     | 0755  | Run by connecting client           |
| `/etc/pam.d/postgresql`                       | root:root     | 0644  | PAM config                         |
| `/etc/pg_sshkeys/`                            | root:postgres | 0750  | Root of authorized_keys tree       |
| `/etc/pg_sshkeys/<user>/`                     | root:postgres | 0750  | Per-user subdirectory              |
| `/etc/pg_sshkeys/<user>/authorized_keys`      | root:postgres | 0640  | **Must not be group/world writable** |
| `/var/run/pg_sshkey/`                         | postgres:postgres | 0750 | Nonce files live here            |
| `/var/run/pg_sshkey/<hex>`                    | postgres:postgres | 0600 | Created by pg_sshkey_challenge   |

---

## 13. Logging & Troubleshooting

### Syslog output

All authentication events are logged to syslog facility `authpriv`:

```bash
# Show PAM auth events from the last 10 minutes
journalctl -t postgresql --since "10 minutes ago"

# Or filter to just pam_pg_sshkey messages
journalctl -t postgresql --since "10 minutes ago" | grep pam_pg_sshkey
```

### Common log messages

| Message                                    | Meaning                                           |
|--------------------------------------------|---------------------------------------------------|
| `authenticated with key ssh-ed25519`       | Success — key type and comment logged             |
| `malformed token`                          | Token is not `hex:base64` — client-side issue     |
| `challenge not found or expired`           | Nonce >60 s old or already used (replay attempt)  |
| `no valid keys in '/etc/pg_sshkeys/...'`   | File missing, unreadable, or has wrong format     |
| `authorized_keys … world/group writable`   | Permission error — fix file mode                  |
| `account not found in passwd`              | OS user doesn't exist; PostgreSQL user must match |

### Enable debug mode (temporarily)

Add `debug` to the PAM configuration:

```
auth required pam_pg_sshkey.so ... debug
```

Then reload PostgreSQL (`systemctl reload postgresql@16-main` or equivalent) and attempt a
connection. Debug logs include the challenge hex, key type tried, and
authorized_keys path used.

**Remove `debug` after diagnosis** — it logs the challenge hex which, while
not a private key, adds unnecessary noise.

### `conversation failed` / `failed to get auth token`

```
pam_pg_sshkey(postgresql:auth): conversation failed
pam_pg_sshkey(postgresql:auth): pam_pg_sshkey: failed to get auth token for 'user'
```

This means the PAM module triggered a second password round-trip to the
client, which the client does not expect and drops.

PostgreSQL does **not** call `pam_set_item(PAM_AUTHTOK)` before invoking
`pam_authenticate()`. It stores the client password only in `appdata_ptr`
of the `pam_conv` struct. Any call to `pam_get_authtok()` — even with a
`NULL` prompt — falls through to the conversation function when
`PAM_AUTHTOK` is unset, which causes PostgreSQL to send a second
`AUTH_REQ_PASSWORD` to the client. The client ignores it and the exchange
fails.

Version 1.0.1 fixes this by calling the conversation function directly
via `pam_get_item(PAM_CONV)` with a single `PAM_PROMPT_ECHO_OFF` message,
which PostgreSQL answers immediately from `appdata_ptr`. Upgrade to 1.0.1.

If you see this with 1.0.1 or later, the client sent an empty password.
Confirm the token is being passed:

```bash
echo "$TOKEN" | grep -Eo '^[0-9a-f]{64}:[A-Za-z0-9+/=]+$' \
  && echo "Token format OK" || echo "Token is empty or malformed"
```

### `invalid authentication method "pamservice=postgresql"`

This log error means PostgreSQL parsed `pamservice=postgresql` as the
authentication method name rather than as an option to the `pam` method.
The `pg_hba.conf` line has a column count or formatting problem.

**Wrong** — only five columns; `pamservice=postgresql` lands in the METHOD slot:
```
host  all  all  0.0.0.0/0  pamservice=postgresql
```

**Correct** — six columns; `pam` is the method, `pamservice=postgresql` is the option:
```
host    all    all    0.0.0.0/0    pam    pamservice=postgresql
```

After correcting the line, validate and reload:

```bash
# Validate — must return zero rows
psql -U postgres -c "SELECT line_number, error FROM pg_hba_file_rules WHERE error IS NOT NULL;"

# Reload without dropping connections (adjust unit name for your version/platform)
sudo systemctl reload postgresql@16-main
```

### Authentication fails immediately

1. Confirm `pam` method is in `pg_hba.conf` and PostgreSQL was reloaded.
2. Confirm `/etc/pam.d/postgresql` exists and references `pam_pg_sshkey.so`.
3. Check that the PostgreSQL process can read `/lib/.../pam_pg_sshkey.so`:
   ```bash
   sudo -u postgres ls -la /lib/$(gcc -dumpmachine)/security/pam_pg_sshkey.so
   ```
4. Confirm `/var/run/pg_sshkey/` is writable by the `postgres` user.

### Token format errors

The token must be exactly `<64 hex chars>:<base64 string>`. Verify:

```bash
echo "$TOKEN" | grep -Eo '^[0-9a-f]{64}:[A-Za-z0-9+/=]+$'
```

If this returns nothing, the token is malformed.

### Challenge file not found

```bash
ls -la /var/run/pg_sshkey/
```

If empty, `pg_sshkey_challenge` did not run, the directory doesn't exist,
or PostgreSQL connected more than 60 seconds after the challenge was issued.
Reduce the workflow latency or increase `CHALLENGE_TTL_SECS` (requires
recompiling).

---

## 14. Uninstalling

```bash
sudo make uninstall

# Optionally restore the original PAM config
sudo mv /etc/pam.d/postgresql.bak /etc/pam.d/postgresql

# Revert pg_hba.conf to the previous auth method, then:
sudo systemctl reload postgresql@16-main   # adjust version as needed
```

---

## 15. Security Hardening Checklist

- [ ] TLS is enabled on PostgreSQL connections (`ssl = on` in
      `postgresql.conf`, `sslmode=require` on clients).
- [ ] `authorized_keys` files are owned by `root:postgres` and mode `0640`.
- [ ] `/var/run/pg_sshkey/` is mode `0750`, owned by `postgres:postgres`.
- [ ] `debug` mode is **off** in production.
- [ ] Private keys used with `pg_sshkey_sign` are passphrase-protected or
      managed by `ssh-agent`.
- [ ] The challenge service endpoint is authenticated (not publicly reachable
      without credentials).
- [ ] A cron job cleans up stale nonce files every 2 minutes.
- [ ] RSA keys in `authorized_keys` are at least 3072 bits; Ed25519 preferred.
- [ ] You review `journalctl` / `/var/log/auth.log` for repeated failures
      (brute-force indicators).
- [ ] The `pg_sshkeys` directory tree is under configuration management
      (Ansible / Puppet) for auditability.
