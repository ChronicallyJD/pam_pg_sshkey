# pam_pg_sshkey — Installation & Configuration Manual

Version 1.0.6 · June 2026

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
9. [Why You Must Use pg_sshkey_connect](#9-why-you-must-use-pg_sshkey_connect)
10. [Connecting as a User](#10-connecting-as-a-user)
11. [Module Reference](#11-module-reference)
12. [File & Directory Permissions Reference](#12-file--directory-permissions-reference)
13. [Logging & Troubleshooting](#13-logging--troubleshooting)
14. [Uninstalling](#14-uninstalling)
15. [Security Hardening Checklist](#15-security-hardening-checklist)

---

## 1. Overview

`pam_pg_sshkey` lets PostgreSQL authenticate database users via **SSH
public-key cryptography** instead of passwords.  The database stores only
public keys; private keys never leave the client machine.

### Authentication flow

```
Client                                  Server
  │                                        │
  │  pg_sshkey_connect -U alice mydb       │
  │                                        │
  │  1. pg_sshkey_challenge ──────────────►│ writes /var/run/pg_sshkey/<hex>
  │◄─ 2. <64-char hex nonce> ─────────────│
  │                                        │
  │  3. pg_sshkey_sign <nonce> <key>       │
  │     → <hex>:<base64_signature>         │
  │                                        │
  │  4. PGPASSWORD=<token> psql ──────────►│ PostgreSQL
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

---

## 2. System Requirements

### Supported distributions

| Distribution          | Minimum version | Notes                                    |
|-----------------------|-----------------|------------------------------------------|
| Ubuntu                | 22.04 LTS       | Tested on 22.04, 24.04                   |
| Debian                | 12 (Bookworm)   | Tested on 12                             |
| RHEL / Rocky / Alma   | 9.x             | Set `PAM_LIB_DIR=/lib64/security`        |

### PostgreSQL requirement

PostgreSQL **14 or later** is required.  Verify PAM support is compiled in:

```bash
psql --version                          # must print 14.x or later
pg_config --configure | grep '\-\-with-pam'   # must print: --with-pam
```

### Build dependencies

```bash
sudo apt update
sudo apt install build-essential libssl-dev libpam0g-dev pkg-config
```

| Package          | Provides                         | Why needed                                     |
|------------------|----------------------------------|------------------------------------------------|
| `build-essential`| gcc, make, dpkg-dev, libc6-dev   | Compiler, linker, make, gcc -dumpmachine triplet|
| `libssl-dev`     | OpenSSL headers + libcrypto.so   | Ed25519/RSA signing, RAND_bytes, base64        |
| `libpam0g-dev`   | PAM headers + libpam.so          | Compile and link the PAM shared module         |
| `pkg-config`     | pkg-config tool                  | Locates OpenSSL flags automatically            |

#### Verify packages installed correctly

```bash
gcc --version                          # gcc 10.x or newer
pkg-config --modversion libcrypto      # 3.0.x or newer
ls /usr/include/openssl/evp.h          # must exist
ls /usr/include/security/pam_modules.h # must exist
gcc -dumpmachine                       # e.g. x86_64-linux-gnu
```

#### Ubuntu/Debian version notes

| Release              | OpenSSL  | PAM package    |
|----------------------|----------|----------------|
| Ubuntu 22.04 (Jammy) | 3.0.2    | `libpam0g-dev` |
| Ubuntu 24.04 (Noble) | 3.0.13   | `libpam0g-dev` |
| Debian 12 (Bookworm) | 3.0.11   | `libpam0g-dev` |

---

## 3. Building from Source

```bash
tar -xzf pam_pg_sshkey-1.0.6.tar.gz
cd pam_pg_sshkey-1.0.6
make
```

Output files:

| File                  | Description                                     |
|-----------------------|-------------------------------------------------|
| `pam_pg_sshkey.so`    | PAM module — installed to the security dir      |
| `pg_sshkey_challenge` | Server tool: generate a nonce                   |
| `pg_sshkey_sign`      | Client tool: sign a nonce with an SSH key       |
| `pg_sshkey_connect`   | Client script: full connect wrapper (required)  |
| `pg_sshkey_addkey`    | Admin script: deploy public keys correctly      |

### Expected build output

```
cc -Wall -Wextra -Wpedantic -O2 -I/usr/include/security -fPIC \
   -c -o src/pam_pg_sshkey.o src/pam_pg_sshkey.c
cc -Wall -Wextra -Wpedantic -O2 -I/usr/include/security -fPIC \
   -c -o src/challenge_store.o src/challenge_store.c
...
cc -Wall -Wextra -Wpedantic -O2 -shared -fPIC \
   -o pam_pg_sshkey.so src/*.o -lcrypto -lpam
cc -Wall -Wextra -Wpedantic -O2 \
   -o pg_sshkey_sign src/pg_sshkey_sign.c -lcrypto
cc -Wall -Wextra -Wpedantic -O2 \
   -o pg_sshkey_challenge src/pg_sshkey_challenge.c ... -lcrypto
```

### Common build errors

| Error                                       | Missing package         | Fix                              |
|---------------------------------------------|-------------------------|----------------------------------|
| `fatal error: openssl/evp.h: No such file`  | `libssl-dev`            | `sudo apt install libssl-dev`    |
| `fatal error: security/pam_modules.h: ...`  | `libpam0g-dev`          | `sudo apt install libpam0g-dev`  |
| `pkg-config: command not found`             | `pkg-config`            | `sudo apt install pkg-config`    |
| `gcc: command not found`                    | `build-essential`       | `sudo apt install build-essential`|

---

## 4. Running the Test Suite

```bash
make test
```

Builds four test binaries with AddressSanitizer and UBSan and runs them:

| Binary                        | Tests                                              |
|-------------------------------|----------------------------------------------------|
| `tests/test_challenge_store`  | Nonce create/load/delete, TTL, path traversal guard|
| `tests/test_key_parser`       | Base64, authorized_keys parsing, key types         |
| `tests/test_sig_verify`       | Ed25519 and RSA signature verification             |
| `tests/test_integration`      | Full flow, replay prevention, wrong-key rejection  |
| `tests/test_system`           | pg_sshkey_challenge and pg_sshkey_sign tools       |

A clean run prints `0 failed` for every suite.

---

## 5. Installation

### Standard install (Debian/Ubuntu)

```bash
sudo make install
sudo make install-conf
```

`make install` installs:

| File                  | Destination                                      |
|-----------------------|--------------------------------------------------|
| `pam_pg_sshkey.so`    | `/lib/<arch>/security/pam_pg_sshkey.so`          |
| `pg_sshkey_sign`      | `/usr/local/bin/pg_sshkey_sign`                  |
| `pg_sshkey_challenge` | `/usr/local/bin/pg_sshkey_challenge`             |
| `pg_sshkey_connect`   | `/usr/local/bin/pg_sshkey_connect`               |
| `pg_sshkey_addkey`    | `/usr/local/bin/pg_sshkey_addkey`                |
| tmpfiles.d config     | `/usr/lib/tmpfiles.d/pg_sshkey.conf`             |

It also creates:

| Directory           | Owner             | Mode | Purpose                     |
|---------------------|-------------------|------|-----------------------------|
| `/etc/pg_sshkeys`   | root:postgres     | 0750 | Root of authorized_keys tree|
| `/var/run/pg_sshkey`| postgres:postgres | 1733 | Challenge nonce files       |

The `1733` mode on `/var/run/pg_sshkey` (sticky-bit world-write) is
critical — see [§12](#12-file--directory-permissions-reference).

`make install-conf` installs `/etc/pam.d/postgresql`, backing up any
existing file as `postgresql.bak`.

### RHEL/Fedora

```bash
sudo dnf install gcc make openssl-devel pam-devel pkgconf
sudo make install PAM_LIB_DIR=/lib64/security
sudo make install-conf
```

### Surviving reboots

`/var/run` is a tmpfs wiped at every boot. The installed `tmpfiles.d`
config recreates the challenge directory automatically at startup:

```
# /usr/lib/tmpfiles.d/pg_sshkey.conf
d /var/run/pg_sshkey 1733 postgres postgres -
```

Apply immediately without rebooting:

```bash
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/pg_sshkey.conf
```

---

## 6. PostgreSQL Configuration

### pg_hba.conf

Open `/etc/postgresql/<version>/main/pg_hba.conf` and add a `pam` line
for local connections **before** any existing `peer` or `md5` catch-alls
for normal users:

```
# TYPE  DATABASE  USER      ADDRESS     METHOD  OPTIONS
local   all       postgres              peer
local   all       all                   pam     pamservice=postgresql
host    all       all       127.0.0.1/32  scram-sha-256
host    all       all       ::1/128       scram-sha-256
```

The six columns are positional — `pam` is the METHOD and
`pamservice=postgresql` is the OPTIONS value.  A common mistake is
writing only five columns, which makes PostgreSQL interpret
`pamservice=postgresql` as the method name and log
`invalid authentication method "pamservice=postgresql"`.

**Wrong** (five columns — options parsed as method):
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
```

No password needed or wanted.

### Validate and reload

```sql
-- Check for parse errors before reloading
SELECT line_number, type, error
FROM pg_hba_file_rules
WHERE error IS NOT NULL;
```

```bash
# Reload without dropping connections
sudo systemctl reload postgresql@16-main   # adjust version
# or from inside psql:
SELECT pg_reload_conf();
```

---

## 7. PAM Configuration

`/etc/pam.d/postgresql` (installed by `make install-conf`):

```
#%PAM-1.0
auth    required    pam_pg_sshkey.so \
            authorized_keys_dir=/etc/pg_sshkeys \
            challenge_dir=/var/run/pg_sshkey

account required    pam_permit.so
```

Add `debug` temporarily to see per-attempt detail in syslog:

```
auth    required    pam_pg_sshkey.so \
            authorized_keys_dir=/etc/pg_sshkeys \
            challenge_dir=/var/run/pg_sshkey    \
            debug
```

Remove `debug` after diagnosis — it logs the challenge hex.

---

## 8. Deploying SSH Public Keys

Always use `pg_sshkey_addkey` (must run as root).  It creates the
per-user directory, writes the key, and enforces `root:postgres 0640`
permissions.  Creating keys manually almost always produces wrong
ownership (`alice:alice 0600`) that the `postgres`-owned PAM module
cannot read.

```bash
# Add a key from a .pub file
sudo pg_sshkey_addkey alice ~/.ssh/id_ed25519.pub

# Add from stdin
ssh-keygen -y -f ~/.ssh/id_ed25519 | sudo pg_sshkey_addkey alice -

# Append a second key without replacing the first
sudo pg_sshkey_addkey --append alice ~/.ssh/id_rsa.pub

# List current keys
sudo pg_sshkey_addkey --list alice

# Remove all keys for a user
sudo pg_sshkey_addkey --remove alice
```

Verify the PAM module can read the file:

```bash
sudo -u postgres cat /etc/pg_sshkeys/alice/authorized_keys
```

### Accepted key types

| Key type     | authorized_keys token | Digest   |
|--------------|-----------------------|----------|
| Ed25519      | `ssh-ed25519`         | internal |
| RSA (≥ 2048) | `ssh-rsa`             | SHA-256  |
| RSA (≥ 2048) | `rsa-sha2-256`        | SHA-256  |
| RSA (≥ 2048) | `rsa-sha2-512`        | SHA-512  |

### Generate a key for a new user

```bash
# As the database user — Ed25519 with no passphrase (required)
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""

# Register it (as root)
sudo pg_sshkey_addkey alice ~/.ssh/id_ed25519.pub
```

The key must have **no passphrase**.  `pg_sshkey_sign` reads PEM private
keys directly and cannot unlock passphrase-protected keys interactively.
To use a passphrase-protected key, export it to an unencrypted PEM file
once:

```bash
openssl pkey -in ~/.ssh/id_ed25519 -out ~/.ssh/pg_key.pem
# OpenSSL prompts for the passphrase once during export
pg_sshkey_connect -U alice -i ~/.ssh/pg_key.pem mydb
```

---

## 9. Why You Must Use pg_sshkey_connect

This section explains why running `psql` directly always fails, and why
`pg_sshkey_connect` is the required entry point.

### The PostgreSQL password handshake

When a client connects to PostgreSQL using the `pam` auth method,
PostgreSQL sends an `AUTH_REQ_PASSWORD` message to the client.  The client
must respond with a password.  PostgreSQL passes whatever the client sends
to the PAM module as the authtok.

### How libpq handles AUTH_REQ_PASSWORD

When `libpq` (the PostgreSQL client library used by `psql`) receives
`AUTH_REQ_PASSWORD`, it checks immediately whether a password is already
available.  It looks in exactly two places, in order:

1. The `password=` field in the connection string or `PGPASSWORD` environment variable
2. The `~/.pgpass` file

If neither contains a password, **libpq immediately disconnects**.  It
does not prompt the user.  It does not wait.  It logs `fe_sendauth: no
password supplied` and closes the connection.

This means the PAM module never gets a chance to run its logic — it
receives a NULL token and logs:

```
pam_pg_sshkey: failed to get auth token for 'alice' (client sent no password)
```

### Why you cannot type the token at a prompt

Even if libpq did prompt interactively (it does not for `AUTH_REQ_PASSWORD`),
you could not type the token.  The token is:

```
3a7fb2c1...d4e9 (64 hex chars) : xWKq2XCL...MTCA== (base64 signature)
```

It is 150+ characters of cryptographic material that must be computed
fresh for every connection.  It cannot be memorised or typed.

### Why PGPASSWORD set after psql starts does not work

`PGPASSWORD` must be in the environment **before** `psql` opens the
connection.  The handshake happens immediately during connection setup.
By the time psql's interactive prompt appears (if it does), the
authentication exchange is already complete or failed.

### What pg_sshkey_connect does

`pg_sshkey_connect` solves all of this by running the three steps
atomically before `psql` opens the connection:

```
1. pg_sshkey_challenge /var/run/pg_sshkey
       → generates a 32-byte nonce, stores it on disk, prints hex ID

2. pg_sshkey_sign <hex> ~/.ssh/id_ed25519
       → signs "pg-sshkey-v1\0" || nonce_bytes with your private key
       → prints <hex>:<base64_signature>

3. PGPASSWORD=<token> exec psql -U alice mydb
       → psql starts with the token already in its environment
       → when AUTH_REQ_PASSWORD arrives, libpq sends the token immediately
       → PAM module receives the token, verifies the signature, grants access
```

Steps 1–2 happen in milliseconds on the local machine.  By the time the
TCP/socket connection opens, `PGPASSWORD` is already set to a valid token.

### The complete connection timeline

```
pg_sshkey_connect -U alice mydb
  │
  ├─ pg_sshkey_challenge /var/run/pg_sshkey
  │    writes /var/run/pg_sshkey/3a7fb2c1...  (mode 0644)
  │    prints "3a7fb2c1..."
  │
  ├─ pg_sshkey_sign 3a7fb2c1... ~/.ssh/id_ed25519
  │    signs pg-sshkey-v1\0 + raw_nonce_bytes
  │    prints "3a7fb2c1...:xWKq2XCL...=="
  │
  └─ PGPASSWORD="3a7fb2c1...:xWKq2XCL...==" exec psql -U alice mydb
       │
       ├─ psql opens unix socket to PostgreSQL
       ├─ PostgreSQL sends AUTH_REQ_PASSWORD
       ├─ libpq reads PGPASSWORD, sends token
       │
       └─ pam_pg_sshkey.so receives token
            ├─ parse "3a7fb2c1...":"xWKq2XCL...=="
            ├─ load /var/run/pg_sshkey/3a7fb2c1...  (verify not expired)
            ├─ delete /var/run/pg_sshkey/3a7fb2c1...  (prevent replay)
            ├─ read /etc/pg_sshkeys/alice/authorized_keys
            ├─ verify Ed25519 signature
            └─ return PAM_SUCCESS → session opened
```

### Summary

| What you run        | What happens                                    |
|---------------------|-------------------------------------------------|
| `psql -U alice`     | libpq gets AUTH_REQ_PASSWORD, has no password, disconnects immediately |
| `PGPASSWORD=wrong psql` | PAM receives wrong string, fails signature verification |
| `pg_sshkey_connect -U alice` | Works: token computed before connection opens |

---

## 10. Connecting as a User

### Prerequisites

1. An SSH key with no passphrase in `~/.ssh/id_ed25519`
2. The public key registered with `sudo pg_sshkey_addkey <user> ~/.ssh/id_ed25519.pub`
3. `pg_sshkey_connect` in your `PATH` (installed by `make install`)

### Generate a key (first time)

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
sudo pg_sshkey_addkey "$USER" ~/.ssh/id_ed25519.pub
```

### Connect

```bash
pg_sshkey_connect                            # connect as $USER to $USER db
pg_sshkey_connect mydb                       # specific database
pg_sshkey_connect -U alice mydb              # specific user
pg_sshkey_connect -i ~/.ssh/pg_key mydb      # specific key file
pg_sshkey_connect -h dbserver -U alice mydb  # remote host
pg_sshkey_connect -v mydb                    # verbose: show each step
pg_sshkey_connect -U alice -- -c "SELECT 1"  # pass flags through to psql
```

### Troubleshoot a connection

```bash
pg_sshkey_connect -v -U alice mydb 2>&1
```

Verbose output shows each step:

```
pg_sshkey_connect: username:      alice
pg_sshkey_connect: database:      mydb
pg_sshkey_connect: key:           /home/alice/.ssh/id_ed25519
pg_sshkey_connect: challenge dir: /var/run/pg_sshkey
pg_sshkey_connect: generating challenge...
pg_sshkey_connect: challenge:     3a7fb2c1...
pg_sshkey_connect: signing challenge...
pg_sshkey_connect: token:         3a7fb2c1...:xWKq2XCL...
pg_sshkey_connect: running: PGPASSWORD=<token> psql -U alice -d mydb
```

If any step fails the script exits before opening the connection, so the
PostgreSQL log stays clean.

### Using from scripts

Each token is single-use.  Generate a fresh token per connection:

```bash
pg_sshkey_connect -U alice mydb -- -c "SELECT count(*) FROM orders"
```

---

## 11. Module Reference

### pam_pg_sshkey.so options

| Option                       | Default              | Description                          |
|------------------------------|----------------------|--------------------------------------|
| `authorized_keys_dir=<path>` | `/etc/pg_sshkeys`    | Root of per-user key directories     |
| `challenge_dir=<path>`       | `/var/run/pg_sshkey` | Directory holding nonce files        |
| `debug`                      | off                  | Verbose syslog at `LOG_DEBUG` level  |

### pg_sshkey_challenge

```
pg_sshkey_challenge <challenge_dir>
```

Creates the directory if absent (mode 1733), generates a 32-byte
cryptographically random nonce, writes it to `<challenge_dir>/<hex>`
(mode 0644), and prints the hex ID to stdout.

Exit 0 on success, 1 on error.

### pg_sshkey_sign

```
pg_sshkey_sign <challenge_hex> <private_key_path>
```

Signs `"pg-sshkey-v1\0" || challenge_bytes` and prints
`<challenge_hex>:<base64_signature>` to stdout.

Accepted key formats:

| Format                             | Key types           |
|------------------------------------|---------------------|
| OpenSSH (`BEGIN OPENSSH PRIVATE KEY`) | Ed25519 only, unencrypted |
| PKCS#8 PEM (`BEGIN PRIVATE KEY`)   | Ed25519, RSA        |
| Traditional PEM (`BEGIN RSA PRIVATE KEY`) | RSA           |

For RSA OpenSSH keys or passphrase-protected keys:
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

Must be run as root.  Enforces `root:postgres 0640` on the key file.

---

## 12. File & Directory Permissions Reference

| Path                                      | Owner             | Mode | Notes                          |
|-------------------------------------------|-------------------|------|--------------------------------|
| `/lib/<arch>/security/pam_pg_sshkey.so`   | root:root         | 0755 | Loaded by PAM as root          |
| `/usr/local/bin/pg_sshkey_challenge`      | root:root         | 0755 | Run by any user                |
| `/usr/local/bin/pg_sshkey_sign`           | root:root         | 0755 | Run by any user                |
| `/usr/local/bin/pg_sshkey_connect`        | root:root         | 0755 | Run by any user                |
| `/usr/local/bin/pg_sshkey_addkey`         | root:root         | 0755 | Run as root only               |
| `/etc/pam.d/postgresql`                   | root:root         | 0644 | PAM service config             |
| `/etc/pg_sshkeys/`                        | root:postgres     | 0750 | Root of key tree               |
| `/etc/pg_sshkeys/<user>/`                 | root:postgres     | 0750 | Per-user directory             |
| `/etc/pg_sshkeys/<user>/authorized_keys`  | root:postgres     | 0640 | Must not be group/world writable |
| `/var/run/pg_sshkey/`                     | postgres:postgres | 1733 | Sticky world-write nonce dir   |
| `/var/run/pg_sshkey/<hex>`                | <client user>     | 0644 | Nonce file; readable by postgres |

### Challenge directory mode 1733 explained

```
drwx-wx-wt  postgres postgres  /var/run/pg_sshkey
```

| Bit          | Who          | Effect                                          |
|--------------|--------------|-------------------------------------------------|
| `rwx` owner  | postgres     | PAM module can read and delete any nonce file   |
| `-wx` group  | postgres grp | postgres group members can create/enter         |
| `-wx` other  | everyone     | Any user can create a nonce file and enter dir  |
| `t` sticky   | everyone     | Can only delete files you own                   |

Nonce files are created mode `0644` so the `postgres`-owned PAM module
can read files created by any user.

### authorized_keys ownership is critical

The PAM module runs as the `postgres` OS user.  If `authorized_keys` is
owned by the database user (`alice:alice 0600`), `postgres` cannot read
it and authentication fails.  Always use `pg_sshkey_addkey` to deploy
keys — it enforces `root:postgres 0640` automatically.

---

## 13. Logging & Troubleshooting

### View auth logs

```bash
journalctl -t postgresql --since "10 minutes ago" | grep pam_pg_sshkey
```

### Log messages reference

| Message | Meaning | Fix |
|---------|---------|-----|
| `authenticated with key ssh-ed25519` | Success | — |
| `failed to get auth token (client sent no password)` | psql run directly without PGPASSWORD | Use `pg_sshkey_connect` |
| `malformed token` | Token not in `hex:base64` format | Verify `pg_sshkey_sign` output |
| `challenge not found or expired` | Nonce >60s old, already used, or challenge dir wrong | Check `/var/run/pg_sshkey`; use fresh token |
| `cannot read authorized_keys (permission denied)` | File is not `root:postgres 0640` | `sudo pg_sshkey_addkey --list <user>` then re-add |
| `no authorized_keys` | File doesn't exist | `sudo pg_sshkey_addkey <user> ~/.ssh/id_ed25519.pub` |
| `no valid keys (empty or unsupported types)` | File exists but has no Ed25519/RSA keys | Check key type; ECDSA not supported |
| `authentication failed` | Signature verification failed | Wrong key; regenerate and re-register |
| `account not found in passwd` | OS user doesn't exist | Create OS account or check username |
| `conversation failed` | PAM conv returned error | Check challenge dir permissions |
| `invalid authentication method "pamservice=postgresql"` | pg_hba.conf has 5 columns not 6 | See §6 |

### `failed to get auth token (client sent no password)`

This is the most common error.  It means `psql` was run directly without
a pre-computed token in `PGPASSWORD`.

```bash
# Wrong — psql has no password to send
psql -U alice mydb

# Correct — pg_sshkey_connect computes the token first
pg_sshkey_connect -U alice mydb
```

See [§9](#9-why-you-must-use-pg_sshkey_connect) for a full explanation.

### `cannot read authorized_keys (permission denied)`

The key file is not readable by the `postgres` OS user running the PAM
module.  The log shows the actual uid, gid, and mode and the fix command.

```bash
# Re-deploy with correct permissions
sudo pg_sshkey_addkey alice ~/.ssh/id_ed25519.pub

# Or fix manually
sudo chown root:postgres /etc/pg_sshkeys/alice/authorized_keys
sudo chmod 640 /etc/pg_sshkeys/alice/authorized_keys

# Verify
sudo -u postgres cat /etc/pg_sshkeys/alice/authorized_keys
```

### `Failed to create challenge` from pg_sshkey_connect

The challenge directory doesn't exist or has wrong permissions.

```bash
ls -la /var/run/ | grep pg_sshkey
# Should show: drwx-wx-wt 2 postgres postgres ... pg_sshkey

# If missing or wrong:
sudo chown postgres:postgres /var/run/pg_sshkey
sudo chmod 1733 /var/run/pg_sshkey

# If missing entirely after a reboot:
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/pg_sshkey.conf
```

### `DECODER routines: unsupported, Input type: PEM`

Your key is in OpenSSH format but is either RSA or passphrase-protected.
Convert it:

```bash
openssl pkey -in ~/.ssh/id_rsa -out ~/.ssh/pg_key.pem
pg_sshkey_connect -U alice -i ~/.ssh/pg_key.pem mydb
```

---

## 14. Uninstalling

```bash
sudo make uninstall

# Restore original PAM config if needed
sudo mv /etc/pam.d/postgresql.bak /etc/pam.d/postgresql

# Revert pg_hba.conf, then reload
sudo systemctl reload postgresql@16-main
```

---

## 15. Security Hardening Checklist

- [ ] PostgreSQL connections use TLS (`ssl = on`, `sslmode=require`)
- [ ] `authorized_keys` files are `root:postgres 0640`
- [ ] `/var/run/pg_sshkey` is `postgres:postgres 1733`
- [ ] `debug` is **off** in `/etc/pam.d/postgresql`
- [ ] SSH keys have no passphrase, or unencrypted PEM exports are used
- [ ] `/etc/pg_sshkeys` is under configuration management (Ansible/Puppet)
- [ ] Stale nonce files are swept every 2 minutes (cron or systemd timer)
- [ ] RSA keys in `authorized_keys` are ≥ 3072 bits; Ed25519 preferred
- [ ] Auth failures are reviewed in the journal for brute-force indicators
