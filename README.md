# pam_pg_sshkey

A custom PAM module (written in C) that lets PostgreSQL authenticate users
via **SSH public-key cryptography** instead of passwords.

## How it works

```
 ┌─────────────────────────────────────────────────────────────────┐
 │                         Authentication Flow                      │
 │                                                                  │
 │  1. Server issues a random 32-byte challenge (nonce)             │
 │       pg_sshkey_challenge → <challenge_hex>                      │
 │                                                                  │
 │  2. Client signs the challenge with its SSH private key          │
 │       pg_sshkey_sign <challenge_hex> ~/.ssh/id_ed25519           │
 │       → <challenge_hex>:<base64_signature>                       │
 │                                                                  │
 │  3. Client connects to PostgreSQL with that string as password   │
 │       psql "host=db user=alice password=<challenge_hex>:<sig>"   │
 │                                                                  │
 │  4. PostgreSQL passes user+password to PAM (pam_pg_sshkey.so)   │
 │                                                                  │
 │  5. PAM module:                                                  │
 │       a. Parses challenge_hex + base64_sig from token            │
 │       b. Looks up challenge from /var/run/pg_sshkey/             │
 │       c. Validates timestamp (60-second TTL), deletes nonce      │
 │       d. Reads /etc/pg_sshkeys/<username>/authorized_keys        │
 │       e. Verifies signature against each key                     │
 │       f. Returns PAM_SUCCESS on first match                      │
 └─────────────────────────────────────────────────────────────────┘
```

The challenge prevents replay attacks. The nonce is deleted immediately
after the first use, so a captured token cannot be reused.

---

## Requirements

| Package           | Debian/Ubuntu           | RHEL/Fedora               |
|-------------------|-------------------------|---------------------------|
| libssl (OpenSSL)  | `libssl-dev`            | `openssl-devel`           |
| libpam            | `libpam0g-dev`          | `pam-devel`               |
| gcc               | `gcc`                   | `gcc`                     |

```bash
# Debian/Ubuntu
sudo apt install libssl-dev libpam0g-dev gcc make

# RHEL/Fedora
sudo dnf install openssl-devel pam-devel gcc make
```

---

## Build

```bash
git clone https://github.com/yourorg/pam_pg_sshkey
cd pam_pg_sshkey
make
```

Output files:

| File                    | Purpose                                  |
|-------------------------|------------------------------------------|
| `pam_pg_sshkey.so`      | PAM module — install to `/lib/security/` |
| `pg_sshkey_challenge`   | Server: generate a nonce                 |
| `pg_sshkey_sign`        | Client: sign a nonce with SSH private key|

---

## Install

```bash
sudo make install          # installs .so, binaries, creates directories
sudo make install-conf     # installs /etc/pam.d/postgresql (backs up old)
```

Default paths:

| Path                              | Purpose                          |
|-----------------------------------|----------------------------------|
| `/lib/<arch>/security/pam_pg_sshkey.so` | PAM module                 |
| `/etc/pg_sshkeys/<user>/authorized_keys` | Per-user public keys      |
| `/var/run/pg_sshkey/`             | Temporary challenge nonce files  |

---

## PostgreSQL configuration

### pg_hba.conf

Replace (or add alongside) your existing auth line:

```
# /etc/postgresql/16/main/pg_hba.conf

# SSH-key PAM auth for all remote connections
host    all    all    0.0.0.0/0    pam    pamservice=postgresql
```

> **Important:** The PostgreSQL user must already exist in the database:
> ```sql
> CREATE USER alice;
> ```
> PAM only handles authentication; PostgreSQL still manages authorisation.

### Reload PostgreSQL

```bash
sudo systemctl reload postgresql
```

---

## Deploy SSH public keys

For each database user, create an `authorized_keys` file:

```bash
# As root:
PGUSER=alice
sudo mkdir -p /etc/pg_sshkeys/$PGUSER
sudo cp /home/$PGUSER/.ssh/id_ed25519.pub \
        /etc/pg_sshkeys/$PGUSER/authorized_keys
sudo chown -R root:postgres /etc/pg_sshkeys/
sudo chmod 750 /etc/pg_sshkeys/
sudo chmod 640 /etc/pg_sshkeys/$PGUSER/authorized_keys
```

The file uses standard OpenSSH `authorized_keys` format:

```
ssh-ed25519 AAAA... alice@laptop
ssh-rsa AAAA... alice@desktop
```

---

## Connecting as a user

Use `pg_sshkey_connect` — the included wrapper that handles the full
challenge-sign-connect flow in one command:

```bash
pg_sshkey_connect                          # connect as $USER to $USER db
pg_sshkey_connect mydb                     # connect to a specific database
pg_sshkey_connect -U alice mydb            # connect as alice
pg_sshkey_connect -i ~/.ssh/pg_key mydb    # use a specific key file
pg_sshkey_connect -h dbserver -U alice mydb  # remote host
```

**You must use `pg_sshkey_connect` (or manually set `PGPASSWORD` to a signed
token) every time you connect.** Running `psql` directly will fail: when
PostgreSQL sends the password challenge, `libpq` immediately disconnects if
no password is pre-loaded, before the PAM module can do anything.

### What pg_sshkey_connect does

```
1. pg_sshkey_challenge /var/run/pg_sshkey  → 64-char hex nonce
2. pg_sshkey_sign <nonce> <key>            → nonce:base64_signature
3. PGPASSWORD=<token> psql ...             → authenticated session
```

### Key format support

| Key file                         | Works directly |
|----------------------------------|----------------|
| `~/.ssh/id_ed25519` (OpenSSH)    | ✓              |
| `~/.ssh/id_rsa` (OpenSSH)        | Convert first  |
| `key.pem` (PKCS#8 or traditional)| ✓              |

To convert an OpenSSH RSA key to PEM:
```bash
openssl pkey -in ~/.ssh/id_rsa -out ~/.ssh/id_rsa.pem
pg_sshkey_connect -U alice -i ~/.ssh/id_rsa.pem mydb
```

---

## Security notes

| Concern               | Mitigation                                              |
|-----------------------|---------------------------------------------------------|
| Replay attacks        | 60-second TTL; nonce deleted on first use               |
| Key file permissions  | Module refuses world/group-writable authorized_keys     |
| Path traversal        | Challenge hex validated to be hex-only before use       |
| Private key safety    | `pg_sshkey_sign` only needed at sign time; consider     |
|                       | using an `ssh-agent` integration (see below)            |
| PostgreSQL PAM limit  | PAM receives only username+password; the signed token   |
|                       | is the password, so TLS on the PostgreSQL connection    |
|                       | is strongly recommended (sslmode=verify-full)           |

### ssh-agent integration (recommended)

Instead of reading the raw private key file with `pg_sshkey_sign`, use
`ssh-agent` so the private key never leaves the agent:

```bash
# Sign via ssh-agent (requires ssh-keysign or agent protocol)
# A minimal approach using ssh's ProxyCommand pattern or
# the pam_ssh_agent_auth module for agent forwarding.
```

---

## Module options (in /etc/pam.d/postgresql)

```
auth required pam_pg_sshkey.so \
    authorized_keys_dir=/etc/pg_sshkeys \
    challenge_dir=/var/run/pg_sshkey    \
    debug
```

| Option                      | Default              | Description                       |
|-----------------------------|----------------------|-----------------------------------|
| `authorized_keys_dir=<dir>` | `/etc/pg_sshkeys`    | Root directory for key files      |
| `challenge_dir=<dir>`       | `/var/run/pg_sshkey` | Directory holding nonce files     |
| `debug`                     | off                  | Log verbose messages to syslog    |

---

## File structure

```
pam_pg_sshkey/
├── Makefile
├── README.md
├── config/
│   └── pam.d/
│       └── postgresql          ← /etc/pam.d/postgresql
└── src/
    ├── pam_pg_sshkey.c         ← PAM module (main entry point)
    ├── challenge_store.[ch]    ← Nonce create / load / delete
    ├── key_parser.[ch]         ← Parse authorized_keys → EVP_PKEY
    ├── sig_verify.[ch]         ← Verify Ed25519 / RSA signatures
    ├── pg_sshkey_challenge.c   ← Server: generate nonce
    └── pg_sshkey_sign.c        ← Client: sign nonce with private key
```

---

## License

MIT. See individual source files.
