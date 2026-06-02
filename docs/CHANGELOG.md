# Changelog

All notable changes to `pam_pg_sshkey` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [1.0.8] — 2026-06-01

### Added

- **`pam_pg_sshkey.py`** — Python module for authenticating to PostgreSQL
  with pam_pg_sshkey from application code, without shell wrappers or
  external processes.

  Designed for replication subscribers and any application using `psycopg2`
  directly.  Everything is done in-process using Python's `cryptography`
  library — no subprocess calls, no shell, no `pg_sshkey_connect`.

  Core API:

  ```python
  from pam_pg_sshkey import get_token, connect, connect_replication

  # Low-level: get the signed token and use it yourself
  token = get_token(key_path="~/.ssh/id_ed25519")
  conn  = psycopg2.connect(host="publisher", user="replicator",
                           dbname="mydb", password=token)

  # High-level convenience wrapper
  conn = connect(user="alice", dbname="mydb", host="dbserver")

  # Replication subscriber connection
  conn = connect_replication(user="replicator", host="publisher.example.com",
                             dbname="mydb")
  ```

  Supported key formats:
  - OpenSSH format (`BEGIN OPENSSH PRIVATE KEY`) — Ed25519 and RSA,
    with or without passphrase
  - PKCS#8 PEM (`BEGIN PRIVATE KEY`) — Ed25519 and RSA
  - Traditional PEM (`BEGIN RSA PRIVATE KEY`) — RSA

  Requirements: `pip install psycopg2-binary cryptography`
  For passphrase-protected OpenSSH keys: also `pip install bcrypt`

- **`tests/test_python_module.py`** — 32 unit tests for `pam_pg_sshkey.py`
  covering sign prefix correctness, key loading (all formats, with/without
  passphrase), challenge creation (file mode, uniqueness, atomicity), signing
  (Ed25519 and RSA, cross-verified against public key), `get_token()` end-to-end,
  and API guards.

---

## [1.0.7] — 2026-06-01

### Added

- **`pg_sshkey_query`** — Python utility script for connecting to PostgreSQL
  with SSH-key authentication and running a query.

  Replicates the token-generation flow of `pg_sshkey_connect` in Python,
  then uses `psycopg2` to open the connection with the signed token as the
  password.  The token is computed before `psycopg2.connect()` is called
  and passed as `password=`, so libpq holds it ready to send the instant
  `AUTH_REQ_PASSWORD` arrives.

  ```
  pg_sshkey_query                        # SELECT 1 as $USER
  pg_sshkey_query -U alice -d mydb       # specific user and database
  pg_sshkey_query -q "SELECT version()"  # custom query
  pg_sshkey_query -v                     # verbose: show each step
  ```

  Requires `psycopg2-binary` (`pip install psycopg2-binary`).

---

## [1.0.6] — 2026-06-01

### Fixed

- **`pg_sshkey_challenge` failed with `chmod: Operation not permitted`**
  for any user who does not own the challenge directory.

  A `chmod(dir, 01733)` call added in 1.0.3 ran on every challenge
  creation.  Because the directory is owned by `postgres`, any other user
  got `EPERM` and the tool exited before creating the nonce.  The call
  has been removed — permissions are set once at install time and
  recreated at boot by `tmpfiles.d`.

---

## [1.0.5] — 2026-06-01

### Added

- **`pg_sshkey_addkey`** — admin script that deploys a public key with
  correct `root:postgres 0640` ownership.  Using it is required; creating
  keys manually produces `<user>:<user> 0600` files that the
  `postgres`-owned PAM module cannot read.

  ```
  sudo pg_sshkey_addkey alice ~/.ssh/id_ed25519.pub
  sudo pg_sshkey_addkey --append alice ~/.ssh/id_rsa.pub
  sudo pg_sshkey_addkey --list alice
  sudo pg_sshkey_addkey --remove alice
  ```

### Fixed

- **PAM module silently failed for non-superusers** when their
  `authorized_keys` file was `<user>:<user> 0600`.  The `postgres`
  process could `stat()` the file (world-`x` on the parent directory
  was sufficient) but `open()` failed silently and the module logged the
  misleading `no valid keys` message.

  An explicit `access(R_OK)` check now runs after `stat()`.  When the
  file is unreadable the module logs the actual uid, gid, and mode and
  prints the exact `chown`/`chmod` commands needed to fix it.

---

## [1.0.4] — 2026-06-01

### Added

- **`pg_sshkey_connect`** — the required client entry point.

  `psql` cannot be used directly: when PostgreSQL sends
  `AUTH_REQ_PASSWORD`, libpq checks immediately for a pre-loaded
  password.  If `PGPASSWORD` is not set, libpq disconnects without
  sending anything — the PAM module receives a NULL token and logs
  `failed to get auth token (client sent no password)`.

  `pg_sshkey_connect` computes the token before the connection opens:

  1. Runs `pg_sshkey_challenge` to create a nonce
  2. Runs `pg_sshkey_sign` to produce a signed token
  3. Validates token format
  4. Exports `PGPASSWORD=<token>` and `exec`s `psql`

  Options: `-U`, `-h`, `-p`, `-d`, `-i` (key file), `-c` (challenge
  dir), `-v` (verbose), `--` (pass remaining args to psql).

---

## [1.0.3] — 2026-06-01

### Fixed

- **`pg_sshkey_challenge` failed with `Permission denied`** for
  non-`postgres` users.

  The challenge directory was `postgres:postgres 0750` — inaccessible to
  any other user.  Changed to `postgres:postgres 1733` (sticky world-write,
  matching `/tmp` semantics): any user can create nonce files; only the
  owner can delete their own; `postgres` can read and delete any file.

  Nonce files changed from `0600` to `0644` so the PAM module (running
  as `postgres`) can read files created by any client user.

- **Challenge directory lost on reboot** — `make install` now installs
  `/usr/lib/tmpfiles.d/pg_sshkey.conf` so systemd recreates the directory
  correctly at every boot.

---

## [1.0.2] — 2026-06-01

### Fixed

- **`pg_sshkey_sign` failed with `DECODER routines: unsupported,
  Input type: PEM`** when given an OpenSSH private key
  (`-----BEGIN OPENSSH PRIVATE KEY-----`).

  `ssh-keygen` has produced OpenSSH format keys by default since 2014.
  OpenSSL's `PEM_read_PrivateKey` and `OSSL_DECODER` cannot read this
  format.  `pg_sshkey_sign` now parses OpenSSH format natively:

  - Detects passphrase-protected keys and prints actionable conversion instructions
  - For Ed25519: extracts the 32-byte seed via `EVP_PKEY_new_raw_private_key()`
  - For non-Ed25519 OpenSSH keys: prints the `openssl pkey` conversion command

  Key format support matrix:

  | Format                            | Ed25519 | RSA          |
  |-----------------------------------|---------|--------------|
  | OpenSSH (`BEGIN OPENSSH ...`)     | ✓       | convert first|
  | PKCS#8 PEM (`BEGIN PRIVATE KEY`)  | ✓       | ✓            |
  | Traditional PEM (`BEGIN RSA ...`) | ✓       | ✓            |

---

## [1.0.1] — 2026-06-01

### Fixed

- **`conversation failed` / `failed to get auth token`** on every login.

  PostgreSQL does not call `pam_set_item(PAM_AUTHTOK)` before invoking
  `pam_authenticate()`.  It stores the client password only in
  `appdata_ptr` of the `pam_conv` struct.  Any call to
  `pam_get_authtok()` — even with a NULL prompt — falls through to the
  conversation function when `PAM_AUTHTOK` is unset.  PostgreSQL's
  conversation function then issues a second `AUTH_REQ_PASSWORD` to the
  client; the client does not expect a second challenge and disconnects.

  Fixed by calling the conversation function directly via
  `pam_get_item(PAM_CONV)` with a single `PAM_PROMPT_ECHO_OFF` message.
  PostgreSQL answers immediately from `appdata_ptr` without network I/O.
  The result is cached with `pam_set_item(PAM_AUTHTOK)`.

---

## [1.0.0] — 2026-06-01

Initial release.

### Added

- `pam_pg_sshkey.so` — PAM module implementing challenge-response
  authentication via SSH public keys for PostgreSQL 14+.
- `challenge_store.c` — filesystem-backed nonce store with 60-second TTL,
  atomic `O_CREAT|O_EXCL` creation, hex-only ID validation.
- `key_parser.c` — OpenSSH `authorized_keys` parser producing
  `EVP_PKEY` objects; supports `ssh-ed25519`, `ssh-rsa`,
  `rsa-sha2-256`, `rsa-sha2-512`.
- `sig_verify.c` — signature verification via OpenSSL EVP; signed
  message is `"pg-sshkey-v1\0" || challenge_bytes`.
- `pg_sshkey_challenge` — server nonce generator.
- `pg_sshkey_sign` — client signing tool (PKCS#8 and traditional PEM).
- Test suite: 51 tests across challenge_store, key_parser, sig_verify,
  and integration suites; built with AddressSanitizer and UBSan.
- `Makefile` with `all`, `test`, `install`, `install-conf`,
  `uninstall`, `clean` targets.
- `config/pam.d/postgresql` — drop-in PAM service config.
