# Changelog

All notable changes to `pam_pg_sshkey` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## [1.0.5] — 2026-06-01

### Added

- **`pg_sshkey_addkey`** — key management script (installed to `$BIN_DIR`,
  must be run as root).

  Creates the per-user directory, writes the public key, and enforces
  `root:postgres 0640` ownership on both the directory and the file.
  This is the only supported way to deploy keys — doing it manually
  produces `<user>:<user> 0600` files that the `postgres`-owned PAM
  module cannot read.

  ```
  sudo pg_sshkey_addkey alice ~/.ssh/id_ed25519.pub
  sudo pg_sshkey_addkey --append alice ~/.ssh/id_rsa.pub
  sudo pg_sshkey_addkey --list alice
  sudo pg_sshkey_addkey --remove alice
  ```

### Fixed

- **PAM module silently failed for non-superusers** when their
  `authorized_keys` file was owned by the OS user (`alice:alice 0600`)
  rather than `root:postgres 0640`. The `postgres` process running the
  PAM module could `stat()` the file (world-execute on the parent
  directory was sufficient) but could not `open()` it. The module
  logged `no valid keys` with no indication of the real cause.

  Fixed by adding an explicit `access(R_OK)` check after `stat()`.
  When the file is unreadable the module now logs the actual uid, gid,
  and mode of the file and prints the exact `chown`/`chmod` commands
  needed to fix it.

---

## [1.0.4] — 2026-06-01

### Added

- **`pg_sshkey_connect` — client entry point script** (`src/pg_sshkey_connect`,
  installed to `$BIN_DIR/pg_sshkey_connect`).

  Previously, users had to manually run `pg_sshkey_challenge`, `pg_sshkey_sign`,
  and set `PGPASSWORD` before every `psql` invocation. Running `psql` directly
  always failed because `libpq` immediately disconnects when `AUTH_REQ_PASSWORD`
  arrives with no password pre-set, before the PAM module can do anything —
  producing `failed to get auth token (client sent no password)` in the log.

  `pg_sshkey_connect` wraps the full flow atomically:
  1. Runs `pg_sshkey_challenge` to obtain a nonce
  2. Runs `pg_sshkey_sign` to produce a signed token
  3. Validates the token format before attempting a connection
  4. Exports `PGPASSWORD=<token>` and `exec`s `psql`

  Options mirror `psql`: `-U`, `-h`, `-p`, `-d`, `-i` (key file),
  `-c` (challenge dir), `-v` (verbose), and `--` to pass remaining
  arguments directly to `psql`.

  `make install` now installs `pg_sshkey_connect` alongside the other binaries.

### Fixed

- **`failed to get auth token (client sent no password)`** — documented the
  root cause (libpq disconnects on `AUTH_REQ_PASSWORD` with no password set)
  and added a dedicated troubleshooting entry to `INSTALL.md`.

---

## [1.0.3] — 2026-06-01

### Fixed

- **`pg_sshkey_challenge` failed with `Permission denied` for non-postgres users.**

  The challenge directory `/var/run/pg_sshkey` was installed with mode `0750`
  owned by `postgres:postgres`, so only the `postgres` user could enter it.
  Client users (e.g. `test`, `alice`) could not create nonce files, causing
  `pg_sshkey_challenge` to fail with "Failed to create challenge" and producing
  a malformed empty token.

  Fixed by changing the challenge directory to mode **1733** (sticky-bit
  world-write), matching the semantics of `/tmp`:
  - Any user can create nonce files (`-wx` for group and other)
  - Only the file's owner can delete their own nonce (sticky bit `t`)
  - The `postgres` user (directory owner) can read and unlink any file

  Nonce files are now created with mode **0644** (was `0600`) so the
  `postgres`-owned PAM module can read files created by any client user.

  `pg_sshkey_challenge` now also `chmod`s the directory to `1733` each time
  it runs, self-correcting any wrong permissions left after a reboot or
  manual misconfiguration.

- **Challenge directory lost on reboot** — `/var/run` is a `tmpfs` that is
  wiped at every boot. `make install` now installs
  `/usr/lib/tmpfiles.d/pg_sshkey.conf` so systemd recreates the directory
  with the correct owner and mode automatically at startup.

---

## [1.0.2] — 2026-06-01

### Fixed

- **`pg_sshkey_sign` failed with `DECODER routines: unsupported, Input type: PEM`
  when given an OpenSSH private key file** (`-----BEGIN OPENSSH PRIVATE KEY-----`).

  The tool previously called `PEM_read_PrivateKey()`, which only understands
  PKCS#8 (`-----BEGIN PRIVATE KEY-----`) and traditional (`-----BEGIN RSA PRIVATE KEY-----`)
  PEM formats. OpenSSH's own format — the default output of `ssh-keygen` since
  OpenSSH 6.5 (2014) — uses a custom binary encoding that OpenSSL cannot decode
  with standard PEM APIs, and `OSSL_DECODER` does not support it either.

  `pg_sshkey_sign` now detects `-----BEGIN OPENSSH PRIVATE KEY-----` and parses
  the format natively:
  - Reads the binary structure (magic, cipher, kdf, public key blob, private section)
  - Detects passphrase-protected keys (non-`none` cipher) and prints a clear error
    with the commands needed to remove the passphrase or convert to PKCS#8 PEM
  - For Ed25519 keys, extracts the 32-byte seed and loads it via
    `EVP_PKEY_new_raw_private_key()`
  - For non-Ed25519 OpenSSH format keys (e.g. `ssh-rsa`), prints a conversion
    command (`openssl pkey -in <keyfile> -out key.pem`)

  PKCS#8 PEM and traditional PEM formats continue to work as before.

  **Key format support matrix after this fix:**

  | Key file format               | Ed25519 | RSA  |
  |-------------------------------|---------|------|
  | OpenSSH (`BEGIN OPENSSH ...`) | ✓       | convert to PEM first |
  | PKCS#8 PEM (`BEGIN PRIVATE KEY`) | ✓    | ✓    |
  | Traditional PEM (`BEGIN RSA PRIVATE KEY`) | ✓ | ✓ |

---

## [1.0.1] — 2026-06-01

### Fixed

- **`conversation failed` / `failed to get auth token` on every login.**

  The root cause was a misunderstanding of how PostgreSQL passes the client
  password to PAM modules.

  PostgreSQL does **not** call `pam_set_item(PAM_AUTHTOK)` before invoking
  `pam_authenticate()`.  Instead it stores the client password exclusively
  in `appdata_ptr` of the `pam_conv` struct.  As a result:

  - `pam_get_item(PAM_AUTHTOK)` always returns `NULL`.
  - `pam_get_authtok()` with any prompt (including `NULL`) falls through to
    calling the conversation function, which PostgreSQL's implementation
    handles by issuing a second `AUTH_REQ_PASSWORD` round-trip to the
    client.  The client does not expect a second password challenge and the
    exchange fails with "conversation failed".

  The fix introduces `get_token_via_conv()`, which retrieves the token by
  calling the PAM conversation function directly via `pam_get_item(PAM_CONV)`
  and issuing exactly one `PAM_PROMPT_ECHO_OFF` message.  PostgreSQL's
  conversation function answers immediately from `appdata_ptr` without any
  network I/O.  The result is cached with `pam_set_item(PAM_AUTHTOK)` so
  stacked PAM modules can read it normally.

  The `(void)flags` suppression for the previously-warned unused `flags`
  parameter in `pam_sm_authenticate` was also added, eliminating the
  remaining compiler warning.

---

## [1.0.0] — 2026-06-01

Initial public release.

### Added

#### Core PAM module (`pam_pg_sshkey.so`)
- `pam_sm_authenticate`: full challenge-response authentication flow.
  Parses the `<challenge_hex>:<base64_signature>` token from the PAM
  authtok, loads and expires the nonce, iterates the user's
  `authorized_keys` entries, and verifies the signature.
- `pam_sm_acct_mgmt`: validates that the OS account still exists in
  `passwd`, so deleted system accounts cannot authenticate even if their
  database role persists.
- `pam_sm_setcred`: no-op stub required by the PAM specification.
- Module options: `authorized_keys_dir`, `challenge_dir`, `debug`.
- Permission guard: refuses `authorized_keys` files that are group- or
  world-writable.
- Path-traversal guard: challenge hex IDs validated to be `[0-9a-f]+`
  before being used as filesystem names.

#### Challenge store (`challenge_store.c`)
- `challenge_create`: generates a 32-byte cryptographically random nonce
  via `RAND_bytes`, hex-encodes it, and stores it atomically with
  `O_CREAT | O_EXCL` to prevent overwrite races.
- `challenge_load`: reads and validates a nonce file, enforces a 60-second
  TTL, and deletes expired files automatically.
- `challenge_delete`: removes a nonce file immediately after first use to
  prevent replay attacks.

#### Key parser (`key_parser.c`)
- `parse_authorized_keys`: parses OpenSSH `authorized_keys` files into a
  linked list of `key_list_t` entries backed by OpenSSL `EVP_PKEY` objects.
  Skips blank lines, `#` comments, and unsupported key types gracefully.
- `b64_decode`: base64 decoder backed by OpenSSL BIO chain.
- SSH wire-format decoders for:
  - `ssh-ed25519` — 32-byte raw public key via `EVP_PKEY_new_raw_public_key`.
  - `ssh-rsa` / `rsa-sha2-256` / `rsa-sha2-512` — RSA modulus and exponent
    decoded from SSH mpint encoding; uses `EVP_PKEY_fromdata` on OpenSSL ≥ 3.0
    and the legacy `RSA_new` / `RSA_set0_key` path on OpenSSL 1.x.

#### Signature verifier (`sig_verify.c`)
- `verify_signature`: verifies ECDSA-style signatures via `EVP_DigestVerify`.
  Signed message is `"pg-sshkey-v1\0" || challenge_bytes` (domain-separated).
  Supported algorithms:
  - Ed25519 (one-shot `EVP_DigestVerify` with `md=NULL`)
  - RSA-PKCS1-v1_5 with SHA-256 (`ssh-rsa`, `rsa-sha2-256`)
  - RSA-PKCS1-v1_5 with SHA-512 (`rsa-sha2-512`)

#### Server helper (`pg_sshkey_challenge.c`)
- Standalone binary: creates the challenge directory if absent, generates a
  nonce via `challenge_create`, and prints the hex ID to stdout.

#### Client helper (`pg_sshkey_sign.c`)
- Standalone binary: reads a PEM private key (Ed25519 or RSA), signs the
  canonical message, and prints the PAM token to stdout.
- Automatically selects SHA-256 for RSA and the Ed25519 internal hash.

#### Build system
- `Makefile` with targets: `all`, `test` / `check`, `install`,
  `install-conf`, `uninstall`, `clean`.
- Compiler flags detected via `pkg-config libcrypto`.
- Install paths configurable via `PAM_LIB_DIR`, `BIN_DIR`, `KEY_DIR`,
  `CHAL_DIR`, `DESTDIR`.
- Test binaries built with `-fsanitize=address,undefined` for memory- and
  undefined-behaviour safety checking.

#### Test suite (`tests/`)
- Custom single-header test framework (`test_framework.h`) — C99-compatible,
  no external dependencies.
- **`test_challenge_store`** — 17 tests:
  - `challenge_create`: return value, hex format, lowercase chars, file
    creation, uniqueness, bad directory, undersized buffer.
  - `challenge_load`: round-trip correctness, missing nonce, expired nonce,
    auto-deletion of expired files, path-traversal rejection, non-hex ID
    rejection, undersized output buffer.
  - `challenge_delete`: prevents replay, idempotence, graceful no-op on
    missing file.
- **`test_key_parser`** — 14 tests:
  - `b64_decode`: known value, empty input, zero-size buffer, round-trip.
  - `parse_authorized_keys`: missing file, single Ed25519 key, comment
    field, hash-comment lines, empty lines, unsupported key type, multiple
    keys, malformed base64.
  - `free_key_list`: NULL argument, single entry.
- **`test_sig_verify`** — 16 tests:
  - Ed25519: valid signature, wrong key, tampered signature, wrong
    challenge, truncated signature.
  - RSA: SHA-256 valid, SHA-512 valid, `ssh-rsa` alias, wrong key,
    digest mismatch (SHA-256 sig claimed as SHA-512).
  - Error paths: NULL entry, NULL `pkey`, NULL challenge, NULL signature,
    unknown key type, zero-length signature.
- **`test_integration`** — 4 end-to-end tests:
  - Full happy-path flow (challenge → sign → parse → verify).
  - Replay attack prevention (nonce consumed on first use).
  - Wrong-key rejection.
  - Multiple authorised keys — any matching key succeeds.

#### Documentation
- `README.md`: project overview, architecture diagram, quick-start.
- `docs/INSTALL.md`: full installation and configuration manual (15 sections).
- `docs/CHANGELOG.md`: this file.
- `config/pam.d/postgresql`: drop-in PAM service configuration.

### Security notes

- Nonces are 256-bit (32 bytes) from `RAND_bytes` — collision probability
  is negligible.
- The `O_CREAT | O_EXCL` flag on nonce file creation prevents two
  simultaneous challenges from clobbering each other.
- The 60-second TTL (`CHALLENGE_TTL_SECS`) balances usability against the
  window in which a stolen (but unused) token could be replayed.
- `pg_sshkey_sign` reads raw PEM private keys; a future release will add
  `ssh-agent` protocol support so private keys never leave the agent.

---

## [0.9.0] — 2026-05-15 (internal pre-release)

### Added
- Prototype PAM module with Ed25519 support only.
- Filesystem nonce store (no TTL enforcement).
- Initial `pg_sshkey_challenge` and `pg_sshkey_sign` tools.

### Changed
- Nonce format changed from binary to hex (improves debuggability and
  eliminates filesystem-unsafe characters).

### Fixed
- Module crashed when `authorized_keys` directory did not exist; now
  returns `PAM_AUTH_ERR` with a syslog warning.
- `challenge_load` did not validate that the stored hex matched the
  requested ID; corrected to use the stored hex for decoding.

### Removed
- ECDSA key support removed in favour of Ed25519 and RSA only.
  ECDSA (NIST curves) will be reconsidered in a later release pending
  the resolution of curve-selection security concerns.

---

[Unreleased]: https://github.com/yourorg/pam_pg_sshkey/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/yourorg/pam_pg_sshkey/releases/tag/v1.0.0
[0.9.0]: https://github.com/yourorg/pam_pg_sshkey/releases/tag/v0.9.0
