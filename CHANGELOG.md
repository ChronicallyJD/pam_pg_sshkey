# Changelog

Notable changes to pam_pg_sshkey are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/). Each entry names the test that
covers it; see [docs/testing.md](docs/testing.md).

## [1.1.0] - 2026-08-21

### Changed

- New default token format, v2: the client issues its own challenge.
  `pg_sshkey_sign <key>` prints `<unix_ts>:<nonce_hex>:<base64_sig>`, signed
  over `"pg-sshkey-v2\0" || "<unix_ts>:<nonce_hex>"`. The module accepts the
  token when the timestamp is within 60 seconds of server time and the
  signature verifies, then records the nonce atomically (`O_CREAT|O_EXCL`,
  owned by `postgres`, mode 0600). A second use of the nonce is refused, and
  if the nonce cannot be recorded the login is refused. Verification happens
  before recording, so forged tokens create no files. Nothing happens on the
  server before the connection: remote clients need no ssh, the nonce
  directory can be `0700`, and umask and ownership no longer matter. Client
  and server clocks must agree to within 60 seconds.
  `pg_sshkey_connect`, `pg_sshkey_query`, `pam_pg_sshkey.py`, and
  `utils/select1.py` produce v2 by default; v1 remains available with
  `--v1` or `version=1` and will be removed in a future release.
  Tests: `test_pam_module` (seven v2 tests), `test_system`,
  `test_python_module`; e2e `v2_replay_rejected`, `v2_private_0700_dir`,
  `v2_timestamp_window`, `v2_unrecordable_nonce_fails_closed`,
  `v1_token_still_accepted`.
- Nonce records are swept after 120 seconds instead of 60, so a v2 record
  outlives every moment at which its token could still pass the timestamp
  check. Test: `test_challenge_store`.
- Log messages no longer contain em dashes, so they can be quoted in the
  documentation verbatim.

### Added

- `pg_sshkey_sign --at <unix_ts>` and `--nonce <hex64>` for tests and clock
  experiments.
- `verify_signature_raw()` in `sig_verify.c` and `challenge_mark()` in
  `challenge_store.c`.
- `make e2e-rocky`: the end-to-end checks on Rocky Linux 9 with
  PostgreSQL 16.
- `CLAUDE.md` with the project's verification and documentation rules, and
  `tests/test_docs.sh`, which enforces the mechanical documentation rules in
  `make test`.
- A `LICENSE` file (MIT, as the source headers already declared).
- The documentation was rewritten as one page per question under `docs/`;
  `docs/INSTALL.md` and the duplicate `docs/CHANGELOG.md` were removed.

## [1.0.9] - 2026-08-21

### Fixed

- RSA keys never authenticated through the module on OpenSSL 3.
  `key_parser.c` passed the modulus and exponent to
  `OSSL_PARAM_construct_BN()` in big-endian form; that API expects native
  byte order, so every RSA key parsed from `authorized_keys` was wrong. The
  RSA unit tests did not catch it because they built the key object directly
  instead of parsing a key line. Now uses `BN_bn2nativepad()` with bounds
  checks. Tests: `test_pam_module` (`rsa_ssh_rsa_entry_succeeds`), e2e
  `rsa_key_connect`.
- `rsa-sha2-512` entries could never verify. The verifier selected SHA-512
  for that key-type word while every signer signs PKCS#1 v1.5 with SHA-256,
  and a client cannot know which server-side label will match. `ssh-rsa`,
  `rsa-sha2-256`, and `rsa-sha2-512` are now aliases that verify SHA-256.
  Tests: `test_sig_verify`, `test_pam_module`.
- Replay protection was silently void when the nonce could not be deleted.
  `challenge_delete()` ignored the result of `unlink()`; with a nonce
  directory not owned by `postgres`, a token authenticated repeatedly until
  it expired. The function now returns a status and the module refuses the
  login, logging `could not delete challenge ... refusing`. Tests:
  `test_pam_module` (`unremovable_nonce_fails_closed`), e2e
  `root_owned_chal_dir_fails_closed`.
- Clients running under `umask 077` could not log in: the nonce file was
  created with mode 0600 and the module could not read it. `pg_sshkey_challenge`
  and `pam_pg_sshkey.py` now `fchmod` the file to 0644. Tests: `test_system`,
  `test_python_module`, e2e `umask_077_client_still_authenticates`.
- Remote subscribers could not authenticate as documented: the module reads
  nonces only from the server's own directory, and the guide had the
  subscriber create the nonce locally. `challenge_cmd=` (Python) and
  `--challenge-cmd` (`pg_sshkey_connect`) run a command such as
  `ssh publisher pg_sshkey_challenge /var/run/pg_sshkey` to create it on the
  server. The guide now states that single-use tokens cannot be stored in a
  `CREATE SUBSCRIPTION` connection string. Tests: `test_python_module`, e2e
  `ssh_challenge_cmd_connect`.
- Orphaned nonces accumulated without bound: every connection attempt created
  one and only a successful login removed it. The module now sweeps expired
  records on each authentication, at most 256 per call. Tests:
  `test_challenge_store`, `test_pam_module`, e2e `stale_nonces_swept`.
- `pam_pg_sshkey.py`: `UnsupportedAlgorithm` from `cryptography` (for
  example a passphrase-protected key without `bcrypt`) is reported as
  `KeyError_` with install guidance; `connect_replication()` recognises
  every libpq spelling of a physical connection (`true`, `on`, `yes`, `1`)
  and no longer forwards the Python bool as the string `'True'`; importing
  the module no longer fails when `HOME` is unset. Test: `test_python_module`.
- `pg_sshkey_query`: missing helper binaries, a bad `PGPORT`, and SQL errors
  are reported as one `error:` line instead of a traceback; helpers are found
  beside the script when not on `PATH`; `PGDATABASE` is honoured. Tests:
  `test_pg_sshkey_query`, e2e `pg_sshkey_query_bad_sql_clean_error`.
- `make test` did not run what the manual said it ran: `test_system` was
  built but never executed, and the Python tests were not wired up. `make
  test` now depends on `all` and runs every suite. Test: `tests/test_make_test.sh`.
- `make install` detects `/lib64/security` on RHEL and Fedora.
- Build outputs are no longer tracked in git.

### Added

- `tests/test_pam_module`: the production module loaded through libpam with
  a PostgreSQL-faithful conversation function.
- `make e2e`: end-to-end checks against PostgreSQL 18 in a dedicated incus
  container (`tests/e2e/`).
- `tests/test_make_test.sh` and `tests/test_pg_sshkey_query.py`.

## [1.0.8] - 2026-06-01

### Added

- `pam_pg_sshkey.py`, a Python module with `get_token`, `connect`, and
  `connect_replication` for applications and replication subscribers that
  use psycopg2 directly.
- A replication guide in `docs/INSTALL.md` (since rewritten as
  `docs/replication.md`).

## [1.0.7] - 2026-06-01

### Added

- `pg_sshkey_query`, a psycopg2-based tool that produces a token and runs one
  query.
- `utils/select1.py`, a minimal standalone example of the token flow.

## [1.0.6] - 2026-06-01

### Fixed

- `pg_sshkey_challenge` failed with `chmod: Operation not permitted` for any
  user who did not own the nonce directory. The `chmod` on every call was
  removed; permissions are set at install time and by the tmpfiles.d rule.

## [1.0.5] - 2026-06-01

### Added

- `pg_sshkey_addkey`, which deploys a public key with `root:postgres 0640`
  ownership.

### Fixed

- The module logged a misleading `no valid keys` when `authorized_keys` was
  readable by `stat()` but not by `open()`. It now checks `access(R_OK)` and
  logs the owner, mode, and the commands that fix them.

## [1.0.4] - 2026-06-01

### Added

- `pg_sshkey_connect`, which computes the token before starting `psql`.
  libpq disconnects when PostgreSQL asks for a password it does not hold, so
  `psql` cannot be used on its own.

## [1.0.3] - 2026-06-01

### Fixed

- `pg_sshkey_challenge` failed with `Permission denied` for users other than
  `postgres`. The nonce directory became `1733 postgres:postgres` and nonce
  files `0644`.
- The nonce directory was lost on reboot. `make install` now installs a
  tmpfiles.d rule.

## [1.0.2] - 2026-06-01

### Fixed

- `pg_sshkey_sign` could not read OpenSSH-format private keys. It now parses
  the format natively for Ed25519 and prints conversion instructions for
  other types and for passphrase-protected keys.

## [1.0.1] - 2026-06-01

### Fixed

- Every login failed with `conversation failed`. PostgreSQL does not set
  `PAM_AUTHTOK`; the module now calls the conversation function directly,
  once, and caches the result.

## [1.0.0] - 2026-06-01

Initial release: the PAM module, `pg_sshkey_challenge`, `pg_sshkey_sign`, the
unit tests, and the Makefile.
