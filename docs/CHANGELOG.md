# Changelog

All notable changes to `pam_pg_sshkey` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

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
