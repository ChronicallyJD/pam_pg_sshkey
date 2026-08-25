# Changelog

Notable changes to pam_pg_sshkey are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/). Each entry names the test that
covers it; see [docs/testing.md](docs/testing.md). Four releases are tagged
in git: `1.0`, `1.1.0`, `1.2.0`, and `2.0.0`. The 1.0.1 to 1.0.9 entries
have no tag of their own.

## [2.0.0] - 2026-08-24

### Removed

- v1 tokens. The module accepts only `<unix_ts>:<nonce_hex>:<signature>` and
  the certificate form that appends `:<certificate>`; a token of the old
  shape `<nonce_hex>:<signature>` is refused as malformed. `pg_sshkey_challenge`
  is gone, and with it `--v1`, `--challenge-dir`, `--challenge-cmd` and
  `--challenge-bin` on `pg_sshkey_connect` and `pg_sshkey_query`, and the
  `version`, `challenge_dir` and `challenge_cmd` parameters of `get_token`,
  `connect` and `connect_replication`, which now raise `TypeError`.
  `pg_sshkey_sign` takes one private key and no challenge; a second
  positional argument is a usage error.

  A client that has not been updated stops working, which is why this is a
  major version. Nothing on the server needs reconfiguring: the same
  `authorized_keys` files, certificates and options keep working.

  `/var/run/pg_sshkey` is now installed `0700 postgres:postgres` instead of
  `1733`. It held nonce files that clients created; it now holds only the
  records the module writes, so nothing but the module needs to write there.
  An existing installation can be tightened with
  `chmod 0700 /var/run/pg_sshkey` and the same change to
  `/usr/lib/tmpfiles.d/pg_sshkey.conf`.
  Tests: `test_pam_module` (`test_v1_token_is_refused`), `test_system`
  (`TestV1IsGone` in `test_pg_sshkey_query`), `test_python_module`
  (`TestV1ParametersRemoved`); e2e `private_nonce_dir` and the `--v1`
  refusal in `cert_alice_key_without_cert_still_works`.

### Added

- The `source-address` critical option is enforced instead of refused. A
  certificate signed with `ssh-keygen -O source-address=<list>` authenticates
  only from those addresses: PostgreSQL reports the client address in
  `PAM_RHOST` and the module matches it against the list, comma-separated
  CIDR masks in either family. Every other critical option is still refused.
  The module refuses whenever it cannot decide, so a pinned certificate does
  not work over the unix socket, where PostgreSQL sets no `PAM_RHOST`, nor
  with `pam_use_hostname=1` in `pg_hba.conf`, where PostgreSQL sets the
  client's reverse-DNS name instead of its address; a malformed list,
  including a stray comma, an entry with host bits set, or a prefix
  `ssh-keygen` would refuse, refuses rather than matching what it can.
  Tests: `test_ssh_cert` (`test_address_permitted`, covering prefixes, both
  families, lists, and every malformed form); `test_pam_module`
  (`test_certificate_source_address_is_enforced`,
  `test_source_address_refuses_what_it_cannot_check`,
  `test_source_address_list_and_ipv6`,
  `test_source_address_malformed_list_refuses` (which uses the new
  `tests/cert_helper.py` to sign a list `ssh-keygen` will not), and
  `test_cert_with_critical_option_refused` for the options still refused);
  e2e `cert_source_address_permitted`, `cert_source_address_refused`,
  `cert_source_address_local_socket_refused`, where the address comes from
  PostgreSQL itself.

- Key revocation. `revoked_keys=<file>` in `/etc/pam.d/postgresql` names
  public keys, in `authorized_keys` format, that may not authenticate. The
  list is checked after the signature verifies and before the login is
  granted, on every attempt, for a key in an `authorized_keys` file, a key
  carried by a certificate, and a key on a security key alike, so revoking
  the key inside a certificate is the way to withdraw that certificate
  before it expires. A list that cannot be read refuses every login rather
  than readmitting the keys it named; an empty file revokes nothing. The
  file must be readable by `postgres`, be a regular file, and not be group or
  world writable, and every line that is not blank or a comment must parse as
  a public key: a file the module cannot read that way, such as a revocation
  list from `ssh-keygen -k`, refuses every login rather than revoking
  nothing. Revoking a CA key withdraws every certificate it signed. One file
  cannot serve as both `revoked_keys` and `trusted_ca_keys`; the module
  refuses that configuration rather than turn every revoked key into a
  trusted CA. The list holds keys: there is no revocation by certificate
  serial or key id.
  Tests: `test_pam_module` (`test_revoked_key_refused`,
  `test_revoked_certified_key_refused`, `test_revoked_security_key_refused`,
  `test_unreadable_revocation_list_fails_closed`,
  `test_unparseable_revocation_list_fails_closed`,
  `test_revoked_ca_key_refuses_its_certificates`,
  `test_same_file_for_ca_and_revocation_refused`,
  `test_group_writable_revocation_list_refused`,
  `test_revocation_names_one_key_not_all`); e2e `revoked_key_rejected`,
  `revoked_certificate_rejected`,
  `unreadable_revocation_list_fails_closed`,
  `revoked_security_key_rejected`.

- Security keys. An `sk-ssh-ed25519@openssh.com` entry in `authorized_keys`
  authenticates, so a key that lives on a FIDO authenticator can log in to
  PostgreSQL. The module verifies the authenticator's own signature, over
  `SHA256(application) || flags || counter || SHA256(message)`, and refuses
  one whose user-presence bit is clear, so a login needs a touch. The token
  is an ordinary v2 or v3 token whose signature field holds 69 bytes: the 64
  raw bytes, the flags byte, then the counter. Signing goes through
  `--agent` or `agent_pubkey=`, because the private key is on the hardware,
  and `pg_sshkey_addkey` now accepts the type. `sk-ecdsa-sha2-nistp256` is
  refused: the module has no ECDSA verifier. The tests build signatures in
  the authenticator's format rather than driving hardware, so what is
  verified is the format.
  Tests: `test_pam_module` (`test_security_key_authenticates`,
  `test_security_key_without_user_presence_refused`,
  `test_security_key_signature_is_bound_to_its_application`,
  `test_security_key_counter_and_flags_are_signed`,
  `test_security_key_ecdsa_type_is_not_accepted`,
  `test_security_key_signature_length_is_exact`);
  `test_ssh_agent` (`test_security_key_signature_is_passed_through_with_its_tail`);
  `test_system` (`test_agent_security_key_types`);
  `test_python_module` (`TestSkAgentSigning`, seven tests); e2e
  `security_key_connect`, `security_key_without_presence_rejected`,
  `security_key_counter_is_not_checked`.

- `tests/test_addkey.sh` covers `pg_sshkey_addkey`, which had no test of its
  own. It found the tool reporting the wrong key count for a security key,
  refusing a literal `sk-` key string, and refusing the standard input form
  its own usage text advertises; all three are fixed.

- Signing through an `ssh-agent`. `pg_sshkey_sign --agent <public_key.pub>`,
  `pg_sshkey_connect --agent FILE`, `pg_sshkey_query --agent FILE`, and
  `agent_pubkey=` in `get_token`, `connect`, and `connect_replication` ask
  the agent at `$SSH_AUTH_SOCK` to sign, so the private key is never read.
  A passphrase-protected key, an OpenSSH-format RSA key, and a key on
  another machine behind a forwarded agent all work; none of them could be
  used from the C tools before. `--agent` takes the public key file and
  replaces the private key argument, combines with `--cert`, and is not
  available with v1. RSA identities are signed as `rsa-sha2-256`, because
  the module verifies RSA with SHA-256; an agent that answers with the
  SHA-1 `ssh-rsa` algorithm is refused, as are `sk-` FIDO keys, whose
  signature carries authenticator fields the module does not verify. The
  server is unchanged: an agent signature is an ordinary v2 or v3 token.
  The client verifies the agent's answer against the public key it was given
  before printing a token, refuses an empty signature, waits at most 60
  seconds for the agent, survives an agent that closes the socket mid
  exchange, and replaces any byte outside printable ASCII in agent-supplied
  text before printing it, so a forwarded agent cannot repaint the terminal.
  `-i` together with `--agent` is refused rather than silently ignored.
  Tests: `test_ssh_agent` (six tests driving a hostile agent under
  AddressSanitizer: the timeout, oversize and truncated replies, an empty
  signature, a wrong algorithm name on a valid signature, a signature by
  another key, and a refusal followed by a close);
  `test_pam_module` (six tests against a real `ssh-agent`, including
  an Ed25519 key deleted from disk after `ssh-add` and a
  passphrase-protected key that no other route can use),
  `test_system` (`test_agent_without_auth_sock_fails`,
  `test_agent_security_key_type_refused`,
  `test_agent_rejects_private_key_and_stray_positional`),
  `test_python_module` (`TestAgentSigning`, `TestAgentErrors`, 15 tests),
  `test_pg_sshkey_query` (five forwarding and refusal tests); e2e
  `agent_connect_as_alice`, `agent_passphrase_key_connects`,
  `agent_rsa_key_connects`, `agent_certificate_connects`,
  `agent_query_and_python_connect`, `agent_absent_is_a_clean_error`.

## [1.2.0] - 2026-08-24

### Added

- SSH certificate authentication. With `trusted_ca_keys=<file>` in
  `/etc/pam.d/postgresql` (recommended `/etc/pg_sshkeys/trusted_ca_keys`,
  `root:postgres` mode 0640, one `ssh-ed25519` or `ssh-rsa` CA public key
  per line), a user whose key was certified with
  `ssh-keygen -s <ca> -I <id> -n <role> -V <window>` authenticates without
  an `authorized_keys` file, as sshd does with `TrustedUserCAKeys`. The
  client sends a v3 token, `<unix_ts>:<nonce_hex>:<base64_sig>:<base64_cert>`,
  signed over `"pg-sshkey-v3\0" || "<unix_ts>:<nonce_hex>"` by the certified
  key; timestamp window, nonce recording, and replay refusal are as for v2.
  The module refuses a certificate that is not a user certificate, is
  outside its validity window, does not list the role name as a principal,
  carries any critical option, is not signed by a listed CA, or has a CA
  signature that does not verify or uses SHA-1 `ssh-rsa`; each refusal has
  its own log line and no nonce is recorded. Certificate strings must be
  printable ASCII, so a key id or option name cannot forge a log line, and
  a token of 8192 bytes or more is refused before parsing. There is no revocation list.
  Without the option every v3 token is refused, and v1 and v2 tokens are
  unchanged. The module's token limit rises from 4096 to 8192 bytes.
  `pg_sshkey_sign --cert <cert.pub>`, `pg_sshkey_connect --cert FILE`,
  `pg_sshkey_query --cert FILE`, and `cert_path=` in `get_token`, `connect`,
  and `connect_replication` produce the token; `<identity>-cert.pub` is
  never picked up automatically.
  Tests: `test_pam_module` (`test_cert_ed25519_authenticates_without_authorized_keys`,
  `test_cert_refused_when_trusted_ca_keys_unset`,
  `test_cert_from_untrusted_ca_refused`, `test_cert_expired_refused`,
  `test_cert_not_yet_valid_refused`, `test_cert_wrong_principal_refused`,
  `test_cert_without_principals_refused`, `test_host_cert_refused`,
  `test_cert_with_critical_option_refused`, `test_cert_tampered_byte_refused`,
  `test_cert_token_signed_by_other_key_refused`,
  `test_cert_replay_and_timestamp_window`,
  `test_cert_rsa_key_under_ed25519_ca`, `test_cert_ed25519_key_under_rsa_ca`,
  `test_cert_group_writable_ca_file_refused`,
  `test_oversized_token_refused_before_parsing`,
  `test_cert_with_control_characters_refused`,
  `test_v1_and_v2_still_pass_with_trusted_ca_keys_set`); `test_ssh_cert`
  (five tests, including truncated blobs under AddressSanitizer);
  `test_system` (`test_sign_cert_ed25519_prints_v3_token`,
  `test_sign_cert_rsa_pem_prints_v3_token`, `test_sign_cert_missing_file_fails`,
  `test_sign_cert_not_a_cert_fails`, `test_sign_cert_unpadded_field_fails`,
  `test_sign_cert_signature_covers_v3_prefix`);
  `test_python_module` (`test_token_has_four_fields_and_cert_is_the_file_base64`,
  `test_signature_verifies_over_v3_message_with_certified_key`,
  `test_token_is_identical_to_pg_sshkey_sign_cert`,
  `test_cert_path_with_version_1_raises_valueerror`,
  `test_connect_and_connect_replication_forward_cert_path`,
  `test_unpadded_cert_field_is_refused`, and four more);
  `test_pg_sshkey_query` (`TestCertOption`,
  `test_cert_with_v1_is_refused_before_minting_a_nonce`); e2e `cert_connect_as_carol`,
  `cert_python_connect`, `cert_pg_sshkey_query`, `cert_untrusted_ca_rejected`,
  `cert_expired_rejected`, `cert_wrong_principal_rejected`,
  `cert_replay_rejected`, `cert_alice_key_without_cert_still_works`.

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

[2.0.0]: https://github.com/ChronicallyJD/pam_pg_sshkey/compare/1.2.0...2.0.0
[1.2.0]: https://github.com/ChronicallyJD/pam_pg_sshkey/compare/1.1.0...1.2.0
[1.1.0]: https://github.com/ChronicallyJD/pam_pg_sshkey/compare/1.0...1.1.0
[1.0]: https://github.com/ChronicallyJD/pam_pg_sshkey/releases/tag/1.0
