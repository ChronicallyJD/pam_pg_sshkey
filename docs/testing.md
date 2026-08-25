# Testing

This page describes the test suite: what each part proves, how to run it,
and how a change is verified. It assumes the build requirements from
[Installation](installation.md#requirements) plus `ssh-keygen`, `ssh-agent`,
`ssh-add`, and Python with `cryptography` and `psycopg2`. The C agent tests
fail without `ssh-agent`; the Python ones skip.

## make test

```sh
make test
```

`make test` rebuilds everything and runs the suites below. It needs neither
root, nor PostgreSQL, nor a container, and takes about ten seconds.

| Suite | Tests | What it proves |
| --- | --- | --- |
| `tests/test_challenge_store` | 20 | Nonce create, load, delete, and sweep; TTL; hex-only names |
| `tests/test_key_parser` | 14 | Base64 and `authorized_keys` parsing |
| `tests/test_ssh_agent` | 7 | `ssh_agent.c` against a hostile agent served by the test: a silent agent times out, oversize and truncated replies, an inner string that overruns, an empty signature (with a certificate blob, where the local check is skipped), terminal escapes in the algorithm name, a refusal followed by a close (which must not raise `SIGPIPE`), a signature by another key, and a genuine signature under a wrong algorithm name, all under AddressSanitizer. A security key reply is included: its flags and counter must survive into the token, and a reply without them, or with the presence bit clear, is refused. |
| `tests/test_sig_verify` | 16 | Ed25519 and RSA verification, including the RSA label aliases |
| `tests/test_ssh_cert` | 6 | `ssh_cert.c` on real `ssh-keygen -s` output: fields (serial, key id, principals, window), host type and critical options, RSA certificates and RSA CAs (`rsa-sha2-256`, `rsa-sha2-512`; `ssh-rsa` refused), a tampered body, and every truncated prefix and a padded blob refused under AddressSanitizer |
| `tests/test_integration` | 4 | The library-level flow and replay prevention |
| `tests/test_pam_module` | 62 | The production `pam_pg_sshkey.so`, loaded through libpam with `pam_start_confdir` and a PostgreSQL-style conversation function: v2 and v1 success, replay, expired and future timestamps, wrong key, tampered and malformed tokens, missing, empty, and group-writable key files, a private `0700` nonce directory, fail-closed recording, RSA, `acct_mgmt`, and stale-nonce sweeping; and, with `trusted_ca_keys=` on the service line, certificates: an Ed25519 certificate with no `authorized_keys`, RSA key under an Ed25519 CA, Ed25519 key under an RSA CA (`rsa-sha2-512` accepted, `ssh-rsa` refused), and refusal of an untrusted CA, expired, not yet valid, wrong principal, no principals, host certificate, critical option, `trusted_ca_keys` unset, group-writable CA file, replay, timestamps outside the window, a tampered certificate byte, a token signed by a key other than the certified one, a token of 8192 bytes or more, and a certificate whose key id or option name contains a newline, with v1 and v2 still passing; and, against a real `ssh-agent` started by the test, `--agent`: an Ed25519 key deleted from disk after `ssh-add`, an RSA key (which proves the client asks for `rsa-sha2-256`), a passphrase-protected key that no other route can use, a certificate signed through the agent, an unregistered agent key refused, and no agent, a dead socket, and an agent without the key each producing no token. Each negative test asserts the return code, the log line, and that no nonce was recorded. Revocation is covered by a revoked key, a revoked certified key, a revoked security key, an unreadable list refusing every login, a group-writable list, and one revoked key not locking out another. Security keys are covered by a signature in the authenticator's format (built by `tests/sk_helper.py`, not by hardware): the user-presence bit required, the application and counter covered by the signature, and `sk-ecdsa` skipped as an unsupported type. |
| `tests/test_system` | 27 | The built `pg_sshkey_sign` and `pg_sshkey_challenge` binaries as a user runs them, including `--cert`: a four-field token whose fourth field is the certificate file's base64, the v3 prefix under the signature, and exit 1 for a missing file, a plain public key, or an unpadded certificate field; and `--agent` refusing a missing `SSH_AUTH_SOCK`, an `sk-` key type, a private key file, a stray positional key, and a v1 challenge |
| `tests/test_python_module.py` | 101 | `pam_pg_sshkey.py`: key loading, signing, v2 and v1 tokens, `challenge_cmd`, `connect_replication` selection, error mapping, and `cert_path`: token shape, the 13-byte v3 prefix, signature verified with the certified key, byte-identical output to `pg_sshkey_sign --cert` for the same nonce and time, `ValueError` with `version=1` or `challenge_cmd`, a plain public key or an unpadded certificate field refused, security keys through a fake agent, at a non-default application (the token carrying flags and counter, byte-identical to `pg_sshkey_sign --agent`, a signature for another application refused, a tail that disagrees with the signed bytes refused, no user presence refused, `sk-ecdsa` refused), and forwarding by `connect` and `connect_replication`; and `agent_pubkey` against a real `ssh-agent`: tokens byte-identical to `pg_sshkey_sign --agent`, Ed25519 and RSA signatures verified with `cryptography`, a passphrase-protected key, a v3 token through the agent, and refusals for a missing socket, a dead socket, an identity the agent does not hold, an `sk-` key, `key_path` together with `agent_pubkey`, and `version=1`. Four tests skip when `bcrypt` is absent |
| `tests/test_pg_sshkey_query.py` | 16 | `pg_sshkey_query` and `pg_sshkey_connect` as subprocesses: error handling, `PGDATABASE` and `PGPORT`, helper lookup, `--cert` reaching `pg_sshkey_sign` as `--cert FILE` (and not reaching it without the option), `--cert` with `--v1` refused before a nonce is minted, and `--agent FILE` reaching the signer with no key path, for both tools |
| `tests/test_addkey.sh` | 8 | `pg_sshkey_addkey` as an administrator runs it: a security key registered and counted, appending, `--list`, a literal key string, a key on standard input, `sk-ecdsa` refused, and `--remove`. Runs under `fakeroot`, and skips without it |
| `tests/test_docs.sh` | | The documentation rules in `CLAUDE.md`: no em dashes, no emoji, sentence-case headings, fenced code with a language, links that resolve |

`tests/test_make_test.sh` checks that `make test` runs every suite above and
that no build outputs are tracked in git.

`tests/test_pam_module` is the closest thing to PostgreSQL that runs on the
build host. It writes a PAM service file that names the freshly built `.so`
by absolute path, sets `PAM_USER` and `PAM_CONV` the way PostgreSQL's
`CheckPAMAuth` does, and answers the single `PAM_PROMPT_ECHO_OFF` from the
token. Keys, CAs, certificates, and tokens come from `ssh-keygen` and the built
tools, so the module only ever sees real client output. The harness also
defines `pam_syslog` and is linked with `-rdynamic`, so the module's log
lines bind to it and each test asserts the exact message.

## End to end

```sh
make e2e          # Ubuntu 26.04, PostgreSQL 18
make e2e-rocky    # Rocky Linux 9, PostgreSQL 16
make e2e-clean    # delete the container (e2e-rocky-clean for Rocky)
make e2e-shell    # a shell inside the container
```

`make e2e` needs [incus](https://linuxcontainers.org/incus/) on the host. It
launches a dedicated container, pushes the repository source into it, builds
and installs the module, configures `pg_hba.conf`, creates OS users and
roles, and runs `tests/e2e/check.sh`. The 45 checks log in as real users
through `pg_sshkey_connect` over TCP and the local socket, `pg_sshkey_query`,
and the Python module, and assert on both the journal and the PostgreSQL
log: a positive login counts only when the journal shows
`authenticated with key`. The negative checks cover a wrong key, a replayed
v2 and v1 token, expired and future timestamps, a user without keys, a
malformed token, a nonce directory the module cannot write, a client under
`umask 077`, and a subscription-style reuse. The certificate checks use a
third user, `carol`, who has no `authorized_keys` file, a CA installed at
`/etc/pg_sshkeys/trusted_ca_keys`, and a second CA the module does not
trust: `cert_connect_as_carol`, `cert_python_connect`,
`cert_pg_sshkey_query`, `cert_untrusted_ca_rejected`,
`cert_expired_rejected`, `cert_wrong_principal_rejected`,
`cert_replay_rejected`, and `cert_alice_key_without_cert_still_works`; a
positive certificate login counts only when the journal shows
`authenticated with certificate`. Re-running is idempotent and
takes a few seconds; `E2E_ONLY=<check> make e2e` runs one check.

## Verifying a change

A change is done when a test at one of these seams fails without it. For a
fix, write the check first and watch it fail for the stated reason; then
make it pass; then remove the fix (a `sed` on the source in the container
copy works well), rebuild with `make clean && make`, and confirm the check
fails again. The e2e checks for fail-closed nonce handling, the umask fix,
the RSA parser, and v2 replay were each confirmed this way.
