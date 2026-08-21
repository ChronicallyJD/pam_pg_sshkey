# Testing

This page describes the test suite: what each part proves, how to run it,
and how a change is verified. It assumes the build requirements from
[Installation](installation.md#requirements) plus `ssh-keygen` and Python
with `cryptography` and `psycopg2`.

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
| `tests/test_sig_verify` | 16 | Ed25519 and RSA verification, including the RSA label aliases |
| `tests/test_integration` | 4 | The library-level flow and replay prevention |
| `tests/test_pam_module` | 20 | The production `pam_pg_sshkey.so`, loaded through libpam with `pam_start_confdir` and a PostgreSQL-style conversation function: v2 and v1 success, replay, expired and future timestamps, wrong key, tampered and malformed tokens, missing, empty, and group-writable key files, a private `0700` nonce directory, fail-closed recording, RSA, `acct_mgmt`, and stale-nonce sweeping |
| `tests/test_system` | 18 | The built `pg_sshkey_sign` and `pg_sshkey_challenge` binaries as a user runs them |
| `tests/test_python_module.py` | 51 | `pam_pg_sshkey.py`: key loading, signing, v2 and v1 tokens, `challenge_cmd`, `connect_replication` selection, error mapping. Four tests skip when `bcrypt` is absent |
| `tests/test_pg_sshkey_query.py` | 6 | `pg_sshkey_query` as a subprocess: error handling, `PGDATABASE` and `PGPORT`, helper lookup |
| `tests/test_docs.sh` | | The documentation rules in `CLAUDE.md`: no em dashes, no emoji, sentence-case headings, fenced code with a language, links that resolve |

`tests/test_make_test.sh` checks that `make test` runs every suite above and
that no build outputs are tracked in git.

`tests/test_pam_module` is the closest thing to PostgreSQL that runs on the
build host. It writes a PAM service file that names the freshly built `.so`
by absolute path, sets `PAM_USER` and `PAM_CONV` the way PostgreSQL's
`CheckPAMAuth` does, and answers the single `PAM_PROMPT_ECHO_OFF` from the
token. Keys and tokens come from `ssh-keygen` and the built tools, so the
module only ever sees real client output.

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
roles, and runs `tests/e2e/check.sh`. The 21 checks log in as real users
through `pg_sshkey_connect` over TCP and the local socket, `pg_sshkey_query`,
and the Python module, and assert on both the journal and the PostgreSQL
log: a positive login counts only when the journal shows
`authenticated with key`. The negative checks cover a wrong key, a replayed
v2 and v1 token, expired and future timestamps, a user without keys, a
malformed token, a nonce directory the module cannot write, a client under
`umask 077`, and a subscription-style reuse. Re-running is idempotent and
takes a few seconds; `E2E_ONLY=<check> make e2e` runs one check.

## Verifying a change

A change is done when a test at one of these seams fails without it. For a
fix, write the check first and watch it fail for the stated reason; then
make it pass; then remove the fix (a `sed` on the source in the container
copy works well), rebuild with `make clean && make`, and confirm the check
fails again. The e2e checks for fail-closed nonce handling, the umask fix,
the RSA parser, and v2 replay were each confirmed this way.
