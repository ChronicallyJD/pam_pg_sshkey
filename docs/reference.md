# Reference

This page lists the token formats, the command-line tools and their options,
the module options, and the messages the module logs. For how to use them,
see the [User guide](user-guide.md).

## Token formats

| Version | Token | Signed message | Server check |
| --- | --- | --- | --- |
| 2 (default) | `<unix_ts>:<nonce_hex>:<base64_sig>` | `"pg-sshkey-v2\0" \|\| "<unix_ts>:<nonce_hex>"` (ASCII) | `\|now - ts\| <= 60`, signature valid, nonce not recorded before; the nonce is then recorded |
| 1 (legacy) | `<nonce_hex>:<base64_sig>` | `"pg-sshkey-v1\0" \|\| nonce_bytes` | A nonce file created by `pg_sshkey_challenge` exists in `challenge_dir` and is under 60 seconds old; the file is then deleted |

Both prefixes are 13 bytes including the NUL. `nonce_hex` is 64 lowercase
hexadecimal characters (32 random bytes). Ed25519 signs the message directly;
RSA uses PKCS#1 v1.5 with SHA-256. The module tells the versions apart by the
number of colons. The window and lifetime are `CHALLENGE_TTL_SECS` (60) in
`src/challenge_store.h`; nonce records are swept after twice that.

## pg_sshkey_sign

```text
pg_sshkey_sign [--at <unix_ts>] [--nonce <hex64>] <private_key>     v2
pg_sshkey_sign <nonce_hex> <private_key>                             v1
```

Prints the token to standard output. `--at` and `--nonce` override the
timestamp and nonce of a v2 token; they exist for tests. Accepted key files:
OpenSSH Ed25519 (unencrypted), PKCS#8 PEM (Ed25519 or RSA), traditional PEM
(RSA). Exit status 1 on any error, with the reason on standard error.

## pg_sshkey_connect

```text
pg_sshkey_connect [options] [dbname] [-- psql arguments]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `-U`, `--username USER` | `$PGUSER`, then `$USER` | PostgreSQL role |
| `-h`, `--host HOST` | `$PGHOST`, then the local socket | Server |
| `-p`, `--port PORT` | `$PGPORT`, then 5432 | Port |
| `-d`, `--dbname NAME` | `$PGDATABASE`, then the user name | Database |
| `-i`, `--identity FILE` | `~/.ssh/id_ed25519` | Private key |
| `-v`, `--verbose` | off | Print each step to standard error |
| `--sign-bin PATH` | from `PATH` | Location of `pg_sshkey_sign` |
| `--v1` | off | Produce a v1 token |
| `-c`, `--challenge-dir DIR` | `/var/run/pg_sshkey` | v1: where to create the nonce on a local server |
| `--challenge-cmd CMD` | none | v1: shell command that creates the nonce on the server and prints it; implies `--v1` |
| `--challenge-bin PATH` | from `PATH` | v1: location of `pg_sshkey_challenge` |

Everything after `--` is passed to `psql`.

## pg_sshkey_query

```text
pg_sshkey_query [options] [dbname]
```

Takes `-U`, `-h`, `-p`, `-d`, `-i`, `-v`, `--v1`, and `-c` with the meanings
above, plus `-q`, `--query SQL` (default `SELECT 1`). Prints the result rows,
or one `error:` line and exit status 1. Helper tools are found on `PATH` or
beside the script.

## pg_sshkey_addkey

```text
pg_sshkey_addkey [-d DIR] [-a] <pg_username> <pubkey_file | - | "ssh-... key">
pg_sshkey_addkey --list <pg_username>
pg_sshkey_addkey --remove <pg_username>
```

Runs as root. `-d`, `--keys-dir` changes the root directory from
`/etc/pg_sshkeys`; `-a`, `--append` adds to an existing file instead of
replacing it. Unsupported key types in the input are skipped with a warning.

## pg_sshkey_challenge (v1 only)

```text
pg_sshkey_challenge <challenge_dir>
```

Creates a 32-byte nonce file `<challenge_dir>/<hex>` (mode 0644) and prints
the hex. Not used by v2 tokens.

## Module options

Set in `/etc/pam.d/postgresql`; see [Configuration](configuration.md#module-options).

| Option | Default |
| --- | --- |
| `authorized_keys_dir=<dir>` | `/etc/pg_sshkeys` |
| `challenge_dir=<dir>` | `/var/run/pg_sshkey` |
| `debug` | off |

## Log messages

The module logs through `pam_syslog` to the `authpriv` facility. On systemd
hosts read them with `journalctl -t postgres` or
`journalctl SYSLOG_FACILITY=10`. Each line is prefixed
`pam_pg_sshkey(postgresql:auth): pam_pg_sshkey:`.

| Level | Message | Meaning |
| --- | --- | --- |
| info | `user 'U' authenticated with key K` | Success. `K` is the key comment, or its type |
| warning | `authentication failed for 'U'` | No registered key verifies the signature |
| warning | `replayed token for 'U' (nonce already used)` | A v2 token was presented a second time |
| warning | `token timestamp for 'U' is N s from server time (limit 60), expired or clock skew` | v2 timestamp outside the window |
| warning | `challenge not found or expired for 'U'` | v1 nonce file missing, used, or older than 60 seconds |
| warning | `no authorized_keys for 'U'` | `<authorized_keys_dir>/U/authorized_keys` does not exist |
| warning | `no valid keys in 'PATH'` | The file has no `ssh-ed25519` or `ssh-rsa` entries |
| error | `failed to get auth token for 'U' (client sent no password)` | The client connected without a precomputed token |
| error | `malformed token for 'U'` | The password is not a v1 or v2 token |
| error | `base64 decode failed for 'U'` | The signature part is not base64 |
| error | `cannot read authorized_keys for 'U' (permission denied, ...)` | The file is not readable by `postgres`; the next line gives the `chown` and `chmod` to run |
| error | `authorized_keys for 'U' is world/group writable, refusing` | Mode allows writes by group or others |
| error | `could not record nonce in DIR: ..., refusing` | v2: the nonce directory is missing or not writable by `postgres` |
| error | `could not delete challenge H in DIR: ..., refusing` | v1: the nonce file could not be removed, so the login is refused rather than risk a replay |
| debug | `swept N stale challenge(s) from DIR` | Housekeeping, with `debug` on |

PostgreSQL itself logs `PAM authentication failed for user "U"` for any
refusal.
