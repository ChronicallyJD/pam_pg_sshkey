# Reference

This page lists the token formats, the command-line tools and their options,
the module options, and the messages the module logs. For how to use them,
see the [User guide](user-guide.md).

## Token formats

| Version | Token | Signed message | Server check |
| --- | --- | --- | --- |
| 2 (default) | `<unix_ts>:<nonce_hex>:<base64_sig>` | `"pg-sshkey-v2\0" \|\| "<unix_ts>:<nonce_hex>"` (ASCII) | `\|now - ts\| <= 60`, signature valid, nonce not recorded before; the nonce is then recorded |
| 3 (certificate) | `<unix_ts>:<nonce_hex>:<base64_sig>:<base64_cert>` | `"pg-sshkey-v3\0" \|\| "<unix_ts>:<nonce_hex>"` (ASCII) | As v2, with the signature verified against the key inside the certificate, after the certificate passes the checks in [Security](security.md#certificates) |
| 1 (legacy) | `<nonce_hex>:<base64_sig>` | `"pg-sshkey-v1\0" \|\| nonce_bytes` | A nonce file created by `pg_sshkey_challenge` exists in `challenge_dir` and is under 60 seconds old; the file is then deleted |

Each prefix is 13 bytes including the NUL. `nonce_hex` is 64 lowercase
hexadecimal characters (32 random bytes). A security key's signature field
holds 69 bytes, the 64 raw bytes followed by the flags byte and the 4-byte
counter, and covers `SHA256(application) || flags || counter ||
SHA256(message)`. Ed25519 signs the message directly;
RSA uses PKCS#1 v1.5 with SHA-256. `base64_cert` is the second field of an
OpenSSH `*-cert.pub` file, unchanged; `ssh-ed25519-cert-v01@openssh.com` and
`ssh-rsa-cert-v01@openssh.com` are accepted. The module tells the versions
apart by the number of colons (one, two, or three). A token of 8192 bytes
(`MAX_TOKEN_LEN`) or more is refused as malformed before any parsing. The window and lifetime are `CHALLENGE_TTL_SECS` (60) in
`src/challenge_store.h`; nonce records are swept after twice that.

## pg_sshkey_sign

```text
pg_sshkey_sign [--at <unix_ts>] [--nonce <hex64>] <private_key>                    v2
pg_sshkey_sign --cert <cert.pub> [--at <unix_ts>] [--nonce <hex64>] <private_key>  v3
pg_sshkey_sign --agent <pubkey.pub> [--cert <cert.pub>] [--at <ts>] [--nonce <hex>]  v2 or v3
pg_sshkey_sign <nonce_hex> <private_key>                                            v1
```

Prints the token to standard output. `--at` and `--nonce` override the
timestamp and nonce of a v2 or v3 token; they exist for tests. `--cert`
reads an OpenSSH certificate file whose first field ends in
`-cert-v01@openssh.com` and appends its base64 field to the token; a plain
public key is refused with `... is not an OpenSSH certificate` and a missing
file with `Cannot read certificate PATH: ...`. Accepted key files:
OpenSSH Ed25519 (unencrypted), PKCS#8 PEM (Ed25519 or RSA), traditional PEM
(RSA). Exit status 1 on any error, with the reason on standard error.

`--agent` signs through the ssh-agent listening on `$SSH_AUTH_SOCK` using the
identity whose public key is in the named file, and takes no private key
argument, and cannot be combined with `-i`. The private key is never read,
so a passphrase-protected key, an OpenSSH-format RSA key, and a forwarded
agent all work. The client verifies the agent's signature against that public
key before printing the token, and waits at most 60 seconds for the agent
(`PG_SSHKEY_AGENT_TIMEOUT_MS` overrides that). For an RSA key the
client asks the agent for `rsa-sha2-256`, because the module verifies RSA
with SHA-256; an agent that answers with `ssh-rsa` is refused. An
`sk-ssh-ed25519@openssh.com` identity works and the token then carries the
authenticator's flags and counter; `sk-ecdsa-sha2-nistp256@openssh.com` is
refused, because the module has no ECDSA verifier. `--agent` is not available
with a v1 challenge.

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
| `--agent FILE` | none | Sign through the ssh-agent holding the identity whose public key is `FILE`; replaces `-i` |
| `--cert FILE` | none | OpenSSH user certificate for the key; produces a v3 token. `<identity>-cert.pub` is not picked up automatically |
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

Takes `-U`, `-h`, `-p`, `-d`, `-i`, `-v`, `--agent`, `--cert`, `--v1`, and `-c` with the
meanings above, plus `-q`, `--query SQL` (default `SELECT 1`). Prints the result rows,
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
| `trusted_ca_keys=<file>` | unset (certificate tokens refused) |
| `revoked_keys=<file>` | unset (nothing revoked) |
| `debug` | off |

## Log messages

The module logs through `pam_syslog` to the `authpriv` facility. On systemd
hosts read them with `journalctl -t postgres` or
`journalctl SYSLOG_FACILITY=10`. Each line is prefixed
`pam_pg_sshkey(postgresql:auth): pam_pg_sshkey:`.

| Level | Message | Meaning |
| --- | --- | --- |
| info | `user 'U' authenticated with key K` | Success. `K` is the key comment, or its type |
| info | `user 'U' authenticated with certificate 'KEYID' serial N` | Success with a v3 token. `KEYID` is the `-I` value given to `ssh-keygen` |
| warning | `authentication failed for 'U'` | No registered key (v1, v2) or the certified key (v3) verifies the signature |
| warning | `key for 'U' is revoked` | The key that verified is listed in `revoked_keys` |
| warning | `certificate for 'U' rejected: key is revoked` | The certified key is listed in `revoked_keys` |
| warning | `certificate for 'U' rejected: signing CA is revoked` | The CA that signed it is listed in `revoked_keys` |
| error | `revoked_keys PATH has N line(s) but only M parsed as keys, refusing` | The file is not in `authorized_keys` format, so the list cannot be trusted |
| error | `revoked_keys PATH is not a regular file, refusing` | The option names a directory or a device |
| error | `trusted_ca_keys and revoked_keys are the same file (PATH), refusing` | One file cannot be both lists |
| error | `cannot read revoked_keys PATH: ..., refusing` | The list is missing or unreadable, so every login is refused |
| error | `revoked_keys PATH is world/group writable, refusing` | Mode allows writes by group or others |
| warning | `replayed token for 'U' (nonce already used)` | A v2 or v3 token was presented a second time |
| warning | `token timestamp for 'U' is N s from server time (limit 60), expired or clock skew` | v2 or v3 timestamp outside the window |
| warning | `certificate token for 'U' but trusted_ca_keys is not set` | A v3 token arrived and the option is absent from `/etc/pam.d/postgresql` |
| error | `cannot stat trusted_ca_keys PATH: ...` | The CA file does not exist |
| error | `cannot read trusted_ca_keys PATH (permission denied, file must be owned root:postgres mode 0640, got uid=N gid=N mode=NNNN): ...` | The CA file is not readable by `postgres` |
| error | `trusted_ca_keys PATH is world/group writable, refusing` | Mode allows writes by group or others |
| error | `no valid CA keys in trusted_ca_keys PATH` | The CA file has no `ssh-ed25519` or `ssh-rsa` entries |
| error | `certificate for 'U' rejected: malformed certificate` | The fourth field is not base64, does not parse as an OpenSSH certificate, or has a key id, principal, option, or algorithm name with a byte outside printable ASCII |
| warning | `certificate for 'U' rejected: not a user certificate` | A host certificate (`ssh-keygen -h`) |
| warning | `certificate for 'U' rejected: expired` | Server time is at or past `valid_before` |
| warning | `certificate for 'U' rejected: not yet valid` | Server time is before `valid_after` |
| warning | `certificate for 'U' rejected: principal 'U' not listed` | The principal list is empty or does not contain the role name |
| warning | `certificate for 'U' rejected: unsupported critical option NAME` | The certificate carries a critical option such as `source-address` |
| warning | `certificate for 'U' rejected: not signed by a trusted CA` | The signing key is not in `trusted_ca_keys` |
| warning | `certificate for 'U' rejected: unsupported signature algorithm ALGO` | The CA signed with `ssh-rsa` (SHA-1) or another algorithm the module does not verify |
| warning | `certificate for 'U' rejected: invalid CA signature` | The certificate body does not verify with the CA key |
| warning | `challenge not found or expired for 'U'` | v1 nonce file missing, used, or older than 60 seconds |
| warning | `no authorized_keys for 'U'` | `<authorized_keys_dir>/U/authorized_keys` does not exist |
| warning | `no valid keys in 'PATH'` | The file has no `ssh-ed25519`, `ssh-rsa`, or `sk-ssh-ed25519@openssh.com` entries |
| error | `failed to get auth token for 'U' (client sent no password)` | The client connected without a precomputed token |
| error | `malformed token for 'U'` | The password is not a v1, v2, or v3 token |
| error | `base64 decode failed for 'U'` | The signature part is not base64 |
| error | `cannot read authorized_keys for 'U' (permission denied, ...)` | The file is not readable by `postgres`; the next line gives the `chown` and `chmod` to run |
| error | `authorized_keys for 'U' is world/group writable, refusing` | Mode allows writes by group or others |
| error | `could not record nonce in DIR: ..., refusing` | v2 and v3: the nonce directory is missing or not writable by `postgres` |
| error | `could not delete challenge H in DIR: ..., refusing` | v1: the nonce file could not be removed, so the login is refused rather than risk a replay |
| debug | `swept N stale challenge(s) from DIR` | Housekeeping, with `debug` on |

PostgreSQL itself logs `PAM authentication failed for user "U"` for any
refusal.
