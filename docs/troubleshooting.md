# Troubleshooting

This page maps symptoms to causes and fixes. The module's own messages are
listed in [Reference](reference.md#log-messages); PostgreSQL logs
`PAM authentication failed for user "U"` for every refusal, and the reason is
in the system journal beside it.

## Read the logs

```sh
sudo journalctl --since '10 minutes ago' | grep pam_pg_sshkey
sudo tail -n 50 /var/log/postgresql/postgresql-18-main.log     # Debian, Ubuntu
sudo tail -n 50 /var/lib/pgsql/data/log/postgresql-$(date +%a).log   # RHEL, Rocky
```

Add `debug` to the module line in `/etc/pam.d/postgresql` to log each step
of an attempt. Remove it afterwards.

## Symptoms

| Symptom | Cause | Fix |
| --- | --- | --- |
| `psql` asks for a password, or `fe_sendauth: no password supplied` | The client connected without a precomputed token | Use `pg_sshkey_connect`, `pg_sshkey_query`, or the Python module |
| Journal: `failed to get auth token for 'U' (client sent no password)` | Same as above, seen from the server | Same |
| Journal: `no authorized_keys for 'U'` | No key registered for that role name | `sudo pg_sshkey_addkey U key.pub` |
| Journal: `cannot read authorized_keys for 'U' (permission denied, ...)` | File not readable by `postgres`, usually `U:U 0600` | Run the `chown` and `chmod` printed on the next journal line, or re-register with `pg_sshkey_addkey` |
| Journal: `authorized_keys for 'U' is world/group writable, refusing` | Mode too loose | `chmod 640` |
| Journal: `no valid keys in ...` | File has no `ssh-ed25519` or `ssh-rsa` line | Register a supported key; ECDSA and sk- keys are not supported |
| Journal: `authentication failed for 'U'` | The signing key is not one of the registered keys | `pg_sshkey_addkey --list U`; check `-i` on the client |
| Journal: `token timestamp ... expired or clock skew` | Client clock differs from server by more than 60 seconds, or a token was reused after 60 seconds | Synchronise clocks; mint a token per connection |
| Journal: `replayed token for 'U'` | The same token was presented twice | Mint a token per connection; do not store tokens |
| Journal: `challenge not found or expired for 'U'` | v1 token whose nonce file is missing, used, or old; typically a remote v1 client that created the nonce locally | Use v2 tokens, or create the v1 nonce on the server with `--challenge-cmd` |
| Journal: `could not record nonce in DIR` | `/var/run/pg_sshkey` missing (after a reboot without the tmpfiles rule) or not writable by `postgres` | `sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/pg_sshkey.conf`, or `chown postgres:postgres` |
| Journal: `could not delete challenge ... refusing` | v1 nonce directory not owned by `postgres` | `sudo chown postgres:postgres /var/run/pg_sshkey && sudo chmod 1733 /var/run/pg_sshkey` |
| PostgreSQL: `invalid authentication method "pamservice=postgresql"` | The `pg_hba.conf` line has five columns; `pam` is missing | Put `pam` in the method column and `pamservice=postgresql` in the options column |
| PostgreSQL: `password authentication failed` with nothing in the journal | An earlier `pg_hba.conf` rule (`scram-sha-256`, `md5`) matched first | Move the `pam` rule above it; check with `SELECT * FROM pg_hba_file_rules` |
| PostgreSQL: `no pg_hba.conf entry for replication connection` | No `replication` database rule for the subscriber | Add one; see [Replication](replication.md) |
| Subscription authenticates once, then fails | Token stored in `CREATE SUBSCRIPTION` connection string | Not supported; see [Replication](replication.md#what-works-and-what-does-not) |
| `pg_sshkey_sign`: `Failed to load private key` | OpenSSH RSA key, or a key with a passphrase | `openssl pkey -in ~/.ssh/id_rsa -out key.pem`; use the Python module for passphrases |
| Python: `KeyError_: ... Need bcrypt module` | Passphrase-protected OpenSSH key without `bcrypt` installed | `pip install bcrypt`, or export the key to unencrypted PEM |
| Python: `ImportError: dynamic module does not define module export function` | `import pam_pg_sshkey` ran with the repository root as working directory, so `pam_pg_sshkey.so` was found first | Run from another directory, or install the Python file where the `.so` is not |

## Check the installation

```sh
ls -l /lib/*/security/pam_pg_sshkey.so /lib64/security/pam_pg_sshkey.so 2>/dev/null
cat /etc/pam.d/postgresql
ls -ld /var/run/pg_sshkey /etc/pg_sshkeys
sudo -u postgres cat /etc/pg_sshkeys/alice/authorized_keys
sudo -u postgres psql -c "SELECT line_number, type, database, user_name, auth_method, options, error FROM pg_hba_file_rules"
```

The last command shows the rules in the order PostgreSQL evaluates them and
any parse errors.
