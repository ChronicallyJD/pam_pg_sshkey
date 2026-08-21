# pam_pg_sshkey

A PAM module that lets PostgreSQL authenticate database users with SSH
public keys instead of passwords. The server stores public keys in OpenSSH
`authorized_keys` files; the client proves possession of the private key by
signing a one-time challenge. Private keys never leave the client.

pam_pg_sshkey is written in C against libpam and OpenSSL, and ships a Python
module for applications and replication clients. It is licensed under the
[MIT License](LICENSE). The current version is 1.1.0, recorded in
[CHANGELOG.md](CHANGELOG.md).

## How it works

The client issues its own challenge and signs it:

```text
token   = <unix_ts>:<nonce_hex>:<base64_signature>
message = "pg-sshkey-v2\0" || "<unix_ts>:<nonce_hex>"
```

It then connects with the token as the PostgreSQL password. PostgreSQL hands
user and password to PAM, and the module accepts the login when the timestamp
is within 60 seconds of server time, the signature verifies against one of the
user's registered keys, and the nonce has not been seen before. The module
records each nonce on first use, so a captured token cannot be replayed.

Nothing happens on the server before the connection. A client on the same
host and a client on another continent follow the same steps, and the only
operational requirement is that the two clocks agree to within 60 seconds.

## Quick start

On the database server:

```sh
make
sudo make install
sudo make install-conf
```

Add a `pam` line to `pg_hba.conf` ahead of the default rules and reload:

```text
host    all    all    0.0.0.0/0    pam    pamservice=postgresql
```

Register a user's public key and create the role:

```sh
sudo pg_sshkey_addkey alice ~alice/.ssh/id_ed25519.pub
sudo -u postgres psql -c 'CREATE ROLE alice LOGIN'
```

Connect as that user:

```sh
pg_sshkey_connect -h dbserver -U alice mydb
```

`pg_sshkey_connect` computes the token and starts `psql` with it. Plain
`psql` cannot be used on its own: libpq must already hold the password when
PostgreSQL asks for it. The [user guide](docs/user-guide.md) explains this
and the Python equivalent.

## Documentation

| | |
| --- | --- |
| [Where to start](docs/index.md) | Pick a page by task |
| [Installation](docs/installation.md) | Requirements, build, install, uninstall |
| [Configuration](docs/configuration.md) | `pg_hba.conf`, the PAM service file, module options |
| [User guide](docs/user-guide.md) | Keys, connecting, the command-line tools |
| [Python](docs/python.md) | `pam_pg_sshkey.py` for applications |
| [Replication](docs/replication.md) | Logical replication subscribers without stored passwords |
| [Reference](docs/reference.md) | Token formats, tool options, log messages |
| [Security](docs/security.md) | Trust model, file permissions, hardening |
| [Troubleshooting](docs/troubleshooting.md) | Symptoms, causes, fixes |
| [Testing](docs/testing.md) | The test suite and the end-to-end matrix |
| [Changelog](CHANGELOG.md) | Notable changes |

## Repository layout

```text
src/
    pam_pg_sshkey.c         PAM module entry points
    challenge_store.[ch]    nonce records and sweeping
    key_parser.[ch]         authorized_keys to EVP_PKEY
    sig_verify.[ch]         Ed25519 and RSA verification
    pg_sshkey_sign.c        client: issue and sign a token
    pg_sshkey_challenge.c   server: create a v1 nonce (legacy)
    pg_sshkey_connect       client: token, then psql
    pg_sshkey_addkey        administrator: deploy a public key
    pg_sshkey_query.py      client: run one query with psycopg2
    pam_pg_sshkey.py        Python module
config/pam.d/postgresql     PAM service file installed by make install-conf
tests/                      unit, libpam-seam, system and end-to-end tests
docs/                       documentation
```
