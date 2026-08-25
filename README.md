<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="logo/pam_pg_sshkey-logo-dark.svg">
  <img src="logo/pam_pg_sshkey-logo.svg" alt="pam_pg_sshkey" width="420">
</picture>
<p></p>
<p><strong>Your SSH key is your PostgreSQL password.</strong></p>

<a href="docs/installation.md"><img src="badges/postgresql.svg" alt="PostgreSQL 16 and 18 tested"></a>
<a href="LICENSE"><img src="badges/license.svg" alt="License: MIT"></a>
<a href="CHANGELOG.md"><img src="badges/version.svg" alt="Version 2.0.0"></a>
<a href="docs/security.md"><img src="badges/tokens.svg" alt="Tokens: single use, 60 seconds"></a>
<a href="https://github.com/ChronicallyJD/pam_pg_sshkey/actions/workflows/test.yml"><img src="https://github.com/ChronicallyJD/pam_pg_sshkey/actions/workflows/test.yml/badge.svg" alt="CI status"></a>

<p><strong><a href="docs/index.md">Read the documentation</a></strong></p>

</div>

pam_pg_sshkey is a PAM module that lets PostgreSQL authenticate database
users with the SSH keys they already have. The server stores public keys in
OpenSSH `authorized_keys` files; the client proves possession of the private
key by signing a one-time challenge. No password is stored on the server, in
the application, or in a connection string.

It is written in C against libpam and OpenSSL, ships a Python module for
applications and replication clients, and is licensed under the
[MIT License](LICENSE). The current version is 2.0.0; see
[CHANGELOG.md](CHANGELOG.md).

## Why pam_pg_sshkey

- **Nothing secret on the server.** A compromised key tree reveals public
  keys only. There is no password hash to crack and no shared secret to
  rotate.
- **Every token is single use.** A captured token is refused on reuse and
  expires 60 seconds after it was made, so it is worthless to an observer.
- **Works from anywhere, with nothing to set up per login.** The client
  issues its own challenge; a laptop on the local socket and a replication
  subscriber in another region follow the same two steps.
- **Uses what you already run.** Keys come from `ssh-keygen`, registration is
  an `authorized_keys` file, and any libpq client works: `psql` through
  `pg_sshkey_connect`, psycopg2 through `pam_pg_sshkey.py`, or your own code
  with a 13-byte prefix and one signature.
- **Certificates, no per-user files.** Point the module at a CA public key
  and any key certified by `ssh-keygen -s` for that role name logs in, the
  way sshd's `TrustedUserCAKeys` works.
- **Proven, not promised.** Every release runs the production module through
  libpam exactly as PostgreSQL does, and logs real OS users in against
  PostgreSQL 18 on Ubuntu and PostgreSQL 16 on Rocky Linux. See
  [Testing](docs/testing.md).

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
    ssh_cert.[ch]           OpenSSH certificate parsing and CA verification
    pg_sshkey_sign.c        client: issue and sign a token
    pg_sshkey_connect       client: token, then psql
    pg_sshkey_addkey        administrator: deploy a public key
    pg_sshkey_query.py      client: run one query with psycopg2
    pam_pg_sshkey.py        Python module
config/pam.d/postgresql     PAM service file installed by make install-conf
tests/                      unit, libpam-seam, system and end-to-end tests
docs/                       documentation
logo/                       logo and mark (SVG and PNG), see logo/README.md
badges/                     README badges
```
