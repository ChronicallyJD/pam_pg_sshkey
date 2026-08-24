# User guide

This page covers registering a user's SSH key on the server and connecting
from the shell. It assumes the module is installed and PostgreSQL is
configured ([Installation](installation.md), [Configuration](configuration.md)).
For Python applications see [Python](python.md).

## Generate a key

On the client, as the user who will connect:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ''
```

Ed25519 is the recommended type. RSA keys of 2048 bits or more also work.
The tools read OpenSSH Ed25519 keys directly; an OpenSSH RSA key must first be
exported to PEM with `openssl pkey -in ~/.ssh/id_rsa -out key.pem`. A key with
a passphrase cannot be used by the C tools; the Python module accepts a
passphrase.

## Register the key on the server

As root on the database server:

```sh
sudo pg_sshkey_addkey alice ~alice/.ssh/id_ed25519.pub
```

`pg_sshkey_addkey` writes `/etc/pg_sshkeys/alice/authorized_keys` with owner
`root:postgres` and mode `0640`, which is what the module, running as
`postgres`, needs. Files created by hand usually end up owned by the user with
mode `0600`, and the module then refuses them with a permission error.

| Command | Effect |
| --- | --- |
| `pg_sshkey_addkey alice key.pub` | Replace alice's keys with the one in `key.pub` |
| `pg_sshkey_addkey --append alice key.pub` | Add a key |
| `ssh-keygen -y -f ~/.ssh/id_ed25519 \| pg_sshkey_addkey alice -` | Read the key from standard input |
| `pg_sshkey_addkey --list alice` | Show registered keys with fingerprints |
| `pg_sshkey_addkey --remove alice` | Remove all of alice's keys |

The file uses the OpenSSH `authorized_keys` format, one key per line. The
module accepts `ssh-ed25519` and `ssh-rsa` keys; the words `rsa-sha2-256` and
`rsa-sha2-512` are accepted as aliases of `ssh-rsa`. Other types are skipped.

Then create the role if it does not exist:

```sql
CREATE ROLE alice LOGIN;
```

## Connect

```sh
pg_sshkey_connect                            # as $USER, to database $USER, local socket
pg_sshkey_connect mydb                       # a database
pg_sshkey_connect -h dbserver -U alice mydb  # another host and user
pg_sshkey_connect -i ~/.ssh/other_key mydb   # another key
pg_sshkey_connect -v mydb                    # show each step
pg_sshkey_connect -U alice -- -c 'SELECT 1'  # arguments after -- go to psql
```

`pg_sshkey_connect` runs `pg_sshkey_sign` to produce a token, exports it as
`PGPASSWORD`, and executes `psql`. Arguments after `--` are passed to `psql`
unchanged. `PGUSER`, `PGHOST`, `PGPORT`, and `PGDATABASE` are honoured as
defaults.

### Why plain psql does not work

When PostgreSQL asks for a password, libpq answers from the password it
already holds (`PGPASSWORD`, the connection string, or `~/.pgpass`). If it
holds none, it disconnects without sending anything, and the module logs
`failed to get auth token (client sent no password)`. The token is about 170
characters of signature material that must be fresh for every connection, so
it cannot be typed at a prompt. Every client therefore computes the token
before opening the connection, which is what `pg_sshkey_connect`,
`pg_sshkey_query`, and the Python module do.

### Run one query

```sh
pg_sshkey_query -h dbserver -U alice -q 'SELECT now()' mydb
```

`pg_sshkey_query` uses psycopg2 and prints the rows. It takes the same
connection options as `pg_sshkey_connect`.

## Connecting with a certificate

A key certified by a trusted certificate authority needs no `authorized_keys`
file on the server. The server administrator creates the CA once and
installs its public key; each user's key is then signed by the CA with the
role name as the principal. This is the same certificate format sshd
accepts with `TrustedUserCAKeys`.

Create the CA, on a machine you control and not on the database server:

```sh
ssh-keygen -t ed25519 -f ca_key -N '' -C 'pg CA'
```

Sign a user's public key. `-I` is a key id that appears in the server log,
`-n` is the principal, which must equal the PostgreSQL role name, and `-V`
is the validity window:

```sh
ssh-keygen -s ca_key -I alice-laptop -n alice -V +52w ~alice/.ssh/id_ed25519.pub
```

This writes `~alice/.ssh/id_ed25519-cert.pub`. Install the CA public key on
the database server and name it in `/etc/pam.d/postgresql`
([Configuration](configuration.md#certificates)):

```sh
sudo install -o root -g postgres -m 0640 ca_key.pub /etc/pg_sshkeys/trusted_ca_keys
```

Connect with `--cert`; the private key is still `-i` or the default
`~/.ssh/id_ed25519`, and there is no automatic lookup of `<identity>-cert.pub`:

```sh
pg_sshkey_connect --cert ~/.ssh/id_ed25519-cert.pub -h dbserver -U alice mydb
pg_sshkey_query --cert ~/.ssh/id_ed25519-cert.pub -h dbserver -U alice -q 'SELECT 1' mydb
```

The server log shows `user 'alice' authenticated with certificate
'alice-laptop' serial 0`. The certificate must list the role name among its
principals, be within its validity window, be a user certificate, and carry
no critical options (`-O source-address=...` or `-O force-command=...` are
refused). There is no revocation list: to withdraw a certificate before it
expires, replace the CA key or wait for the window to close, so keep windows
short. RSA user keys and RSA CAs work; a CA signature made with the SHA-1
`ssh-rsa` algorithm (`ssh-keygen -t ssh-rsa` when signing) is refused. A
certificate token is about 770 characters for Ed25519 and about 1660 for a
3072-bit RSA key.

## Tokens

A token is valid for one use and for 60 seconds either side of the server's
clock. Keep client clocks synchronised with NTP or chrony; a client more than
60 seconds adrift is refused with `expired or clock skew` in the server log.

Because a token is consumed on first use, it cannot be stored in any place
that several connections read, such as a connection pool configuration or a
`CREATE SUBSCRIPTION` connection string. [Replication](replication.md)
explains what to do instead.

## Legacy v1 tokens

Releases before 1.1.0 used a token of the form `<nonce_hex>:<signature>` over
a nonce file that the client first had to create in the server's
`/var/run/pg_sshkey` with `pg_sshkey_challenge`. The module still accepts
these tokens. To produce one, pass `--v1` to `pg_sshkey_connect` or
`pg_sshkey_query`, or `version=1` to the Python module. A v1 client on another
host must create the nonce on the server, for example
`--challenge-cmd 'ssh alice@dbserver pg_sshkey_challenge /var/run/pg_sshkey'`.
v1 support will be removed in a future release.
