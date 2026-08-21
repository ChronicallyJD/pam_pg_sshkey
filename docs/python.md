# Python

This page covers `src/pam_pg_sshkey.py`, a module that produces tokens and
opens psycopg2 connections authenticated with an SSH key. It assumes a
registered key ([User guide](user-guide.md)). The module needs `cryptography`
and, for the connection helpers, `psycopg2`; `bcrypt` is needed only for
passphrase-protected OpenSSH keys.

Copy `src/pam_pg_sshkey.py` next to your application or put `src/` on
`PYTHONPATH`. Do not import it with the repository root as the working
directory: `./pam_pg_sshkey.so` shadows the Python file there.

## Get a token

```python
from pam_pg_sshkey import get_token

token = get_token(key_path="~/.ssh/id_ed25519")
```

`get_token` loads the key, issues a timestamped nonce, signs it, and returns
`<ts>:<nonce_hex>:<base64_signature>`. Nothing is written anywhere and no
server is contacted, so the same call serves local and remote servers. Pass
the result as `password=` to any libpq-based client; it must be present when
the connection opens.

| Parameter | Default | Meaning |
| --- | --- | --- |
| `key_path` | `~/.ssh/id_ed25519` | OpenSSH, PKCS#8 PEM, or traditional PEM private key |
| `passphrase` | `None` | Passphrase as `bytes` for an encrypted key |
| `version` | `2` | `1` selects the legacy server-nonce token |
| `challenge_dir` | `/var/run/pg_sshkey` | v1 only: where to create the nonce on a local server |
| `challenge_cmd` | `None` | v1 only: command that creates the nonce on a remote server and prints it; implies `version=1` |

## Connect

```python
from pam_pg_sshkey import connect

conn = connect(user="alice", dbname="mydb", host="dbserver")
cur = conn.cursor()
cur.execute("SELECT current_user")
```

`connect` accepts the `get_token` parameters and forwards every other keyword
argument to `psycopg2.connect`. Passing `password=` raises `ValueError`; the
function sets it. Each call mints a new token, so call `connect` again rather
than reusing a token after a disconnect.

## Replication connections

```python
from pam_pg_sshkey import connect_replication

logical  = connect_replication(user="replicator", host="publisher", dbname="mydb")
physical = connect_replication(user="replicator", host="publisher", replication=True)
```

`connect_replication` sets `replication=` and the matching psycopg2
`connection_factory`: `"database"` (the default) gives a
`LogicalReplicationConnection`; `True`, `"true"`, `"on"`, `"yes"`, or `"1"`
gives a `PhysicalReplicationConnection`. An explicit `connection_factory=` is
respected. See [Replication](replication.md) for the publisher setup.

## Errors

All errors raised by the module derive from `PamPgSshKeyError`:

| Exception | Raised when |
| --- | --- |
| `KeyError_` | The key file is missing, unreadable, encrypted without a passphrase, of an unsupported type, or needs `bcrypt` |
| `ChallengeError` | A v1 nonce could not be created, or `challenge_cmd` failed or printed something other than a 64-character hex nonce |

Messages include the command to fix the problem. The module never lets a raw
`cryptography` exception escape from key loading. Importing the module
succeeds when `HOME` is unset; pass `key_path` explicitly in that case.

## Signing by hand

Any language with Ed25519 or RSA can produce a token. The signed message is
the 13-byte prefix `pg-sshkey-v2` followed by a NUL byte, then the ASCII
string `<unix_ts>:<nonce_hex>`. Ed25519 signs the message directly; RSA uses
PKCS#1 v1.5 with SHA-256. `utils/select1.py` is a 90-line example that does
this with `cryptography` and psycopg2 alone.
