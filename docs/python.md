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

`get_token` loads the key, picks a timestamp and a nonce, signs them, and
returns `<ts>:<nonce_hex>:<base64_signature>`. Nothing is written anywhere
and no server is contacted, so the same call serves local and remote servers.
Pass the result as `password=` to any libpq-based client; it must be present
when the connection opens. The token is single-use and the server refuses it
more than 60 seconds after its timestamp.

| Parameter | Default | Meaning |
| --- | --- | --- |
| `key_path` | `~/.ssh/id_ed25519` | OpenSSH, PKCS#8 PEM, or traditional PEM private key |
| `passphrase` | `None` | Passphrase as `bytes` for an encrypted key |
| `agent_pubkey` | `None` | Path to the public key of an identity in the ssh-agent at `$SSH_AUTH_SOCK`; the private key is never read. `ValueError` when `key_path` or `passphrase` is also given |
| `cert_path` | `None` | Path to an OpenSSH user certificate (`*-cert.pub`) for the key; produces a v3 token `<ts>:<nonce_hex>:<base64_signature>:<base64_cert>` |

`agent_pubkey` replaces `key_path`: the agent signs, so the key may carry a
passphrase, be an OpenSSH-format RSA key, or live on another machine behind a
forwarded agent. RSA identities are signed as `rsa-sha2-256`, and an agent
that answers with `ssh-rsa` raises `KeyError_`, as do a missing
`SSH_AUTH_SOCK`, an unreachable socket, an identity the agent does not hold,
an `sk-ecdsa` key, an empty signature, and a signature that does not verify
with the public key you named. An `sk-ssh-ed25519@openssh.com` identity
works: the token then carries the authenticator's flags and counter, and a
signature reporting no user presence is refused. The wait for the agent is 60 seconds,
overridden by `PG_SSHKEY_AGENT_TIMEOUT_MS`. It combines with `cert_path`.

```python
token = get_token(agent_pubkey="~/.ssh/id_ed25519.pub")
```

`cert_path` needs `trusted_ca_keys` set on the server and a certificate whose
principals include the role name ([User guide](user-guide.md#connecting-with-a-certificate)).
The certificate is sent as is; the module checks only that the first field
names a `*-cert-v01@openssh.com` certificate and that the second is padded
base64. It does not parse the certificate.

## Connect

```python
from pam_pg_sshkey import connect

conn = connect(user="alice", dbname="mydb", host="dbserver")
cur = conn.cursor()
cur.execute("SELECT current_user")
```

`connect` accepts the `get_token` parameters, including `agent_pubkey` and
`cert_path`, and forwards every other keyword argument to
`psycopg2.connect`. Passing `password=` raises `ValueError`; the function
sets it. Without psycopg2 installed it raises `ImportError` naming the
package to install. Each call mints a new token, so call `connect` again
rather than reusing a token after a disconnect.

## Replication connections

```python
from pam_pg_sshkey import connect_replication

logical  = connect_replication(user="replicator", host="publisher", dbname="mydb")
physical = connect_replication(user="replicator", host="publisher", replication=True)
```

`connect_replication` accepts `agent_pubkey` and `cert_path` as well, and sets `replication=` and the matching psycopg2
`connection_factory`: `"database"` (the default) gives a
`LogicalReplicationConnection`; `True`, `"true"`, `"on"`, `"yes"`, or `"1"`
gives a `PhysicalReplicationConnection`. An explicit `connection_factory=` is
respected. See [Replication](replication.md) for the publisher setup.

## Errors

All errors raised by the module derive from `PamPgSshKeyError`:

| Exception | Raised when |
| --- | --- |
| `PamPgSshKeyError` | Base class; catch it to catch every error below |
| `KeyError_` | The key file is missing, unreadable, encrypted without a passphrase, of an unsupported type, or needs `bcrypt`; or `cert_path` cannot be read or is not a `*-cert-v01@openssh.com` certificate; or an ssh-agent signature could not be obtained |

Combining `agent_pubkey` with `key_path` or `passphrase` raises `ValueError`,
which is not a `PamPgSshKeyError`.

Messages include the command to fix the problem. The module never lets a raw
`cryptography` exception escape from key loading. Importing the module
succeeds when `HOME` is unset; pass `key_path` explicitly in that case.

## Signing by hand

Any language with Ed25519 or RSA can produce a token. The signed message is
`pg-sshkey-v2` followed by a NUL byte, 13 bytes in all, then the ASCII string
`<unix_ts>:<nonce_hex>`. Ed25519 signs the message directly; RSA uses
PKCS#1 v1.5 with SHA-256. A certificate token uses the prefix `pg-sshkey-v3`
followed by a NUL byte and appends `:<base64_cert>`, the second field of the
`*-cert.pub` file. `utils/select1.py` is an 86-line example that does
this with `cryptography` and psycopg2 alone.
