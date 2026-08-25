# Security

This page describes what pam_pg_sshkey relies on, what it protects against,
and the file permissions a deployment needs. It assumes familiarity with the
token format in [Reference](reference.md#token-formats).

## Trust model

- The server stores only public keys. Compromise of the server's key tree
  reveals nothing that lets an attacker log in.
- Possession of the private key is proved by a signature over a message the
  client chooses. The module accepts the message only if its timestamp is
  within 60 seconds of server time and its nonce has never been accepted
  before, so an observed token cannot be used again and a recorded token
  cannot be used later.
- The module verifies the signature before it records the nonce. A flood of
  forged tokens creates no files.
- If the module cannot record a nonce, or cannot remove a v1 nonce file, it
  refuses the login. It does not fall back to accepting.
- Replay protection depends on the nonce directory. The module records nonces
  in `challenge_dir` and sweeps records older than 120 seconds on each
  authentication, so the directory stays small under reconnect loops.
- Client and server clocks must agree to within 60 seconds. A client further
  adrift is refused, never accepted with a stale timestamp.

## Certificates

With `trusted_ca_keys` set, the module also trusts any key certified by one
of the listed CA public keys, so the CA private key is the secret that
matters: whoever holds it can mint a certificate for any role name. Keep it
off the database server and sign with short validity windows. A v3 token
carries the certificate and a signature by the certified key over the same
timestamped nonce as v2, so the replay and clock rules above apply
unchanged. A token of 8192 bytes or more is refused before parsing. Before
it accepts the certificate the module checks, in order, that the blob parses
(every string in it must be printable ASCII, so that a key id or option name
chosen by the client cannot put a newline, and with it a forged line, into
the log), that it is a user certificate (type 1), that the
current time is inside `valid_after` to `valid_before`, that the principal
list is non-empty and contains the role name exactly, that a
`source-address` option permits the client address, that there is no other
critical option, that the signing key equals one of the trusted CA keys,
and that the CA signature verifies over the certificate body with
`ssh-ed25519`, `rsa-sha2-256`, or `rsa-sha2-512`. Only then does it verify
the token signature with the certified key and record the nonce. What it
does not do: revocation is by key, so a leaked certified key must be named
in `revoked_keys` (see below) and there is no revocation by serial or key id
and no KRL support; `force-command` and every critical option other than
`source-address` are refused rather than enforced; host certificates are
refused; CA signatures made with the SHA-1
`ssh-rsa` algorithm are refused; and there is no principals file, so the
principal must be the role name itself. The CA file is subject to the same
ownership and mode rules as `authorized_keys`.

## Revoked keys

`revoked_keys` is checked after the signature verifies and before the login
is granted, on every attempt and for every path: a key in an
`authorized_keys` file, a key certified by a trusted CA, and a key on a
security key alike. Revoking the key inside a certificate is the only way to
withdraw that certificate before `valid_before`, and it takes effect on the
next connection with no reload. A list that cannot be read refuses every
login rather than readmitting the keys it named, and the file is subject to
the same ownership and mode rules as `authorized_keys`. The list holds
keys: there is no revocation by certificate serial or key id, and no KRL
support. Revoking a CA key stops every certificate it signed. A file the
module cannot read as a list of keys refuses every login rather than
revoking nothing, and one file cannot serve as both `revoked_keys` and
`trusted_ca_keys`, which would make every revoked key a trusted CA.

## Security keys

An `sk-ssh-ed25519@openssh.com` key signs
`SHA256(application) || flags || counter || SHA256(message)`, and the module
verifies all of it, so a signature made for another application does not
authenticate here. The user-presence bit must be set, which is what makes
the touch a requirement rather than a convention; the module does not
require user verification (a PIN), and does not check the counter for
rollback, because a database server sees a fraction of a key's use and would
reject legitimate logins. `sk-ecdsa-sha2-nistp256@openssh.com` is not
supported. The private key is on the hardware, so signing goes through an
agent, and what the tests verify is the signature format rather than any
particular authenticator.

## Source address restrictions

A certificate signed with `-O source-address=<list>` is accepted only from
those addresses. PostgreSQL reports the client address in `PAM_RHOST` and
the module matches it against the list, which is comma-separated CIDR masks
in either family, as `ssh-keygen` writes it.

The list must be one `ssh-keygen` would sign: an entry with host bits set,
such as `192.168.1.50/24`, is refused rather than widened to its network,
because a CA that skips that check would otherwise hand out a subnet where
sshd hands out nothing. Address spellings `inet_pton` refuses, such as
`010.0.0.1` or the short form `127.1`, are refused for the same reason:
their meaning is not agreed between parsers.

The module refuses whenever it cannot decide. On the unix socket PostgreSQL
sets no `PAM_RHOST` at all, so a pinned certificate does not work there.
With the `pg_hba.conf` option `pam_use_hostname=1` PostgreSQL sets the
reverse-DNS name of the client instead of its address. Leave that option
off, and not only because a name cannot match an address list: the name
comes from the client's own DNS, and a PTR record that reads like an
address, `10.0.0.1`, is a name this module cannot tell from the real thing.
With `pam_use_hostname=1` a source-address restriction is worth nothing. A malformed list, including a stray comma, refuses rather than
matching what it can.

What this is worth: with `pam_use_hostname` off, the address is the
server's own view of the socket, so a client cannot forge it. It is still
only the address PostgreSQL sees: behind a proxy or a NAT that is the
proxy's address, and every client behind it looks the same.

## What the module does not do

- It does not encrypt the connection. The token is the PostgreSQL password
  and PostgreSQL sends it in clear text on an unencrypted connection. A
  captured token is single-use and expires within 60 seconds, which limits
  the damage, but use `hostssl` rules and `sslmode=verify-full` on any
  network you do not control.
- It does not rate-limit attempts. Failed logins are logged with the role
  name; feed the journal to fail2ban or an equivalent if brute-force attempts
  are a concern. Signature verification makes guessing infeasible, but each
  attempt costs the server a verification.
- It does not hold your private key. With `--agent` the key stays in the
  ssh-agent and the client only receives a signature, so the key can be
  passphrase-protected or on another machine behind a forwarded agent.
  Forwarding moves the trust: anyone who can reach the forwarded socket on
  the intermediate host can have the agent sign a database token for as long
  as the socket lives, and the tested matrix covers only a local agent.
  Without `--agent` the C tools read an unencrypted private key file and the
  Python module accepts a passphrase. An `sk-ssh-ed25519@openssh.com` key
  works through `--agent` only, because its private key is on the hardware;
  `sk-ecdsa` is not supported by either route.

## File permissions

| Path | Owner | Mode | Why |
| --- | --- | --- | --- |
| `/lib/.../security/pam_pg_sshkey.so` | `root:root` | `0755` | Loaded by the PostgreSQL backend through libpam |
| `/etc/pam.d/postgresql` | `root:root` | `0644` | PAM service file |
| `/etc/pg_sshkeys/` | `root:postgres` | `0750` | Only root writes keys; `postgres` reads them |
| `/etc/pg_sshkeys/<user>/` | `root:postgres` | `0750` | Per-user directory |
| `/etc/pg_sshkeys/<user>/authorized_keys` | `root:postgres` | `0640` | The module refuses files writable by group or others, and files it cannot read |
| `/etc/pg_sshkeys/trusted_ca_keys` | `root:postgres` | `0640` | CA public keys; the same refusal rules as `authorized_keys` apply |
| `/var/run/pg_sshkey/` | `postgres:postgres` | `1733` installed; `0700` recommended once only v2 clients remain | Nonce records |
| `/var/run/pg_sshkey/<nonce>` | `postgres` | `0600` | Written by the module on first use |

`pg_sshkey_addkey` sets the key-file ownership and mode; creating the files
by hand is the most common cause of a login failure.

### The nonce directory

With v2 tokens the module is the only writer, so the directory can be
`0700 postgres:postgres`. The installed mode `1733` (sticky, world-writable,
not world-readable) exists for the legacy v1 flow in which each client user
creates its own nonce file and only the owner or `postgres` may remove it.
Tighten the mode once no v1 clients remain:

```sh
sudo chmod 0700 /var/run/pg_sshkey
```

and change the tmpfiles.d rule in `/usr/lib/tmpfiles.d/pg_sshkey.conf` to
`0700` so the setting survives a reboot.

## Hardening checklist

- `hostssl` rules in `pg_hba.conf`, and `sslmode=verify-full` on clients.
- `authorized_keys` files `root:postgres 0640`, managed by `pg_sshkey_addkey`
  or by configuration management.
- `/var/run/pg_sshkey` owned by `postgres`; `0700` when v1 is no longer used.
- `trusted_ca_keys` set only when certificates are in use; the CA private
  key kept off the database server; certificate windows of weeks, not years.
- `debug` off in `/etc/pam.d/postgresql` outside of diagnosis.
- Ed25519 keys, or RSA keys of at least 3072 bits.
- Replication roles with `REPLICATION` and the `SELECT` grants they need,
  never superuser.
- NTP or chrony on every client and server.
- Authentication failures reviewed in the journal.
