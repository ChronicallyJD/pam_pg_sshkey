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
- It does not read keys from `ssh-agent`. The C tools need an unencrypted
  private key file; the Python module accepts a passphrase.

## File permissions

| Path | Owner | Mode | Why |
| --- | --- | --- | --- |
| `/lib/.../security/pam_pg_sshkey.so` | `root:root` | `0755` | Loaded by the PostgreSQL backend through libpam |
| `/etc/pam.d/postgresql` | `root:root` | `0644` | PAM service file |
| `/etc/pg_sshkeys/` | `root:postgres` | `0750` | Only root writes keys; `postgres` reads them |
| `/etc/pg_sshkeys/<user>/` | `root:postgres` | `0750` | Per-user directory |
| `/etc/pg_sshkeys/<user>/authorized_keys` | `root:postgres` | `0640` | The module refuses files writable by group or others, and files it cannot read |
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
- `debug` off in `/etc/pam.d/postgresql` outside of diagnosis.
- Ed25519 keys, or RSA keys of at least 3072 bits.
- Replication roles with `REPLICATION` and the `SELECT` grants they need,
  never superuser.
- NTP or chrony on every client and server.
- Authentication failures reviewed in the journal.
