# Configuration

This page covers the two files PostgreSQL and PAM read to use pam_pg_sshkey:
`pg_hba.conf` and `/etc/pam.d/postgresql`. It assumes the module is
installed ([Installation](installation.md)).

## pg_hba.conf

Add `pam` rules ahead of the default rules. PostgreSQL uses the first rule
that matches, so a `pam` rule placed after a `scram-sha-256` rule for the
same clients never applies.

```text
# TYPE  DATABASE      USER   ADDRESS        METHOD  OPTIONS
local   all           all                   pam     pamservice=postgresql
host    all           all    0.0.0.0/0      pam     pamservice=postgresql
host    replication   all    0.0.0.0/0      pam     pamservice=postgresql
```

The `OPTIONS` column is separate from the `METHOD` column. A line with
`pamservice=postgresql` in the method position fails to parse, and PostgreSQL
reports `invalid authentication method "pamservice=postgresql"`.

Keep a `peer` rule for the `postgres` superuser on the local socket so
administration continues to work without a key:

```text
local   all           postgres              peer
```

Check the file and reload:

```sql
SELECT line_number, error FROM pg_hba_file_rules WHERE error IS NOT NULL;
```

```sh
sudo systemctl reload postgresql
```

Use `hostssl` rather than `host` on networks you do not control. The token
travels as the password, and PostgreSQL sends it in clear text unless the
connection is encrypted.

## The PAM service file

`make install-conf` installs this file as `/etc/pam.d/postgresql`:

```text
auth    required    pam_pg_sshkey.so \
            authorized_keys_dir=/etc/pg_sshkeys \
            challenge_dir=/var/run/pg_sshkey

account required    pam_permit.so
```

PostgreSQL calls the `auth` stack and then the `account` stack. The `account`
stack is `pam_permit.so` because a database role need not be an OS account.

### Module options

| Option | Default | Meaning |
| --- | --- | --- |
| `authorized_keys_dir=<dir>` | `/etc/pg_sshkeys` | Keys are read from `<dir>/<username>/authorized_keys` |
| `challenge_dir=<dir>` | `/var/run/pg_sshkey` | Where used nonces are recorded (and where v1 nonce files are read) |
| `trusted_ca_keys=<file>` | unset | CA public keys that may certify user keys; unset refuses every certificate token |
| `revoked_keys=<file>` | unset | Public keys that may not authenticate, whatever else admits them |
| `debug` | off | Log each step at `LOG_DEBUG` to the `authpriv` facility |

Turn `debug` on only while diagnosing a problem; it logs the challenge of
every attempt.

### Revoked keys

`revoked_keys` names a file of public keys, in `authorized_keys` format,
that may not authenticate. It is checked after the signature verifies and
before the login is granted, for a key in an `authorized_keys` file and for
a key carried by a certificate alike, so revoking a key does not require
finding every file that lists it.

```text
auth    required    pam_pg_sshkey.so \
            authorized_keys_dir=/etc/pg_sshkeys \
            challenge_dir=/var/run/pg_sshkey \
            revoked_keys=/etc/pg_sshkeys/revoked_keys
```

The file must exist, be readable by `postgres`, and not be group or world
writable, with the same ownership as the CA file. If it cannot be read every
login is refused: a revocation list that vanishes must not readmit the keys
it named. An empty file is a valid list that revokes nothing.

Add a key with `cat key.pub >> /etc/pg_sshkeys/revoked_keys`. The list holds
keys, not certificates: revoking the key inside a certificate stops that
certificate, and there is no way to revoke by serial or key id.

### Security keys

The module accepts `sk-ssh-ed25519@openssh.com` entries, so a key that lives
on a FIDO authenticator can authenticate. The signature covers the key's
application string, a flags byte, and the authenticator's counter, and the
module refuses one whose user-presence bit is clear, so a login requires a
touch. `sk-ecdsa-sha2-nistp256@openssh.com` is not accepted; the module has
no ECDSA verifier. Signing needs `--agent`, because the private key is on
the hardware. See [User guide](user-guide.md#connecting-with-a-security-key).

### Certificates

With `trusted_ca_keys` set, a user whose key is certified by one of the
listed CAs authenticates without an `authorized_keys` file, the way sshd's
`TrustedUserCAKeys` works. The recommended path is
`/etc/pg_sshkeys/trusted_ca_keys`, owner `root:postgres`, mode `0640`:

```text
auth    required    pam_pg_sshkey.so \
            authorized_keys_dir=/etc/pg_sshkeys \
            challenge_dir=/var/run/pg_sshkey \
            trusted_ca_keys=/etc/pg_sshkeys/trusted_ca_keys
```

The file is in `authorized_keys` format, one `ssh-ed25519` or `ssh-rsa` CA
public key per line; `pg_sshkey_addkey` does not manage it. The module
refuses the file when `postgres` cannot read it or when group or others can
write it, and logs
`cannot read trusted_ca_keys PATH (permission denied, file must be owned root:postgres mode 0640, ...)`
or `trusted_ca_keys PATH is world/group writable, refusing`. Certificates
signed with the SHA-1 `ssh-rsa` algorithm, host certificates, and
certificates carrying any critical option are refused; there is no
revocation list. [Security](security.md#certificates) lists every check.

## Roles

PAM authenticates; PostgreSQL authorizes. The role must exist, and it needs
no password:

```sql
CREATE ROLE alice LOGIN;
```

A replication subscriber additionally needs the `REPLICATION` attribute; see
[Replication](replication.md).
