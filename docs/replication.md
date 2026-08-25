# Replication

This page covers a logical replication subscriber that authenticates to the
publisher with an SSH key, so no password is stored on either side. It
assumes pam_pg_sshkey is installed and configured on the publisher
([Installation](installation.md), [Configuration](configuration.md)).

## What works and what does not

A subscriber driven by your own client works: each connection gets a fresh
token from the Python module, and the publisher verifies it like any other
login. The subscriber needs nothing on the publisher beyond its registered
public key.

A subscription created with `CREATE SUBSCRIPTION ... CONNECTION '...'` does
not work with pam_pg_sshkey. PostgreSQL stores that connection string and
reuses it from several worker processes (the apply worker and each tablesync
worker). A token is single-use and expires 60 seconds after its timestamp, so
the first worker consumes it and every later connection is refused: the
journal says `replayed token for 'replicator' (nonce already used)`, or
`expired or clock skew` once the 60 seconds have passed. No setting changes
the lifetime. If you need a server-managed subscription, terminate SSH-key
authentication at a local proxy and point the subscription at the proxy.

## Publisher setup

1. Create the replication role and register the subscriber's key:

   ```sql
   CREATE ROLE replicator REPLICATION LOGIN;
   GRANT SELECT ON ALL TABLES IN SCHEMA public TO replicator;
   ```

   ```sh
   sudo pg_sshkey_addkey replicator replicator_key.pub
   ```

2. Allow the subscriber in `pg_hba.conf`, for the `replication` database and
   for the database being published:

   ```text
   hostssl   replication   replicator   <subscriber_ip>/32   pam   pamservice=postgresql
   hostssl   mydb          replicator   <subscriber_ip>/32   pam   pamservice=postgresql
   ```

3. Enable logical replication in `postgresql.conf` and restart:

   ```text
   wal_level = logical
   max_replication_slots = 10
   max_wal_senders = 10
   ```

4. Create the publication:

   ```sql
   CREATE PUBLICATION my_publication FOR ALL TABLES;
   ```

## Subscriber client

```python
import sys
sys.path.insert(0, "/path/to/pam_pg_sshkey/src")

import psycopg2
from pam_pg_sshkey import connect_replication

PUBLISHER   = "publisher.example.com"
DBNAME      = "mydb"
USER        = "replicator"
KEY         = "/home/replicator/.ssh/replicator_key"
SLOT        = "my_slot"
PUBLICATION = "my_publication"


def get_connection():
    # A new token on every call: tokens are single-use.
    return connect_replication(key_path=KEY, host=PUBLISHER, user=USER, dbname=DBNAME)


def main():
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.create_replication_slot(SLOT, output_plugin="pgoutput")
    except psycopg2.errors.DuplicateObject:
        pass
    cur.start_replication(slot_name=SLOT, decode=True,
                          options={"proto_version": "1", "publication_names": PUBLICATION})
    cur.consume_stream(lambda msg: handle(msg))


def handle(msg):
    print(msg.data_start, msg.payload)
    msg.cursor.send_feedback(flush_lsn=msg.data_start)


if __name__ == "__main__":
    main()
```

Reconnect by calling `get_connection()` again. For physical replication pass
`replication=True`; see [Python](python.md#replication-connections).

## Check that it is running

On the publisher:

```sql
SELECT slot_name, active, restart_lsn FROM pg_replication_slots;
SELECT usename, client_addr, state, sent_lsn FROM pg_stat_replication;
```

Authentication failures appear in the publisher's PostgreSQL log as
`PAM authentication failed for user "replicator"` and in the system journal
with the module's reason; see [Troubleshooting](troubleshooting.md).
