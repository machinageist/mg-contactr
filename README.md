# mg-contacts

mg-contacts is the local-first, encrypted contact store for the Geist suite. It owns contact
identity, encrypted contact fields, revisions, audit history, and soft-delete state. It does not
own calendar events, knowledge, source material, or external identity records.

## MVP workflow

The CLI authenticates once per process. A new process starts locked; passphrases are never command
arguments or environment variables.

```text
mg-contacts setup
mg-contacts status
mg-contacts create person-1     # stdin: name, email, phone
mg-contacts read person-1
mg-contacts list
mg-contacts update person-1     # stdin: name, email, phone
mg-contacts delete person-1     # append-only soft delete
```

Create and update read three lines from stdin after the passphrase prompt. Read and list decrypt
only for the authenticated process. A deleted record is retained as encrypted history but omitted
from `list`; attempting to read or mutate it reports a typed error.

The current MVP store is an append-only encrypted JSON-lines file under the XDG data directory.
Contact fields are individually ChaCha20-Poly1305 encrypted with authenticated record/field/privacy
context. Revisions and audit events are persisted with each mutation. The store is private (`0600`)
and its parent directory is private (`0700`). Restart persistence is verified by reopening the key
in a separate process and reading the same store.

## Privacy and authority boundaries

- The user-held key is encrypted at rest with Argon2id and is process-local after authentication.
- Plaintext contact fields are not written to the store, logs, debug output, or CLI arguments.
- Audit entries contain action, actor, timestamp, and provenance—not private contact payloads.
- Privacy classification defaults to sensitive and unindexable; there is no plaintext search index.
- mg-contacts does not automatically remediate, synchronize, publish, or disclose contacts.
- PostgreSQL configuration is validated as local-only and output is redacted; PostgreSQL topology,
  imports, organization records, digests, and cross-application interoperability remain outside
  this MVP slice.

## Configuration

`MG_CONTACTS_DATABASE_URL` and the config file are accepted only when the URL uses localhost,
loopback, or a Unix socket. Credentials are never accepted through CLI arguments. On Linux,
configuration, key, state, and cache paths use descriptor-relative no-follow traversal; insecure
paths fail closed. Other platforms fail closed for secure storage until an equivalent race-safe
implementation exists.
