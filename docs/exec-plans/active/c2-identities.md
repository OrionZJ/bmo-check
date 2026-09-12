# C2 — Stable analysis identities

Status: complete on branch `dev`

This step introduces only the identity value objects in `bmo_check_core.identity`.
Existing static and dynamic models still produce route-local IDs; the static
certificate consumer now reaches these identities through the C4/C7 adapter.

## Identity rules

- every identity is a frozen value object with a type-specific prefix and SHA-256
  digest;
- semantic materials use canonical JSON with sorted keys;
- set-like module, marker, target and premise collections are sorted before hashing;
- module paths, traversal order, benchmark labels and Python object addresses are not
  identity inputs;
- module identity binds content hash and role, while binary closure identity also binds
  the executable hash and ABI;
- runtime thread instances bind to a trace identity and tracer instance identifier;
- evidence identity binds category, schema, producer, subject and canonical premises.

## Test coverage

`tests/unit/test_identity.py` checks deterministic construction, order-independent
collections, parent propagation, JSON/string round trips, cross-process stability,
semantic changes and invalid material. It intentionally does not claim that legacy
static or dynamic facts have been converted natively to these IDs.

## Migration boundary

The package exports no analyzer, database, benchmark or CLI imports. C3 uses these IDs
in the typed evidence ledger, and the static certificate bridge replays the translated
IDs. Native producer conversion remains a one-way migration task; this package is not
a second business model.
