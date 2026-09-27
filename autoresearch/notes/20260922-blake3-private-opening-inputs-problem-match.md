# Private authenticated trace and FRI opening values

Previous turn: progress; samples private across all consumers, queried trace and
FRI opening values still public. Task: remove leaf payload and arithmetic anchors
by sharing actual scalar wires. Reuse scalar_wire_source for literal zero extension,
field_bytes for canonical encoding, fri_hash_wire_plan for exact FRI bindings and
qm31_pack_wire for secure reconstruction. No AIR equation/identity changes.

Trace query nodes derive from canonical DEEP bindings. Repeated projected rows
share a canonical scalar producer, with routed per-query consumers and exact use
counts. FRI coordinates derive from the canonical FRI plan; scalar producers feed
arithmetic and pack, which feeds encoding and complete subtree authentication.
No guessed node offsets. Deterministic insertion order defines canonical IDs.
Reject missing/duplicate bindings and inconsistent aliases. Keep private sibling
sources and root checks. Complexity linear in input inventory plus hash-map work.

Validate the entire joined parent and existing arithmetic regression, including
independent preprocessing. Add exact wire-accounting negative checks at the input
boundary where practical. Query routing, public challenges/roots and fixed attempt
schedules remain outside this step. Production keys, CPU/Metal and parent-of-parent
are still required. No speed claim; use serialized focused builds only.
