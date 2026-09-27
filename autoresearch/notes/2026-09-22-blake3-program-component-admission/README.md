# BLAKE3 program components and commitment-plan admission

Decoded program tuples now feed four scalar wires, the existing canonical
field-byte encoder and four BLAKE3 field paths. The typed program boundary uses
the exact program-access schema (PC plus four fields). Request weights are
negative multiplicities so their interaction numerators retain the existing
positive provider sign. The pinned AIR identity is
9c210270e637dc55090e0f06e16e4127bc58e3acd0d04c436a67b5fe0c9fdd16.

The prover witness now owns program schedules alongside memory schedules.
A shared ten-component roster emits live or independent trusted rows to a sink
with one word workspace live at a time. Verifier preprocessing requires an
admitted plan, with full roots, schedules and typed roster identities bound to
a versioned BLAKE3 identity. Plan validation enforces disjoint canonical
namespaces, address order, root agreement and zero initial ordinary clocks.
Admission revalidates the identity and rejects mutated schedules/public roots.
This is component-plan admission, not a complete PCS verification key.

The focused ReleaseSafe gate passed (36 s, 1 GiB), including exact program
multiplicity, canonical negative-field wire closure, substitution rejection,
live/trusted fixed-column equality, complete memory/program emission counts,
plan tampering, explicit fixed-PC lowering and default PC rejection. The first
checks caught registry-role/type and request-sign mistakes; these were corrected
before the passing run. No full joined execution STARK is claimed by this gate.

Still required: production component placement and proof orchestration, complete
PCS key/artifact admission, whole execution-relation closure, continuation
source/claims and production multi-level recursion. Defaults remain unchanged.
