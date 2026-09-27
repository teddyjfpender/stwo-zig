---
title: BLAKE3 typed private input bridge and message-free preprocessing
author: Teddy Pender
created_utc: 2026-09-21T19:38:22Z
---

# Private BLAKE3 input binding — 2026-09-21

Previous turn: progress, including full public-message hash STARKs. This turn
adds a typed copy bridge and witness projection for private caller words. The
production migration and original recursion performance goal remain active.

The new `blake3_input_bridge.zig` has four main byte columns, ten fixed columns,
four degree-two unused-byte constraints, and two recursion-wire events in one
interaction batch. It consumes one caller tuple and emits identical byte
coordinates into the BLAKE3 graph with its canonical use count. Both namespaces,
wire IDs, multiplicity, and partial-word zero selectors are fixed schedule data.
Semantic digest:
`1de95d16ebc1bf0a3eec04a2ae2fd423e4a3609d18ef1aa63096d609738dc4da`.

`blake3_private_hash_witness.zig` replaces public input boundary rows with these
bridges. Constants and final digest retain existing public boundaries. Trusted
preprocessing takes only length, caller wire range, hash namespace and digest;
it never receives message bytes or evaluates private hash rounds. Caller words
are four little-endian bytes, and high bytes of a final partial word must be
zero. Source and destination namespaces must differ; checked wire bounds prevent
field aliases. This is contiguous word routing, not arbitrary byte repacking.

Eight focused tests pass across private-input, hash-graph and existing real-proof
targets. The three private-input tests check:

- Typed semantic pin, direct compiler and committed framework export.
- Zero-padding constraints for all partial-word lengths and full 32-bit values.
- Message-free preprocessing against a live 65-byte witness.
- Exact global wire closure with independent caller emissions, and failure when
  caller emissions are omitted or byte, enable, source/destination namespace,
  wire ID or multiplicity is changed.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-private-input test-blake3-hash test-blake3-proof -Doptimize=ReleaseSafe --summary all
```

Private-input tests ran in 544 ms, hash-graph tests in 892 ms, and the existing
compression/public-hash proof tests in 9 seconds. These are dev-loop diagnostics,
not performance claims. The public-hash proof parameters remain test-only:
eight queries, blowup 1 and zero PoW.

Qualification boundary: the new bridge has NOT yet been included in a complete
STARK or authenticated to a production child-proof source. The exact closure
test uses explicit upstream fixture emissions; no host witness is treated as
caller authentication. Next is committed private hash composition, followed by
real recursive caller adapters, transcript framing/rejection/PoW, Merkle paths,
new trusted protocol/key/artifact identities and CPU/Metal qualification.
Production still selects Poseidon.

Formatting and diff checks pass. Source conformance remains at the same 103
pre-existing finding identities. Earlier evidence snapshots were not modified.
