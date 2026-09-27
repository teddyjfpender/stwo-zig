# BLAKE3 compression wiring — 2026-09-21

Prior turn classification: progress (compact typed arithmetic and mutation
checks). Current turn connects that arithmetic to the complete compression
word graph and canonical table accounting; production recursion remains on
Poseidon and the wider goal remains active.

Implemented:

- Fixed single-assignment topology: 32 initial state/message words, 56 G calls
  creating 224 words, then 16 feedforward XORs. Total 272 wire IDs. Output
  multiplicities include every consumer and the final output boundary.
- Typed G call component: 124 main + 16 fixed inputs, 80 arithmetic roots,
  66 relation events (56 table requests, 6 wire consumes, 4 wire emits).
  Semantic digest:
  `a52ac45d3419725438c11005ca5847e92ac73731d6368804389bd4dad86b4945`.
- Typed XOR call component: 12 main + 6 fixed inputs, no algebraic roots,
  seven relation events (four bitwise requests and three wire endpoints).
  Semantic digest:
  `46f94e6dd6cfca03e0995cdd905f95f9bedc3aa477b47c38c9474f0a3f47405e`.
- Both compile through existing universal_relation_binding; no second tuple
  compiler or frozen relation-registry mutation. Each word's four coordinates
  are bounded bytes, preserving all 32 bits.
- Compression witness writer fills 56 G and 16 XOR logical rows, checks each
  native input against the planned source wire, and checks final feedforward
  against the native compression output.
- Compact arithmetic can predeclare its physical input prefix for the existing
  relation compiler. It discovers input types from the pinned definition and
  reuses the same arithmetic author. The compiler itself is unchanged.
- BLAKE3 targets moved out of the large segment build file into
  `src/integrations/riscv_cpu/build_blake3_steps.zig`.

Validation: six focused guarded tests pass across wiring and packed targets;
4-second compilation for each, wiring tests ~1 second, packed tests 518 ms.
The wiring gate authenticates both typed plans, checks degree, evaluates all
ordered G arithmetic constraints, proves exact signed wire multiset closure,
and rejects changed namespace, wire ID, byte coordinate, or multiplicity.

For table accounting, the gate passes all 3200 lookup requests through the real
production `tables.Counter.registerRaw` and uses canonical `schema.tupleAt`
rows for balancing contributions. The combined wire/byte/XOR multiset is
exactly zero. Changing a provider multiplicity makes it nonzero. This tests
canonical table indexing and counters, not just test-local membership formulas.
The generic bitwise provider's actual domain is 2^18 rows (operations included),
while the byte-pair provider is 2^16; a complete proof must include that cost.
Allocation-failure injection verifies all partial call-definition owners unwind.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-wiring test-blake3-packed -Doptimize=ReleaseSafe --summary all
```

Qualification boundary: exact multiset closure is not a committed STARK proof.
Input and output boundary contributions in this gate are explicit trusted test
fixtures. The production verifier still needs to authenticate the fixed plan,
initialization (CV, IV, counters, length, flags, message), digest boundary and
provider commitments. The Prepared witness is not an admission token. G padding
retains valid zero-valued table requests; its wire weights are controlled by the
fixed columns, so table accounting must include padded requests.

Next: export these typed components through the committed framework, construct
provider multiplicity/interaction traces and authenticate boundary statements,
then prove and independently verify a complete compression. Follow with full
BLAKE3 block/chunk framing, recursive transcript/Merkle integration, versioned
keys and CPU/Metal qualification. No complete recursive speedup is claimed.

Source conformance remains at 103 pre-existing finding identities; it is not
green. Formatting and `git diff --check` pass.
