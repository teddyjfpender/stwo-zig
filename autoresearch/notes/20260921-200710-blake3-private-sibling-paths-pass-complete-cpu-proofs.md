---
title: BLAKE3 private sibling paths pass complete CPU proofs
author: Teddy Pender
created_utc: 2026-09-21T20:07:10Z
---

# BLAKE3 paths with private siblings — 2026-09-22

Previous turn: progress, including a native-framed two-leaf tree proof. This
turn implements binary authentication paths with private sibling digests and
verifies complete CPU proofs. The production migration and original recursion
performance goal remain active.

`blake3_merkle_path_witness.zig` owns preparation in one arena and derives fixed
routing from a public statement: namespace, leaf values, index, depth and root.
It hashes the canonical leaf frame, folds low index bits bottom-up to order each
current/sibling pair, and routes each canonical parent frame through the existing
byte-selection AIR. Namespaces are disjoint and checked against M31 capacity;
index range and sibling count must match depth. Zero depth is supported.

Trusted preprocessing receives no sibling bytes and does not compute the path's
intermediate digests. It reconstructs source multiplicities, fixed routes and
hash schedules. Each private sibling is introduced by the new typed bounded-word
source, then authenticated by the path reaching the public root. It is not
misrepresented as a child with a known preimage.

The word source has four byte main columns, four fixed columns, no direct roots,
and three relation events: one wire emission and two byte-pair range requests.
Its semantic digest is:
`8dbfba49958aac1df9478d41f2aa812e764eecd3921b4124e81b3733a27e99db`.
Both range requests use the existing production table. No new registry schema
or handwritten evaluator was introduced.

Validation:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-path test-blake3-path-proof -Doptimize=ReleaseSafe --summary all
```

Three guarded tests pass:

- Typed semantic/compiler/export qualification; a byte value of 256 is rejected
  by the actual range schema.
- All four positions in a native four-leaf tree reach the expected root, both
  directions are covered, and fixed columns match sibling-free reconstruction.
  Changing a sibling changes the computed root. Index/sibling-count mismatch is
  rejected. Zero-depth behavior and every backing allocation failure are checked.
- Real BLAKE3 STARK proofs for depth zero and depth two pass the core verifier,
  with private sibling sources, routing, hash components and real providers.
  Changed public root and substituted preprocessing root fail trusted admission.

Witness tests ran in 616 ms; the two complete proofs took about 6 seconds total,
maximum RSS 350 MiB. These are development-loop diagnostics with eight queries,
blowup 1 and zero PoW, not production performance or security qualification.
Witness-only means outside the public statement, not a zero-knowledge claim.

Remaining production obligations: query-index binding to constrained Fiat–Shamir
challenges, lifted PCS/FRI path geometry and batching, actual child-proof source
admission, transcript challenge rejection and PoW, new trusted key/artifact
identities, Metal and same-security parent-of-parent qualification. A public-index
path gate does not discharge the challenge-derived index requirement. Product
defaults remain Poseidon.

Source conformance remains at 103 pre-existing finding identities. Formatting and
diff checks pass. Evidence/source hashes are pinned without changing older runs.
