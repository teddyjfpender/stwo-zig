# Authenticated BLAKE3 byte routing — 2026-09-21

Previous turn: progress on shared framing and a public-child node proof. This
turn constrains unaligned private digest routing and composes both child hashes
with their Merkle parent inside a complete CPU STARK. Production migration and
the original recursion performance goal remain active.

## Typed routing

`blake3_byte_route.zig` has 12 main columns, 45 fixed columns, four degree-two
roots and three recursion-wire events in two interaction batches. Each output
word selects bytes from at most two authenticated source words or fixed byte
constants. A fixed 4-by-8 selection matrix supplies the affine byte map. Fixed
source endpoints and enable weights control two consumes; the destination emits
with its canonical hash-graph use count. Padding is zero and satisfies the AIR.
No new relation registry schema or handwritten evaluator was introduced.
Semantic digest:
`5deae0f0745922a26429f79804263c6c365d7ce4a8c4f418c72d31b3a42ba178`.

The canonical frame writer now optionally reports digest roles to symbolic
sinks. Native hash/buffer sinks still receive identical bytes. The node-routing
compiler uses this same writer to derive literal bytes and left/right digest
references, avoiding a second transcription of prefix lengths or payload order.
The compiler deduplicates source words within a destination row and counts every
actual consumer. Producer root-output multiplicities use these counts: a word
spanning two destination words must be emitted twice, not once.

## Complete proof

The final routed proof uses the native commitment framing at all three nodes:
two public M31 leaf-value arrays produce two witness-only leaf digests, then the
routing AIR places their bytes after the canonical node prefix. The parent hash
consumes those routed words. Its expected root comes from the native Merkle
hasher. Trusted preprocessing reconstructs leaf frames, structural hash graphs,
routing selectors and use counts from the public values and final root without
computing or receiving the intermediate leaf digests. The two intermediate
public digest boundaries are removed.

This is a two-leaf commitment-tree proof, not yet a production child-proof
adapter or a general recursive Merkle authentication path. Witness-only here
means outside the public statement, not a zero-knowledge claim.

## Verification

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-byte-route test-blake3-routed-proof test-blake3-protocol -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-routed-proof -Doptimize=ReleaseSafe --summary all
```

The first command passes eight guarded tests: typed semantic/export checks,
selected source/output/constant/selector mutation rejection, canonical frame
byte parity including high bits and final zero padding, routed parent proof,
and unchanged independent native protocol vectors/PCS-FRI checks. The second
command strengthens the routed proof's child messages to actual native leaf
frames. Its final result is in routed-leaf-proof.log.

Initial routed proof runtime was about 3 seconds, maximum RSS 347 MiB; routing
unit tests took 945 ms. These are test-loop diagnostics. Proof parameters remain
eight queries, blowup 1 and zero PoW, not a production benchmark or security
qualification. No production speedup is claimed.

Next: production child-proof source admission; general Merkle paths and scheduled
transcript routing; challenge rejection/PoW constraints; new trusted key/artifact
identities; Metal and same-security parent-of-parent qualification. Product
defaults remain Poseidon. Source conformance retains the same 103 existing
finding identities, with no new ones; older evidence snapshots are unchanged.
