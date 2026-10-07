# S31 hash and commitment functions

The implemented library has three BLAKE2s nodes, two pinned M31 Poseidon2 nodes, and a constrained array selector. Every build emits a native verifier. The [language guide](../../../src/frontends/s31/docs/reference/LANGUAGE_AND_AIR.md#hashes-tree-nodes-and-conditional-paths) shows their syntax and row equations. BLAKE2s and Poseidon2 have different digest constructions; the same tree source shape does not make their roots interchangeable.

The limited [text frontend](../../../src/frontends/s31/docs/reference/TEXT_LANGUAGE.md) now wraps these nodes in nominal `Digest<Poseidon2>` and `Digest<Blake2sReduced>` types and a fixed-depth Merkle path function. Its type check rejects cross-family pairing before lowering to the existing JSON relation. These text types add no hash constraints or new proof profile.

## Exact interface

| Node | Message | Domain/framing | Output |
| --- | --- | --- | --- |
| `hash_blake2s` | 4, 8, 12 or 16 canonical M31 words | eight zero bytes | eight reduced M31 words |
| `hash_blake2s_leaf` | 4, 8, 12 or 16 canonical M31 words | `S31LEAF1` | eight reduced M31 words |
| `hash_blake2s_pair` | left digest then right digest, eight M31 words each | `S31PAIR1` | eight reduced M31 words |
| `hash_poseidon2_leaf` | 4, 8, 12 or 16 canonical M31 words | capacity word 15 set to 1; additive rate-8 sponge with end marker 1 | eight canonical M31 words |
| `hash_poseidon2_pair` | ordered left and right digests, eight M31 words each | direct width-16 permutation of `left[0..8] || right[0..8]` | eight canonical M31 words |

Each message word is encoded little endian in four bytes. The 32-byte BLAKE2s output is split into eight little-endian words and reduced separately modulo `2^31-1`. The resulting array is S31's digest type in this normalized JSON language. It is not byte-identical to a BLAKE2s-256 output. The reduced representation has fewer than 256 bits of range; a standalone security analysis of its collision bound and of the tree construction remains open. The leaf and parent domains are distinct, and child order is fixed by the source graph. The [BLAKE2 specification](https://www.blake2.net/blake2_20130129.pdf) defines its eight-byte personalization parameter.

`select` takes equally shaped M31 arrays and an `m31[1]` selector. The circuit constrains `b²-b=0` and `out=(1-b)·lhs+b·rhs` lane by lane. Its host evaluator rejects any value besides zero or one. Two `select` nodes can place a leaf digest on the left or right of a sibling before `hash_blake2s_pair`; [merkle_path1](../../../src/frontends/s31/examples/hashes/merkle_path1.s31.json) demonstrates this. For a static multi-level path, repeat those nodes once per level.

The builder's M31-to-`u32` conversion proves the message encoding, the Blake-G and XOR AIR components prove compression, and the output circuit binds the reduced words to the public root. Personalization changes BLAKE2s initial constants inside the constrained circuit. Every leaf and parent in the current examples is at most 64 bytes, so each uses one compression block. The three-node [merkle2](../../../src/frontends/s31/examples/hashes/merkle2.s31.json) circuit has 240 Blake-G rows; the one-level path has 160 Blake-G rows and two selector Eq rows.

## Field-native Poseidon2 path

S31 uses the repository's [pinned Stark-V constants](../../../src/frontends/riscv/air/memory_commitment/poseidon2_constants.zig), [scalar permutation](../../../src/frontends/riscv/air/memory_commitment/poseidon2.zig), and [Merkle framing](../../../src/frontends/riscv/recursion/poseidon2_channel.zig). The constants file cites Stark-V commit `d478f783055aa0d73a93768a433a3c6c31c91d1c` and has SHA-256 `d02b32f2f5302d21a440fbace2112d3232603e759cd0b24691c32e81d2bd4cfd`. The permutation has width 16, exponent 5, four full rounds, fourteen partial rounds, then four full rounds. The external and internal matrices and all round constants are pinned by that file.

The leaf starts at `(0,…,0,1)` with the tag in capacity word 15. Each canonical input word is added into the next rate word. Each full group of eight words triggers a permutation; an extra marker word `1` is then absorbed, and a final permutation runs if the marker leaves a partial group. The digest is state words 0–7. A parent initializes the state as the left eight digest words followed by the right eight and runs one permutation, returning words 0–7. This is the same framing as the local recursion channel; it is deliberately separate from the BLAKE2s personalization domains.

[`poseidon2.zig`](../../../src/frontends/s31/library/hash/poseidon2.zig) lowers every round to the existing QM31 arithmetic circuit: additions for constants and matrix mixing, and three multiplication gates for each `x⁵` S-box. The direct-M31 proof profile needs only the QM31 operation AIR and eight fixed columns. There is no dedicated Poseidon2 AIR chip yet. In direct mode, a selector must be a directly referenced private or public `m31[1]` input. Its witness wire has exactly one producing gate, `b·b=b`, which enforces `b∈{0,1}`. Two `select` nodes then constrain ordered child placement through `(1-b)·lhs+b·rhs`. The regular full-gate mode retains its Eq-based selector constraint.

The [independent arithmetic oracle](../../../src/frontends/s31/python/poseidon2_oracle.py) implements the permutation and sponge in Python from the pinned constants, including the local `hashPair(1,2)=1975699496` vector. The [Poseidon2 acceptance suite](../../../src/frontends/s31/tests/acceptance/acceptance_poseidon_v6.py) proves and native-verifies all supported leaf lengths (4, 8, 12, 16), independently calculated two-leaf and path roots, both selector values, and malformed source, witness, statement, and proof cases. This demonstrates correctness of the implemented relation and verifier path; a separate cryptographic review is still required before declaring this hash construction suitable for a new production protocol.

The [five-trial matched-shape comparison](../measurements/hash/poseidon-comparison-v6-2026-10-06.json) uses the same private M31 arrays and tree topology for each hash family. Each trial has a distinct valid input and a generated native verifier checks its proof. The different functions produce different public roots and have different cryptographic assumptions; these figures compare implementation cost for the workload shape.

| Workload | Hash/profile | Fixed cells | Median proof | Median prove | Median cold setup |
| --- | --- | ---: | ---: | ---: | ---: |
| Two leaves + parent | BLAKE2s/full gate | 4,255,616 | 464,630 B | 0.553 s | 0.0503 s |
| Two leaves + parent | Poseidon2/direct gate | 131,072 | 164,333 B | 0.0745 s | 0.00159 s |
| One-level private path | BLAKE2s/full gate | 4,255,440 | 471,736 B | 0.480 s | 0.0511 s |
| One-level private path | Poseidon2/direct gate | 65,536 | 136,331 B | 0.123 s | 0.00102 s |

The fixed-cell ratios are 32.5× and 64.9×; proof-size ratios are 2.83× and 3.46×. Median proving ratios in this five-trial sample are 7.42× and 3.91×. Proof-of-work is included and stochastic, so these are observed sample medians, not stable speedup guarantees. Poseidon2 uses more raw arithmetic rows because every round is expanded into generic gates; its lower fixed-table and proof cost comes from avoiding the full bitwise AIR profile. A dedicated hash AIR chip is the next route to reducing those generic rows.

[`generate_merkle_path.py`](../../../src/frontends/s31/tools/generate/generate_merkle_path.py) accepts `--hash poseidon2` for depths 1–16 and computes assignments through the Python oracle. A generated depth-eight path with seed 1 was [built, proved, and native-verified](../measurements/hash/poseidon-depth8-smoke-v6-2026-10-06.json): 23,055 raw arithmetic rows, 32,768 padded rows, 262,144 fixed cells, and a 189,460-byte proof. The one-run proving sample was 0.184 s; it is a scale smoke check, not a timing distribution.

## Evidence and current cost

The Python acceptance oracle uses `hashlib.blake2s(person=...)` and independently computes both example roots. Generated native verifiers accepted the resulting proofs. The suite also proves both valid selector values and rejects an invalid selector, changed private input, changed public root, damaged proof, cross-program proof replay and malformed source shapes. The three-trial [timing record](../measurements/hash/hash-suite-benchmark-v5-2026-10-06.json) uses distinct valid inputs and native verification on every trial. Median proving times were 0.632 s for two leaves plus parent and 0.444 s for one leaf plus parent. Proofs were about 460–472 KB, and both examples used about 4.26 million fixed preprocessed cells. Full-profile proof-of-work is included in those proving times and varies between runs.

[`generate_merkle_path.py`](../../../src/frontends/s31/tools/generate/generate_merkle_path.py) expands a static path of depth 1–16 and independently computes a valid assignment. A generated depth-four path with seed 1 was compiled, proved and accepted by its native verifier: 400 raw Blake-G rows padded to 512, a 472,001-byte proof, 0.053 s cold setup and 0.609 s proving in one smoke run. Those timings are one sample and include variable proof-of-work.

The next efficiency step is a dedicated Poseidon2 AIR chip that batches permutations and shares round constants and matrix columns, while preserving the exact leaf and parent framing above. [Stwo's Poseidon2 example](https://github.com/starkware-libs/stwo/tree/dev/crates/examples/src/poseidon) is an AIR architecture reference; it cannot substitute for this repository's pinned permutation parameters. The S31 direct circuit already gives an exact field-native baseline and generated single-proof native verifier. BLAKE2s still needs a hash-specific sparse component manifest to avoid its full-profile fixed-table cost.

The next library functions should build on these primitives: a first-class fixed-depth Merkle path, a public commitment/opening interface, then a batch-hash chip. General byte strings and external SHA/Keccak digests need distinct typed encodings; silently treating their raw digest words as reduced M31 values would give the wrong statement.
