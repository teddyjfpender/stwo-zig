# Batched sparse-memory frontier extraction

Problem match: ZisK-style witness-generation work reduction, shared by ordinary
BLAKE3 memory commitments rather than selected benchmark cases. The former live
shared-path emitter called `TreeHasher.opening` for every in-range frontier node.
Each call validates and reconstructs the entire sparse source tree, even though
only one sibling digest is retained. Source-root authentication already runs once
before emission and the emitted root is checked again after graph evaluation.

`TreeHasher.subtreeRoots` validates the complete source and all coordinates before
writing any output, locates each subtree's leaf interval by binary search, and
uses the existing canonical traversal on that interval. Empty intervals return
cached default roots. The graph's disjoint frontier means its subtree traversals
do not rehash one another. Input/output root checks, typed AIRs, routing, namespace,
full-width digests, security parameters and proof format remain unchanged.

The emitter retains one 32-byte digest per frontier coordinate while generating
rows. `STWO_RISCV_REPEAT_FRONTIER_OPENINGS=1` selects the preceding implementation
for same-binary controls. This is a small bounded cache, not a claimed memory
reduction or a new hash design. General API callers may request overlapping ranges;
only disjoint frontiers have the no-repeated-subtree-work property.

Focused ReleaseSafe checks pass: empty/nonempty sources, all tree heights, all
three domain kinds, explicit zeros and edge addresses match independent whole-tree
openings; malformed shapes/coordinates/leaves are rejected before output mutation.
The existing execution-commitment integration check passes, including authenticated
column/interaction parity and failure/retry behavior. Logs are retained here.

CPU/Metal ReleaseFast builds passed. `measure.py` compares
control/candidate/candidate/control, three samples per block, zero warmups,
16 workers, 70 queries / 26 PoW bits, including precompiled ECDSA. Exact proof
hashes must match the retained full suite, and every retained artifact is freshly
verified. Profile timers and reports preserve stage and whole-transaction scope.
All 96 timed proofs and 32 retained fresh verifications passed with unchanged
full-suite proof hashes. No substantial CSP E2E improvement was established.

## Results

Medians pool six samples per arm across two blocks; execution order was
control/candidate/candidate/control. These are complete transaction times,
including admission, artifact encoding and fresh verification. Raw profiles,
reports, commands, frozen executables and Metal bundle are retained.

| Workload | CPU control → candidate seconds | Metal control → candidate seconds |
| --- | ---: | ---: |
| ecdsa_secp256k1-32 | 0.962251 → 0.950485 | 1.013951 → 1.009734 |
| sha256-128 | 2.217996 → 2.225670 | 2.136901 → 2.141443 |
| sha256-2048 | 3.914027 → 3.900223 | 3.846354 → 3.854102 |
| keccak-128 | 3.958487 → 3.941130 | 3.798553 → 3.778929 |

The differences are small and do not establish a CSP performance win. Retain the
algorithmic fix for sparse-memory scaling, not as recovery of the old Poseidon
baseline. The allocation cache can slightly increase live memory; no memory
improvement is claimed. No AIR width, hash row or recursive verifier reduction
was implemented by this experiment.

The opt-in ReleaseFast scaling diagnostic uses 64 widely spaced memory words,
whose shared graph has 1284 frontier nodes. Batched extraction took 35083 ns;
repeated independent openings took 253522583 ns. Every extracted digest matched.
This is a single synthetic observation of one operation, not a proof benchmark,
whole-program speedup or hardware-normalized throughput claim. Reproduce with:

```sh
STWO_RISCV_FRONTIER_PROFILE=1 python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments -Driscv-test-filter='BLAKE3 subtree batch' -Doptimize=ReleaseFast --summary all
```

## Next problem match

`blake3_commitment_columns.Owner.interactions` always calls the CPU
`framework_parallel_interaction.generate`, including from Metal execution and
extension proof paths. Existing larger-case profiles put this stage near 0.55 s
on both backends. The device framework already exposes fraction generation and
prefix scans, but its host bridge accepts only the admitted recursive-framework
AOT profile; ordinary native products cannot simply enable it. The next substantial
experiment should add authenticated hash-AIR kernel coverage and final-column
input reuse, then compare complete proofs against the existing CPU interaction
oracle. It must preserve relation ordering, zero-padding requests, denominator
failure behavior and claimed sums. GPU residency/scheduling and fewer circuit
columns remain separate opportunities. The broader objective is unfinished.
