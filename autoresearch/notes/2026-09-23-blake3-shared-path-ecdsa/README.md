# Shared-path full-width BLAKE3 ECDSA qualification

Canonical CSP ECDSA input, pinned odd-parity precompile ELF, 70 queries / 26 PoW
bits, 16 workers, one sample / zero warmups. Dirty ReleaseSafe builds; compilation
of other qualification targets overlapped these runs. These are functionality and
resource qualifications, NOT the clean ReleaseFast CSP performance suite.

| Backend | Execution through fresh verification | Tracked host allocation peak | Artifact bytes |
| --- | ---: | ---: | ---: |
| CPU | 18.414376375 s | 3,384,009,196 | 3,782,051 |
| Metal | 18.742173083 s | 3,061,590,428 | 3,782,051 |

Serialized STARK payload: 3,740,508 bytes. CPU and Metal artifact hashes,
statements and transcripts are identical. Fresh CPU/Metal cross-verifiers passed;
Metal verification passed with an absent AOT bundle. The verifier enforces the
actual input/ELF, caller-supplied statement pin, one signer call, zero Keccak calls,
halt completion and exact 32-byte CSP success output. Metal proof telemetry was
1730 dispatches / 233 CPU fallbacks; this is hybrid execution.

## Structural result

The same 1,828-step execution and 303 memory / 404 program words now use 8,738
BLAKE3 compression blocks, down from 172,508. G rows fell from 9,660,448 to 489,328
(19.74x fewer); padded G domain fell from 2^24 to 2^19. Witness live host allocations
fell from 10,971,429,417 to 438,024,745 bytes. The preceding 36 GiB bounded proof
failed, whereas both shared-path proofs completed within that same limit.
These row and allocation ratios are not an end-to-end speedup measurement.

## Implementation and admission

A deterministic sparse topology is derived separately for program, initial and
final roots. Existing typed G/XOR, routing, private-digest and input-bridge AIRs
hash each shared ancestor once. Computed children feed exact parent fanout;
frontier digests are range-checked private sources; only roots retain public
output sinks. One hash node's row workspace is emitted at a time. Verifier
preprocessing derives identical columns from authenticated schedules, without
snapshot bytes. The previous per-word emission helpers are removed.

Commitment-plan identity and codec version are now 2. Version 1 independent-path
plans are rejected; old experimental artifacts are not silently reinterpreted.
Tree hash framing, roots and canonical PCS parameters are unchanged.

## Checks

- Shared column integration and padded interaction/reference parity passed.
- Program/frontier mutations break wire closure; fixed columns match independent
  trusted emission; wrong roots and independent-path codec version are rejected.
- Real base proof/artifact verification, recursive parent and parent-of-parent
  passed. Its canonical parent used 70/26 with diagnostic 8/0 children.
- CPU and Metal product builds passed; actual canonical ECDSA and cross-verification
  passed as above.
- Full canonical Ethereum leaf/parent gate is currently running separately.

Defaults, remaining prover-owned Poseidon cleanup, full current CSP suite timings,
and the broader recursion performance objective remain unfinished.

Process-lifetime physical footprint (separate from bounded host allocations): CPU 3,586,510,952 bytes (3.340 GiB), Metal 5,388,096,192 bytes (5.018 GiB). The retained CSP CLI also rejects wrong statement pin, input, ELF and mutated proof; see the negative-result JSON.


## Canonical recursion qualification completed

The CPU Ethereum leaf and parent both passed 70 queries / 26 PoW bits. Fresh
parent verification succeeded after worker and prepared rows were destroyed;
leaf artifact roundtrip and capture-mutation rejections also passed. Parent
artifact: 907,299 bytes; prepared rows: 5,899,803,296 bytes; tracked worker peak:
32,402,522,298 bytes within a 38,654,705,664-byte limit. The wrapper took 9 minutes
including compilation and test work; this is not isolated parent proving latency.
This does not establish a 10x recursion speedup or requalify the canonical Metal
parent with the new layout.

A single live stack sample found the parent in sampled-value opening, constructing
barycentric weights after opting out of coefficient retention. Retained as a
specific profiling lead for the original recursion-performance goal, not a full
phase attribution. Default promotion, guest Poseidon adapter migration, legacy
prover path cleanup and new clean ReleaseFast CSP suite timings remain open.
