# Complete bounded v7 mixed root

The production assembly joins original verifier rows before proving one parent. Standalone native, caller, ROM, compact lookup and joint-memory parent proofs are qualification fixtures; they are not intermediate stages required by the complete path.

```
actual execution originals                         independent admission
  native segments                                  ELF bytes + hash + profile
  SHA/Keccak/recovery caller sources                completion + output + config
  decoded ROM                                      exact original epoch roster
  compact lookup                                   original physical claims (public proposals)
  joint RAM/initialization/range/terminal                      |
       | original verification + capture                       |
       | exact verifier rows                         original equations + geometry
       v                                                       v
  canonical typed frames ---------------------------> independent fixed rows/key
       |                                                       |
       +-- namespace rebasing -- one drain join                |
                            |                                  |
                   one mixed parent STARK                      |
                            |                                  |
                            +---- fresh detached verifier <----+
                                       |
                        independently rebuild all public frames
                        verify parent under expected key/schedule
                        reconstruct ELF/windows/fixed roots
                        close all original typed relations
                                       |
                             one execution-root receipt
```

`block_v7_mixed_inputs_v1` reconstructs every public frame from the appropriate original profile. It requires exact canonical family/index order, shared epoch and complete roster. It never trusts serialized offsets or a producer's success receipt. Each expected entry includes the original family, index, identity and first roots. Public-wire schedules remain explicit and bind every consumed original operand.

`block_v7_global_public_closure_v1.closePublic` is deliberately not proof authority. The complete receiver calls it only after authenticating the canonical frames with the parent equation. Its checks preserve the original execution receiver's obligations:

- Reconstruct initial intervals and the full decoded ROM from independent ELF bytes and hash; bind execution profile, initial registers and PC.
- Admit contiguous execution windows, external retirement counts and caller-to-native identities; preserve state/register compensation per window, not just one aggregate.
- Require exact caller arithmetic/fused residuals, ordinary-memory and auxiliary-clock closure, fetch counts, RAM event counts, and all six lookup claims independently.
- Derive lookup demand from the actual native/caller statements; admit exact program census and table geometry.
- Rebuild native, caller, ROM, compact lookup and joint-memory fixed roots. Bind memory initialization, first-halt constraints, final cycle and terminal public output through the original policy and equations.
- Close program fetches, RAM transitions, initialization/link/range/terminal claims and integer census only after those operands are authenticated.

The final receiver accepts root bytes, independently selected metadata, key and wire schedule. It has no original-proof, trace or capture parameter. Public metadata remains O(original roster); the implementation does not claim a constant-size statement. The current direct root admits at most 64 original children. Larger/canonical workloads require bounded batches and a qualified reduction path; a successful small diagnostic root does not qualify Ethereum throughput or canonical security.

## Qualification

The genuine two-segment SHA + Keccak path passed all 11 tests on 29 October
2026: six originals, one 161,305-byte root, fresh detached verification and
complete global closure. Diagnostic q8/PoW0 only. Exact evidence and timing
scope: [complete-root receipt](performance/v7-complete-root-qualification-20261029.md).

Cold and live compilation partition each child G cohort before namespace
rebasing and joining. This order is part of the physical key geometry; final
partitioning alone is not equivalent when a child already exceeds the shard
threshold. The complete gate compares every fixed row and public wire.
