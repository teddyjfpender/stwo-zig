# Explicit q70/PoW26 BLAKE3 parent profile

The execution-parent key admits two exact PCS profiles: the existing diagnostic
q8/PoW0 profile and explicit `csp_q70_pow26`. The latter uses 70 FRI queries,
26 PoW bits, log blowup 1, last-layer bound 0, fold step 1 and no lifting override.
`deriveKeyWithProfile` derives the preprocessing commitment under the selected
configuration. Existing `deriveKey` retains the diagnostic default.

Profile and complete configuration were already transcript/key inputs. Adding a
new profile tag preserves existing version-3 diagnostic encodings and gives the
70/26 profile a distinct identity. A profile/config mismatch rejects; lowering
queries or PoW, relabeling the profile, or substituting lifting presence cannot
silently reuse an admitted key. Artifact decoding also requires the externally
admitted key and its exact PCS configuration.

## Qualification

Command:
`python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments -Driscv-test-filter='BLAKE3 execution commitment real runner' -Doptimize=ReleaseSafe --summary all`

Passed: 3 minutes build/test, 5 GiB peak RSS. The q70/PoW26 artifact is
738,033 bytes. Recursive transcript emission produces 39,704 G rows and matches
the verified channel digest/draw counter. Successful worker rekey and verification
after worker destruction pass. The log explicitly records child q8/PoW0.

The real execution fixture retains its existing Span/custody and two diagnostic
recursive proofs. Its prepared parent is additionally proved at q70/PoW26, then
independently verified both directly and after artifact roundtrip. The persistent
worker successfully replaces its diagnostic plan with the admitted 70/26 plan,
retains its two-worker pool, and is destroyed before output verification. The
original capture retains its allocation lease. A diagnostic key cannot decode
the new artifact. Query count and PoW configuration are checked explicitly.

The canonical bounded transcript planner replays the verified 70/26 capture,
including PoW and all queries, and emits its hash witness. Its final digest and
draw counter must match independent verification.

This qualifies the parent's PCS profile and replay only. Its child remains
q8/PoW0: the stronger parent does not upgrade child soundness. It is not a fully
70/26 recursive chain, a new parent-of-70/26 STARK, production key approval,
Metal qualification, default promotion or an end-to-end performance claim.
The separately reviewed larger-domain/fewer-query experiment in the original
goal remains unperformed; this change does not relax production parameters.
