# Q193 hostile native Tree-0 checkpoint

This is a local G-8(a) checkpoint, **not** a final-revision qualification
record. It was produced from the uncommitted recursion worktree based on
`cb9c11309955ad66eef7d053d4b22fa758c2cbd9`. The test-only native hook
changed an unused bitwise-table tuple before commitment, then re-proved the
native segment at 193 queries and 16 PCS PoW bits. The ordinary native verifier
rejected its noncanonical Tree 0; a test-only capture adapter accepted the
remaining AIR/PCS/FRI checks. Outer proving produced the retained candidate.

The test verified the 2,483,181-byte outer proof under the candidate's
self-pinned key without canonical native-root admission. The ordinary
standalone leaf verifier then rejected that same candidate with
`InvalidNativePreprocessedCommitment`, both with `proof.bin` present and with
it absent. The latter establishes that the rejection occurs before proof I/O.
All input and verifier hashes are in `gate/report.json`; the two verifier logs
and the native test log are retained beside it. The native statement JSON is
an explicit geometry/authority projection; its public wire is
`candidate/expected-wire.json`.

To regenerate from the current source, create a new output directory and run
`test-segment-v2-hostile-tree0-q193` with
`STWO_RISCV_HOSTILE_TREE0_EXPORT_DIR` set to a new `candidate` path. Then run
`scripts/riscv_segment_v2_hostile_tree0_gate.py` with that bundle, the key and
verifier SHA-256 pins, the test log, and a new report directory. A final G-8
record must be regenerated after the identity batch is committed and paired
with the other G-1–G-10 records at one source revision.
