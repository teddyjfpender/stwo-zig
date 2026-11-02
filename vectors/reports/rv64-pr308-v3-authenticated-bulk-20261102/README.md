# Authenticated bulk v3 GKR foundation

This slice splits the existing nine-kind bulk tuple authority into local
OWNER/U16 and global RAM consumers, adds the physical OM31 bulk component,
durable metadata retirement, and versioned local-child receiver framing.

Production v3 admission remains closed. These are component and framing
qualifications, not an accepted full v3 GKR block, speedup, or new security claim.
The design note lists the remaining worker, closure and security gates:
[rv64-v3-authenticated-bulk-gkr.md](../../../design/riscv-proving-stack/rv64-v3-authenticated-bulk-gkr.md).

Focused checks and classic-block parity are recorded alongside this file.
Raw proof artifacts stay in scratch; committed receipts retain their identities.

Results:

- Focused services-GKR and bulk suites pass in ReleaseSafe and ReleaseFast;
  both Ethereum drivers build in ReleaseFast.
- All nine projections match classic fractions, including padding, and fit
  degree-three binding/global residuals over full OM31 sample lines.
- Honest physical bulk proof freshly verifies after MAIN/fixed retirement,
  with nonzero RAM debt. Four retained invalid physical proofs (MAIN, target,
  Eq, prefix) each reject with `OodsNotMatching` at fresh receivers. Altering
  the published RAM claim also rejects.
- Child framing rejects changed role, height, term count, offsets, order and
  v2/v3 wire replay. These tests do not admit a whole v3 roster.
- The complete classic v3 block re-proves and freshly verifies; all15 artifact
  hashes match the committed reference. The complete v2 GKR bundle freshly
  verifies unchanged. The real v3 GKR request still rejects.

Scratch reproduction inputs are under
`/private/tmp/stwo-rv64-pr308-guest-artifacts`: `request-v3-24628607.json`,
`native-v3-24628607/jobs`; output `classic-v3-bulk-authority-parity-24628607`.
The full classic command uses `produce REQUEST JOBS OUT 0 --proof-jobs=2
--lane-workers=8,8 --proof-memory-cap=38654705664 --commit-batch-columns=64
--park-retained-main`, followed by `verify REQUEST OUT`. The legacy GKR check
uses `verify-candidate request-v2-24628607.json gkr-v2-full-24628607 12884901888`.
The qualification JSON records binary hashes, source hashes and artifact
identities. Timings from this correctness run are not a new benchmark.
