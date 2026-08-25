# 2026-08-25 — R-006 prefix and native CSP closeout

## Outcome

The long-running R-006 capture now has an independently replayed,
append-compatible complete-block prefix receipt. It validates all 1,754
retained attempts, scores 1,600 attempts in 24 complete cells across three
workloads, and reports zero failed attempts. Every scored attempt has complete
exact-work disclosure and every same-cell disclosure is deterministic.

The honest result is `NO_VERDICT`: the A/A calibration gate does not close,
there are no qualifying workloads, and the dominant Poseidon2 block is
incomplete. The receipt is not an M7 promotion receipt. The original capture
remains safely resumable with 326 planned attempts unexecuted; completing them
is optional evidence collection, not a prerequisite for preserving or
replaying the result already obtained.

The native old-versus-current CSP cohort is also complete. It ran all 16
canonical cases twice per arm, producing 64 independently admitted captures.
Every proof and fresh verification passed, and both required ECDSA negative
fixtures rejected. The current arm was the clean typed-AIR checkout at
`2f1a5227…0ca`; the old commit `b6c4f632…6fab` was used only as the frozen
benchmark denominator. Recursion was explicitly disabled in both arms.

Power remained on Battery Power and the execution preflight also narrowly
exceeded the load threshold. The operator-authorized cohort is therefore
descriptive, not a publishable performance claim. No cross-workload average is
reported. Per-case medians show the current prover faster in 7/16 cases,
slower in 9/16, with smaller proofs in 8/16 and lower peak RSS in 6/16.

## Evidence identities

- checked closeout receipt:
  `artifacts/r006-csp-closeout-v1/receipt-v1.json`;
- R-006 reduction file SHA-256:
  `c83de5c5da9bfd138a3f8e9b898651a78564c82d312c1e18293f4245bb02959d`;
- R-006 independent validation file SHA-256:
  `de9236d31e3581f2d12797306d4b7442ce8891187777451ddacae43afc8f7d83`;
- CSP report SHA-256:
  `03bad5358a4f830b4a50eb17ff4886ce8c1746ea987167617ab6dc1e8f36badb`;
- CSP internal report seal:
  `627aeccf0943d46333063b86f120b151d13076b323c512bdee87975f7d34dd47`.

The raw evidence roots are recorded in the checked receipt. They are external
operator artifacts, not repository source and not silently promoted into a
normative performance claim.

## Old-authority cleanup

The current CSP registry parser now admits the versioned `guest_profiles`
authority emitted by the typed-AIR product while retaining explicit support
for the historical aggregate registry used only by the baseline arm. The CSP
benchmark command's final oversized-file exception was removed by moving its
terminal report projection into the focused validation module. Strict
`active_native_backend` source conformance now reports zero explained legacy
findings and zero new violations.

Historical receipts and the old CSP commit remain immutable evidence. They are
not imported by, selected by, or treated as authority for the current product
path.
