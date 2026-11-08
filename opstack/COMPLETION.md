# OP Stack CPU delivery gates

Updated 2026-11-08. This is the completion checklist for PR #322, not a claim
that the unchecked gates already work. Receipts, source and fresh receivers
are the authority. Historical plans in `DESIGN.md` and the feasibility study
predate the anchored transition implementation.

The functional comparison is ZisK's OP flow: execution ranges, authenticated
L1 derivation, execution/derivation binding, an accumulating recursive proof,
and settlement. Its dashboard describes a SNARK wrap. Our chosen settlement
route remains a direct STARK verifier. CPU qualification comes first; GPU
latency figures are not CPU acceptance criteria.

| Gate | Evidence at the starting head `5b7d3ffbd` | Required closure |
| --- | --- | --- |
| Kona execution | Six historical OP Mainnet execution agreements; complete native execution bundles exist | Reproduce complete bundles and independent acceptance on this machine, preserving full output and corruption checks |
| Anchored derivation | Native and RV64 accept transition 159257841 → 159257842; KZG/anchor/root mutations reject | Complete physical STARK proof of the anchored transition with independently pinned OD output |
| Capacity and continuity | Fastest retained replay needs at least 733 CPU proofs before services; native cap is 256 | A reviewed versioned segmented construction binding PC, registers, clocks, memory, service spans and the final output; no unversioned cap increase |
| Recursive closure | Native execution wrap reached outer FIXED commitment, then failed under a 6 GiB requested-live cap | Complete leaf/fold/root generation, bounded memory, and fresh recursive reception on real OP execution and derivation |
| Joined statement | Receiver-side OD/OP join exists; synthetic ordered fold admission exists | An actual recursive root authenticating both matching programs, exact outputs, order and complete native closure |
| Accumulator | No complete running OP checkpoint accumulator receipt | Adjacent checkpoint folds with rejection of gaps, overlaps, swapped branches and substituted anchors |
| Settlement | Real native PCS pieces replay locally; one worker costs ~1.72 billion gas | Compact STARK plus complete checkpoint verifier under actual chain transaction constraints, with independently established program/input authority |
| Security | Conjectured-128 native profile, explicitly unqualified; recursion separate | Bounded composed accounting for the actual native, segmentation, recursive and settlement construction under documented assumptions |
| Regression hygiene | OP guest/tooling is separate; shared native engine is reused | Keep Ethereum proof formats/defaults stable unless separately versioned and qualified; exercise shared regressions for every shared-engine change |

## Working rules

The [CPU continuation receipt](../vectors/reports/rv64-opstack-cpu-20261108/README.md)
reproduces complete execution bundles for 120794432 and 121057303 with fresh
receivers and both corruption controls. The synthetic OD/OP child/parent fold
also completes with physical STARK verification. These close the local execution
reproduction and synthetic-fold checks, not anchored transition or real-root
acceptance.

- Replay is not a proof. A native bundle is not a recursive root. A receiver-side
  join is not an in-circuit join. A PCS replay is not a complete checkpoint verifier.
- Do not raise the 256-proof, trace-log or characteristic limits to bypass
  admission. A changed construction needs its own identity and bounded review.
- Canonical anchor/finality selection remains external verifier policy; the
  derivation guest proves ancestry from that independently selected anchor.
- Keep OP changes under `opstack/` and `settlement/` where possible. Shared
  fixes must justify their Ethereum impact and retain protocol parity evidence.
- Measure complete CPU requests separately from compile time. Record geometry,
  profiles, workers, wall/user/system time, per-child peak RSS and failure status.
  RSS uses Darwin bytes or Linux KiB converted to bytes. Requested-live budgets
  are admissions, not RSS caps; retained immutable setup is accounted separately.
- Retain exact ELF/input identities and portable reproduction instructions.
  Scratch paths in old receipts do not establish that the files still exist.

## Reproduction inputs

The execution corpus is publicly retrievable with the hash-pinned
`mainnet.py` importer. The anchored transition archives named in `TRANSITION.md`
are not in Git and were not found in this checkout or local artifact store.
Their location is needed for physical replay of the same transition. Until
recovered, keep the transition gate open; do not replace it with a synthetic
case or call an execution-only proof an OP validity proof.
