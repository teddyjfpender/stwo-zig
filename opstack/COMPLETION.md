# OP Stack CPU delivery gates

Updated 2026-11-09. This is the completion checklist for PR #322, not a claim
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
reproduction and synthetic-fold checks. The follow-up [real recursion receipt](../vectors/reports/rv64-opstack-cpu-20261108/real-recursion.json)
also closes an execution-only Mainnet root: three wrapped leaves and two folds,
accepted in a separate receiver process. The [heavy execution root](../vectors/reports/rv64-opstack-cpu-20261108/heavy-recursion-ternary.json)
also closes block 121065789 with 126 leaves and 64 ternary folds, independent
strict acceptance and physical corruption/missing-node rejection. Its 42.3-minute
recursion is a functionality and memory milestone, not a speed target. The
strict receiver still needs all native and recursive proofs. Anchored transition,
joined checkpoint, accumulation and settlement acceptance remain open.
The [selected guest and bounded schedule](../vectors/reports/rv64-opstack-cpu-20261108/heavy-cpu-scheduling-and-guest.json)
also complete the heavy block's native proof with 91 CPU and 24 service proofs.
The subsequent [capture/packed-accumulation qualification](../vectors/reports/rv64-opstack-cpu-20261108/capture-and-packed-accumulation.json)
reduces native production to **1,222.972 s**, with **32.358 s** fresh reception
and byte identity for all preceding proof/statement artifacts. This excludes
recursion. The [selected D2 heavy root](../vectors/reports/rv64-opstack-cpu-20261108/heavy-d2-recursion-comparison.json)
also closes all 115 native members and 173 recursive nodes in **1,781.674 s**,
additional to **1,586.092 s** D2 native production. D2 reduces native proof bytes
and increases native time; it is an explicit profile, not a default speedup.
The matched CPU recursion fanout experiment is removed after no heavy-block
gain and higher memory. Its patch and refusal selector remain documented in
[CPU tuning](CPU_TUNING.md).

The [fixed-source repair](../design/riscv-proving-stack/rv64-fixed-source-geometry.md)
checks ordered native column geometry as well as the lifted source root before
reusing a fixed binding. Complete heavy native acceptance works with both
committed-source and identity-only independently derived setup. This closes a
real cache alias; no transcript or admission guard was weakened.

The [packed Solidity arithmetic](../settlement/PACKED_AIR.md) reduces the pinned
177-node AIR to **637,484 gas**, while the full worker PCS remains around
1.724 billion gas. Component gas improvements do not close settlement.

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
