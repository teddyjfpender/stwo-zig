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

| Gate | Current qualification | Required closure |
| --- | --- | --- |
| Kona execution | Three complete local native execution bundles, including selected heavy block 121065789 with 91 CPU and 24 service proofs; fresh receivers and physical corruption rejection | Extend representative execution coverage without weakening expected-output binding |
| Anchored derivation | Native and RV64 accept transition 159257841 → 159257842; KZG/anchor/root mutations reject | Complete physical STARK proof with independently pinned OD output and retained authenticated input |
| Capacity and continuity | Fastest retained anchored replay needs at least 733 CPU proofs before services; native cap is 256 | Reviewed versioned segmentation binding PC, registers, clocks, memory, services and final output; no blind cap increase |
| Recursive closure | Complete small grouped roots plus original B2 heavy root (126 leaves/64 folds) and selected D2 heavy root (115 leaves/58 folds); final executable accepts both and rejects physical attacks | Reduce heavy latency; extend closure to an actual anchored derivation proof |
| Joined statement | Receiver-side OD/OP join and synthetic ordered folds exist | Actual recursive root authenticating both matching programs, exact outputs, order and complete native closure |
| Accumulator | No complete running OP checkpoint accumulator receipt | Adjacent checkpoint folds rejecting gaps, overlaps, swapped branches and substituted anchors |
| Settlement | Packed pinned AIR 637,484 gas; full native worker PCS remains about 1.724 billion gas | Complete authorized checkpoint verifier under actual transaction constraints |
| Security | 128-bit security target under documented assumptions; `security_qualified=false` | Bounded composed accounting for the concrete derivation, segmentation, recursive and settlement construction; no certification claim |
| Regression hygiene | Fixed-source geometry repair; both heavy profiles accepted by final executable; 24 settlement tests pass, three external-fixture skips | Keep formats/defaults stable; resolve outstanding broader CI failures and qualify new shared changes independently |

## Current optimization branch: explicit pure-P2 execution

The CPU continuation is developing a separate construction rather than silently
replacing the qualified execution controls above. Its records are in
[`rv64-opstack-cpu-20261109`](../vectors/reports/rv64-opstack-cpu-20261109/) and
[`rv64-opstack-performance-20261109`](../vectors/reports/rv64-opstack-performance-20261109/).

| New construction gate | Established evidence | Still required |
| --- | --- | --- |
| Selected OP guest | Three real blocks agree with independent execution; heavy block runs 238,226,172 instructions, down from 380,167,068 | Complete native and recursive proofs of that selected heavy execution |
| Compact native route | Actual block 120794432, CPU + Keccak + SHA, exact 43-byte result; retained 7,048,980-byte bundle and fresh receiver | Complete selected heavy execution; do not substitute preparation or replay for proving |
| Bounded immutable setup | Two fresh heavy captures reuse all 36 setup classes with no new misses; all roots, public cells and final states match; 28.068 GB peak requested memory under 32 GiB; final heap/external counters zero | Uninterrupted warm end-to-end proving measurements; both preparation timers were interrupted |
| R5 portable root-only handoff | Actual small block: three physical leaves, two folds, 667,304-byte root; fresh receiver derives source authority and verifies only the root | Practical performance: 305.567 seconds additional recursion remains too slow; not a default promotion |
| R6 independent OM31 multiplication | Actual small execution closes all three leaves and two folds: 687,908-byte root: original Safe run 198.102 seconds; subsequent Fast run 138.898 seconds with every node/root/sidecar byte-identical and fresh source-only acceptance; native production is additional | Actual full-height heavy classes and complete heavy native-plus-root performance; no extrapolation from the small block |
| Service-local GKR | Regenerated CPU/Keccak/SHA native bundle, actual 338-call Keccak physical wrapper, complete small recursive root and source-only adversarial receiver; original RAM/KIO/Wire and terminal policy close | Heavy resource-derived sharding and complete inventory; isolated Miller local GKR worker has physical fragment qualification but is not admitted into the complete inventory |
| Bounded truth planning | Source-derived checkpoint/whole-worker estimator refuses heavy log18 Keccak and admits log16/4,518-permutation shards under the declared 8 GiB worker limit | Resource-derived shard-plan integration is present; physical heavy qualification remains open. Estimates are requested bytes, not measured RSS |
| Complete heavy performance | Matched D2 native + M6 root baseline 3,328.446 seconds | At most 332.845 seconds for the same heavy block, through a complete recursive root; **not achieved** |

R5's source-only receiver loads source declarations and public cells, not native
proof bytes. It retains exact expected program/image/output, terminal and global
closure checks; a small final proof does not eliminate cold source-key setup.
R6's receiver additionally discards prover-only FIXED buffers after independently
constructing each source key. This is a retention improvement, not avoidance of
the initial commitment or a certified security claim.

The current `rv64-op-native` and `rv64-op-root` commands expose only their explicit
experimental route; they do not switch the historical Ethereum driver or its
profiles. Admission of service-local GKR requires the receiver's independent
protocol selection and complete physical gates. The production security label
remains **128-bit security target under documented assumptions** with
`security_qualified=false`.

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
