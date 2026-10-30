# CPU RISC-V recursion: final 4M / 8M / 16M calibration

The final round is complete and work is stopped for discussion. These are real
retained-Ethereum-guest native execution windows, with one independently verified
recursive root each. They are nonterminal windows after one skipped instruction,
not complete Ethereum blocks. All observations use 70 queries, 26 PoW bits,
eight proving workers, the production allocator and frozen executables. Root
preparation uses two one-worker source jobs. No GPU measurements were made.

| Instructions | Execution cohorts | Originals recursively verified | Original bundle incl. loading/publication | Saved originals → fresh root | Sum of separate measured phases | Root charged peak |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 4,194,304 | 1 | 3 | 25.85 s | 52.66 s | 78.51 s | 12.30 GB |
| 8,388,608 | 1 | 3 | 56.65 s | 63.75 s | 120.40 s | 14.27 GB |
| 16,777,216 | 2 | 4 | 103.01 s | 90.61 s | 193.63 s | 18.29 GB |

The 16M window uses two 8M wide native originals, one endpoint bridge and one
compact global-memory original. A single 16M source was not attempted: its
projected allocation exceeds this Mac's capacity. Peak original proving memory
is 48.67 GB; peak root proving memory is 18.29 GB. These are separate phases.
The final root is 1,030,765 bytes, SHA256
`07eac98d945121aa780695ccf15e7b712da3df01c42b8fedf9185ae742075b03`.
Every root consumes saved originals without guest execution or original reproof,
then passes a fresh serialized-only receiver. Snapshot-delta public ports: zero.

## What improved

The old qualified 4M root took 290.826 s and 49.241 GB. The new 4M root takes
52.659 s and 12.298 GB: **5.52× less root time and 4.00× less charged memory**.
The larger 16M window doubles the 8M instruction count while increasing root
time only 1.42× (63.749 → 90.612 s). Its combined phase sum is 19.6% below two
separate 8M phase sums. The data supports amortization; it does not support
assuming recursion is constant time as windows grow.

Increasing group size alone was insufficient. The separate 32-cohort Group
experiment reduced 34 originals to 3, but its 16M original bundle was slower
than the previous Local bundle (90.368 versus 80.865 s). No large Group root was
measured. Small Group source/root and complete three-original-join qualification
passed, but those fixture times must not be used as throughput measurements.

## Where the final 16M run spends time

Original bundle: **103.01 s**, including 86.53 s native-original production
(60.49 s core proving), 0.97 s bridge proving, 3.82 s global-memory proving,
and 3.08 s fresh bundle receiving. The other preparation, execution and artifact
work remains included in the total.

Saved originals to root: **90.61 s**, including 44.57 s parent core proving,
12.25 s witness construction, 12.38 s fresh root receiving, 5.37 s fixed
compilation, 5.08 s fixed commitment and 4.67 s proving-plan construction.
Loading, original capture/admission, encoding and cleanup make up the remainder.
These partitions identify both substantial proof work and setup/receiving cost;
cache improvements alone cannot remove the whole bottleneck.

## Full-block budget: useful, explicitly conditional

The retained execution census contains **139,214,856 cycles**, 32,835 Keccak
calls and 78 recovery calls. Dividing it into eight full 16M windows plus a
4,997,128-instruction tail gives nine modeled window roots. The tail lies
between the measured 4M and 8M sizes; its time is interpolated.

Using measured native-only window costs gives **14.26 minutes of originals +
12.99 minutes of window recursion = 27.26 minutes serial CPU time**. The older
8M-window model gives 33.55 minutes. A native-main-area sensitivity using the
actual per-window opcode census changes the 16M plan to 27.75 minutes; this
is an unvalidated work proxy, not a statistical confidence interval.

**27.26 minutes is not a full-block ETA.** Eight of the nine modeled windows
contain callers, which the measured wide profile does not yet admit. Additional
unknowns are caller recursion, the skipped prefix and terminal/output binding,
and reduction of the nine window roots into one final root. Closed-window costs
already include their bridge/global-memory proofs; adding another whole-block
memory proof would double-count closure in this plan.

| Assumed upper-fold cost per binary node (unmeasured) | Native-only serial budget, including eight such nodes |
| ---: | ---: |
| 10 s | 28.59 min |
| 30 s | 31.26 min |
| 60 s | 35.26 min |
| 120 s | 43.26 min |

Caller and terminal work remain additional unknown terms in every row. There
is no qualified upper-fold adapter for these B8 roots yet: the generic parent
requires zero total claimed sum, whereas these roots require the exact public
supply relation. The 4M and 8M measured windows overlap and cannot be presented
as an adjacent pair for an aggregation demonstration.

## Remaining work to discuss

1. Implement the RISC-V-specific upper verifier/fold: exact public-supply and
   transcript binding, independent child-key admission, CPU/snapshot adjacency,
   and hostile/fresh-receiver qualification. Copy and specialize Cairo machinery
   where useful; preserving its API is not a requirement.
2. Complete mixed-caller wide execution/recursion and explicit initial/terminal
   output binding. Independently size crypto and native work: an 8M native
   source already approaches this host's memory capacity.
3. Then optimize the measured parent core, witness work and original core,
   including reusable immutable setup and a bounded reduction pipeline. The
   qualified new BLAKE3 circuit hash/transcript/Merkle/FRI/PCS kernels are useful
   building blocks; typed AIR and complete leaf wrapping remain unfinished.

## Evidence

- `final-round-window-times.csv`: measured stage boundaries, memory and root hashes.
- `full-block-cost-model-v1/model.json`, `windows.csv`, `windows-16m.csv`: assumptions,
  source hashes and actual full-execution census grouped into windows.
- Reproduce analysis only with
  `python3 design/riscv-proving-stack/performance/full-block-recursion-cost-20261030.py`.
- The 16M root directory's `final-round-summary.json` audits all original/root
  artifact hashes and both frozen binaries; the root report records fresh receiving.

No additional proofs, optimizations or GPU runs are scheduled after this round.
