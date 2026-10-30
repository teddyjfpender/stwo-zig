# Calibrating a full-block result from real recursive roots

This model uses actual closed-window recursion measurements. Tiny hash,
transcript, Merkle, FRI and PCS circuit-satisfaction gates contribute **no rate
estimate**. No complete recursive Ethereum block result is currently implied.

## Measured inputs

All rows below concern the same retained ELF and a declared nonterminal window
starting after one skipped cycle. Both native windows have zero external
retirements. The new 4M root report is the raw fresh-verified result; its final
campaign timing/provenance annotation belongs to the primary runner.

| Observation | Old 4M / eight 512K Local sources | New 4M / one wide-profile-4 Local source |
|---|---:|---:|
| Original source captures verified by recursive root | 10 | 3 |
| Parent core proof | 186.964 s | 26.686 s |
| Parent setup+witness+proof+encode | 259.153 s | 43.979 s |
| Complete saved-source root command, including fresh receiver | 290.826 s | 52.659 s |
| Retained parent rows | 17.608 GB | 4.594 GB |
| Charged parent peak | 49.241 GB | 12.298 GB |
| Root bytes | 1,115,560 | 1,007,493 |

These are combined architectural changes: wider consolidation, direct RAM-clock
profile and root geometry, not an isolated optimization factor. The new source
original bundle was separately measured at 25.854 s for 4M and 56.649 s for 8M.
Those are **not recursive-root times**. The 8M source peak is 48.665 GB; it already
approaches the same 48 GiB charged budget. The actual fresh-verified 8M recursive root is now retained: core proof
30.476 s, parent setup+witness+proof+encode 50.869 s, complete saved-source
command 63.749 s including 8.697 s fresh receiving. Its retained rows are
5.343 GB, charged peak 14.275 GB and root 1,032,737 bytes. The 63.749 s
figure is the complete command, **not** core proof time. This is a second
nonterminal native window observation; it does not cover missing caller or
terminal obligations.

Source reports:

- `vectors/reports/riscv-cpu-architecture-20261029/native-8388608-direct-clock-v3-wide-single-sparse-compact-profile4-single-dag-root/report.json`

- `vectors/reports/riscv-cpu-architecture-20261029/native-4194304-local-sparse-compact-parallel2-8x524288-single-dag-root-v3/report.json`
- `vectors/reports/riscv-cpu-architecture-20261029/native-4194304-direct-clock-v3-wide-single-sparse-compact-profile4-single-dag-root/report.json`
- `vectors/reports/riscv-cpu-architecture-20261029/native-4194304-direct-clock-v3-wide-single-sparse-compact-profile4/report.json`
- `vectors/reports/riscv-cpu-architecture-20261029/native-8388608-direct-clock-v3-wide-single-sparse-compact-profile4/report.json`

## The cost equation and the double-counting trap

For the endpoint architecture with conditional CPU/local-RAM groups and one
late global RAM closure, use:

`T = execution/restore + Σ(source-original production) + global/bridge originals`
`    + Σ(conditional recursive group roots) + final recursive closure + receiver`.

A source-original term must include its real Native/Mixed/caller statement;
adding an independent caller cost again would double count a fused original.
Likewise, the measured 4M root already verifies Local + bridge + compact-global
and closes that **window**. Multiplying that complete-window cost by a chunk
count and then adding one whole-block bridge/global term double counts closure.
Use it as an observed complete-window scenario, not an exact conditional-group
unit. A hierarchy of independently closed windows is a different design and
needs an actual parent-source adapter plus proved CPU and memory-boundary links.
Conditional endpoint transition sums from different epochs cannot simply be
added together.

The retained full execution census is 139,214,856 cycles. Dividing by 4M or 8M
provides a chunk count, not a proof-time estimate. Fit native/root stage costs
only after the real 8M root is available, with separate setup, witness, core,
receiver and padded-row counts. Do not fit total time to cycle count alone:
power-of-two padding, selected PCs, lookup cardinality, endpoint count and
physical proof width determine the verifier work. The first 4M prefix is copy
heavy; its instruction mix is not the full execution's mix.

## Required unmeasured terms

- Mixed SHA/Keccak/recovery originals and their actual recursive adapters.
  A real 890-call Keccak source-original measurement does not measure recursive
  caller verification. Current zero-caller native root rates cannot price it.
- Terminal execution semantics and the skipped initial cycle. The measured
  roots enforce a nonterminal policy; they do not prove final halt retirement.
- Whole-block endpoint roster, one common late epoch, bridge batches and full
  initial/final memory closure under the complete pinned statement.
- The actual hierarchy/final root proof and fresh receiver. A Group bundle with
  three genuine original proofs is not yet a qualified Group-aware recursive
  root, and a host-verified summary is not recursive authority.
- A representative full-program shape: the full execution has different opcode,
  PC/ROM, range, caller and endpoint geometry from the copy-heavy prefix.

A defensible current report is therefore: a real 4M native nonterminal window
has one fresh-verified recursive root with the measured stage costs above;
8M root calibration and the listed caller/terminal/hierarchy terms remain to be
measured or implemented. A full-block numerical forecast must label its choices
for those missing terms rather than present the native-prefix rate as a result.
