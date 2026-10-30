# CPU campaign measurement boundaries

## Native calibration complete; full-block assembly resumed

The requested 16M window now has one fresh-verified recursive root. Exact
4M/8M/16M comparisons, stage boundaries, memory and remaining limitations are in
[FINAL-RECURSION-CALIBRATION.md](FINAL-RECURSION-CALIBRATION.md) and
[final-round-window-times.csv](final-round-window-times.csv). The final 16M
original/root phases take 103.01/90.61 s, separately measured; their sum is 193.63 s.
Root charged peak 18.29 GB; original charged peak 48.67 GB. This closes a native-only
nonterminal window, not a complete Ethereum block. Implementation has resumed for
[complete execution-to-root assembly](full-block-assembly-v1/README.md); that work
does not replace these measurements with an unmeasured block-time claim.

All accepted observations here use 70 queries and 26 proof-of-work bits.
Instruction counts refer to RISC-V instructions of the retained Ethereum guest,
not EVM instructions or Cairo steps. No row below is a complete Ethereum block.

| Observation | Boundary | Time | Charged peak | Result |
| --- | --- | ---: | ---: | --- |
| `native-4194304-local-sparse-compact-parallel2-8x524288` | Execute/prep/prove/publish/freshly verify originals | 23.224 s | 4.307 GB | Eight local originals + bridge + compact global RAM |
| `native-16777216-local-sparse-compact-parallel2-32x524288` | Same original-bundle boundary | 80.865 s | 5.107 GB | 32 local originals + bridge + compact global RAM |
| `native-4194304-local-sparse-compact-parallel2-8x524288-single-dag-root-v3` | Saved original bundle → one freshly verified recursive root | 290.826 s internal / 291.47 s OS wall | 49.241 GB | One 1,115,560-byte root, independently verified |
| `keccak-131072-mixed-sparse-original` | Captured 131K window with 890 Keccak calls → one freshly verified mixed original | 21.311 s | 3.009 GB | All local buses closed; global RAM and recursion **open** |

GB means decimal charged heap bytes, not process RSS or device memory. The root
budget is 48 GiB (51,539,607,552 bytes), not 48 decimal GB. Original native
bundles use two proof jobs, each configured for eight workers; the root core
uses eight workers and two one-worker source-preparation jobs. The mixed
original benchmark uses eight workers and a production concurrent allocator.
Earlier original-bundle measurements use the testing allocator. These choices
are recorded and must not be silently treated as identical hardware budgets.

The 4M original and root measurements were separate runs. Their arithmetic sum
is 314.050 seconds, about 5m14s, **not** one measured end-to-end invocation.
The root stage does not execute or reprove the guest. It freshly captures the
saved originals once and proves their verifier bodies plus CPU/endpoint/global
closure. Its final receiver loads no original proofs, captures or producer keys.

The 16M observation has no corresponding root. Large native windows above
contain no precompile calls; the Keccak window is a separate, smaller real
caller-containing window. Tiny SHA/Keccak/recovery bundle and hostile halt
qualification gates establish correctness coverage, not large-window timings.

## Root-stage breakdown

| Stage | Seconds |
| --- | ---: |
| Fixed compilation | 9.360 |
| Fixed commitment | 24.401 |
| Source witness generation | 27.577 |
| Proving plan | 10.834 |
| Parent STARK proof | 186.964 |
| Fresh independently reconstructed receiver | 27.575 |
| Other loading/admission/encoding/cleanup | 4.115 |

Root proving is the dominant measured cost. Earlier flat-DAG attempts failed the
same budget; failure histories are retained. Rebalancing G rows, removing cold
compiler copies and using the production allocator made the 4M root fit. These
changes do not yet establish that a flat 16M or complete-block root fits.

## Real caller-containing original

The retained 131,072-instruction window starts at cycle 42,700,000 and contains
130,182 native instructions and 890 Keccak calls. Preparation takes 1.661 s;
original production 19.321 s (including 2.258 s interaction preparation and
16.429 s core proving); fresh byte verification takes 0.151 s. Background Python
and Rust processes were observed immediately after completion, so timing
isolation is unconfirmed. The verified proof and metadata hashes are unchanged;
this is diagnostic data, not an isolated ranked comparison.

## Machine-readable data

- `local-global-window-times.csv`: original bundles; `whole_s` is driver elapsed,
  while `whole_including_loading_and_publication_s` includes the outer boundary.
- `recursive-root-times.csv`: saved-original-to-root boundary only.
- `mixed-original-window-times.csv`: caller-containing originals, global RAM open.
- Per-observation `report.json`, `build.json` and `invocation.json`: exact inputs,
  executable provenance, worker policy, timings and artifact hashes.
- `publication-overwrite-audits.json`: historical runner bug affecting descriptive
  final-cohort timing JSON only. Proof/statement bytes and aggregate measurements
  remain intact; missing original timing bytes were not reconstructed.

Full-block latency remains unqualified. Native-window extrapolations exclude
caller proof costs and recursive reduction unless explicitly stated otherwise.

## Bounded shared original: actual 4M execution

`native-4194304-group-8x524288` executes the same pinned 4,194,304-instruction
window as the eight-local baseline, but commits all eight native/endpoint
members into **one original**, with shared ROM, lookup and range providers.
It uses 39 trace trees and independently checks each member's local closure;
per-member CPU/register/RAM residuals are not allowed to cancel across members.

| Boundary | Seconds |
| --- | ---: |
| Execute, prepare, produce and freshly verify group once | 20.941 |
| Same including outer loading/publication | 20.998 |
| Original production (inclusive) | 15.762 |
| Original core proving (inside production) | 10.784 |
| Fresh serialized group verification | 1.996 |

Charged peak is **12,158,340,617 bytes**; proof size **5,587,460 bytes**.
This is one diagnostic observation at q70/PoW26 and eight workers using the
production allocator. All our other compiler/prover jobs were held during the
measurement. It is **not** the same boundary as the 23.224-second original
bundle: the Group run leaves global RAM open and contains no recursive root.
Its higher memory use and smaller original proof roster are both material.

`endpoint-parity.json` independently checks all eight endpoint roots, endpoint
counts and CPU clock frames against the previously qualified complete original
bundle: all match byte for byte. Thus the new group preserves the exact narrow
inputs needed by the late bridge. Complete Group + bridge + compact-global
closure and the Group recursive adapter still need separate qualification.
Machine-readable data is in `group-original-window-times.csv`.

## Caller work removal and remaining composition cost

The genuine 131,072-instruction window with 890 Keccak calls now extends only
four metadata columns per Keccak RAM projection, rather than 64. The canonical
lazy tuple formula and all 50 RAM-slot inventories are tested at arbitrary
extension-field points. Genuine mixed SHA/Keccak and recovery originals pass
fresh byte verification (466 passed, 1 skipped).

A single diagnostic baseline/candidate pair measured 20.939 versus 19.771 seconds
at the same input, q70/PoW26, eight workers and production allocator: 5.58% less
whole-request time. This is not a repeated ranked result. Complete proof and
metadata bytes match exactly, including SHA256
`ac6afba3ae35f20780e8adbd271f3d4a9ce453b13d94cd79b45185f6aa20ff4d`.
The separate instrumented candidate reports 14.930 seconds composition evaluation
out of 15.395 seconds core proving (~97%). Its proof bytes also match. Therefore
further PCS/FRI tuning alone cannot yield a large gain on this window.

The one-second stack sample starts four seconds after process launch and spans
interaction preparation and early composition; it is not a representative
whole-run CPU-share census. It confirms repeated typed-entry derivation in
`block_v5_native_projection_fused_source_v1.fromCommittedMainBase`: each lookup
projection reconstructs the whole opcode entry list. The existing row-batched
interaction producer already avoids that repetition, but the domain quotient
evaluator still repeats it. The next optimization is shared source-row recipes
for all physical quotient slots, preserving their separate claims, constraint
coefficient order, masks and OODS equations. Bounded row tiles and a configurable
projection batch size must keep this optimization useful on wide native shapes;
a whole-domain recipe cache that only fits tiny windows is insufficient.

All mixed observations remain original-only with global RAM and recursion open.
The CSV distinguishes unprofiled, stage-profiled and stack-sampled observations;
sampled timings must not be ranked as clean latency results.

## Bounded Group originals: complete declared-window closure (2026-10-30)

These are CPU, canonical 70-query/26-bit-PoW **complete original bundles**:
one Group original, one late bridge opening the exact retained per-cohort
23-column endpoint roots, and one compact global RAM original. All producer
objects are destroyed before file-only receiving; that receiver verifies the
Group once and closes all endpoints against independently pinned incoming and
outgoing snapshots. They are not recursive roots, terminal Ethereum proofs or
GPU measurements. Cohorts remain 524,288 instructions; wider consolidation is
an explicit new native-only Group protocol, independent of native row geometry.

| Instructions | Cohorts | Group profile | Original proofs | Bundle, s | Loading/publication included, s | Source core, s | Fresh bundle verification, s | Charged host peak, GB |
|---:|---:|---|---:|---:|---:|---:|---:|---:|
| 4,194,304 | 8 | compact_v1 | 3 | 24.934 | 24.989 | 10.634 | 3.053 | 12.192 |
| 8,388,608 | 16 | native_wide_v2 | 3 | 48.317 | 48.353 | 21.514 | 5.632 | 24.024 |
| 16,777,216 | 32 | native_wide_v2 | 3 | 90.324 | 90.368 | 46.412 | 9.622 | 45.610 |

Source core means original STARK production only. The bundle clock also includes
execution/witness preparation, commitments/interactions, bridge/global proofs,
serialization and fresh independent verification. Charged host storage is the
bounded allocator peak, not GPU VRAM. These are individual diagnostic runs,
not repeated timing distributions.

The proof roster improves substantially, **but a CPU latency win over the
latest sparse two-job Local pipeline has not been demonstrated**. At 16M,
that retained baseline took 80.865 s including loading/publication versus
90.368 s for the grouped bundle (90.324 s inner bundle clock): 11.8% longer.
It used 5.107 GB versus 45.610 GB charged host storage. Original proof count
falls from 34 to three (11.33x fewer), not an 11.33x latency improvement. At 4M,
the current Local baseline is 23.224 s versus 24.989 s grouped. Recursive root
costs have not yet been compared for this new Group protocol; proving fewer
originals is preparation for that experiment, not evidence of root supremacy.

The Local source proof/core timers in the comparison CSV are **sums across
concurrent jobs** and may overlap. They must not be compared to wall time as
if they were sequential phases. Group source timers contain one original.

Data and provenance:

- `group-complete-bundle-window-times.csv`: all three Group runs and the current 4M/16M sparse Local references, with stage boundaries, proof counts, RSS/charged peaks and source hashes.
- `group-complete-bundle-comparison.json`: derived ratios and immutable report SHA-256s; explicitly records the negative latency result.
- `native-4194304-group-compact-global-8x524288/`
- `native-8388608-wide-group-compact-global-16x524288/`
- `native-16777216-wide-group-compact-global-32x524288/`
- `group-complete-bundle-benchmark-build/`: frozen executable and exact 10,798-file source manifest.

The 4M postprocessing print error was repaired and its existing artifacts were
checked with `--validate-only`; no proof was rerun. Publication records retain
both the executing runner identity and the later validation runner identity.

## Group recursive qualification

The canonical Group source adapter now has an actual recursively proved/freshly
received result: two genuine native cohorts, 15 trace trees, eight first roots,
927,130-byte recursive proof. The parent proving phase was 15.084 s in this tiny
diagnostic qualification. Its scope remains `group_execution_global_ram_open`;
the later same-root bridge and compact global relation must close it. All
original proof/capture/profile/key objects were erased before fresh root-only
receiving. Symbolic opposite per-member RAM residuals reject even though their
aggregate is unchanged; the intentionally open plane remains open and a changed
CPU byte rejects. Gate: 485 passed, one skipped, no failures.
`group-recursive-source-qualification-v1/` records the log and direct-source
hashes. The temporary unit proof was not retained; no production speed claim is
inferred from it.

The Group-aware three-body SingleDAG qualification subsequently passed all 11
checks: one parent proof over Group + same-root bridge + compact global original,
zero intermediate recursive proofs, fresh file-only verification after all
producer destruction. Its tiny/nonisolated parent core phase was 33.516 s and
proof size 975,915 bytes. Evidence is in
`group-single-root-qualification-v1/`. This establishes the complete recursive
relation; it does not provide a measured 4M Group recursive benchmark. That
measurement was deliberately not launched when the requested final priority
changed to the separate 16M native-wide proof train.

The private native-projection batching switch also passed complete canonical
original byte parity (401,832 bytes) with every physical constraint, claim,
transcript and public metadata unchanged. Its gate passed 463 tests, skipped one
and failed none; evidence is in `group-native-batch-qualification-v1/`. No
additional Group performance experiment was run after the final-round stop.

## Actual caller-rich mixed window, 2026-10-30

The 131,072-instruction window at skip 42,700,000 contains 130,182 native rows and 890 Keccak calls. The wide native/mixed original, exact-root endpoint bridge and compact snapshot-bound RAM proof were reduced directly into one canonical q70/pow26 recursive root, with no intermediate recursive proofs. Fresh file-only receiving succeeded after every producer, original/capture/profile and key owner was destroyed.

The retained root is 1,028,985 bytes, SHA-256 `4cc5746f3d3aa1372499a62e46b6fadfaff967610a974e373597c74b207760ac`. The saved-originals-to-root command took 77.106 s: 40.882 s parent core, 12.935 s witness construction, 4.595 s fixed compilation, 4.984 s fixed commitment, 3.667 s planning and 8.410 s fresh receiving, plus loading/admission/transport. Charged peak was 15.857 GB; OS sampled final peak footprint was 15.893 GB. This was a contended diagnostic CPU run with eight workers. It is not an isolated latency result or a whole-block proof.

The separately executed original-bundle command took 16.746 s. Adding that number to recursive command time is a sum of saved stages, not a measured continuous execution-to-root latency. `mixed-window-proving-times.csv` retains the distinct phase boundaries. Both commands' complete reports, artifact hashes, source manifests and provenance are retained alongside the actual original and root proof bytes.

A separate complete nine-instruction fixture includes a real Keccak call at cycle 3 and native final halt at cycle 9. Its 1,021,354-byte root (SHA-256 `f204e46da61d61b2d38516da5b6ae0c3cc57284f18d3d751d491e7f7361acca9`) passed fresh `Upper.verifyFull` from serialized metadata, with independently derived FIRST/input and terminal/output policies. Missing FIRST, missing terminal, and changed expected output were rejected. This closes the terminal mixed *fixture*; it does not establish the complete retained 139.2M-instruction block.
