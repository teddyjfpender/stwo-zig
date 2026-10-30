# Complete execution-to-root assembly

This is the functional qualification campaign following the native 16M
calibration. It is not a completed block proof or a new timing forecast.

## Required statement

The retained ELF and private input execute from their independently reconstructed
initial state for exactly 139,214,856 cycles. The final execution must halt through
the ELF's halt flag and publish the pinned 43-byte output. Every intermediate CPU
state and complete RAM snapshot identity must be adjacent. Every native, caller,
program, lookup and memory obligation must close into one independently verified
recursive root at 70 queries and 26 PoW bits.

## Structural changes

* `block_v8_endpoint_mixed_pipeline_v1.zig` builds each real mixed witness and
  original once, retains only its authenticated endpoint tree and narrow rows,
  proves the late bridge and compact global RAM, and freshly verifies the durable
  directory after destroying every producer. Initial gates passed for SHA/Keccak
  and recovery. Wide-geometry and boundary extensions require their own gates.
* Native wide-shard geometry is independently selectable in mixed sessions. It
  does not enable direct RAM clocks or change caller arithmetic and RAM equations.
  Geometry remains in the serialized statement and transcript/key admission.
* The execution census can emit scheduled checkpoints in one bounded execution
  using `STWO_B8_CENSUS_CHECKPOINT_PLAN`. This removes one skipped-prefix replay
  per requested window. Checkpoints remain untrusted proof inputs.
* `scripts/v8_full_block_campaign.py` checks census coverage and inventories,
  chooses independently bounded native/mixed windows, and creates a balanced
  reduction DAG without duplicating odd leaves or rounding proof count upward.

The current conservative schedule uses native windows up to 8M cycles and mixed
windows up to 1M cycles/4,096 calls. It contains **107 windows**: 12 native windows
covering 44,318,728 cycles, and 95 mixed windows covering 94,896,128 cycles. There
are **106 binary folds**. These are resource-policy choices for qualification,
not inherent limits or a claim that 107 roots is the desired final architecture.
The earlier nine-window model extrapolated native-only capacity and does not
describe this mixed schedule's proving time.

## Qualification order

1. Genuine mixed original, bridge and memory closure from saved bytes.
2. Complete mixed recursive root, including every typed caller equation.
3. Two contiguous roots merged with exact public-supply and coverage closure.
4. Initial/middle/terminal chain, including the first instruction and final output.
5. Complete retained execution, one recursive root, fresh final verification and
   a profile covering execution, preparation, originals, recursion and receiving.

No setup or format optimization may move input-dependent witness work outside the
reported end-to-end boundary. No complete-block claim follows from a passing
checkpoint writer, directory receiver or a conditional source root alone.

## Complete retained run

`retained-139m-native4m-workers16-v1/` is the first complete retained-block
attempt. It uses the frozen ReleaseFast binary recorded in `build-v1/`, 16 CPU
workers, 4M native cohorts inside the independently planned windows, and a 60 GiB
shared host budget. The final `proof/report.json` is created only after fresh
serialized full-root verification. `progress.json` explicitly remains unverified
while the run is incomplete.

`scripts/v8_full_block_results.py ATTEMPT` collects the live artifacts into
`analysis/windows.csv`, `analysis/folds.csv`, `analysis/stages.csv` and
`analysis/summary.json`. The detailed stage export preserves every recorded
duration and byte counter with its source report, measurement path and window
or fold ID. Nested whole times overlap their children; do not sum them together.
The observer started before this detailed export was added; collect once more
after completion to produce it without restarting the live observer. Optional
`--watch-pid PID` also records progress observations and process RSS. Missing
measurements remain empty. Parent-core proving time is not mislabeled as the
complete wrapper or end-to-end time. Native budget peaks are cumulative across
the parent allocator and are explicitly named accordingly.

Receiving needs the shared checkpoint files and pinned source bundle as well as
thin metadata. This is statement-specific verification with large public auxiliary
data, not yet a universal fixed-key proof from bounded input/output hashes alone.
