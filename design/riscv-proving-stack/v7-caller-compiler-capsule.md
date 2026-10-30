# Reusing trusted caller verifier compilation

## Problem-match brief

The task is common-subexpression reuse across two trusted consumers of the
same immutable compiler result: independent fixed-key generation and captured
witness evaluation. It is not memoization keyed by an untrusted producer digest.
The existing cold compiler already constructs the exact original composition,
DEEP and FRI graphs plus the arithmetic plan, then discards them. Live preparation
records the composition graph again before evaluating it.

The selected transfer is an owned, opaque compiler capsule constructed only by
the original metadata compiler. The first slice retains the composition DAG and
its canonical input-source map, clones its contiguous arrays into live-owned
storage, and evaluates them on a freshly admitted original capture. This keeps
the existing Prepared destruction model and avoids borrowing graph memory across
owners. Fixed-key compilation reads the same retained trusted compiler object.

The computational saving is the second symbolic graph construction and source
mapping, at the cost of a linear array copy and a longer compiler lifetime.
Clone/evaluation is O(nodes + inputs); the existing hash-consing recorder and
symbolic constraint replay are removed from this live path. The diagnostic
measurement below is not a qualified production speedup. No reuse across different statements, epochs or geometries
is made. Original capture/mask admission and dynamic input/public-wire binding
remain mandatory.

Alternatives: borrowing every graph would save the copy but change multiple
ownership contracts; producer-supplied serialized graphs are rejected because
their claimed identity is not independent compiler authority. Default paths
remain unchanged, including the opt-in shared-epoch transcript work.

Qualification compares the original and capsule composition graphs, source
maps, exact inputs/evaluations, every emitted fixed row and public wire, cold
keys, and actual proofs. Timings must split cold construction, baseline live,
and capsule live on the same genuine caller fixture. Mutated captures must fail.
DEEP/FRI and arithmetic-plan reuse are later extensions after this first slice.

## Qualified first slice

The genuine SHA+Keccak caller gate passed 12 checks and produced a 152,714-byte
parent proof. Baseline and capsule fixed rows, MAIN values, public frames,
contexts and wire schedules match exactly. A changed capture is rejected. The
fresh detached receiver verifies after the compiler capsule, original fixture
and all producer rows have been destroyed.

| Measured preparation stage | Seconds |
|---|---:|
| Capsule compilation |0.839|
| Fixed setup using retained capsule |3.005|
| Baseline ordinary cold setup |3.997|
| Baseline live preparation |7.258|
| Capsule live preparation |6.386|

This single paired observation is diagnostic/unranked under concurrent
compilation. Live preparation was 0.872s lower (about 12%); it is not a controlled
production speedup claim. The graph contains 263,489 nodes. DEEP/FRI/transcript
construction and live arithmetic lowering are still unchanged.

The whole qualification job peaked at 6.82GB RSS while deliberately retaining
both baseline and candidate for exact row comparison; this is not the candidate
production memory footprint. Exact data and binary/log hashes are in
`performance/v7-caller-capsule-qualification-20261029.json`.

The capsule is a trusted in-process compiler object, not a serialized cache.
Its constructor runs the independent original compiler. The borrowed const
compiler view is for trusted fixed-roster code; Zig const does not deeply freeze
nested slices. No producer-supplied graph or self-reported fingerprint is an
accepted capsule constructor.

## Bounded producer integration

`block_v7_mixed_fixed_v1.Limits.caller_compilers` and
`block_v7_mixed_collection_v1.Limits.caller_compilers` are optional, default-null
slices indexed by the independently admitted whole-job caller ordinal. The
slice length must match the caller count. Every used capsule is compared against
that caller's exact template, epoch, entries and canonical physical public
claims without recording any graph. A null slot uses the existing compiler.

The new `block_v7_complete_cpu_producer_v1` constructs capsules once for its
bounded direct root, under a single aggregate host-memory cap (default 2 GiB)
and an explicit caller-count cap (at most 64). It passes the same capsules to
cold setup and live preparation, then destroys all capsules before root
commitments and proving. These are not caches retained across a whole block or
across reduction batches. `reuse_caller_compiler=false` keeps the original path.
`caller_compile_ns` reports the one-time compiler work separately, so reuse
cannot conceal it outside the measured producer interval.

The integration passes the complete streaming-root semantic compile. Its full
runtime qualification is pending the scheduled streaming-root gate; the
12-check genuine capsule result above applies to the isolated caller path.

## Qualified PCS and arithmetic reuse extension

The capsule now supplies owned clones of its independently compiled DEEP and
FRI graphs. Fresh capture inputs are decoded using that same independent profile;
FRI additionally checks its geometry against the actual DEEP profile and PCS
configuration. Each graph evaluates fresh request values. No witness, transcript
state or proof-derived result is cached.

Live row assembly can borrow the capsule's original arithmetic lowering plan.
It reconstructs the canonical lane reference from the three actual evaluated
graphs, checks exact authority equality with the retained compiler reference,
and validates the plan before materializing fresh arithmetic columns. The
borrow lasts only for synchronous assembly: no plan or graph pointer escapes
into the returned rows. Default assembly still builds its own plan.

Optional `STWO_RISCV_PARENT_PREPARATION_PROFILE=1` diagnostics now split caller
composition, DEEP, FRI, transcript planning, links, public schedule, emission
and final assembly. The preceding composition-only diagnostic replay remained
fully correct (12 checks): baseline live 7.583s versus capsule live 6.331s;
candidate transcript/path emission accounted for about 1.93s. These are busy-host
observations, not a new ranked benchmark. Full and finite-active exact row and fresh detached proof gates now pass
(13 checks); the full capsule is destroyed before parent key and proof creation.

| Caller policy | Ordinary live preparation | Capsule live preparation | Parent bytes |
|---|---:|---:|---:|
| Full SHA+Keccak | 6.994s | 5.827s | 152,714 |
| Active SHA+Keccak | 5.702s | 4.975s | 149,644 |

These diagnostic pairs show about 16.7% and 12.8% lower live preparation,
respectively. Full DEEP preparation fell from 335.3ms to 36.0ms; active DEEP
fell from 244.3ms to 24.6ms. FRI and arithmetic-plan reuse had little effect
on these small fixtures. The next measured target is transcript planning
(1.53–1.78s), followed by transcript/path emission (about 2s). Reusing a
compiled plan alone does not remove actual hash witness work.

The combined 97.04s qualification job peaked at 6.45GB RSS while retaining
baseline and candidate for comparison. It includes two original fixtures,
two genuine parent proofs, cold setup and hostile tests, and is not a
candidate production footprint. Exact stages, scope and binary/log hashes
are in `performance/v7-caller-pcs-capsule-qualification-20261029.json`.

## Qualified transcript preprocessing reuse

The next measured opportunity is repeated construction of immutable transcript
routing. A caller compiler may now request `transcript_capacity`; it builds the
original metadata-only fixed transcript plan once under the compiler budget.
Ordinary cold setup and live replay borrow that plan at exactly that capacity.
A changed capacity is rejected, and custom tighter transcript limits retain the
ordinary independent construction path. This is a bounded request-local object,
not a producer-supplied cached receipt.

Live replay still reconstructs every request operation, replays the original
channel, checks physical claims and the final channel, and emits all actual hash
witnesses. The original emission path compares its fixed fingerprint with the
independent plan. An explicit ownership flag preserves the plan while temporary
operations and emitted sources are destroyed; no borrowed pointer survives row
collection. The compiler is destroyed before parent commitments and proving.

The baseline complete CPU producer requests this cache at its configured
capacity and accounts for construction in `caller_compile_ns`. Shared-epoch
preparation retains its existing path, and bounded-window proving does not yet
supply compiler capsules. This slice targets redundant planning, not required
hash work; full and active exact-row, hostile-capture, capacity and detached-proof
tests pass (13 checks).

The recorded concurrent diagnostic pair measured full live preparation
7.564s → 5.578s and active preparation 6.583s → 4.413s. Transcript planning
fell from 1.936s to 0.977s (full) and 1.838s to 0.744s (active).
Cold construction remains charged: the full capsule took 1.998s, followed by
1.993s fixed setup, versus 4.187s ordinary cold setup. Combined cold+live
was 9.569s versus 11.751s in this pair; this is not a controlled production
speedup. Both parent sizes and exact fixed/MAIN data remain unchanged.
See `performance/v7-caller-transcript-capsule-qualification-20261029.json`
for complete phases, RSS scope and authoritative binary/log hashes.
