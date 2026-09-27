from pathlib import Path
import json,statistics,hashlib,subprocess,datetime,shutil
H=Path(__file__).resolve().parent;R=H.parents[2]
r=json.loads((H/'candidate3/results.json').read_text());serial=json.loads((H/'candidate3-serial/results.json').read_text());proof=json.loads((H/'canonical-proof-results.json').read_text())
s='''# Larger ZisK/Stwo stages and retained full-stack optimizations

The retained changes specialize the shared Keccak lane schedule, remove redundant
aggregate copying from its witness lookup reads, and reduce native BLAKE3 framing
updates without changing transcript/commitment bytes. This is an intermediate
campaign result, not a claim that the complete ZisK/prover comparison is finished.

## Same-host optimization results

Apple M5 Max, Zig 0.15.2 ReleaseFast/native, frozen before/candidate binaries,
four interleaved samples per arm. All these runs were on battery and record power
before/after; they are not pooled with the previous AC campaign. ZisK sources stay
pinned to the commits in ../2026-09-24-zisk-component-suite/CATALOG.md. The local
before arm is the exact dirty-tree state before these changes, not an older git HEAD.

| Operation | Before | Retained | ZisK | Interpretation |
|---|---:|---:|---:|---|
'''
for row in r[:7]:
 def ns(n):return f'{n/1e6:.3f} ms' if n>=1e6 else f'{n/1e3:.3f} µs' if n>=1000 else f'{n:.2f} ns'
 label=row['name']+(f" ({row['input_bytes']} B)" if 'input_bytes' in row else '')
 m=row['median_ns'];s+=f"| {label} | {ns(m['before'])} | {ns(m['after'])} | {ns(m['zisk']) if 'zisk' in m else 'not measured'} | {row['comparison']} |\n"
s+='''
The permutation's ~34x local improvement now puts it slightly ahead of the same-host
ZisK `tiny-keccak` arm. The complete paired witness/validation/counter stage improves
8.9x, not 34x. Its benchmark includes both input calls, all 29 witness rows, complete
validation, compact chi/xor5 counting, and output consumption. Counter storage is
allocated once per timed batch. The harness resets the logical slot limit each
iteration while accumulating histogram values; this is a repeated one-slot stage
probe, not a single proof containing all repetitions.

The 32 KB transcript workload now beats the peer's native counterpart; the 64 B and
1 KB cases still trail. As in the first campaign, protocols, output field widths,
framing and challenge reuse differ. No protocol change or weakened domain separation
was used to improve a number. The one-at-a-time local draw API is measured here;
its timings are not a benchmark of the separate batched-draw API.

## Complete LDE → commitment pipeline

Both arms execute actual prover APIs, not a sum of independent kernel timings:

- Peer: `NTT_Goldilocks::LDE` into row-major extended evaluations, followed by
  `Blake3Goldilocks::merkletree`, with a retained base plan and buffers.
- Local: circle interpolation and extended evaluation with retained twiddles,
  followed by the production `MerkleProverLifted(MerkleHasher).commit`, then teardown.

The explicit **one-worker** comparison is the appropriate CPU baseline. Peer
OpenMP pragmas are disabled in this portable ARM build. Initial automatic-worker
local results are retained separately under candidate3/; they must not be described
as equal-worker speed ratios. The following times include per-batch setup amortized
over repetitions, input preparation and root consumption. Inner stage clocks exclude
those outer costs. Local commitment allocation/deallocation and peer internal LDE
extension-plan construction remain part of their respective native API costs.

| Input rows | Columns | Ours total | ZisK total | Ours LDE / commit | ZisK LDE / commit |
|---:|---:|---:|---:|---:|---:|
'''
for row in serial:
 def stage(arm):return ' / '.join(f"{statistics.median(x['stage_ns_per_call'][i] for x in row['samples'] if x['arm']==arm)/1e6:.3f}" for i in (0,1))
 s+=f"| {row['input_rows']:,} | {row['columns']} | {row['median_ns']['after']/1e6:.3f} ms | {row['median_ns']['zisk']/1e6:.3f} ms | {stage('after')} ms | {stage('zisk')} ms |\n"
s+='''
All use 2x expansion and the same number of field elements. **They do not use the
same field, polynomial domain, field-element byte width or native hash framing.**
Peer GL64 columns occupy twice the bytes of local M31 columns. This explains part
of the layout/memory cost and prevents any equivalent-security prover ranking.
At each shape, constant input evaluates to constant output on all arms; repeated
before/after local root checksums match. General peer/local roots are not expected
to match. Full proof workloads remain necessary to compare equivalent statements.

The narrow-row commitment stage is still slower locally even where the overall
pipeline wins. Wide rows amortize local framing and favour the native tiled builder.
This is why both stage breakdowns and total latency are retained.

## Complete independently verified Keccak proof

Added `bench-keccakf-blake3-system`, which reuses the existing typed Keccak shard
harness with an explicit configuration: BLAKE3, **70 queries, 26 PoW bits**, log2
blowup 1, last-layer log degree 0, and an explicit **16-worker scoped pool**. It
creates the witness and complete lookup tables, commits preprocessed/main/interaction
columns, proves, and independently verifies the resulting proof.

This is a standalone precompile proof, **not the full CSP guest or recursion tree**.
The reported sum includes witness, commitments, interaction generation, proving and
verification; it excludes process startup, worker-pool initialization and final
harness teardown. Frozen before/after binaries run in interleaved fresh processes,
four observations per arm. Every proof verifies.

| Measurement | Before median | After median |
|---|---:|---:|
'''
for key,label in [('witness_ms','Witness preparation'),('prove_production_ms','Witness through proof creation'),('verify_ms','Independent verification'),('total_ms','Complete measured pipeline')]:
 s+=f"| {label} | {proof['median']['before'][key]:.4f} ms | {proof['median']['after'][key]:.4f} ms |\n"
s+='''
The complete measured pipeline improves **6.4%**; the witness improvement does not
translate into an 8.9x proof speedup. Canonical-proof raw stage samples are in
canonical-proof-results.json. The older default Keccak test uses Blake2s, three
queries and PoW 0: its separate proof-results.json is diagnostic only.

An initial canonical test run took ~1.9 s because Zig tests deliberately disable
the implicit production worker pool. The new benchmark now binds its pool explicitly
on **both** arms. Those unpooled logs are retained as canonical-*-unpooled.log and
are not evidence of a production prover regression or an optimization speedup.

## Engineering and qualification

- Shared `keccakf_authority.applyRound` fixes lane/rotation indices at compile time;
  `permute` groups three rounds without changing the round schedule or constants.
- `keccakf_witness` explicitly borrows state/parity arrays for dynamic lookup reads.
  Generated ARM code previously emitted repeated large aggregate `memcpy` calls.
  This affects validation and multiplicity consumers without skipping any checks.
- `blake3_frame` absorbs little-endian word slices in one update for byte sinks,
  preserves semantic word callbacks for witness sinks, and encodes fixed frames
  once before hashing. Frames, domain tags, challenge count and proof parameters
  are unchanged.
- An intermediate attempt to inline lookup loops failed to improve the counting
  stage and was removed. candidate2/ retains its measurements; candidate3/ is kept.
- 256 randomized complete 25-state Keccak traces match before/after word-for-word;
  final states also match the peer's tiny-keccak implementation.
- Complete paired witness bytes and all 9,216 histogram entries are independently
  compared before/after for 32 random pairs in full-witness-parity.json.
- 97 ReleaseSafe semantic/mutation/encoding checks passed, including malformed
  witness rejection and fixed-frame digest parity. Three native BLAKE3 proof gates
  passed (transcript, challenge and routed Merkle hash), as did the Keccak proof gate.
- Source-only isolated baseline mirror avoids changing the shared working tree.
  The first mirror build missed embedded design artifacts; its diagnostic is retained
  and the mirror now explicitly references the unchanged design directory.

## Reproduction and next boundaries

Build adapters with `build.py before|candidate3` and `build_pipeline.py
before|candidate3` against the corresponding recorded source state. `run.py candidate3`
repeats default-stage comparisons; append `--serial-pipeline` for explicit one-worker
LDE/commit runs. Benchmark timings are serialized with scripts/zig_serial_build.py.
Sources and binary digests are retained; do not rebuild the before-labelled artifacts
from an already optimized working tree.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \\
  bench-keccakf-blake3-system -Doptimize=ReleaseFast -j1 --summary all
```

The benchmark defaults to 16 scoped workers; set STWO_RISCV_SYSTEM_BENCH_WORKERS
explicitly for a worker-scaling experiment. `run_proofs.py --canonical` freezes and
compares the latest matching binaries from the current and baseline-mirror caches;
it asserts the recorded 16-worker profile.

Remaining peer system comparisons: complete hash witness/layout/count reduction,
generated AIR/interaction and DEEP/quotient stages, openings/verification, complete
ZisK hash-AIR proofs, then matched recursion levels. Peer-generated proving keys
and equivalent statements/profiles are still required. NVIDIA CUDA measurements
require a CUDA host. Neither the standalone proof here nor the pipeline comparison
replaces that unfinished campaign. Small transcript draws and narrow commitments
remain explicit local optimization targets.
'''
(H/'README.md').write_text(s)
files=['src/core/channel/blake3_frame.zig','src/frontends/riscv/air/guest_precompile/keccakf_authority.zig','src/frontends/riscv/air/guest_precompile/keccakf_witness.zig','src/frontends/riscv/testing/keccakf_proof_harness.zig','src/integrations/riscv_cpu/keccakf_precompile_proof_test.zig','src/integrations/riscv_cpu/build_proof_steps.zig','src/frontends/riscv/zisk_system_benchmark.zig','src/frontends/riscv/zisk_pipeline_benchmark.zig']
for rel in files:
 dest=H/'retained-source'/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(R/rel,dest)
meta=dict(time_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip(),dirty=True,sources={rel:hashlib.sha256((R/rel).read_bytes()).hexdigest() for rel in files})
(H/'provenance.json').write_text(json.dumps(meta,indent=2)+'\n')
