export const meta = {
  name: 'rv64-m7',
  description: 'RV64 GPU 10x plan, iteration 4: M7 kill host latency in recursion (GPU leaf tape, device transcript + CUDA graphs, 2 proofs/GPU), wire outer + native GKR, two-stage compress to ~100 KB, native witness on GPU, fast capture, service cold-start/RSS; adversarial checks; integration with tracked benchmarks',
  phases: [
    { title: 'Build', detail: 'ten streams in parallel on 2x5090, dev blocks only, everything switched on in the prover' },
    { title: 'Check', detail: 'adversarial: forgery attempts on new formats, GKR/compress soundness, byte identity + memory safety on pipeline streams' },
    { title: 'Integrate', detail: 'merge, compose, gates, one scale probe, default decision, ledger, push, PR comment' },
  ],
}

const COMMON = `
You are a senior GPU/HPC + ZK systems engineer on stwo-zig's RV64 Ethereum prover (CUDA, Circle STARK over M31, OM31 recursion).
Owner goal: an ORDER OF MAGNITUDE on every column (request, capture, setup, native, recursion, verifier, RAM, proof size) via LARGE
architectural leaps (not small greedy tweaks), HPC best practice, and benchmark data in every commit so progress is trackable.
FIRST read in full:
 - ~/Coding/ge-cache/rv64-m4/PROTOCOL-M7.md (binding: pod access, sync, GPU lock, build throttle, branches from 26ca20793,
   benchmark-in-every-commit, progress ledger vectors/reports/progress/<stream>.jsonl with milestone "M7", NO-BASKET-LOOPS, acceptance,
   interface file /workspace/m3/M7-INTERFACES.md, THE M5 LESSON (done = switched on in the production prover on both dev blocks), the M6
   default-format change (k4-cap3), and the six measured M6 time sinks you must attack).
 - design/riscv-proving-stack/rv64-gpu-10x-plan.md (section 3 frontier lessons: ZisK, Airbender, zkDTVM; section 5 M6/M7).
 - vectors/reports/rv64-m6-20261105/summary.json, integrate/ receipts and gate.sh, /workspace/m3/M6-INTERFACES.md, and the M6 stream
   design notes design/riscv-proving-stack/rv64-m6-*.md relevant to you.
Rules: develop/measure ONLY on 26235156 and 24628607. Proof-format changes need a NAMED version/profile, the written argument
(design/riscv-proving-stack/*.md), fresh-receiver acceptance (separate cache-disabled process) and the negative corpus
(scripts/rv64_m5_negative_corpus.py + stream corpora). Scheduling-only changes stay byte-identical to the M6 default receipts.
Never weaken security (conjectured-128 everywhere). Build/test on the pod (flock build locks; GPU work under the GPU lock, <= ~25 min
per hold, release between runs). Publish your interface in M7-INTERFACES.md within ~45 minutes. Every performance commit: receipt +
progress row, headline in the subject. Push often. Delete your own pod build/src copies and .zig-cache when done (disk is shared,
~37 GB free). Time box ~6 hours. Stop at a coherent, tested, pushed state; report precisely; never claim unmeasured numbers; label [M]/[D]/[E].
`

const REPORT = { type: 'object', properties: {
  branch: { type: 'string' }, head_sha: { type: 'string' },
  done: { type: 'array', items: { type: 'string' } },
  measured: { type: 'array', items: { type: 'string' } },
  tests: { type: 'array', items: { type: 'string' } },
  proof_change: { type: 'string' },
  switched_on: { type: 'string', description: 'exactly what runs in the production prover/receiver now, on which blocks, behind which flag' },
  caveats: { type: 'array', items: { type: 'string' } },
  integration_notes: { type: 'array', items: { type: 'string' } },
}, required: ['branch', 'head_sha', 'done', 'measured', 'tests', 'proof_change', 'switched_on', 'caveats', 'integration_notes'] }

const CHECK = { type: 'object', properties: {
  verdict: { type: 'string', enum: ['sound', 'issues', 'broken'] },
  issues: { type: 'array', items: { type: 'object', properties: {
    severity: { type: 'string' }, claim: { type: 'string' }, evidence: { type: 'string' }, fixed: { type: 'boolean' } },
    required: ['severity', 'claim', 'evidence', 'fixed'] } },
  head_sha: { type: 'string' }, summary: { type: 'string' },
}, required: ['verdict', 'issues', 'summary'] }

const STREAMS = [
{ key: 'leaf-tape', check: 'bytes', prompt: `
STREAM leaf-tape (owns om31_native/fold_tape.zig + a new leaf tape, outer_assignment.zig, assignment_runs.zig, native_capture.zig,
circuit_fill_*.cu). Worktree ~/Coding/ge-wt/rv64-m7-leaf-tape, branch codex/rv64-m7-leaf-tape.
Big leap: LEAVES WITHOUT A HOST GRAPH AND WITHOUT A SERIAL-DEPTH DAG. Today each leaf builds the verifier graph + host DAG plan (1.6-2.1 s;
first wave ~1.5 s before any device work) and its device DAG has 146k dependency levels (101k Blake-G levels of width ~26) costing 113 ms.
(1) Leaf seed tape, like the fold seed tape: emit the leaf's guessed words directly from the converted native capture and pair them with a
class template; make leaf classes shareable (strict-roster / canonical leaf geometry where it exists; otherwise cache per (family, shape)).
(2) Break the serial depth: fill Blake columns with a dedicated kernel that recomputes every compression from its recorded inputs in one
wide launch (the native verifier already knows every Blake input/chaining value - record them in the tape), the same for Merkle paths and
FRI folds; the DAG keeps only the genuinely dependent arithmetic. Target ~11 fill kernels per node. Also make cold fold classes (root fold)
cheap: precompute class templates at service start / from the store. Gate: byte-identical to the M6 default on both dev blocks, host prep
per node <= 0.1 s for leaves AND folds (warm and first request), leaf fill device time, recursion and request time in the resident service.` },
{ key: 'device-graph', check: 'bytes', prompt: `
STREAM device-graph (owns outer_source*.zig, trace_commit.zig, pcs_native.{zig,cu}, channel.cu, transcript.cu, graph capture, the sync
lint, per-lane prover contexts). Worktree ~/Coding/ge-wt/rv64-m7-device-graph, branch codex/rv64-m7-device-graph.
Big leap: ENQUEUE-ONLY OUTER PROVE + 2 PROOFS PER GPU (Airbender contract, M6 left undone). Today 123.5 blocking calls and 1,774 launches per
node, recursion-window kernel busy 41.6%. (1) Device-side Fiat-Shamir (Blake2s channel on the GPU, or cudaLaunchHostFunc fallback) so
commit -> interaction -> composition -> OODS -> DEEP -> FRI -> decommit never blocks the host; (2) one captured CUDA graph per class replayed
per node (poison per-proof pinned regions); (3) per-lane trace-commit and composition contexts so STWO_RV64_RECURSION_LANES_PER_DEVICE=2
works within the 22 GiB arena (2 nodes in flight per GPU hide each other's gaps); (4) sync lint test. Gate: byte-identical to the M6 default,
transcript parity GPU vs CPU per class, <= 10 blocking calls and <= 500 launches per node, recursion-window GPU busy >= 70%, recursion and
request time in the resident service, device peak <= 28 GB. Coordinate with leaf-tape (fill kernels go into the same graph).` },
{ key: 'outer-gkr', check: 'gkr', prompt: `
STREAM outer-gkr (proof change; sole owner of recursion circuit construction: om31_native/{execution_wrap,outer_wrap,proof}.zig,
rv64_recursion/om31_outer.zig, the outer GKR and fused Blake hooks - fold_tape.zig record must be updated in the same commit as any guess
change, see M6 merge hygiene). Worktree ~/Coding/ge-wt/rv64-m7-outer-gkr, branch codex/rv64-m7-outer-gkr.
Big leap: OUTER LogUp-GKR AND ONE-INSTANCE FUSED BLAKE SWITCHED ON in every leaf and fold of the k4-cap3 tree. Close DW-R1 first (the eq
column E is unconstrained: constrain it, or derive it with the succinct auxiliary evaluator the review owes) and get it re-reviewed in
M7-INTERFACES. GPU GKR with fused projection so it fits next to the 22 GiB arena (unfused it needed 26.9 GB). Fused Blake2s as ONE instance per
node (3 power-of-two instances was a net loss). Then retry the m3_b4_q51_p26 outer profile for folds/root now that interaction width drops
(the 304-column interaction LDE was the OOM). Named profile building on k4-cap3. Gate: both dev blocks prove end to end with the diet on,
fresh receiver accepts (full tree and --audit), corpus incl. GKR + Blake tamper cases clean, MEASURED committed cells per leaf (target <= 0.5 G),
recursion GPU-s, recursion and request time, proof bytes, device peak.` },
{ key: 'native-gkr', check: 'native', prompt: `
STREAM native-gkr (proof change; owns services/gkr_local/*, services/native_gkr/*, manifest.zig, the native AIR binding, the rung table and
the native receiver path). Worktree ~/Coding/ge-wt/rv64-m7-native-gkr, branch codex/rv64-m7-native-gkr.
Big leap: NATIVE LogUp-GKR IN PRODUCTION (v2-gkr) and a native format that is FASTER than flat, not slower. (1) CUDA batch_max_oracles 64 ->
128 through a device job buffer (first retry the nvcc -shared link with TMPDIR on /workspace); (2) v2-gkr end to end on the strict classes:
drop the classic global/truth columns, GKR roots carry the global claims, source-bound mass gate (the conservative 2^35 bound is >= p), Keccak
truth fully under GKR; (3) make v2 TOTAL (cpu_single rung, finer cpu_last) and cut the rung padding tax (610 M cells on 607; terminal +220 M)
- e.g. finer rungs or per-component rung choice - so v2 commits fewer cells than flat overall; (4) retention that works for large blocks
(byte-budgeted per device instead of all-or-nothing). Gate: both dev blocks prove under the new named version in the production GPU prover,
fresh cache-disabled receiver accepts, corpora clean, measured native committed cells (target INTER x0.5 vs flat), native time faster than
flat, proof bytes, device peak; plus a capture-only/native-only check that 24697070 still fits.` },
{ key: 'native-witness', check: 'bytes', prompt: `
STREAM native-witness (owns riscv_cuda/rv64/{cpu_replay,cpu_projection}.zig, the *_witness.cu family, streaming commit, native graphs;
coordinate the native AIR boundary with native-gkr). Worktree ~/Coding/ge-wt/rv64-m7-native-witness, branch codex/rv64-m7-native-witness.
Big leap: NATIVE <= 2 s ON 24628607 (today 4.45 s) by moving witness generation onto the GPU (ZisK gpu-witness): upload compact
per-instruction records + a per-image decode table once, widen to every native trace column on the device (H2D 213-223 -> <= 80 B/instr),
streaming commit (unpack -> LDE -> hash per column chunk), native CUDA graphs per class, and kill the owner-thread idle (1.1-2.0 s per GPU;
kernel busy only 1.5-2.4 s per GPU). Gate: byte-identical native and root proofs vs the M6 default on both dev blocks, native time warm,
H2D bytes/instruction, GPU busy in the native window, device peak.` },
{ key: 'compress', check: 'compress', prompt: `
STREAM compress (proof change; owns the C1/C2 compress provers and the compressed final-proof container; circuit shape requests go through
outer-gkr). Worktree ~/Coding/ge-wt/rv64-m7-compress, branch codex/rv64-m7-compress.
Big leap: FINAL PROOF 708 KB -> <= 120 KB (stretch 100) WITHOUT SNARK WRAPPING (pure Circle STARK; the owner rules out SNARKs). Build the
two-stage compress on the k4-cap3 root: C1 b8_q36_p20 on a narrow circuit verifying the root, then C2 (profiles' rv64-m7-compress-profiles.md:
b16_q27_p20 or b64_q18_p20_fold3; FRI fold 8/16, Merkle caps, multiproof dedup, pruned last FRI layer), with PROFILES entries and the written
conjectured-128 arithmetic. A fresh compressed-proof receiver (root-only style, VK tables derived from a pinned commit). Keep the C2 tail
small: run C1/C2 as soon as the root exists, overlap where possible. Gate: both dev blocks, compressed proof bytes, compress time (tail added
to request), fresh receiver accepts, verify time, tamper corpus clean. Kill: if the C2 tail > 2.5 s, ship it as an async compact proof.` },
{ key: 'fold-circuit', check: 'binding', prompt: `
STREAM fold-circuit (proof change; owns rv64_recursion/{fold_root,root_admission,leaf_statement}.zig, root_verify*, derive-vk-tables).
Worktree ~/Coding/ge-wt/rv64-m7-fold-circuit, branch codex/rv64-m7-fold-circuit.
Big leap: FOLD v3 IN-CIRCUIT so root-only is the acceptance path (no --audit), plus set-v2 canonical fold classes so cold fold classes (incl.
the root fold, 1-2.7 s host prep today) are shared across blocks. T_rec membership, the NS interval chain with the seg_lo range check, PCD
self-VK (vk_fold public input), every receiver-side check moved in-circuit, for k-ary (k<=4) with null slots and caps. Root-only verify
<= 1 s (today 1.41 s: image/program 0.38, native key restore 0.49, admission 0.43), derive <= 20 s. Gate: both dev blocks prove end to end,
fresh root-only receiver accepts with stores deleted, --audit agrees, corpora clean, recursion time impact measured.` },
{ key: 'capture', check: null, prompt: `
STREAM capture (capture 2.07 s on 24628607 -> <= 1.0 s, stretch 0.6). Worktree ~/Coding/ge-wt/rv64-m7-capture, branch codex/rv64-m7-capture.
Measured critical path: image/program init 0.5 s (cache per image in the resident service), batch-0 admission + CPU capture ~0.45 s, serial
ledger ~0.5 s (shard 0 225 ms: sponge 97 ms, bulk 86 ms, first touch 68 ms, LS 39 ms) -> two-phase / sharded parallel ledger, finish 0.05 s.
Then the AOT/JIT RV64 emulator with checkpoints (ZisK/Airbender) only if it is on the critical path. Also tighten the per-segment ready hook so
segment 0 reaches native earlier (1.2 s today). Byte-identical captured values and proofs; capture time per block with receipts.` },
{ key: 'service', check: 'bytes', prompt: `
STREAM service (owns the resident service, ArtifactStore, arena carve, pool policy, RSS). Worktree ~/Coding/ge-wt/rv64-m7-service, branch
codex/rv64-m7-service. Big leap: A SERVICE THAT IS FAST ON THE FIRST REQUEST AND LEAN. Today the first request per block pays 8.6-10.7 s cold
setup with --store none, RSS is 33.5 GiB with an 18-20 GiB floor between requests, and device peak 31.5 GB (27.8 with the 22G arena at +0.9 s).
Deliver: an install step that precomputes and persists every per-image class artifact (native FIXED per strict class, recursion class
PP/plans/templates, VK tables) so a never-seen block's first request costs <= 3 s setup; RSS <= 20 GiB peak (find and drop the retained
host copies; per-request arenas); 22G arena with no time cost (default on). Gate: byte-identical to the M6 default, cold-first-request and
warm timings, RSS and device peak.` },
{ key: 'profiles', check: null, prompt: `
STREAM profiles (sole owner of om31_security_candidate.zig PROFILES and soundness notes; corpus owner). Worktree
~/Coding/ge-wt/rv64-m7-profiles, branch codex/rv64-m7-profiles. (1) Second reviewer of: outer-gkr's DW-R1 fix and wired GKR/fused Blake
profile, native-gkr's v2-gkr + rung changes, compress C1/C2, fold-circuit's in-circuit fold v3; sign off or reopen with concrete cases.
(2) PROFILES entries + conjectured-bit arithmetic tests for every new profile. (3) Extend the negative corpus to every new format and run it
against the other streams' branches periodically; publish case IDs in M7-INTERFACES. (4) M8 prep: a written analysis (with numbers from the
receipts) of the next protocol levers: D2 native b4_q54_p20, larger canonical rungs / batched services, recursion arity 8, and a multilinear
(WHIR/Basefold-style) recursion alternative per plan 3.5's S-ML trigger.` },
]

const CHECKS = {
  native: (r) => `Adversarial soundness check of the new native protocol (branch ${r.branch} @ ${r.head_sha}). Report: ${JSON.stringify(r)}.
You are a senior ZK cryptographer. Try to FORGE native proofs under the new version: dropped/relabelled relation groups, unbound global claims
in GKR roots, mass/characteristic bound (source-bound masses), transcript order, strict draws, binding residual vs MAIN, rung padding rows,
chain/vkhash vs T_nat, cross-block/segment replay. Run concrete tamper cases with a fresh receiver (GPU only under the lock, on 26235156).
Check completeness on both dev blocks. Fix high-severity issues on the branch (commit+push) and report.`,
  gkr: (r) => `Adversarial soundness + completeness check of the wired outer GKR + fused Blake (branch ${r.branch} @ ${r.head_sha}). Report:
${JSON.stringify(r)}. Check DW-R1 (eq column E) is truly closed, the in-circuit GKR verifier (transcript binding, strict draws, range checks,
class constants vs proof-supplied shape), the one-instance fused Blake (XOR table order, padding, completeness vs reference Blake2s), k-ary
null slots and caps, and that the MEASURED savings are real. Run tamper cases with a fresh receiver. Fix high-severity issues on the branch
(commit+push) and report.`,
  compress: (r) => `Adversarial soundness check of the two-stage compress (branch ${r.branch} @ ${r.head_sha}). Report: ${JSON.stringify(r)}.
Check the C1/C2 profiles' conjectured-128 arithmetic (q*log2(blowup)+pow, FRI fold 8/16 proximity), Merkle caps and multiproof dedup
(missing or duplicated openings), pruned last FRI layer, that C1 really verifies the root statement and C2 binds C1's statement, VK tables
from a pinned commit, and the fresh receiver. Construct and run tamper cases. Fix high-severity issues on the branch (commit+push) and report.`,
  binding: (r) => `Adversarial soundness check of fold v3 in-circuit + the standalone root-only receiver (branch ${r.branch} @ ${r.head_sha}).
Report: ${JSON.stringify(r)}. You are a senior ZK cryptographer. Try to FORGE: any statement field, VK, class key, NS interval, null slot,
vk_fold, cap, native VK-table entry or derived table that is unbound or checked only outside the circuit; table authenticity; unknown
profiles; k-ary null-slot tricks. Construct and run concrete tamper cases. Fix high-severity issues on the branch (commit+push) and report.`,
  bytes: (r) => `Adversarial check of a proof-neutral pipeline/service stream (branch ${r.branch} @ ${r.head_sha}). Report: ${JSON.stringify(r)}.
Rebuild from the branch on the pod, re-prove 26235156 and 24628607 under the GPU lock in the resident service and compare every proof hash to
the M6 default receipts; hunt memory-safety and concurrency bugs (buffer reuse before completion, graph replay with stale parameters,
device-transcript divergence, arena aliasing between concurrent lanes, store corruption/staleness, races); reproduce the claimed counter and
time reductions with paired A/B on a quiet-as-possible pod. Fix high-severity issues on the branch (commit+push) and report.`,
}

phase('Build')
const results = await pipeline(
  STREAMS,
  (s) => agent(`${COMMON}\n${s.prompt}`, { label: `build:${s.key}`, phase: 'Build', schema: REPORT }),
  (r, s) => (!r || !s.check) ? { key: s.key, build: r } :
    agent(`${COMMON}\n${CHECKS[s.check](r)}`, { label: `check:${s.key}`, phase: 'Check', schema: CHECK })
      .then(c => ({ key: s.key, build: r, check: c })),
)

phase('Integrate')
const integ = await agent(`${COMMON}
STREAM integrate. Worktree ~/Coding/ge-wt/rv64-m7-integrate, branch codex/rv64-m7-integrate. Stream results and checks:
${JSON.stringify(results)}
1. Merge streams whose checks left no unfixed high-severity issue. Order: capture, profiles, service, native-witness, leaf-tape,
   device-graph (proof-neutral), then native-gkr, fold-circuit, outer-gkr, compress. Resolve conflicts preserving intent; note each.
2. Gate on 26235156 then 24628607 in the resident service, warm AND first-request-cold, with paired A/B against the M6 default in the same
   session (run on as quiet a pod as you can get; record load):
   (a) pipeline config, M6 default format: byte-identical to the M6 default receipts;
   (b) the full M7 format composed with the pipeline: native GKR + wired outer GKR/fused Blake (+ q51 if it fits) + fold v3 in-circuit +
       compress: fresh root-only and compressed receivers accept with stores deleted, --audit agrees, all corpora reject every case.
   Report every column per config (request, capture, setup cold/warm, native, recursion, tail, compress tail, root-only and compressed verify,
   full-tree verify, derive, RSS, device peak, root and final proof bytes, launches/syncs per node, H2D B/instr, GPU busy) vs M3/M4/M5/M6 and the
   M7 targets. Then ONE scale probe on 24697070 with the best config.
3. Decide the default (best config that passes every gate), set it in code, write it down.
4. Record vectors/reports/rv64-m7-20261105/summary.json (+ SUMMARY.md if writable), progress rows, regenerate progress/PROGRESS.md; commit with
   headline numbers in the subject; push; fast-forward codex/rv64-cuda-ethereum; post a concise PR #314 comment (gh) with the table.
5. Prune your pod spools/nsys files at the end.
6. integration_notes: exact M8 entry state, gaps vs targets, and the 3-5 biggest remaining time sinks per column with measured numbers.`,
  { label: 'integrate', phase: 'Integrate', schema: REPORT })

return { results, integ }
