# RV64 M4-M7 campaign protocol (2026-11-04, owner-approved: drive 10x per column through M7)

## Goal (M4-M7)
Execute ~/Coding/ge-wt/rv64-m4-integrate/design/riscv-proving-stack/rv64-gpu-10x-plan.md (the 10x plan). Baseline = M3 integrate
(codex/rv64-cuda-ethereum @ e61851f9e / bcd401ce4): 24628607 51.1 s request, 26235156 34.3 s; full table in
vectors/reports/rv64-m3-20261104/summary.json. Owner wants an order of magnitude on every column, large architectural leaps per
iteration, HPC best practice, and benchmark data in every commit so progress is trackable over time.

## Code
- PR branch: codex/rv64-cuda-ethereum. M7 streams branch from 26ca20793 (M6 integrate): codex/rv64-m7-<stream>, worktrees ~/Coding/ge-wt/rv64-m7-<stream>.
  Integration: codex/rv64-m7-integrate -> fast-forwarded into codex/rv64-cuda-ethereum at the end of each milestone.
- Commit + push often (git push -u origin HEAD). Commit messages end with "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>".
- BENCHMARK DATA IN EVERY PERFORMANCE COMMIT: any commit that changes prover/verifier behaviour or performance includes its receipt(s)
  under vectors/reports/rv64-m7-20261105/<stream>/<block>-<what>.json (+ short .md) AND appends one JSON line per measured run to
  vectors/reports/progress/<stream>.jsonl (one file per stream -> no merge conflicts). Row schema (stream measure owns it, see
  vectors/reports/progress/SCHEMA.md once it exists; until then use these keys): {"date","commit","stream","milestone" (use "M7"),"block",
  "gpus","request_s","capture_s","setup_s","native_s","recursion_s","verifier_s","rss_peak_gib","device_peak_gb","proof_bytes",
  "byte_identical_to","receiver_accepted","label":"M|D|E","notes"}. Commit messages of performance commits put the headline in
  the subject, e.g. "rv64 m4 resident: 24628607 setup 12.6->0.8 s [M]".
- Ownership: each stream is the sole writer of the files listed for it in plan section 6.1. Need a change elsewhere? put it in your
  integration_notes, or make a minimal hook and say so.
- Build throttle on the pod: wrap every zig/nvcc build in flock on one of /workspace/m3/locks/build.{1,2,3}.lock, e.g.
  for i in 1 2 3; do flock -n /workspace/m3/locks/build.$i.lock CMD && break; done  (or flock -w 3600 on build.$((RANDOM%3+1)).lock).
- Disk: /workspace has ~37 GB free (pruned 2026-11-05). Reviewer/adv build copies are the big consumers: delete your own src/build/run copies (and .zig-cache) when you finish. Your build dir is /workspace/m3/build/m7-<stream>; keep it pruned. Do not delete other streams' dirs.
- Timing hygiene: timing runs record the 1-min load average in the receipt; quote numbers from quiet runs; single observations labelled.

## The laptop (36 GB, crashed from OOM before)
Do NOT run big zig builds or tests locally. Edit + git locally; build/test on the pod. If something must run locally, use
~/Coding/ge-ops/bin/memguard run --gb 6 -- <cmd>.

## The pod (2x RTX 5090, 48 vCPU quota, 377 GB RAM, /workspace 80 GB volume)
- Run a command: ~/Coding/ge-ops/bin/pod '<shell command>'   (ssh; keep each call short; long jobs go in tmux, then poll log files)
- Sync sources: ~/Coding/ge-ops/bin/podsync ~/Coding/ge-wt/rv64-m7-<s> m7-<s>   -> /workspace/m3/src/m7-<s> (no .git on the pod)
- Copy back: ~/Coding/ge-ops/bin/podget <remote_path> <local_path>
- Zig 0.15.2: /workspace/zig/zig. CUDA 12.8: /usr/local/cuda/bin/nvcc (sm_120). Use ZIG_GLOBAL_CACHE_DIR=/workspace/m3/cache/zig-global
  and a per-stream local cache in the source dir.
- Long jobs: pod 'tmux new -d -s <name> "<cmd> > /workspace/m3/runs/<s>/<name>.log 2>&1; echo EXIT=\$? >> /workspace/m3/runs/<s>/<name>.log"'
  then poll with pod 'tail -5 ...'. Never wait on monitors that may not fire; poll files.
- GPU LOCK: any job that touches a GPU must run under flock:  flock -w 7200 /workspace/m3/locks/gpu.lock <cmd>   (both GPUs).
  Hold it for at most ~25 minutes per job. CPU-only builds/tests do not need the lock.
- Existing team state lives in /workspace/rv64-gpu-session and /workspace/rv64-* (accepted runtime library assets/library.so sha 25295868...,
  driver assets/ready-fixed-driver sha d5766d83..., full15 harness two-gpu-ready-fixed-full15/, partial monolithic build cache). READ ONLY:
  copy what you need into /workspace/m3/. Never stop or delete pods. Keep /workspace usage under ~60 GB total.
- Shared infra (stream infra) publishes the build/prove recipe in /workspace/m3/RECIPE.md and touches /workspace/m3/READY when a
  from-source driver + CUDA image build and a 2-GPU prove of 24628607 work. Other streams develop host-side until then.

## Acceptance
A block counts as proven only when its root proof is accepted by an independent receiver (separate process, fresh, cache-disabled) and
native proofs verify. Report request wall time and stage breakdown (capture, setup, native prove, native verify, recursion) per block.
Measured vs estimated always labelled. Never claim a number you did not measure.

## Owner rule: no basket loops (2026-11-04)
NEVER re-run the whole 15-block basket (~9,400 s on 1 GPU). Develop and measure ONLY on the small blocks: 26235156 (15.3M instr, the
smallest) and 24628607 (26.9M, the headline). Get the work right there first. Large architectural changes are preferred over long
measurement loops. Scaling up happens once at the end, one block at a time in increasing size order, each block proven once; stop and
fix on the first failure instead of continuing the loop. No stream runs anything bigger than 24628607 except the final integration
agent's ordered scale-up.

M4-M7 note: streams still develop only on 26235156 and 24628607. The integrate agent of each milestone may run the two dev blocks
plus at most ONE larger block (24697070) as a scale probe; the full ordered scale-up happens only at the end (M8), one block at a time.

M5 note: M4 baseline = vectors/reports/rv64-m4-20261104/integrate/ (24628607 28.46 s, 26235156 19.52 s warm resident service, arena on,
byte-identical to M3). Run the M4 harness/service (scripts/rv64_m3_pod.py + resident daemon mode, see vectors/reports/rv64-m4-20261104/
integrate/SUMMARY.md and /workspace/m3/M4-MEASURE.md). Proof-format streams (canon-native, canon-vk, rootverify, outer-gkr,
blake-gadget) introduce NAMED versions/profiles; old formats stay working until integrate switches the default. Shared interface
contracts between M5 streams live in /workspace/m3/M5-INTERFACES.md (append-only sections per stream; read it before changing a boundary).
Disk: /workspace ~34 GB free; each stream keeps build+runs under ~4 GB and prunes as it goes.

## M6 (2026-11-05) — supersedes the M5 note where they differ
Baseline = M5 integrate, codex/rv64-cuda-ethereum @ 95d40063d, vectors/reports/rv64-m5-20261104/summary.json + integrate/ receipts.
Default config (a) old format, resident service warm: 24628607 request 27.4 s (capture 2.5, setup 0.15, native 6.1-6.4, recursion 18.2;
full-tree verify 61.5 s, root-only 13.7 s = native keys 7.3 + native FIXED 4.7 + OM31 root 0.012; proof 706 KB; device peak 31.5 GB
auto / 27.8 GB with STWO_RV64_DEVICE_ARENA=22G; service RSS 32.8 GiB (+5.4 GiB regression from canon-vk class-PP retention);
syncs 10.7k, pageable copies 0, launches 223k; recursion GPU busy 39.8%; host prep per node 1.8-3.0 s leaves / 1.0-1.5 s folds).
26235156 request 17.8-20.5 s. Scale probe 24697070 74.8 s.

THE M5 LESSON (binding for M6): M5 built many correct pieces (outer GKR section + in-circuit verifier, fused Blake AIR, native GKR v1
reference, chi chain, canonical profiles, root-only verify) but most were NOT SWITCHED ON in the prover, so request time did not move.
In M6 a stream is done only when its change runs IN THE PRODUCTION PROVER/RECEIVER on BOTH dev blocks end to end, with measured
request/stage times, a fresh-receiver acceptance (proof-format streams) or byte identity (scheduling streams). Reference-only or
model-only results do not count as done; if you cannot get there, say so precisely and leave the hook behind a flag.

Other M5 data to respect: fused Blake as designed is a NET LOSS in the tree (3 power-of-two instances per node; one instance per node
gives x0.93/x0.76 at q108/q51); a single uniform fold VK costs +10-23% recursion (set-v2 +4% is the preferred canonical shape);
4-ary folds and the q51 outer profile OOM on GPU (18.4 GB composition / 23.7 GB interaction LDE); outer GKR GPU prover needs 26.9 GB
unfused; native INTER is 7.8k bits/gas (15.6k LDE) vs ZisK 28.3k; native-gkr v1 (codex/rv64-m5-native-gkr @ 2fc4b878b) -> INTER x0.487,
Keccak truth 743 M cells is the largest item; canon-native (codex/rv64-m5-canon-native @ 3ab539067) not merged: A1 (chain vkhash hashes
the segment declaration, T_nat hashes the rung vector) needs the strict roster.

M6 targets on 24628607 (plan section 5, with the diet pulled in): request <= 12 s (stretch 8), native <= 2.0 s, recursion <= 8 s
(stretch 5), capture <= 1.0 s, root-only verify <= 1.5 s, derive <= 30 s, recursion GPU busy >= 70%, launches per node <= 500,
syncs per node <= 10, host prep per node <= 0.1 s, H2D <= 80 B/instruction, no host replay, device peak <= 28 GB, RSS <= 20 GiB.

Interfaces: /workspace/m3/M6-INTERFACES.md (append-only sections per stream; create it if missing, copy forward anything still live
from M5-INTERFACES.md). Proof-neutral streams stay byte-identical to the M5 default (= M3/M4 receipts). Proof-format streams use NAMED
versions and are composed by integrate. Disk: keep each stream under ~4 GB on /workspace and prune as you go.

## M7 (2026-11-05) — supersedes the M6 note where they differ
Baseline = M6 integrate, codex/rv64-cuda-ethereum @ 26ca20793, vectors/reports/rv64-m6-20261105/summary.json + integrate/ receipts and
gate.sh (use its steps). DEFAULT FORMAT CHANGED in M6: STWO_RV64_OUTER_PROFILE=m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1 (4-ary folds
+ fold Merkle cap 3) is set by scripts/rv64_m3_pod.py DEFAULT_PRODUCER_ENV; byte-identity checks compare against the M6 default receipts
(or pass --env STWO_RV64_OUTER_PROFILE=r1 for M5 bytes). Receivers take the format from the run plan.
M6 default, warm resident service, 24628607: request 18.2-19.2 s (capture 2.07, setup 0.15, native 4.45, recursion 11.35 harness stage,
tail after last leaf 2.15), 23 nodes, root-only verify 1.41 s, derive 28.3 s, full-tree verify 49.4 s, proof 708,696 B, RSS 33.5 GiB,
device peak 31.5 GB (27.8 with 22G arena, +0.9 s), recursion-window kernel busy 41.6%, 82.4k launches + 6.8k syncs per request,
123.5 blocking calls and 1,774 launches per node. 26235156: 13.2 s (native 3.12, recursion 8.07, tail 1.36). 24697070: 73.5 s one-shot cold.

What M6 measured about the remaining time (the M7 design must attack these):
 1. Recursion is HOST-LATENCY bound, not GPU bound: diet-wire's k4-cap3 cut recursion cells x0.69 and GPU time 23-34% but wall moved little.
    Leaves still build the verifier graph + host DAG plan (1.6-2.1 s each; first wave ~1.5 s before any device work); the leaf DAG is
    serial-depth bound (146k levels, 101k of them Blake-G levels of width ~26, 0.77 us/level, 113 ms). Fold seed tape works (fold host prep
    0.39 -> 0.027 s) but cold fold classes (incl. the root fold) still cost 1-2.7 s. 2 proofs per GPU fails (needs per-lane trace-commit and
    composition contexts). Device transcript and CUDA graphs were not built.
 2. Native 4.4 s vs 2 s: H2D 213-223 B/instr, owner-thread idle 1.1-2.0 s per GPU, kernel busy only 1.5-2.4 s per GPU. GPU witness
    widening not built. Native v2-strict (opt-in, accepted, corpus-clean) is SLOWER today (+16-22% cells: rung padding 610 M on 607,
    terminal alone +220 M) and NOT TOTAL (no cpu_single rung; cpu_last only covers cpu_log 20-22). v2-gkr (native GKR in production)
    not built: needs CUDA batch_max_oracles 128 (device job buffer; first retry the nvcc -shared link with TMPDIR on /workspace).
    [D] v2-gkr on strict classes: INTER 2,270.7 -> 1,124.2 M on 607, Keccak truth 742.8 -> 110.4 M; mass gate must use source-bound masses.
 3. Outer LogUp-GKR NOT wired: review item DW-R1 reopened because the eq column E is unconstrained; the succinct auxiliary evaluator is owed.
    One-instance fused Blake, set-v2 folds, fold v3 in-circuit not built; q51 outer profile still OOMs (304-col interaction LDE 23.7 GB).
 4. Capture 2.0-2.2 s: image/program init 0.5 s, batch-0 admission + CPU capture ~0.45 s, serial ledger ~0.5 s (shard 0 225 ms).
 5. First request per block pays cold setup 8.6-10.7 s with --store none; RSS floor 18-20 GiB between requests.
 6. Retention is all-or-nothing per device (>4 CPU segments per GPU -> replay-all), so large blocks lose native-stream's gain.

M7 targets on 24628607 (plan section 5 M7, adjusted): request <= 8 s (stretch 6), recursion <= 4 s with tail <= 2 s, native <= 2 s,
capture <= 1.0 s (stretch 0.6), final proof <= 120 KB (stretch 100), root-only verify <= 1 s, recursion-window GPU busy >= 70%,
committed cells per leaf <= 0.5 G, nodes <= 10, RSS <= 20 GiB, device peak <= 28 GB, cold first request <= 3 s setup.
Interfaces: /workspace/m3/M7-INTERFACES.md (append-only; create it; copy forward anything still live from M6-INTERFACES.md).
