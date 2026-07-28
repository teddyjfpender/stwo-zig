# Session 12 — increment 3.11: the epoch-fusion census, and the 30x pricing error it found

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.
Workspace `/private/tmp/stwo-zig-cairo-native-throughput-10x`, branch
`autoresearch/cairo-native-throughput-10x`, head at start `804a50bb` (clean, pushed).
Audit/pricing increment: no product change, single packaging commit, and the tree
stayed untouched until it — the external metallib delivery could have preempted
this work at any point without losing anything.

## The brief

Turn "collapse 74-79 submissions" into an ordered work plan: census every
host-blocking command-buffer submission in one big and one small workload,
classify each boundary as Fiat-Shamir-forced / host-compute-forced /
structural, map the 13 transcript round trips, price three tiers of recovery
against increment 3.5's ~0.17 ms dispatch floor, and refine Phase 0's claim that
epoch fusion is the mechanism behind the `1.632x → 1.971x` step.

## What made it measurable without touching the tree

Two instruments, both in `/private/tmp/i311/`:

- **`submit_cost.m`** — a standalone Metal program that prices one host-blocking
  submission four ways (N blocking; one buffer with N dispatches; N committed
  with one wait; N with completion handlers), with and without real GPU work and
  with and without host compute between submissions.
- **`subcount.m`** — a `DYLD_INSERT_LIBRARIES` shim that swizzles the concrete
  `MTLCommandBuffer` / `MTLComputeCommandEncoder` classes inside the **shipping**
  `stwo-cairo-metal` process and records every `commit`, every
  `waitUntilCompleted` with its duration, every dispatch, and a full timeline.

The second one is the increment. It turned a census that would otherwise have
been structural inference into a measurement, and the instrumented proofs came
out byte-identical (`79ae76e1…`, `25e5719f…`), which is the check that the
observation did not change the thing observed.

## The four findings, in the order they changed the conclusion

1. **`metal_dispatches` is not a submission count.** It sums twelve counter
   fields (not Phase 0's ten), over-counts fused epochs — `commitFriLineCascade`
   ticks `2 + layer_count` times for one command buffer — and cannot see the
   12-16 blocking submissions in `transcript_decommitment.m` at all. Measured:
   **53 commits / 52 waits** on all-opcodes and **51 / 50** on arithmetic-2m,
   against a reported 75 and 74, carrying 675 and 635 kernel dispatches. The
   pipeline is already ~13 kernels per submission.
2. **A submission costs 0.169 ms, additively.** The single-blocking-submission
   measurement, 0.1735 ms, independently reproduces 3.5's 0.1763 ms
   "per-dispatch floor" — so that floor was never kernel time; it was the round
   trip, which closes a question 3.5 left open. With 0.73 ms kernels the
   overhead is still 0.171 ms per submission, i.e. it does **not** hide behind
   GPU work.
3. **Fusion is worth 1.2-3.0% of prove.** 38.4 ms on all-opcodes, 24.3 ms on
   arithmetic-2m, at the ceiling where only the six genuine Fiat-Shamir
   boundaries remain. Substituted into Phase 0 §2.2's `@S + caches` column the
   four-row geomean goes 1.632x → **1.680x**, against a 1.768x bar. To have
   delivered 1.971x it would have had to recover 149-207 ms, i.e. 924-1,284
   collapsible submissions. There are 44-46. **Phase 0 §6.6 was off by ~20-30x**,
   and it was off because it read `74` as a submission count and never priced a
   submission.
4. **The prize is in not blocking, not in fusing.** Committing N separate
   command buffers and waiting on the last recovers 93% of what merging them
   into one buffer recovers (0.0115 vs 0.0053 ms per boundary), and on the same
   in-order queue it costs the same wall time with real kernels. Tier (ii) and
   tier (iii) differ by 0.3 ms. So the plan's expensive item — restructuring
   encoders — should not be built.

## The finding that was not in the brief

`proof_of_work` is a Fiat-Shamir boundary whose cost is host *computation*:
`channel.grind(24)` on the CPU, no grind kernel anywhere in the shaders. It is
**110.3 ms on all-opcodes and 145.5 ms on arithmetic-2m** this session (81.5 /
112.8 in Phase 0) — four to six times the entire epoch-fusion programme on the
same two rows, and unlike fusion it disturbs no existing submission site. Phase 0
listed "a PoW kernel" third in the Phase 3 bundle. The order should be inverted,
and because it needs a new kernel it should ride the pending metallib mint rather
than be scheduled on its own.

It is bimodal like witness: ~6% on all-opcodes and arithmetic-2m, 0.2-0.5% on
pedersen and memory-7m. A two-row lever, stated as one.

## Corrections to the record

- Phase 0 §6.6's "74-79 blocking host↔device round trips per proof" → **51-53
  submissions, 50-52 blocking waits**.
- Phase 0 §6.3.3's "`metalDispatchTotal()` sums exactly ten counters" → twelve;
  the relation and composition counters were added since, and the test at
  `telemetry.zig:505-527` records it.
- Phase 0 §6.5's "13 sequential round trips" for `bootstrapThroughBase` → **11**
  for the loop, 12 including `initialize`, 14 before `z, alpha` exist. Everything
  else in §6.5 — the per-op command buffer, the four line references, the
  UMA-pointer-read characterisation of the root, the CPU-PoW attribution, the
  missing `encodeRelation` — checks out exactly.
- And the boundary that §6.5 did not draw: the resident transcript is **not on
  the product path**. The shipping proof mixes and draws on the host; zero of the
  measured 51-53 submissions is a transcript op. The 12 decommit ops in the same
  file *are* on the product path and are invisible to the counter.

## The thing that would have gone wrong

Device composition **adds** submissions, and the committed hook adds them in the
worst shape available: `composition_stage.zig:430-434` is one blocking submission
per plan handle, inside a loop. Increment 3.6 measured all-opcodes composition at
75 per-part dispatches — so Phase 1 landing as written adds ~75 blocking
submissions to a proof that makes 53, **+12.7 ms**, which is more than the 1.106x
kernel-fusion benefit 3.6 credited on that row. Batching the loop is a small
change now and a regression hunt later, so it is plan item #2, ahead of every
other fusion item.

## What was not done

No gate other than the Metal build was run, because there is nothing to compile —
the diff is two documents. Two of four workloads were instrumented; pedersen and
memory-7m tier-(iii) values in §6 are scaled estimates and are flagged as such.
Host load was elevated (loadavg 10.9-13.0), so every price is computed against
Phase 0's stage table rather than this session's, which errs toward
over-valuing fusion rather than under-valuing it. Per-stage attribution of
submissions is anchored to the first device stage and cross-checked against the
host-only stages; the totals are exact, the split is good to about a stage
boundary. And the census establishes that 44-46 of 50-52 boundaries carry no
*semantic* requirement — it does not establish that nothing reads arena bytes
behind a submitted-but-unwaited buffer, which is the first thing plan item #3 has
to prove.

## What the successor should take

1. **Correct §6.6 in place**, and note that the program remains 5.3% short of
   1.768x with fusion counted at its measured value. Phase 0 §2.3's "a fourth
   lever must be held in reserve" stands, unrelieved — fusion was that reserve
   and it is now spent.
2. **Plan items #1 and #2 together**: make `metal_dispatches` mean submissions
   (the `CommandEpoch.Stats` ABI already carries `command_buffers` and
   `wait_count`), and batch the per-plan composition submissions before Phase 1
   ships. Half an increment for both.
3. **Re-scope Phase 3 around proof-of-work**, and do not build
   `MTLSharedEvent` / `MTLFence` / a second queue: the census found no
   cross-buffer GPU→GPU dependency that in-order single-queue semantics do not
   already provide.
