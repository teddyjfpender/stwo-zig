# Session 13 — increment 3.12: one submission per component, not per part

Implementation: Claude Opus 5. Orchestration: Claude Fable 5.
Workspace `/private/tmp/stwo-zig-cairo-native-throughput-10x`, branch
`autoresearch/cairo-native-throughput-10x`, head at start `d385ffd9` (clean).
Small pre-gate fix, 45-minute budget, **preempted by the #124 metallib delivery
during verification**.

## The brief

Increment 3.11's work-plan item 2: `composition_stage.zig` submitted and blocked
once per component plan, which §3.11 priced at ~75 × 0.169 ms = +12.7 ms on
all-opcodes — a regression Phase 1 would land the moment the hook was enabled.
Restructure so the stage's eval dispatches encode into one command buffer,
submitted once and waited once, with semantics unchanged and the hook still off.

## What made this small

The primitive already existed and I did not have to write any Metal. Searching
for the batching shape before designing one turned up
`prepareEvalBatch` / `evalBatchPrepared`, whose Objective-C side
(`dynamic_evaluation.m:607-680`) is exactly the target: one command buffer, one
compute encoder per plan, one `commit`, one `waitUntilCompleted`. It was already
in use by the composition front path (`arena_binding.zig:1447`) and by
`execution_graph_test.zig:540`. The brief's instruction to follow the FRI
quotient's established pattern rather than invent one turned out to be
satisfiable literally: the batch call *is* that pattern, already wrapped.

So the increment reduced to lifecycle plumbing: prepare a batch per component at
admission, deinit it with the entry, and replace the dispatch loop with one call.

## The two things worth being careful about

**Ordering.** The kernels accumulate across parts into shared coordinate words —
the code says so at the `@memset` that zeroes the planes. Batching would be wrong
if the encoders raced. They do not: separate compute command encoders within one
`MTLCommandBuffer` execute in encode order, so the accumulation is preserved.
Had the batch used one encoder with `MTLDispatchTypeConcurrent`, this change
would have been unsound; it does not.

**Telemetry.** The tempting move is to make `metal_composition_eval_dispatches`
count submissions now. That would be wrong twice over: the dispatch count did not
change (each part still gets a dispatch), and §3.11 plan item 1 flags this
counter as governance-visible in released evidence JSON. So the counter records
per part exactly as before, and the new submission count is a session-local field
that only reaches the debug log. The log line now reads
"N dispatches in M submissions", which is the whole point of the increment made
visible in one string.

## Where the failure attribution went

`metal-test` came back 75/79 with two failures. Neither test references
`composition_stage` — both assert on `backends/metal` source contracts, which I
had not touched — but "looks unrelated" is not attribution, so I stashed the edit
and re-ran on clean `d385ffd9`. Identical: same 75/79, same two tests. They are
pre-existing. That stash-and-rerun cost one build cycle and is the only reason
the verdict below distinguishes "pre-existing" from "possibly mine".

## Preempted

The #124 delivery landed before `test-cairo-metal-product` or the all-opcodes
digest spot could run. Per the preemption clause I stopped at a compiling,
checkpointed state rather than pushing on, and re-ran `metal-check` and
`package-workspace` against the delivered tree so the checkpoint is verified
where it actually sits.

That turned out to matter: the branch had already been fast-forwarded onto the
delivery while I was working, so my commit's parent is `f7f8c3a3`, not the
`d385ffd9` I started from. `d385ffd9` is still an ancestor and the delivery
touched none of the files I touched, so nothing was lost — but the rebase the
orchestrator expected to perform is already unnecessary, and I corrected the note
and this transcript rather than leave a record that claims otherwise. Checking
`git log` after committing, instead of trusting the head I was handed, is what
caught it.

The change is structurally complete; what is missing is two gates and the first
real end-to-end measurement. The hook is off, so nothing in product behaviour
depends on this landing correctly today.

The prior agent on this branch forfeited its work by not checkpointing. This one
committed at the preemption boundary instead.
