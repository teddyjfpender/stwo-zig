# Experimental narrow assignment-level runs

The retained production log for block 26235168 reports 17,980,712 ready tasks
and 109,504 dependency levels. Generation made 109,503 native level calls and
spent 508 ms enqueueing them on that node. The mean of approximately 164 tasks
per level does not establish the fraction at or below 128 threads. The retained
proof/bundle/log artifacts inspected here do not contain the full level-end
array; no real width distribution or speedup is claimed.

The existing schedule builder assigns each task one level above all of its
producers, rejecting duplicate producers and cycles, then preserves task order
within levels. A single CTA can therefore execute consecutive narrow levels
with a block barrier between them. Writes to global assignment storage become
visible to that same CTA before dependent reads at the next level. A broad
level remains an ordinary multi-CTA kernel on the same stream, preserving the
existing complete-kernel ordering boundary before and after it.

This isolated candidate adds optional `stwo_circuit_assignment_narrow_run_on`.
The old 56-byte Job, 16-kind capability mask and ordinary entry are unchanged.
The new entry takes at most 256 absolute host level-end offsets. It validates
monotonicity, each width <= 128, final coverage equal to Job.first+Job.count, all
usual record bounds and reserved fields, then applies the original allocation
registry and writable-alias custody. It copies the bounded offsets into an
approximately 1.1 KB launch packet and launches exactly one 128-thread CTA.
There is no new device geometry allocation, upload, cache namespace or lease.
The kernel calls the original task evaluator; errors set the same status word.
Every thread still reaches every barrier after an evaluator error return.

`STWO_RV64_OUTER_ASSIGNMENT_NARROW_RUNS=1` enables grouping only with the new
symbol. Absent or 0 keeps the old route; other values reject. Singleton narrow
levels keep the ordinary route. Contiguous runs are bounded to 256 levels and
never cross a broad level. Copied host run metadata is owned by Prepared and
charged to its existing allocator. The original task/seed ordering, immutable
cache identity, numerical constraints and proof transcript are unchanged.

The source also prints actual width buckets and selected-run counts on the
next graph preparation. For a GPU-free production diagnostic, reconstruct an
independently admitted leaf with the existing `leaf_graph.cpuTraceOnly` bridge,
then run `Schedule.buildProfiled(a,graph.ctx,...)` and
`assignment_runs.inspect(plan.level_ends,plan.tasks.len)`. No GPU is required for
that measurement; fresh geometry/admission is still required. This candidate
has not run that production reconstruction and does not substitute an estimate
for it.

Six pure host planner tests pass: task coverage and broad barriers,256-level
bounds and singleton fallback, malformed and overflowed level ends, exact
histogram buckets, valid prior-level dependency replay, and strict opt-in.
The full GNU GPU-recursion production semantic check passes. New CUDA source
and `assignment_narrow_run_smoke.cu` remain UNCOMPILED and UNEXECUTED. That future
bounded fixture compares the original and grouped routes to an independent
small scalar oracle, includes a 129-task broad barrier, rejects malformed
coverage/width/reserved/alias/context cases, and checks that invalid-task status
does not strand threads at a barrier. Afterwards the existing connected
`--outer-dag-proof` fixture must prove exact native bytes with a positive
`narrow_run_calls` counter, followed by real-leaf parity and performance gates.

This addresses generation launch overhead only. It does not reduce the much
larger retained assignment-planning, packing or hashing costs. Register use,
packet traffic, actual narrow-run distribution, CUDA memory use and whole-node
performance must be measured before activation. No GPU job or lease restart
was performed for this source checkpoint.
