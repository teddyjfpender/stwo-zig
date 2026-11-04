# Experimental narrow assignment-level runs

The retained production log for block 26235168 reports 17,980,712
`ready_tasks` and 109,504 dependency levels, with 109,503 native level calls and
508 ms of enqueue time on that node. `ready_tasks` counts the scheduler's fast
path and excludes tasks visited through DFS; it is not the full task count.
Neither that counter nor a layer average establishes the width distribution.
Initially the retained proof/bundle/log artifacts did not contain full
level-end arrays. The later CPU reconstruction below supplies the missing
census. No GPU speedup is claimed.

A later CPU-only diagnostic reconstructed two independently admitted real leaves,
applied the exact outer padding used by production, and matched retained GPU
variables/tasks/levels. CPU0 had 45,088,768 variables /18,990,989 tasks /120,241
levels; Keccak7 had 26,738,688 /13,484,113 /146,140. Bounded 256-thread runs project
6,869 and 3,712 level calls versus 120,240 and 146,139 old nonempty-level calls.
The corresponding 128-thread projections are 22,542 and 23,410. This motivated
selecting 256 rather than 128 threads in this isolated successor, not a claim of
faster GPU execution. Only 24.37% and 38.05% of tasks fall in the selected runs;
broad 257+ levels retain their old parallel route. A 129–256-task level formerly
used two 128-thread CTAs, so the new one 256-thread CTA can trade SM parallelism
and register occupancy against launch overhead. That trade remains unmeasured.

Diagnostic source edc22ba74 / binary 11116523a1cc103b049717278c8122855f62e997a787e686a3888f211b6a8a22;
CPU result 9bf1759341a47ab97bd2a4bc9a478841541bdd17666051646964703aa6bad4d9;
Keccak result 668eedc2af7b40bece9aa97895ce7c3ab4e8cd39f3f6784b05d34e5cd969434f.
Earlier unpadded diagnostic records remain exploratory and are not the production
assignment geometry. No GPU run was performed for either diagnostic.

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
monotonicity, each width <= 256, final coverage equal to Job.first+Job.count, all
usual record bounds and reserved fields, then applies the original allocation
registry and writable-alias custody. It copies the bounded offsets into an
approximately 1.1 KB launch packet and launches exactly one 256-thread CTA.
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
small scalar oracle, includes a 257-task broad barrier, rejects malformed
coverage/width/reserved/alias/context cases, and checks that invalid-task status
does not strand threads at a barrier. Afterwards the existing connected
`--outer-dag-proof` fixture must prove exact native bytes with a positive
`narrow_run_calls` counter, followed by real-leaf parity and performance gates.

This addresses generation launch overhead only. It does not reduce the much
larger retained assignment-planning, packing or hashing costs. Register use,
packet traffic, actual narrow-run distribution, CUDA memory use and whole-node
performance must be measured before activation. No GPU job or lease restart
was performed for this source checkpoint.
