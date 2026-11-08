# R1 CPU projection cost/lifetime primitive

Status: **CPU tests6/6 and TC/dependency tests14/14 PASS; runtime adapter, class admission and GPU gates pending.** No GPU was used and no memory or latency improvement is claimed.

`native_cpu_projection_cost.zig` is std-only. `layoutFor` derives metadata words, compact record/seed words, actual compact MAIN width, ROM width and column-header size from the **same imported types/constants as the formatter**. Runtime admission must instantiate that adapter using actual frontend/CPU types; the standalone test's explicit ABI schema is not evidence that a runtime adapter was instantiated. The module never authorizes launch itself.

The input pins formatter format, source/program compact mode, actual layout, program identity/profile, CPU/ROM logs, metadata count and public steps, ledger retention, ingress choice and cold/warm ROM state. Invalid geometry, unsupported format/modes and inconsistent public/metadata counts fail before numerical work. Layout and source identity are included in the plan digest. The supported retained-ledger path allocates in actual `cpu_projection.Job.run` order:

1. Cold immutable ROM `rom_rows * ROM_FIXED` words, kind4; a warm borrow is already charged to the immutable owner.
2. Scratch `max(1,active*metadata_words)+65536+256+rom_rows+1+65536`, kind0.
3. Evaluation matrix `rows * mainCount(true)`, kind1.
4. Optional compact input `max(1,active*record_words+ceil(active/chunk_rows)*seed_words)`, kind0.

The plan exposes allocation and release events. Compact device input is released only after the formatter/verdict join; scratch-ledger and evaluations survive until actual Source owner release, in ledger→evaluation order. ROM survives under a separate immutable cache owner; Source release must not free it. The peak field is a payload sum, **not a physical footprint**: the aggregator must independently round every allocation and combine all provider/source/TC lifetimes.

Warm ROM state must be protected by a real cache borrow/validation across planning and execution, or cost it conservatively as cold. An unprotected lookup is insufficient: eviction could change the allocation sequence. Strict execution checking must account for an optional cold allocation becoming a cache hit.

Host fields expose exact borrowed metadata/ROM bytes, compact records/seeds, returned column headers and additional packing-thread count. A cold retired ROM creates a separate reconstructed host payload before scratch/evaluation allocation. It must not be blindly added to a later host peak. **Host cost remains unknown**: actual `spawn(.{})` default stacks/worker permits, owner/pending descriptors, immutable ROM authority storage, JSON identity allocation and allocator overhead are not fully admitted by this primitive. Full metadata remains borrowed while packing occurs. There can be3 pack helpers in addition to the pre-stage thread.

Tests cover allocation/free ordering, retained versus temporary owner separation, warm/raw ingress, empty captures, chunk boundary257, large packing threshold, identity change, malformed public/shape/modes, source-type-driven adapter widths and cold retired-ROM lifetime. Logs and source hashes are retained.

## Trace commit correction

Source audit of `trace_commit.zig` and `Context.allocationPlan` finds `separate_coefficients = beta==1 && n2b_columns!=null`. Thus **TC beta2 is already modeled correctly**: legacy coefficient+LDE arena, tree/prefix scratch, then newly allocated final coefficient copy. A stream budget alone cannot select the beta1-only separate/stream ABI. The new test checks exact beta2 allocation order and rejects separate beta2 while preserving existing beta1 fixtures byte-for-byte.

No TC numerical model change was made. The accepted `separate_coefficients=true log_blowup=2` log refers to **composition**, whose separate beta2 cost-model gap is a different module owned by Root/Device. No silent beta2 TC feature is introduced.
