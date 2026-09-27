# Production global planning and warm ordinary memory

`block_v5_native_memory_stage_v1` collects ordinary memory witnesses from the
actual first-pass native owner. It stores the real witness root, typed slot
descriptors, event census and range8 counter digest before any native public
instance ID exists. The proposal is bound to that ID only after independently
collected global plans are available. The second pass checks the native physical
proposal and reconstructs the witness and counters, then proves the sidecar
using leases of the original native fixed/main commitment trees. A producer-only
proof entrypoint accepts the genuine still-owned native first round; it does not
construct a verified native receipt. Consumer verification still requires a
fresh native receipt. Empty ordinary leaves use the existing versioned empty
entry, with no arbitrary empty STARK accepted.

The native physical kernel releases coefficient storage. The packed v5 sidecar
therefore uses the existing complete-LDE interpolation helper when necessary:
it checks the full recovered polynomial degree before evaluating on the quotient
domain, and reuses the required quotient buffer. The old v2 evaluator branch is
unchanged. Committed native evaluations remain shared by pointer.

`block_v5_cpu_lookup_groups_v1` accepts one execution's real six-table counters
and independently admitted demand. It checks centered signed multiplicity mass
before field addition and uses the same greedy contiguous partition as the
receiver planner. One current counter Set and one immutable fixed table basis
stay live. Each flushed group receives actual provider commitment roots and a
versioned canonical dense counter file with SHA-256 and exact byte-length pins.
No per-execution or per-group counter Sets are retained. The proving source
reopens, schema-checks and hash-checks one owned Set at a time. Metadata, group
count and aggregate file length have explicit limits; the caller's bounded
allocator remains responsible for PCS and trace storage limits.

`block_v5_cpu_global_plans_v1` runs the production initial/first-touch/final/
register writer over a reopenable sorted stream, then collects actual
independently sized packed36 memory and range16 roots and plan digests. Both
full-image RW roots are mandatory pins, including public input and untouched
nonzero words. These real digests feed driver late public admission. A second
binding step matches the independently built ROM census and exact lookup plans,
commits the ROM table and exposes the complete global first-round roster and
memory receiver pins. The replay, ROM census and online group stage are borrowed
and must outlive proving and reception. Returned metadata grants no block or
proof authority.

## Focused qualification

ReleaseFast with `-lc -mcpu=native`, Zig 0.15.2:

* Warm ordinary memory gate: **8/8 passed**. A real ADDI segment produced two
  memory-access events and 28 range8 requests. Physical native/witness proposal,
  late ID binding, warm same-root sidecar proof, original native proof and fresh
  verification of both passed. Native fixed/main pointers remained identical.
  Changed ordinal and counter snapshot rejected; testing allocator clean.
  Log: `/tmp/block-v5-native-memory-stage-gate.log`.
* Global planner/counter spool gate: **5/5 passed**. Actual sorted register/RW
  transitions yielded packed memory/range roots and all source plan digests,
  preserving an untouched nonzero RW word. Signed counters formed two exact
  greedy groups; reloaded files reproduced both provider roots. Changed plans,
  a canonical-residue file mutation and the aggregate file cap rejected. Failed
  file creation removed the partial file; testing allocator clean.
  Log: `/tmp/block-v5-global-plans-gate.log`.

The warm proof test uses scoped placeholder entries for unrelated families and
does not claim ROM, global tables, sorted closure or complete block authority.
The global planning test proves no block. Their production integration must be
qualified through the assembled mixed driver and fresh complete receiver.

Runner-only `Source.initFromPlan` and `initFromPlanWithSchedule` avoid a duplicate
host preflight after endpoints have already been collected. They require an
independently pinned expected job and retain the existing exact source hashes,
endpoint checks, schedule reconstruction and all replay checks. Their focused
test amendments are source-ready; no separate semantic gate has been run yet.

`Program.FirstRound.finishCollected(expected_fetches, config, program_entry)`
reuses the global collector's actual ROM root proposal during assembly. It
checks the unfinalized phase, exact execution/extension census, exact table plan
identity, family/index and both nonzero roots, then stores plain roots only.
The original `finish` keeps its commitment recipe and shares the same final
bookkeeping. Pass2 `proveTable` still reconstructs and matches both roots, and
fresh receiver verification remains mandatory. This avoids a duplicate pass1
ROM commitment without retaining a PCS owner or treating proposed roots as a
receipt. The actual-census parity and mutation test is source-ready; its narrow
semantic gate is pending the root-owned build lane.
