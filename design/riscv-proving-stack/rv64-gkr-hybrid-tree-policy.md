# Optional hybrid CPU tree storage

Status: software/physical-fixture qualified; complete-block performance comparison
pending. This changes operational storage only. No proof/profile/statement/wire,
security parameters, relation closure or immutable setup authority changes.

Resources and coordinator Options accept `checkpoint_above_gkr_bytes`, default0
(disabled and omitted from default resource JSON). A nonzero threshold requires
streaming with forced checkpoint2 unset. Invalid/conflicting bases are rejected
before coordinator request copying or witness work. The environment is read once;
the global policy observation explicitly reports this BASE policy.

For every CPU, `tree_selection.forCpu` derives its source80 plan once without
using the configured GKR cap as a selection signal. Strictly above the threshold
selects the existing source-checkpoint68 path; equality stays source80. Only the
selected plan is then admitted against the configured GKR budget. Thus a selected
68 plan may fit when80 would not, but failed80 admission never triggers a retry
or fallback. Zero threshold preserves the original base-policy path.

Admission owns one resolved policy entry per CPU. The same frozen array controls
retention/task estimates and stage-one sealing; it remains live through joined
workers and failure cleanup. Per-worker timing exposes `resolved_tree_policy`
for CPUs and null for truths. The base observation is not relabeled as the actual
policy of every shard. Candidate resources forward this operational field while
preserving independent profile and fixed-key authority.

Focused Safe/Fast qualification covers strict below/equal/above selection,
default behavior and conflicting bases. Actual two-CPU plus K/ADD/DOUBLE proofs
run under two2-worker lanes with different CPU policies, match all control proof
bytes/claims and the stage-one manifest, and pass an independently reconstructed
fresh receiver. Telemetry must match each selected admission peak exactly. A cap
between68/80 is accepted only for explicitly selected68; selected80 over cap is
rejected. Exhaustive admission allocation-failure checks cover the policy array
and planner owners. An additional serial failure fixture injects the first
allocation failure after CPU0 has sealed a live worker, then checks CPU1 failure
and teardown. Captured MAIN uses the same injection allocator, preserving the
existing strict source-owner identity requirement. Invalid base policy leaves
native inputs unconsumed.

The supplied12GiB K16 resource example predicts checkpointing CPU shards4,5,6
from the actual source80 shape model (14.292,14.272,12.417GiB respectively). This
is a shape prediction, not measured concurrency, RSS or a promised speedup. The
configured resource caps still govern the complete execution. A matched complete
block and fresh independent receiver remain the policy-promotion gate. Native
payload admission excludes independent setup/capture/PCS, free recycler cache,
allocator rounding, stacks and kernel memory.
