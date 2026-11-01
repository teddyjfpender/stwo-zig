# Interrupted RV64 performance work: recovery and integration

The interrupted Claude session was recovered from session
`41eff230-75ab-4f11-a53b-7db4dcd5a611`, workflow `wf_335591ee-e99`.
Its journal records 17 agent tasks, 11 with completed result records. Task
completion is not equivalent to production qualification: some implementations
committed source after the workflow stopped recording their completion.

## Durable source and evidence

All nine original `codex/rv64-perf2-*` branches were pushed without modifying
their worktrees. The three dirty worktrees were also committed through isolated
temporary indexes, preserving their original working files and indexes:

| Recovery branch suffix under `recovery/rv64-wave2-20261101/` | Snapshot |
| --- | --- |
| `composition-queue` | `0ea417bcca0908ebf874f699b1c7e37ffc174c24` |
| `gkr-prototype` | `e129aa435e5ed0fe32dbe8badfe80defd76f05e7` |
| `interaction-gen` | `8261bc7c09e77266c11c9b239e3db48677406b08` |

These refs are pushed and explicitly retain unfinished work. A local recovery
archive at `/private/tmp/rv64-wave2-recovery-20261101-v1/` contains a Git bundle,
binary patches, the source inventory, and the parent session plus nested agent
traces. Raw session traces remain local; they are not repository artifacts.
That path is a compatibility symlink to the persistent, private archive at
`~/.local/share/stwo-zig/recovery/20261101-wave2/`, so temporary-directory cleanup
does not remove the recovered evidence.
The machine-readable `agent-recovery-inventory-v1.json` report records original
refs and recovered structured implementation/review results. Recovered results
are attributed evidence, not new independent acceptance claims.

## Integration decisions

| Workstream | Decision and qualification |
| --- | --- |
| Small AIR trims | Integrate affine substitutions, retained range obligations and adversarial tests. Omit three accidentally tracked root-level test-output files. Original slice includes a complete-block fresh receiver result. |
| INIT/TEARDOWN | Integrate receiver-owned public-order reduction; schema 6. Public list validation, transcript binding and expected RAM claims remain mandatory. Merged boundary/memory/circuit tests pass. |
| DIV trims | Integrate with additional production MUL byte-query regression and raised test-count floors. Safe/Fast DIV tests and circuit checks pass. |
| Scheduling | Integrate N-lane controls and telemetry with fixes for shared mutable timer access and ignored single-lane worker limits. Default remains two lanes. The memory admission cap is a transient estimate, not a hard RSS/device-memory bound. |
| GKR | Integrate a separately named experimental tool and dedicated tests. Safe/Fast21 and real-input fresh verification pass; fast/reference GKR proof bytes agree. Production execution, RAM and recursive receivers are unchanged. |
| Interaction generators | Integrate after correcting relative-block grouping against the actual row permutation. Six Safe and six Fast suites pass; recovered prefix proofs and all eleven durable artifacts match the schema5 control, with fresh acceptance. Merged schema6 qualification is recorded separately. |
| Composition queue | Integrate as an explicit experiment, off by default. Safe/Fast152 and same-binary prefix parity pass. Scheduling, metrics and shared state validation have separate modules. Active-output admission excludes some retained completed buffers, so it does not establish a hard total-memory limit. |
| LS32 | Preserve and hold production promotion pending completion of the writer/canonicality audit and balanced cross-component adversarial coverage. An interrupted review is not a passing review. |

The original per-workstream design documents and their qualification limits
remain authoritative. Existing receipts measured against `87df8e6a5` or
`eac3b7c07` must not be relabeled as measurements of the combined branch.
Stage-time sums overlap and are not block wall time. No aggregate multiplier
or controlled GPU/CPU speed claim follows from this recovery.
