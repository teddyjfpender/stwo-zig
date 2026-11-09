# Witness-free retained source lifetime inventory

No heavy guest execution or proof was rerun. This model reads the frozen 238,226,172-step declarations/cost records and compiled owner ABI sizes. It reconstructs the original native capture payload exactly (15,677,219,728 bytes) and ordinary event payload exactly (7,263,933,624 bytes) as internal checks.

| Owner | Derived payload | Lifetime |
|---|---:|---|
| CPU metadata | 13,340,665,632 B | One immutable file per shard; only active restored view remains live |
| LS32 + LS-D64 metadata | 9,867,247,616 B | 82 bytes per padded row, retained through stage-one barrier for binding/RAM |
| All new provider tuple metadata, including LS | 12,705,825,168 B | Replaces temporary weighted native facts and consumed event owners |
| Raw per-source fixed masks | 2,199,984,384 B | LS/D64 1,443,987,456 B retires after seal; other masks remain |
| Histograms + saved multiplicity planes | 1,920,184,320 B | SHIFT 780,140,544 B retires after seal; saved committed table MAIN remains |
| CPU bridge/bulk/sponge copied advice | 1,375,941,721–1,380,200,553 B | Additional to original advice retained for truth production |
| All 16 truth workers' durable metadata bound | 244,464,728 B | Independent source-declaration resource/catalog formulas |
| All 22 classic Miller workers' advice bound | 121,485,280 B | Current 5,344 B/call + 133,120 B/worker, from compiled ResourcePlan ABI |

The old 4,704-byte Miller figure is stale: the current `trace.Input + micro.Advice` totals 5,344 bytes.

The model applies ownership changes in actual producer order. Original CPU ROM/range histograms and JALR facts move into the source; they are counted once and released at worker retirement. ALU/BINARY/SHIFT weighted fact arrays retire after replacement provider construction. Multiplication source metadata is per active request, while ALU/BINARY/SHIFT and LS metadata use padded rows. Ordinary LS events retire after memory construction. Original service advice stays live for later truth workers, so CPU bridge copies are additional. Bulk sources currently clone all call/word lists once per present kind, rather than just that kind's rows.

With both qualified opt-in retirements enabled, the all-CPU post-seal payload is 19.10 GB. The largest CPU seal diagnostic is 27.46 GB at shard 53. Including truth/Miller retained metadata, the CPU phase-two interaction-commit payload envelope peaks at 25.01 GB. A separate service-stage-one envelope using reviewed local-GKR resource plans and the classic 8 GiB hard worker cap peaks at 28.05 GB. Every per-shard timeline appears in the JSON.

These numbers **do not establish 32 GiB whole-worker admission or RSS**. They omit child proof/artifact/header payloads, source-construction overlap/capacities, PCS/FFT/composition scratch, immutable FIXED lease mappings and the immutable-class difference between the measured schema-1 baseline and the current retiled schema-2 inventory. They are not throughput forecasts. Existing numerical allocators remain the hard limit.

Another LS metadata parking extension would remove much of the remaining 9.87 GB barrier owner, preserve the same source constraints and need no replay. This ledger does not yet demonstrate that it is necessary. It adds disk traffic and must reserve the same combined MAIN/FIXED/advice quota; no independent unaccounted disk pool or cap increase is justified. The next decision should compare the remaining explicitly excluded live terms with current headroom, rather than halve windows or rerun the heavy proof blindly.

## Reproduce without guest execution

The test `OP retained source layout manifest uses compiled owner ABI sizes only` writes ABI sizes to `STWO_OP_SOURCE_LAYOUT_OUTPUT`. The test `OP retained truth planner manifest needs no setup witness or execution` reads `STWO_OP_SOURCE_FROZEN_PLAN` and writes source-derived schema-2 resource plans to `STWO_OP_SOURCE_TRUTH_OUTPUT`. Both passed ReleaseSafe. Neither constructs wide immutable keys, witnesses or proofs.

Run `python3 scripts/rv64_op_retained_source_report.py --plan FROZEN/native-op-plan.json --cost FROZEN/native-op-cost.json --seal cpu-seal-plan.json --sizes source-owner-abi-sizes.json --truths source-owner-schema2-truth-plans.json --output report.json`. The source report's native/event exact-equality checks fail closed on mismatched accounting.
