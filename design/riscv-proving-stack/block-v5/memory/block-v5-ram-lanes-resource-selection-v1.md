# Resource-admitted RAM lane sizing v1

Canonical mode1 lane planning now admits row sizes before scanning boundary events, creating source files or committing roots. It uses the same independently configured fixed/interaction buffer caps, trace byte formula and FRI/config geometry checks that the real proof phase repeats. The backend minimum and actual row guard are checked as well. Resident ingress uses the exact serialized shard-plus-device-copy/histogram bound repeated immediately before upload. No device call is used by selection.

Previously the replay planner selected the configured maximum log, collected real boundaries, and only then applied Resources.require. GlobalPlans wrote full source files before that resource check. SortedMemory.collect also assigned the configured maximum over an independently supplied stricter proof.max_row_log. The canonical path now calls the same Replay.selectSizes both in GlobalPlans before source writing and in actual replay collection. Its resource intersection narrows row, instance and shard caps; it never widens independent phase authority.

The selector constructs a bounded bitmap of admissible physical row logs. It minimizes actual instance count first, using the largest admitted height, then total committed row area with the smallest admitted covering tail. Backend holes are supported, so an inadmissible smaller tail cannot slip through a contiguous-log assumption. Counts remain exact and non-rounded. Empty RW census returns no instances. Every real claim, endpoint, source sequence, transition adjacency, range census, initial/final source/root, source seal and actual first/second-pass root comparison remains unchanged.

The proof and trace helpers share their original formulas:

- Proof.Limits.require(claim) validates the actual claim then calls requireGeometry(row_log).
- Proof.validateConfig(claim,config) validates the actual claim then calls validateGeometry(row_log,config).
- Trace.ownedBytes(claim) validates the actual claim then calls ownedBytesForRowLog(row_log).
- Resources.requireResidentIngress(events) is called both by selection and the actual upload owner.

Planning.collectAdmitted transfers ownership of selected capacities on all paths, validates their exact nonempty coverage/power-of-two domain before touching the real reader, and then uses the existing boundary/claim collection kernel. One real trace and PCS remain live at a time. Plan metadata and at least one real range16 provider for nonempty RAM are admitted before collection; exact provider grouping is still derived from the actual source census in Stage/Plan, not guessed by sizing.

This selects against the exposed independent geometry/resource budgets. It is not a whole-proof RSS estimate or a guarantee that all later resident PCS/fraction allocations fit. Those phases additionally check retained columns, FFT workspace, actual generated DAG metadata and shared allocator budgets. These checks remain mandatory. No estimate, synthetic claim or producer receipt replaces proof resource admission, and no memory/proof speed improvement is claimed.

Both the legacy and capacity-native factories share this same sorted-RAM route. Mode0 word memory remains an explicit separate protocol. No CLI, capacity/native proof codec, recursive cache, lane equation/mask/ABI or device kernel was changed.

Source formatting is checked. No compiler, tests, witnesses, commitments, proofs, guest, segments, devices or benchmarks were run by this agent. Five pure fixtures are ready under root `src/frontends/riscv/block_v5_ram_lanes_resource_plan_test_root.zig`, filter `block-v5 RAM resource selection`:

```sh
python3 autoresearch/notes/2026-09-24-ethereum-block-delivery/test_sha_memory_proof.py --root src/frontends/riscv/block_v5_ram_lanes_resource_plan_test_root.zig 'block-v5 RAM resource selection'
```

They cover independent fixed/interaction/trace caps and exact boundary values, non-rounded counts/metadata/provider caps, FRI/backend holes/resident ingress, exhaustive small admitted masks against an independent count/row-area oracle, typed empty RAM, malformed geometry rejection before reader access, and all allocation failures. Actual lane/GlobalPlans production body codegen is a separate root-owned qualification; no runtime proof qualification is implied.
