# M7 partial truth-family coalescing review

Status: read-only source review. No omission or duplication blocker found in the reviewed routing changes. This is not a production proof, security certification, performance measurement, or qualification of the 14-leaf candidate.

Reviewed integration head: `6062ea967` (2026-11-05). The review covers `ethereum/plan.zig`, the producer route in `ethereum/gkr_main.zig`, existing `services/wire.zig` receiver admission, and `services/gkr_local/service_scope.zig`.

- Producer selection is explicit and restricted to the v3 candidate route; conflicting complete-family and partial-family flags refuse (`gkr_main.zig:491`). The old route remains selected when both flags are false.
- Advice array lengths are checked before planning (`gkr_main.zig:608`, `service_scope.zig:63`). The new multi-array count loop therefore consumes equal shard inventories.
- Counts use checked arithmetic. Keccak includes the same raw calls plus sponge permutation inputs as the old path. Every other family sums the same original per-shard call inventory (`plan.zig:398`).
- Partial coalescing keeps the bounded Keccak splitter, zeros only that family's remainder, and emits one complete declaration for each nonempty remaining family (`plan.zig:501`). A non-Keccak declaration starts at ID 1 and carries its full count. Existing source geometry/rung admission runs before returning. Unsupported sizes refuse; there is no silent dropping or fallback split.
- Receiver admission checks family ordering, nonempty spans, exact next ID, geometry and proof budgets (`wire.zig:405`). Its final equality requires every family's covered endpoint to equal the CPU-declared total plus one, including the separate sponge permutation term for Keccak (`wire.zig:449`). Missing, duplicate, overlapping or truncated declarations cannot bypass those checks through the producer flag.

The existing dev-count unit controls check contiguous IDs, total conservation, bounded Keccak logs and admitted secp row rungs. The actual coalesced proofs and fresh CPU receiver checks remain a separate required gate. This review does not establish global memory admission, fewer Keccak proofs, general capacity beyond the source roster, or a latency gain.
