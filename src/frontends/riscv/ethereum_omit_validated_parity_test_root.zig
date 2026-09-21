//! Focused validated-vs-unvalidated parity gate for the omission path.
//!
//! Every `...Validated` sibling on the Ethereum provider-omission path swaps
//! one `ProviderShardPlanV1.validate(calls)` corpus rehash for an O(1)
//! pointer-closed readmission. That is a validation change only, and this
//! gate is the backend-neutral half of the evidence: both routes admit the
//! same corpus, mint byte-identical Stage-A manifests and identities, admit
//! the same shard slices, and close the same aggregate. The proving half
//! lives in `src/integrations/riscv_cpu`.

comptime {
    _ = @import(
        "prover/memory_provider_shards/ethereum_omit_validated_parity_v1_test.zig",
    );
}
