//! Legacy exact shared typed source-page binding specialization.
//! Original masks, graph scheduling and B5SP key grammar are preserved.
const Impl = @import("block_v5_memory_source_legacy_schema_v1.zig").BindingInteraction;
pub const Claim = Impl.Claim;
pub const normalize = Impl.normalize;
pub const Generated = Impl.Generated;
pub const generate = Impl.generate;
