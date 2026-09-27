//! Legacy exact shared typed source-page binding specialization.
//! Original masks, graph scheduling and B5SP key grammar are preserved.
const Impl = @import("block_v5_memory_source_legacy_schema_v1.zig").BindingComponent;
pub const Spec = Impl.Spec;
pub const Component = Impl.Component;
