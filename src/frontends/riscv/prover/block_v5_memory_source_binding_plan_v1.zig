//! Legacy exact shared typed source-page binding specialization.
//! Original masks, graph scheduling and B5SP key grammar are preserved.
const Impl = @import("block_v5_memory_source_legacy_schema_v1.zig").BindingPlan;
pub const ROUTING_COUNT = Impl.ROUTING_COUNT;
pub const Limits = Impl.Limits;
pub const Plan = Impl.Plan;
