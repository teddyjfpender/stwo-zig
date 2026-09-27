//! Legacy exact shared typed source-page binding specialization.
//! Original masks, graph scheduling and B5SP key grammar are preserved.
const Impl = @import("block_v5_memory_source_legacy_schema_v1.zig").BindingAir;
pub const PAIRS = Impl.PAIRS;
pub const FIXED_COUNT = Impl.FIXED_COUNT;
pub const MAIN_COUNT = Impl.MAIN_COUNT;
pub const INTERACTION_COUNT = Impl.INTERACTION_COUNT;
pub const CONSTRAINT_COUNT = Impl.CONSTRAINT_COUNT;
pub const Algebra = Impl.Algebra;
pub const degree = Impl.degree;
