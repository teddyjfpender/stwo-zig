//! Legacy B5SC API, exact shared typed ownership/grammar specialization.
//! New raw/fold protocols remain distinct; no proof authority is added.
const Impl = @import("block_v5_memory_source_legacy_schema_v1.zig").Store;
pub const Pin = Impl.Pin;
pub const Limits = Impl.Limits;
pub const write = Impl.write;
pub const load = Impl.load;
