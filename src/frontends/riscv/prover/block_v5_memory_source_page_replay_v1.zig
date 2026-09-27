//! Legacy B5SC API, exact shared typed ownership/grammar specialization.
//! New raw/fold protocols remain distinct; no proof authority is added.
const Impl = @import("block_v5_memory_source_legacy_schema_v1.zig").Replay;
pub const ForBackend = Impl.ForBackend;
