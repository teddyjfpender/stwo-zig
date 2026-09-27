//! Legacy B5SC API, exact shared typed ownership/grammar specialization.
//! New raw/fold protocols remain distinct; no proof authority is added.
const Impl = @import("block_v5_memory_source_legacy_schema_v1.zig").Round;
pub const Collector = Impl.Collector;
pub const InputBinding = Impl.InputBinding;
pub const ChunkCandidate = Impl.ChunkCandidate;
pub const ForBackend = Impl.ForBackend;
