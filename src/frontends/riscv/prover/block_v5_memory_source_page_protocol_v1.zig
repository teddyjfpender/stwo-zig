//! Legacy exact shared typed source-page binding specialization.
//! Original masks, graph scheduling and B5SP key grammar are preserved.
const Impl = @import("block_v5_memory_source_legacy_schema_v1.zig").Page;
pub const TAG = Impl.TAG;
pub const VERSION = Impl.VERSION;
pub const CIRCUIT_BASE = Impl.CIRCUIT_BASE;
pub const abiId = Impl.abiId;
pub const SourceEpoch = Impl.SourceEpoch;
pub const sourceEpoch = Impl.sourceEpoch;
pub const ArithmeticPin = Impl.ArithmeticPin;
pub const Challenges = Impl.Challenges;
pub const draw = Impl.draw;
pub const circuitId = Impl.circuitId;
