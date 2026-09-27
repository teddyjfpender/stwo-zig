//! Genuine capacity staged producer; reuses the shared bounded owner lifetime.
pub const Source = @import("block_v5_cpu_staged_execution_source_common_v1.zig").ForCapacity(true).Source;
