//! Shared witness-once staged lifetime with explicit typed producer authority.
pub const ForCapacity = @import("block_v5_cpu_staged_execution_source_common_v1.zig").ForCapacity;
pub const Source = ForCapacity(false).Source;
