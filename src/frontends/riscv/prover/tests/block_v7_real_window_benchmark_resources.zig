//! Externally selected benchmark envelope shared by original production and
//! detached root verification. Never derive these limits from candidate claims.
const Memory = @import("../block_v7_window_memory_joint_v1.zig");
const Storage = @import("../block_v7_input_storage_v1.zig").Policy;
const Global = @import("../block_v7_global_public_closure_v1.zig");

pub fn memory(storage: Storage) Memory.Limits {
    return .{
        .memory = .{ .max_events = 1 << 24, .max_row_log = 22, .max_matrix_bytes = 8 << 30 },
        .max_live_bytes = 20 << 30,
        .input_storage = storage,
        .interaction_storage = storage,
        .consume_rows = true,
    };
}
pub fn receiver(storage: Storage) Global.Limits {
    return .{ .max_segments = 64, .window_memory = memory(storage) };
}
