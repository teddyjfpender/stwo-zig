//! Canonical typed domain interfaces; test hooks are explicitly unstable.

pub const access_clock = @import("access_clock.zig");
pub const authority = @import("authority.zig");
pub const bulk_memcpy_candidate = @import("bulk_memcpy_candidate.zig");
pub const bulk_memcpy_private_registry = @import("bulk_memcpy_private_registry.zig");
pub const custom0 = @import("custom0.zig");
pub const decode = @import("decode.zig");
pub const execution_profile = @import("execution_profile.zig");
pub const host = struct {
    pub const interface = @import("host/interface.zig");
};
pub const instruction_set = @import("implementation.zig");
pub const machine = struct {
    pub const cpu = @import("runner/cpu.zig");
    pub const decode = @import("runner/decode.zig");
    pub const execution_boundary = @import("runner/execution_boundary.zig");
    pub const memory = @import("runner/memory.zig");
    pub const memory_state = @import("runner/memory_state.zig");
    pub const state_chain = @import("runner/state_chain.zig");
    pub const trace_row = @import("runner/trace_row.zig");
};
pub const opcode_manifest = @import("opcode_manifest.zig");
pub const profile = @import("profile.zig");
pub const segment_wire_layout = @import("segment_wire_layout.zig");
pub const sha256_compression = @import("sha256_compression.zig");
pub const span_word_geometry = @import("span_word_geometry.zig");
pub const stack_swap_candidate = @import("stack_swap_candidate.zig");
pub const stack_swap_private_registry = @import("stack_swap_private_registry.zig");
pub const testing = struct {
    pub const inventory_source = @embedFile("tests/root.zig");
};

test {
    _ = @import("tests/root.zig");
}
