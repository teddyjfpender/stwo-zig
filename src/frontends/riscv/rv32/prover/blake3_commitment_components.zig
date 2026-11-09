//! Shared typed component roster and bounded emission for ordinary commitments.
//! The caller supplies a final-layout sink; only one word's hash workspace is
//! live at once. Independent preprocessing uses admitted schedules, no snapshot.
const std = @import("std");
const witness = @import("blake3_commitment_witness.zig");
const g = @import("stwo_riscv_air_lang").modules.framework_blake3_g_call;
const xor = @import("stwo_riscv_air_lang").modules.framework_blake3_xor_call;
const route = @import("stwo_riscv_air_lang").modules.framework_blake3_byte_route;
const private_word = @import("stwo_riscv_air_lang").modules.framework_blake3_private_word;
const bridge = @import("stwo_riscv_air_lang").modules.framework_blake3_input_bridge;
const memory_boundary = @import("stwo_riscv_air_lang").modules.framework_blake3_memory_boundary;
const public_program = @import("stwo_riscv_air_lang").modules.framework_blake3_public_program;
pub const Roster = @import("stwo_riscv_air_lang").modules.framework_blake3_component_roster.WithExtras(.{ route, private_word, bridge, memory_boundary, public_program });
pub const Airs = Roster.Airs;
pub fn emit(a: std.mem.Allocator, source: *const witness.Witness, sink: anytype) !void {
    var plan = try source.plan(a);
    defer plan.deinit();
    const admission = try @import("blake3_commitment_plan.zig").Admission.init(&plan, try plan.identity());
    try @import("blake3_commitment_shared_emit.zig").emit(a, admission, source, sink);
}
/// Build identical shared topology solely from caller-authenticated schedules.
pub fn emitTrusted(a: std.mem.Allocator, admission: @import("blake3_commitment_plan.zig").Admission, sink: anytype) !void {
    try @import("blake3_commitment_shared_emit.zig").emit(a, admission, null, sink);
}
