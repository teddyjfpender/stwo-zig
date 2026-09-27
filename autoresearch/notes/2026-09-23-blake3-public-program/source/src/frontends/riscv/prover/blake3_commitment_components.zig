//! Shared typed component roster and bounded emission for ordinary commitments.
//! The caller supplies a final-layout sink; only one word's hash workspace is
//! live at once. Independent preprocessing uses admitted schedules, no snapshot.
const std = @import("std");
const witness = @import("blake3_commitment_witness.zig");
const g = @import("../recursion/air/blake3_g_call.zig");
const xor = @import("../recursion/air/blake3_xor_call.zig");
const digest_boundary = @import("../recursion/air/blake3_boundary.zig");
const route = @import("../recursion/air/blake3_byte_route.zig");
const private_word = @import("../recursion/air/blake3_private_word.zig");
const bridge = @import("../recursion/air/blake3_input_bridge.zig");
const memory_boundary = @import("../recursion/air/blake3_memory_boundary.zig");
const public_program = @import("../recursion/air/blake3_public_program.zig");
pub const Roster = @import("../recursion/air/blake3_component_roster.zig").WithExtras(.{ route, private_word, bridge, memory_boundary, public_program });
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
