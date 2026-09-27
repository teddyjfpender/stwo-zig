//! Shared typed component roster and bounded emission for ordinary commitments.
//! The caller supplies a final-layout sink; only one word's hash workspace is
//! live at once. Independent preprocessing uses admitted schedules, no snapshot.
const std = @import("std");
const witness = @import("blake3_commitment_witness.zig");
const memory = @import("../recursion/air/blake3_memory_word.zig");
const program = @import("../recursion/air/blake3_program_word.zig");
const path = @import("../recursion/air/blake3_memory_path.zig");
const g = @import("../recursion/air/blake3_g_call.zig");
const xor = @import("../recursion/air/blake3_xor_call.zig");
const digest_boundary = @import("../recursion/air/blake3_boundary.zig");
const route = @import("../recursion/air/blake3_byte_route.zig");
const private_word = @import("../recursion/air/blake3_private_word.zig");
const bridge = @import("../recursion/air/blake3_input_bridge.zig");
const memory_boundary = @import("../recursion/air/blake3_memory_boundary.zig");
const program_boundary = @import("../recursion/air/blake3_program_boundary.zig");
const packing = @import("../recursion/air/qm31_pack_wire.zig");
const encoding = @import("../recursion/air/blake3_field_bytes.zig");
pub const Roster = @import("../recursion/air/blake3_component_roster.zig").WithExtras(.{ route, private_word, bridge, memory_boundary, program_boundary, packing, encoding });
pub const Airs = Roster.Airs;
pub fn emit(a: std.mem.Allocator, source: *const witness.Witness, sink: anytype) !void {
    for (0..source.boundaries.len) |i| {
        var prepared = try source.prepareBoundary(a, i);
        defer prepared.deinit();
        try emitMemory(&prepared, sink);
    }
    for (0..source.programs.len) |i| {
        var prepared = try source.prepareProgram(a, i);
        defer prepared.deinit();
        try emitProgram(&prepared, sink);
    }
}
/// These schedules must be authenticated by verifier key admission. Never take
/// them from an unchecked proof or infer them from prover-owned byte witnesses.
pub fn emitTrusted(a: std.mem.Allocator, admission: @import("blake3_commitment_plan.zig").Admission, sink: anytype) !void {
    try admission.validate();
    const memories = admission.plan.memories;
    const programs = admission.plan.programs;
    for (memories) |statement| {
        var prepared = try memory.trusted(a, statement);
        defer prepared.deinit();
        try emitMemory(&prepared, sink);
    }
    for (programs) |statement| {
        var prepared = try program.trusted(a, statement);
        defer prepared.deinit();
        try emitProgram(&prepared, sink);
    }
}
pub fn emitMemory(prepared: *const memory.Prepared, sink: anytype) !void {
    try sink.append(memory_boundary, &.{prepared.boundary_row});
    for (&prepared.paths) |*item| try emitPath(item, sink);
}
pub fn emitProgram(prepared: *const program.Prepared, sink: anytype) !void {
    try sink.append(program_boundary, &.{prepared.boundary_row});
    try sink.append(packing, &.{prepared.packing_row});
    try sink.append(encoding, &.{prepared.encoding_row});
    for (&prepared.paths) |*item| try emitPath(item, sink);
}
fn emitPath(item: *const path.Prepared, sink: anytype) !void {
    inline for (.{ g, xor, digest_boundary, route, private_word, bridge }, .{ item.g_rows, item.xor_rows, item.boundary_rows, item.route_rows, item.word_rows, &@as([1]bridge.Row, .{item.input}) }) |Air, rows| try sink.append(Air, rows);
}
