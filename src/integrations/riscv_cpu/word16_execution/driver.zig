//! Durable native execution receipt. The receiver reconstructs its own image
//! and immutable key; serialized claims and geometry grant no authority.
const std = @import("std");
const P = @import("protocol.zig");
const Mat = @import("setup.zig");
const E = @import("execution.zig");
const Memory = @import("memory/statement.zig");
pub const cells = @import("cells_wire.zig");
const Cells = cells;
const Receipt = @import("../rv64_proof_artifact_support.zig");
pub const Bundle = struct {
    schema: u32 = P.SCHEMA,
    geometry: Mat.Geometry,
    cpu: @FieldType(P.Request, "cpu"),
    epoch: u16,
    division_requests: u32,
    multiplication_requests: u32,
    ls_count: u32,
    memory_words: u32,
    claims: P.Claims,
};
pub fn writeJson(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, value: anytype) !void {
    const bytes = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(bytes);
    try Receipt.writeExclusive(dir, name, bytes);
}
pub fn publish(a: std.mem.Allocator, dir: std.fs.Dir, setup: *const Mat.Setup, encoded: E.Encoded) !void {
    try Receipt.writeExclusive(dir, "proof.bin", encoded.bytes);
    const r = encoded.request;
    try Cells.write(dir, r.memory.initial, r.memory.terminal);
    try writeJson(a, dir, "statement.json", Bundle{ .geometry = setup.materials.geometry, .cpu = r.cpu, .epoch = r.epoch, .division_requests = r.division_requests, .multiplication_requests = r.multiplication_requests, .ls_count = r.memory.ls_count, .memory_words = @intCast(r.memory.initial.len), .claims = encoded.claims });
    try std.posix.fsync(dir.fd);
}
