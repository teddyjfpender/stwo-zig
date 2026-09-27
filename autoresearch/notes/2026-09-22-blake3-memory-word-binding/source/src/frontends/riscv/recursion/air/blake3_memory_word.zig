//! One exact memory-access boundary word opened against a full BLAKE3 root.
//! The statement is verifier-owned; execution/clock provenance is an external
//! memory-access relation obligation, not inferred from the snapshot here.
const std = @import("std");
const core = @import("stwo_core");
const tree = @import("../../air/memory_commitment/blake3_byte_tree.zig");
const boundary = @import("blake3_memory_boundary.zig");
const path = @import("blake3_memory_path.zig");
pub const Statement = struct {
    address: u32,
    clock: u32,
    direction: boundary.Direction,
    source_circuit: u32,
    path_namespace: u32,
    root: tree.Digest,
    pub fn schedule(self: Statement) boundary.Schedule {
        return .{ .address = self.address, .clock = self.clock, .direction = self.direction, .circuit = self.source_circuit, .first_wire = 0, .uses = @splat(1) };
    }
    pub fn validate(self: Statement) !void {
        _ = try boundary.fixedRow(self.schedule());
        const end = @as(u64, self.path_namespace) + 4 * (2 * tree.DEPTH + 1) - 1;
        if (end >= core.fields.m31.Modulus or (self.source_circuit >= self.path_namespace and self.source_circuit <= end)) return error.InvalidMemoryWordNamespace;
    }
    pub fn bytePath(self: Statement, index: u2) !path.Statement {
        try self.validate();
        return .{ .namespace = self.path_namespace + @as(u32, index) * (2 * tree.DEPTH + 1), .source = .{ .circuit = self.source_circuit, .wire = index }, .kind = .memory, .address = self.address + @as(u32, index), .root = self.root };
    }
};
pub const Prepared = struct {
    boundary_row: boundary.Row,
    paths: [4]path.Prepared,
    pub fn deinit(self: *Prepared) void {
        for (&self.paths) |*item| item.deinit();
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, statement: Statement, snapshot: []const tree.Leaf) !Prepared {
    try statement.validate();
    const hasher = tree.TreeHasher.init(.memory);
    var openings: [4]tree.Opening = undefined;
    var bytes: [4]u8 = undefined;
    // Reject a snapshot/root mismatch before constructing any hash witness.
    for (&openings, &bytes, 0..) |*opening, *byte, i| {
        opening.* = try hasher.opening(snapshot, statement.address + @as(u32, @intCast(i)));
        if (!std.meta.eql(opening.root, statement.root)) return error.MemorySnapshotRootMismatch;
        byte.* = opening.value;
    }
    var result: Prepared = undefined;
    result.boundary_row = try boundary.logicalRow(statement.schedule(), bytes);
    var built: usize = 0;
    errdefer for (result.paths[0..built]) |*item| item.deinit();
    for (&result.paths, openings, 0..) |*item, opening, i| {
        item.* = try path.prepare(a, try statement.bytePath(@intCast(i)), opening.value, &opening.siblings);
        built += 1;
    }
    return result;
}
pub fn trusted(a: std.mem.Allocator, statement: Statement) !Prepared {
    try statement.validate();
    var result: Prepared = undefined;
    result.boundary_row = try boundary.fixedRow(statement.schedule());
    var built: usize = 0;
    errdefer for (result.paths[0..built]) |*item| item.deinit();
    for (&result.paths, 0..) |*item, i| {
        item.* = try path.trusted(a, try statement.bytePath(@intCast(i)));
        built += 1;
    }
    return result;
}
