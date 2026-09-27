//! One exact memory-access boundary word opened against a full BLAKE3 root.
//! The statement is verifier-owned; execution/clock provenance is an external
//! memory-access relation obligation, not inferred from the snapshot here.
const std = @import("std");
const core = @import("stwo_core");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
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
        return .{ .address = self.address, .clock = self.clock, .direction = self.direction, .circuit = self.source_circuit, .first_wire = 0, .uses = 1 };
    }
    pub fn validate(self: Statement) !void {
        _ = try boundary.fixedRow(self.schedule());
        const end = @as(u64, self.path_namespace) + (2 * tree.DEPTH + 1) - 1;
        if (end >= core.fields.m31.Modulus or (self.source_circuit >= self.path_namespace and self.source_circuit <= end)) return error.InvalidMemoryWordNamespace;
    }
    pub fn wordPath(self: Statement) !path.Statement {
        try self.validate();
        return .{ .namespace = self.path_namespace, .source = .{ .circuit = self.source_circuit, .wire = 0 }, .kind = .memory, .address = try tree.memoryIndex(self.address), .root = self.root };
    }
};
pub const Prepared = struct {
    boundary_row: boundary.Row,
    paths: [1]path.Prepared,
    pub fn deinit(self: *Prepared) void {
        for (&self.paths) |*item| item.deinit();
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, statement: Statement, snapshot: []const tree.Leaf) !Prepared {
    try statement.validate();
    const hasher = tree.TreeHasher.init(.memory);
    const opening = try hasher.opening(snapshot, try tree.memoryIndex(statement.address));
    if (!std.meta.eql(opening.root, statement.root)) return error.MemorySnapshotRootMismatch;
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, opening.value, .little);
    return .{
        .boundary_row = try boundary.logicalRow(statement.schedule(), bytes),
        .paths = .{try path.prepare(a, try statement.wordPath(), opening.value, &opening.siblings)},
    };
}

pub fn trusted(a: std.mem.Allocator, statement: Statement) !Prepared {
    try statement.validate();
    return .{
        .boundary_row = try boundary.fixedRow(statement.schedule()),
        .paths = .{try path.trusted(a, try statement.wordPath())},
    };
}
