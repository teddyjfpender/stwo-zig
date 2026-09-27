//! Decoded program-access tuple, canonical field encoding and four full roots.
const std = @import("std");
const core = @import("stwo_core");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
const boundary = @import("blake3_program_boundary.zig");
const packing = @import("qm31_pack_wire.zig");
const encoding = @import("blake3_field_bytes.zig");
const path = @import("blake3_memory_path.zig");
pub const CIRCUIT_COUNT = 3 + 4 * (2 * tree.DEPTH + 1);
pub const Statement = struct {
    namespace: u32,
    address: u32,
    multiplicity: u32,
    root: tree.Digest,
    pub fn validate(self: Statement) !void {
        _ = try boundary.fixedRow(self.schedule());
        if (@as(u64, self.namespace) + CIRCUIT_COUNT > core.fields.m31.Modulus) return error.InvalidProgramWordNamespace;
    }
    pub fn schedule(self: Statement) boundary.Schedule {
        return .{ .address = self.address, .multiplicity = self.multiplicity, .circuit = self.namespace };
    }
    pub fn packSchedule(self: Statement) packing.Schedule {
        return .{ .source_circuit = self.namespace, .source_nodes = .{ 0, 1, 2, 3 }, .destination_circuit = self.namespace + 1, .destination_wire = 0 };
    }
    pub fn encodingSchedule(self: Statement) encoding.Schedule {
        return .{ .source_circuit = self.namespace + 1, .source_wire = 0, .destination_circuit = self.namespace + 2, .destination_first = 0, .uses = @splat(1) };
    }
    pub fn fieldPath(self: Statement, index: u2) !path.Statement {
        try self.validate();
        return .{ .namespace = self.namespace + 3 + @as(u32, index) * (2 * tree.DEPTH + 1), .source = .{ .circuit = self.namespace + 2, .wire = index }, .kind = .program, .address = self.address + @as(u32, index), .root = self.root };
    }
};
pub const Prepared = struct {
    boundary_row: boundary.Row,
    packing_row: packing.Row,
    encoding_row: encoding.Row,
    paths: [4]path.Prepared,
    pub fn deinit(self: *Prepared) void {
        for (&self.paths) |*item| item.deinit();
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, statement: Statement, leaves: []const tree.Leaf) !Prepared {
    try statement.validate();
    const hasher = tree.TreeHasher.init(.program);
    var openings: [4]tree.Opening = undefined;
    var values: [4]u32 = undefined;
    for (&openings, &values, 0..) |*opening, *value, i| {
        opening.* = try hasher.opening(leaves, statement.address + @as(u32, @intCast(i)));
        if (!std.meta.eql(opening.root, statement.root)) return error.ProgramRootMismatch;
        value.* = opening.value;
    }
    var result: Prepared = undefined;
    result.boundary_row = try boundary.logicalRow(statement.schedule(), values);
    const coordinates = core.fields.qm31.QM31.fromM31Array(result.boundary_row[0..4].*);
    result.packing_row = try packing.logicalRow(statement.packSchedule(), coordinates);
    result.encoding_row = try encoding.logicalRow(statement.encodingSchedule(), coordinates);
    var built: usize = 0;
    errdefer for (result.paths[0..built]) |*item| item.deinit();
    for (&result.paths, openings, 0..) |*item, opening, i| {
        item.* = try path.prepare(a, try statement.fieldPath(@intCast(i)), opening.value, &opening.siblings);
        built += 1;
    }
    return result;
}
pub fn trusted(a: std.mem.Allocator, statement: Statement) !Prepared {
    try statement.validate();
    var result: Prepared = undefined;
    result.boundary_row = try boundary.fixedRow(statement.schedule());
    result.packing_row = try packing.fixedRow(statement.packSchedule());
    result.encoding_row = try encoding.fixedRow(statement.encodingSchedule());
    var built: usize = 0;
    errdefer for (result.paths[0..built]) |*item| item.deinit();
    for (&result.paths, 0..) |*item, i| {
        item.* = try path.trusted(a, try statement.fieldPath(@intCast(i)));
        built += 1;
    }
    return result;
}
