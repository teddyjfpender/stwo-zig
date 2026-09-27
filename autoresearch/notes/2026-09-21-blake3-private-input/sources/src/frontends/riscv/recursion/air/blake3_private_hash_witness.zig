//! Binds contiguous caller word wires to private BLAKE3 message words.
//! Caller words use four little-endian bytes, with zero high bytes in the last
//! partial word. Their balancing emissions belong to the caller component.
const std = @import("std");
const core = @import("stwo_core");
const graph = @import("blake3_hash_plan.zig");
const hash = @import("blake3_hash_witness.zig");
const boundary = @import("blake3_boundary.zig");
const bridge = @import("blake3_input_bridge.zig");
pub const Caller = struct { circuit: u32, first_wire: u32 };
pub const Rows = struct {
    hash_rows: hash.Rows,
    bridge_rows: []bridge.Row,
    pub fn deinit(self: *Rows) void {
        const a = self.hash_rows.allocator;
        self.hash_rows.deinit();
        a.free(self.bridge_rows);
        self.* = undefined;
    }
};
pub const Prepared = struct { rows: Rows, digest: [32]u8 };
pub fn prepare(a: std.mem.Allocator, circuit: u32, caller: Caller, input: []const u8, digest: [32]u8) !Prepared {
    var prepared = try hash.prepare(a, circuit, input, digest);
    errdefer prepared.rows.deinit();
    const rows = try replaceInputs(a, circuit, caller, input.len, &prepared.rows);
    return .{ .rows = rows, .digest = prepared.digest };
}
pub fn trustedRows(a: std.mem.Allocator, circuit: u32, caller: Caller, input_len: usize, digest: [32]u8) !Rows {
    var rows = try hash.trustedShapeRows(a, circuit, input_len, digest);
    errdefer rows.deinit();
    return replaceInputs(a, circuit, caller, input_len, &rows);
}
fn replaceInputs(a: std.mem.Allocator, circuit: u32, caller: Caller, input_len: usize, rows: *hash.Rows) !Rows {
    if (caller.circuit == circuit or caller.circuit >= core.fields.m31.Modulus) return error.InvalidBlake3Caller;
    var plan = try graph.build(a, input_len);
    defer plan.deinit();
    const word_count = input_len / 4 + @intFromBool(input_len % 4 != 0);
    const end = std.math.add(usize, caller.first_wire, word_count) catch return error.InvalidBlake3Caller;
    if (end >= core.fields.m31.Modulus) return error.InvalidBlake3Caller;
    const bridges = try a.alloc(bridge.Row, word_count);
    errdefer a.free(bridges);
    const boundaries = try a.alloc(boundary.Row, rows.boundary_rows.len - word_count);
    errdefer a.free(boundaries);
    var private_count: usize = 0;
    var fixed_count: usize = 0;
    for (plan.sources, rows.boundary_rows[0..plan.sources.len]) |source, row| switch (source.value) {
        .constant => {
            boundaries[fixed_count] = row;
            fixed_count += 1;
        },
        .input => |part| {
            if (part.offset % 4 != 0 or part.offset / 4 >= word_count) return error.InvalidBlake3Caller;
            var word: u32 = 0;
            for (row[0..4], 0..) |byte, i| word |= byte.toU32() << @as(u5, @intCast(i * 8));
            bridges[private_count] = try bridge.logicalRow(.{
                .source_circuit = caller.circuit,
                .source_wire = @intCast(caller.first_wire + part.offset / 4),
                .hash_circuit = circuit,
                .hash_wire = source.wire,
                .uses = plan.uses[source.wire],
                .byte_count = part.len,
            }, word);
            private_count += 1;
        },
    };
    if (private_count != word_count or fixed_count + 8 != boundaries.len) return error.InvalidBlake3Caller;
    @memcpy(boundaries[fixed_count..], rows.boundary_rows[plan.sources.len..]);
    a.free(rows.boundary_rows);
    rows.boundary_rows = boundaries;
    return .{ .hash_rows = rows.*, .bridge_rows = bridges };
}
