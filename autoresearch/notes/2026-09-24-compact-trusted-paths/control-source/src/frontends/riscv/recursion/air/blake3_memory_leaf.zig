//! Private full-word leaf hashing. All four caller byte limbs feed the hash.
const std = @import("std");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
const hash = @import("blake3_hash_witness.zig");
const graph = @import("blake3_hash_plan.zig");
const bridge = @import("blake3_input_bridge.zig");
const boundary = @import("blake3_boundary.zig");
pub const Caller = struct { circuit: u32, wire: u32 };
pub const Prepared = struct {
    rows: hash.Rows,
    input: bridge.Row,
    digest: ?[32]u8,
    pub fn deinit(self: *Prepared) void {
        self.rows.deinit();
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, kind: tree.Kind, caller: Caller, circuit: u32, value: u32, claim: tree.Digest) !Prepared {
    return buildWithPlan(a, kind, caller, circuit, value, claim, null);
}
pub fn trusted(a: std.mem.Allocator, kind: tree.Kind, caller: Caller, circuit: u32, claim: tree.Digest) !Prepared {
    return buildWithPlan(a, kind, caller, circuit, null, claim, null);
}
pub fn buildWithPlan(a: std.mem.Allocator, kind: tree.Kind, caller: Caller, circuit: u32, value: ?u32, claim: tree.Digest, borrowed: ?*const graph.Plan) !Prepared {
    if (caller.circuit == circuit) return error.InvalidMemoryLeafCaller;
    const byte_count: u3 = 4;
    if (value) |v| {
        if (kind == .program) {
            if (v >= @import("stwo_core").fields.m31.Modulus) return error.NonCanonicalProgramField;
        }
    }
    const frame: tree.Frame = if (kind == .program)
        .{ .program_field = value orelse 0 }
    else
        .{ .leaf = .{ .kind = kind, .value = @intCast(value orelse 0) } };
    const bytes = try frame.encode(a);
    defer a.free(bytes);
    var owned: ?graph.Plan = if (borrowed == null) try graph.build(a, bytes.len) else null;
    defer if (owned) |*item| item.deinit();
    const shape = borrowed orelse &owned.?;
    if (shape.input_len != bytes.len) return error.InvalidMemoryLeafShape;
    var source_index: ?usize = null;
    for (shape.sources, 0..) |source, index| if (source.value == .input and source.value.input.offset == bytes.len - byte_count) {
        if (source.value.input.len != byte_count or source_index != null) return error.InvalidMemoryLeafShape;
        source_index = index;
    };
    const index = source_index orelse return error.InvalidMemoryLeafShape;
    const schedule = bridge.Schedule{ .source_circuit = caller.circuit, .source_wire = caller.wire, .hash_circuit = circuit, .hash_wire = shape.sources[index].wire, .uses = shape.uses[shape.sources[index].wire], .byte_count = byte_count };
    const input = if (value) |byte| try bridge.logicalRow(schedule, byte) else try bridge.fixedRow(schedule);
    var digest: ?[32]u8 = null;
    var rows = if (value != null) blk: {
        const live = try hash.prepareWithPlan(a, circuit, bytes, claim.bytes, shape);
        digest = live.digest;
        break :blk live.rows;
    } else try hash.trustedRowsWithPlan(a, circuit, bytes, claim.bytes, shape);
    errdefer rows.deinit();
    const retained = try a.alloc(boundary.Row, rows.boundary_rows.len - 1);
    @memcpy(retained[0..index], rows.boundary_rows[0..index]);
    @memcpy(retained[index..], rows.boundary_rows[index + 1 ..]);
    a.free(rows.boundary_rows);
    rows.boundary_rows = retained;
    return .{ .rows = rows, .input = input, .digest = digest };
}
