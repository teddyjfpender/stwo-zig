const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const P = core.fields.packed_qm31.PackedQM31;
const M = core.fields.m31.M31;
const K = @import("../block_v8_ram_endpoint_kernel_v1.zig");
const C = @import("../block_v8_ram_endpoint_component_v1.zig");
const T = @import("../block_v7_memory_trace_v1.zig");
fn q(v: u32) Q {
    return Q.fromBase(M.fromCanonical(v));
}
fn relation(comptime n: usize, seed: u32) @import("../block_v7_memory_relations_v1.zig").Relation(Q, n) {
    var result: @import("../block_v7_memory_relations_v1.zig").Relation(Q, n) = undefined;
    result.z = Q.fromU32Unchecked(seed, 3, 5, 7);
    var power = Q.one();
    for (&result.powers) |*v| {
        v.* = power;
        power = power.mul(q(seed + 11));
    }
    return result;
}
fn challenges() C.Challenges(Q) {
    return .{ .native = relation(7, 11), .transition = relation(11, 13), .range16 = relation(1, 17), .bytes = relation(2, 19) };
}
const Context = struct {
    policy: K.Policy,
    ch: C.Challenges(Q),
    pub fn termsAt(self: Context, matrix: T.Matrix, row: usize) ![C.PLANES]@import("../block_v7_memory_relations_v1.zig").Term(Q) {
        return C.terms(Q, self.policy, self.ch, Q.fromBase(matrix.get(0, row)), matrix.row(K.COLUMN_COUNT, 2, row));
    }
};
fn packRows(comptime N: usize, matrix: T.Matrix, offset: usize, start: usize) [N]P {
    var out: [N]P = undefined;
    for (&out, 0..) |*value, column| {
        var lanes: [core.fields.m31.PACK_WIDTH]Q = undefined;
        for (&lanes, 0..) |*lane, index| lane.* = Q.fromBase(matrix.get(offset + column, (start + index) % matrix.size()));
        value.* = P.fromLanes(lanes);
    }
    return out;
}
test "endpoint AIR scalar packed and cyclic interaction equations agree" {
    const a = std.testing.allocator;
    const policy = K.Policy{ .source_ordinal = 7, .max_local_clock = 1024 };
    var source = try T.Matrix.init(a, 4, 2 + K.COLUMN_COUNT, 1 << 20);
    defer source.deinit();
    const endpoints = [_]K.Endpoint{ .{ .address = 16, .initial = 7, .final = 8, .last_clock = 17 }, .{ .address = 65536, .initial = 9, .final = 11, .last_clock = 1000 } };
    for (endpoints, 0..) |endpoint, index| {
        source.set(0, index, M.one());
        source.set(1, index, if (index == 0) M.one() else M.zero());
        const row = try K.constructWithPrevious(endpoint, if (index == 0) null else endpoints[index - 1].address, policy);
        for (row, 0..) |value, column| source.set(2 + column, index, value.toM31Array()[0]);
    }
    const ch = challenges();
    var generated = try T.interactions(C.PLANES, a, source, Context{ .policy = policy, .ch = ch }, 1 << 20);
    defer generated.deinit();
    var spec = C.Spec{ .policy = policy, .challenges = ch, .sums = generated.sums };
    var domain = try spec.prepareDomain(@intCast(source.size()));
    for (0..source.size()) |index| {
        const previous = (index + source.size() - 1) % source.size();
        const result = try domain.evaluate(source.row(2, 0, index), source.row(K.COLUMN_COUNT, 2, index), source.row(K.COLUMN_COUNT, 2, previous), generated.matrix.row(C.PLANES * 4, 0, index), generated.matrix.row(C.PLANES * 4, 0, previous), @intCast(source.size()));
        for (result) |value| try std.testing.expect(value.isZero());
    }
    const W = core.fields.m31.PACK_WIDTH;
    var index: usize = 0;
    while (index < source.size()) : (index += W) {
        const previous = (index + source.size() - 1) % source.size();
        const result = domain.evaluatePacked(packRows(2, source, 0, index), packRows(K.COLUMN_COUNT, source, 2, index), packRows(K.COLUMN_COUNT, source, 2, previous), packRows(C.PLANES * 4, generated.matrix, 0, index), packRows(C.PLANES * 4, generated.matrix, 0, previous));
        for (result) |value| for (0..W) |lane| try std.testing.expect(value.lane(lane).isZero());
    }
    // Changing one physical plane must violate the original prefix equation,
    // even if an aggregate elsewhere could be compensated.
    spec.sums[0] = spec.sums[0].add(Q.one());
    const forged = try spec.evaluate(source.row(2, 0, 0), source.row(K.COLUMN_COUNT, 2, 0), source.row(K.COLUMN_COUNT, 2, source.size() - 1), generated.matrix.row(C.PLANES * 4, 0, 0), generated.matrix.row(C.PLANES * 4, 0, source.size() - 1), @intCast(source.size()));
    var rejected = false;
    for (forged) |value| rejected = rejected or !value.isZero();
    try std.testing.expect(rejected);
}
