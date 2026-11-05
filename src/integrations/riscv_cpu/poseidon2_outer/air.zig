//! Source-owned polynomial recording of the dedicated permutation rows.
//! This is not yet an admitted complete outer proving/PCS factory.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const L = @import("layout.zig");
const Row = @import("row.zig");
const O = Core.fields.om31.OM31;
const M = Core.fields.m31.M31;
const IR = Engine.air.secure_polynomial_program_v2;
const Builder = IR.BuilderFor(O);
threadlocal var current: ?*Builder = null;
const F = struct {
    id: u32,
    fn b() *Builder {
        return current orelse @panic("Poseidon AIR recorder inactive");
    }
    pub fn fromBase(value: M) F {
        return .{ .id = b().constant(O.fromBase(value)) };
    }
    pub fn add(a: F, z: F) F {
        return .{ .id = b().add(a.id, z.id) };
    }
    pub fn sub(a: F, z: F) F {
        return .{ .id = b().sub(a.id, z.id) };
    }
    pub fn mul(a: F, z: F) F {
        return .{ .id = b().mul(a.id, z.id) };
    }
};
pub const Program = IR.ProgramFor(O);
pub fn record(a: std.mem.Allocator) !Program {
    if (current != null) return error.NestedPoseidonRecorder;
    var builder = Builder.init(a);
    defer builder.deinit();
    current = &builder;
    defer current = null;
    var main: [L.MAIN_COLUMNS]F = undefined;
    for (&main, 0..) |*value, i| value.* = .{ .id = builder.input(.{ .tree = 1, .column = @intCast(i), .offset = 0 }) };
    const values = try Row.evaluateFor(F, &main);
    var roots: [L.CONSTRAINTS]u32 = undefined;
    for (&roots, values) |*root, value| root.* = value.id;
    var program = try builder.finish(Row.sourceIdentity(), &roots);
    errdefer program.deinit();
    const degrees = try program.degrees(a);
    defer a.free(degrees);
    for (program.roots) |root| if (degrees[root] > L.MAX_DEGREE) return error.PoseidonDegreeExceeded;
    for (program.inputs) |input| if (input.tree != 1 or input.offset != 0 or input.column >= L.MAIN_COLUMNS) return error.PoseidonMaskAuthority;
    return program;
}
test "dedicated Poseidon source polynomial has452 degree-bounded roots and authentic MAIN masks" {
    const a = std.testing.allocator;
    var program = try record(a);
    defer program.deinit();
    try std.testing.expectEqual(@as(usize, L.CONSTRAINTS), program.roots.len);
    const row = try Row.fill(@splat(M.fromCanonical(37)));
    const inputs = try a.alloc(O, program.inputs.len);
    defer a.free(inputs);
    for (inputs, program.inputs) |*value, input| value.* = O.fromBase(row[input.column]);
    const roots = try program.evaluate(a, inputs);
    defer a.free(roots);
    for (roots) |root| try std.testing.expect(root.isZero());
    const degrees = try program.degrees(a);
    defer a.free(degrees);
    var cubic: usize = 0;
    for (program.roots) |root| {
        try std.testing.expect(degrees[root] <= 3);
        cubic += @intFromBool(degrees[root] == 3);
    }
    try std.testing.expectEqual(@as(usize, L.SBOXES), cubic);
    for ([_]usize{ L.TEMPORARY, L.TEMPORARY + 1, L.OUTPUT }) |column| {
        for (inputs, program.inputs) |*value, input| value.* = O.fromBase(if (input.column == column) row[input.column].add(M.one()) else row[input.column]);
        const bad = try program.evaluate(a, inputs);
        defer a.free(bad);
        var rejected = false;
        for (bad) |value| rejected = rejected or !value.isZero();
        try std.testing.expect(rejected);
    }
    std.debug.print("\nPOSEIDON2_DEDICATED_AIR main={} fixed={} roots={} cubic_roots={} nodes={} identity={x}\n", .{ L.MAIN_COLUMNS, L.FIXED_COLUMNS, program.roots.len, cubic, program.nodes.len, program.identity });
}
