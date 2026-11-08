const std = @import("std");
const E = @import("../symbolic_external.zig");
const Core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const O = Core.fields.om31.OM31;
const a = std.testing.allocator;
test "external symbolic publics are independently named wires at equal and zero runtime values" {
    const F = E.Lane;
    comptime {
        if (A.evaluation.ConstFor(F) != F) @compileError("public values must remain wires");
    }
    var recording = E.Recording.init(a);
    defer recording.deinit();
    recording.begin();
    defer recording.end();
    const calls = F.parameter(0);
    const first = F.parameter(1);
    const nonempty = F.parameter(2);
    const span = A.evaluation.CallSpanFor(F){ .calls = calls, .first_id = first, .nonempty = nonempty };
    const last = A.evaluation.lastIdFor(F, span);
    const count = A.evaluation.scalarFor(F, calls);
    const roots = [_]u32{ last.id, count.id, A.evaluation.nonemptyFor(F, span).id };
    var p = try recording.builder.finish(@splat(119), &roots);
    defer p.deinit();
    for (p.parameters) |*v| v.* = O.zero();
    const identity = p.identity;
    const out = try p.evaluate(a, &.{});
    defer a.free(out);
    try std.testing.expect(out[0].eql(O.one().neg()));
    try std.testing.expect(out[1].isZero() and out[2].isZero());
    try std.testing.expectEqualSlices(u8, &identity, &p.identity);
    try std.testing.expectEqual(@as(usize, 3), p.parameters.len);
}
test "external symbolic polynomial recorder fails closed on inverse operations" {
    var recording = E.Recording.init(a);
    defer recording.deinit();
    recording.begin();
    defer recording.end();
    const inverse = E.Lane.parameter(0).inv();
    try std.testing.expectError(error.NonPolynomialInverse, recording.builder.finish(@splat(12), &.{inverse.id}));
}

fn spongeParity(comptime kind: A.crypto.keccak_sponge.layout.Kind) !void {
    const K = A.crypto.keccak_sponge;
    const F = E.Lane;
    var recording = E.Recording.init(a);
    defer recording.deinit();
    recording.begin();
    defer recording.end();
    var fixed: [K.layout.FIXED]F = undefined;
    var main: [K.layout.main(kind)]F = undefined;
    var previous: [K.layout.main(kind)]F = undefined;
    for (&fixed, 0..) |*v, i| v.* = F.input(0, i, 0);
    for (&main, &previous, 0..) |*v, *p, i| {
        v.* = F.input(1, i, 0);
        p.* = F.input(1, i, -1);
    }
    const residuals = try a.alloc(F, 4096);
    defer a.free(residuals);
    var sink = A.evaluation.SinkFor(F){ .values = residuals };
    K.equations.emitMainFor(F, kind, &fixed, &main, &previous, .{ .rows = F.parameter(0), .nonempty = F.parameter(1) }, &sink);
    const roots = try a.alloc(u32, sink.count);
    defer a.free(roots);
    for (roots, residuals[0..sink.count]) |*root, v| root.* = v.id;
    var program = try recording.builder.finish(@splat(49), roots);
    defer program.deinit();
    try std.testing.expectEqual(@as(usize, 2), program.parameters.len);
    // Non-Boolean, extension-valued row inputs exercise polynomial identity,
    // not merely agreement on a valid trace where residuals would all vanish.
    const inputs = try a.alloc(O, program.inputs.len);
    defer a.free(inputs);
    var nf: [K.layout.FIXED]O = undefined;
    var nm: [K.layout.main(kind)]O = undefined;
    var np: [K.layout.main(kind)]O = undefined;
    for (&nf, 0..) |*v, i| v.* = O.fromBase(Core.fields.m31.M31.fromCanonical(@intCast(i + 3)));
    for (&nm, &np, 0..) |*v, *p, i| {
        var c: [8]Core.fields.m31.M31 = undefined;
        for (&c, 0..) |*coordinate, k| coordinate.* = Core.fields.m31.M31.fromCanonical(@intCast(7 + 11 * i + k));
        v.* = O.fromM31Array(c);
        p.* = v.add(O.one());
    }
    for (inputs, program.inputs) |*v, mask| v.* = if (mask.tree == 0) nf[mask.column] else if (mask.offset == -1) np[mask.column] else nm[mask.column];
    const native = try a.alloc(O, sink.count);
    defer a.free(native);
    const semantic_ids = try a.alloc(u32, program.parameters.len);
    defer a.free(semantic_ids);
    for (semantic_ids, program.parameters) |*id, v| id.* = v.toM31Array()[0].v - 1;
    for ([_]u32{ 0, 1, 17 }) |rows| {
        // Parameter order is first use, which need not be semantic-ID order.
        for (program.parameters, semantic_ids) |*v, id| {
            v.* = O.fromBase(Core.fields.m31.M31.fromCanonical(if (id == 0) rows else @intFromBool(rows != 0)));
        }
        const actual = try program.evaluate(a, inputs);
        defer a.free(actual);
        var ns = A.evaluation.SinkFor(O){ .values = native };
        K.equations.emitMainFor(O, kind, &nf, &nm, &np, rows, &ns);
        try std.testing.expectEqual(sink.count, ns.count);
        for (actual, native) |x, y| try std.testing.expect(x.eql(y));
    }
}
test "external sponge call and permutation MAIN match native OM31 polynomial authority" {
    try spongeParity(.call);
    try spongeParity(.perm);
}
