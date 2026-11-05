const std = @import("std");
const core = @import("stwo_core");
const G = @import("../projection_codegen.zig");
const Fixtures = @import("../projection_fixture_support.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
test "native source projection IR preserves every role tuple weight and semantic draw slot at aliased values" {
    var rng = std.Random.DefaultPrng.init(0x87323);
    for (Fixtures.descriptors(), 0..) |descriptor, descriptor_index| {
        var artifact = try G.record(a, descriptor);
        defer artifact.deinit();
        const identity = try artifact.identity();
        const shape = try descriptor.shape();
        const fixed = try a.alloc(M, shape.fixed);
        defer a.free(fixed);
        const main = try a.alloc(M, shape.main);
        defer a.free(main);
        const previous = try a.alloc(M, shape.main);
        defer a.free(previous);
        var public: [G.Source.Public.count]M = undefined;
        for (fixed) |*v| v.* = M.fromCanonical(rng.random().uintLessThan(u32, 2147483647));
        for (main) |*v| v.* = M.fromCanonical(rng.random().uintLessThan(u32, 2147483647));
        for (previous) |*v| v.* = M.fromCanonical(rng.random().uintLessThan(u32, 2147483647));
        for (&public) |*v| v.* = M.fromCanonical(rng.random().uintLessThan(u32, 2147483647));
        const inputs = try a.alloc(O, artifact.program.inputs.len);
        defer a.free(inputs);
        for (artifact.program.inputs, inputs) |input, *v| v.* = O.fromBase(switch (input.tree) {
            0 => fixed[input.column],
            1 => if (input.offset == 0) main[input.column] else previous[input.column],
            2 => public[input.column],
            else => unreachable,
        });
        const ns = try a.alloc(M, artifact.terms);
        defer a.free(ns);
        const ds = try a.alloc(O, artifact.terms);
        defer a.free(ds);
        for (0..3) |mode| {
            var ch: G.Source.Challenges.For(O) = undefined;
            for (&ch.offsets) |*v| v.* = if (mode == 0) Fixtures.random(rng.random()) else if (mode == 1) O.one() else O.zero();
            for (&ch.coefficients, 0..) |*coefficients, relation| for (coefficients) |*v| {
                v.* = if (mode == 0) Fixtures.random(rng.random()) else if (mode == 1) O.one() else O.zero();
                if (relation == @intFromEnum(G.Source.Fractions.Relation.range8)) v.* = O.one();
            };
            for (artifact.source_slots, artifact.program.parameters) |slot, *v| v.* = Fixtures.challenge(ch, slot);
            var sink = G.Source.RowSink{ .challenges = &ch, .numerator = ns, .denominator = ds };
            var base_sink = G.Source.BaseSink{ .row = &sink };
            try descriptor.emit(M, fixed, main, previous, &public, &base_sink);
            if (sink.invalid or sink.count != artifact.terms) {
                std.debug.print("projection sink mismatch descriptor={} mode={} count={} terms={} invalid={}\n", .{ descriptor_index, mode, sink.count, artifact.terms, sink.invalid });
                return error.TestUnexpectedResult;
            }
            const roots = try artifact.program.evaluate(a, inputs);
            defer a.free(roots);
            for (ns, ds, 0..) |n, d, i| {
                if (!roots[2 * i].eql(O.fromBase(n)) or !roots[2 * i + 1].eql(d))
                    std.debug.print("projection value mismatch descriptor={} mode={} term={} numerator={} denominator={}\n", .{ descriptor_index, mode, i, roots[2 * i].eql(O.fromBase(n)), roots[2 * i + 1].eql(d) });
                try std.testing.expect(roots[2 * i].eql(O.fromBase(n)));
                try std.testing.expect(roots[2 * i + 1].eql(d));
            }
            try std.testing.expectEqualSlices(u8, &identity, &(try artifact.identity()));
        }
    }
}
test "projection executable explicitly distinguishes public values from PCS masks and includes binding map in identity" {
    var artifact = try G.record(a, .{ .origin = .{ .core = .cpu }, .cpu_u8_pairs = true, .cpu_compact_decode = true });
    defer artifact.deinit();
    var source: std.ArrayList(u8) = .empty;
    defer source.deinit(a);
    try G.emit(a, source.writer(a), &artifact, "projection_test");
    try std.testing.expect(std.mem.indexOf(u8, source.items, "public_values[") != null);
    try std.testing.expect(std.mem.indexOf(u8, source.items, "trace_log,trace_log,-1)") != null);
    try std.testing.expect(std.mem.indexOf(u8, source.items, "invalid_projection_row") != null);
    const before = try artifact.identity();
    artifact.source_slots[0] = @intCast((artifact.source_slots[0] + 1) % G.challenge_slots);
    try std.testing.expect(!std.mem.eql(u8, &before, &(try artifact.identity())));
    try std.testing.expectError(error.InvalidKernelName, G.emit(a, source.writer(a), &artifact, "bad;kernel"));
}

test "projection shape and source labels cannot change behind an admitted executable identity" {
    var artifact = try G.record(a, .{ .origin = .{ .core = .alu } });
    defer artifact.deinit();
    const lanes = artifact.lanes;
    artifact.lanes *= 2;
    try std.testing.expectError(error.InvalidSourceArtifact, artifact.identity());
    artifact.lanes = lanes;
    artifact.descriptor.origin = .{ .core = .alu_tail };
    try std.testing.expectError(error.InvalidSourceArtifact, artifact.identity());
}

test "load store native opcode projection agrees with integer modular reference" {
    const LS = @import("stwo_riscv_frontend").rv64_air.memory.load_store_v2;
    const Opcode = @import("stwo_riscv_frontend").rv64.decode.Opcode;
    const opcodes = [_]Opcode{ .LB, .LBU, .LH, .LHU, .LW, .LWU, .LD, .SB, .SH, .SW, .SD };
    const flags = [_]u32{ 2047410331, 1079474999, 1044960359, 1338273001, 1640647698, 311033753, 1649266398, 362622634, 2101754357, 2079242676, 1714112313 };
    var main: [LS.layout.projection.MAIN]M = @splat(M.zero());
    var expected: u64 = 0;
    for (flags, opcodes, 0..) |flag, opcode, i| {
        main[LS.layout.projection.column(49 + i)] = M.fromCanonical(flag);
        expected = (expected + @as(u64, flag) * @intFromEnum(opcode)) % core.fields.m31.Modulus;
    }
    try std.testing.expectEqual(@as(u64, 876440816), expected);
    const tuple = LS.equations.ownerTuple(M, &main);
    try std.testing.expectEqual(@as(u32, @intCast(expected)), tuple[0].v);
}
