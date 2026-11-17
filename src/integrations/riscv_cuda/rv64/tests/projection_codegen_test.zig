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

test "byte shift address projections agree with independent integer modular reference" {
    const A = @import("stwo_riscv_frontend").rv64_air;
    const B = A.crypto.bulk_memory;
    const K = A.crypto.keccak_sponge;
    var selectors: [7]M = undefined;
    for ([_]u32{ 1280130139, 658457521, 2039696468, 2002804288, 1117755473, 1311423401, 260321919 }, &selectors) |v, *s| s.* = M.fromCanonical(v);
    try std.testing.expectEqual(@as(u32, 971785791), A.evaluation.addByteShiftFor(M, M.fromCanonical(1177117555), &selectors).v);
    var bulk: [B.layout.ucopy.MAIN]M = @splat(M.zero());
    bulk[B.layout.ucopy.src] = M.fromCanonical(1177117555);
    @memcpy(bulk[B.layout.ucopy.sel..][0..7], &selectors);
    try std.testing.expectEqual(@as(u32, 971785791), B.equations.ucopySource(M, &bulk)[0].v);
    var sponge: [K.layout.call.MAIN]M = @splat(M.zero());
    @memcpy(sponge[K.layout.call.shift + 1 ..][0..7], &selectors);
    try std.testing.expectEqual(@as(u32, 1942151883), K.equations.callPacket(M, &sponge, 1)[0].v);
}

test "LS-D64 descriptor45 seeded OWNER projection agrees across base lifted and symbolic lanes" {
    const A = @import("stwo_riscv_frontend").rv64_air;
    const D = A.memory.load_store_dword;
    const F = A.evaluation.symbolic.SymbolicLane(O);
    var rng = std.Random.DefaultPrng.init(0x87323);
    var row: [D.layout.MAIN]M = undefined;
    var challenges: G.Source.Challenges.For(O) = undefined;
    var found = false;
    // Replay precisely the original regression's RNG consumption. Recording
    // preceding IR programs consumes no RNG and is deliberately unnecessary.
    for (Fixtures.descriptors(), 0..) |descriptor, index| {
        const shape = try descriptor.shape();
        const selected = descriptor.origin == .dword and descriptor.origin.dword == 0;
        for (0..shape.fixed) |_| _ = rng.random().uintLessThan(u32, core.fields.m31.Modulus);
        for (0..shape.main) |i| {
            const value = M.fromCanonical(rng.random().uintLessThan(u32, core.fields.m31.Modulus));
            if (selected) row[i] = value;
        }
        for (0..shape.main + G.Source.Public.count) |_| _ = rng.random().uintLessThan(u32, core.fields.m31.Modulus);
        for (&challenges.offsets) |*value| value.* = Fixtures.random(rng.random());
        for (&challenges.coefficients, 0..) |*coefficients, relation| for (coefficients) |*value| {
            value.* = Fixtures.random(rng.random());
            if (relation == @intFromEnum(G.Source.Fractions.Relation.range8)) value.* = O.one();
        };
        if (selected) {
            try std.testing.expectEqual(@as(usize, 45), index);
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
    const raw = D.equations.ownerTuple(M, &row);
    var lifted: [D.layout.MAIN]O = undefined;
    for (row, &lifted) |value, *out| out.* = O.fromBase(value);
    const secure = D.equations.ownerTuple(O, &lifted);
    const modulus: u64 = core.fields.m31.Modulus;
    const load = (@as(u64, row[0].v) + modulus - row[1].v) % modulus;
    const opcode = (load * D.layout.LD_OPCODE + @as(u64, row[1].v) * D.layout.SD_OPCODE) % modulus;
    try std.testing.expectEqual(@as(u32, @intCast(opcode)), raw[0].v);
    const tick = (@as(u64, row[D.layout.column(12)].v) + @as(u64, row[D.layout.column(13)].v) * 65536) % modulus;
    try std.testing.expectEqual(@as(u32, @intCast(tick)), raw[18].v);
    var recording = A.evaluation.symbolic.Recording(O).init(a);
    defer recording.deinit();
    recording.begin();
    defer recording.end();
    var symbolic: [D.layout.MAIN]F = undefined;
    for (&symbolic, 0..) |*value, column| value.* = F.input(1, column, 0);
    const tuple = D.equations.ownerTuple(F, &symbolic);
    var ids: [19]u32 = undefined;
    for (tuple, &ids) |value, *id| id.* = value.id;
    var program = try recording.builder.finish(@splat(0), &ids);
    defer program.deinit();
    const inputs = try a.alloc(O, program.inputs.len);
    defer a.free(inputs);
    for (program.inputs, inputs) |input, *value| value.* = O.fromBase(row[input.column]);
    const evaluated = try program.evaluate(a, inputs);
    defer a.free(evaluated);
    for (raw, secure, evaluated, 0..) |base, extension, ir, coordinate| {
        if (!O.fromBase(base).eql(extension) or !ir.eql(extension))
            std.debug.print("descriptor45 OWNER coordinate={d} row={any}\n", .{ coordinate, row });
        try std.testing.expect(O.fromBase(base).eql(extension));
        try std.testing.expect(ir.eql(extension));
    }
    const relation: usize = @intFromEnum(G.Source.Fractions.Relation.owner);
    var expected = challenges.offsets[relation];
    for (secure, 0..) |value, i| expected = expected.sub(challenges.coefficients[relation][i].mul(value));
    try std.testing.expect(expected.eql(challenges.denominatorBase(.owner, raw)));
}
