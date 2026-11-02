const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const E = @import("../evaluation.zig");
const Q = E.Q;
const L = E.L;
const Encoding = @import("../encoding.zig");
const Cpu = @import("../range/cpu.zig");
const Provider = @import("../range/provider.zig");
const P = @import("../projection.zig");
const W = @import("../witness.zig");
const S = @import("../statement.zig");
const a = std.testing.allocator;

test "rv64 byte encoding keeps only publicly referenced byte bits" {
    const program = [_]u32{0x001080b3}; // ADD x1,x1,x1
    var initial: [32]u64 = @splat(0);
    initial[1] = 0x87654321ffffffff;
    var final = initial;
    final[1] +%= final[1];
    const public = S.Statement{ .program_base = 0x1000, .program = &program, .initial_pc = 0x1000, .final_pc = 0x1004, .initial_registers = initial, .final_registers = final, .memory = &.{}, .steps = 1 };
    var witness = try W.Witness.build(a, public);
    defer witness.deinit();
    const projection = try P.Projection.init(a, public, witness.metadata, 32);
    const plan = Encoding.Plan.init(&projection, &.{.ADD});
    try std.testing.expect(plan.main_count < projection.main_count);
    var physical: [L.MAIN]Q = undefined;
    for (plan.main_sources[0..plan.main_count], 0..) |c, i| physical[i] = Q.fromBase(witness.rows[0][c]);
    const logical = plan.inflateMain(physical[0..plan.main_count]);
    for (0..L.WORDS) |w| for (0..8) |i| {
        const word: L.Word = @enumFromInt(w);
        try std.testing.expect(logical[L.byte(word, i)].eql(Q.fromBase(witness.rows[0][L.byte(word, i)])));
    };
    const mixed = Encoding.Plan.init(&projection, &.{ .AND, .JALR, .DIVW, .LB });
    for (mixed.byte_bits[@intFromEnum(L.Word.a)]) |selected| try std.testing.expect(selected);
    try std.testing.expect(mixed.byte_bits[@intFromEnum(L.Word.address)][0]);
    try std.testing.expect(mixed.byte_bits[@intFromEnum(L.Word.b)][3]);
    for (mixed.byte_bits[@intFromEnum(L.Word.memory_before)]) |selected| try std.testing.expect(selected);
}

fn syntheticPlan(count: usize) Encoding.Plan {
    var result = Encoding.Plan{ .support = .{}, .main_count = count, .range_count = count };
    for (0..count) |i| result.range_sources[i] = @intCast(i);
    return result;
}

test "rv64 byte LogUp closes batches of one two three and rejects malformed values" {
    const alpha = Q.fromU32Unchecked(911, 3, 5, 7);
    for (1..8) |count| {
        const plan = syntheticPlan(count);
        var data: [7][32]M = undefined;
        var columns: [7][]const M = undefined;
        for (0..count) |c| {
            for (&data[c], 0..) |*v, i| v.* = M.fromCanonical(@intCast((17 * c + i) % 256));
            columns[c] = &data[c];
        }
        const counts = try plan.counts(columns[0..count]);
        var provider = try Provider.Trace.init(a, &counts);
        defer provider.deinit();
        const provider_claim = try provider.generateInteraction(alpha);
        var interaction = try Cpu.buildInteraction(a, &plan, columns[0..count], 5, alpha);
        defer interaction.deinit();
        try std.testing.expect(provider_claim.add(interaction.claim).isZero());
        const width = Cpu.interactionCount(&plan);
        var current: [16]Q = undefined;
        var previous: [16]Q = undefined;
        var physical: [7]Q = undefined;
        var residuals: [8]Q = undefined;
        for (0..32) |i| {
            const row = W.physical(i, 5);
            const prior = W.physical((i + 31) % 32, 5);
            for (0..count) |c| physical[c] = Q.fromBase(data[c][row]);
            for (0..width) |c| {
                current[c] = Q.fromBase(interaction.storage[c * 32 + row]);
                previous[c] = Q.fromBase(interaction.storage[c * 32 + prior]);
            }
            var sink = E.Sink{ .values = &residuals };
            Cpu.evaluate(&plan, physical[0..count], current[0..width], previous[0..width], E.q(@intFromBool(i == 0)), E.q(@intFromBool(i == 31)), alpha, interaction.claim, &sink);
            for (residuals[0..sink.count]) |v| try std.testing.expect(v.isZero());
            current[0] = current[0].add(Q.one());
            sink.count = 0;
            Cpu.evaluate(&plan, physical[0..count], current[0..width], previous[0..width], E.q(@intFromBool(i == 0)), E.q(@intFromBool(i == 31)), alpha, interaction.claim, &sink);
            try std.testing.expect(!residuals[0].isZero());
        }
        // Commit the honest table counts, then forge a CPU byte. All CPU local
        // equations can still hold, but its claim cannot close that provider.
        data[0][0] = M.fromCanonical(256);
        try std.testing.expectError(error.InvalidByteRangeWitness, plan.counts(columns[0..count]));
        var forged = try Cpu.buildInteraction(a, &plan, columns[0..count], 5, alpha);
        defer forged.deinit();
        try std.testing.expect(!forged.claim.add(provider_claim).isZero());
    }
}

test "rv64 byte LogUp evaluates arbitrary full-extension coordinates with degree four" {
    const plan = syntheticPlan(7);
    const alpha = Q.fromU32Unchecked(911, 3, 5, 7);
    var differences: [6][5]Q = undefined;
    var physical: [7]Q = undefined;
    var current: [16]Q = undefined;
    var previous: [16]Q = undefined;
    for (0..6) |t| {
        const x = E.q(@intCast(t));
        for (&physical, 0..) |*v, i| v.* = Q.fromU32Unchecked(@intCast(7 + i), 11, 13, 17).add(x.mul(Q.fromU32Unchecked(19, 23, 29, 31)));
        for (&current, &previous, 0..) |*c, *p, i| {
            c.* = Q.fromU32Unchecked(@intCast(37 + i), 41, 43, 47).add(x.mul(Q.fromU32Unchecked(53, 59, 61, 67)));
            p.* = Q.fromU32Unchecked(@intCast(71 + i), 73, 79, 83).add(x.mul(Q.fromU32Unchecked(89, 97, 101, 103)));
        }
        var sink = E.Sink{ .values = &differences[t] };
        Cpu.evaluate(&plan, &physical, &current, &previous, x, x.add(Q.one()), alpha, alpha, &sink);
        try std.testing.expectEqual(@as(usize, 5), sink.count);
        // Explicit independent denominator and sum-of-inverses numerator.
        const d0 = alpha.sub(physical[0]);
        const d1 = alpha.sub(physical[1]);
        const d2 = alpha.sub(physical[2]);
        try std.testing.expect(differences[t][0].eql(d0.mul(d1).mul(d2).mul(Q.fromPartialEvals(current[0..4].*)).sub(Q.one())));
    }
    for (0..5) |order| for (0..5 - order) |t| for (0..5) |c| {
        differences[t][c] = differences[t + 1][c].sub(differences[t][c]);
    };
    for (differences[0]) |v| try std.testing.expect(v.isZero());
}

test "rv64 byte encoding compacts product carries with authenticated low bytes" {
    var projection: P.Projection = undefined;
    projection.support = .{};
    projection.main_map = @splat(0);
    for (0..16) |i| projection.main_map[L.productCarry(i)] = Encoding.derived;
    for (0..4) |slot| {
        projection.main_map[L.previousClock(slot)] = Encoding.derived;
        projection.main_map[L.gap(slot)] = Encoding.derived;
    }
    var opcodes: [L.fixed.OPCODES]E.O = undefined;
    for (&opcodes, 0..) |*op, i| op.* = @enumFromInt(i);
    var plan = Encoding.Plan.init(&projection, &opcodes);
    const original_count = plan.main_count;
    const original_ranges = plan.range_count;
    plan.compactProductCarries();
    try std.testing.expectEqual(original_count - 112, plan.main_count);
    try std.testing.expectEqual(original_ranges + 16, plan.range_count);
    var row: [L.MAIN]M = @splat(M.zero());
    var physical: [L.MAIN]Q = undefined;
    for (0..2048) |value| {
        row[L.productCarry(0)] = M.fromCanonical(@intCast(value));
        for (0..11) |bit| row[L.productCarry(0) + 1 + bit] = M.fromCanonical(@intCast((value >> @as(u5, @intCast(bit))) & 1));
        for (0..plan.main_count) |c| physical[c] = Q.fromBase(plan.projectValue(&row, c));
        const logical = plan.inflateMain(physical[0..plan.main_count]);
        try std.testing.expect(logical[L.productCarry(0)].eql(E.q(@intCast(value))));
        var fixed: E.Fixed = @splat(Q.zero());
        var residuals: [5]Q = undefined;
        var sink = E.Sink{ .values = &residuals };
        @import("../range/constraints.zig").productCarryRange(.{ .f = &fixed, .m = &logical }, &sink, 0, Q.one());
        for (residuals) |residual| try std.testing.expect(residual.isZero());
    }
    // At 2^21 rows every committed base column is exactly 8 MiB, before
    // interpolation, LDE, commitment nodes or quotient scratch.
    std.debug.print("RV64 all-opcode byte plan: main={d}, requests={d}, interaction={d}; compact carry main={d}, requests={d}, interaction={d}\n", .{ original_count, original_ranges, ((original_ranges + 2) / 3 + 1) * 4, plan.main_count, plan.range_count, Cpu.interactionCount(&plan) });
}
