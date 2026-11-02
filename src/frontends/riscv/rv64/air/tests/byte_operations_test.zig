const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const E = @import("../evaluation.zig");
const Q = E.Q;
const L = E.L;
const P = @import("../projection.zig");
const Encoding = @import("../encoding.zig");
const Operations = @import("../range/operations.zig");
const Consumer = @import("../range/table_cpu.zig");
const Tables = @import("../providers/tables.zig");
const W = @import("../witness.zig");
const a = std.testing.allocator;

fn allPlan(opcodes: []const E.O) Encoding.Plan {
    var projection: P.Projection = undefined;
    projection.support = .{};
    projection.main_map = @splat(0);
    for (0..16) |i| projection.main_map[L.productCarry(i)] = Encoding.derived;
    for (0..4) |slot| {
        projection.main_map[L.previousClock(slot)] = Encoding.derived;
        projection.main_map[L.gap(slot)] = Encoding.derived;
    }
    var plan = Encoding.Plan.init(&projection, opcodes);
    plan.wideClocks();
    plan.compactProductCarries();
    plan.byteOperations(opcodes);
    return plan;
}
fn word(row: *[L.MAIN]M, which: L.Word, value: u64) void {
    for (0..8) |i| row[L.byte(which, i)] = M.fromCanonical(@intCast((value >> @as(u6, @intCast(i * 8))) & 255));
    for (0..64) |i| row[L.bit(which, i)] = M.fromCanonical(@intCast((value >> @as(u6, @intCast(i))) & 1));
}
fn project(plan: *const Encoding.Plan, row: *const [L.MAIN]M, physical: []Q) E.Main {
    for (physical, 0..) |*v, c| v.* = Q.fromBase(plan.projectValue(row, c));
    return plan.inflateMain(physical);
}
fn expectZero(values: []const Q) !void {
    for (values) |v| try std.testing.expect(v.isZero());
}
fn expectTuple(plan: *const Encoding.Plan, kind: Tables.Kind, logical: *const E.Main, physical: []const Q) !void {
    for (0..Consumer.requests(plan, kind)) |request| {
        const tuple = Consumer.tuple(plan, kind, logical, physical, request);
        var base: Tables.Tuple = undefined;
        for (tuple, 0..) |v, i| base[i] = (try v.tryIntoM31()).v;
        _ = try kind.rowIndex(base);
    }
}

test "rv64 byte operations: all signed unsigned W shifts all byte offsets and bit amounts" {
    const opcodes = [_]E.O{ .SLL, .SRL, .SRA, .SLLI, .SRLI, .SRAI, .SLLW, .SRLW, .SRAW, .SLLIW, .SRLIW, .SRAIW };
    const plan = allPlan(&opcodes);
    var row: [L.MAIN]M = @splat(M.zero());
    var physical: [L.MAIN]Q = undefined;
    const p = physical[0..plan.main_count];
    var residuals: [128]Q = undefined;
    const inputs = [_]u64{ 0, 1, 0xffffffffffffffff, 0x8000000000000000, 0x7fffffffffffffff, 0x80000000, 0x12345678deadbeef, 0xff00ff00ff00ff00 };
    for (opcodes) |opcode| for (inputs) |input| for (0..256) |amount| {
        var fixed: E.Fixed = @splat(Q.zero());
        fixed[L.fixed.opcode_start + @intFromEnum(opcode)] = Q.one();
        const is_word = @import("../operations.zig").word(opcode);
        const is_left = @import("../operations.zig").left(opcode);
        const arithmetic = @import("../operations.zig").arithmeticRight(opcode);
        const result: u64 = if (is_word) blk: {
            const value: u32 = @truncate(input);
            const shift: u5 = @truncate(amount);
            const low: u32 = if (is_left) value << shift else if (arithmetic) @bitCast(@as(i32, @bitCast(value)) >> shift) else value >> shift;
            break :blk @bitCast(@as(i64, @as(i32, @bitCast(low))));
        } else blk: {
            const shift: u6 = @truncate(amount);
            break :blk if (is_left) input << shift else if (arithmetic) @bitCast(@as(i64, @bitCast(input)) >> shift) else input >> shift;
        };
        word(&row, .a, input);
        word(&row, .rhs, @intCast(amount));
        word(&row, .result, result);
        var logical = project(&plan, &row, p);
        var sink = E.Sink{ .values = &residuals };
        Operations.shifts(.{ .f = &fixed, .m = &logical }, p, &plan, &sink);
        try expectZero(residuals[0..sink.count]);
        try expectTuple(&plan, .byte_shift, &logical, p);
        logical[L.byte(.result, 0)] = logical[L.byte(.result, 0)].add(Q.one());
        sink.count = 0;
        Operations.shifts(.{ .f = &fixed, .m = &logical }, p, &plan, &sink);
        var rejected = false;
        for (residuals[0..sink.count]) |v| rejected = rejected or !v.isZero();
        try std.testing.expect(rejected);
    };
}

test "rv64 byte operations: AND OR XOR share authenticated AND tuples" {
    const opcodes = [_]E.O{ .AND, .ANDI, .OR, .ORI, .XOR, .XORI };
    const plan = allPlan(&opcodes);
    var row: [L.MAIN]M = @splat(M.zero());
    var physical: [L.MAIN]Q = undefined;
    const p = physical[0..plan.main_count];
    var fixed: E.Fixed = @splat(Q.zero());
    var residuals: [24]Q = undefined;
    for (opcodes) |opcode| for (0..256) |x| for ([_]u64{ 0, 0xff, 0x0123456789abcdef, 0xfedcba9876543210 }) |y| {
        const input = @as(u64, @intCast(x)) * 0x0101010101010101;
        const result = switch (opcode) {
            .AND, .ANDI => input & y,
            .OR, .ORI => input | y,
            else => input ^ y,
        };
        word(&row, .a, input);
        word(&row, .rhs, y);
        word(&row, .result, result);
        @memset(&fixed, Q.zero());
        fixed[L.fixed.opcode_start + @intFromEnum(opcode)] = Q.one();
        const logical = project(&plan, &row, p);
        var sink = E.Sink{ .values = &residuals };
        Operations.bitwise(.{ .f = &fixed, .m = &logical }, p, &plan, &sink);
        try expectZero(&residuals);
        try expectTuple(&plan, .byte_and, &logical, p);
    };
}

test "rv64 byte operations: table claims close physical consumer and reject helper mutation" {
    const plan = allPlan(&.{ .AND, .SRA });
    var row: [L.MAIN]M = @splat(M.zero());
    word(&row, .a, 0xdeadbeef01234567);
    word(&row, .rhs, 39);
    const data = try a.alloc(M, plan.main_count * 32);
    defer a.free(data);
    const columns = try a.alloc([]const M, plan.main_count);
    defer a.free(columns);
    for (columns, 0..) |*column, c| {
        const values = data[c * 32 ..][0..32];
        @memset(values, plan.projectValue(&row, c));
        column.* = values;
    }
    var challenges = Tables.Challenges{ .offset = Q.fromU32Unchecked(911, 3, 5, 7), .coefficients = undefined };
    for (&challenges.coefficients, 0..) |*v, i| v.* = Q.fromU32Unchecked(@intCast(11 + i), 13, 17, 19);
    for ([_]Tables.Kind{ .byte_and, .byte_shift }) |kind| {
        const counts = try Consumer.counts(a, &plan, kind, columns);
        defer a.free(counts);
        var setup = try Tables.Setup.init(a, kind);
        defer setup.deinit();
        var provider = try Tables.Request.init(a, &setup, counts);
        defer provider.deinit();
        const provider_claim = try provider.generateInteraction(challenges);
        var interaction = try Consumer.buildInteraction(a, &plan, kind, columns, 5, challenges);
        defer interaction.deinit();
        try std.testing.expect(interaction.claim.add(provider_claim).isZero());
        var physical: [L.MAIN]Q = undefined;
        for (columns, 0..) |column, c| physical[c] = Q.fromBase(column[0]);
        const p = physical[0..plan.main_count];
        const logical = plan.inflateMain(p);
        var current: [16]Q = undefined;
        var previous: [16]Q = undefined;
        var residuals: [5]Q = undefined;
        const width = Consumer.interactionCount(&plan, kind);
        for (0..32) |i| {
            const index = W.physical(i, 5);
            const prior = W.physical((i + 31) % 32, 5);
            for (0..width) |c| {
                current[c] = Q.fromBase(interaction.storage[c * 32 + index]);
                previous[c] = Q.fromBase(interaction.storage[c * 32 + prior]);
            }
            var sink = E.Sink{ .values = &residuals };
            Consumer.evaluate(&plan, kind, &logical, p, current[0..width], previous[0..width], E.q(@intFromBool(i == 0)), E.q(@intFromBool(i == 31)), challenges, interaction.claim, &sink);
            try expectZero(residuals[0..sink.count]);
        }
        const helper = if (kind == .byte_and) plan.and_start else plan.shift_outputs;
        physical[helper] = physical[helper].add(Q.one());
        var sink = E.Sink{ .values = &residuals };
        Consumer.evaluate(&plan, kind, &logical, p, current[0..width], previous[0..width], Q.zero(), Q.one(), challenges, interaction.claim, &sink);
        try std.testing.expect(!residuals[0].isZero());
    }
}

test "rv64 byte operations: whole opcode support footprint" {
    var opcodes: [L.fixed.OPCODES]E.O = undefined;
    for (&opcodes, 0..) |*op, i| op.* = @enumFromInt(i);
    const plan = allPlan(&opcodes);
    std.debug.print("RV64 byte-operation all-opcode plan: main={d}, byte_requests={d}, byte_interaction={d}, AND_interaction={d}, SHIFT_interaction={d}\n", .{ plan.main_count, plan.range_count, @import("../range/cpu.zig").interactionCount(&plan), Consumer.interactionCount(&plan, .byte_and), Consumer.interactionCount(&plan, .byte_shift) });
    try std.testing.expect(plan.main_count < 650);
}

test "rv64 byte operations: 24-bit clocks reconstruct and enforce strict integer order" {
    const plan = allPlan(&.{.ADD});
    var row: [L.MAIN]M = @splat(M.zero());
    var physical: [L.MAIN]Q = undefined;
    const p = physical[0..plan.main_count];
    var fixed: E.Fixed = @splat(Q.zero());
    var residuals: [12]Q = undefined;
    for ([_]u32{ 0, 4095, 4096, 65535, 65536, 6_503_751, 0xfffffe }) |previous| {
        row[L.previousClock(0)] = M.fromCanonical(previous);
        row[L.gap(0)] = M.fromCanonical(0);
        fixed[L.fixed.slot_start] = Q.one();
        fixed[L.fixed.tick_start] = E.q(previous + 1);
        var logical = project(&plan, &row, p);
        try std.testing.expect(logical[L.previousClock(0)].eql(E.q(previous)));
        var sink = E.Sink{ .values = &residuals };
        @import("../range/constraints.zig").clockRanges(.{ .f = &fixed, .m = &logical }, &sink, &plan);
        try expectZero(&residuals);
        logical[L.gap(0)] = Q.one();
        sink.count = 0;
        @import("../range/constraints.zig").clockRanges(.{ .f = &fixed, .m = &logical }, &sink, &plan);
        try std.testing.expect(!residuals[2].isZero());
        // A modular negative predecessor cannot satisfy the bounded-byte
        // representation, and using the maximum integer forces rejection.
        logical[L.previousClock(0)] = E.q(0xffffff);
        logical[L.gap(0)] = Q.zero();
        sink.count = 0;
        @import("../range/constraints.zig").clockRanges(.{ .f = &fixed, .m = &logical }, &sink, &plan);
        try std.testing.expect(!residuals[2].isZero());
    }
}

test "rv64 byte operations: combined full-extension authority has degree four and streams identically" {
    var opcodes: [L.fixed.OPCODES]E.O = undefined;
    for (&opcodes, 0..) |*op, i| op.* = @enumFromInt(i);
    const plan = allPlan(&opcodes);
    const ByteCpu = @import("../range/cpu.zig");
    const byte_width = ByteCpu.interactionCount(&plan);
    const table_width = Consumer.interactionCount(&plan, .byte_and);
    const width = L.fixed.COUNT + plan.main_count + 2 * (byte_width + 2 * table_width);
    const base = try a.alloc(Q, width);
    defer a.free(base);
    const slope = try a.alloc(Q, width);
    defer a.free(slope);
    const values = try a.alloc(Q, width);
    defer a.free(values);
    const differences = try a.alloc(Q, 6 * 8192);
    defer a.free(differences);
    var random: u64 = 0x5256363442595445;
    for (base, slope) |*b, *s| {
        b.* = draw(&random);
        s.* = draw(&random);
    }
    var challenges = Tables.Challenges{ .offset = draw(&random), .coefficients = undefined };
    for (&challenges.coefficients) |*c| c.* = draw(&random);
    const alpha = draw(&random);
    const claim = draw(&random);
    var count: usize = 0;
    for (0..6) |t| {
        for (values, base, slope) |*v, b, s| v.* = b.add(s.mul(E.q(@intCast(t))));
        const fixed: *const E.Fixed = values[0..L.fixed.COUNT];
        const physical = values[L.fixed.COUNT..][0..plan.main_count];
        const logical = plan.inflateMain(physical);
        const interaction = values[L.fixed.COUNT + plan.main_count ..];
        const Accumulator = core.air.accumulation.PointEvaluationAccumulator;
        var streaming = Accumulator.init(alpha);
        var buffered = Accumulator.init(alpha);
        var sink = E.Sink{ .values = differences[t * 8192 ..][0..8192] };
        var direct = E.Sink{ .values = null, .accumulator = &streaming, .scale = E.q(7) };
        for ([_]*E.Sink{ &sink, &direct }) |out| {
            @import("../range/constraints.zig").local(.{ .f = fixed, .m = &logical }, out, &plan, physical);
            ByteCpu.evaluate(&plan, physical, interaction[0..byte_width], interaction[byte_width..][0..byte_width], fixed[L.fixed.first], fixed[L.fixed.last], alpha, claim, out);
            var offset = byte_width * 2;
            for ([_]Tables.Kind{ .byte_and, .byte_shift }) |kind| {
                Consumer.evaluate(&plan, kind, &logical, physical, interaction[offset..][0..table_width], interaction[offset + table_width ..][0..table_width], fixed[L.fixed.first], fixed[L.fixed.last], challenges, claim, out);
                offset += 2 * table_width;
            }
        }
        count = sink.count;
        try std.testing.expectEqual(count, direct.count);
        for (differences[t * 8192 ..][0..count]) |residual| buffered.accumulate(residual.mul(E.q(7)));
        try std.testing.expect(buffered.finalize().eql(streaming.finalize()));
    }
    for (0..5) |order| for (0..5 - order) |t| for (0..count) |c| {
        differences[t * 8192 + c] = differences[(t + 1) * 8192 + c].sub(differences[t * 8192 + c]);
    };
    for (differences[0..count], 0..) |v, i| if (!v.isZero()) {
        std.debug.print("RV64 byte profile degree exceeds four at constraint {d}\n", .{i});
        return error.InvalidByteProfileDegree;
    };
}
fn draw(state: *u64) Q {
    var limbs: [4]u32 = undefined;
    for (&limbs) |*limb| {
        state.* ^= state.* << 13;
        state.* ^= state.* >> 7;
        state.* ^= state.* << 17;
        limb.* = @intCast(state.* % 2147483647);
    }
    return Q.fromU32Unchecked(limbs[0], limbs[1], limbs[2], limbs[3]);
}

test "rv64 byte operations: admitted-opcode omissions are identities with forbidden selectors zero" {
    var random: u64 = 0x41444d4954544544;
    const residuals = try a.alloc(Q, 8192);
    defer a.free(residuals);
    const differences = try a.alloc(Q, 6 * 8192);
    defer a.free(differences);
    var physical: [L.MAIN]Q = undefined;
    var base: [L.MAIN]Q = undefined;
    var slope: [L.MAIN]Q = undefined;
    for (0..63) |opcode_index| {
        const opcode: E.O = @enumFromInt(opcode_index);
        const plan = Encoding.Plan.fromOpcodes(&.{opcode});
        for (base[0..plan.main_count], slope[0..plan.main_count]) |*b, *s| {
            b.* = draw(&random);
            s.* = draw(&random);
        }
        var fixed_base: E.Fixed = undefined;
        var fixed_slope: E.Fixed = undefined;
        for (&fixed_base, &fixed_slope) |*b, *s| {
            b.* = draw(&random);
            s.* = draw(&random);
        }
        for (0..L.fixed.OPCODES) |op| if (op != opcode_index) {
            fixed_base[L.fixed.opcode_start + op] = Q.zero();
            fixed_slope[L.fixed.opcode_start + op] = Q.zero();
        };
        var count: usize = 0;
        for (0..6) |t| {
            const x = E.q(@intCast(t));
            for (physical[0..plan.main_count], base[0..plan.main_count], slope[0..plan.main_count]) |*v, b, s| v.* = b.add(s.mul(x));
            const logical = plan.inflateMain(physical[0..plan.main_count]);
            var fixed: E.Fixed = undefined;
            for (&fixed, fixed_base, fixed_slope) |*v, b, s| v.* = b.add(s.mul(x));
            const view = E.View{ .f = &fixed, .m = &logical };
            if (!plan.support.product) {
                var omitted = E.Sink{ .values = residuals };
                @import("../product_constraints.zig").evaluate(view, &omitted);
                try expectZero(residuals[0..omitted.count]);
            }
            if (!plan.support.shifts) {
                var omitted = E.Sink{ .values = residuals };
                @import("../shift_constraints.zig").evaluate(view, &omitted);
                try expectZero(residuals[0..omitted.count]);
            }
            for (plan.support.words, 0..) |supported, w| if (!supported) {
                for (0..L.WORD_COLUMNS) |column| try std.testing.expect(logical[w * L.WORD_COLUMNS + column].isZero());
            };
            var sink = E.Sink{ .values = differences[t * 8192 ..][0..8192] };
            @import("../range/constraints.zig").local(view, &sink, &plan, physical[0..plan.main_count]);
            count = sink.count;
        }
        for (0..5) |order| for (0..5 - order) |t| for (0..count) |c| {
            differences[t * 8192 + c] = differences[(t + 1) * 8192 + c].sub(differences[t * 8192 + c]);
        };
        try expectZero(differences[0..count]);
    }
}

test "rv64 byte operations: retained ECDSA admitted-opcode footprint" {
    // Exact active enum IDs in the retained 1,625,938-retirement execution
    // report. This is geometry accounting, not full-proof qualification.
    const ids = [_]u8{ 0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 15, 16, 17, 18, 24, 26, 28, 29, 30, 31, 32, 35, 36, 37, 38, 39, 40, 43, 44, 45, 46, 47, 48, 49, 52 };
    var opcodes: [ids.len]E.O = undefined;
    for (&opcodes, ids) |*op, id| op.* = @enumFromInt(id);
    const plan = Encoding.Plan.fromOpcodes(&opcodes);
    std.debug.print("RV64 retained ECDSA opcode plan: main={d}, byte_requests={d}, byte_interaction={d}, AND_interaction={d}, SHIFT_interaction={d}\n", .{ plan.main_count, plan.range_count, @import("../range/cpu.zig").interactionCount(&plan), Consumer.interactionCount(&plan, .byte_and), Consumer.interactionCount(&plan, .byte_shift) });
    try std.testing.expect(plan.main_count < 420);
    for ([_]L.Word{ .abs_a, .abs_b, .quotient, .remainder, .remainder_gap, .raw_result, .out_abs }) |word_kind| try std.testing.expect(!plan.support.words[@intFromEnum(word_kind)]);
}
