const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const P = @import("block_v7_terminal_protocol_v1.zig");
const A = @import("block_v7_terminal_algebra_v1.zig");
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const Event = @import("../air/block/memory_event.zig").Event;

fn policy() P.Policy {
    var output: [P.OUTPUT_BYTES]u8 = undefined;
    for (&output, 0..) |*byte, i| byte.* = @truncate(i * 37 + 19);
    output[32] = 1;
    return .{ .final_cycle = (@as(u64, 1) << 40) + 7, .halt_address = 0xc00000, .length_address = 0xc00004, .data_address = 0xc00008, .output_end = 0x1000000, .output = output };
}
fn secure(row: [A.COLUMN_COUNT]M) A.Algebra(Q).Row {
    var out: A.Algebra(Q).Row = undefined;
    for (&out, row) |*dst, cell| dst.* = Q.fromBase(cell);
    return out;
}
fn satisfied(fixed: P.Fixed, row: [A.COLUMN_COUNT]M) bool {
    for (A.Algebra(Q).constraints(A.Algebra(Q).lift(fixed), secure(row))) |equation|
        if (!equation.isZero()) return false;
    return true;
}

test "v7 terminal thirteen exact reads accept all legitimate private high bytes" {
    const plan = try P.Plan.init(policy());
    for (0..256) |high| {
        for (0..P.ROWS) |index| {
            const row = try A.witness(plan, index, @intCast(high));
            try std.testing.expect(satisfied(plan.fixed[index], row));
            for (A.Algebra(M).constraints(A.Algebra(M).lift(plan.fixed[index]), row)) |equation|
                try std.testing.expect(equation.isZero());
            if (index >= P.READS) {
                for (row) |cell| try std.testing.expect(cell.isZero());
                try std.testing.expect(plan.fixed[index].active.isZero());
                continue;
            }
            const event = try plan.transition(index, @intCast(high));
            try (Event{ .space = 1, .address = event.address, .clock = event.clock, .value = event.after }).validate();
            try std.testing.expectEqual(event.before, event.after);
            try std.testing.expectEqualDeep(Word.transitionTuple(event), row[0..A.TUPLE_WIDTH].*);
            if (index >= 2) {
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &bytes, event.after, .little);
                const at = 4 * (index - 2);
                const count = @min(4, P.OUTPUT_BYTES - at);
                try std.testing.expectEqualSlices(u8, plan.policy.output[at..][0..count], bytes[0..count]);
                if (index == 12) try std.testing.expectEqual(@as(u8, @intCast(high)), bytes[3]);
            }
        }
    }
    try std.testing.expectEqual(@as(u32, 1), (try plan.transition(0, 0)).after);
    try std.testing.expectEqual(@as(u32, 43), (try plan.transition(1, 0)).after);
}

test "v7 terminal constrained tuples bits and padding reject every single cell mutation" {
    const plan = try P.Plan.init(policy());
    for (0..P.ROWS) |index| {
        const valid = try A.witness(plan, index, 0xa5);
        for (0..A.COLUMN_COUNT) |column| {
            var wrong = valid;
            wrong[column] = wrong[column].add(M.one());
            try std.testing.expect(!satisfied(plan.fixed[index], wrong));
        }
    }
    // A coordinated invalid-byte forgery still fails Boolean equations.
    var nonbit = try A.witness(plan, 12, 0);
    nonbit[A.TUPLE_WIDTH] = M.fromCanonical(2);
    nonbit[8] = nonbit[8].add(M.fromCanonical(512));
    nonbit[10] = nonbit[10].add(M.fromCanonical(512));
    try std.testing.expect(!satisfied(plan.fixed[12], nonbit));
}

test "v7 terminal fixed plan binds every public byte cycle and ABI address" {
    const original = policy();
    const plan = try P.Plan.init(original);
    try plan.require(original);
    for (0..P.OUTPUT_BYTES) |i| {
        var changed = original;
        changed.output[i] ^= 1;
        if (i == 32) {
            try std.testing.expectError(error.UnsuccessfulTerminalOutput, plan.require(changed));
        } else {
            try std.testing.expectError(error.UntrustedTerminalPlan, plan.require(changed));
            const other = try P.Plan.init(changed);
            try std.testing.expect(!satisfied(other.fixed[2 + i / 4], try A.witness(plan, 2 + i / 4, 0x3c)));
        }
    }
    inline for (.{ "final_cycle", "halt_address", "length_address", "data_address", "output_end" }) |name| {
        var changed = original;
        @field(changed, name) += if (std.mem.eql(u8, name, "final_cycle")) 1 else 64;
        try std.testing.expectError(error.UntrustedTerminalPlan, plan.require(changed));
    }
    var forged = plan;
    forged.fixed[5].clock[3] = forged.fixed[5].clock[3].add(M.one());
    try std.testing.expectError(error.UntrustedTerminalPlan, forged.require(original));
}

test "v7 terminal canonical clock schedule handles wide cycles and rejects overflow" {
    for ([_]u64{ 1, 7, (@as(u64, 1) << 32), P.MAX_FINAL_CYCLE }) |cycle| {
        var admitted = policy();
        admitted.final_cycle = cycle;
        const plan = try P.Plan.init(admitted);
        var previous = 4 * cycle - 1;
        for (0..P.READS) |i| {
            const event = try plan.transition(i, 0);
            try std.testing.expectEqual(4 * cycle + 4 * (i / 3) + i % 3 + 1, event.clock);
            try std.testing.expect(event.clock > previous and event.clock % 4 != 0);
            previous = event.clock;
        }
        try std.testing.expectEqual(4 * cycle + 17, previous);
    }
    for ([_]u64{ 0, P.MAX_FINAL_CYCLE + 1, std.math.maxInt(u64) }) |cycle| {
        var bad = policy();
        bad.final_cycle = cycle;
        try std.testing.expectError(error.InvalidTerminalClock, P.Plan.init(bad));
    }
}

test "v7 terminal rejects aliases unaligned bounded output and out of roster reads" {
    inline for (.{ "halt_address", "length_address", "data_address" }) |name| {
        var bad = policy();
        @field(bad, name) += 1;
        try std.testing.expectError(error.InvalidTerminalAddresses, P.Plan.init(bad));
    }
    var bad = policy();
    bad.halt_address = bad.length_address;
    try std.testing.expectError(error.InvalidTerminalAddresses, P.Plan.init(bad));
    bad = policy();
    bad.length_address = bad.data_address + 40;
    try std.testing.expectError(error.InvalidTerminalAddresses, P.Plan.init(bad));
    bad = policy();
    bad.data_address = 0xffff_fffc;
    bad.output_end = std.math.maxInt(u32);
    try std.testing.expectError(error.InvalidTerminalAddresses, P.Plan.init(bad));
    bad = policy();
    bad.output_end = bad.data_address + 43;
    try std.testing.expectError(error.InvalidTerminalAddresses, P.Plan.init(bad));
    const plan = try P.Plan.init(policy());
    try std.testing.expectError(error.InvalidTerminalReadIndex, plan.transition(13, 0));
    try std.testing.expectError(error.InvalidTerminalReadIndex, A.witness(plan, 16, 0));
}

test "v7 terminal physical interaction recurrence closes exact thirteen read demand" {
    const plan = try P.Plan.init(policy());
    const Relations = @import("../air/relation_challenges.zig").RelationElements(A.TUPLE_WIDTH);
    const relation = Relations.init(Q.fromBase(M.fromCanonical(103)), Q.fromBase(M.fromCanonical(17)));
    var rows: [P.ROWS]A.Algebra(Q).Row = undefined;
    var fractions: [P.ROWS]Q = undefined;
    var sum = Q.zero();
    var count: u32 = 0;
    for (&rows, &fractions, 0..) |*row, *fraction, i| {
        row.* = secure(try A.witness(plan, i, 0xc3));
        const item = A.Algebra(Q).emission(A.Algebra(Q).lift(plan.fixed[i]), row.*);
        fraction.* = item.weight.mul(try relation.combineSecure(item.tuple).inv());
        sum = sum.add(fraction.*);
        count += plan.fixed[i].active.toU32();
    }
    try std.testing.expectEqual(@as(u32, 13), count);
    const normalized = try sum.divM31(M.fromCanonical(P.ROWS));
    var previous = Q.zero();
    for (rows, fractions, 0..) |row, fraction, i| {
        const current = previous.add(fraction).sub(normalized);
        const fixed = A.Algebra(Q).lift(plan.fixed[i]);
        try std.testing.expect(A.Algebra(Q).interactionConstraint(fixed, row, relation, current, previous, normalized).isZero());
        try std.testing.expect(!A.Algebra(Q).interactionConstraint(fixed, row, relation, current, previous, normalized.add(Q.one())).isZero());
        previous = current;
    }
    try std.testing.expect(previous.isZero());
}
