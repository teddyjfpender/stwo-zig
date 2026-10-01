//! Tests of `finalize_constants.zig`: `crates/circuits/src/finalize_constants_test.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). `expect!` snapshots are kept
//! verbatim; the IndexMap order rules get their own tests.

const std = @import("std");
const stwo_core = @import("stwo_core");
const context_mod = @import("context.zig");
const finalize_constants = @import("finalize_constants.zig");
const ivalue = @import("ivalue.zig");
const testing = @import("testing.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const Var = context_mod.Var;
const TraceContext = context_mod.Context(QM31);
const gpa = std.testing.allocator;

fn q(a: u32, b: u32, c: u32, d: u32) QM31 {
    return ivalue.qm31FromU32s(a, b, c, d);
}

fn m(value: u32) QM31 {
    return q(value, 0, 0, 0);
}

fn expectValid(ctx: *const TraceContext) !void {
    try std.testing.expectEqual(null, try ctx.circuit.firstYieldViolation(gpa));
    try std.testing.expect(try ctx.isCircuitValid());
}

test "finalize constants: plus-one chain topology" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    _ = try ctx.constant(m(2));
    _ = try ctx.constant(m(4));
    // `min_base = 6` and the longest run is 0..=2 (gap at 3), so the chain runs 2..=6.
    try finalize_constants.finalizeConstantsWithMinBase(QM31, &ctx, 6);
    try testing.expectCircuit(&ctx.circuit,
        \\[0] = [0] + [0]
        \\[1] = [1] + [0]
        \\[3] = [1] + [1]
        \\[5] = [3] + [1]
        \\[4] = [5] + [1]
        \\[6] = [4] + [1]
        \\[7] = [6] + [1]
        \\[10] = [9] + [1]
        \\[12] = [10] + [11]
        \\[9] = [8] - [3]
        \\[2] = [2] * [1]
        \\[8] = [2] * [2]
        \\[11] = [10] * [2]
        \\output [2]
        \\
    );
    // The chain filled fresh vars with 3, 5 and 6.
    try std.testing.expect(ctx.get(.{ .idx = 5 }).eql(m(3)));
    try std.testing.expect(ctx.get(.{ .idx = 6 }).eql(m(5)));
    try std.testing.expect(ctx.get(.{ .idx = 7 }).eql(m(6)));
    try expectValid(&ctx);
}

test "finalize constants: large M31 decomposition" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    // 37 = (1·5 + 2)·5 + 2 in base `min_base = 5`.
    _ = try ctx.constant(m(37));
    try finalize_constants.finalizeConstantsWithMinBase(QM31, &ctx, 5);
    try testing.expectCircuit(&ctx.circuit,
        \\[0] = [0] + [0]
        \\[1] = [1] + [0]
        \\[4] = [1] + [1]
        \\[5] = [4] + [1]
        \\[6] = [5] + [1]
        \\[7] = [6] + [1]
        \\[8] = [7] + [4]
        \\[3] = [9] + [4]
        \\[12] = [11] + [1]
        \\[14] = [12] + [13]
        \\[11] = [10] - [4]
        \\[2] = [2] * [1]
        \\[9] = [8] * [7]
        \\[10] = [2] * [2]
        \\[13] = [12] * [2]
        \\output [2]
        \\
    );
    try std.testing.expect(ctx.get(.{ .idx = 8 }).eql(m(7)));
    try std.testing.expect(ctx.get(.{ .idx = 9 }).eql(m(35)));
    try std.testing.expect(ctx.get(.{ .idx = 3 }).eql(m(37)));
    try expectValid(&ctx);
}

test "finalize constants: broadcast decomposition" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    // (11, 11, 11, 11) = 11 · (1, 1, 1, 1), with 11 = 2·5 + 1 built in base 5.
    _ = try ctx.constant(q(11, 11, 11, 11));
    try finalize_constants.finalizeConstantsWithMinBase(QM31, &ctx, 5);
    try testing.expectCircuit(&ctx.circuit,
        \\[0] = [0] + [0]
        \\[1] = [1] + [0]
        \\[4] = [1] + [1]
        \\[5] = [4] + [1]
        \\[6] = [5] + [1]
        \\[7] = [6] + [1]
        \\[10] = [9] + [1]
        \\[12] = [10] + [11]
        \\[14] = [13] + [1]
        \\[9] = [8] - [4]
        \\[2] = [2] * [1]
        \\[8] = [2] * [2]
        \\[11] = [10] * [2]
        \\[13] = [4] * [7]
        \\[3] = [14] * [12]
        \\output [2]
        \\
    );
    try std.testing.expect(ctx.get(.{ .idx = 12 }).eql(q(1, 1, 1, 1)));
    try std.testing.expect(ctx.get(.{ .idx = 14 }).eql(m(11)));
    try std.testing.expect(ctx.get(.{ .idx = 3 }).eql(q(11, 11, 11, 11)));
    try expectValid(&ctx);
}

test "finalize constants: small mixed M31 and QM31 constants" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    _ = try ctx.constant(q(1, 2, 3, 4));
    try finalize_constants.finalizeConstantsWithMinBase(QM31, &ctx, 5);
    try testing.expectCircuit(&ctx.circuit,
        \\[0] = [0] + [0]
        \\[1] = [1] + [0]
        \\[4] = [1] + [1]
        \\[5] = [4] + [1]
        \\[6] = [5] + [1]
        \\[7] = [6] + [1]
        \\[10] = [9] + [1]
        \\[12] = [10] + [11]
        \\[14] = [1] + [13]
        \\[16] = [5] + [15]
        \\[3] = [14] + [17]
        \\[9] = [8] - [4]
        \\[2] = [2] * [1]
        \\[8] = [2] * [2]
        \\[11] = [10] * [2]
        \\[13] = [9] * [4]
        \\[15] = [9] * [6]
        \\[17] = [16] * [2]
        \\output [2]
        \\
    );
    try std.testing.expect(ctx.get(.{ .idx = 3 }).eql(q(1, 2, 3, 4)));
    try std.testing.expect(ctx.get(.{ .idx = 14 }).eql(q(1, 2, 0, 0)));
    try std.testing.expect(ctx.get(.{ .idx = 17 }).eql(q(0, 0, 3, 4)));
    try expectValid(&ctx);
}

test "finalize constants: large mixed M31 and QM31 constants" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    for ([_]QM31{
        q(1000, 2000, 3000, 4000), q(1, 1, 1, 1),    q(2, 2, 2, 2),    q(666, 666, 666, 666), m(3456),
        m(7890),                   q(1234, 2, 3, 4), q(0, 1234, 0, 0), q(0, 0, 1234, 0),      q(0, 0, 0, 1234),
    }) |value| _ = try ctx.constant(value);
    try finalize_constants.finalizeConstants(QM31, &ctx);
    try expectValid(&ctx);
}

test "finalize constants: find_max_consecutive stops at the first gap" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    for ([_]u32{ 4, 2, 3, 7 }) |value| _ = try ctx.constant(m(value));
    // Constants 0..=4 are consecutive, so a min base of 2 is raised to 4:
    // the chain is `1+1=2, 2+1=3, 3+1=4`, then 7 = 1·4 + 3, where `1·4` is
    // the cached 4 and needs no gate.
    try finalize_constants.finalizeConstantsWithMinBase(QM31, &ctx, 2);
    try testing.expectCircuit(&ctx.circuit,
        \\[0] = [0] + [0]
        \\[1] = [1] + [0]
        \\[4] = [1] + [1]
        \\[5] = [4] + [1]
        \\[3] = [5] + [1]
        \\[6] = [3] + [5]
        \\[9] = [8] + [1]
        \\[11] = [9] + [10]
        \\[8] = [7] - [4]
        \\[2] = [2] * [1]
        \\[7] = [2] * [2]
        \\[10] = [9] * [2]
        \\output [2]
        \\
    );
    try expectValid(&ctx);
}

test "finalize constants: swap_remove order drives QM31 emission order" {
    // Upstream takes the *first* pending QM31 constant each round, and every
    // `swap_remove` moves the last entry into the hole. Removing `u` (the
    // first QM31 constant) moves `5·i` (the last) to the front, so `5·i` is
    // built before `3 + 4·i` although it was requested after it. An ordered
    // removal would build `4·i` first.
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    for ([_]QM31{ q(2, 1, 0, 0), q(3, 4, 0, 0), q(0, 5, 0, 0) }) |value| _ = try ctx.constant(value);
    try finalize_constants.finalizeConstantsWithMinBase(QM31, &ctx, 5);
    // Vars: 3 = 2 + i, 4 = 3 + 4i, 5 = 5i; the chain is 6..=9 (2..=5), then i = 10.
    const text = try @import("debug_format.zig").circuitText(gpa, &ctx.circuit);
    defer gpa.free(text);
    const five_i = std.mem.indexOf(u8, text, "[5] = [10] * [9]").?;
    const four_i = std.mem.indexOf(u8, text, "] = [10] * [8]").?;
    try std.testing.expect(five_i < four_i);
    try expectValid(&ctx);
}

test "finalize constants: broadcast retain keeps the remaining order" {
    // Requested: B (broadcast), A, C, D. Removing `u` moves D to the front:
    // [D, B, A, C]. `retain` drops B and keeps [D, A, C]. Building D then
    // swap-removes it, moving C to the front: [C, A]. So the constants are
    // built D, C, A. A swap-remove of B instead of `retain` would give
    // [D, C, A], then [A, C] after D: the order D, A, C.
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    _ = try ctx.constant(q(7, 7, 7, 7));
    const a = try ctx.constant(q(1, 2, 3, 4));
    const c = try ctx.constant(q(4, 3, 2, 1));
    const d = try ctx.constant(q(5, 6, 7, 8));
    try finalize_constants.finalizeConstantsWithMinBase(QM31, &ctx, 5);
    var positions: [3]?usize = .{ null, null, null };
    for (ctx.circuit.add.items, 0..) |gate, i| {
        for ([_]Var{ d, c, a }, 0..) |v, k| {
            if (gate.out == v.idx) positions[k] = i;
        }
    }
    try std.testing.expect(positions[0].? < positions[1].?);
    try std.testing.expect(positions[1].? < positions[2].?);
    try expectValid(&ctx);
}
