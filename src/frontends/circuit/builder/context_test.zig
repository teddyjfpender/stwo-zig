//! Tests of `context.zig`: `crates/circuits/src/context_test.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230) plus the Zig-side invariants.

const std = @import("std");
const stwo_core = @import("stwo_core");
const context_mod = @import("context.zig");
const ivalue = @import("ivalue.zig");
const testing = @import("testing.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const NoValue = ivalue.NoValue;
const TraceContext = context_mod.Context(QM31);
const gpa = std.testing.allocator;

test "context: constants are interned in first-use order" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const x = ivalue.qm31FromU32s(1, 2, 3, 4);
    const a = try ctx.constant(x);
    _ = try ctx.constant(x.add(x));
    // The second request for `x` returns the same variable.
    const c = try ctx.constant(x);
    try std.testing.expectEqual(a, c);
    const expected = [_]QM31{ QM31.zero(), QM31.one(), context_mod.u_value, x, x.add(x) };
    try std.testing.expectEqual(expected.len, ctx.values().len);
    for (expected, ctx.values()) |e, actual| try std.testing.expect(e.eql(actual));

    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

test "context: set_outputs copies values, yields and marks the reserved vars" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const a = try ctx.constant(ivalue.qm31FromU32s(3, 0, 0, 0));
    const reserved0 = try ctx.reserve();
    const reserved1 = try ctx.reserve();
    try ctx.setOutputs(&.{ a, a });
    try std.testing.expect(ctx.get(reserved0).eql(ivalue.qm31FromU32s(3, 0, 0, 0)));
    try std.testing.expect(ctx.get(reserved1).eql(ivalue.qm31FromU32s(3, 0, 0, 0)));
    try std.testing.expectEqualSlices(u32, &.{ context_mod.u_var_idx, reserved0.idx, reserved1.idx }, ctx.circuit.output.items);

    try ctx.finalize(false);
    try std.testing.expectEqual(null, try ctx.circuit.firstYieldViolation(gpa));
    try std.testing.expect(try ctx.isCircuitValid());
}

test "context: an unfulfilled reservation fails finalize" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    _ = try ctx.reserve();
    try std.testing.expectError(error.UnassignedReservedVars, ctx.finalize(false));
}

test "context: set_outputs rejects a count mismatch" {
    var ctx = try TraceContext.init(gpa, 2);
    defer ctx.deinit();
    try std.testing.expectError(error.OutputCountMismatch, ctx.setOutputs(&.{ctx.zero()}));
}

test "context: Context::new(n) reserves vars 3..3+n" {
    var ctx = try context_mod.Context(NoValue).init(gpa, 8);
    defer ctx.deinit();
    try std.testing.expectEqual(@as(u32, 11), ctx.circuit.n_vars);
    try std.testing.expectEqualSlices(u32, &.{ 3, 4, 5, 6, 7, 8, 9, 10 }, ctx.reserved_vars.items);
}

/// A circuit with a single U16 guess holding `value`, its guesses finalized.
fn checkU16Guess(value: u32) !bool {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    _ = try ctx.guessU16(ivalue.qm31FromU32s(value, 0, 0, 0));
    try ctx.finalizeGuessedVars();
    return ctx.isCircuitValid();
}

test "context: a U16 guess accepts 16-bit values" {
    for ([_]u32{ 0, 12345, 0xFFFF }) |value| try std.testing.expect(try checkU16Guess(value));
}

test "context: a U16 guess rejects out-of-range values" {
    for ([_]u32{ 0x1_0000, 70_000 }) |value| try std.testing.expect(!try checkU16Guess(value));
}

test "context: zero and one are the first two constants" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    try std.testing.expectEqual(ctx.zero(), try ctx.constant(QM31.zero()));
    try std.testing.expectEqual(ctx.one(), try ctx.constant(QM31.one()));
}

test "context: check_vars_used reports unused and wrongly marked vars" {
    {
        var ctx = try TraceContext.init(gpa, 0);
        defer ctx.deinit();
        _ = try ctx.guess(QM31.one());
        try std.testing.expectError(error.UnusedVarNotMarked, ctx.finalize(true));
    }
    {
        var ctx = try TraceContext.init(gpa, 0);
        defer ctx.deinit();
        const x = try ctx.guess(QM31.one());
        try ctx.markAsUnused(x);
        try ctx.finalize(true);
    }
    {
        var ctx = try TraceContext.init(gpa, 0);
        defer ctx.deinit();
        const x = try ctx.guess(QM31.one());
        try ctx.markAsUnused(x);
        try ctx.eq(x, x);
        try std.testing.expectError(error.UsedVarMarkedUnused, ctx.finalize(true));
    }
}

test "context: constants requested after finalize still intern" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    try ctx.finalize(false);
    const n_vars = ctx.circuit.n_vars;
    // The zero word is var 0; a new value gets a fresh, unyielded var.
    try std.testing.expectEqual(ctx.zero(), try ctx.constant(QM31.zero()));
    const fresh = try ctx.constant(ivalue.qm31FromU32s(77, 0, 0, 0));
    try std.testing.expectEqual(n_vars, fresh.idx);
    try std.testing.expectEqual(fresh, try ctx.constant(ivalue.qm31FromU32s(77, 0, 0, 0)));
}

test "context: assert_eq_on_eval rejects a false eq in value mode" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    ctx.assert_eq_on_eval = true;
    const a = try ctx.guess(ivalue.qm31FromU32s(1, 0, 0, 0));
    const b = try ctx.guess(ivalue.qm31FromU32s(2, 0, 0, 0));
    try std.testing.expectError(error.EqFailedOnEval, ctx.eq(a, b));
    try ctx.eq(a, a);
}

test "context: the default context yields every variable exactly once" {
    // `test_no_constants_beyond_defaults`, `test_finalize_constants_passes_check_vars_used`.
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    try ctx.finalize(true);
    try std.testing.expectEqual(null, try ctx.circuit.firstYieldViolation(gpa));
    try std.testing.expect(try ctx.isCircuitValid());
}

test "context: QM31 and NoValue build identical gate lists" {
    const Build = struct {
        fn run(comptime V: type, ctx: *context_mod.Context(V)) !void {
            const a = try ctx.guess(ivalue.fromQm31(V, ivalue.qm31FromU32s(2, 0, 0, 0)));
            const b = try ctx.guessM31(ivalue.fromQm31(V, ivalue.qm31FromU32s(2, 0, 0, 0)));
            const sum = try ctx.add(a, b);
            const product = try ctx.mul(a, b);
            try ctx.eq(sum, product);
            _ = try ctx.permute(&.{ ctx.u(), a }, ivalue.sortByUCoordinate(V));
            _ = try ctx.inv(sum);
            try ctx.finalize(false);
        }
    };
    var values = try TraceContext.init(gpa, 0);
    defer values.deinit();
    try Build.run(QM31, &values);
    var topology = try context_mod.Context(NoValue).init(gpa, 0);
    defer topology.deinit();
    try Build.run(NoValue, &topology);
    const values_text = try @import("debug_format.zig").circuitText(gpa, &values.circuit);
    defer gpa.free(values_text);
    try testing.expectCircuit(&topology.circuit, values_text);
    try std.testing.expectEqual(values.circuit.n_vars, topology.circuit.n_vars);
    try std.testing.expect(try values.isCircuitValid());
}

test "context: intoValues returns the value table and frees the rest" {
    var ctx = try TraceContext.init(gpa, 1);
    const a = try ctx.guess(QM31.fromU32Unchecked(5, 0, 0, 0));
    _ = try ctx.add(a, ctx.one());
    const expected = try gpa.dupe(QM31, ctx.values());
    defer gpa.free(expected);
    const values = try ctx.intoValues();
    defer gpa.free(values);
    try std.testing.expectEqual(expected.len, values.len);
    for (expected, values) |want, got| try std.testing.expect(want.eql(got));
}
