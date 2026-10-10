//! `crates/stark_verifier/src/oods_test.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230): the upstream regression values
//! of `extract_expected_composition_eval` and the order-sensitive
//! `compute_fri_input`. (`test_eval_domain_samples_guess_circuit` pins
//! upstream's standalone `EvalDomainSamples::guess`, which the port folds
//! into `proof.guess`; R4 and R7 cover that traversal.)

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const oods = @import("oods.zig");
const proof_mod = @import("proof.zig");
const select_queries = @import("select_queries.zig");

const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const Context = builder.Context(QM31);
const Var = builder.Var;
const qm31 = builder.ivalue.qm31FromU32s;
const M31Wrapper = builder.wrappers.M31Wrapper;
const Point = @import("circle.zig").Point(Var);

fn expectValue(ctx: *const Context, v: Var, expected: QM31) !void {
    try std.testing.expect(ctx.get(v).eql(expected));
}

/// `validate_circuit`: finalize, then every gate holds.
fn expectValid(ctx: *Context) !void {
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

/// `test_utils::simd_from_u32s`: one `new_var` per four values, zero-padded.
fn simdFromU32s(ctx: *Context, values: []const u32) !builder.simd.Simd {
    const n = std.math.divCeil(usize, values.len, 4) catch unreachable;
    const data = try ctx.scratch().alloc(Var, n);
    for (data, 0..) |*v, i| {
        var lanes = [_]u32{0} ** 4;
        for (0..4) |j| {
            if (4 * i + j < values.len) lanes[j] = values[4 * i + j];
        }
        v.* = try ctx.newVar(qm31(lanes[0], lanes[1], lanes[2], lanes[3]));
    }
    return .fromPacked(data, values.len);
}

test "oods: extract_expected_composition_eval regression" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    const values = [_]QM31{
        qm31(1508389461, 2095170364, 1242839621, 121914987),
        qm31(2074471118, 525791636, 1741315353, 560542608),
        qm31(1544603421, 1313779258, 1591174380, 2142352248),
        qm31(376285896, 1645064251, 1972412846, 145104793),
        qm31(425315367, 0, 0, 0),
        qm31(1670393541, 0, 0, 0),
        qm31(833801100, 0, 0, 0),
        qm31(374213131, 0, 0, 0),
    };
    var composition: [oods.N_COMPOSITION_COLUMNS]Var = undefined;
    for (&composition, values) |*v, value| v.* = try ctx.guess(value);
    const point: Point = .{
        .x = try ctx.guess(qm31(1343313724, 1951183646, 1685075959, 888698585)),
        .y = try ctx.guess(qm31(674655034, 1516640953, 569857337, 1549701521)),
    };
    const expected = try oods.extractExpectedCompositionEval(QM31, &ctx, &composition, point, 5, 1);
    try expectValue(&ctx, expected, qm31(443798542, 633915785, 595028408, 165661052));
    try expectValid(&ctx);
}

test "oods: compute_fri_input regression" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    const pt: Point = .{
        .x = try ctx.guess(qm31(1977529453, 822446523, 1665855107, 812402677)),
        .y = try ctx.guess(qm31(310991198, 1931472985, 1200685911, 1588389778)),
    };
    const responses = [_]oods.OodsResponse{
        .{ .trace_idx = 0, .column_idx = 0, .pt = pt, .value = try ctx.newVar(qm31(1, 0, 0, 0)) },
        .{ .trace_idx = 0, .column_idx = 1, .pt = pt, .value = try ctx.newVar(qm31(2065172982, 64209128, 2018861108, 1995226139)) },
        .{ .trace_idx = 0, .column_idx = 2, .pt = pt, .value = try ctx.newVar(qm31(2038440027, 1469156040, 504751706, 1024643555)) },
    };
    const input = try simdFromU32s(&ctx, &.{ 0, 21, 26 });
    const queries = try select_queries.selectQueries(QM31, &ctx, input, 5);

    // Upstream `data[tree][column][query]`; the port stores each tree
    // column-major, `[column * n_queries + query]`, and guesses in that order.
    const columns = [3][3]u32{
        .{ 1, 1, 1 },
        .{ 863170483, 58834968, 1606816039 },
        .{ 1430398088, 1532221375, 264974634 },
    };
    const tree = try ctx.scratch().alloc(M31Wrapper(Var), 9);
    for (columns, 0..) |column, c| {
        for (column, 0..) |value, q| {
            tree[c * 3 + q] = try builder.wrappers.guessM31(QM31, &ctx, builder.wrappers.m31Value(QM31, M31.fromCanonical(value)));
        }
    }
    const samples: proof_mod.EvalDomainSamples(Var) = .{ .n_queries = 3, .data = .{ tree, &.{}, &.{}, &.{} } };
    const alpha = try ctx.newVar(qm31(1058706599, 1486409878, 1052004241, 54096853));

    const result = try oods.computeFriInput(QM31, &ctx, &responses, queries, &samples, alpha);
    try std.testing.expectEqual(@as(usize, 3), result.len);
    try expectValue(&ctx, result[0], qm31(1799948512, 769698546, 2025315394, 642248561));
    try expectValue(&ctx, result[1], qm31(628725928, 1812037401, 1687426883, 1599536169));
    try expectValue(&ctx, result[2], qm31(2027161127, 718656514, 538553980, 959876533));
    try expectValid(&ctx);
}
