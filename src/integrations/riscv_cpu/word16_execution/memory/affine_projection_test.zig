//! Independent native row oracle and extension-field affine-map checks.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const X = A.memory.load_store_v2;
const P = X.layout.projection;
const Q = X.types.Q;
const M = X.types.M;

test "LS71 all widths legal offsets high addresses and wrapped EA preserve all79 native coordinates" {
    const ops = [_]@import("stwo_riscv_frontend").rv64.decode.Opcode{ .LB, .LH, .LW, .LD, .LBU, .LHU, .LWU, .SB, .SH, .SW, .SD };
    for (ops) |op| {
        const d = try X.native.describe(op);
        var offset: u64 = 0;
        while (offset + d.width <= 8) : (offset += d.width) {
            const before = A.memory.closed_ram.types.State{ .value = std.math.maxInt(u64), .rights = 3 };
            var after = before;
            after.epoch = 1;
            after.tick = 4;
            const bits: u7 = 8 * @as(u7, d.width);
            const c: u64 = if (d.write) 0 else if (d.signed or bits == 64) std.math.maxInt(u64) else (@as(u64, 1) << @as(u6, @intCast(bits))) - 1;
            for ([_]u64{ offset, 0x8000000000000000 + offset, 0xfffffffffffffff8 + offset }) |ea| {
                const event = X.native.Event{ .opcode = op, .immediate = 4096, .a = ea -% 4096, .b = if (d.write) std.math.maxInt(u64) else 0, .c = c, .epoch = 1, .tick = 4, .before = before, .after = after };
                try X.native.validate(event);
                const original = X.native.logicalRow(event);
                const physical = X.native.row(event);
                try std.testing.expectEqualSlices(M, &original, &P.expandFor(M, &physical));
            }
        }
    }
    const padding = X.native.row(null);
    for (P.expandFor(M, &padding)) |value| try std.testing.expect(value.v == 0);
}

test "LS71 virtual expansion is affine on arbitrary secure coordinates with unchanged stored coordinates" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    var origin: [P.MAIN]Q = undefined;
    var direction: [P.MAIN]Q = undefined;
    for (&origin, &direction) |*a, *b| {
        a.* = channel.drawSecureFelt();
        b.* = channel.drawSecureFelt();
    }
    var expanded: [3][P.LOGICAL_MAIN]Q = undefined;
    for (&expanded, 0..) |*row, at| {
        var physical: [P.MAIN]Q = undefined;
        for (&physical, origin, direction) |*v, a, b| v.* = a.add(b.mul(A.evaluation.q(@intCast(at))));
        row.* = P.expandFor(Q, &physical);
        try std.testing.expectEqualSlices(Q, &physical, &P.projectFor(Q, row));
    }
    for (0..P.LOGICAL_MAIN) |c| try std.testing.expect(expanded[2][c].sub(expanded[1][c]).eql(expanded[1][c].sub(expanded[0][c])));
}

test "LS71 packed quotient rows run on four actual256KiB workers and equal serial accumulation" {
    const engine = @import("stwo_prover_engine");
    const a = std.testing.allocator;
    const size = 16384;
    const widths = X.layout.widths(.ls);
    const count = widths[0] + widths[1] + widths[2];
    const data = try a.alloc(M, count * size);
    defer a.free(data);
    var views: [256][]const M = undefined;
    for (views[0..count], 0..) |*view, c| {
        const column = data[c * size ..][0..size];
        for (column, 0..) |*v, r| v.* = M.fromCanonical(@intCast(c * size + r + 1));
        view.* = column;
    }
    var channel = core.channel.blake2s.Blake2sChannel{};
    var ch: X.types.Challenges = undefined;
    inline for (.{ "ram", "owner", "selection" }) |field| {
        @field(ch, field).offset = channel.drawSecureFelt();
        for (&@field(ch, field).coefficients) |*v| v.* = channel.drawSecureFelt();
    }
    inline for (.{ "range16", "range8" }) |field| @field(ch, field) = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    const component = X.component.Component{ .kind = .ls, .log_size = 13, .rows = 8191, .offsets = .{ 0, 0, 0 }, .claims = X.types.Claims.zero(), .challenges = ch };
    var powers: [X.layout.constraints(.ls)]Q = undefined;
    for (&powers) |*v| v.* = channel.drawSecureFelt();
    const inverses = [_]M{ M.fromCanonical(3), M.fromCanonical(5) };
    const reference = try a.alloc(M, 4 * size);
    defer a.free(reference);
    const actual = try a.alloc(M, 4 * size);
    defer a.free(actual);
    @memset(reference, M.zero());
    @memset(actual, M.zero());
    var ref_col = engine.secure_column.SecureColumnByCoords{ .columns = .{ reference[0..size], reference[size..][0..size], reference[2 * size ..][0..size], reference[3 * size ..][0..size] }, .owns_columns = false };
    var actual_col = engine.secure_column.SecureColumnByCoords{ .columns = .{ actual[0..size], actual[size..][0..size], actual[2 * size ..][0..size], actual[3 * size ..][0..size] }, .owns_columns = false };
    var ref_output = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = &powers, .col = &ref_col, .next_fresh_index = 0 };
    var actual_output = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = &powers, .col = &actual_col, .next_fresh_index = 0 };
    try X.component.testing.packedRows.evaluate(&component, views[0..count], 0, size, &inverses, &ref_output);
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = 256 * 1024, .backing_allocator = a });
    defer pool.deinit();
    try X.component.testing.evaluateRows(&component, views[0..count], &inverses, &actual_output, &pool);
    try std.testing.expectEqualSlices(M, reference, actual);
}
