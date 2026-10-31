const std = @import("std");
const core = @import("stwo_core");
const front = @import("stwo_riscv_frontend");
const X = front.rv64_air.memory.load_store_v2;
const V = front.rv64_air.memory.load_store_v1;
const R = front.rv64_air.memory.closed_ram;
const E = front.rv64_air.evaluation;
const M = X.types.M;
const Q = X.types.Q;
const a = std.testing.allocator;
fn loadSecure(data: []const M, n: usize, row: usize, column: usize) Q {
    return Q.fromM31Array(.{ data[column * n + row], data[(column + 1) * n + row], data[(column + 2) * n + row], data[(column + 3) * n + row] });
}
fn challenges() X.types.Challenges {
    var channel = core.channel.blake2s.Blake2sChannel{};
    channel.mixU32s(&.{ 0x4c534e32, 1 });
    var c: X.types.Challenges = undefined;
    c.ram.offset = channel.drawSecureFelt();
    for (&c.ram.coefficients) |*x| x.* = channel.drawSecureFelt();
    c.owner.offset = channel.drawSecureFelt();
    for (&c.owner.coefficients) |*x| x.* = channel.drawSecureFelt();
    c.range16 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    c.range8 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    c.selection.offset = channel.drawSecureFelt();
    for (&c.selection.coefficients) |*x| x.* = channel.drawSecureFelt();
    return c;
}
const Dictionaries = struct {
    q16: []Q,
    q8: []Q,
    fn init(c: X.types.Challenges) !@This() {
        const q16 = try dictionary(65536, c.range16);
        errdefer a.free(q16);
        return .{ .q16 = q16, .q8 = try dictionary(256, c.range8) };
    }
    fn deinit(self: @This()) void {
        a.free(self.q16);
        a.free(self.q8);
    }
};
fn dictionary(n: usize, ch: @TypeOf(@as(X.types.Challenges, undefined).range16)) ![]Q {
    const input = try a.alloc(Q, n);
    defer a.free(input);
    const output = try a.alloc(Q, n);
    errdefer a.free(output);
    for (input, 0..) |*x, i| x.* = ch.denominatorFor(Q, E.q(@intCast(i)));
    try core.fields.batchInverseInPlace(Q, input, output);
    return output;
}
fn events() [2]X.native.Event {
    const before = R.types.State{ .value = 0x8070605040302010, .rights = 3 };
    const middle = R.types.State{ .value = 0x8070605040301210, .epoch = 0, .tick = 4, .rights = 3 };
    const after = R.types.State{ .value = middle.value, .epoch = 0, .tick = 8, .rights = 3 };
    return .{ .{ .opcode = .SB, .immediate = 0, .a = 0x1001, .b = 0x12, .c = 0, .epoch = 0, .tick = 4, .before = before, .after = middle }, .{ .opcode = .LB, .immediate = 0, .a = 0x1007, .b = 0, .c = 0xffffffffffffff80, .epoch = 0, .tick = 8, .before = middle, .after = after } };
}
fn nativeRows(kind: X.layout.Kind, log: u32, rows: u32, fixed: []const M, main: []const M, interaction: []const M, c: X.types.Challenges, claims: X.types.Claims) !void {
    const n = @as(usize, 1) << @intCast(log);
    const w = X.layout.widths(kind);
    for (0..n) |logical| {
        const pos = R.trace.physical(logical, log);
        const previous = R.trace.physical((logical + n - 1) % n, log);
        var f: [6]Q = undefined;
        var m: [79]Q = @splat(Q.zero());
        var pm: [79]Q = @splat(Q.zero());
        var i: [X.layout.INTERACTION]Q = undefined;
        var pi: [X.layout.INTERACTION]Q = @splat(Q.zero());
        for (0..w[0]) |j| f[j] = Q.fromBase(fixed[j * n + pos]);
        for (0..w[1]) |j| {
            m[j] = Q.fromBase(main[j * n + pos]);
            pm[j] = Q.fromBase(main[j * n + previous]);
        }
        for (0..w[2]) |j| {
            i[j] = Q.fromBase(interaction[j * n + pos]);
            pi[j] = Q.fromBase(interaction[j * n + previous]);
        }
        var values: [273]Q = undefined;
        var sink = E.Sink{ .values = &values };
        X.equations.emitFor(Q, kind, f[0..w[0]], m[0..w[1]], pm[0..w[1]], i[0..w[2]], pi[0..w[2]], rows, claims, c, &sink);
        try std.testing.expectEqual(X.layout.constraints(kind), sink.count);
        for (values[0..sink.count]) |v| try std.testing.expect(v.isZero());
    }
}
test "LS19 affine projection preserves arbitrary secure inputs and emitted negative ownership" {
    const c = challenges();
    var m: [79]Q = undefined;
    for (&m, 0..) |*v, i| v.* = Q.fromU32Unchecked(@intCast(i + 1), @intCast(i + 2), @intCast(i + 3), @intCast(i + 4));
    const actual = V.equations.ownerTuple(Q, &m);
    try std.testing.expect(X.types.project(c).owner.denominatorFor(Q, actual).eql(c.owner.denominatorFor(Q, X.equations.ownerTuple(Q, &m)).neg()));
}
test "LS source after MAIN retirement preserves checked legacy claims and projected interactions and all273 residuals" {
    var input = events();
    var source = try X.source.Source.init(a, &input, 5);
    defer source.deinit();
    var empty = try X.source.Source.init(a, &.{}, 5);
    defer empty.deinit();
    try std.testing.expectEqualSlices(M, source.fixed, empty.fixed);
    const main = try a.dupe(M, source.main);
    defer a.free(main);
    var legacy = V.trace.Trace{ .allocator = a, .kind = .ls, .log_size = 5, .rows = 2, .fixed = try a.dupe(M, source.fixed), .main = try a.dupe(M, source.main) };
    defer legacy.deinit();
    const c = challenges();
    const dict = try Dictionaries.init(c);
    defer dict.deinit();
    const expected = try legacy.generate(X.types.project(c));
    source.releaseMain();
    @memset(&input, input[0]);
    const got = try source.generate(c, dict.q16, dict.q8);
    try std.testing.expectEqualDeep(expected, got);
    // Independent old layout projection: RAM remains exact; pair inverses
    // come from the independently checked range dictionaries, and local sums
    // are the sum of the four original, separately centred prefixes.
    const n: usize = 32;
    for (0..n) |pos| {
        for (0..8) |column| try std.testing.expectEqual(legacy.interaction[column * n + pos], source.interaction[column * n + pos]);
        const owner_inverse = loadSecure(legacy.interaction, n, pos, 8);
        const first_range = dict.q16[legacy.main[V.layout.U16[0] * n + pos].v];
        try std.testing.expect(loadSecure(source.interaction, n, pos, 8).eql(owner_inverse.mul(first_range)));
        for (0..17) |pair| {
            const x = dict.q16[legacy.main[V.layout.U16[1 + 2 * pair] * n + pos].v];
            const y = dict.q16[legacy.main[V.layout.U16[2 + 2 * pair] * n + pos].v];
            try std.testing.expect(loadSecure(source.interaction, n, pos, 12 + 4 * pair).eql(x.mul(y)));
        }
        for (0..2) |pair| {
            const x = dict.q8[legacy.main[V.layout.U8[2 * pair] * n + pos].v];
            const y = dict.q8[legacy.main[V.layout.U8[2 * pair + 1] * n + pos].v];
            try std.testing.expect(loadSecure(source.interaction, n, pos, 80 + 4 * pair).eql(x.mul(y)));
        }
        // The independently generated V1 selection inverse is at column108.
        const last_range = dict.q8[legacy.main[V.layout.U8[4] * n + pos].v];
        try std.testing.expect(loadSecure(source.interaction, n, pos, 88).eql(last_range.mul(loadSecure(legacy.interaction, n, pos, 108))));
        var local = Q.zero();
        for ([_]usize{ 12, 88, 104, 112 }) |column| local = local.add(loadSecure(legacy.interaction, n, pos, column));
        try std.testing.expect(loadSecure(source.interaction, n, pos, X.layout.LOCAL_PREFIX).eql(local));
    }
    try nativeRows(.ls, 5, 2, source.fixed, main, source.interaction, c, got);
    const emptyMain = try a.dupe(M, empty.main);
    defer a.free(emptyMain);
    empty.releaseMain();
    const ec = try empty.generate(c, dict.q16, dict.q8);
    try nativeRows(.ls, 5, 0, empty.fixed, emptyMain, empty.interaction, c, ec);
}
test "LS local ledger shares redistribute only their sum while RAM stays independently bound" {
    const input = events();
    var source = try X.source.Source.init(a, &input, 5);
    defer source.deinit();
    const main = try a.dupe(M, source.main);
    defer a.free(main);
    const c = challenges();
    const dict = try Dictionaries.init(c);
    defer dict.deinit();
    source.releaseMain();
    const claims = try source.generate(c, dict.q16, dict.q8);
    var redistributed = claims;
    redistributed.owner = redistributed.owner.add(Q.one());
    redistributed.range16 = redistributed.range16.sub(Q.one());
    try nativeRows(.ls, 5, 2, source.fixed, main, source.interaction, c, redistributed);
    // A malformed strict pair cannot disappear behind zero activity/weight.
    const index = 8 * 32 + R.trace.physical(31, 5);
    const old = source.interaction[index];
    source.interaction[index] = old.add(M.one());
    try std.testing.expectError(error.TestUnexpectedResult, nativeRows(.ls, 5, 2, source.fixed, main, source.interaction, c, claims));
    source.interaction[index] = old;
}
test "Scalable4096 boundary cells and empty same-geometry source bind native authorized claims" {
    const cells = try a.alloc(R.types.Cell, 4096);
    defer a.free(cells);
    for (cells, 0..) |*cell, j| cell.* = .{ .address = 0x1000 + 8 * j, .state = .{ .value = @as(u64, @intCast(j)) * 19, .rights = 3 } };
    var source = try X.boundary_source.Source.init(a, .initial, cells, 13);
    defer source.deinit();
    const main = try a.dupe(M, source.main);
    defer a.free(main);
    const c = challenges();
    const dict = try Dictionaries.init(c);
    defer dict.deinit();
    source.releaseMain();
    const claim = try source.generate(c, dict.q16, dict.q8);
    try std.testing.expect(claim.ram.eql(try X.boundary_source.expectedClaim(cells, true, c.ram)));
    try nativeRows(.initial, 13, 4096, source.fixed, main, source.interaction, c, claim);
    var empty = try X.boundary_source.Source.init(a, .terminal, &.{}, 5);
    defer empty.deinit();
    const em = try a.dupe(M, empty.main);
    defer a.free(em);
    empty.releaseMain();
    const ec = try empty.generate(c, dict.q16, dict.q8);
    try nativeRows(.terminal, 5, 0, empty.fixed, em, empty.interaction, c, ec);
}
test "LS and boundary exhaustive native allocation errors and borrowed publication stay balanced" {
    const input = events();
    const c = challenges();
    const dict = try Dictionaries.init(c);
    defer dict.deinit();
    const Runner = struct {
        fn run(allocator: std.mem.Allocator, e: []const X.native.Event, ch: X.types.Challenges, d16: []const Q, d8: []const Q) !void {
            var s = try X.source.Source.init(allocator, e, 5);
            defer s.deinit();
            s.releaseMain();
            _ = try s.generate(ch, d16, d8);
        }
    };
    try std.testing.checkAllAllocationFailures(a, Runner.run, .{ &input, c, dict.q16, dict.q8 });
    var buffer: [79 * 32]M = @splat(M.fromCanonical(23));
    for (0..5) |index| {
        var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = index });
        try std.testing.expectError(error.OutOfMemory, X.source.Source.initWithMainBuffers(fail.allocator(), &input, 5, .{ .main = &buffer }));
        for (buffer) |v| try std.testing.expectEqual(@as(u32, 23), v.v);
    }
}

const Prepared = @import("prepared.zig");
const MockImage = struct {
    const Word = @FieldType(front.rv64.machine.Retirement, "pc");
    fn initial(_: *const anyopaque, address: u64) !u64 {
        if (address != 0x1000) return error.UnknownFixtureWord;
        return 0x8070605040302010;
    }
    fn rights(_: *const anyopaque, address: u64) !u2 {
        return if (address >= 0x1000 and address < 0x1008) 3 else 0;
    }
    fn nonuniform(_: *const anyopaque, address: u64) !u2 {
        return if (address == 0x1000) 3 else 1;
    }
};
test "Prepared memory collector grounds INIT in receiver image without VM or graph and retires MAIN" {
    var dummy: u8 = 0;
    const image = Prepared.public.Image{ .context = &dummy, .initial_word = MockImage.initial, .rights_at = MockImage.rights };
    var input = events();
    input[0].epoch = 1;
    input[0].after.epoch = 1;
    input[1].epoch = 1;
    input[1].before.epoch = 1;
    input[1].after.epoch = 1;
    var records: [2]@import("../cpu_source.zig").MemoryRecord = undefined;
    for (input, &records) |e, *record| {
        const d = try X.native.describe(e.opcode);
        record.* = .{ .opcode = e.opcode, .a = e.a, .immediate = e.immediate, .b = e.b, .c = e.c, .epoch = e.epoch, .tick = e.tick, .effect = .{ .address = MockImage.Word.fromInt(e.a +% e.immediate), .width = d.width, .value = MockImage.Word.fromInt(if (d.write) e.b else e.c), .before_word = MockImage.Word.fromInt(e.before.value), .after_word = MockImage.Word.fromInt(e.after.value), .write = d.write } };
    }
    var prepared = try Prepared.Prepared.init(a, image, &records, 1, 5, 5);
    defer prepared.deinit();
    try std.testing.expectEqual(@as(usize, 1), prepared.statement.initial.len);
    try prepared.statement.validate(image);
    const c = challenges();
    const dict = try Dictionaries.init(c);
    defer dict.deinit();
    prepared.releaseMain();
    const claims = try prepared.generate(c, dict.q16, dict.q8);
    try std.testing.expect(claims[0].ram.add(claims[1].ram).add(claims[2].ram).isZero());
    try std.testing.expect(claims[0].selection.add(claims[3].selection).isZero());
    const old = prepared.statement.initial[0];
    const cells = @constCast(prepared.statement.initial);
    cells[0].state.value ^= 1;
    try std.testing.expectError(error.UntrustedMemoryInitialState, prepared.statement.validate(image));
    cells[0] = old;
    var nonuniform = image;
    nonuniform.rights_at = MockImage.nonuniform;
    try std.testing.expectError(error.NonuniformMemoryWordPolicy, prepared.statement.validate(nonuniform));
}

fn dense(seed: u32) Q {
    return Q.fromPartialEvals(.{ E.q(seed), E.q(seed + 1), E.q(seed + 3), E.q(seed + 7) });
}
fn affine(values: []Q, t: Q, seed: u32) void {
    for (values, 0..) |*v, i| v.* = dense(seed + @as(u32, @intCast(i))).add(t.mul(dense(seed + 400 + @as(u32, @intCast(i)))));
}
test "LS and scalable boundary complete arbitrary secure residuals are cubic including previous masks" {
    const c = challenges();
    for ([_]X.layout.Kind{ .ls, .initial, .terminal }) |kind| {
        var samples: [5][273]Q = undefined;
        const w = X.layout.widths(kind);
        const total = X.layout.constraints(kind);
        for (0..5) |k| {
            const t = E.q(@intCast(k));
            var f: [6]Q = undefined;
            var m: [79]Q = undefined;
            var pm: [79]Q = undefined;
            var inter: [X.layout.INTERACTION]Q = undefined;
            var previous: [X.layout.INTERACTION]Q = undefined;
            affine(&f, t, 10);
            affine(&m, t, 30);
            affine(&pm, t, 140);
            affine(&inter, t, 250);
            affine(&previous, t, 410);
            var sink = E.Sink{ .values = &samples[k] };
            X.equations.emitFor(Q, kind, f[0..w[0]], m[0..w[1]], pm[0..w[1]], inter[0..w[2]], previous[0..w[2]], 7, X.types.Claims.zero(), c, &sink);
            try std.testing.expectEqual(total, sink.count);
        }
        for (0..4) |layer| {
            for (0..4 - layer) |k| {
                for (0..total) |i| samples[k][i] = samples[k + 1][i].sub(samples[k][i]);
            }
        }
        for (samples[0][0..total]) |v| try std.testing.expect(v.isZero());
    }
}

test "LS strict owner poles late histogram and selection errors retain metadata for retry" {
    const input = events();
    var source = try X.source.Source.init(a, &input, 5);
    defer source.deinit();
    source.releaseMain();
    const c = challenges();
    const dict = try Dictionaries.init(c);
    defer dict.deinit();
    var pole = c;
    pole.owner.offset = Q.zero();
    pole.owner.coefficients = @splat(Q.zero());
    try std.testing.expectError(error.DivisionByZero, source.generate(pole, dict.q16, dict.q8));
    try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
    try std.testing.expectEqual(@as(usize, 32), source.metadata.len);
    source.counts16[0] += 1;
    try std.testing.expectError(error.InvalidLsCounts, source.generate(c, dict.q16, dict.q8));
    source.counts16[0] -= 1;
    source.metadata[0].selection_words[0] ^= 1;
    try std.testing.expectError(error.InvalidLsCounts, source.generate(c, dict.q16, dict.q8));
    source.metadata[0].selection_words[0] ^= 1;
    _ = try source.generate(c, dict.q16, dict.q8);
    try std.testing.expectError(error.InvalidLsPhase, source.generate(c, dict.q16, dict.q8));
    var storage: [79 * 32]M align(@alignOf(X.native.Event)) = @splat(M.zero());
    const alias: [*]const X.native.Event = @ptrCast(&storage);
    try std.testing.expectError(error.OverlappingLsInputs, X.source.Source.initWithMainBuffers(a, alias[0..1], 5, .{ .main = &storage }));
}

test "LS and boundary packed base lanes match every arbitrary scalar residual" {
    const c = challenges();
    var channel = core.channel.blake2s.Blake2sChannel{};
    channel.mixU32s(&.{ 0x4c534532, 96, 273 });
    const claims = X.types.Claims{ .ram = channel.drawSecureFelt(), .owner = channel.drawSecureFelt(), .range16 = channel.drawSecureFelt(), .range8 = channel.drawSecureFelt(), .selection = channel.drawSecureFelt() };
    for ([_]X.layout.Kind{ .ls, .initial, .terminal }) |kind| {
        const widths = X.layout.widths(kind);
        var native: [5][X.layout.INTERACTION][E.LANES]M = undefined;
        var simd: [5][X.layout.INTERACTION]E.PackedBase = undefined;
        for (&native, &simd) |*group, *columns| for (group, columns) |*lanes, *column| {
            for (lanes) |*v| v.* = channel.drawSecureFelt().toM31Array()[0];
            column.* = E.PackedBase.fromLanes(lanes.*);
        };
        var actual: [273]E.PackedSecure = undefined;
        var sink = E.PackedSink{ .values = &actual };
        X.equations.emitFor(E.PackedBase, kind, simd[0][0..widths[0]], simd[1][0..widths[1]], simd[2][0..widths[1]], simd[3][0..widths[2]], simd[4][0..widths[2]], 7, claims, c, &sink);
        try std.testing.expectEqual(X.layout.constraints(kind), sink.count);
        for (0..E.LANES) |lane| {
            var scalar: [5][X.layout.INTERACTION]Q = undefined;
            for (&scalar, native) |*group, columns| for (group, columns) |*v, lanes| {
                v.* = Q.fromBase(lanes[lane]);
            };
            var expected: [273]Q = undefined;
            var out = E.Sink{ .values = &expected };
            X.equations.emitFor(Q, kind, scalar[0][0..widths[0]], scalar[1][0..widths[1]], scalar[2][0..widths[1]], scalar[3][0..widths[2]], scalar[4][0..widths[2]], 7, claims, c, &out);
            try std.testing.expectEqual(sink.count, out.count);
            for (expected[0..out.count], actual[0..sink.count]) |x, y| try std.testing.expect(x.eql(y.lane(lane)));
        }
    }
}

test "omitted public boundary U8 claims cannot cancel across the complete ledger" {
    const P = @import("../protocol.zig");
    const Sources = @import("../sources.zig");
    var c = std.mem.zeroes(P.Claims);
    c.initial.range8 = Q.one();
    c.terminal.range8 = Q.one().neg();
    try std.testing.expectError(error.NonzeroOmittedBoundaryRangeClaim, c.validate());
    try std.testing.expectError(error.NonzeroOmittedBoundaryRangeClaim, Sources.validateCanonicalClaims(c));
}
