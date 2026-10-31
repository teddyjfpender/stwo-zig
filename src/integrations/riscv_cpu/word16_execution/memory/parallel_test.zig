const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const X = A.memory.load_store_v2;
const R = A.memory.closed_ram;
const I = X.interaction;
const Parallel = X.interaction_parallel;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
const Data = struct {
    ch: X.types.Challenges,
    d16: []Q,
    d8: []Q,
    fn init() !Data {
        var channel = core.channel.blake2s.Blake2sChannel{};
        var ch: X.types.Challenges = undefined;
        inline for (.{ "ram", "owner", "selection" }) |name| {
            @field(ch, name).offset = channel.drawSecureFelt();
            for (&@field(ch, name).coefficients) |*c| c.* = channel.drawSecureFelt();
        }
        ch.range16 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
        ch.range8 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
        const d16 = try dict(65536, ch.range16);
        errdefer a.free(d16);
        return .{ .ch = ch, .d16 = d16, .d8 = try dict(256, ch.range8) };
    }
    fn deinit(self: Data) void {
        a.free(self.d16);
        a.free(self.d8);
    }
};
fn dict(n: usize, ch: @TypeOf(@as(X.types.Challenges, undefined).range16)) ![]Q {
    const input = try a.alloc(Q, n);
    defer a.free(input);
    const out = try a.alloc(Q, n);
    errdefer a.free(out);
    for (input, 0..) |*v, i| v.* = ch.denominatorFor(Q, A.evaluation.q(@intCast(i)));
    try core.fields.batchInverseInPlace(Q, input, out);
    return out;
}
fn events(count: usize) ![]X.native.Event {
    const out = try a.alloc(X.native.Event, count);
    for (out, 0..) |*event, i| {
        const value = 0x8000000000000000 +% (@as(u64, @intCast(i)) *% 0x102030405);
        event.* = .{ .opcode = .SD, .immediate = 0, .a = 0xfedcba9800000000 + 8 * @as(u64, @intCast(i)), .b = value, .c = 0, .epoch = 1, .tick = @intCast(4 * (i + 1)), .before = .{ .value = 0, .rights = 3 }, .after = .{ .value = value, .epoch = 1, .tick = @intCast(4 * (i + 1)), .rights = 3 } };
    }
    return out;
}
fn nativeRows(kind: X.layout.Kind, log: u32, rows: u32, fixed: []const M, main: []const M, inter: []const M, ch: X.types.Challenges, claims: X.types.Claims) !void {
    const n = @as(usize, 1) << @intCast(log);
    const widths = X.layout.widths(kind);
    for (0..n) |logical| {
        const pos = R.trace.physical(logical, log);
        const before = R.trace.physical((logical + n - 1) % n, log);
        var f: [3]Q = undefined;
        var m: [79]Q = undefined;
        var pm: [79]Q = undefined;
        var i: [X.layout.INTERACTION]Q = undefined;
        var pi: [X.layout.INTERACTION]Q = undefined;
        for (&f, 0..) |*v, c| v.* = Q.fromBase(fixed[c * n + pos]);
        for (m[0..widths[1]], pm[0..widths[1]], 0..) |*v, *pv, c| {
            v.* = Q.fromBase(main[c * n + pos]);
            pv.* = Q.fromBase(main[c * n + before]);
        }
        for (i[0..widths[2]], pi[0..widths[2]], 0..) |*v, *pv, c| {
            v.* = Q.fromBase(inter[c * n + pos]);
            pv.* = Q.fromBase(inter[c * n + before]);
        }
        var residuals: [273]Q = undefined;
        var sink = A.evaluation.Sink{ .values = &residuals };
        X.equations.emitFor(Q, kind, &f, m[0..widths[1]], pm[0..widths[1]], i[0..widths[2]], pi[0..widths[2]], rows, claims, ch, &sink);
        try std.testing.expectEqual(X.layout.constraints(kind), sink.count);
        for (residuals[0..sink.count]) |v| try std.testing.expect(v.isZero());
    }
}
test "LS joined1 4 16 worker waves match serial96 columns fiveclaims after MAIN retirement" {
    const data = try Data.init();
    defer data.deinit();
    const input = try events(8193);
    defer a.free(input);
    const log: u32 = 16;
    var reference = try X.source.Source.init(a, input, log);
    defer reference.deinit();
    const original = try a.dupe(M, reference.main);
    defer a.free(original);
    reference.releaseMain();
    const expected = try I.generateSerial(&reference, data.ch, data.d16, data.d8);
    for ([_]usize{ 1, 4, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = Parallel.MIN_STACK_BYTES, .backing_allocator = a });
        defer pool.deinit();
        var source = try X.source.Source.init(a, input, log);
        defer source.deinit();
        source.releaseMain();
        const claims = try Parallel.generate(&source, data.ch, data.d16, data.d8, &pool);
        try std.testing.expectEqualDeep(expected, claims);
        try std.testing.expectEqualSlices(M, reference.interaction, source.interaction);
        try std.testing.expectEqual(@as(usize, 0), source.metadata.len);
        if (workers == 16) try nativeRows(.ls, log, source.rows, source.fixed, original, source.interaction, data.ch, claims);
    }
}
test "LS parallel errors drain bothwaves preserve metadata and permit allocation pole retry" {
    const data = try Data.init();
    defer data.deinit();
    const input = try events(4097);
    defer a.free(input);
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = Parallel.MIN_STACK_BYTES, .backing_allocator = a });
    defer pool.deinit();
    for ([_]usize{ 0, 1 }) |wave| for ([_]usize{ 0, 1 }) |after| {
        var source = try X.source.Source.init(a, input, 14);
        defer source.deinit();
        source.releaseMain();
        try std.testing.expectError(error.InjectedLsInteractionSubmissionFailure, Parallel.testing.failSubmission(&source, data.ch, data.d16, data.d8, &pool, wave, after));
        try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
        try std.testing.expectEqual(@as(usize, 1 << 14), source.metadata.len);
        _ = try Parallel.generate(&source, data.ch, data.d16, data.d8, &pool);
    };
    for ([_]usize{ 0, 4096, 8192 }) |row| {
        var source = try X.source.Source.init(a, input, 14);
        defer source.deinit();
        source.releaseMain();
        var bad = data.ch;
        bad.owner.offset = Q.zero();
        const entry = source.metadata[row].ownerTuple();
        for (bad.owner.coefficients, entry) |c, v| bad.owner.offset = bad.owner.offset.add(c.mulM31(v));
        try std.testing.expectError(error.DivisionByZero, Parallel.generate(&source, bad, data.d16, data.d8, &pool));
        try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
        try std.testing.expectEqual(@as(usize, 1 << 14), source.metadata.len);
        _ = try Parallel.generate(&source, data.ch, data.d16, data.d8, &pool);
    }
    for (0..7) |offset| {
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = std.math.maxInt(usize) });
        var source = try X.source.Source.init(failing.allocator(), input, 14);
        defer source.deinit();
        source.releaseMain();
        failing.fail_index = failing.alloc_index + offset;
        if (Parallel.generate(&source, data.ch, data.d16, data.d8, &pool)) |_| {} else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
            try std.testing.expectEqual(@as(usize, 1 << 14), source.metadata.len);
            failing.fail_index = std.math.maxInt(usize);
            _ = try Parallel.generate(&source, data.ch, data.d16, data.d8, &pool);
        }
    }
    var source = try X.source.Source.init(a, input, 14);
    defer source.deinit();
    source.releaseMain();
    const saved = source.metadata[0];
    source.metadata[0].selection_words[1] = 65535;
    try std.testing.expectError(error.InvalidLsMetadata, I.generateSerial(&source, data.ch, data.d16, data.d8));
    try std.testing.expectError(error.InvalidLsMetadata, Parallel.generate(&source, data.ch, data.d16, data.d8, &pool));
    var single: engine.work_pool.WorkPool = .{};
    try single.initInPlaceWithOptions(.{ .worker_count = 1, .stack_size = Parallel.MIN_STACK_BYTES, .backing_allocator = a });
    defer single.deinit();
    try std.testing.expectError(error.InvalidLsMetadata, Parallel.generate(&source, data.ch, data.d16, data.d8, &single));
    source.metadata[0] = saved;
    source.metadata[0].flags |= 128;
    try std.testing.expectError(error.InvalidLsMetadata, I.generateSerial(&source, data.ch, data.d16, data.d8));
    try std.testing.expectError(error.InvalidLsMetadata, Parallel.generate(&source, data.ch, data.d16, data.d8, &pool));
    source.metadata[0] = saved;
    source.counts16[0] += 1;
    try std.testing.expectError(error.InvalidLsCounts, Parallel.generate(&source, data.ch, data.d16, data.d8, &pool));
    source.counts16[0] -= 1;
    var small: engine.work_pool.WorkPool = .{};
    try small.initInPlaceWithOptions(.{ .worker_count = 1, .stack_size = Parallel.MIN_STACK_BYTES - 1, .backing_allocator = a });
    defer small.deinit();
    try std.testing.expectError(error.InvalidLsInteractionStack, Parallel.generate(&source, data.ch, data.d16, data.d8, &small));
    _ = try Parallel.generate(&source, data.ch, data.d16, data.d8, &pool);
}

const BoundaryParallel = X.boundary_interaction_parallel;
fn cells(count: usize, terminal: bool) ![]R.types.Cell {
    const output = try a.alloc(R.types.Cell, count);
    for (output, 0..) |*cell, i| cell.* = .{ .address = 0xfedcba9800000000 + 8 * @as(u64, @intCast(i)), .state = .{ .value = 0x8000000000000000 + @as(u64, @intCast(i)), .epoch = if (terminal) 1 else 0, .tick = if (terminal) @intCast(4 * (i + 1)) else 0, .rights = 3 } };
    return output;
}
test "INIT TERM pooled3prefix48columns match serial at1 4 16workers after MAIN retirement" {
    const data = try Data.init();
    defer data.deinit();
    for ([_]X.layout.Kind{ .initial, .terminal }) |kind| {
        const input = try cells(8193, kind == .terminal);
        defer a.free(input);
        var reference = try X.boundary_source.Source.init(a, kind, input, 16);
        defer reference.deinit();
        const original = try a.dupe(M, reference.main);
        defer a.free(original);
        reference.releaseMain();
        const expected = try reference.generateSerial(data.ch, data.d16, data.d8);
        try std.testing.expect(expected.ram.eql(try X.boundary_source.expectedClaim(input, kind == .initial, data.ch.ram)));
        for ([_]usize{ 1, 4, 16 }) |workers| {
            var pool: engine.work_pool.WorkPool = .{};
            try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = BoundaryParallel.MIN_STACK_BYTES, .backing_allocator = a });
            defer pool.deinit();
            var source = try X.boundary_source.Source.init(a, kind, input, 16);
            defer source.deinit();
            source.releaseMain();
            const claims = try BoundaryParallel.generate(&source, data.ch, data.d16, data.d8, &pool);
            try std.testing.expectEqualDeep(expected, claims);
            try std.testing.expectEqualSlices(M, reference.interaction, source.interaction);
            if (workers == 16) try nativeRows(kind, 16, source.rows, source.fixed, original, source.interaction, data.ch, claims);
        }
    }
}
test "boundary two-wave submission poles alloc failures drain and remain retryable" {
    const data = try Data.init();
    defer data.deinit();
    const input = try cells(4097, false);
    defer a.free(input);
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = BoundaryParallel.MIN_STACK_BYTES, .backing_allocator = a });
    defer pool.deinit();
    for ([_]usize{ 0, 1 }) |wave| for ([_]usize{ 0, 1 }) |after| {
        var source = try X.boundary_source.Source.init(a, .initial, input, 14);
        defer source.deinit();
        source.releaseMain();
        try std.testing.expectError(error.InjectedBoundaryInteractionSubmissionFailure, BoundaryParallel.testing.failSubmission(&source, data.ch, data.d16, data.d8, &pool, wave, after));
        try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
        try std.testing.expectEqual(@as(usize, 1 << 14), source.metadata.len);
        _ = try BoundaryParallel.generate(&source, data.ch, data.d16, data.d8, &pool);
    };
    for ([_]usize{ 0, 4096, 8192 }) |row| {
        var source = try X.boundary_source.Source.init(a, .initial, input, 14);
        defer source.deinit();
        source.releaseMain();
        var bad = data.ch;
        bad.ram.offset = Q.zero();
        for (bad.ram.coefficients, source.metadata[row].tuple()) |c, v| bad.ram.offset = bad.ram.offset.add(c.mulM31(v));
        try std.testing.expectError(error.DivisionByZero, BoundaryParallel.generate(&source, bad, data.d16, data.d8, &pool));
        try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
        try std.testing.expectEqual(@as(usize, 1 << 14), source.metadata.len);
        _ = try BoundaryParallel.generate(&source, data.ch, data.d16, data.d8, &pool);
    }
    for (0..5) |offset| {
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = std.math.maxInt(usize) });
        var source = try X.boundary_source.Source.init(failing.allocator(), .terminal, input, 14);
        defer source.deinit();
        source.releaseMain();
        failing.fail_index = failing.alloc_index + offset;
        if (BoundaryParallel.generate(&source, data.ch, data.d16, data.d8, &pool)) |_| {} else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
            try std.testing.expectEqual(@as(usize, 1 << 14), source.metadata.len);
            failing.fail_index = std.math.maxInt(usize);
            _ = try BoundaryParallel.generate(&source, data.ch, data.d16, data.d8, &pool);
        }
    }
    var source = try X.boundary_source.Source.init(a, .initial, input, 14);
    defer source.deinit();
    source.releaseMain();
    const saved = source.metadata[0];
    source.metadata[0].flags |= 128;
    try std.testing.expectError(error.InvalidBoundaryMetadata, source.generateSerial(data.ch, data.d16, data.d8));
    try std.testing.expectError(error.InvalidBoundaryMetadata, BoundaryParallel.generate(&source, data.ch, data.d16, data.d8, &pool));
    source.metadata[0] = saved;
    source.counts16[0] += 1;
    try std.testing.expectError(error.InvalidBoundaryCounts, BoundaryParallel.generate(&source, data.ch, data.d16, data.d8, &pool));
    source.counts16[0] -= 1;
    var small: engine.work_pool.WorkPool = .{};
    try small.initInPlaceWithOptions(.{ .worker_count = 1, .stack_size = BoundaryParallel.MIN_STACK_BYTES - 1, .backing_allocator = a });
    defer small.deinit();
    try std.testing.expectError(error.InvalidBoundaryInteractionStack, BoundaryParallel.generate(&source, data.ch, data.d16, data.d8, &small));
    _ = try BoundaryParallel.generate(&source, data.ch, data.d16, data.d8, &pool);
}
