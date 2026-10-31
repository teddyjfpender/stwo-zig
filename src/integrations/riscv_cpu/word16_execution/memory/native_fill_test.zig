const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const X = front.rv64_air.memory.load_store_v2;
const R = front.rv64_air.memory.closed_ram;
const E = front.rv64_air.evaluation;
const S = X.source.Source;
const M = X.types.M;
const Q = X.types.Q;
const a = std.testing.allocator;
fn inputs(n: usize) ![]X.native.Event {
    const out = try a.alloc(X.native.Event, n);
    const opcodes = [_]front.rv64.decode.Opcode{ .LB, .LH, .LW, .LD, .LBU, .LHU, .LWU, .SB, .SH, .SW, .SD };
    for (out, 0..) |*event, i| {
        const opcode = opcodes[i % opcodes.len];
        const d = try X.native.describe(opcode);
        const offset = (i % (8 / @as(usize, d.width))) * d.width;
        const ea = 0x8000000000000000 + @as(u64, @intCast(16 * i + offset));
        const imm: u64 = if (i % 2 == 0) 4096 else 0xfffffffffffff000;
        const before = R.types.State{ .value = 0x8070605040302010 ^ (@as(u64, @intCast(i)) *% 0x9e3779b97f4a7c15), .epoch = if (i % 2 == 0) 0 else 1, .tick = if (i % 2 == 0) 0 else @intCast(4 * i), .rights = 3 };
        var after = before;
        after.epoch = 1;
        after.tick = @intCast(4 * (i + 1));
        const bits = 8 * @as(usize, d.width);
        const mask: u64 = if (bits == 64) std.math.maxInt(u64) else (@as(u64, 1) << @as(u6, @intCast(bits))) - 1;
        const shift: u6 = @intCast(8 * offset);
        var b: u64 = 0;
        var c: u64 = 0;
        if (d.write) {
            b = 0xfedcba9876543210 ^ @as(u64, @intCast(i));
            after.value = (before.value & ~(mask << shift)) | ((b & mask) << shift);
        } else {
            c = (before.value >> shift) & mask;
            if (d.signed and c & (@as(u64, 1) << @as(u6, @intCast(bits - 1))) != 0) c |= ~mask;
        }
        event.* = .{ .opcode = opcode, .a = ea -% imm, .immediate = imm, .b = b, .c = c, .epoch = 1, .tick = after.tick, .before = before, .after = after };
    }
    return out;
}
fn challenges() X.types.Challenges {
    var channel = core.channel.blake2s.Blake2sChannel{};
    var ch: X.types.Challenges = undefined;
    ch.ram.offset = channel.drawSecureFelt();
    for (&ch.ram.coefficients) |*v| v.* = channel.drawSecureFelt();
    ch.owner.offset = channel.drawSecureFelt();
    for (&ch.owner.coefficients) |*v| v.* = channel.drawSecureFelt();
    ch.range16 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    ch.range8 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    ch.selection.offset = channel.drawSecureFelt();
    for (&ch.selection.coefficients) |*v| v.* = channel.drawSecureFelt();
    return ch;
}
fn dictionary(n: usize, ch: anytype) ![]Q {
    const tmp = try a.alloc(Q, n);
    defer a.free(tmp);
    const out = try a.alloc(Q, n);
    errdefer a.free(out);
    for (tmp, 0..) |*v, i| v.* = ch.denominatorFor(Q, E.q(@intCast(i)));
    try core.fields.batchInverseInPlace(Q, tmp, out);
    return out;
}
fn residuals(main: []const M, source: *const S, ch: X.types.Challenges, claims: X.types.Claims) !void {
    const n = source.size();
    const log = source.log_size;
    const w = X.layout.widths(.ls);
    for (0..n) |logical| {
        const p = R.trace.physical(logical, log);
        const prior = R.trace.physical((logical + n - 1) % n, log);
        var f: [3]Q = undefined;
        var m: [X.layout.MAIN]Q = undefined;
        var pm = m;
        var inter: [X.layout.INTERACTION]Q = undefined;
        var pi = inter;
        for (&f, 0..) |*v, c| v.* = Q.fromBase(source.fixed[c * n + p]);
        for (&m, &pm, 0..) |*v, *old, c| {
            v.* = Q.fromBase(main[c * n + p]);
            old.* = Q.fromBase(main[c * n + prior]);
        }
        for (&inter, &pi, 0..) |*v, *old, c| {
            v.* = Q.fromBase(source.interaction[c * n + p]);
            old.* = Q.fromBase(source.interaction[c * n + prior]);
        }
        var values: [X.layout.constraints(.ls)]Q = undefined;
        var sink = E.Sink{ .values = &values };
        X.equations.emitFor(Q, .ls, &f, m[0..w[1]], pm[0..w[1]], &inter, &pi, source.rows, claims, ch, &sink);
        try std.testing.expectEqual(values.len, sink.count);
        for (values) |v| try std.testing.expect(v.isZero());
    }
}
test "LS native physical projections at1 3 16workers preserve every matrix metadata histogram claim and residual" {
    const events = try inputs(40001);
    defer a.free(events);
    const log = 16;
    var reference = try S.testing.initSerial(a, events, log);
    defer reference.deinit();
    const ch = challenges();
    const d16 = try dictionary(65536, ch.range16);
    defer a.free(d16);
    const d8 = try dictionary(256, ch.range8);
    defer a.free(d8);
    const metadata = try a.dupe(X.source.Metadata, reference.metadata);
    defer a.free(metadata);
    const expected = try reference.generate(ch, d16, d8);
    for ([_]usize{ 1, 3, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 1024 * 1024, .backing_allocator = a });
        defer pool.deinit();
        var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var actual = try S.init(a, events, log);
        defer actual.deinit();
        try std.testing.expectEqualSlices(M, reference.main, actual.main);
        try std.testing.expectEqualDeep(metadata, actual.metadata);
        try std.testing.expectEqualSlices(u64, reference.counts16, actual.counts16);
        try std.testing.expectEqualSlices(u64, reference.counts8, actual.counts8);
        try std.testing.expectEqualSlices(u64, reference.selection_counts, actual.selection_counts);
        actual.releaseMain();
        const claims = try actual.generate(ch, d16, d8);
        try std.testing.expectEqualDeep(expected, claims);
        try std.testing.expectEqualSlices(M, reference.interaction, actual.interaction);
        try residuals(reference.main, &actual, ch, claims);
    }
}
test "LS native partial submissions drain cancelled helpers and preserve borrowed MAIN before pool reuse" {
    const events = try inputs(41);
    defer a.free(events);
    const log = 14;
    const n: usize = 1 << log;
    const buffer = try a.alloc(M, X.layout.MAIN * n);
    defer a.free(buffer);
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = 1024 * 1024, .backing_allocator = a });
    defer pool.deinit();
    for ([_]usize{ 0, 1 }) |after| {
        @memset(buffer, M.fromCanonical(91));
        try std.testing.expectError(error.InjectedLsNativeFillSubmissionFailure, S.testing.failSubmission(a, events, log, .{ .main = buffer }, &pool, after));
        for (buffer) |v| try std.testing.expectEqual(@as(u32, 91), v.v);
        var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var reused = try S.initWithMainBuffers(a, events, log, .{ .main = buffer });
        defer reused.deinit();
        try std.testing.expect(!reused.owns_main);
    }
    var small: engine.work_pool.WorkPool = .{};
    try small.initInPlaceWithOptions(.{ .worker_count = 1, .stack_size = 64 * 1024, .backing_allocator = a });
    defer small.deinit();
    @memset(buffer, M.fromCanonical(93));
    var binding = try engine.work_pool.ScopedPoolBinding.init(&small);
    defer binding.deinit();
    try std.testing.expectError(error.InvalidLsNativeFillStack, S.initWithMainBuffers(a, events, log, .{ .main = buffer }));
    for (buffer) |v| try std.testing.expectEqual(@as(u32, 93), v.v);
}
fn allocationFailure(allocator: std.mem.Allocator, events: []const X.native.Event, pool: *engine.work_pool.WorkPool, borrowed: bool) !void {
    const log = 13;
    const buffer: []M = if (borrowed) try a.alloc(M, X.layout.MAIN * (@as(usize, 1) << log)) else &.{};
    defer if (borrowed) a.free(buffer);
    if (borrowed) @memset(buffer, M.fromCanonical(99));
    var binding = try engine.work_pool.ScopedPoolBinding.init(pool);
    defer binding.deinit();
    var source = (if (borrowed) S.initWithMainBuffers(allocator, events, log, .{ .main = buffer }) else S.init(allocator, events, log)) catch |err| {
        if (borrowed) for (buffer) |v| try std.testing.expectEqual(@as(u32, 99), v.v);
        return err;
    };
    defer source.deinit();
}
test "LS native owned and borrowed constructor allocation failures leave no live worker or duplicate owner" {
    const events = try inputs(17);
    defer a.free(events);
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = 1024 * 1024, .backing_allocator = a });
    defer pool.deinit();
    try std.testing.checkAllAllocationFailures(a, allocationFailure, .{ events, &pool, false });
    try std.testing.checkAllAllocationFailures(a, allocationFailure, .{ events, &pool, true });
}
test "LS native parallel full joined proofs at1 3 16workers match serial and fresh receiver" {
    const Fixture = @import("../../tests/rv64_word16_execution_fixture.zig").Fixture;
    const Setup = @import("../setup.zig");
    const Execution = @import("../execution.zig");
    const Driver = @import("../driver.zig");
    var fixture = try Fixture.init(a);
    defer fixture.deinit();
    var setup = try Setup.Setup.initWithAuthority(a, &fixture.image.authority, .{ .cpu_log = 14, .ls_log = 16, .boundary_log = 14 });
    defer setup.deinit();
    const admission = Driver.admission(&fixture.image);
    var expected = try Execution.prove(a, &setup, admission, fixture.boundary, &fixture.tape, null);
    defer expected.deinit(a);
    for ([_]usize{ 1, 3, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 1024 * 1024, .backing_allocator = a });
        defer pool.deinit();
        var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var actual = try Execution.prove(a, &setup, admission, fixture.boundary, &fixture.tape, null);
        defer actual.deinit(a);
        try std.testing.expectEqualSlices(u8, expected.bytes, actual.bytes);
        try std.testing.expectEqualDeep(expected.claims, actual.claims);
        var fresh = try Setup.Setup.initWithAuthority(a, &fixture.image.authority, setup.materials.geometry);
        defer fresh.deinit();
        try Execution.verify(a, &fresh, admission, actual);
    }
}
