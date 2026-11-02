//! Joined parallel MUL degree-3 interaction generation against the serial
//! oracle: identical claim and interaction bytes for every worker count.
const std = @import("std");
const core = @import("stwo_core");
const work = @import("stwo_prover_engine").work_pool;
const rv = @import("stwo_riscv_frontend").rv64_air;
const Mul = rv.arithmetic.multiplication;
const L = Mul.degree3_layout;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
fn requests(count: usize) ![]Mul.trace.Request {
    const out = try a.alloc(Mul.trace.Request, count);
    for (out, 0..) |*r, i| {
        const x = @as(u64, @intCast(i + 3)) *% 0x9e3779b97f4a7c15;
        const y = (x >> 7) ^ 0xd1b54a32d192ed03;
        const product = @as(u128, x) * y;
        r.* = if (i % 2 == 0) .{ .opcode = .MUL, .a = x, .b = y, .result = @truncate(product) } else .{ .opcode = .MULHU, .a = x, .b = y, .result = @intCast(product >> 64) };
    }
    return out;
}
test "joined parallel MUL degree3 interactions equal the serial oracle byte for byte for chunked and line-grouped orders" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = Mul.provider.Challenges.draw(&channel);
    const alpha = channel.drawSecureFelt();
    // log14: round-robin chunks; log17: line-complete groups.
    inline for (.{ 14, 17 }) |log| {
        for ([_]usize{ 1 << log, (1 << log) - 4097, 5051, 0 }) |count| {
            const input = try requests(count);
            defer a.free(input);
            var oracle = try Mul.trace.Trace.initWithLog(a, input, log);
            defer oracle.deinit();
            try oracle.releaseMain();
            const expected = try Mul.degree3_source.generateLegacySerial(&oracle, ch, alpha);
            for ([_]usize{ 1, 2, 3, 8 }) |workers| {
                var pool: work.WorkPool = .{};
                try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = if (@import("builtin").mode == .Debug) 1 << 20 else 1 << 18, .backing_allocator = a });
                defer pool.deinit();
                var binding = try work.ScopedPoolBinding.init(&pool);
                defer binding.deinit();
                var trace = try Mul.trace.Trace.initWithLog(a, input, log);
                defer trace.deinit();
                try trace.releaseMain();
                const claim = try Mul.degree3_source.generateLegacy(&trace, ch, alpha);
                try std.testing.expect(claim.eql(expected));
                try std.testing.expectEqual(L.INTERACTION << log, trace.interaction.len);
                try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(oracle.interaction), std.mem.sliceAsBytes(trace.interaction));
                try std.testing.expectEqual(@as(usize, 0), trace.request_metadata.len);
                try std.testing.expectEqual(workers, pool.availableWorkers());
            }
        }
    }
}
test "joined parallel MUL degree3 allocation failure publishes nothing and permits retry" {
    const input = try requests(9000);
    defer a.free(input);
    var pool: work.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = if (@import("builtin").mode == .Debug) 1 << 20 else 1 << 18, .backing_allocator = a });
    defer pool.deinit();
    var binding = try work.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = Mul.provider.Challenges.draw(&channel);
    const alpha = channel.drawSecureFelt();
    var trace = try Mul.trace.Trace.initWithLog(a, input, 14);
    defer trace.deinit();
    try trace.releaseMain();
    for (0..3) |fail_index| {
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = fail_index });
        trace.allocator = failing.allocator();
        try std.testing.expectError(error.OutOfMemory, Mul.degree3_source.generateLegacy(&trace, ch, alpha));
        trace.allocator = a;
        try std.testing.expectEqual(@as(usize, 0), trace.interaction.len);
        try std.testing.expectEqual(input.len, trace.request_metadata.len);
        try std.testing.expectEqual(@as(usize, 4), pool.availableWorkers());
    }
    var oracle = try Mul.trace.Trace.initWithLog(a, input, 14);
    defer oracle.deinit();
    try oracle.releaseMain();
    const expected = try Mul.degree3_source.generateLegacySerial(&oracle, ch, alpha);
    try std.testing.expect((try Mul.degree3_source.generateLegacy(&trace, ch, alpha)).eql(expected));
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(oracle.interaction), std.mem.sliceAsBytes(trace.interaction));
}
