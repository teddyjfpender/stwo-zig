const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const H = @import("block_v7_halt_algebra_v1.zig");
const T = @import("block_v7_terminal_protocol_v1.zig");
fn policy() T.Policy {
    var output: [43]u8 = @splat(0);
    output[32] = 1;
    return .{ .final_cycle = 100, .halt_address = 0x100000, .length_address = 0x100004, .data_address = 0x100008, .output_end = 0x100100, .output = output };
}
fn valid(active: bool, address: u32, clock: u64, after: u32, row: [6]M) !bool {
    const p = policy();
    var c: H.Constants(M) = undefined;
    const qc = try H.derive(p);
    for (&c.address, qc.address) |*v, q| v.* = try q.tryIntoM31();
    for (&c.clocks, qc.clocks) |*r, qs| {
        for (r, qs) |*v, q| v.* = try q.tryIntoM31();
    }
    var clk: [4]M = undefined;
    for (&clk, 0..) |*v, i| v.* = M.fromCanonical(@intCast((clock >> @as(u6, @intCast(16 * i))) & 65535));
    const residual = H.Algebra(M).constraints(M.fromCanonical(@intFromBool(active)), .{ M.fromCanonical(address & 65535), M.fromCanonical(address >> 16) }, clk, .{ M.fromCanonical(after & 65535), M.fromCanonical(after >> 16) }, c, row);
    for (residual) |v| if (!v.isZero()) return false;
    return true;
}
test "v7 halt exact zero tests and four allowed clocks reject early halt and selector forgery" {
    const p = policy();
    for ([_]u64{ 397, 398, 399, 401 }) |clock| {
        for ([_]u32{ 1, 65536, 0xffffffff }) |after| {
            const row = try H.witness(true, p.halt_address, clock, after, p);
            try std.testing.expect(try valid(true, p.halt_address, clock, after, row));
        }
    }
    for ([_]u64{ 1, 3, 396, 400, 402, 65536 + 399 }) |clock| {
        const row = try H.witness(true, p.halt_address, clock, 1, p);
        try std.testing.expect(!try valid(true, p.halt_address, clock, 1, row));
        for ([_]usize{ 0, 2 }) |i| {
            var forged = row;
            forged[i] = M.zero();
            try std.testing.expect(!try valid(true, p.halt_address, clock, 1, forged));
        }
    }
    const row = try H.witness(true, p.halt_address, 399, 1, p);
    for ([_]usize{ 0, 2, 3, 4, 5 }) |i| {
        var forged = row;
        forged[i] = forged[i].add(M.one());
        try std.testing.expect(!try valid(true, p.halt_address, 399, 1, forged));
    }
    // A 1->0->1 history still contains a forbidden first nonzero row.
    try std.testing.expect(!try valid(true, p.halt_address, 1, 1, try H.witness(true, p.halt_address, 1, 1, p)));
    try std.testing.expect(try valid(true, p.halt_address, 2, 0, try H.witness(true, p.halt_address, 2, 0, p)));
    for ([_]u32{ 0, 0xffff, 0xffffffff, p.halt_address + 4, p.halt_address + 65536 }) |address| {
        const other = try H.witness(true, address, 1, 65536, p);
        try std.testing.expect(try valid(true, address, 1, 65536, other));
        var forged = other;
        forged[0] = M.one();
        try std.testing.expect(!try valid(true, address, 1, 65536, forged));
    }
    try std.testing.expect(try valid(false, 0, 0, 0, try H.witness(false, 0, 0, 0, p)));
    try std.testing.expect(try valid(true, p.halt_address, 1, 0, try H.witness(true, p.halt_address, 1, 0, p)));
}
// Degree semiring: constants degree0, every trace/fixed column degree1.
const Degree = struct {
    n: usize,
    pub fn add(a: @This(), b: @This()) @This() {
        return .{ .n = @max(a.n, b.n) };
    }
    pub fn sub(a: @This(), b: @This()) @This() {
        return a.add(b);
    }
    pub fn mul(a: @This(), b: @This()) @This() {
        return .{ .n = a.n + b.n };
    }
};
test "v7 halt polynomial degree is at most four with public constants" {
    const d = Degree{ .n = 1 };
    const c = Degree{ .n = 0 };
    const constraints = H.Algebra(Degree).constraints(d, @splat(d), @splat(d), @splat(d), .{ .address = @splat(c), .clocks = @splat(@splat(c)) }, @splat(d));
    var max: usize = 0;
    for (constraints) |item| max = @max(max, item.n);
    try std.testing.expectEqual(@as(usize, H.DEGREE), max);
}

test "v7 independent initial policy forbids nonzero private or forbidden halt cells" {
    const a = std.testing.allocator;
    const F = @import("../runner/guest_precompile/test_elf.zig");
    var elf = F.buildReleaseProgram(1, &.{0x0000006f}, 64, .rv32im_zkvm_v1);
    const table = std.mem.readInt(u32, elf[264..268], .little);
    for ([4]usize{ 2, 3, 7, 8 }, [4]u32{ 0x100100, 64, 0x100180, 0x100190 }) |index, value|
        std.mem.writeInt(u32, elf[table + (index + 1) * 16 + 4 ..][0..4], value, .little);
    var initial = try @import("block_v7_initial_intervals_v1.zig").Owned.derive(a, &elf, @import("block_v5_initial_sources_v1.zig").sha256(&elf), .rv32im_zkvm_v1, .{});
    defer initial.deinit();
    var p = policy();
    p.halt_address = initial.info.halt_flag;
    p.length_address = initial.info.output_len;
    p.data_address = initial.info.output_data;
    p.output_end = initial.info.output_end;
    const execution = @import("block_v7_execution_policy_v1.zig").Policy{ .initialized = &initial, .terminal = p, .program_root = @splat(1), .config = .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8), .lifting_log_size = null } };
    try execution.validate();
    const word = p.halt_address / 4;
    for (initial.intervals) |*interval| {
        if (interval.lower <= word and word < interval.upper) {
            const original = interval.*;
            defer interval.* = original;
            interval.value = 1;
            try std.testing.expectError(error.InvalidV7InitialHalt, execution.validate());
            interval.* = original;
            interval.private = true;
            try std.testing.expectError(error.InvalidV7InitialHalt, execution.validate());
            interval.* = original;
            interval.allowed = false;
            try std.testing.expectError(error.InvalidV7InitialHalt, execution.validate());
            return;
        }
    }
    return error.MissingHaltInterval;
}
