//! Interleaved numeric CPU control. Control is the pre-hook SIMD sponge, using
//! the same shared permutation with an Ops type deliberately lacking mulPow2.
const std = @import("std");
const F = @import("fields/m31.zig");
const P = @import("crypto/poseidon2_m31_w24.zig");
const S = @import("crypto/poseidon2_m31_sponge.zig");
const Packed = @import("crypto/poseidon2_m31_sponge4.zig");
comptime {
    if (!@hasDecl(Packed, "DIAGONAL_ROTATION_EXPERIMENT")) @compileError("Build through scripts/bench_poseidon2_diagonal_rotation.py; production has no rotate hook");
}
const Fast = Packed.Sponge4;
const Vec = F.Vec4u32;
const ControlOps = struct {
    pub inline fn constant(_: @This(), x: u32) !Vec {
        return @splat(x);
    }
    pub inline fn add(_: @This(), x: Vec, y: Vec) !Vec {
        return F.addVec4(x, y);
    }
    pub inline fn sub(_: @This(), x: Vec, y: Vec) !Vec {
        return F.subVec4(x, y);
    }
    pub inline fn mul(_: @This(), x: Vec, y: Vec) !Vec {
        return F.mulVec4(x, y);
    }
};
const Control = struct {
    state: [P.WIDTH]Vec,
    at: usize,
    fn init(domain: S.Domain) @This() {
        var state = [_]Vec{@splat(0)} ** P.WIDTH;
        state[22] = @splat(1);
        state[23] = @splat(@intFromEnum(domain));
        return .{ .state = state, .at = 0 };
    }
    fn absorb(self: *@This(), words: [4]u32) void {
        self.state[self.at] = F.addVec4(self.state[self.at], @bitCast(words));
        self.at += 1;
        if (self.at == S.RATE) {
            P.permuteFor(Vec, ControlOps{}, &self.state) catch unreachable;
            self.at = 0;
        }
    }
    fn finish(self: @This()) [4]S.Digest {
        var result = self;
        result.state[result.at] = F.addVec4(result.state[result.at], @splat(1));
        P.permuteFor(Vec, ControlOps{}, &result.state) catch unreachable;
        var output: [4]S.Digest = undefined;
        for (0..S.DIGEST_WORDS) |i| {
            const words: [4]u32 = result.state[i];
            inline for (0..4) |lane| std.mem.writeInt(u32, output[lane][4 * i ..][0..4], words[lane], .little);
        }
        return output;
    }
};
const RotateOps = struct {
    pub inline fn constant(_: @This(), x: u32) !Vec {
        return @splat(x);
    }
    pub inline fn add(_: @This(), x: Vec, y: Vec) !Vec {
        return F.addVec4(x, y);
    }
    pub inline fn sub(_: @This(), x: Vec, y: Vec) !Vec {
        return F.subVec4(x, y);
    }
    pub inline fn mul(_: @This(), x: Vec, y: Vec) !Vec {
        return F.mulVec4(x, y);
    }
    pub inline fn mulPow2(_: @This(), x: Vec, comptime power: u5) !Vec {
        return ((x << @as(@Vector(4, u5), @splat(power))) & @as(Vec, @splat(F.Modulus))) | (x >> @as(@Vector(4, u5), @splat(31 - power)));
    }
};
const Mode = enum { node18, leaf64, leaf128, balanced, permutation };
const Sample = struct { ns: u64, checksum: u64, permutations: u64, felts: u64 };
fn run(comptime Impl: type, mode: Mode, groups: usize, words: *const [128][4]u32) Sample {
    var timer = std.time.Timer.start() catch unreachable;
    var checksum: u64 = 0;
    var permutations: u64 = 0;
    var felts: u64 = 0;
    if (mode == .permutation) {
        var state: [P.WIDTH]Vec = undefined;
        for (&state, 0..) |*v, i| v.* = @bitCast(words[i]);
        const Ops = if (Impl == Control) ControlOps else RotateOps;
        for (0..groups) |_| {
            state[0] = F.addVec4(state[0], @splat(1));
            P.permuteFor(Vec, Ops{}, &state) catch unreachable;
        }
        for (state) |v| for (@as([4]u32, v)) |w| {
            checksum +%= w;
        };
        return .{ .ns = timer.read(), .checksum = checksum, .permutations = 4 * groups, .felts = 0 };
    }
    for (0..groups) |group| {
        const count: usize = switch (mode) {
            .node18 => 18,
            .leaf64 => 64,
            .leaf128 => 128,
            .balanced => ([_]usize{ 18, 64, 18, 128 })[group & 3],
            .permutation => unreachable,
        };
        var sponge = Impl.init(if (count == 18) .node else .leaf);
        const seed: u32 = @intCast(group);
        sponge.absorb(.{ seed, seed + 1, seed + 2, seed + 3 });
        for (words[1..count]) |word| sponge.absorb(word);
        const digest = sponge.finish();
        const bytes = std.mem.asBytes(&digest);
        for (0..bytes.len / 8) |i| checksum +%= std.mem.readInt(u64, bytes[8 * i ..][0..8], .little);
        permutations += 4 * (count / S.RATE + 1);
        felts += 4 * count;
    }
    return .{ .ns = timer.read(), .checksum = checksum, .permutations = permutations, .felts = felts };
}
fn median(values: []u64) u64 {
    std.mem.sort(u64, values, {}, std.sort.asc(u64));
    return values[values.len / 2];
}
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    const groups = if (args.len > 1) try std.fmt.parseInt(usize, args[1], 10) else 32768;
    const repeats = if (args.len > 2) try std.fmt.parseInt(usize, args[2], 10) else 9;
    if (groups == 0 or groups > 1 << 20 or repeats < 3 or repeats > 31) return error.InvalidBenchmarkGeometry;
    var words: [128][4]u32 = undefined;
    var prng = std.Random.DefaultPrng.init(0x504f534549444f4e);
    const random = prng.random();
    for (&words) |*word| {
        for (word) |*value| value.* = random.uintLessThan(u32, F.Modulus);
    }
    for (std.enums.values(Mode)) |mode| {
        if (args.len > 3 and !std.mem.eql(u8, args[3], @tagName(mode))) continue;
        const warm_control = run(Control, mode, 256, &words);
        const warm_fast = run(Fast, mode, 256, &words);
        if (warm_control.checksum != warm_fast.checksum) return error.PoseidonBenchmarkParity;
        const baseline = try a.alloc(u64, repeats);
        defer a.free(baseline);
        const fast = try a.alloc(u64, repeats);
        defer a.free(fast);
        var facts: Sample = undefined;
        for (0..repeats) |repeat| {
            const first = if (repeat & 1 == 0) run(Control, mode, groups, &words) else run(Fast, mode, groups, &words);
            const second = if (repeat & 1 == 0) run(Fast, mode, groups, &words) else run(Control, mode, groups, &words);
            if (first.checksum != second.checksum) return error.PoseidonBenchmarkParity;
            baseline[repeat] = if (repeat & 1 == 0) first.ns else second.ns;
            fast[repeat] = if (repeat & 1 == 0) second.ns else first.ns;
            facts = first;
        }
        const b = median(baseline);
        const f = median(fast);
        std.debug.print("P2_HASH_AB mode={s} groups={} repeats={} baseline_ns={} candidate_ns={} speedup={d:.4} permutations={} felts={} checksum={}\n", .{ @tagName(mode), groups, repeats, b, f, @as(f64, @floatFromInt(b)) / @as(f64, @floatFromInt(f)), facts.permutations, facts.felts, facts.checksum });
    }
}
