//! Four independent w24/r12/c12/d9 sponge states, transposed into M31 SIMD.
//! Exactly the scalar protocol: domain, additive absorption and mandatory pad.
const std = @import("std");
const F = @import("../fields/m31.zig");
const P = @import("poseidon2_m31_w24.zig");
const S = @import("poseidon2_m31_sponge.zig");
const V = F.Vec4u32;
const Ops = struct {
    pub inline fn constant(_: @This(), value: u32) !V {
        return @splat(value);
    }
    pub inline fn add(_: @This(), a: V, b: V) !V {
        return F.addVec4(a, b);
    }
    pub inline fn sub(_: @This(), a: V, b: V) !V {
        return F.subVec4(a, b);
    }
    pub inline fn mul(_: @This(), a: V, b: V) !V {
        return F.mulVec4(a, b);
    }
};
pub const Sponge4 = struct {
    state: [P.WIDTH]V,
    at: usize,
    pub fn init(domain: S.Domain) @This() {
        var state = [_]V{@splat(0)} ** P.WIDTH;
        state[22] = @splat(1);
        state[23] = @splat(@intFromEnum(domain));
        return .{ .state = state, .at = 0 };
    }
    pub fn fromStates(states: *const [4]S.Sponge) @This() {
        var out: @This() = undefined;
        out.at = states[0].at;
        inline for (0..4) |lane| std.debug.assert(states[lane].at == out.at);
        for (&out.state, 0..) |*value, i| {
            var words: [4]u32 = undefined;
            inline for (0..4) |lane| words[lane] = states[lane].state[i].v;
            value.* = @bitCast(words);
        }
        return out;
    }
    pub fn writeStates(self: *const @This(), states: *[4]S.Sponge) void {
        for (self.state, 0..) |value, i| {
            const words: [4]u32 = value;
            inline for (0..4) |lane| states[lane].state[i] = F.M31.fromCanonical(words[lane]);
        }
        inline for (0..4) |lane| states[lane].at = self.at;
    }
    pub fn absorb(self: *@This(), words: [4]u32) void {
        inline for (words) |word| std.debug.assert(word < F.Modulus);
        self.state[self.at] = F.addVec4(self.state[self.at], @bitCast(words));
        self.at += 1;
        if (self.at == S.RATE) {
            P.permuteFor(V, Ops{}, &self.state) catch unreachable;
            self.at = 0;
        }
    }
    pub fn finish(self: @This()) [4]S.Digest {
        var result = self;
        result.state[result.at] = F.addVec4(result.state[result.at], @splat(1));
        P.permuteFor(V, Ops{}, &result.state) catch unreachable;
        var output: [4]S.Digest = undefined;
        for (0..S.DIGEST_WORDS) |i| {
            const words: [4]u32 = result.state[i];
            inline for (0..4) |lane| std.mem.writeInt(u32, output[lane][4 * i ..][0..4], words[lane], .little);
        }
        return output;
    }
};
