//! Byte-based PAGE framing for the ORIGINAL packed BLAKE3 core. Capture
//! range/cryptographic authority comes only from the original fresh G/XOR
//! components, tables and capture-wire closure. This algebra neither hashes
//! private operands on the host nor accepts a recipe's proposed digest.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const Defaults = @import("block_v5_memory_source_batch_defaults_v1.zig");
const Packed = @import("block_v5_memory_source_packed_hash_v1.zig");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
pub const Recipe = struct {
    /// These public labels belong to the independently sealed PAGE inventory.
    /// They cannot substitute for the equalities evaluated below.
    slot: u32,
    multiplicity: u32,
    default_height: ?u32,
    compression_count: u32,
    first_compression: u32,
    pub fn fromCapture(capture: @import("block_v5_memory_source_packed_blake_columns_v1.zig").FrameCapture) Recipe {
        return .{ .slot = capture.recipe, .multiplicity = capture.multiplicity, .default_height = capture.default_height, .compression_count = capture.compression_count, .first_compression = capture.first_compression };
    }
};
pub fn requireRecipes(kind: Fold.Kind, height: u32, recipes: []const Recipe, first_compression: u32, total_compressions: u32) !void {
    if (height > Tree.DEPTH or (kind == .leaf and height != 0) or (kind == .branch and height == 0)) return error.InvalidSourceBlakeRecipe;
    if (kind == .empty or kind == .root) {
        if (recipes.len != 0 or total_compressions != 0) return error.InvalidSourceBlakeRecipe;
        return;
    }
    if (recipes.len == 0 or recipes.len > 2) return error.InvalidSourceBlakeRecipe;
    var next = first_compression;
    for (recipes, 0..) |recipe, i| {
        if (recipe.slot != i or recipe.first_compression != next or recipe.multiplicity != (if (recipes.len == 1) @as(u32, 2) else 1)) return error.InvalidSourceBlakeRecipe;
        if (recipe.default_height) |default_height| {
            if (default_height != height or recipe.compression_count != 0) return error.InvalidSourceBlakeRecipe;
        } else {
            if (recipe.compression_count != (if (kind == .leaf) @as(u32, 1) else 2)) return error.InvalidSourceBlakeRecipe;
            next = try std.math.add(u32, next, recipe.compression_count);
        }
    }
    if (next - first_compression != total_compressions) return error.InvalidSourceBlakeRecipe;
}
pub fn Algebra(comptime S: type) type {
    return struct {
        const Self = @This();
        pub const Frame = union(enum) { leaf: [4]S, node: [64]S };
        pub const Pair = struct { z: S, alpha: S };
        fn scalar(value: u32) S {
            if (S == core.fields.packed_qm31.PackedQM31) return S.fromBase(@splat(M.fromCanonical(value).v));
            return S.fromBase(M.fromCanonical(value));
        }
        pub fn frameFromNative(frame: Packed.Frame) Self.Frame {
            return switch (frame) {
                .leaf => |word| blk: {
                    var bytes: [4]S = undefined;
                    for (&bytes, 0..) |*out, i| out.* = scalar((word >> @as(u5, @intCast(8 * i))) & 255);
                    break :blk .{ .leaf = bytes };
                },
                .node => |node| blk: {
                    var bytes: [64]S = undefined;
                    for (&bytes, node.left ++ node.right) |*out, byte| out.* = scalar(byte);
                    break :blk .{ .node = bytes };
                },
            };
        }
        pub fn digestFromNative(digest: [32]u8) [32]S {
            var bytes: [32]S = undefined;
            for (&bytes, digest) |*out, byte| out.* = scalar(byte);
            return bytes;
        }
        fn wordBytes(value: u32) [4]S {
            var out: [4]S = undefined;
            for (&out, 0..) |*byte, i| byte.* = scalar((value >> @as(u5, @intCast(8 * i))) & 255);
            return out;
        }
        fn raw(frame: Self.Frame) [108]S {
            var out: [108]S = @splat(S.zero());
            for (Tree.DOMAIN, 0..) |byte, i| out[i] = scalar(byte);
            @memcpy(out[32..36], &wordBytes(2));
            @memcpy(out[36..40], &wordBytes(if (std.meta.activeTag(frame) == .leaf) 1 else 2));
            @memcpy(out[40..44], &wordBytes(@intFromEnum(Tree.Kind.memory)));
            switch (frame) {
                .leaf => |bytes| @memcpy(out[44..48], &bytes),
                .node => |bytes| @memcpy(out[44..108], &bytes),
            }
            return out;
        }
        fn equal(sink: anytype, expected: []const S, actual: []const S) !void {
            if (expected.len != actual.len) return error.InvalidSourceBlakeCapture;
            for (expected, actual) |x, y| try sink.zero(x.sub(y));
        }
        fn equalFrame(sink: anytype, expected: Self.Frame, actual: Self.Frame) !void {
            if (std.meta.activeTag(expected) != std.meta.activeTag(actual)) return error.InvalidSourceBlakeCapture;
            switch (expected) {
                .leaf => |bytes| try equal(sink, &bytes, &actual.leaf),
                .node => |bytes| try equal(sink, &bytes, &actual.node),
            }
        }
        /// All 192 cells belong to the original precommitted byte capture.
        /// This function uses no capture bits, arbitrary hash output, or host
        /// digest comparison. Byte validity follows from the fresh core wires.
        pub fn captured(sink: anytype, frame: Self.Frame, digest: [32]S, captures: []const [192]S) !void {
            const length: usize = if (std.meta.activeTag(frame) == .leaf) 48 else 108;
            const count = (length + 63) / 64;
            if (captures.len != count) return error.InvalidSourceBlakeCapture;
            const bytes = raw(frame);
            var cv: [32]S = undefined;
            for (core.crypto.blake3_compression.IV, 0..) |word, i| @memcpy(cv[4 * i ..][0..4], &wordBytes(word));
            for (captures, 0..) |capture, block| {
                var initial: [128]S = @splat(S.zero());
                @memcpy(initial[0..32], &cv);
                for (core.crypto.blake3_compression.IV[0..4], 0..) |word, i| @memcpy(initial[32 + 4 * i ..][0..4], &wordBytes(word));
                const used: usize = @min(@as(usize, 64), length - 64 * block);
                @memcpy(initial[56..60], &wordBytes(@intCast(used)));
                const flags: u32 = (if (block == 0) @as(u32, 1) else 0) | (if (block + 1 == count) @as(u32, 10) else 0);
                @memcpy(initial[60..64], &wordBytes(flags));
                @memcpy(initial[64..][0..used], bytes[64 * block ..][0..used]);
                try equal(sink, &initial, capture[0..128]);
                @memcpy(&cv, capture[128..160]);
            }
            try equal(sink, &cv, &digest);
        }
        fn defaultFrame(height: u32) !Self.Frame {
            if (height > Tree.DEPTH) return error.InvalidSourceBlakeRecipe;
            if (height == 0) return .{ .leaf = @splat(S.zero()) };
            const child = Defaults.get().defaults[Tree.DEPTH - height + 1].bytes;
            return frameFromNative(.{ .node = .{ .left = child, .right = child } });
        }
        fn supply(frame: Self.Frame, digest: [32]S, pair: Self.Pair) !S {
            var payload: [64]S = @splat(S.zero());
            switch (frame) {
                .leaf => |bytes| @memcpy(payload[0..4], &bytes),
                .node => |bytes| @memcpy(&payload, &bytes),
            }
            const values = [_]S{scalar(if (std.meta.activeTag(frame) == .leaf) 1 else 2)} ++ payload ++ digest;
            var denominator = pair.z.neg();
            var power = S.one();
            for (values) |value| {
                denominator = denominator.add(power.mul(value));
                power = power.mul(pair.alpha);
            }
            const inv = if (@hasDecl(S, "inverse")) denominator.inverse() else try denominator.inv();
            return inv.neg();
        }
        /// Exact hash97 negative supply. When a computation is shared, BOTH
        /// frames and digests are constrained equal; multiplicity2 cannot hide
        /// a second private frame. Default recipes constrain the entire frame
        /// and digest to independently reconstructed original tree constants.
        pub fn providers(sink: anytype, kind: Fold.Kind, height: u32, frames: [2]Self.Frame, digests: [2][32]S, recipes: []const Recipe, captures: []const [192]S, first_compression: u32, pair: Self.Pair) !S {
            try requireRecipes(kind, height, recipes, first_compression, @intCast(captures.len));
            if (recipes.len == 0) return S.zero();
            if ((kind == .leaf) != (std.meta.activeTag(frames[0]) == .leaf) or std.meta.activeTag(frames[0]) != std.meta.activeTag(frames[1])) return error.InvalidSourceBlakeRecipe;
            if (recipes.len == 1) {
                try equalFrame(sink, frames[0], frames[1]);
                try equal(sink, &digests[0], &digests[1]);
            }
            var sum = S.zero();
            var cursor: usize = 0;
            for (recipes, 0..) |recipe, i| {
                if (recipe.default_height) |default_height| {
                    try equalFrame(sink, try defaultFrame(default_height), frames[i]);
                    try equal(sink, &digestFromNative(Defaults.get().defaults[Tree.DEPTH - default_height].bytes), &digests[i]);
                } else {
                    try captured(sink, frames[i], digests[i], captures[cursor..][0..recipe.compression_count]);
                    cursor += recipe.compression_count;
                }
                sum = sum.add((try supply(frames[i], digests[i], pair)).mul(scalar(recipe.multiplicity)));
            }
            if (cursor != captures.len) return error.InvalidSourceBlakeCapture;
            return sum;
        }
    };
}
