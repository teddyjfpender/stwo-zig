//! Canonical host twiddles for one resident Cairo CUDA plan.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_impl");
const resident_plan = @import("resident_plan.zig");

const CanonicCoset = core.poly.circle.CanonicCoset;
const M31 = core.fields.m31.M31;
const twiddles = prover.poly.twiddles;

pub const Pack = struct {
    allocator: std.mem.Allocator,
    tree: twiddles.TwiddleTree([]M31),

    pub fn init(
        allocator: std.mem.Allocator,
        plan: *const resident_plan.Plan,
    ) !Pack {
        const forward = plan.slot(.twiddles_forward, 0) orelse
            return error.MissingTwiddleSlot;
        const inverse = plan.slot(.twiddles_inverse, 0) orelse
            return error.MissingTwiddleSlot;
        if (forward.words == 0 or
            forward.words != inverse.words or
            !std.math.isPowerOfTwo(forward.words))
        {
            return error.InvalidTwiddleGeometry;
        }
        const word_log = std.math.log2_int(usize, forward.words);
        const circle_log = std.math.add(
            u32,
            @intCast(word_log),
            1,
        ) catch return error.InvalidTwiddleGeometry;
        const root_coset = CanonicCoset
            .new(circle_log)
            .circleDomain()
            .half_coset;
        var tree = try twiddles.precomputeM31(allocator, root_coset);
        errdefer twiddles.deinitM31(allocator, &tree);
        if (tree.twiddles.len != forward.words or
            tree.itwiddles.len != inverse.words)
        {
            return error.InvalidTwiddleGeometry;
        }
        return .{ .allocator = allocator, .tree = tree };
    }

    pub fn deinit(self: *Pack) void {
        twiddles.deinitM31(self.allocator, &self.tree);
        self.* = undefined;
    }

    pub fn forwardWords(self: *const Pack) []const u32 {
        return m31Words(self.tree.twiddles);
    }

    pub fn inverseWords(self: *const Pack) []const u32 {
        return m31Words(self.tree.itwiddles);
    }
};

fn m31Words(values: []const M31) []const u32 {
    comptime {
        std.debug.assert(@sizeOf(M31) == @sizeOf(u32));
        std.debug.assert(@alignOf(M31) == @alignOf(u32));
    }
    const words: [*]const u32 = @ptrCast(values.ptr);
    return words[0..values.len];
}

test "canonical Cairo twiddle pack is a public checked constructor" {
    comptime {
        _ = Pack;
    }
}
