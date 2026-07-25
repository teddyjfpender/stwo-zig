//! Stable offset-addressed ABI for generated Cairo constraint products.

const std = @import("std");

pub const argument_count: u32 = 3;
pub const interaction_count: u32 = 3;
pub const launch_block: u32 = 256;

pub const ExtSourceKind = enum(u32) {
    constant,
    lookup_z,
    lookup_alpha_power,
    claimed_sum_scaled,
    lookup_alpha_power_scaled,
};

/// Authenticated recipe for one extended evaluation parameter.
pub const ExtSourceDescriptor = extern struct {
    kind: ExtSourceKind,
    source_index: u32,
    scale: u32,
    reserved: u32 = 0,
    constant: [4]u32 = [_]u32{0} ** 4,
};

pub extern "c" fn stwo_cairo_eval_materialize_params_on(
    arena: [*]u32,
    arena_words: u64,
    descriptor_offset: u64,
    descriptor_count: u32,
    z_offset: u64,
    alpha_power_offset: u64,
    alpha_power_count: u32,
    claimed_sum_offset: u64,
    claimed_sum_count: u32,
    output_offset: u64,
    output_words: u64,
    proof_stream: *anyopaque,
    launches_out: *u32,
) c_int;

pub const Args = extern struct {
    trace_offsets: u64,
    interaction_offsets: u64,
    base_params: u64,
    ext_params: u64,
    random_coeffs: u64,
    denom_inv: u64,
    coord_0: u64,
    coord_1: u64,
    coord_2: u64,
    coord_3: u64,
    row_count: u32,
    trace_log_size: u32,
    domain_log_size: u32,
    rc_base: u32,

    pub fn validate(self: Args, bounds: Bounds) !void {
        if (bounds.arena_words == 0 or
            bounds.trace_offset_count == 0 or
            bounds.random_constraint_count == 0 or
            bounds.denominator_count == 0 or
            bounds.rc_count == 0 or
            self.row_count == 0 or
            !std.math.isPowerOfTwo(self.row_count) or
            self.trace_log_size == 0 or
            self.trace_log_size >= 32 or
            self.domain_log_size != self.trace_log_size)
        {
            return error.InvalidCairoEvalArgs;
        }
        const evaluation_log: u32 = @intCast(
            std.math.log2_int(u32, self.row_count),
        );
        if (self.trace_log_size > evaluation_log or
            bounds.denominator_count !=
                (@as(u64, 1) << @intCast(
                    evaluation_log - self.trace_log_size,
                )))
        {
            return error.InvalidCairoEvalArgs;
        }
        const rc_end = std.math.add(
            u64,
            self.rc_base,
            bounds.rc_count,
        ) catch return error.InvalidCairoEvalArgs;
        if (rc_end > bounds.random_constraint_count)
            return error.InvalidCairoEvalArgs;

        try range(
            self.trace_offsets,
            bounds.trace_offset_count,
            bounds.arena_words,
        );
        try range(
            self.interaction_offsets,
            interaction_count,
            bounds.arena_words,
        );
        if (bounds.base_param_count != 0) {
            try range(
                self.base_params,
                bounds.base_param_count,
                bounds.arena_words,
            );
        }
        if (bounds.ext_param_count != 0) {
            try range(
                self.ext_params,
                try wordsForSecure(bounds.ext_param_count),
                bounds.arena_words,
            );
        }
        try range(
            self.random_coeffs,
            try wordsForSecure(bounds.random_constraint_count),
            bounds.arena_words,
        );
        try range(
            self.denom_inv,
            bounds.denominator_count,
            bounds.arena_words,
        );
        try range(self.coord_0, self.row_count, bounds.arena_words);
        const coord_1 = try add(self.coord_0, self.row_count);
        const coord_2 = try add(coord_1, self.row_count);
        const coord_3 = try add(coord_2, self.row_count);
        if (self.coord_1 != coord_1 or
            self.coord_2 != coord_2 or
            self.coord_3 != coord_3)
        {
            return error.InvalidCairoEvalArgs;
        }
        try range(self.coord_3, self.row_count, bounds.arena_words);
    }
};

pub const Bounds = struct {
    arena_words: u64,
    trace_offset_count: u64,
    base_param_count: u64,
    ext_param_count: u64,
    random_constraint_count: u64,
    denominator_count: u64,
    rc_count: u64,
};

fn wordsForSecure(count: u64) !u64 {
    return std.math.mul(u64, count, 4) catch
        error.InvalidCairoEvalArgs;
}

fn range(offset: u64, count: u64, arena_words: u64) !void {
    if (count == 0) return error.InvalidCairoEvalArgs;
    const end = try add(offset, count);
    if (offset >= arena_words or end > arena_words)
        return error.InvalidCairoEvalArgs;
}

fn add(left: u64, right: anytype) !u64 {
    const rhs = std.math.cast(u64, right) orelse
        return error.InvalidCairoEvalArgs;
    return std.math.add(u64, left, rhs) catch
        error.InvalidCairoEvalArgs;
}

comptime {
    std.debug.assert(@sizeOf(ExtSourceDescriptor) == 32);
    std.debug.assert(@alignOf(ExtSourceDescriptor) == 4);
    std.debug.assert(@offsetOf(ExtSourceDescriptor, "constant") == 16);
    std.debug.assert(@sizeOf(Args) == 96);
    std.debug.assert(@offsetOf(Args, "trace_offsets") == 0);
    std.debug.assert(@offsetOf(Args, "random_coeffs") == 32);
    std.debug.assert(@offsetOf(Args, "coord_0") == 48);
    std.debug.assert(@offsetOf(Args, "row_count") == 80);
    std.debug.assert(@offsetOf(Args, "rc_base") == 92);
}

test "Cairo eval ABI rejects range and accumulator drift" {
    const baseline = Args{
        .trace_offsets = 8,
        .interaction_offsets = 16,
        .base_params = 0,
        .ext_params = 32,
        .random_coeffs = 64,
        .denom_inv = 128,
        .coord_0 = 256,
        .coord_1 = 272,
        .coord_2 = 288,
        .coord_3 = 304,
        .row_count = 16,
        .trace_log_size = 3,
        .domain_log_size = 3,
        .rc_base = 4,
    };
    const bounds = Bounds{
        .arena_words = 512,
        .trace_offset_count = 4,
        .base_param_count = 0,
        .ext_param_count = 2,
        .random_constraint_count = 8,
        .denominator_count = 2,
        .rc_count = 3,
    };
    try baseline.validate(bounds);

    var forged = baseline;
    forged.coord_2 += 1;
    try std.testing.expectError(
        error.InvalidCairoEvalArgs,
        forged.validate(bounds),
    );
    forged = baseline;
    forged.rc_base = 7;
    try std.testing.expectError(
        error.InvalidCairoEvalArgs,
        forged.validate(bounds),
    );
    forged = baseline;
    forged.denom_inv = bounds.arena_words;
    try std.testing.expectError(
        error.InvalidCairoEvalArgs,
        forged.validate(bounds),
    );
}
