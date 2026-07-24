//! Reusable host authority for canonical XOR proof inputs.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_impl");
const field = @import("../../../backends/cuda/abi/field.zig");
const canonical_input = @import("canonical_input.zig");
const geometry_mod = @import("geometry.zig");

const CirclePointM31 = core.circle.CirclePointM31;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const CanonicCoset = core.poly.circle.CanonicCoset;
const prover_twiddles = prover.poly.twiddles;

pub const TwiddleView = struct {
    circle_log_size: u32,
    offset_words: u32,
    word_count: u32,
};

pub const CircleConstants = struct {
    domain_log_size: u32,
    half_coset_initial_index: u32,
    half_coset_step_size: u32,
    barycentric_si0: field.SecureField,
    vanishing_rotation: field.CirclePointBaseField,
};

pub const Pack = struct {
    twiddle_tree: prover_twiddles.TwiddleTree([]M31),
    twiddle_views: []TwiddleView,
    fri_inverse_twiddle_offsets: []u32,
    coefficient_log_sizes: [geometry_mod.sampled_mask_points]u32,
    oods_offset_points: [geometry_mod.sampled_mask_points]field.CirclePointBaseField,
    oods_fold_counts: [geometry_mod.sampled_mask_points]u32,
    oods_output_indices: [geometry_mod.sampled_mask_points]u32,
    protocol_words: [canonical_input.protocol_word_count]u32,
    statement_words: [canonical_input.statement_word_count]u32,
    circle: CircleConstants,

    pub fn init(
        allocator: std.mem.Allocator,
        geometry: geometry_mod.Geometry,
    ) !Pack {
        const max_circle_log = geometry.queryLogSize();
        const root_coset = CanonicCoset
            .new(max_circle_log)
            .circleDomain()
            .half_coset;
        var tree = try prover_twiddles.precomputeM31(
            allocator,
            root_coset,
        );
        errdefer prover_twiddles.deinitM31(allocator, &tree);

        const view_count = try add(
            try sub(max_circle_log, min_executed_circle_log),
            1,
        );
        const views = try allocator.alloc(
            TwiddleView,
            try usizeCount(view_count),
        );
        errdefer allocator.free(views);
        for (views, 0..) |*view, index| {
            const circle_log = try add(
                min_executed_circle_log,
                try u32Count(index),
            );
            const words = try twiddleWords(circle_log);
            view.* = .{
                .circle_log_size = circle_log,
                .offset_words = try u32Count(
                    try usizeSub(tree.twiddles.len, words),
                ),
                .word_count = try u32Count(words),
            };
        }

        const fri_offsets = try allocator.alloc(
            u32,
            geometry.fri_tree_count,
        );
        errdefer allocator.free(fri_offsets);
        for (fri_offsets, 0..) |*offset, fold| {
            const fold_u32 = try u32Count(fold);
            offset.* = try friFoldTwiddleOffset(
                tree.itwiddles.len,
                try sub(max_circle_log, fold_u32),
                if (fold == 0) .circle_to_line else .line,
            );
        }

        const offsets: [geometry_mod.sampled_mask_points]field.CirclePointBaseField =
            undefined;
        @memset(offsets, rawBasePoint(CirclePointM31.identity()));
        const folds: [geometry_mod.sampled_mask_points]u32 = undefined;
        const lifting_log =
            geometry.protocol.lifting_log_size orelse max_circle_log;
        if (lifting_log < max_circle_log)
            return error.UnsupportedProtocol;
        @memset(folds, lifting_log - max_circle_log);
        var output_indices: [geometry_mod.sampled_mask_points]u32 = undefined;
        for (&output_indices, 0..) |*output, index| {
            output.* = try u32Count(index);
        }

        return .{
            .twiddle_tree = tree,
            .twiddle_views = views,
            .fri_inverse_twiddle_offsets = fri_offsets,
            .coefficient_log_sizes = canonical_input.coefficientLogSizes(geometry),
            .oods_offset_points = offsets,
            .oods_fold_counts = folds,
            .oods_output_indices = output_indices,
            .protocol_words = canonical_input.protocolWords(geometry.protocol),
            .statement_words = canonical_input.statementWords(geometry.statement),
            .circle = try deriveCircleConstants(geometry),
        };
    }

    pub fn deinit(
        self: *Pack,
        allocator: std.mem.Allocator,
    ) void {
        allocator.free(self.fri_inverse_twiddle_offsets);
        allocator.free(self.twiddle_views);
        prover_twiddles.deinitM31(allocator, &self.twiddle_tree);
        self.* = undefined;
    }

    pub fn forwardTwiddleWords(self: *const Pack) []const u32 {
        return m31Words(self.twiddle_tree.twiddles);
    }

    pub fn inverseTwiddleWords(self: *const Pack) []const u32 {
        return m31Words(self.twiddle_tree.itwiddles);
    }

    pub fn viewForCircleLog(
        self: *const Pack,
        circle_log_size: u32,
    ) !TwiddleView {
        if (circle_log_size < min_executed_circle_log or
            circle_log_size > self.circle.domain_log_size)
        {
            return error.InvalidCircleLog;
        }
        return self.twiddle_views[
            circle_log_size - min_executed_circle_log
        ];
    }
};

const min_executed_circle_log: u32 = 2;

const FriFoldKind = enum {
    circle_to_line,
    line,
};

fn friFoldTwiddleOffset(
    twiddle_word_count: usize,
    evaluation_log_size: u32,
    kind: FriFoldKind,
) !u32 {
    const evaluation_rows = try pow2(evaluation_log_size);
    const consumed_words = switch (kind) {
        .circle_to_line => evaluation_rows / 2,
        .line => evaluation_rows,
    };
    return u32Count(try usizeSub(
        twiddle_word_count,
        consumed_words,
    ));
}

fn deriveCircleConstants(
    geometry: geometry_mod.Geometry,
) !CircleConstants {
    const domain_log = geometry.queryLogSize();
    const canonic = CanonicCoset.new(domain_log);
    const domain = canonic.circleDomain();
    const p0 = domain.at(0);
    const generated_coset = core.circle.Coset.new(
        core.circle.CirclePointIndex.generator(),
        domain_log,
    );
    const derivative = core.constraints.cosetVanishingDerivative(
        M31,
        generated_coset,
        p0,
    );
    const si0 = try p0.y
        .mul(M31.fromCanonical(2).neg())
        .mul(derivative)
        .inv();
    const coset = canonic.coset();
    return .{
        .domain_log_size = domain_log,
        .half_coset_initial_index = try u32Count(domain.half_coset.initial_index.v),
        .half_coset_step_size = try u32Count(domain.half_coset.step_size.v),
        .barycentric_si0 = rawSecure(QM31.fromBase(si0)),
        .vanishing_rotation = rawBasePoint(
            coset.initial
                .conjugate()
                .add(coset.step_size.half().toPoint()),
        ),
    };
}

fn rawSecure(value: QM31) field.SecureField {
    const coordinates = value.toM31Array();
    return .{
        .a = coordinates[0].toU32(),
        .b = coordinates[1].toU32(),
        .c = coordinates[2].toU32(),
        .d = coordinates[3].toU32(),
    };
}

fn rawBasePoint(
    value: CirclePointM31,
) field.CirclePointBaseField {
    return .{ .x = value.x.toU32(), .y = value.y.toU32() };
}

fn m31Words(values: []const M31) []const u32 {
    comptime {
        std.debug.assert(@sizeOf(M31) == @sizeOf(u32));
        std.debug.assert(@alignOf(M31) == @alignOf(u32));
    }
    const words: [*]const u32 = @ptrCast(values.ptr);
    return words[0..values.len];
}

fn twiddleWords(circle_log_size: u32) !usize {
    if (circle_log_size == 0) return error.GeometryOverflow;
    return pow2(circle_log_size - 1);
}

fn pow2(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize))
        return error.GeometryOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

fn u32Count(value: anytype) !u32 {
    return std.math.cast(u32, value) orelse
        error.GeometryOverflow;
}

fn usizeCount(value: anytype) !usize {
    return std.math.cast(usize, value) orelse
        error.GeometryOverflow;
}

fn add(left: u32, right: u32) !u32 {
    return std.math.add(u32, left, right) catch
        error.GeometryOverflow;
}

fn sub(left: u32, right: u32) !u32 {
    return std.math.sub(u32, left, right) catch
        error.GeometryOverflow;
}

fn usizeSub(left: usize, right: usize) !usize {
    return std.math.sub(usize, left, right) catch
        error.GeometryOverflow;
}

test "canonical XOR ingress is exact and reusable" {
    const allocator = std.testing.allocator;
    const geometry = try geometry_mod.admit(
        .{ .log_size = 8, .log_step = 2, .offset = 3 },
        core.pcs.PcsConfig.default(),
    );
    var pack = try Pack.init(allocator, geometry);
    defer pack.deinit(allocator);
    try std.testing.expectEqual(
        try geometry.traceRowCount(),
        pack.forwardTwiddleWords().len,
    );
    try std.testing.expectEqual(
        @as(usize, geometry.fri_tree_count),
        pack.fri_inverse_twiddle_offsets.len,
    );
    try std.testing.expectEqualSlices(
        u32,
        &.{ 8, 2, 3, 0 },
        &pack.statement_words,
    );
}
