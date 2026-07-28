//! Canonical host inputs for the resident Native CUDA proof.
//!
//! Every value in this pack is derived from Zig Stwo core/prover APIs. The
//! pack owns no device state and is intentionally reusable across proofs with
//! identical geometry.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_impl");
const field = @import("stwo_cuda_backend").abi.field;
const geometry_mod = @import("geometry.zig");
const exact_oods = @import("oods.zig");

const CirclePointM31 = core.circle.CirclePointM31;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const CanonicCoset = core.poly.circle.CanonicCoset;
const prover_twiddles = prover.poly.twiddles;

pub const transcript_config_words: usize = 4;
pub const transcript_empty_root_words: usize = 8;
pub const transcript_statement_words: usize = 1;
pub const transcript_static_words: usize =
    transcript_config_words +
    transcript_empty_root_words +
    transcript_statement_words;

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
    composition_denominator_inverses: [4]u32,
};

pub const Pack = struct {
    twiddle_tree: prover_twiddles.TwiddleTree([]M31),
    twiddle_views: []TwiddleView,
    fri_inverse_twiddle_offsets: []u32,
    coefficient_log_sizes: []u32,
    oods_offset_points: []field.CirclePointBaseField,
    oods_fold_counts: []u32,
    oods_output_indices: []u32,
    circle: CircleConstants,
    transcript_static: [transcript_static_words]u32,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        geometry: geometry_mod.Geometry,
    ) !Self {
        // Poseidon's AIR has degree log + 2 even though its trace trees commit
        // at log + 1. One rooted tree supplies suffix views for both domains.
        const max_circle_log = geometry.composition_log_rows;
        const root_coset = CanonicCoset
            .new(max_circle_log)
            .circleDomain()
            .half_coset;
        var tree = try prover_twiddles.precomputeM31(allocator, root_coset);
        errdefer prover_twiddles.deinitM31(allocator, &tree);

        const view_count = std.math.cast(
            usize,
            max_circle_log - min_executed_circle_log + 1,
        ) orelse return error.GeometryOverflow;
        const views = try allocator.alloc(TwiddleView, view_count);
        errdefer allocator.free(views);
        for (views, 0..) |*view, index| {
            const circle_log = min_executed_circle_log +
                (std.math.cast(u32, index) orelse
                    return error.GeometryOverflow);
            const words = try twiddleWords(circle_log);
            view.* = .{
                .circle_log_size = circle_log,
                .offset_words = try u32Count(tree.twiddles.len - words),
                .word_count = try u32Count(words),
            };
        }

        const fri_offsets = try allocator.alloc(
            u32,
            geometry.fri_tree_count,
        );
        errdefer allocator.free(fri_offsets);
        for (fri_offsets, 0..) |*offset, fold| {
            const fold_u32 = std.math.cast(u32, fold) orelse
                return error.GeometryOverflow;
            offset.* = try friFoldTwiddleOffset(
                tree.itwiddles.len,
                geometry.queryLogSize() - fold_u32,
                if (fold == 0) .circle_to_line else .line,
            );
        }

        const coefficient_logs = try allocator.alloc(
            u32,
            geometry_mod.source_columns,
        );
        errdefer allocator.free(coefficient_logs);

        const offsets = try allocator.alloc(
            field.CirclePointBaseField,
            geometry_mod.sampled_mask_points,
        );
        errdefer allocator.free(offsets);

        const folds = try allocator.alloc(
            u32,
            geometry_mod.sampled_mask_points,
        );
        errdefer allocator.free(folds);
        const lifting_log = geometry.protocol.lifting_log_size orelse
            geometry.queryLogSize();
        const evaluation_log = geometry.queryLogSize();
        if (lifting_log < evaluation_log) return error.UnsupportedProtocol;
        @memset(folds, lifting_log - evaluation_log);

        const output_indices = try allocator.alloc(
            u32,
            geometry_mod.sampled_mask_points,
        );
        errdefer allocator.free(output_indices);
        const oods_policy = exact_oods.Policy.init(geometry);
        @memcpy(coefficient_logs, &oods_policy.coefficient_log_sizes);
        @memcpy(offsets, &oods_policy.offset_points);
        @memcpy(output_indices, &oods_policy.output_indices);

        return .{
            .twiddle_tree = tree,
            .twiddle_views = views,
            .fri_inverse_twiddle_offsets = fri_offsets,
            .coefficient_log_sizes = coefficient_logs,
            .oods_offset_points = offsets,
            .oods_fold_counts = folds,
            .oods_output_indices = output_indices,
            .circle = try deriveCircleConstants(geometry),
            .transcript_static = deriveTranscriptStatic(geometry),
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.oods_output_indices);
        allocator.free(self.oods_fold_counts);
        allocator.free(self.oods_offset_points);
        allocator.free(self.coefficient_log_sizes);
        allocator.free(self.fri_inverse_twiddle_offsets);
        allocator.free(self.twiddle_views);
        prover_twiddles.deinitM31(allocator, &self.twiddle_tree);
        self.* = undefined;
    }

    pub fn viewForCircleLog(
        self: *const Self,
        circle_log_size: u32,
    ) error{InvalidCircleLog}!TwiddleView {
        const max_circle_log = min_executed_circle_log +
            @as(u32, @intCast(self.twiddle_views.len - 1));
        if (circle_log_size < min_executed_circle_log or
            circle_log_size > max_circle_log)
        {
            return error.InvalidCircleLog;
        }
        return self.twiddle_views[
            circle_log_size - min_executed_circle_log
        ];
    }

    pub fn forwardTwiddleWords(self: *const Self) []const u32 {
        return m31Words(self.twiddle_tree.twiddles);
    }

    pub fn inverseTwiddleWords(self: *const Self) []const u32 {
        return m31Words(self.twiddle_tree.itwiddles);
    }

    pub fn transcriptConfig(self: *const Self) []const u32 {
        return self.transcript_static[0..transcript_config_words];
    }

    pub fn transcriptEmptyRoot(self: *const Self) []const u32 {
        const first = transcript_config_words;
        return self.transcript_static[first .. first + transcript_empty_root_words];
    }

    pub fn transcriptStatement(self: *const Self) []const u32 {
        const first =
            transcript_config_words + transcript_empty_root_words;
        return self.transcript_static[first .. first + transcript_statement_words];
    }
};

const min_executed_circle_log: u32 = 2;

const FriFoldKind = enum {
    circle_to_line,
    line,
};

/// Circle folding consumes the packed half-domain (`n / 2` words), whereas a
/// line fold indexes its `n / 2` butterflies from an `n`-word tree suffix.
fn friFoldTwiddleOffset(
    twiddle_words: usize,
    evaluation_log_size: u32,
    kind: FriFoldKind,
) error{GeometryOverflow}!u32 {
    if (evaluation_log_size >= @bitSizeOf(usize))
        return error.GeometryOverflow;
    const evaluation_rows = @as(usize, 1) <<
        @intCast(evaluation_log_size);
    const consumed_words = switch (kind) {
        .circle_to_line => evaluation_rows / 2,
        .line => evaluation_rows,
    };
    if (consumed_words > twiddle_words) return error.GeometryOverflow;
    return u32Count(twiddle_words - consumed_words);
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
    const minus_two = M31.fromCanonical(2).neg();
    const si0 = try p0.y.mul(minus_two).mul(derivative).inv();

    const coset = canonic.coset();
    const vanishing_rotation = coset.initial
        .conjugate()
        .add(coset.step_size.half().toPoint());

    const trace_coset = CanonicCoset
        .new(geometry.log_n_rows)
        .coset();
    // The exact AIR evaluates over 4N rows and selects the physical coset with
    // `row >> log_n_rows`. Convert each physical block representative through
    // the bit-reversed storage map before deriving its inverse.
    const composition_domain = CanonicCoset
        .new(geometry.composition_log_rows)
        .circleDomain();
    var denominator_inverses: [4]u32 = undefined;
    for (&denominator_inverses, 0..) |*inverse, row| {
        const physical_row = row * try geometry.traceRowCount();
        const logical_row = core.utils.bitReverseIndex(
            physical_row,
            geometry.composition_log_rows,
        );
        inverse.* = (try core.constraints.cosetVanishing(
            M31,
            trace_coset,
            composition_domain.at(logical_row),
        ).inv()).toU32();
    }

    return .{
        .domain_log_size = domain_log,
        .half_coset_initial_index = try u32Count(
            domain.half_coset.initial_index.v,
        ),
        .half_coset_step_size = try u32Count(
            domain.half_coset.step_size.v,
        ),
        .barycentric_si0 = rawSecure(QM31.fromBase(si0)),
        .vanishing_rotation = rawBasePoint(vanishing_rotation),
        .composition_denominator_inverses = denominator_inverses,
    };
}

fn deriveTranscriptStatic(
    geometry: geometry_mod.Geometry,
) [transcript_static_words]u32 {
    var output: [transcript_static_words]u32 = undefined;
    output[0..transcript_config_words].* = .{
        geometry.protocol.pow_bits,
        geometry.protocol.fri_config.log_blowup_factor,
        @intCast(geometry.protocol.fri_config.n_queries),
        geometry.protocol.fri_config.log_last_layer_degree_bound,
    };

    const Hasher =
        core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
    var empty_hasher = Hasher.defaultWithInitialState();
    const empty_root = empty_hasher.finalize();
    const root_first = transcript_config_words;
    for (0..transcript_empty_root_words) |index| {
        const byte_first = index * @sizeOf(u32);
        output[root_first + index] = std.mem.readInt(
            u32,
            empty_root[byte_first..][0..@sizeOf(u32)],
            .little,
        );
    }

    const statement_first =
        transcript_config_words + transcript_empty_root_words;
    output[statement_first] = geometry.statement.log_n_instances;
    return output;
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

fn rawBasePoint(point: CirclePointM31) field.CirclePointBaseField {
    return .{ .x = point.x.toU32(), .y = point.y.toU32() };
}

fn m31Words(values: []const M31) []const u32 {
    comptime {
        std.debug.assert(@sizeOf(M31) == @sizeOf(u32));
        std.debug.assert(@alignOf(M31) == @alignOf(u32));
    }
    const words: [*]const u32 = @ptrCast(values.ptr);
    return words[0..values.len];
}

fn twiddleWords(circle_log_size: u32) error{GeometryOverflow}!usize {
    if (circle_log_size == 0) return error.GeometryOverflow;
    const word_log = circle_log_size - 1;
    if (word_log >= @bitSizeOf(usize)) return error.GeometryOverflow;
    return @as(usize, 1) << @intCast(word_log);
}

fn u32Count(value: usize) error{GeometryOverflow}!u32 {
    return std.math.cast(u32, value) orelse error.GeometryOverflow;
}

fn testGeometry(log_n_rows: u32) !geometry_mod.Geometry {
    const pcs = @import("stwo_core").pcs;
    return geometry_mod.admitRequest(.{
        .statement = .{ .log_n_instances = log_n_rows + 3 },
        .protocol = pcs.PcsConfig.default(),
    });
}

test "canonical ingress twiddle suffixes match exact core trees" {
    const allocator = std.testing.allocator;
    for ([_]u32{ 3, 5, 14 }) |trace_log| {
        const geometry = try testGeometry(trace_log);
        var pack = try Pack.init(allocator, geometry);
        defer pack.deinit(allocator);

        try std.testing.expectEqual(
            geometry.commitment_rows,
            pack.twiddle_tree.twiddles.len,
        );
        for (
            pack.twiddle_tree.twiddles,
            pack.forwardTwiddleWords(),
        ) |canonical, abi_word| {
            try std.testing.expectEqual(canonical.toU32(), abi_word);
        }
        for (
            pack.twiddle_tree.itwiddles,
            pack.inverseTwiddleWords(),
        ) |canonical, abi_word| {
            try std.testing.expectEqual(canonical.toU32(), abi_word);
        }

        for (pack.twiddle_views) |view| {
            var exact = try prover_twiddles.precomputeM31(
                allocator,
                CanonicCoset
                    .new(view.circle_log_size)
                    .circleDomain()
                    .half_coset,
            );
            defer prover_twiddles.deinitM31(allocator, &exact);

            const offset: usize = view.offset_words;
            const count: usize = view.word_count;
            try std.testing.expectEqualSlices(
                M31,
                exact.twiddles,
                pack.twiddle_tree.twiddles[offset..][0..count],
            );
            try std.testing.expectEqualSlices(
                M31,
                exact.itwiddles,
                pack.twiddle_tree.itwiddles[offset..][0..count],
            );
        }

        for (pack.fri_inverse_twiddle_offsets, 0..) |offset, fold| {
            const fold_u32: u32 = @intCast(fold);
            const evaluation_log = geometry.queryLogSize() - fold_u32;
            try std.testing.expectEqual(
                try friFoldTwiddleOffset(
                    pack.twiddle_tree.itwiddles.len,
                    evaluation_log,
                    if (fold == 0) .circle_to_line else .line,
                ),
                offset,
            );
        }
        try std.testing.expectEqual(
            @as(u32, @intCast(geometry.trace_rows)),
            pack.fri_inverse_twiddle_offsets[0],
        );
        try std.testing.expectEqual(
            @as(u32, @intCast(geometry.trace_rows)),
            pack.fri_inverse_twiddle_offsets[1],
        );
        if (trace_log == 3) {
            try std.testing.expectEqualSlices(
                u32,
                &.{ 8, 8, 12 },
                pack.fri_inverse_twiddle_offsets,
            );
        }
        if (trace_log == 5) {
            try std.testing.expectEqualSlices(
                u32,
                &.{ 32, 32, 48, 56, 60 },
                pack.fri_inverse_twiddle_offsets,
            );
        }
    }
}

test "canonical ingress OODS descriptors retain proof order" {
    const allocator = std.testing.allocator;
    for ([_]u32{ 3, 5, 14 }) |trace_log| {
        const geometry = try testGeometry(trace_log);
        var pack = try Pack.init(allocator, geometry);
        defer pack.deinit(allocator);

        try std.testing.expectEqual(
            geometry_mod.source_columns,
            pack.coefficient_log_sizes.len,
        );
        try std.testing.expectEqual(
            geometry_mod.sampled_mask_points,
            pack.oods_offset_points.len,
        );
        const policy = exact_oods.Policy.init(geometry);
        for (0..geometry_mod.source_columns) |index| {
            try std.testing.expectEqual(
                trace_log,
                pack.coefficient_log_sizes[index],
            );
            try std.testing.expectEqual(
                policy.coefficient_log_sizes[index],
                pack.coefficient_log_sizes[index],
            );
        }
        for (0..geometry_mod.sampled_mask_points) |index| {
            try std.testing.expectEqual(
                policy.offset_points[index],
                pack.oods_offset_points[index],
            );
            try std.testing.expectEqual(@as(u32, 0), pack.oods_fold_counts[index]);
            try std.testing.expectEqual(
                policy.output_indices[index],
                pack.oods_output_indices[index],
            );
        }
    }
}

test "canonical ingress seals the exact raw Stwo transcript prefix" {
    const allocator = std.testing.allocator;
    const geometry = try testGeometry(5);
    var pack = try Pack.init(allocator, geometry);
    defer pack.deinit(allocator);

    try std.testing.expectEqualSlices(
        u32,
        &.{
            geometry.protocol.pow_bits,
            geometry.protocol.fri_config.log_blowup_factor,
            @intCast(geometry.protocol.fri_config.n_queries),
            geometry.protocol.fri_config.log_last_layer_degree_bound,
        },
        pack.transcriptConfig(),
    );
    var root_bytes: [32]u8 = undefined;
    for (pack.transcriptEmptyRoot(), 0..) |word, index| {
        std.mem.writeInt(
            u32,
            root_bytes[index * @sizeOf(u32) ..][0..@sizeOf(u32)],
            word,
            .little,
        );
    }
    const root_hex = std.fmt.bytesToHex(root_bytes, .lower);
    try std.testing.expectEqualStrings(
        "2a133e150238721921d1ea772882979c810f85f2849099b9d3415a8619d85fad",
        &root_hex,
    );
    try std.testing.expectEqualSlices(
        u32,
        &.{geometry.statement.log_n_instances},
        pack.transcriptStatement(),
    );
}

test "canonical ingress circle constants satisfy core field identities" {
    const allocator = std.testing.allocator;
    for ([_]u32{ 3, 5, 14 }) |trace_log| {
        const geometry = try testGeometry(trace_log);
        var pack = try Pack.init(allocator, geometry);
        defer pack.deinit(allocator);

        const domain = CanonicCoset
            .new(geometry.queryLogSize())
            .circleDomain();
        try std.testing.expectEqual(
            @as(u32, @intCast(domain.half_coset.initial_index.v)),
            pack.circle.half_coset_initial_index,
        );
        try std.testing.expectEqual(
            @as(u32, @intCast(domain.half_coset.step_size.v)),
            pack.circle.half_coset_step_size,
        );

        const generated_coset = core.circle.Coset.new(
            core.circle.CirclePointIndex.generator(),
            geometry.queryLogSize(),
        );
        const p0 = domain.at(0);
        const denominator = p0.y
            .mul(M31.fromCanonical(2).neg())
            .mul(core.constraints.cosetVanishingDerivative(
            M31,
            generated_coset,
            p0,
        ));
        const raw_si0 = pack.circle.barycentric_si0;
        try std.testing.expectEqual(@as(u32, 0), raw_si0.b);
        try std.testing.expectEqual(@as(u32, 0), raw_si0.c);
        try std.testing.expectEqual(@as(u32, 0), raw_si0.d);
        try std.testing.expect(
            denominator
                .mul(M31.fromCanonical(raw_si0.a))
                .eql(M31.one()),
        );

        const canonic_coset = CanonicCoset
            .new(geometry.queryLogSize())
            .coset();
        const rotation = canonic_coset.initial
            .conjugate()
            .add(canonic_coset.step_size.half().toPoint());
        try std.testing.expectEqual(
            rotation.x.toU32(),
            pack.circle.vanishing_rotation.x,
        );
        try std.testing.expectEqual(
            rotation.y.toU32(),
            pack.circle.vanishing_rotation.y,
        );

        const trace_coset = CanonicCoset.new(trace_log).coset();
        const composition_domain = CanonicCoset
            .new(geometry.composition_log_rows)
            .circleDomain();
        for (pack.circle.composition_denominator_inverses, 0..) |raw, row| {
            const logical_row = core.utils.bitReverseIndex(
                row * try geometry.traceRowCount(),
                geometry.composition_log_rows,
            );
            const vanishing = core.constraints.cosetVanishing(
                M31,
                trace_coset,
                composition_domain.at(logical_row),
            );
            try std.testing.expect(
                vanishing.mul(M31.fromCanonical(raw)).eql(M31.one()),
            );
        }
    }
}

test "canonical ingress denominators match all four physical AIR cosets" {
    const allocator = std.testing.allocator;
    for ([_]u32{ 3, 5, 14 }) |trace_log| {
        const geometry = try testGeometry(trace_log);
        var pack = try Pack.init(allocator, geometry);
        defer pack.deinit(allocator);

        const domain_log = geometry.composition_log_rows;
        const domain = CanonicCoset.new(domain_log).circleDomain();
        const trace_coset = CanonicCoset.new(trace_log).coset();
        for (0..geometry.commitment_rows) |physical_row| {
            const denominator_index = physical_row >> @intCast(trace_log);
            try std.testing.expect(denominator_index < 4);
            const logical_row = core.utils.bitReverseIndex(
                physical_row,
                domain_log,
            );
            const vanishing = core.constraints.cosetVanishing(
                M31,
                trace_coset,
                domain.at(logical_row),
            );
            const inverse = M31.fromCanonical(
                pack.circle.composition_denominator_inverses[
                    denominator_index
                ],
            );
            try std.testing.expect(vanishing.mul(inverse).eql(M31.one()));
        }

        try std.testing.expectEqual(
            @as(usize, 0),
            core.utils.bitReverseIndex(0, domain_log),
        );
        try std.testing.expectEqual(
            @as(usize, 2),
            core.utils.bitReverseIndex(geometry.trace_rows, domain_log),
        );
    }
}

test "canonical ingress rejects twiddle views outside executed logs" {
    const allocator = std.testing.allocator;
    const geometry = try testGeometry(5);
    var pack = try Pack.init(allocator, geometry);
    defer pack.deinit(allocator);

    try std.testing.expectError(
        error.InvalidCircleLog,
        pack.viewForCircleLog(min_executed_circle_log - 1),
    );
    try std.testing.expectError(
        error.InvalidCircleLog,
        pack.viewForCircleLog(geometry.composition_log_rows + 1),
    );
}
