const std = @import("std");

const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const core_utils = @import("stwo_core").utils;
const circle_poly = @import("stwo_prover_engine").poly.circle.poly;
const twiddles_mod = @import("stwo_prover_engine").poly.twiddles;
const arena_plan = @import("../arena_plan.zig");
const recovery = @import("../recovery.zig");
const runtime = @import("../runtime.zig");
const blake2_hash = @import("stwo_core").vcs.blake2_hash;
const fri_geometry = @import("stwo_core").fri.geometry;
const cairo_merkle = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;

const cairo_domain_prefix_bytes = cairo_merkle.domainPrefixBytes();

pub const FriGeometry = fri_geometry.FriGeometry;

/// One circle-to-line or line-to-line FRI fold with every operand resident in
/// the shared arena. The challenge and inverse-coordinate column are bindings,
/// so replay never uploads control data or reads the folded column back.
pub const FriFoldRecipe = struct {
    metal: *runtime.Runtime,
    arena: *arena_plan.ResidentArena,
    destination: arena_plan.Binding,
    prepared: runtime.FriFoldPlan,
    last_tick: ?u16 = null,
    accumulated_gpu_ms: f64 = 0,

    pub fn init(
        metal: *runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
        source: arena_plan.Binding,
        inverse_coordinates: arena_plan.Binding,
        challenge: arena_plan.Binding,
        destination: arena_plan.Binding,
        source_count: u32,
        circle: bool,
    ) !FriFoldRecipe {
        const destination_count = source_count / 2;
        if (source_count < 2 or source_count & 1 != 0 or
            source.offset_bytes % 4 != 0 or inverse_coordinates.offset_bytes % 4 != 0 or
            challenge.offset_bytes % 4 != 0 or destination.offset_bytes % 4 != 0 or
            source.size_bytes < @as(u64, source_count) * 16 or
            inverse_coordinates.size_bytes < @as(u64, destination_count) * 4 or
            challenge.size_bytes < 16 or destination.size_bytes < @as(u64, destination_count) * 16)
            return recovery.RecoveryError.BindingSizeMismatch;
        return .{
            .metal = metal,
            .arena = resident_arena,
            .destination = destination,
            .prepared = try metal.prepareFriFold(
                std.math.cast(u32, source.offset_bytes / 4) orelse return recovery.RecoveryError.BindingSizeMismatch,
                std.math.cast(u32, inverse_coordinates.offset_bytes / 4) orelse return recovery.RecoveryError.BindingSizeMismatch,
                std.math.cast(u32, challenge.offset_bytes / 4) orelse return recovery.RecoveryError.BindingSizeMismatch,
                std.math.cast(u32, destination.offset_bytes / 4) orelse return recovery.RecoveryError.BindingSizeMismatch,
                source_count,
                circle,
            ),
        };
    }

    pub fn deinit(self: *FriFoldRecipe) void {
        self.prepared.deinit();
        self.* = undefined;
    }

    pub fn recipe(self: *FriFoldRecipe) recovery.Recipe {
        return .{ .logical_id = self.destination.logical_id, .context = self, .run = run };
    }

    fn run(raw: *anyopaque, tick: u16, requested: arena_plan.Binding, _: []u8) !void {
        const self: *FriFoldRecipe = @ptrCast(@alignCast(raw));
        if (requested.logical_id != self.destination.logical_id) return recovery.RecoveryError.MissingRecipe;
        if (self.last_tick == tick) return;
        self.accumulated_gpu_ms += try self.metal.friFoldPrepared(self.arena.buffer, self.prepared);
        self.last_tick = tick;
    }
};

/// Prepared quotient bottom: combine mixed-log secure numerators on the
/// quotient subdomain, interpolate its four coordinates in place, then LDE
/// directly into the full-domain planar buffer consumed by FRI.
pub const QuotientRecipe = struct {
    allocator: std.mem.Allocator,
    metal: *runtime.Runtime,
    arena: *arena_plan.ResidentArena,
    destination: arena_plan.Binding,
    partials: []arena_plan.Binding,
    sample_points: arena_plan.Binding,
    first_linear_terms: arena_plan.Binding,
    subdomain_values: arena_plan.Binding,
    inverse_subdomain_twiddles: arena_plan.Binding,
    subdomain_log: u32,
    quotient_log: u32,
    combine: runtime.QuotientCombinePlan,
    interpolate: runtime.CircleIfftPlan,
    evaluate: runtime.CircleLdePlan,
    last_tick: ?u16 = null,
    accumulated_gpu_ms: f64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        metal: *runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
        partials_source_major: []const arena_plan.Binding,
        sample_points: arena_plan.Binding,
        first_linear_terms: arena_plan.Binding,
        denominator_scratch: arena_plan.Binding,
        subdomain_values: arena_plan.Binding,
        quotient_values: arena_plan.Binding,
        inverse_subdomain_twiddles: arena_plan.Binding,
        forward_twiddles: arena_plan.Binding,
    ) !QuotientRecipe {
        if (partials_source_major.len == 0 or partials_source_major.len % 4 != 0 or
            sample_points.offset_bytes % 4 != 0 or first_linear_terms.offset_bytes % 4 != 0 or
            denominator_scratch.offset_bytes % 4 != 0 or subdomain_values.offset_bytes % 4 != 0 or
            quotient_values.offset_bytes % 4 != 0 or inverse_subdomain_twiddles.offset_bytes % 4 != 0 or
            forward_twiddles.offset_bytes % 4 != 0)
            return recovery.RecoveryError.BindingSizeMismatch;
        const sample_count = partials_source_major.len / 4;
        if (sample_points.size_bytes != @as(u64, sample_count) * 8 * 4 or
            first_linear_terms.size_bytes != @as(u64, sample_count) * 4 * 4 or
            subdomain_values.size_bytes % 16 != 0 or quotient_values.size_bytes % 16 != 0)
            return recovery.RecoveryError.BindingSizeMismatch;
        const subdomain_rows = subdomain_values.size_bytes / 16;
        const quotient_rows = quotient_values.size_bytes / 16;
        if (!std.math.isPowerOfTwo(subdomain_rows) or !std.math.isPowerOfTwo(quotient_rows) or quotient_rows <= subdomain_rows)
            return recovery.RecoveryError.BindingSizeMismatch;
        const subdomain_log: u32 = std.math.log2_int(u64, subdomain_rows);
        const quotient_log: u32 = std.math.log2_int(u64, quotient_rows);
        if (denominator_scratch.size_bytes != subdomain_rows * sample_count * 8 or
            inverse_subdomain_twiddles.size_bytes < subdomain_rows / 2 * 4 or
            forward_twiddles.size_bytes < quotient_rows / 2 * 4)
            return recovery.RecoveryError.BindingSizeMismatch;

        const offsets = try allocator.alloc(u32, partials_source_major.len);
        defer allocator.free(offsets);
        const logs = try allocator.alloc(u32, sample_count);
        defer allocator.free(logs);
        for (0..sample_count) |source| {
            const first = partials_source_major[source * 4];
            if (first.size_bytes < 4 or first.size_bytes % 4 != 0 or !std.math.isPowerOfTwo(first.size_bytes / 4))
                return recovery.RecoveryError.BindingSizeMismatch;
            logs[source] = std.math.log2_int(u64, first.size_bytes / 4);
            if (logs[source] > subdomain_log) return recovery.RecoveryError.BindingSizeMismatch;
            for (0..4) |coordinate| {
                const partial = partials_source_major[source * 4 + coordinate];
                if (partial.size_bytes != first.size_bytes or partial.offset_bytes % 4 != 0)
                    return recovery.RecoveryError.BindingSizeMismatch;
                offsets[coordinate * sample_count + source] = std.math.cast(u32, partial.offset_bytes / 4) orelse
                    return recovery.RecoveryError.BindingSizeMismatch;
            }
        }
        const subdomain_offset = std.math.cast(u32, subdomain_values.offset_bytes / 4) orelse
            return recovery.RecoveryError.BindingSizeMismatch;
        const quotient_offset = quotient_values.offset_bytes / 4;
        const initial_index = @as(u32, 1) << @intCast(30 - quotient_log);
        const step_size = @as(u32, 1) << @intCast(32 - subdomain_log);
        var combine = try metal.prepareQuotientCombine(
            offsets,
            logs,
            std.math.cast(u32, sample_points.offset_bytes / 4) orelse return recovery.RecoveryError.BindingSizeMismatch,
            std.math.cast(u32, first_linear_terms.offset_bytes / 4) orelse return recovery.RecoveryError.BindingSizeMismatch,
            std.math.cast(u32, denominator_scratch.offset_bytes / 4) orelse return recovery.RecoveryError.BindingSizeMismatch,
            subdomain_offset,
            subdomain_log,
            initial_index,
            step_size,
        );
        errdefer combine.deinit();
        var subdomain_offsets: [4]u64 = undefined;
        var quotient_offsets: [4]u64 = undefined;
        for (0..4) |coordinate| {
            subdomain_offsets[coordinate] = subdomain_offset + @as(u64, @intCast(coordinate)) * subdomain_rows;
            quotient_offsets[coordinate] = quotient_offset + @as(u64, @intCast(coordinate)) * quotient_rows;
        }
        const scale = @import("stwo_core").fields.m31.M31.fromCanonical(@intCast(subdomain_rows)).inv() catch
            return recovery.RecoveryError.BindingSizeMismatch;
        var interpolate = try metal.prepareCircleIfft(
            &subdomain_offsets,
            &subdomain_offsets,
            subdomain_log,
            std.math.cast(u32, inverse_subdomain_twiddles.offset_bytes / 4) orelse return recovery.RecoveryError.BindingSizeMismatch,
            scale.v,
        );
        errdefer interpolate.deinit();
        const forward_words = forward_twiddles.size_bytes / 4;
        const quotient_twiddle_words = quotient_rows / 2;
        const forward_twiddle_offset = std.math.add(
            u64,
            forward_twiddles.offset_bytes / 4,
            forward_words - quotient_twiddle_words,
        ) catch return recovery.RecoveryError.BindingSizeMismatch;
        var evaluate = try metal.prepareCircleLde(
            &subdomain_offsets,
            &quotient_offsets,
            subdomain_log,
            quotient_log,
            std.math.cast(u32, forward_twiddle_offset) orelse return recovery.RecoveryError.BindingSizeMismatch,
        );
        errdefer evaluate.deinit();
        const owned_partials = try allocator.dupe(arena_plan.Binding, partials_source_major);
        errdefer allocator.free(owned_partials);
        return .{
            .allocator = allocator,
            .metal = metal,
            .arena = resident_arena,
            .destination = quotient_values,
            .partials = owned_partials,
            .sample_points = sample_points,
            .first_linear_terms = first_linear_terms,
            .subdomain_values = subdomain_values,
            .inverse_subdomain_twiddles = inverse_subdomain_twiddles,
            .subdomain_log = subdomain_log,
            .quotient_log = quotient_log,
            .combine = combine,
            .interpolate = interpolate,
            .evaluate = evaluate,
        };
    }

    pub fn deinit(self: *QuotientRecipe) void {
        self.evaluate.deinit();
        self.interpolate.deinit();
        self.combine.deinit();
        self.allocator.free(self.partials);
        self.* = undefined;
    }

    pub fn recipe(self: *QuotientRecipe) recovery.Recipe {
        return .{ .logical_id = self.destination.logical_id, .context = self, .run = run };
    }

    pub fn execute(self: *QuotientRecipe) !void {
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            try self.validateInverseTwiddles();
        self.accumulated_gpu_ms += try self.metal.quotientCombinePrepared(self.arena.buffer, self.combine);
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) {
            try self.validateCombineSamples();
            self.logDigest("combine", self.subdomain_values) catch {};
        }
        self.accumulated_gpu_ms += try self.metal.circleIfftPrepared(self.arena.buffer, self.interpolate);
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) {
            self.logDigest("ifft", self.subdomain_values) catch {};
            try self.validateIfftAtRow(0);
        }
        self.accumulated_gpu_ms += try self.metal.circleLdePrepared(self.arena.buffer, self.evaluate);
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) {
            self.logDigest("lde", self.destination) catch {};
            try self.validateLdeAtRow(0);
        }
    }

    fn logDigest(self: *QuotientRecipe, stage: []const u8, binding: arena_plan.Binding) !void {
        const bytes = try self.arena.bytes(binding);
        const digest = blake2_hash.Blake2sHasher.hash(bytes);
        const aligned: []align(4) const u8 = @alignCast(bytes);
        const words = std.mem.bytesAsSlice(u32, aligned);
        std.debug.print(
            "quotient stage={s} digest={x} first={},{},{},{}\n",
            .{ stage, digest, words[0], words[1], words[2], words[3] },
        );
    }

    fn validateInverseTwiddles(self: *QuotientRecipe) !void {
        const actual_bytes: []align(4) u8 = @alignCast(try self.arena.bytes(self.inverse_subdomain_twiddles));
        const actual_words = std.mem.bytesAsSlice(u32, actual_bytes);
        var split = try canonic.CanonicCoset.new(self.quotient_log).circleDomain().split(
            self.allocator,
            self.quotient_log - self.subdomain_log,
        );
        defer split.deinit(self.allocator);
        var expected = try twiddles_mod.precomputeM31(self.allocator, split.subdomain.half_coset);
        defer twiddles_mod.deinitM31(self.allocator, &expected);
        if (actual_words.len != expected.itwiddles.len)
            return error.QuotientInverseTwiddleParityMismatch;
        for (actual_words, expected.itwiddles, 0..) |actual, wanted, index| {
            if (actual != wanted.v) {
                std.debug.print(
                    "quotient inverse_twiddles mismatch index={} expected={} actual={}\n",
                    .{ index, wanted.v, actual },
                );
                return error.QuotientInverseTwiddleParityMismatch;
            }
        }
        const actual_digest = blake2_hash.Blake2sHasher.hash(actual_bytes);
        const expected_digest = blake2_hash.Blake2sHasher.hash(std.mem.sliceAsBytes(expected.itwiddles));
        std.debug.print(
            "quotient inverse_twiddles exact words={} digest={x} expected_digest={x} first={},{},{},{} last={} offset_words={}\n",
            .{
                actual_words.len,
                actual_digest,
                expected_digest,
                actual_words[0],
                actual_words[1],
                actual_words[2],
                actual_words[3],
                actual_words[actual_words.len - 1],
                self.inverse_subdomain_twiddles.offset_bytes / 4,
            },
        );
    }

    fn expectedCombineAtRow(self: *QuotientRecipe, row: usize) !QM31 {
        const sample_count = self.partials.len / 4;
        const sample_bytes: []align(4) u8 = @alignCast(try self.arena.bytes(self.sample_points));
        const linear_bytes: []align(4) u8 = @alignCast(try self.arena.bytes(self.first_linear_terms));
        const sample_words = std.mem.bytesAsSlice(u32, sample_bytes);
        const linear_words = std.mem.bytesAsSlice(u32, linear_bytes);
        var split = try canonic.CanonicCoset.new(self.quotient_log).circleDomain().split(
            self.allocator,
            self.quotient_log - self.subdomain_log,
        );
        defer split.deinit(self.allocator);
        const point = split.subdomain.at(core_utils.bitReverseIndex(row, self.subdomain_log));
        var expected = QM31.zero();
        for (0..sample_count) |sample| {
            const sample_base = sample * 8;
            const sample_x = QM31.fromU32Unchecked(
                sample_words[sample_base],
                sample_words[sample_base + 1],
                sample_words[sample_base + 2],
                sample_words[sample_base + 3],
            );
            const sample_y = QM31.fromU32Unchecked(
                sample_words[sample_base + 4],
                sample_words[sample_base + 5],
                sample_words[sample_base + 6],
                sample_words[sample_base + 7],
            );
            const denominator = sample_x.c0.subM31(point.x).mul(sample_y.c1).sub(
                sample_y.c0.subM31(point.y).mul(sample_x.c1),
            );
            const inverse = try denominator.inv();
            const partial_log = std.math.log2_int(u64, self.partials[sample * 4].size_bytes / 4);
            const log_ratio = self.subdomain_log - partial_log;
            const lifted = (row >> @intCast(log_ratio + 1) << 1) + (row & 1);
            var partial_coordinates: [4]M31 = undefined;
            for (0..4) |coordinate| {
                const partial_bytes: []align(4) u8 = @alignCast(try self.arena.bytes(self.partials[sample * 4 + coordinate]));
                const partial_words = std.mem.bytesAsSlice(u32, partial_bytes);
                partial_coordinates[coordinate] = M31.fromCanonical(partial_words[lifted]);
            }
            const linear_base = sample * 4;
            const first = QM31.fromU32Unchecked(
                linear_words[linear_base],
                linear_words[linear_base + 1],
                linear_words[linear_base + 2],
                linear_words[linear_base + 3],
            );
            expected = expected.add(
                QM31.fromM31Array(partial_coordinates).sub(first.mulM31(point.y)).mulCM31(inverse),
            );
        }
        return expected;
    }

    fn validateCombineSamples(self: *QuotientRecipe) !void {
        const output_bytes: []align(4) u8 = @alignCast(try self.arena.bytes(self.subdomain_values));
        const output_words = std.mem.bytesAsSlice(u32, output_bytes);
        const row_count = @as(usize, 1) << @intCast(self.subdomain_log);
        const sample_rows = [_]usize{
            0,                 1,                 2,                 3,                 7,
            row_count / 16,    row_count / 8,     row_count / 4,     row_count / 2 - 1, row_count / 2,
            row_count / 2 + 1, 3 * row_count / 4, 7 * row_count / 8, row_count - 8,     row_count - 4,
            row_count - 2,     row_count - 1,
        };
        for (sample_rows) |row| {
            const expected = try self.expectedCombineAtRow(row);
            const actual = QM31.fromU32Unchecked(
                output_words[row],
                output_words[row_count + row],
                output_words[2 * row_count + row],
                output_words[3 * row_count + row],
            );
            if (!actual.eql(expected)) {
                std.debug.print(
                    "quotient stage=combine mismatch row={} expected={any} actual={any}\n",
                    .{ row, expected.toM31Array(), actual.toM31Array() },
                );
                return error.QuotientCombineParityMismatch;
            }
        }
        std.debug.print("quotient stage=combine cpu_samples=exact rows={}\n", .{sample_rows.len});
    }

    fn coefficientsAtPoint(self: *QuotientRecipe, point: @import("stwo_core").circle.CirclePointM31) !QM31 {
        const coefficient_bytes: []align(4) u8 = @alignCast(try self.arena.bytes(self.subdomain_values));
        const coefficient_words = std.mem.bytesAsSlice(u32, coefficient_bytes);
        const row_count = @as(usize, 1) << @intCast(self.subdomain_log);
        var partial_evals: [4]QM31 = undefined;
        for (0..4) |coordinate| {
            const words = coefficient_words[coordinate * row_count .. (coordinate + 1) * row_count];
            const coefficients = try self.allocator.alloc(M31, row_count);
            defer self.allocator.free(coefficients);
            for (words, coefficients) |word, *coefficient| coefficient.* = M31.fromCanonical(word);
            const polynomial = try circle_poly.CircleCoefficients.initBorrowed(coefficients);
            partial_evals[coordinate] = polynomial.evalAtPoint(.{
                .x = QM31.fromBase(point.x),
                .y = QM31.fromBase(point.y),
            });
        }
        return QM31.fromPartialEvals(partial_evals);
    }

    fn validateIfftAtRow(self: *QuotientRecipe, row: usize) !void {
        var split = try canonic.CanonicCoset.new(self.quotient_log).circleDomain().split(
            self.allocator,
            self.quotient_log - self.subdomain_log,
        );
        defer split.deinit(self.allocator);
        const point = split.subdomain.at(core_utils.bitReverseIndex(row, self.subdomain_log));
        const expected = try self.expectedCombineAtRow(row);
        const actual = try self.coefficientsAtPoint(point);
        if (!actual.eql(expected)) {
            std.debug.print("quotient stage=ifft mismatch row={} expected={any} actual={any}\n", .{
                row, expected.toM31Array(), actual.toM31Array(),
            });
            return error.QuotientIfftParityMismatch;
        }
        std.debug.print("quotient stage=ifft scalar_eval=exact row={}\n", .{row});
    }

    fn validateLdeAtRow(self: *QuotientRecipe, row: usize) !void {
        const point = canonic.CanonicCoset.new(self.quotient_log).circleDomain().at(
            core_utils.bitReverseIndex(row, self.quotient_log),
        );
        const expected = try self.coefficientsAtPoint(point);
        const output_bytes: []align(4) u8 = @alignCast(try self.arena.bytes(self.destination));
        const output_words = std.mem.bytesAsSlice(u32, output_bytes);
        const row_count = @as(usize, 1) << @intCast(self.quotient_log);
        const actual = QM31.fromU32Unchecked(
            output_words[row],
            output_words[row_count + row],
            output_words[2 * row_count + row],
            output_words[3 * row_count + row],
        );
        if (!actual.eql(expected)) {
            std.debug.print("quotient stage=lde mismatch row={} expected={any} actual={any}\n", .{
                row, expected.toM31Array(), actual.toM31Array(),
            });
            return error.QuotientLdeParityMismatch;
        }
        std.debug.print("quotient stage=lde scalar_eval=exact row={}\n", .{row});
    }

    fn run(raw: *anyopaque, tick: u16, requested: arena_plan.Binding, _: []u8) !void {
        const self: *QuotientRecipe = @ptrCast(@alignCast(raw));
        if (requested.logical_id != self.destination.logical_id) return recovery.RecoveryError.MissingRecipe;
        if (self.last_tick == tick) return;
        try self.execute();
        self.last_tick = tick;
    }
};

fn validateFriCardinalities(
    geometry: FriGeometry,
    retained_count: usize,
    challenge_count: usize,
    merkle_layer_count: usize,
) !void {
    const round_count = std.math.add(usize, retained_count, 1) catch
        return recovery.RecoveryError.BindingSizeMismatch;
    if (round_count != geometry.roundCount() or
        challenge_count != geometry.roundCount() or
        merkle_layer_count != geometry.totalLayerCount() or
        geometry.terminalLog() != geometry.finalLog())
        return recovery.RecoveryError.BindingSizeMismatch;
}

pub fn validateFriOpeningRound(geometry: FriGeometry, round: usize, leaf_log: u32) !void {
    if (round >= geometry.roundCount() or leaf_log != try geometry.leafLog(round))
        return recovery.RecoveryError.BindingSizeMismatch;
}

test "Metal FRI cardinalities accept seven-round Fib and eight-round SN2 geometry" {
    const sn2 = try FriGeometry.init(24);
    try validateFriCardinalities(sn2, 7, 8, 100);
    try std.testing.expectError(
        recovery.RecoveryError.BindingSizeMismatch,
        validateFriCardinalities(sn2, 6, 8, 100),
    );

    const fib = try FriGeometry.initRuntime(21, .{
        .round_count = 7,
        .fold_step = 3,
        .final_log = 1,
        .packed_log = 2,
    });
    try validateFriCardinalities(fib, 6, 7, 77);
    for (0..fib.roundCount()) |round| try validateFriOpeningRound(fib, round, try fib.leafLog(round));
    try std.testing.expectError(
        recovery.RecoveryError.BindingSizeMismatch,
        validateFriCardinalities(fib, 6, 8, 77),
    );
    try std.testing.expectError(
        recovery.RecoveryError.BindingSizeMismatch,
        validateFriCardinalities(fib, 6, 7, 78),
    );
    try std.testing.expectError(
        recovery.RecoveryError.BindingSizeMismatch,
        validateFriOpeningRound(fib, 6, 2),
    );
    try std.testing.expectError(
        recovery.RecoveryError.BindingSizeMismatch,
        validateFriOpeningRound(fib, 7, 0),
    );
}

/// Exact STWO FRI bottom with planar secure evaluations and four rows per leaf.
/// Transcript control calls
/// `commitTree` and `foldRound` alternately so each device root can be mixed
/// before its resident challenge is consumed.
pub const FriRecipe = struct {
    pub const FinalDegreeError = error{
        FinalDegreeNotComputed,
        FinalDegreeExceeded,
    };

    metal: *runtime.Runtime,
    arena: *arena_plan.ResidentArena,
    rounds: [FriGeometry.max_round_count]runtime.FriRoundPlan,
    trees: [FriGeometry.max_round_count]runtime.FriTreePlan,
    final: runtime.FriFinalPlan,
    roots: [FriGeometry.max_round_count]arena_plan.Binding,
    round_count: usize = FriGeometry.round_count,
    initialized_rounds: usize,
    initialized_trees: usize,
    initialized_final: bool,
    final_degree_error: arena_plan.Binding,
    finalized: bool = false,
    accumulated_gpu_ms: f64 = 0,

    pub fn init(
        metal: *runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
        quotient: arena_plan.Binding,
        retained: []const arena_plan.Binding,
        challenges: []const arena_plan.Binding,
        inverse_twiddles: arena_plan.Binding,
        final_evaluation: arena_plan.Binding,
        final_coefficients: arena_plan.Binding,
        final_degree_error: arena_plan.Binding,
        merkle_layers_root_first: []const arena_plan.Binding,
        leaf_seed: [8]u32,
        node_seed: [8]u32,
    ) !FriRecipe {
        if (quotient.offset_bytes % 4 != 0 or quotient.size_bytes < 16 or quotient.size_bytes % 16 != 0 or
            !std.math.isPowerOfTwo(quotient.size_bytes / 16))
            return recovery.RecoveryError.BindingSizeMismatch;
        const geometry = try FriGeometry.init(std.math.log2_int(u64, quotient.size_bytes / 16));
        return initWithGeometry(
            metal,
            resident_arena,
            geometry,
            quotient,
            retained,
            challenges,
            inverse_twiddles,
            final_evaluation,
            final_coefficients,
            final_degree_error,
            merkle_layers_root_first,
            leaf_seed,
            node_seed,
        );
    }

    pub fn initWithGeometry(
        metal: *runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
        geometry: FriGeometry,
        quotient: arena_plan.Binding,
        retained: []const arena_plan.Binding,
        challenges: []const arena_plan.Binding,
        inverse_twiddles: arena_plan.Binding,
        final_evaluation: arena_plan.Binding,
        final_coefficients: arena_plan.Binding,
        final_degree_error: arena_plan.Binding,
        merkle_layers_root_first: []const arena_plan.Binding,
        leaf_seed: [8]u32,
        node_seed: [8]u32,
    ) !FriRecipe {
        if (quotient.offset_bytes % 4 != 0 or quotient.size_bytes < 16 or quotient.size_bytes % 16 != 0 or
            !std.math.isPowerOfTwo(quotient.size_bytes / 16) or
            std.math.log2_int(u64, quotient.size_bytes / 16) != geometry.startLog() or
            geometry.finalLog() != 1 or geometry.packedLog() != 2)
            return recovery.RecoveryError.BindingSizeMismatch;
        try validateFriCardinalities(geometry, retained.len, challenges.len, merkle_layers_root_first.len);
        if (inverse_twiddles.offset_bytes % 4 != 0 or inverse_twiddles.size_bytes != geometry.inverseTwiddleWords() * 4)
            return recovery.RecoveryError.BindingSizeMismatch;
        var self = FriRecipe{
            .metal = metal,
            .arena = resident_arena,
            .rounds = undefined,
            .trees = undefined,
            .final = undefined,
            .roots = undefined,
            .round_count = geometry.roundCount(),
            .initialized_rounds = 0,
            .initialized_trees = 0,
            .initialized_final = false,
            .final_degree_error = final_degree_error,
        };
        errdefer self.deinitInitialized();

        var evaluations: [FriGeometry.max_round_count]arena_plan.Binding = undefined;
        evaluations[0] = quotient;
        @memcpy(evaluations[1..geometry.roundCount()], retained);
        var layer_cursor: usize = 0;
        for (evaluations[0..geometry.roundCount()], 0..) |evaluation, tree| {
            const log_size = try geometry.evaluationLog(tree);
            const layer_count = try geometry.layerCount(tree);
            const rows = @as(u64, 1) << @intCast(log_size);
            if (evaluation.offset_bytes % 4 != 0 or evaluation.size_bytes != rows * 16)
                return recovery.RecoveryError.BindingSizeMismatch;
            var layer_offsets: [32]u32 = undefined;
            const group = merkle_layers_root_first[layer_cursor .. layer_cursor + layer_count];
            for (0..layer_count) |bottom_index| {
                const binding = group[layer_count - 1 - bottom_index];
                const expected_hashes = (@as(u64, 1) << @intCast(log_size - 2)) >> @intCast(bottom_index);
                if (binding.offset_bytes % 4 != 0 or binding.size_bytes != expected_hashes * 32)
                    return recovery.RecoveryError.BindingSizeMismatch;
                layer_offsets[bottom_index] = std.math.cast(u32, binding.offset_bytes / 4) orelse
                    return recovery.RecoveryError.BindingSizeMismatch;
            }
            self.roots[tree] = group[0];
            self.trees[tree] = try metal.prepareFriTree(
                std.math.cast(u32, evaluation.offset_bytes / 4) orelse return recovery.RecoveryError.BindingSizeMismatch,
                @intCast(rows),
                @intCast(rows),
                2,
                layer_offsets[0..layer_count],
                leaf_seed,
                node_seed,
                cairo_domain_prefix_bytes,
            );
            self.initialized_trees += 1;
            layer_cursor += layer_count;
        }

        const twiddle_base = std.math.cast(u32, inverse_twiddles.offset_bytes / 4) orelse
            return recovery.RecoveryError.BindingSizeMismatch;
        const twiddle_words: u32 = @intCast(inverse_twiddles.size_bytes / 4);
        for (0..geometry.roundCount()) |round| {
            const source = evaluations[round];
            const source_rows = @as(u32, 1) << @intCast(try geometry.evaluationLog(round));
            const fold_count = try geometry.roundFold(round);
            const output = if (round + 1 == geometry.roundCount()) final_evaluation else evaluations[round + 1];
            const output_rows = source_rows >> @intCast(fold_count);
            if (challenges[round].offset_bytes % 4 != 0 or challenges[round].size_bytes < 16 or
                output.offset_bytes % 4 != 0 or output.size_bytes < @as(u64, output_rows) * 16)
                return recovery.RecoveryError.BindingSizeMismatch;
            self.rounds[round] = try metal.prepareFriRound(
                twiddle_base,
                twiddle_words,
                std.math.cast(u32, source.offset_bytes / 4) orelse return recovery.RecoveryError.BindingSizeMismatch,
                source_rows,
                std.math.cast(u32, challenges[round].offset_bytes / 4) orelse return recovery.RecoveryError.BindingSizeMismatch,
                std.math.cast(u32, output.offset_bytes / 4) orelse return recovery.RecoveryError.BindingSizeMismatch,
                output_rows,
                source_rows,
                fold_count,
                round == 0,
            );
            self.initialized_rounds += 1;
        }
        if (final_coefficients.offset_bytes % 4 != 0 or final_coefficients.size_bytes != 32 or
            final_degree_error.offset_bytes % 4 != 0 or final_degree_error.size_bytes != 4)
            return recovery.RecoveryError.BindingSizeMismatch;
        const final_x = @import("stwo_core").circle.Coset.halfOdds(1).initial.x;
        const inverse_x = final_x.inv() catch return recovery.RecoveryError.BindingSizeMismatch;
        self.final = try metal.prepareFriFinal(
            std.math.cast(u32, final_evaluation.offset_bytes / 4) orelse return recovery.RecoveryError.BindingSizeMismatch,
            2,
            inverse_x.v,
            std.math.cast(u32, final_coefficients.offset_bytes / 4) orelse return recovery.RecoveryError.BindingSizeMismatch,
            std.math.cast(u32, final_degree_error.offset_bytes / 4) orelse return recovery.RecoveryError.BindingSizeMismatch,
        );
        self.initialized_final = true;
        return self;
    }

    fn deinitInitialized(self: *FriRecipe) void {
        if (self.initialized_final) self.final.deinit();
        for (self.rounds[0..self.initialized_rounds]) |*plan| plan.deinit();
        for (self.trees[0..self.initialized_trees]) |*plan| plan.deinit();
    }

    pub fn deinit(self: *FriRecipe) void {
        self.deinitInitialized();
        self.* = undefined;
    }

    pub fn commitTree(self: *FriRecipe, tree: usize) !arena_plan.Binding {
        if (tree >= self.round_count) return recovery.RecoveryError.BindingSizeMismatch;
        self.accumulated_gpu_ms += try self.metal.friTreePrepared(self.arena.buffer, self.trees[tree]);
        return self.roots[tree];
    }

    pub fn foldRound(self: *FriRecipe, round: usize) !void {
        if (round >= self.round_count) return recovery.RecoveryError.BindingSizeMismatch;
        self.accumulated_gpu_ms += try self.metal.friRoundPrepared(self.arena.buffer, self.rounds[round]);
    }

    pub fn finalize(self: *FriRecipe) !void {
        self.accumulated_gpu_ms += try self.metal.friFinalPrepared(self.arena.buffer, self.final);
        self.finalized = true;
        try self.validateFinalDegree();
    }

    pub fn validateFinalDegree(self: *FriRecipe) !void {
        if (!self.finalized) return FinalDegreeError.FinalDegreeNotComputed;
        const bytes = try self.arena.bytes(self.final_degree_error);
        if (bytes.len != @sizeOf(u32)) return recovery.RecoveryError.BindingSizeMismatch;
        const aligned: []align(@alignOf(u32)) u8 = @alignCast(bytes);
        if (std.mem.bytesAsValue(u32, aligned).* != 0)
            return FinalDegreeError.FinalDegreeExceeded;
    }
};
