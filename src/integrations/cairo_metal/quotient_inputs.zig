//! Metal orchestration for Cairo quotient-input accumulation.

const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;
const metal_runtime = @import("stwo_metal_backend").runtime;
const composition_bundle = @import("stwo_cairo_frontend").witness.composition_bundle;
const geometry = @import("stwo_cairo_frontend").witness.quotient_geometry;
const quotients = @import("stwo_core").pcs.quotients;
const twiddles = @import("stwo_prover_impl").poly.twiddles;
const circle = @import("stwo_core").circle;
const canonic = @import("stwo_core").poly.circle.canonic;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub const Telemetry = struct {
    wall_ms: f64,
    gpu_ms: f64,
    sample_count: usize,
    column_count: usize,
    source_words_scanned: u64,
};

const SampleRange = struct { start: usize, len: usize };

const OwnedColumns = struct {
    allocator: std.mem.Allocator,
    bindings: []arena_plan.Binding,
    flat_samples: []quotients.SampleWithRandomness,
    samples: [][]const quotients.SampleWithRandomness,

    fn deinit(self: *OwnedColumns) void {
        self.allocator.free(self.samples);
        self.allocator.free(self.flat_samples);
        self.allocator.free(self.bindings);
        self.* = undefined;
    }
};

const SavedPartial = struct {
    log_size: u32,
    coordinates: [4][]M31,

    fn init(
        allocator: std.mem.Allocator,
        resident_arena: *arena_plan.ResidentArena,
        partials: []const arena_plan.Binding,
        target: usize,
        log_size: u32,
    ) !SavedPartial {
        const word_count = @as(usize, 1) << @intCast(log_size);
        var coordinates: [4][]M31 = undefined;
        var initialized: usize = 0;
        errdefer for (coordinates[0..initialized]) |coordinate| allocator.free(coordinate);
        for (0..4) |coordinate| {
            const source = try bindingM31(resident_arena, partials[target * 4 + coordinate]);
            if (source.len < word_count) return error.InvalidQuotientInputShape;
            coordinates[coordinate] = try allocator.dupe(M31, source[0..word_count]);
            initialized += 1;
        }
        return .{ .log_size = log_size, .coordinates = coordinates };
    }

    fn deinit(self: *SavedPartial, allocator: std.mem.Allocator) void {
        for (self.coordinates) |coordinate| allocator.free(coordinate);
        self.* = undefined;
    }
};

fn liftAndAccumulateEvaluation(destination: []M31, previous: []const M31) !void {
    if (destination.len <= previous.len or
        !std.math.isPowerOfTwo(destination.len) or
        !std.math.isPowerOfTwo(previous.len))
        return error.InvalidQuotientPartialLogs;
    const log_ratio = std.math.log2_int(usize, destination.len) -
        std.math.log2_int(usize, previous.len);
    const lift_shift: std.math.Log2Int(usize) = @intCast(log_ratio + 1);
    for (destination, 0..) |*value, row| {
        const lifted_index = ((row >> lift_shift) << 1) + (row & 1);
        if (lifted_index >= previous.len) return error.InvalidQuotientPartialLogs;
        value.* = value.add(previous[lifted_index]);
    }
}

/// Builds the 19 accumulated numerator inputs used by the quotient bottom.
/// Numerators are accumulated and transformed per source log, then lifted and
/// accumulated in evaluation space exactly like the Rust backend.
pub fn populate(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    bundle: composition_bundle.Bundle,
    preprocessed: []const arena_plan.Binding,
    base: []const arena_plan.Binding,
    interaction: []const arena_plan.Binding,
    composition: []const arena_plan.Binding,
    oods_challenge: arena_plan.Binding,
    quotient_random: arena_plan.Binding,
    sampled_values: arena_plan.Binding,
    partials: []const arena_plan.Binding,
    sample_points: arena_plan.Binding,
    first_linear_terms: arena_plan.Binding,
    forward_twiddles: arena_plan.Binding,
) !Telemetry {
    var timer = try std.time.Timer.start();
    if (composition.len != 8 or partials.len == 0 or partials.len % 4 != 0)
        return error.InvalidQuotientInputShape;
    const lifting_log_size = try geometry.validatedLiftingLogSize(bundle.max_evaluation_log_size);
    const max_trace_log_size = lifting_log_size - 1;
    const sample_count = partials.len / 4;
    if (sample_points.size_bytes != @as(u64, sample_count) * 8 * 4 or
        first_linear_terms.size_bytes != @as(u64, sample_count) * 4 * 4)
        return error.InvalidQuotientInputShape;

    const oods_words = try bindingWords(resident_arena, oods_challenge);
    const random_words = try bindingWords(resident_arena, quotient_random);
    const sampled_words = try bindingWords(resident_arena, sampled_values);
    if (oods_words.len < 4 or random_words.len < 4 or sampled_words.len % 4 != 0)
        return error.InvalidQuotientInputShape;
    try geometry.canonicalWords(oods_words[0..4]);
    try geometry.canonicalWords(random_words[0..4]);
    try geometry.canonicalWords(sampled_words);
    const oods_point = try geometry.pointFromParameter(geometry.secureFromWords(oods_words[0..4]));
    const random_coeff = geometry.secureFromWords(random_words[0..4]);

    var masks = try geometry.deriveMasks(allocator, bundle, preprocessed.len, base.len, interaction.len);
    defer masks.deinit();
    const log_stages = std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS");
    if (log_stages)
        std.debug.print(
            "quotient_inputs stage=masks preprocessed={} base={} interaction={}\n",
            .{ preprocessed.len, base.len, interaction.len },
        );
    var columns = try buildColumns(
        allocator,
        preprocessed,
        base,
        interaction,
        composition,
        masks,
        oods_point,
        sampled_words,
        random_coeff,
        lifting_log_size,
        max_trace_log_size,
    );
    defer columns.deinit();
    if (log_stages) {
        var maximum_end: u64 = 0;
        for (columns.bindings) |binding| maximum_end = @max(maximum_end, binding.offset_bytes + binding.size_bytes);
        std.debug.print(
            "quotient_inputs stage=columns columns={} samples={} maximum_end_bytes={}\n",
            .{ columns.bindings.len, columns.flat_samples.len, maximum_end },
        );
    }

    const batches = try quotients.ColumnSampleBatch.newVec(allocator, columns.samples);
    defer quotients.ColumnSampleBatch.deinitSlice(allocator, batches);
    if (batches.len != sample_count) return error.InvalidQuotientSampleCount;
    if (log_stages)
        std.debug.print("quotient_inputs stage=batches batches={}\n", .{batches.len});
    var constants = try quotients.quotientConstants(allocator, batches);
    defer constants.deinit(allocator);
    if (log_stages)
        std.debug.print("quotient_inputs stage=constants line_coeff_batches={}\n", .{constants.line_coeffs.len});

    const sample_output = try bindingWords(resident_arena, sample_points);
    const linear_output = try bindingWords(resident_arena, first_linear_terms);
    const assigned = try allocator.alloc(bool, sample_count);
    defer allocator.free(assigned);
    @memset(assigned, false);
    var targets_by_point = std.AutoHashMap(circle.CirclePointQM31, usize).init(allocator);
    defer targets_by_point.deinit();
    var source_words_scanned: u64 = 0;

    // Rust sorts the per-log accumulations by sample point before grouping and
    // lifting them. Preserve that order when assigning equal-sized bindings.
    const batch_order = try allocator.alloc(usize, batches.len);
    defer allocator.free(batch_order);
    for (batch_order, 0..) |*index, value| index.* = value;
    std.mem.sort(usize, batch_order, batches, struct {
        fn lessThan(all_batches: []quotients.ColumnSampleBatch, lhs: usize, rhs: usize) bool {
            return geometry.pointLessThan(all_batches[lhs].point, all_batches[rhs].point);
        }
    }.lessThan);

    // Establish the final point-to-binding geometry and linear terms. Partial
    // numerators are produced per source log below, as in the Rust backend.
    for (batch_order) |batch_index| {
        const batch = batches[batch_index];
        const line_coeffs = constants.line_coeffs[batch_index];
        if (batch.cols_vals_randpows.len == 0 or batch.cols_vals_randpows.len != line_coeffs.len)
            return error.InvalidQuotientInputShape;
        var maximum_source_words: u64 = 0;
        for (batch.cols_vals_randpows) |sample| {
            if (sample.column_index >= columns.bindings.len) return error.InvalidQuotientInputShape;
            maximum_source_words = @max(
                maximum_source_words,
                columns.bindings[sample.column_index].size_bytes / 4,
            );
        }
        if (maximum_source_words == 0 or !std.math.isPowerOfTwo(maximum_source_words))
            return error.InvalidQuotientInputShape;
        const row_words = maximum_source_words;
        var group: ?usize = null;
        for (0..sample_count) |candidate| {
            if (!assigned[candidate] and partials[candidate * 4].size_bytes / 4 == row_words) {
                group = candidate;
                break;
            }
        }
        const target = group orelse return error.InvalidQuotientPartialLogs;
        assigned[target] = true;
        var sum_a = QM31.zero();
        for (line_coeffs) |coeffs| {
            sum_a = sum_a.add(coeffs.a);
        }

        const point_words = batch.point.x.toM31Array() ++ batch.point.y.toM31Array();
        for (point_words, 0..) |word, coordinate| sample_output[target * 8 + coordinate] = word.v;
        const linear = sum_a.toM31Array();
        for (linear, 0..) |word, coordinate| linear_output[target * 4 + coordinate] = word.v;
        const point_entry = try targets_by_point.getOrPut(batch.point);
        if (point_entry.found_existing) return error.InvalidQuotientSampleCount;
        point_entry.value_ptr.* = target;
    }
    for (assigned) |value| if (!value) return error.InvalidQuotientPartialLogs;
    if (log_stages)
        std.debug.print("quotient_inputs stage=geometry points={}\n", .{targets_by_point.count()});

    const accumulated_logs = try allocator.alloc(?u32, sample_count);
    defer allocator.free(accumulated_logs);
    @memset(accumulated_logs, null);
    var gpu_ms: f64 = 0;
    _ = forward_twiddles;
    var source_log: u32 = 3;
    while (source_log <= max_trace_log_size) : (source_log += 1) {
        var group_bindings = std.ArrayList(arena_plan.Binding).empty;
        defer group_bindings.deinit(allocator);
        var group_samples = std.ArrayList([]const quotients.SampleWithRandomness).empty;
        defer group_samples.deinit(allocator);
        for (columns.bindings, columns.samples) |binding, column_samples| {
            if (column_samples.len == 0) continue;
            const word_count = binding.size_bytes / 4;
            if (word_count == 0 or !std.math.isPowerOfTwo(word_count))
                return error.InvalidQuotientInputShape;
            const coefficient_log = std.math.log2_int(u64, word_count);
            if (coefficient_log < 3 or coefficient_log > max_trace_log_size)
                return error.InvalidQuotientInputShape;
            if (coefficient_log != source_log) continue;
            try group_bindings.append(allocator, binding);
            try group_samples.append(allocator, column_samples);
        }
        if (group_bindings.items.len == 0) continue;

        const group_batches = try quotients.ColumnSampleBatch.newVec(allocator, group_samples.items);
        defer quotients.ColumnSampleBatch.deinitSlice(allocator, group_batches);
        if (group_batches.len == 0) continue;
        var group_constants = try quotients.quotientConstants(allocator, group_batches);
        defer group_constants.deinit(allocator);

        const targets = try allocator.alloc(usize, group_batches.len);
        defer allocator.free(targets);
        const tasks = try allocator.alloc(metal_runtime.QuotientCoefficientTask, group_batches.len);
        defer allocator.free(tasks);
        const coefficient_zero_oracles = try allocator.alloc(QM31, group_batches.len);
        defer allocator.free(coefficient_zero_oracles);
        const saved_partials = try allocator.alloc(?SavedPartial, group_batches.len);
        defer {
            for (saved_partials) |*saved| if (saved.*) |*partial| partial.deinit(allocator);
            allocator.free(saved_partials);
        }
        @memset(saved_partials, null);
        const row_starts = try allocator.alloc(u32, group_batches.len + 1);
        defer allocator.free(row_starts);
        row_starts[0] = 0;
        var terms = std.ArrayList(metal_runtime.QuotientCoefficientTerm).empty;
        defer terms.deinit(allocator);
        const row_words_u64 = @as(u64, 1) << @intCast(source_log);
        const row_words = std.math.cast(usize, row_words_u64) orelse
            return error.InvalidQuotientInputShape;

        for (group_batches, group_constants.line_coeffs, 0..) |batch, line_coeffs, batch_index| {
            if (batch.cols_vals_randpows.len == 0 or batch.cols_vals_randpows.len != line_coeffs.len)
                return error.InvalidQuotientInputShape;
            const target = targets_by_point.get(batch.point) orelse return error.InvalidQuotientSampleCount;
            targets[batch_index] = target;
            if (accumulated_logs[target]) |previous_log| {
                if (previous_log >= source_log) return error.InvalidQuotientPartialLogs;
                saved_partials[batch_index] = try SavedPartial.init(
                    allocator,
                    resident_arena,
                    partials,
                    target,
                    previous_log,
                );
            }

            var destinations: [4]u32 = undefined;
            for (0..4) |coordinate| {
                const partial = partials[target * 4 + coordinate];
                if (partial.size_bytes / 4 < row_words_u64 or partial.offset_bytes % 4 != 0)
                    return error.InvalidQuotientInputShape;
                destinations[coordinate] = std.math.cast(u32, partial.offset_bytes / 4) orelse {
                    if (log_stages)
                        std.debug.print("quotient_inputs invalid=destination_offset bytes={}\n", .{partial.offset_bytes});
                    return error.InvalidQuotientInputShape;
                };
            }

            const term_start = terms.items.len;
            var sum_b = QM31.zero();
            var coefficient_zero = QM31.zero();
            for (batch.cols_vals_randpows, line_coeffs) |sample, coeffs| {
                if (sample.column_index >= group_bindings.items.len)
                    return error.InvalidQuotientInputShape;
                const source = group_bindings.items[sample.column_index];
                if (source.offset_bytes % 4 != 0 or source.size_bytes / 4 != row_words_u64)
                    return error.InvalidQuotientInputShape;
                const value_coefficients = coeffs.c.toM31Array();
                try terms.append(allocator, .{
                    .source_word_offset = source.offset_bytes / 4,
                    .source_word_count = std.math.cast(u32, row_words_u64) orelse
                        return error.InvalidQuotientInputShape,
                    .value_coefficients = .{
                        value_coefficients[0].v,
                        value_coefficients[1].v,
                        value_coefficients[2].v,
                        value_coefficients[3].v,
                    },
                });
                source_words_scanned = std.math.add(u64, source_words_scanned, row_words_u64) catch
                    return error.InvalidQuotientInputShape;
                if (log_stages) {
                    const source_words = try bindingWords(resident_arena, source);
                    if (source_words.len == 0 or source_words[0] >= geometry.m31_prime)
                        return error.InvalidQuotientInputShape;
                    coefficient_zero = coefficient_zero.add(
                        coeffs.c.mulM31(M31.fromCanonical(source_words[0])),
                    );
                }
                sum_b = sum_b.add(coeffs.b);
            }
            coefficient_zero_oracles[batch_index] = coefficient_zero.sub(sum_b);
            const b = sum_b.toM31Array();
            tasks[batch_index] = .{
                .term_start = std.math.cast(u32, term_start) orelse return error.InvalidQuotientInputShape,
                .term_count = std.math.cast(u32, terms.items.len - term_start) orelse
                    return error.InvalidQuotientInputShape,
                .destination_word_offsets = destinations,
                .row_count = std.math.cast(u32, row_words_u64) orelse
                    return error.InvalidQuotientInputShape,
                .constant_terms = .{ b[0].v, b[1].v, b[2].v, b[3].v },
            };
            row_starts[batch_index + 1] = std.math.add(
                u32,
                row_starts[batch_index],
                std.math.cast(u32, row_words_u64) orelse return error.InvalidQuotientInputShape,
            ) catch return error.InvalidQuotientInputShape;
        }

        gpu_ms += try metal.accumulateQuotientCoefficientsResident(
            resident_arena.buffer,
            terms.items,
            tasks,
            row_starts,
        );
        if (log_stages) for (targets, coefficient_zero_oracles) |target, expected_value| {
            const expected = expected_value.toM31Array();
            for (0..4) |coordinate| {
                const actual = (try bindingWords(resident_arena, partials[target * 4 + coordinate]))[0];
                if (actual != expected[coordinate].v) {
                    std.debug.print(
                        "quotient_inputs mismatch=coefficient_zero log={} target={} coordinate={} expected={} actual={}\n",
                        .{ source_log, target, coordinate, expected[coordinate].v, actual },
                    );
                    return error.QuotientCoefficientParityMismatch;
                }
            }
        };

        var transform_columns = std.ArrayList([]M31).empty;
        defer transform_columns.deinit(allocator);
        for (targets) |target| for (0..4) |coordinate| {
            const destination = try bindingM31(resident_arena, partials[target * 4 + coordinate]);
            if (destination.len < row_words) return error.InvalidQuotientInputShape;
            try transform_columns.append(allocator, destination[0..row_words]);
        };
        var split = try canonic.CanonicCoset.new(source_log + 1).circleDomain().split(allocator, 1);
        defer split.deinit(allocator);
        var split_twiddles = try twiddles.precomputeM31(allocator, split.subdomain.half_coset);
        defer twiddles.deinitM31(allocator, &split_twiddles);
        gpu_ms += try metal.transformCircle(
            allocator,
            transform_columns.items,
            split_twiddles.twiddles,
            source_log,
            false,
        );

        // Rust's lift_and_accumulate uses this bit-reversed evaluation index.
        for (targets, saved_partials) |target, *saved_slot| {
            if (saved_slot.*) |*saved| {
                if (saved.log_size >= source_log) return error.InvalidQuotientPartialLogs;
                for (0..4) |coordinate| {
                    const destination_all = try bindingM31(resident_arena, partials[target * 4 + coordinate]);
                    const destination = destination_all[0..row_words];
                    try liftAndAccumulateEvaluation(destination, saved.coordinates[coordinate]);
                }
            }
            accumulated_logs[target] = source_log;
        }
        if (log_stages)
            std.debug.print(
                "quotient_inputs stage=source_log log={} columns={} batches={} terms={}\n",
                .{ source_log, group_bindings.items.len, group_batches.len, terms.items.len },
            );
    }

    for (accumulated_logs, 0..) |accumulated_log, target| {
        const expected_log = std.math.log2_int(u64, partials[target * 4].size_bytes / 4);
        if (accumulated_log == null or accumulated_log.? != expected_log)
            return error.InvalidQuotientPartialLogs;
    }

    return .{
        .wall_ms = @as(f64, @floatFromInt(timer.read())) / std.time.ns_per_ms,
        .gpu_ms = gpu_ms,
        .sample_count = batches.len,
        .column_count = columns.bindings.len,
        .source_words_scanned = source_words_scanned,
    };
}
fn buildColumns(
    allocator: std.mem.Allocator,
    preprocessed: []const arena_plan.Binding,
    base: []const arena_plan.Binding,
    interaction: []const arena_plan.Binding,
    composition: []const arena_plan.Binding,
    masks: geometry.Masks,
    oods_point: circle.CirclePointQM31,
    sampled_words: []const u32,
    random_coeff: QM31,
    lifting_log_size: u32,
    max_trace_log_size: u32,
) !OwnedColumns {
    var bindings = std.ArrayList(arena_plan.Binding).empty;
    defer bindings.deinit(allocator);
    var ranges = std.ArrayList(SampleRange).empty;
    defer ranges.deinit(allocator);
    var flat_samples = std.ArrayList(quotients.SampleWithRandomness).empty;
    defer flat_samples.deinit(allocator);
    var value_cursor: usize = 0;
    var random_pow = QM31.one();
    const trace_step_m31 = canonic.CanonicCoset.new(max_trace_log_size).step();
    const trace_step = geometry.pointM31IntoQM31(trace_step_m31);
    const lifting_generator = canonic.CanonicCoset.new(lifting_log_size).step();

    for (preprocessed, masks.preprocessed_used) |binding, used| {
        var points: [1]circle.CirclePointQM31 = .{oods_point};
        try appendColumn(
            allocator,
            &bindings,
            &ranges,
            &flat_samples,
            binding,
            if (used) &points else &.{},
            sampled_words,
            &value_cursor,
            &random_pow,
            random_coeff,
            lifting_generator,
            lifting_log_size,
        );
    }
    for (base, masks.base_offsets) |binding, offsets| {
        if (offsets.items.len == 0 or offsets.items.len > 2) return error.InvalidQuotientMask;
        var points: [2]circle.CirclePointQM31 = undefined;
        for (offsets.items, 0..) |offset, index| points[index] = oods_point.add(trace_step.mulSigned(offset));
        try appendColumn(
            allocator,
            &bindings,
            &ranges,
            &flat_samples,
            binding,
            points[0..offsets.items.len],
            sampled_words,
            &value_cursor,
            &random_pow,
            random_coeff,
            lifting_generator,
            lifting_log_size,
        );
    }
    for (interaction, masks.interaction_offsets) |binding, offsets| {
        if (offsets.items.len == 0 or offsets.items.len > 2) return error.InvalidQuotientMask;
        var points: [2]circle.CirclePointQM31 = undefined;
        for (offsets.items, 0..) |offset, index| points[index] = oods_point.add(trace_step.mulSigned(offset));
        try appendColumn(
            allocator,
            &bindings,
            &ranges,
            &flat_samples,
            binding,
            points[0..offsets.items.len],
            sampled_words,
            &value_cursor,
            &random_pow,
            random_coeff,
            lifting_generator,
            lifting_log_size,
        );
    }
    for (composition) |binding| {
        var points: [1]circle.CirclePointQM31 = .{oods_point};
        try appendColumn(
            allocator,
            &bindings,
            &ranges,
            &flat_samples,
            binding,
            &points,
            sampled_words,
            &value_cursor,
            &random_pow,
            random_coeff,
            lifting_generator,
            lifting_log_size,
        );
    }
    if (value_cursor * 4 != sampled_words.len) return error.InvalidQuotientSampleCount;

    const owned_bindings = try bindings.toOwnedSlice(allocator);
    errdefer allocator.free(owned_bindings);
    const owned_samples = try flat_samples.toOwnedSlice(allocator);
    errdefer allocator.free(owned_samples);
    const views = try allocator.alloc([]const quotients.SampleWithRandomness, ranges.items.len);
    for (ranges.items, views) |range, *view| view.* = owned_samples[range.start .. range.start + range.len];
    return .{
        .allocator = allocator,
        .bindings = owned_bindings,
        .flat_samples = owned_samples,
        .samples = views,
    };
}

fn appendColumn(
    allocator: std.mem.Allocator,
    bindings: *std.ArrayList(arena_plan.Binding),
    ranges: *std.ArrayList(SampleRange),
    flat_samples: *std.ArrayList(quotients.SampleWithRandomness),
    binding: arena_plan.Binding,
    points: []const circle.CirclePointQM31,
    sampled_words: []const u32,
    value_cursor: *usize,
    random_pow: *QM31,
    random_coeff: QM31,
    lifting_generator: circle.CirclePointM31,
    lifting_log_size: u32,
) !void {
    if (binding.size_bytes == 0 or binding.size_bytes % 4 != 0 or
        !std.math.isPowerOfTwo(binding.size_bytes / 4) or points.len > 2)
        return error.InvalidQuotientInputShape;
    const coefficient_log_size: u32 = std.math.log2_int(u64, binding.size_bytes / 4);
    // Tree 0 contains preprocessed columns larger than the FRI lifting domain.
    // They are valid here when the AIR mask does not sample them: upstream keeps
    // those columns in the tree shape but produces no quotient contribution.
    if (points.len != 0 and coefficient_log_size >= lifting_log_size)
        return error.InvalidQuotientInputShape;
    const column_log_size = coefficient_log_size + 1;
    const start = flat_samples.items.len;
    var values: [2]QM31 = undefined;
    for (points, 0..) |_, index| {
        const word_start = (value_cursor.* + index) * 4;
        if (word_start + 4 > sampled_words.len) return error.InvalidQuotientSampleCount;
        values[index] = geometry.secureFromWords(sampled_words[word_start .. word_start + 4]);
    }
    if (points.len == 2) {
        const periodic_point = points[1].add(
            geometry.pointM31IntoQM31(lifting_generator.repeatedDouble(column_log_size)),
        );
        try flat_samples.append(allocator, .{
            .point = periodic_point,
            .value = values[1],
            .random_coeff = nextRandomPower(random_pow, random_coeff),
        });
    }
    for (points, values[0..points.len]) |point, value| try flat_samples.append(allocator, .{
        .point = point,
        .value = value,
        .random_coeff = nextRandomPower(random_pow, random_coeff),
    });
    value_cursor.* += points.len;
    try bindings.append(allocator, binding);
    try ranges.append(allocator, .{ .start = start, .len = flat_samples.items.len - start });
}

fn bindingWords(resident_arena: *arena_plan.ResidentArena, binding: arena_plan.Binding) ![]align(4) u32 {
    const bytes: []align(4) u8 = @alignCast(try resident_arena.bytes(binding));
    if (bytes.len % 4 != 0 or binding.offset_bytes % 4 != 0) return error.InvalidQuotientInputShape;
    return std.mem.bytesAsSlice(u32, bytes);
}

fn bindingM31(resident_arena: *arena_plan.ResidentArena, binding: arena_plan.Binding) ![]M31 {
    const words = try bindingWords(resident_arena, binding);
    return std.mem.bytesAsSlice(M31, std.mem.sliceAsBytes(words));
}

fn nextRandomPower(power: *QM31, random_coeff: QM31) QM31 {
    const result = power.*;
    power.* = power.mul(random_coeff);
    return result;
}

test "Cairo Metal quotient lift matches Rust bit-reversed indexing" {
    const previous = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(2),
    };
    var destination = [_]M31{
        M31.fromCanonical(10),
        M31.fromCanonical(11),
        M31.fromCanonical(12),
        M31.fromCanonical(13),
        M31.fromCanonical(14),
        M31.fromCanonical(15),
        M31.fromCanonical(16),
        M31.fromCanonical(17),
    };
    const expected = [_]u32{ 11, 13, 13, 15, 15, 17, 17, 19 };

    try liftAndAccumulateEvaluation(&destination, &previous);
    for (destination, expected) |actual, expected_word|
        try std.testing.expectEqual(expected_word, actual.v);
}

test "Cairo Metal unsampled preprocessed columns may exceed the FRI lifting domain" {
    const allocator = std.testing.allocator;
    const lifting_log_size: u32 = 24;
    var bindings = std.ArrayList(arena_plan.Binding).empty;
    defer bindings.deinit(allocator);
    var ranges = std.ArrayList(SampleRange).empty;
    defer ranges.deinit(allocator);
    var samples = std.ArrayList(quotients.SampleWithRandomness).empty;
    defer samples.deinit(allocator);
    var value_cursor: usize = 0;
    var random_pow = QM31.one();
    const binding = arena_plan.Binding{
        .logical_id = 1,
        .slot = 0,
        .offset_bytes = 0,
        .size_bytes = @as(u64, 4) << 25,
        .materialization = .resident,
        .occupied = [_]u64{0} ** (arena_plan.max_ticks / 64),
    };

    try appendColumn(
        allocator,
        &bindings,
        &ranges,
        &samples,
        binding,
        &.{},
        &.{},
        &value_cursor,
        &random_pow,
        QM31.one(),
        canonic.CanonicCoset.new(lifting_log_size).step(),
        lifting_log_size,
    );

    try std.testing.expectEqual(@as(usize, 1), bindings.items.len);
    try std.testing.expectEqual(@as(usize, 1), ranges.items.len);
    try std.testing.expectEqual(@as(usize, 0), ranges.items[0].len);
    try std.testing.expectEqual(@as(usize, 0), samples.items.len);
    try std.testing.expectEqual(@as(usize, 0), value_cursor);
}
