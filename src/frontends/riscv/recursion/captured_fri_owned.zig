//! Internal captured fri authority shard; use captured_fri.zig publicly.

const dependency_0 = @import("captured_fri_contract.zig");

const Error = dependency_0.Error;
const M31 = dependency_0.M31;
const ProfileConfig = dependency_0.ProfileConfig;
const QM31 = dependency_0.QM31;
const STAGE_TELEMETRY_ENV = dependency_0.STAGE_TELEMETRY_ENV;
const add = dependency_0.add;
const canonic = dependency_0.canonic;
const canonicalPosition = dependency_0.canonicalPosition;
const captureStageFailure = dependency_0.captureStageFailure;
const circle = dependency_0.circle;
const circuit_mod = dependency_0.circuit_mod;
const fri_merkle = dependency_0.fri_merkle;
const m31 = dependency_0.m31;
const mapTreeQueryPosition = dependency_0.mapTreeQueryPosition;
const merkle_root = dependency_0.merkle_root;
const multiply = dependency_0.multiply;
const pcs_circuit_mod = dependency_0.pcs_circuit_mod;
const protocol = dependency_0.protocol;
const sample_point_layout = dependency_0.sample_point_layout;
const std = dependency_0.std;
const take = dependency_0.take;
const trace_merkle = dependency_0.trace_merkle;
const validateDigest = dependency_0.validateDigest;
const validateM31 = dependency_0.validateM31;
const validateQm31 = dependency_0.validateQm31;

/// Immutable, independently replayed input authority for the universal FRI
/// verifier input and arithmetic rows. `init` accepts a pointer to the core
/// verifier's successful proof capture; the generic parameter deliberately
/// avoids coupling this leaf-owned bridge to one hash engine.
pub const Owned = struct {
    allocator: std.mem.Allocator,
    circuit: circuit_mod.Circuit,
    evaluation: circuit_mod.Evaluation,
    pcs_circuit: pcs_circuit_mod.Circuit,
    pcs_evaluation: pcs_circuit_mod.Evaluation,

    fold_widths: []u32,
    trace_tree_heights: []u32,
    column_log_sizes: [][]const u32,
    column_log_storage: []u32,
    sample_layouts: []sample_point_layout.Layout,
    trace_siblings: [][]const protocol.Digest,
    authenticated_values: [][]const QM31,
    fri_positions: [][]const M31,
    fri_offsets: [][]const M31,
    fri_layer_profiles: []fri_merkle.LayerProfile,
    fri_layer_openings: []fri_merkle.LayerOpening,
    fri_siblings: [][]const protocol.Digest,
    qm31_storage: []QM31,
    m31_storage: []M31,
    fri_opening_words: []M31,
    digest_storage: []protocol.Digest,

    sampled_values: []const QM31,
    queried_values: []const M31,
    deep_answers: []const QM31,
    fri_alphas: []const QM31,
    raw_queries: []const M31,
    last_layer_positions: []const M31,
    last_layer_coefficients: []const QM31,
    sampled_value_count: u32,
    queried_values_per_query: u32,
    interaction_pow_bits: u32,
    pcs_pow_bits: u32,
    claimed_sum_count: u32,
    trace_roots: []const protocol.Digest,
    fri_roots: []const protocol.Digest,
    composition_randomness: QM31,
    oods_seed: QM31,
    deep_randomness: QM31,

    pub fn init(
        allocator: std.mem.Allocator,
        config: ProfileConfig,
        capture: anytype,
    ) Error!Owned {
        const layers = capture.fri.layers;
        const query_count = capture.queries.raw.len;
        if (layers.len == 0 or query_count == 0 or
            capture.deep_answers.len != query_count or
            capture.queried_values.len % query_count != 0 or
            capture.commitments.len != capture.trace_paths.len or
            capture.commitments.len != capture.column_log_sizes.len or
            capture.sampled_points.len != capture.column_log_sizes.len or
            config.interaction_pow_bits >= m31.Modulus or
            config.pcs_pow_bits >= m31.Modulus or
            config.claimed_sum_count == 0 or
            config.claimed_sum_count >= m31.Modulus)
        {
            return error.CaptureShapeMismatch;
        }
        const sampled_value_count = std.math.cast(
            u32,
            capture.sampled_values.len,
        ) orelse return error.ArithmeticOverflow;
        const queried_values_per_query = std.math.cast(
            u32,
            capture.queried_values.len / query_count,
        ) orelse return error.ArithmeticOverflow;
        if (sampled_value_count == 0 or sampled_value_count >= m31.Modulus or
            queried_values_per_query == 0 or queried_values_per_query >= m31.Modulus)
        {
            return error.CaptureShapeMismatch;
        }

        try validateQm31(capture.composition_randomness);
        try validateQm31(capture.oods_seed);
        try validateQm31(capture.deep_randomness);

        const fold_widths = try allocator.alloc(u32, layers.len);
        errdefer allocator.free(fold_widths);
        if (capture.trace_paths.len == 0) return error.CaptureShapeMismatch;
        const trace_tree_heights = try allocator.alloc(u32, capture.trace_paths.len);
        errdefer allocator.free(trace_tree_heights);
        const column_log_sizes = try allocator.alloc(
            []const u32,
            capture.column_log_sizes.len,
        );
        errdefer allocator.free(column_log_sizes);
        var column_log_count: usize = 0;
        var nested_sample_count: usize = 0;
        var trace_sibling_count: usize = 0;
        for (
            capture.trace_paths,
            capture.column_log_sizes,
            capture.sampled_points,
            trace_tree_heights,
        ) |path, logs, point_columns, *height| {
            if (path.path_depth == 0 or logs.len == 0 or
                point_columns.len != logs.len or
                path.positions.len != query_count or
                path.siblings.len != try multiply(query_count, path.path_depth))
            {
                return error.CaptureShapeMismatch;
            }
            var maximum_log: u32 = 0;
            for (logs) |log_size| {
                if (log_size == 0 or log_size > path.path_depth)
                    return error.CaptureShapeMismatch;
                maximum_log = @max(maximum_log, log_size);
            }
            if (maximum_log != path.path_depth)
                return error.CaptureShapeMismatch;
            height.* = path.path_depth;
            column_log_count = try add(column_log_count, logs.len);
            for (point_columns) |points|
                nested_sample_count = try add(nested_sample_count, points.len);
            trace_sibling_count = try add(trace_sibling_count, path.siblings.len);
        }
        if (nested_sample_count != capture.sampled_values.len)
            return error.CaptureShapeMismatch;
        const column_log_storage = try allocator.alloc(u32, column_log_count);
        errdefer allocator.free(column_log_storage);
        const sample_layouts = try allocator.alloc(
            sample_point_layout.Layout,
            column_log_count,
        );
        errdefer allocator.free(sample_layouts);
        var column_log_cursor: usize = 0;
        for (capture.column_log_sizes, column_log_sizes) |source, *destination| {
            destination.* = take(u32, column_log_storage, &column_log_cursor, source.len);
            @memcpy(@constCast(destination.*), source);
        }
        std.debug.assert(column_log_cursor == column_log_storage.len);
        const trace_siblings = try allocator.alloc(
            []const protocol.Digest,
            capture.trace_paths.len,
        );
        errdefer allocator.free(trace_siblings);
        const authenticated_values = try allocator.alloc([]const QM31, layers.len);
        errdefer allocator.free(authenticated_values);
        const fri_positions = try allocator.alloc([]const M31, layers.len);
        errdefer allocator.free(fri_positions);
        const fri_offsets = try allocator.alloc([]const M31, layers.len);
        errdefer allocator.free(fri_offsets);
        const fri_layer_profiles = try allocator.alloc(
            fri_merkle.LayerProfile,
            layers.len,
        );
        errdefer allocator.free(fri_layer_profiles);
        const fri_layer_openings = try allocator.alloc(
            fri_merkle.LayerOpening,
            layers.len,
        );
        errdefer allocator.free(fri_layer_openings);
        const fri_siblings = try allocator.alloc(
            []const protocol.Digest,
            layers.len,
        );
        errdefer allocator.free(fri_siblings);

        var qm31_count = try add(capture.sampled_values.len, capture.deep_answers.len);
        qm31_count = try add(qm31_count, layers.len);
        qm31_count = try add(qm31_count, capture.last_layer_coefficients.len);
        var fri_opening_word_count: usize = 0;
        var digest_count = try add(capture.commitments.len, layers.len);
        digest_count = try add(digest_count, trace_sibling_count);
        for (layers) |layer| {
            if (layer.query_count != query_count or
                layer.positions.len != query_count or
                layer.fold_width == 0 or
                layer.values.len != try multiply(query_count, layer.fold_width) or
                layer.siblings.len != try multiply(query_count, layer.path_depth))
            {
                return error.CaptureShapeMismatch;
            }
            qm31_count = try add(qm31_count, layer.values.len);
            fri_opening_word_count = try add(
                fri_opening_word_count,
                try multiply(layer.values.len, fri_merkle.SECURE_WORD_COUNT),
            );
            digest_count = try add(digest_count, layer.siblings.len);
        }
        const layer_position_count = try multiply(layers.len, query_count);
        const m31_count = try add(
            capture.queried_values.len,
            try add(
                try multiply(query_count, 2),
                try multiply(layer_position_count, 2),
            ),
        );
        const qm31_storage = try allocator.alloc(QM31, qm31_count);
        errdefer allocator.free(qm31_storage);
        const m31_storage = try allocator.alloc(M31, m31_count);
        errdefer allocator.free(m31_storage);
        const fri_opening_words = try allocator.alloc(M31, fri_opening_word_count);
        errdefer allocator.free(fri_opening_words);
        const digest_storage = try allocator.alloc(protocol.Digest, digest_count);
        errdefer allocator.free(digest_storage);

        var qm31_cursor: usize = 0;
        const sampled_values = take(
            QM31,
            qm31_storage,
            &qm31_cursor,
            capture.sampled_values.len,
        );
        @memcpy(@constCast(sampled_values), capture.sampled_values);
        const deep_answers = take(QM31, qm31_storage, &qm31_cursor, capture.deep_answers.len);
        @memcpy(@constCast(deep_answers), capture.deep_answers);
        for (layers, 0..) |layer, layer_index| {
            fold_widths[layer_index] = layer.fold_width;
            authenticated_values[layer_index] = take(
                QM31,
                qm31_storage,
                &qm31_cursor,
                layer.values.len,
            );
            @memcpy(@constCast(authenticated_values[layer_index]), layer.values);
        }
        const fri_alphas = take(QM31, qm31_storage, &qm31_cursor, layers.len);
        for (layers, @constCast(fri_alphas)) |layer, *alpha|
            alpha.* = layer.folding_alpha;
        const last_layer_coefficients = take(
            QM31,
            qm31_storage,
            &qm31_cursor,
            capture.last_layer_coefficients.len,
        );
        @memcpy(@constCast(last_layer_coefficients), capture.last_layer_coefficients);
        std.debug.assert(qm31_cursor == qm31_storage.len);

        var opening_cursor: usize = 0;
        var digest_cursor: usize = 0;
        const trace_roots = take(
            protocol.Digest,
            digest_storage,
            &digest_cursor,
            capture.commitments.len,
        );
        for (capture.commitments, @constCast(trace_roots)) |source, *destination| {
            destination.* = source;
            try validateDigest(destination.*);
        }
        const fri_roots = take(
            protocol.Digest,
            digest_storage,
            &digest_cursor,
            layers.len,
        );
        for (layers, @constCast(fri_roots)) |layer, *destination| {
            destination.* = layer.commitment;
            try validateDigest(destination.*);
        }
        for (capture.trace_paths, trace_siblings) |path, *destination| {
            destination.* = take(
                protocol.Digest,
                digest_storage,
                &digest_cursor,
                path.siblings.len,
            );
            for (path.siblings, @constCast(destination.*)) |source, *target| {
                target.* = source;
                try validateDigest(target.*);
            }
        }
        for (layers, 0..) |layer, layer_index| {
            const fold_step = std.math.log2_int(u32, layer.fold_width);
            const leaf_log_size: u32 = if (fold_step > 1)
                @min(fold_step, std.math.log2_int(u32, fri_merkle.PACKED_LEAF_SIZE))
            else
                0;
            const subtree_height = fold_step - leaf_log_size;
            fri_layer_profiles[layer_index] = .{
                .width = layer.fold_width,
                .tree_height = std.math.add(
                    u32,
                    layer.path_depth,
                    subtree_height,
                ) catch return error.ArithmeticOverflow,
            };
            const word_count = try multiply(
                layer.values.len,
                fri_merkle.SECURE_WORD_COUNT,
            );
            const words = take(
                M31,
                fri_opening_words,
                &opening_cursor,
                word_count,
            );
            const mutable_words = @constCast(words);
            for (layer.values, 0..) |value, value_index| {
                mutable_words[value_index * fri_merkle.SECURE_WORD_COUNT ..][0..fri_merkle.SECURE_WORD_COUNT].* = value.toM31Array();
            }
            fri_layer_openings[layer_index] = .{
                .width = layer.fold_width,
                .values = words,
            };
            fri_siblings[layer_index] = take(
                protocol.Digest,
                digest_storage,
                &digest_cursor,
                layer.siblings.len,
            );
            for (layer.siblings, @constCast(fri_siblings[layer_index])) |
                source,
                *destination,
            | {
                destination.* = source;
                try validateDigest(destination.*);
            }
        }
        std.debug.assert(opening_cursor == fri_opening_words.len);
        std.debug.assert(digest_cursor == digest_storage.len);

        var m31_cursor: usize = 0;
        const queried_values = take(
            M31,
            m31_storage,
            &m31_cursor,
            capture.queried_values.len,
        );
        for (capture.queried_values, @constCast(queried_values)) |source, *destination| {
            try validateM31(source);
            destination.* = source;
        }
        const raw_queries = take(M31, m31_storage, &m31_cursor, query_count);
        for (capture.queries.raw, @constCast(raw_queries)) |position, *destination|
            destination.* = try canonicalPosition(position);

        var consumed_folds: u32 = 0;
        for (layers, 0..) |layer, layer_index| {
            const width: usize = @intCast(layer.fold_width);
            if (!std.math.isPowerOfTwo(width)) return error.CaptureShapeMismatch;
            const expected_step = std.math.log2_int(usize, width);
            if (layer.fold_step != expected_step)
                return error.CaptureShapeMismatch;
            fri_positions[layer_index] = take(
                M31,
                m31_storage,
                &m31_cursor,
                query_count,
            );
            fri_offsets[layer_index] = take(
                M31,
                m31_storage,
                &m31_cursor,
                query_count,
            );
            for (
                layer.positions,
                @constCast(fri_positions[layer_index]),
                @constCast(fri_offsets[layer_index]),
            ) |position, *position_out, *offset_out| {
                position_out.* = try canonicalPosition(position);
                offset_out.* = M31.fromCanonical(@intCast(position & (width - 1)));
            }
            consumed_folds = std.math.add(
                u32,
                consumed_folds,
                layer.fold_step,
            ) catch return error.ArithmeticOverflow;
        }
        const last_layer_positions = take(
            M31,
            m31_storage,
            &m31_cursor,
            query_count,
        );
        for (capture.queries.raw, @constCast(last_layer_positions)) |
            position,
            *destination,
        | destination.* = try canonicalPosition(position >> @intCast(consumed_folds));
        std.debug.assert(m31_cursor == m31_storage.len);

        const lifting_log_size = std.math.add(
            u32,
            layers[0].path_depth,
            layers[0].fold_step,
        ) catch return error.ArithmeticOverflow;
        const mask_log_size = std.math.sub(
            u32,
            lifting_log_size,
            config.log_blowup_factor,
        ) catch return error.CaptureShapeMismatch;
        if (mask_log_size == 0) return error.CaptureShapeMismatch;
        const current_point = circle.secureFieldPointFromRandomSeedChecked(
            capture.oods_seed,
        ) catch return error.CaptureShapeMismatch;
        const previous_step = canonic.CanonicCoset.new(mask_log_size).step();
        const previous_point = current_point.sub(.{
            .x = QM31.fromBase(previous_step.x),
            .y = QM31.fromBase(previous_step.y),
        });
        var sample_layout_cursor: usize = 0;
        for (capture.sampled_points) |point_columns| {
            for (point_columns) |points| {
                sample_layouts[sample_layout_cursor] = try sample_point_layout.classifyColumn(
                    points,
                    current_point,
                    previous_point,
                );
                sample_layout_cursor += 1;
            }
        }
        if (sample_layout_cursor != sample_layouts.len)
            return error.CaptureShapeMismatch;
        for (capture.trace_paths, trace_tree_heights) |path, tree_height| {
            for (capture.queries.raw, path.positions) |raw_position, actual_position| {
                if (actual_position != mapTreeQueryPosition(
                    raw_position,
                    lifting_log_size,
                    tree_height,
                )) return error.PositionNotCanonical;
            }
        }
        const profile = circuit_mod.Profile{
            .lifting_log_size = lifting_log_size,
            .log_blowup_factor = config.log_blowup_factor,
            .log_last_layer_degree_bound = config.log_last_layer_degree_bound,
            .fold_widths = fold_widths,
            .query_count = std.math.cast(u32, query_count) orelse
                return error.ArithmeticOverflow,
        };
        if (std.process.hasEnvVarConstant(STAGE_TELEMETRY_ENV)) {
            std.debug.print(
                "  captured-fri profile: lifting_log={d} trees={d} columns={d} " ++
                    "samples={d} queried_per_query={d} fri_layers={d} queries={d}\n",
                .{
                    lifting_log_size,
                    column_log_sizes.len,
                    column_log_count,
                    sampled_values.len,
                    queried_values_per_query,
                    layers.len,
                    query_count,
                },
            );
        }
        profile.validate() catch |err| {
            captureStageFailure("fri-profile", err);
            return err;
        };
        var circuit = circuit_mod.build(allocator, profile) catch |err| {
            captureStageFailure("fri-build", err);
            return err;
        };
        errdefer circuit.deinit();
        const witness_value = circuit_mod.Witness{
            .active = true,
            .deep_answers = deep_answers,
            .authenticated_values = authenticated_values,
            .fri_alphas = fri_alphas,
            .raw_queries = raw_queries,
            .fri_positions = fri_positions,
            .fri_offsets = fri_offsets,
            .last_layer_positions = last_layer_positions,
            .last_layer_coefficients = last_layer_coefficients,
        };
        var evaluation = circuit.evaluate(allocator, witness_value) catch |err| {
            captureStageFailure("fri-evaluate", err);
            return err;
        };
        errdefer evaluation.deinit();
        evaluation.validateAgainst(&circuit) catch |err| {
            captureStageFailure("fri-revalidate", err);
            return err;
        };

        const pcs_trees = try allocator.alloc(
            pcs_circuit_mod.TreeProfile,
            column_log_sizes.len,
        );
        defer allocator.free(pcs_trees);
        for (column_log_sizes, pcs_trees) |logs, *tree|
            tree.* = .{ .column_log_sizes = logs };
        const pcs_profile = pcs_circuit_mod.Profile{
            .trees = pcs_trees,
            .sample_layouts = sample_layouts,
            .lifting_log_size = lifting_log_size,
            .log_blowup_factor = config.log_blowup_factor,
            .query_count = @intCast(query_count),
        };
        if (std.process.hasEnvVarConstant(STAGE_TELEMETRY_ENV)) {
            std.debug.print(
                "  captured-fri PCS profile: columns={d} samples={d} terms={d} " ++
                    "inputs={d} queried_values={d}\n",
                .{
                    pcs_profile.columnCount() catch 0,
                    pcs_profile.sampleCount() catch 0,
                    pcs_profile.termCount() catch 0,
                    pcs_profile.inputCount() catch 0,
                    queried_values.len,
                },
            );
        }
        pcs_profile.validate() catch |err| {
            captureStageFailure("pcs-profile", err);
            return err;
        };
        var pcs_circuit = pcs_circuit_mod.build(allocator, pcs_profile) catch |err| {
            captureStageFailure("pcs-build", err);
            return err;
        };
        errdefer pcs_circuit.deinit();
        var pcs_evaluation = pcs_circuit.evaluate(allocator, .{
            .active = true,
            .sampled_values = sampled_values,
            .queried_values = queried_values,
            .oods_seed = capture.oods_seed,
            .deep_randomness = capture.deep_randomness,
            .raw_queries = raw_queries,
            .answers = deep_answers,
        }) catch |err| {
            captureStageFailure("pcs-evaluate", err);
            return err;
        };
        errdefer pcs_evaluation.deinit();
        pcs_evaluation.validateAgainst(&pcs_circuit) catch |err| {
            captureStageFailure("pcs-revalidate", err);
            return err;
        };

        return .{
            .allocator = allocator,
            .circuit = circuit,
            .evaluation = evaluation,
            .pcs_circuit = pcs_circuit,
            .pcs_evaluation = pcs_evaluation,
            .fold_widths = fold_widths,
            .trace_tree_heights = trace_tree_heights,
            .column_log_sizes = column_log_sizes,
            .column_log_storage = column_log_storage,
            .sample_layouts = sample_layouts,
            .trace_siblings = trace_siblings,
            .authenticated_values = authenticated_values,
            .fri_positions = fri_positions,
            .fri_offsets = fri_offsets,
            .fri_layer_profiles = fri_layer_profiles,
            .fri_layer_openings = fri_layer_openings,
            .fri_siblings = fri_siblings,
            .qm31_storage = qm31_storage,
            .m31_storage = m31_storage,
            .fri_opening_words = fri_opening_words,
            .digest_storage = digest_storage,
            .sampled_values = sampled_values,
            .queried_values = queried_values,
            .deep_answers = deep_answers,
            .fri_alphas = fri_alphas,
            .raw_queries = raw_queries,
            .last_layer_positions = last_layer_positions,
            .last_layer_coefficients = last_layer_coefficients,
            .sampled_value_count = sampled_value_count,
            .queried_values_per_query = queried_values_per_query,
            .interaction_pow_bits = config.interaction_pow_bits,
            .pcs_pow_bits = config.pcs_pow_bits,
            .claimed_sum_count = config.claimed_sum_count,
            .trace_roots = trace_roots,
            .fri_roots = fri_roots,
            .composition_randomness = capture.composition_randomness,
            .oods_seed = capture.oods_seed,
            .deep_randomness = capture.deep_randomness,
        };
    }

    pub fn deinit(self: *Owned) void {
        self.pcs_evaluation.deinit();
        self.pcs_circuit.deinit();
        self.evaluation.deinit();
        self.circuit.deinit();
        self.allocator.free(self.digest_storage);
        self.allocator.free(self.fri_opening_words);
        self.allocator.free(self.m31_storage);
        self.allocator.free(self.qm31_storage);
        self.allocator.free(self.fri_siblings);
        self.allocator.free(self.fri_layer_openings);
        self.allocator.free(self.fri_layer_profiles);
        self.allocator.free(self.fri_offsets);
        self.allocator.free(self.fri_positions);
        self.allocator.free(self.authenticated_values);
        self.allocator.free(self.trace_siblings);
        self.allocator.free(self.sample_layouts);
        self.allocator.free(self.column_log_storage);
        self.allocator.free(self.column_log_sizes);
        self.allocator.free(self.trace_tree_heights);
        self.allocator.free(self.fold_widths);
        self.* = undefined;
    }

    pub fn witness(self: *const Owned) circuit_mod.Witness {
        return .{
            .active = true,
            .deep_answers = self.deep_answers,
            .authenticated_values = self.authenticated_values,
            .fri_alphas = self.fri_alphas,
            .raw_queries = self.raw_queries,
            .fri_positions = self.fri_positions,
            .fri_offsets = self.fri_offsets,
            .last_layer_positions = self.last_layer_positions,
            .last_layer_coefficients = self.last_layer_coefficients,
        };
    }

    pub fn friMerkleReference(self: *const Owned) Error!fri_merkle.Reference {
        const lane = fri_merkle.LaneProfile{
            .query_count = self.circuit.query_count,
            .lifting_log_size = self.circuit.lifting_log_size,
            .layers = self.fri_layer_profiles,
        };
        return fri_merkle.Reference.seal(lane, lane);
    }

    pub fn friOpeningWitness(self: *const Owned) fri_merkle.OpeningWitness {
        return .{ .segment_leaf = .{
            .raw_queries = self.raw_queries,
            .layers = self.fri_layer_openings,
        } };
    }

    pub fn merkleRootReference(self: *const Owned) Error!merkle_root.Reference {
        const lane = merkle_root.LaneProfile{
            .query_count = self.circuit.query_count,
            .trace_tree_count = @intCast(self.trace_roots.len),
            .fri_layer_count = @intCast(self.fri_roots.len),
        };
        return merkle_root.Reference.seal(lane, lane);
    }

    pub fn merkleRootWitness(self: *const Owned) merkle_root.RootWitness {
        return .{ .segment_leaf = .{
            .trace = self.trace_roots,
            .fri = self.fri_roots,
        } };
    }

    pub fn traceOpeningWitness(self: *const Owned) trace_merkle.OpeningWitness {
        return .{ .segment_leaf = .{
            .queried_values = self.queried_values,
            .raw_queries = self.raw_queries,
        } };
    }

    /// Builds the exact inactive-lane evaluation without retaining a second
    /// copy of the large input witness. Temporary zero arenas are released as
    /// soon as the circuit has produced its owned node evaluation.
    pub fn evaluateInactive(self: *const Owned) Error!circuit_mod.Evaluation {
        const zero_qm31 = try self.allocator.alloc(
            QM31,
            self.qm31_storage.len - self.sampled_values.len,
        );
        defer self.allocator.free(zero_qm31);
        @memset(zero_qm31, QM31.zero());
        const zero_m31 = try self.allocator.alloc(
            M31,
            self.m31_storage.len - self.queried_values.len,
        );
        defer self.allocator.free(zero_m31);
        @memset(zero_m31, M31.zero());

        var authenticated_values: [circuit_mod.MAX_FRI_LAYERS][]const QM31 = undefined;
        var fri_positions: [circuit_mod.MAX_FRI_LAYERS][]const M31 = undefined;
        var fri_offsets: [circuit_mod.MAX_FRI_LAYERS][]const M31 = undefined;
        var qm31_cursor: usize = 0;
        const deep_answers = take(
            QM31,
            zero_qm31,
            &qm31_cursor,
            self.deep_answers.len,
        );
        for (self.authenticated_values, 0..) |values, index|
            authenticated_values[index] = take(
                QM31,
                zero_qm31,
                &qm31_cursor,
                values.len,
            );
        const fri_alphas = take(
            QM31,
            zero_qm31,
            &qm31_cursor,
            self.fri_alphas.len,
        );
        const last_layer_coefficients = take(
            QM31,
            zero_qm31,
            &qm31_cursor,
            self.last_layer_coefficients.len,
        );
        std.debug.assert(qm31_cursor == zero_qm31.len);

        var m31_cursor: usize = 0;
        const raw_queries = take(
            M31,
            zero_m31,
            &m31_cursor,
            self.raw_queries.len,
        );
        for (self.fri_positions, 0..) |positions, index| {
            fri_positions[index] = take(
                M31,
                zero_m31,
                &m31_cursor,
                positions.len,
            );
            fri_offsets[index] = take(
                M31,
                zero_m31,
                &m31_cursor,
                self.fri_offsets[index].len,
            );
        }
        const last_layer_positions = take(
            M31,
            zero_m31,
            &m31_cursor,
            self.last_layer_positions.len,
        );
        std.debug.assert(m31_cursor == zero_m31.len);

        return self.circuit.evaluate(self.allocator, .{
            .active = false,
            .deep_answers = deep_answers,
            .authenticated_values = authenticated_values[0..self.authenticated_values.len],
            .fri_alphas = fri_alphas,
            .raw_queries = raw_queries,
            .fri_positions = fri_positions[0..self.fri_positions.len],
            .fri_offsets = fri_offsets[0..self.fri_offsets.len],
            .last_layer_positions = last_layer_positions,
            .last_layer_coefficients = last_layer_coefficients,
        });
    }

    pub fn evaluatePcsInactive(self: *const Owned) Error!pcs_circuit_mod.Evaluation {
        return self.pcs_circuit.evaluateInactive(self.allocator);
    }
};
