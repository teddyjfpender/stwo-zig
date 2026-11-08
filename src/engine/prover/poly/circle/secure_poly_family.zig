const std = @import("std");
const circle = @import("stwo_core").circle;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const domain_mod = @import("stwo_core").poly.circle.domain;
const poly = @import("poly.zig");
const eval_mod = @import("evaluation.zig");
const secure_column = @import("../../secure_column.zig");
const twiddles_mod = @import("../twiddles.zig");
const work_profile = @import("stwo_prover_api").work_profile;

const M31 = m31.M31;
const CircleDomain = domain_mod.CircleDomain;
const CircleCoefficients = poly.CircleCoefficients;
const WorkRecorder = work_profile.Recorder(true);

pub fn ForField(comptime Secure: type) type {
    return struct {
        const QM31 = Secure;
        const DEGREE = @typeInfo(@TypeOf(Secure.zero().toM31Array())).array.len;
        const CirclePointQM31 = circle.CirclePoint(Secure);
        const SecureColumnByCoords = secure_column.SecureColumnByCoordsFor(Secure);
        pub const SecurePolyError = error{
            ShapeMismatch,
        };

        pub const SecureCirclePoly = struct {
            polys: [DEGREE]CircleCoefficients,

            pub fn init(
                polys: [DEGREE]CircleCoefficients,
            ) (SecurePolyError || poly.PolyError)!SecureCirclePoly {
                const log_size = polys[0].logSize();
                for (polys[1..]) |coord| {
                    if (coord.logSize() != log_size) return SecurePolyError.ShapeMismatch;
                }
                return .{ .polys = polys };
            }

            pub fn deinit(self: *SecureCirclePoly, allocator: std.mem.Allocator) void {
                for (&self.polys) |*coord| {
                    coord.deinit(allocator);
                }
                self.* = undefined;
            }

            pub fn evalColumnsAtPoint(
                self: SecureCirclePoly,
                point: CirclePointQM31,
            ) [DEGREE]QM31 {
                var out: [DEGREE]QM31 = undefined;
                for (self.polys, 0..) |coordinate, i| out[i] = coordinate.evalAtPointFor(Secure, point);
                return out;
            }

            pub fn evalAtPoint(self: SecureCirclePoly, point: CirclePointQM31) QM31 {
                return QM31.fromPartialEvals(self.evalColumnsAtPoint(point));
            }

            pub fn logSize(self: SecureCirclePoly) u32 {
                return self.polys[0].logSize();
            }

            pub fn intoCoordinatePolys(self: SecureCirclePoly) [DEGREE]CircleCoefficients {
                return self.polys;
            }

            pub const SplitPair = struct {
                left: SecureCirclePoly,
                right: SecureCirclePoly,

                pub fn deinit(self: *SplitPair, allocator: std.mem.Allocator) void {
                    self.left.deinit(allocator);
                    self.right.deinit(allocator);
                    self.* = undefined;
                }
            };

            pub const SplitChunks = struct {
                chunks: []SecureCirclePoly,

                pub fn deinit(self: *SplitChunks, allocator: std.mem.Allocator) void {
                    for (self.chunks) |*chunk| chunk.deinit(allocator);
                    allocator.free(self.chunks);
                    self.* = undefined;
                }
            };

            /// Splits each coordinate coefficient vector into `2^depth` contiguous
            /// chunks. Chunk order is the recursive left-to-right split order used by
            /// the composition OODS reconstruction.
            pub fn splitIntoChunks(
                self: SecureCirclePoly,
                allocator: std.mem.Allocator,
                depth: u32,
            ) (std.mem.Allocator.Error || SecurePolyError || poly.PolyError)!SplitChunks {
                if (depth == 0 or depth >= self.logSize()) {
                    return SecurePolyError.ShapeMismatch;
                }
                if (depth >= @bitSizeOf(usize)) return SecurePolyError.ShapeMismatch;
                const chunk_count = @as(usize, 1) << @intCast(depth);
                const coefficient_count = self.polys[0].coefficients().len;
                const chunk_len = coefficient_count / chunk_count;
                if (chunk_len == 0) return SecurePolyError.ShapeMismatch;

                const chunks = try allocator.alloc(SecureCirclePoly, chunk_count);
                var initialized: usize = 0;
                errdefer {
                    for (chunks[0..initialized]) |*chunk| chunk.deinit(allocator);
                    allocator.free(chunks);
                }

                for (chunks, 0..) |*chunk, chunk_index| {
                    var coordinates: [DEGREE]CircleCoefficients = undefined;
                    var coordinate_count: usize = 0;
                    errdefer {
                        for (coordinates[0..coordinate_count]) |*coordinate| {
                            coordinate.deinit(allocator);
                        }
                    }
                    const start = chunk_index * chunk_len;
                    for (&coordinates, self.polys) |*coordinate, source| {
                        coordinate.* = try CircleCoefficients.initOwned(
                            try allocator.dupe(
                                M31,
                                source.coefficients()[start .. start + chunk_len],
                            ),
                        );
                        coordinate_count += 1;
                    }
                    chunk.* = try SecureCirclePoly.init(coordinates);
                    initialized += 1;
                }
                return .{ .chunks = chunks };
            }

            pub fn splitAtMid(
                self: SecureCirclePoly,
                allocator: std.mem.Allocator,
            ) (std.mem.Allocator.Error || SecurePolyError || poly.PolyError)!SplitPair {
                var left_polys: [DEGREE]CircleCoefficients = undefined;
                var right_polys: [DEGREE]CircleCoefficients = undefined;
                var initialized: usize = 0;
                errdefer {
                    var i: usize = 0;
                    while (i < initialized) : (i += 1) {
                        left_polys[i].deinit(allocator);
                        right_polys[i].deinit(allocator);
                    }
                }

                for (self.polys, 0..) |coord, i| {
                    const split = try coord.splitAtMid(allocator);
                    left_polys[i] = split.left;
                    right_polys[i] = split.right;
                    initialized += 1;
                }

                return .{
                    .left = try SecureCirclePoly.init(left_polys),
                    .right = try SecureCirclePoly.init(right_polys),
                };
            }
        };

        pub fn interpolateFromEvaluation(
            allocator: std.mem.Allocator,
            domain: CircleDomain,
            values: *const SecureColumnByCoords,
        ) !SecureCirclePoly {
            var twiddle_tree_owned = try twiddles_mod.precomputeM31(allocator, domain.half_coset);
            defer twiddles_mod.deinitM31(allocator, &twiddle_tree_owned);
            return interpolateFromEvaluationWithTwiddles(
                allocator,
                domain,
                values,
                .{
                    .root_coset = twiddle_tree_owned.root_coset,
                    .twiddles = twiddle_tree_owned.twiddles,
                    .itwiddles = twiddle_tree_owned.itwiddles,
                },
            );
        }

        /// Interpolates and splits an evaluation, with a direct path for constant
        /// secure-field columns. A constant polynomial has only coefficient zero in
        /// the left half and an all-zero right half.
        pub fn interpolateAndSplitFromEvaluation(
            allocator: std.mem.Allocator,
            domain: CircleDomain,
            values: *SecureColumnByCoords,
        ) !SecureCirclePoly.SplitPair {
            var twiddle_tree_owned = try twiddles_mod.precomputeM31(allocator, domain.half_coset);
            defer twiddles_mod.deinitM31(allocator, &twiddle_tree_owned);
            return interpolateAndSplitFromEvaluationWithTwiddles(
                allocator,
                domain,
                values,
                .{
                    .root_coset = twiddle_tree_owned.root_coset,
                    .twiddles = twiddle_tree_owned.twiddles,
                    .itwiddles = twiddle_tree_owned.itwiddles,
                },
            );
        }

        pub fn interpolateAndSplitFromEvaluationWithTwiddles(
            allocator: std.mem.Allocator,
            domain: CircleDomain,
            values: *SecureColumnByCoords,
            twiddle_tree: twiddles_mod.TwiddleTree([]const M31),
        ) !SecureCirclePoly.SplitPair {
            return interpolateAndSplitFromEvaluationWithTwiddlesForBackend(
                void,
                allocator,
                domain,
                values,
                twiddle_tree,
            );
        }

        /// Backend-scoped secure interpolation. An accelerator is selected from the
        /// proof's backend type instead of process-global mutable state.
        pub fn interpolateAndSplitFromEvaluationWithTwiddlesForBackend(
            comptime B: type,
            allocator: std.mem.Allocator,
            domain: CircleDomain,
            values: *SecureColumnByCoords,
            twiddle_tree: twiddles_mod.TwiddleTree([]const M31),
        ) !SecureCirclePoly.SplitPair {
            return interpolateAndSplitFromEvaluationWithTwiddlesForBackendAndWorkRecorder(
                B,
                allocator,
                domain,
                values,
                twiddle_tree,
                null,
            );
        }

        pub fn interpolateAndSplitFromEvaluationWithTwiddlesForBackendAndWorkRecorder(
            comptime B: type,
            allocator: std.mem.Allocator,
            domain: CircleDomain,
            values: *SecureColumnByCoords,
            twiddle_tree: twiddles_mod.TwiddleTree([]const M31),
            work_recorder: ?*WorkRecorder,
        ) !SecureCirclePoly.SplitPair {
            if (domain.size() != values.len() or values.len() < 2) return SecurePolyError.ShapeMismatch;

            const already_coefficients = values.representation == .coefficients;
            if (already_coefficients) {
                var result = try splitCoefficientColumnsBorrowed(values);
                errdefer result.deinit(allocator);
                try recordSecureInterpolation(work_recorder, null);
                return result;
            }

            if (comptime B != void and (Secure == @import("stwo_core").fields.qm31.QM31 and @hasDecl(B, "interpolateSecureComposition"))) {
                const dispatch: work_profile.M31InterpolationBackendResult =
                    try B.interpolateSecureComposition(
                        allocator,
                        values,
                        domain,
                        twiddle_tree,
                    );
                try dispatch.validate();
                switch (dispatch) {
                    .declined => {
                        if (values.representation != .evaluations)
                            return SecurePolyError.ShapeMismatch;
                    },
                    .already_coefficients => return SecurePolyError.ShapeMismatch,
                    .transformed => |execution| {
                        try validateSecureExecution(execution, domain.logSize());
                        if (values.representation != .coefficients)
                            return SecurePolyError.ShapeMismatch;
                        var result = try splitCoefficientColumnsBorrowed(values);
                        errdefer result.deinit(allocator);
                        try recordSecureInterpolation(work_recorder, execution);
                        return result;
                    },
                }
            }

            if (!evaluationIsConstant(values)) {
                var polynomial = try interpolateFromEvaluationWithTwiddles(
                    allocator,
                    domain,
                    values,
                    twiddle_tree,
                );
                defer polynomial.deinit(allocator);
                var result = try polynomial.splitAtMid(allocator);
                errdefer result.deinit(allocator);
                try recordSecureInterpolation(work_recorder, .{
                    .log_size = domain.logSize(),
                    .column_count = DEGREE,
                    .batch_count = DEGREE,
                });
                return result;
            }

            const half_len = values.len() / 2;
            var left_polys: [DEGREE]CircleCoefficients = undefined;
            var right_polys: [DEGREE]CircleCoefficients = undefined;
            var initialized: usize = 0;
            errdefer {
                for (0..initialized) |coordinate| {
                    left_polys[coordinate].deinit(allocator);
                    right_polys[coordinate].deinit(allocator);
                }
            }

            for (0..DEGREE) |coordinate| {
                const left = try allocator.alloc(M31, half_len);
                errdefer allocator.free(left);
                @memset(left, M31.zero());
                left[0] = values.columns[coordinate][0];
                const right = try allocator.alloc(M31, half_len);
                errdefer allocator.free(right);
                @memset(right, M31.zero());
                left_polys[coordinate] = try CircleCoefficients.initOwned(left);
                right_polys[coordinate] = try CircleCoefficients.initOwned(right);
                initialized += 1;
            }

            var result = SecureCirclePoly.SplitPair{
                .left = try SecureCirclePoly.init(left_polys),
                .right = try SecureCirclePoly.init(right_polys),
            };
            initialized = 0;
            errdefer result.deinit(allocator);
            try recordSecureInterpolation(work_recorder, null);
            return result;
        }

        pub fn validateSecureExecution(
            execution: work_profile.M31InterpolationExecution,
            log_size: u32,
        ) !void {
            try execution.validate();
            if (execution.log_size != log_size or
                execution.column_count != DEGREE)
            {
                return error.InvalidCounterGroup;
            }
        }

        pub fn recordSecureInterpolation(
            recorder: ?*WorkRecorder,
            execution: ?work_profile.M31InterpolationExecution,
        ) !void {
            const active = recorder orelse return;
            const counters: work_profile.Counters = if (execution) |completed|
                try completed.exactWork()
            else
                .{};
            try active.recordCompletedDelta(.{
                .site = .secure_composition_interpolation_fft,
                .producer = work_profile.boundaryForSite(.secure_composition_interpolation_fft),
                .source_mask = .{ .bits = work_profile.SourceMask.one(.field_additions).bits |
                    work_profile.SourceMask.one(.field_multiplications).bits |
                    work_profile.SourceMask.one(.field_inversions).bits |
                    work_profile.SourceMask.one(.fft_butterflies).bits },
                .counters = counters,
            });
            // work-profile-complete:secure-composition-interpolation-fft
        }

        fn splitCoefficientColumnsBorrowed(
            values: *const SecureColumnByCoords,
        ) !SecureCirclePoly.SplitPair {
            if (values.representation != .coefficients) return SecurePolyError.ShapeMismatch;
            const half_len = values.len() / 2;
            var left_polys: [DEGREE]CircleCoefficients = undefined;
            var right_polys: [DEGREE]CircleCoefficients = undefined;
            for (values.columns, 0..) |column, coordinate| {
                left_polys[coordinate] = try CircleCoefficients.initBorrowed(column[0..half_len]);
                right_polys[coordinate] = try CircleCoefficients.initBorrowed(column[half_len..]);
            }
            return .{
                .left = try SecureCirclePoly.init(left_polys),
                .right = try SecureCirclePoly.init(right_polys),
            };
        }

        fn evaluationIsConstant(values: *const SecureColumnByCoords) bool {
            for (values.columns) |column| {
                const first = column[0];
                for (column[1..]) |value| {
                    if (!value.eql(first)) return false;
                }
            }
            return true;
        }
        pub fn interpolateFromEvaluationWithTwiddles(
            allocator: std.mem.Allocator,
            domain: CircleDomain,
            values: *const SecureColumnByCoords,
            twiddle_tree: twiddles_mod.TwiddleTree([]const M31),
        ) !SecureCirclePoly {
            if (domain.size() != values.len()) return SecurePolyError.ShapeMismatch;

            var coordinate_polys: [DEGREE]CircleCoefficients = undefined;
            var initialized: usize = 0;
            errdefer {
                var i: usize = 0;
                while (i < initialized) : (i += 1) coordinate_polys[i].deinit(allocator);
            }

            for (0..DEGREE) |i| {
                const evaluation = try eval_mod.CircleEvaluation.init(domain, values.columns[i]);
                coordinate_polys[i] = try poly.interpolateFromEvaluationWithTwiddles(
                    allocator,
                    evaluation,
                    twiddle_tree,
                );
                initialized += 1;
            }

            return SecureCirclePoly.init(coordinate_polys);
        }
    };
}
