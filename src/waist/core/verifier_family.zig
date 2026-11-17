const std = @import("std");
const diagnostic_codes = @import("error_codes.zig");
const circle = @import("circle.zig");
const m31 = @import("fields/m31.zig");
const line = @import("poly/line.zig");
const qm31 = @import("fields/qm31.zig");
const verifier_types = @import("verifier_types.zig");
const vcs_verifier = @import("vcs_lifted/verifier.zig");

const M31 = m31.M31;

const qm31_mod = @import("fields/qm31.zig");

pub fn ForField(comptime Secure: type) type {
    return struct {
        const QM31 = Secure;
        const CirclePointQM31 = circle.CirclePoint(Secure);
        const CM31 = Secure.InnerField;
        const air_accumulation = @import("air/accumulation.zig").ForField(Secure);
        const air_components = @import("air/components.zig").ForField(Secure);
        const fri = @import("fri.zig").ForField(Secure);
        const pcs = @import("pcs/mod.zig").ForField(Secure);
        const pcs_verifier = @import("pcs/verifier.zig").ForField(Secure);
        const proof_mod = @import("proof.zig").ForField(Secure);
        const MaskPoints = air_components.MaskPoints;
        const DEGREE = @typeInfo(@TypeOf(Secure.zero().toM31Array())).array.len;
        pub const PREPROCESSED_TRACE_IDX = verifier_types.PREPROCESSED_TRACE_IDX;
        pub const COMPOSITION_LOG_SPLIT = verifier_types.COMPOSITION_LOG_SPLIT;
        pub const VerificationError = verifier_types.VerificationError;
        pub const QueryCapture = pcs_verifier.QueryCapture;
        pub const ProofCapture = pcs_verifier.VerifiedProofCapture;

        pub fn verify(
            comptime H: type,
            comptime MC: type,
            allocator: std.mem.Allocator,
            component_list: []const air_components.Component,
            channel: anytype,
            commitment_scheme: *pcs_verifier.CommitmentSchemeVerifier(H, MC),
            proof_in: proof_mod.StarkProof(H),
        ) anyerror!void {
            return verifyImpl(
                H,
                MC,
                true,
                allocator,
                component_list,
                channel,
                commitment_scheme,
                proof_in,
                null,
                null,
                false,
                null,
            );
        }

        pub fn verifyEx(
            comptime H: type,
            comptime MC: type,
            allocator: std.mem.Allocator,
            component_list: []const air_components.Component,
            channel: anytype,
            commitment_scheme: *pcs_verifier.CommitmentSchemeVerifier(H, MC),
            proof_in: proof_mod.StarkProof(H),
            include_all_preprocessed_columns: bool,
        ) anyerror!void {
            return verifyImpl(H, MC, true, allocator, component_list, channel, commitment_scheme, proof_in, null, null, include_all_preprocessed_columns, null);
        }

        /// Complete STARK verification with transactional publication of the exact
        /// FRI query draw used by the successful PCS verifier.
        pub fn verifyWithQueryCapture(
            comptime H: type,
            comptime MC: type,
            allocator: std.mem.Allocator,
            component_list: []const air_components.Component,
            channel: anytype,
            commitment_scheme: *pcs_verifier.CommitmentSchemeVerifier(H, MC),
            proof_in: proof_mod.StarkProof(H),
            capture: *QueryCapture,
        ) anyerror!void {
            return verifyImpl(
                H,
                MC,
                true,
                allocator,
                component_list,
                channel,
                commitment_scheme,
                proof_in,
                capture,
                null,
                false,
                null,
            );
        }

        /// Complete STARK verification with transactional publication of the expanded
        /// fixed-recursion proof material authenticated by the native verifier.
        pub fn verifyWithProofCapture(
            comptime H: type,
            comptime MC: type,
            allocator: std.mem.Allocator,
            component_list: []const air_components.Component,
            channel: anytype,
            commitment_scheme: *pcs_verifier.CommitmentSchemeVerifier(H, MC),
            proof_in: proof_mod.StarkProof(H),
            capture: *ProofCapture(H),
        ) anyerror!void {
            return verifyImpl(
                H,
                MC,
                true,
                allocator,
                component_list,
                channel,
                commitment_scheme,
                proof_in,
                null,
                capture,
                false,
                null,
            );
        }

        pub fn verifyExWithProofCapture(
            comptime H: type,
            comptime MC: type,
            allocator: std.mem.Allocator,
            component_list: []const air_components.Component,
            channel: anytype,
            commitment_scheme: *pcs_verifier.CommitmentSchemeVerifier(H, MC),
            proof_in: proof_mod.StarkProof(H),
            include_all_preprocessed_columns: bool,
            capture: *ProofCapture(H),
        ) anyerror!void {
            return verifyImpl(H, MC, true, allocator, component_list, channel, commitment_scheme, proof_in, null, capture, include_all_preprocessed_columns, null);
        }

        /// Verifies an immutable proof without consuming it. Every published capture
        /// allocation is independently owned; the original proof must remain alive
        /// and unchanged until this call returns. Wire receivers retain their owned
        /// verification path and independent decode/resource admission.
        pub fn verifyBorrowedWithProofCapture(
            comptime H: type,
            comptime MC: type,
            allocator: std.mem.Allocator,
            component_list: []const air_components.Component,
            channel: anytype,
            commitment_scheme: *pcs_verifier.CommitmentSchemeVerifier(H, MC),
            proof: *const proof_mod.StarkProof(H),
            capture: *ProofCapture(H),
        ) anyerror!void {
            return verifyImpl(H, MC, false, allocator, component_list, channel, commitment_scheme, proof.*, null, capture, false, null);
        }

        /// Borrowed pinned-revision proof capture for circuits whose PCS opens every
        /// preprocessed column. This preserves the caller's decoded proof for the
        /// recursive witness conversion after successful native verification.
        pub fn verifyBorrowedExWithProofCapture(
            comptime H: type,
            comptime MC: type,
            allocator: std.mem.Allocator,
            component_list: []const air_components.Component,
            channel: anytype,
            commitment_scheme: *pcs_verifier.CommitmentSchemeVerifier(H, MC),
            proof: *const proof_mod.StarkProof(H),
            include_all_preprocessed_columns: bool,
            capture: *ProofCapture(H),
        ) anyerror!void {
            return verifyImpl(H, MC, false, allocator, component_list, channel, commitment_scheme, proof.*, null, capture, include_all_preprocessed_columns, null);
        }

        /// Only owned Core checks may populate this output; caller callback errors remain unmapped.
        pub fn verifyDiagnosed(comptime H: type, comptime MC: type, allocator: std.mem.Allocator, component_list: []const air_components.Component, channel: anytype, commitment_scheme: *pcs_verifier.CommitmentSchemeVerifier(H, MC), proof_in: proof_mod.StarkProof(H), diagnostic: *?diagnostic_codes.Entry) anyerror!void {
            return verifyImpl(H, MC, true, allocator, component_list, channel, commitment_scheme, proof_in, null, null, false, diagnostic);
        }

        pub fn verifyExDiagnosed(comptime H: type, comptime MC: type, allocator: std.mem.Allocator, component_list: []const air_components.Component, channel: anytype, commitment_scheme: *pcs_verifier.CommitmentSchemeVerifier(H, MC), proof_in: proof_mod.StarkProof(H), include_all_preprocessed_columns: bool, diagnostic: *?diagnostic_codes.Entry) anyerror!void {
            return verifyImpl(H, MC, true, allocator, component_list, channel, commitment_scheme, proof_in, null, null, include_all_preprocessed_columns, diagnostic);
        }

        fn verifyImpl(
            comptime H: type,
            comptime MC: type,
            comptime owns_proof: bool,
            allocator: std.mem.Allocator,
            component_list: []const air_components.Component,
            channel: anytype,
            commitment_scheme: *pcs_verifier.CommitmentSchemeVerifier(H, MC),
            proof_in: proof_mod.StarkProof(H),
            capture_out: ?*QueryCapture,
            proof_capture_out: ?*ProofCapture(H),
            include_all_preprocessed_columns: bool,
            diagnostic: ?*?diagnostic_codes.Entry,
        ) anyerror!void {
            if (diagnostic) |sink| sink.* = null;
            var proof = proof_in;
            var proof_moved = false;
            defer if (owns_proof and !proof_moved) proof.deinit(allocator);

            if (commitment_scheme.trees.items.len <= PREPROCESSED_TRACE_IDX) {
                return diagnostic_codes.recordPcsFailure(diagnostic, VerificationError.InvalidPreprocessedTree);
            }

            const n_preprocessed_columns = commitment_scheme
                .trees
                .items[PREPROCESSED_TRACE_IDX]
                .column_log_sizes
                .len;

            const components = air_components.Components{
                .components = component_list,
                .n_preprocessed_columns = n_preprocessed_columns,
            };
            const composition_log_size = components.compositionLogDegreeBound();
            const composition_log_split = components.compositionLogSplit() catch
                return diagnostic_codes.recordPcsFailure(diagnostic, VerificationError.InvalidStructure);
            const component_mask_log = verifier_types.compositionMaskLogSize(
                composition_log_size,
                composition_log_split,
            ) orelse return diagnostic_codes.recordPcsFailure(diagnostic, VerificationError.InvalidStructure);
            // In the proving@5a7c5ed revision every committed tree, including the
            // composition tree, is lifted to the configured height. The AIR's own
            // degree can be lower; OODS and quotient replay use the lifted domain.
            const max_log_degree_bound = if (comptime @import("protocol_revision.zig").Revision.of(MC) == .proving_5a7c5ed) blk: {
                const config = commitment_scheme.revision_config;
                const lifted_mask_log = std.math.sub(u32, config.trace_lifting_log_size, config.fri_config.log_blowup_factor) catch return diagnostic_codes.recordPcsFailure(diagnostic, VerificationError.InvalidStructure);
                break :blk @max(component_mask_log, lifted_mask_log);
            } else component_mask_log;

            const composition_randomness = channel.drawSecureFelt();

            if (proof.commitment_scheme_proof.commitments.items.len == 0) {
                return diagnostic_codes.recordPcsFailure(diagnostic, VerificationError.InvalidStructure);
            }

            const composition_commitment =
                proof.commitment_scheme_proof.commitments.items[
                    proof.commitment_scheme_proof.commitments.items.len - 1
                ];

            const composition_column_count = verifier_types.compositionColumnCount(
                composition_log_split,
                DEGREE,
            ) orelse return diagnostic_codes.recordPcsFailure(diagnostic, VerificationError.InvalidStructure);
            const composition_commitment_log_sizes = try allocator.alloc(
                u32,
                composition_column_count,
            );
            defer allocator.free(composition_commitment_log_sizes);
            @memset(
                composition_commitment_log_sizes,
                max_log_degree_bound,
            );
            try commitment_scheme.commit(
                allocator,
                composition_commitment,
                composition_commitment_log_sizes,
                channel,
            );

            const oods_seed = channel.drawSecureFelt();
            const oods_point = try circle.secureFieldPointFromRandomSeedCheckedFor(QM31, oods_seed);

            var sample_points = try components.maskPoints(
                allocator,
                oods_point,
                max_log_degree_bound,
                include_all_preprocessed_columns,
            );
            var sample_points_moved = false;
            defer if (!sample_points_moved) sample_points.deinitDeep(allocator);

            try appendCompositionMaskTree(
                allocator,
                &sample_points,
                oods_point,
                composition_log_split,
            );

            const composition_oods_eval = proof.extractCompositionOodsEvalWithSplit(
                oods_point,
                std.math.add(u32, max_log_degree_bound, composition_log_split) catch
                    return diagnostic_codes.recordPcsFailure(diagnostic, VerificationError.InvalidStructure),
                composition_log_split,
            ) orelse return diagnostic_codes.recordPcsFailure(diagnostic, VerificationError.InvalidStructure);

            if (!composition_oods_eval.eql(try components.evalCompositionPolynomialAtPoint(
                oods_point,
                &proof.commitment_scheme_proof.sampled_values,
                composition_randomness,
                max_log_degree_bound,
            ))) {
                return diagnostic_codes.recordPcsFailure(diagnostic, VerificationError.OodsNotMatching);
            }

            sample_points_moved = true;
            proof_moved = true;
            const pcs_proof = proof.commitment_scheme_proof;
            if (proof_capture_out) |capture| {
                const challenges = pcs_verifier.ProofCaptureChallenges{ .composition_randomness = composition_randomness, .oods_seed = oods_seed };
                if (owns_proof) {
                    commitment_scheme.verifyValuesWithProofCapture(allocator, sample_points, pcs_proof, channel, challenges, capture) catch |err| return diagnostic_codes.recordPcsFailure(diagnostic, err);
                } else {
                    commitment_scheme.verifyValuesWithBorrowedProofCapture(allocator, sample_points, &pcs_proof, channel, challenges, capture) catch |err| return diagnostic_codes.recordPcsFailure(diagnostic, err);
                }
            } else if (capture_out) |capture| {
                commitment_scheme.verifyValuesWithQueryCapture(
                    allocator,
                    sample_points,
                    pcs_proof,
                    channel,
                    capture,
                ) catch |err| return diagnostic_codes.recordPcsFailure(diagnostic, err);
            } else {
                commitment_scheme.verifyValues(
                    allocator,
                    sample_points,
                    pcs_proof,
                    channel,
                ) catch |err| return diagnostic_codes.recordPcsFailure(diagnostic, err);
            }
        }

        fn appendCompositionMaskTree(
            allocator: std.mem.Allocator,
            sample_points: *MaskPoints,
            oods_point: CirclePointQM31,
            split_depth: u32,
        ) !void {
            const n_composition_cols = verifier_types.compositionColumnCount(
                split_depth,
                DEGREE,
            ) orelse return VerificationError.InvalidStructure;

            const composition_tree = try allocator.alloc([]CirclePointQM31, n_composition_cols);
            var initialized: usize = 0;
            errdefer {
                for (composition_tree[0..initialized]) |col| allocator.free(col);
                allocator.free(composition_tree);
            }

            for (composition_tree) |*col| {
                col.* = try allocator.alloc(CirclePointQM31, 1);
                col.*[0] = oods_point;
                initialized += 1;
            }

            const old_len = sample_points.items.len;
            const out = try allocator.alloc([][]CirclePointQM31, old_len + 1);
            @memcpy(out[0..old_len], sample_points.items);
            out[old_len] = composition_tree;

            allocator.free(sample_points.items);
            sample_points.items = out;
        }

        fn buildTestProof(
            comptime H: type,
            allocator: std.mem.Allocator,
            commitments: []const H.Hash,
            composition_value: QM31,
        ) !proof_mod.StarkProof(H) {
            const composition_tree = try allocator.alloc([]QM31, 2 * DEGREE);
            var initialized: usize = 0;
            errdefer {
                for (composition_tree[0..initialized]) |col| allocator.free(col);
                allocator.free(composition_tree);
            }
            for (composition_tree) |*col| {
                col.* = try allocator.alloc(QM31, 1);
                col.*[0] = composition_value;
                initialized += 1;
            }

            return .{
                .commitment_scheme_proof = .{
                    .config = pcs.PcsConfig.default(),
                    .commitments = pcs.TreeVec(H.Hash).initOwned(try allocator.dupe(H.Hash, commitments)),
                    .sampled_values = pcs.TreeVec([][]QM31).initOwned(
                        try allocator.dupe([][]QM31, &[_][][]QM31{composition_tree}),
                    ),
                    .decommitments = pcs.TreeVec(vcs_verifier.MerkleDecommitmentLifted(H)).initOwned(
                        try allocator.alloc(vcs_verifier.MerkleDecommitmentLifted(H), 0),
                    ),
                    .queried_values = pcs.TreeVec([][]M31).initOwned(
                        try allocator.alloc([][]M31, 0),
                    ),
                    .proof_of_work = 0,
                    .fri_proof = .{
                        .first_layer = .{
                            .fri_witness = try allocator.alloc(QM31, 0),
                            .decommitment = .{ .hash_witness = try allocator.alloc(H.Hash, 0) },
                            .commitment = [_]u8{0} ** 32,
                        },
                        .inner_layers = try allocator.alloc(fri.FriLayerProof(H), 0),
                        .last_layer_poly = line.LinePoly.initOwned(
                            try allocator.dupe(QM31, &[_]QM31{QM31.one()}),
                        ),
                    },
                },
            };
        }
    };
}

test "verifier: invalid proof structure when commitments missing" {
    inline for (.{ false, true }) |diagnosed| {
        const alloc = std.testing.allocator;
        const Hasher = @import("vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
        const MerkleChannel = @import("vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
        const Channel = @import("channel/blake2s.zig").Blake2sChannel;

        const CommitmentSchemeVerifier = @import("pcs/verifier.zig").CommitmentSchemeVerifier(Hasher, MerkleChannel);

        const MockComponent = struct {
            max_log_degree_bound: u32,
            evaluation: qm31_mod.QM31,

            fn asComponent(self: *const @This()) @import("air/components.zig").Component {
                return .{
                    .ctx = self,
                    .vtable = &.{
                        .nConstraints = nConstraints,
                        .maxConstraintLogDegreeBound = maxConstraintLogDegreeBound,
                        .traceLogDegreeBounds = traceLogDegreeBounds,
                        .maskPoints = maskPoints,
                        .preprocessedColumnIndices = preprocessedColumnIndices,
                        .evaluateConstraintQuotientsAtPoint = evaluateConstraintQuotientsAtPoint,
                    },
                };
            }

            fn cast(ctx: *const anyopaque) *const @This() {
                return @ptrCast(@alignCast(ctx));
            }

            fn nConstraints(_: *const anyopaque) usize {
                return 1;
            }

            fn maxConstraintLogDegreeBound(ctx: *const anyopaque) u32 {
                return cast(ctx).max_log_degree_bound;
            }

            fn traceLogDegreeBounds(ctx: *const anyopaque, allocator: std.mem.Allocator) !@import("air/components.zig").TraceLogDegreeBounds {
                const self = cast(ctx);
                const preprocessed = try allocator.dupe(u32, &[_]u32{self.max_log_degree_bound});
                const main = try allocator.dupe(u32, &[_]u32{self.max_log_degree_bound});
                return @import("air/components.zig").TraceLogDegreeBounds.initOwned(
                    try allocator.dupe([]u32, &[_][]u32{ preprocessed, main }),
                );
            }

            fn maskPoints(
                _: *const anyopaque,
                allocator: std.mem.Allocator,
                point: circle.CirclePointQM31,
                _: u32,
            ) !@import("air/components.zig").MaskPoints {
                const pp_col = try allocator.alloc(circle.CirclePointQM31, 0);
                const preprocessed_cols = try allocator.dupe([]circle.CirclePointQM31, &[_][]circle.CirclePointQM31{pp_col});

                const main_col = try allocator.alloc(circle.CirclePointQM31, 1);
                main_col[0] = point;
                const main_cols = try allocator.dupe([]circle.CirclePointQM31, &[_][]circle.CirclePointQM31{main_col});

                return @import("air/components.zig").MaskPoints.initOwned(
                    try allocator.dupe([][]circle.CirclePointQM31, &[_][][]circle.CirclePointQM31{
                        preprocessed_cols,
                        main_cols,
                    }),
                );
            }

            fn preprocessedColumnIndices(_: *const anyopaque, allocator: std.mem.Allocator) ![]usize {
                return allocator.dupe(usize, &[_]usize{0});
            }

            fn evaluateConstraintQuotientsAtPoint(
                ctx: *const anyopaque,
                _: circle.CirclePointQM31,
                _: *const @import("air/components.zig").MaskValues,
                evaluation_accumulator: *@import("air/accumulation.zig").PointEvaluationAccumulator,
                _: u32,
            ) !void {
                evaluation_accumulator.accumulate(cast(ctx).evaluation);
            }
        };

        var commitment_scheme = try CommitmentSchemeVerifier.init(alloc, .{
            .pow_bits = 4,
            .fri_config = try @import("fri.zig").FriConfig.init(0, 1, 1),
        });
        defer commitment_scheme.deinit(alloc);

        var commit_channel = Channel{};
        try commitment_scheme.commit(alloc, [_]u8{1} ** 32, &[_]u32{4}, &commit_channel);

        const mock = MockComponent{
            .max_log_degree_bound = 5,
            .evaluation = qm31_mod.QM31.fromBase(M31.fromCanonical(7)),
        };
        const components = [_]@import("air/components.zig").Component{mock.asComponent()};

        const proof = try ForField(qm31_mod.QM31).buildTestProof(Hasher, alloc, &[_]Hasher.Hash{}, qm31_mod.QM31.zero());
        var verify_channel = Channel{};

        const trees_before = commitment_scheme.trees.items.len;
        var diagnostic: ?diagnostic_codes.Entry = diagnostic_codes.fromFriConfig(error.InvalidBlowupFactor);
        try std.testing.expectError(
            ForField(qm31_mod.QM31).VerificationError.InvalidStructure,
            if (diagnosed) ForField(qm31_mod.QM31).verifyDiagnosed(Hasher, MerkleChannel, alloc, components[0..], &verify_channel, &commitment_scheme, proof, &diagnostic) else ForField(qm31_mod.QM31).verify(Hasher, MerkleChannel, alloc, components[0..], &verify_channel, &commitment_scheme, proof),
        );
        try std.testing.expectEqual(trees_before, commitment_scheme.trees.items.len);

        if (diagnosed) try std.testing.expectEqual(@as(u16, 0x1101), diagnostic.?.code);
    }
}

test "verifier: oods mismatch is rejected" {
    inline for (.{ .legacy, .owned, .callback, .pcs, .fri }) |case| {
        const alloc = std.testing.allocator;
        const Hasher = @import("vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
        const MerkleChannel = @import("vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
        const Channel = @import("channel/blake2s.zig").Blake2sChannel;
        const CommitmentSchemeVerifier = @import("pcs/verifier.zig").CommitmentSchemeVerifier(Hasher, MerkleChannel);

        const Mock = struct {
            max_log_degree_bound: u32,
            evaluation: qm31_mod.QM31,
            callback_failure: bool = false,

            fn asComponent(self: *const @This()) @import("air/components.zig").Component {
                return .{
                    .ctx = self,
                    .vtable = &.{
                        .nConstraints = nConstraints,
                        .maxConstraintLogDegreeBound = maxConstraintLogDegreeBound,
                        .traceLogDegreeBounds = traceLogDegreeBounds,
                        .maskPoints = maskPoints,
                        .preprocessedColumnIndices = preprocessedColumnIndices,
                        .evaluateConstraintQuotientsAtPoint = evaluateConstraintQuotientsAtPoint,
                    },
                };
            }

            fn cast(ctx: *const anyopaque) *const @This() {
                return @ptrCast(@alignCast(ctx));
            }

            fn nConstraints(_: *const anyopaque) usize {
                return 1;
            }

            fn maxConstraintLogDegreeBound(ctx: *const anyopaque) u32 {
                return cast(ctx).max_log_degree_bound;
            }

            fn traceLogDegreeBounds(ctx: *const anyopaque, allocator: std.mem.Allocator) !@import("air/components.zig").TraceLogDegreeBounds {
                const self = cast(ctx);
                const preprocessed = try allocator.dupe(u32, &[_]u32{self.max_log_degree_bound});
                const main = try allocator.dupe(u32, &[_]u32{self.max_log_degree_bound});
                return @import("air/components.zig").TraceLogDegreeBounds.initOwned(
                    try allocator.dupe([]u32, &[_][]u32{ preprocessed, main }),
                );
            }

            fn maskPoints(
                _: *const anyopaque,
                allocator: std.mem.Allocator,
                point: circle.CirclePointQM31,
                _: u32,
            ) !@import("air/components.zig").MaskPoints {
                const pp_col = try allocator.alloc(circle.CirclePointQM31, 0);
                const preprocessed_cols = try allocator.dupe([]circle.CirclePointQM31, &[_][]circle.CirclePointQM31{pp_col});

                const main_col = try allocator.alloc(circle.CirclePointQM31, 1);
                main_col[0] = point;
                const main_cols = try allocator.dupe([]circle.CirclePointQM31, &[_][]circle.CirclePointQM31{main_col});

                return @import("air/components.zig").MaskPoints.initOwned(
                    try allocator.dupe([][]circle.CirclePointQM31, &[_][][]circle.CirclePointQM31{
                        preprocessed_cols,
                        main_cols,
                    }),
                );
            }

            fn preprocessedColumnIndices(_: *const anyopaque, allocator: std.mem.Allocator) ![]usize {
                return allocator.dupe(usize, &[_]usize{0});
            }

            fn evaluateConstraintQuotientsAtPoint(
                ctx: *const anyopaque,
                _: circle.CirclePointQM31,
                _: *const @import("air/components.zig").MaskValues,
                evaluation_accumulator: *@import("air/accumulation.zig").PointEvaluationAccumulator,
                _: u32,
            ) !void {
                if (cast(ctx).callback_failure) return error.OodsNotMatching;
                evaluation_accumulator.accumulate(cast(ctx).evaluation);
            }
        };

        var commitment_scheme = try CommitmentSchemeVerifier.init(alloc, .{
            .pow_bits = 4,
            .fri_config = try @import("fri.zig").FriConfig.init(0, 1, 1),
        });
        defer commitment_scheme.deinit(alloc);

        var commit_channel = Channel{};
        try commitment_scheme.commit(alloc, [_]u8{2} ** 32, &[_]u32{4}, &commit_channel);
        if (case == .fri) try commitment_scheme.commit(alloc, [_]u8{3} ** 32, &[_]u32{4}, &commit_channel);

        const mock = Mock{
            .max_log_degree_bound = 5,
            .evaluation = if (case == .pcs or case == .fri) qm31_mod.QM31.zero() else qm31_mod.QM31.fromBase(M31.fromCanonical(1)),
            .callback_failure = case == .callback,
        };
        const components = [_]@import("air/components.zig").Component{mock.asComponent()};

        var proof = try ForField(qm31_mod.QM31).buildTestProof(
            Hasher,
            alloc,
            &[_]Hasher.Hash{[_]u8{9} ** 32},
            qm31_mod.QM31.zero(),
        );
        var proof_owned = true;
        defer if (proof_owned) proof.deinit(alloc);
        if (case == .fri) {
            // Admit the three tree-vector lengths, then physically reject the absent FRI layers.
            const D = vcs_verifier.MerkleDecommitmentLifted(Hasher);
            const decommitments = try alloc.dupe(D, &([_]D{.{ .hash_witness = &.{} }} ** 3));
            alloc.free(proof.commitment_scheme_proof.decommitments.items);
            proof.commitment_scheme_proof.decommitments.items = decommitments;
            const values = try alloc.dupe([][]M31, &([_][][]M31{&.{}} ** 3));
            alloc.free(proof.commitment_scheme_proof.queried_values.items);
            proof.commitment_scheme_proof.queried_values.items = values;
        }
        var verify_channel = Channel{};

        var diagnostic: ?diagnostic_codes.Entry = diagnostic_codes.fromFriConfig(error.InvalidBlowupFactor);
        proof_owned = false;
        try std.testing.expectError(
            if (case == .fri) error.InvalidNumFriLayers else if (case == .pcs) error.ShapeMismatch else ForField(qm31_mod.QM31).VerificationError.OodsNotMatching,
            if (case == .legacy) ForField(qm31_mod.QM31).verify(Hasher, MerkleChannel, alloc, components[0..], &verify_channel, &commitment_scheme, proof) else ForField(qm31_mod.QM31).verifyDiagnosed(Hasher, MerkleChannel, alloc, components[0..], &verify_channel, &commitment_scheme, proof, &diagnostic),
        );

        if (case == .callback) try std.testing.expect(diagnostic == null);
        if (case == .owned) try std.testing.expectEqual(@as(u16, 0x1102), diagnostic.?.code);
        if (case == .pcs) try std.testing.expectEqual(@as(u16, 0x1104), diagnostic.?.code);
        if (case == .fri) try std.testing.expectEqual(@as(u16, 0x110f), diagnostic.?.code);
    }
}
