//! Cairo resident-proof transcript replay and generic verifier orchestration.

const std = @import("std");
const air_accumulation = @import("stwo_core").air.accumulation;
const air_components = @import("stwo_core").air.components;
const circle = @import("stwo_core").circle;
const constraints = @import("stwo_core").constraints;
const pcs = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const canonic = @import("stwo_core").poly.circle.canonic;
const core_verifier = @import("stwo_core").verifier;
const vcs_verifier = @import("stwo_core").vcs_lifted.verifier;
const public_logup = @import("../statement/public_logup.zig");
const statement_bootstrap = @import("../statement_bootstrap.zig");
const composition_bundle = @import("composition_bundle.zig");
const eval_program = @import("eval_program.zig");
const proof_bundle = @import("proof_bundle.zig");
const geometry = @import("resident_geometry.zig");
const proof_reconstruction = @import("resident_proof.zig");
const types = @import("resident_types.zig");

const M31 = types.M31;
const QM31 = types.QM31;
const Point = circle.CirclePointQM31;

pub const Hasher = types.Hasher;
pub const Proof = types.Proof;
pub const Channel = types.Channel;
pub const MerkleChannel = types.MerkleChannel;
pub const sn2_pow_bits = types.sn2_pow_bits;
pub const sn2_interaction_pow_bits = types.sn2_interaction_pow_bits;
pub const sn2_query_count = types.sn2_query_count;
pub const sn2_fold_step = types.sn2_fold_step;
pub const Error = types.Error;
pub const SampleShape = types.SampleShape;
pub const ProtocolGeometry = types.ProtocolGeometry;
pub const TranscriptInput = types.TranscriptInput;
pub const VerifyInput = types.VerifyInput;
pub const decodeProof = proof_reconstruction.decodeProof;
pub const decodeProofWithGeometry = proof_reconstruction.decodeProofWithGeometry;
pub const sampleShape = geometry.sampleShape;
pub const freeSampleShape = geometry.freeSampleShape;

const qm31FromWords = types.qm31FromWords;
const qm31Words = types.qm31Words;
const validateMaximumDegreeLog = geometry.validateMaximumDegreeLog;
const componentSpan = geometry.componentSpan;
const spanLength = geometry.spanLength;
const componentOffsets = geometry.componentOffsets;
const freeOffsetLists = geometry.freeOffsetLists;
const pointsFromOffsets = geometry.pointsFromOffsets;
const freePointTree = geometry.freePointTree;
const offsetIndex = geometry.offsetIndex;

/// Replays the direct Cairo transcript and runs the generic AIR/PCS/FRI
/// verifier. Success is the only state a caller may expose as `verified`.
pub fn verify(allocator: std.mem.Allocator, input: VerifyInput) !void {
    const protocol_geometry = ProtocolGeometry.sn2();
    const config_words = transcriptWords(input.transcript_inputs, 2) orelse
        return Error.InvalidProofShape;
    if (!protocol_geometry.matchesTranscript(config_words)) return Error.InvalidProtocolGeometry;
    return verifyWithGeometry(allocator, input, protocol_geometry);
}

/// Verifies a Cairo proof against caller-authenticated runtime PCS geometry.
/// Ordinal 2 must encode the same geometry and is mixed into the transcript;
/// proof-controlled parameters can therefore neither drift nor downgrade it.
pub fn verifyRuntime(
    allocator: std.mem.Allocator,
    input: VerifyInput,
    protocol_geometry: ProtocolGeometry,
) !void {
    return verifyWithGeometry(allocator, input, protocol_geometry);
}

fn verifyWithGeometry(
    allocator: std.mem.Allocator,
    input: VerifyInput,
    protocol_geometry: ProtocolGeometry,
) !void {
    try protocol_geometry.validate();
    if (input.tree_logs[0].len == 0 or input.tree_logs[1].len == 0 or
        input.tree_logs[2].len == 0 or input.composition.components.len == 0)
        return Error.InvalidTraceShape;
    const verifier_max_log_degree_bound = input.composition.verifierMaxLogDegreeBound() catch
        return Error.InvalidProtocolGeometry;
    if (protocol_geometry.max_log_degree_bound != verifier_max_log_degree_bound or
        protocol_geometry.trace_tree_count != 4)
        return Error.InvalidProtocolGeometry;
    const config_words = transcriptWords(input.transcript_inputs, 2) orelse
        return Error.InvalidProofShape;
    if (!protocol_geometry.matchesTranscript(config_words)) return Error.InvalidProtocolGeometry;
    try validateStatementBinding(allocator, input, protocol_geometry);

    const commitment_words = input.bundle.words[input.bundle.layout.commitments.start..input.bundle.layout.commitments.end];
    if (commitment_words.len != protocol_geometry.trace_tree_count * proof_bundle.hash_words)
        return Error.InvalidProofShape;
    if (!hashWordsEqual(transcriptWords(input.transcript_inputs, 3), commitment_words[0..8]) or
        !hashWordsEqual(transcriptWords(input.transcript_inputs, 20), commitment_words[8..16]))
        return Error.InvalidProofShape;

    var channel = Channel{};
    for ([_]u32{ 1, 2, 3, 10, 11, 12, 13, 14, 15, 16, 20 }) |ordinal| {
        channel.mixU32s(transcriptWords(input.transcript_inputs, ordinal) orelse
            return Error.InvalidProofShape);
    }
    if (!channel.verifyPowNonce(protocol_geometry.interaction_pow_bits, input.bundle.interactionNonce()))
        return error.ProofOfWork;
    channel.mixU64(input.bundle.interactionNonce());
    const lookup_challenges = try channel.drawSecureFelts(allocator, 2);
    defer allocator.free(lookup_challenges);
    const lookup_z = lookup_challenges[0];
    const lookup_alpha = lookup_challenges[1];

    const claim_words = input.bundle.words[input.bundle.layout.interaction_claim.start..input.bundle.layout.interaction_claim.end];
    if (claim_words.len != input.composition.components.len * 4)
        return Error.InvalidComponentShape;
    var base_cursor: usize = 0;
    var interaction_cursor: usize = 0;
    for (input.composition.components) |component| {
        const base_span = try componentSpan(component, 1);
        const interaction_span = try componentSpan(component, 2);
        if (base_span.start != base_cursor or interaction_span.start != interaction_cursor)
            return Error.InvalidComponentShape;
        base_cursor = base_span.end;
        interaction_cursor = interaction_span.end;
    }
    if (base_cursor != input.tree_logs[1].len or interaction_cursor != input.tree_logs[2].len)
        return Error.InvalidComponentShape;
    var global_lookup_sum = try public_logup.sum(
        allocator,
        input.statement,
        lookup_z,
        lookup_alpha,
    );
    var claim_cursor: usize = 0;
    while (claim_cursor < claim_words.len) : (claim_cursor += 4) {
        global_lookup_sum = global_lookup_sum.add(
            try qm31FromWords(claim_words[claim_cursor..][0..4]),
        );
    }
    try enforceGlobalLookupClosure(global_lookup_sum);
    channel.mixU32s(claim_words);
    channel.mixU32s(commitment_words[16..24]);

    var diagnostic_point: ?Point = null;
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_VERIFIER_ACCUMULATORS")) {
        var diagnostic_channel = channel;
        const random_coefficient = diagnostic_channel.drawSecureFelt();
        var composition_root: Hasher.Hash = undefined;
        @memcpy(&composition_root, std.mem.sliceAsBytes(commitment_words[24..32]));
        MerkleChannel.mixRoot(&diagnostic_channel, composition_root);
        const parameter = diagnostic_channel.drawSecureFelt();
        const parameter_square = parameter.square();
        const denominator = parameter_square.add(QM31.one()).inv() catch unreachable;
        diagnostic_point = .{
            .x = QM31.one().sub(parameter_square).mul(denominator),
            .y = parameter.add(parameter).mul(denominator),
        };
        std.debug.print(
            "verifier_transcript random_coefficient={any} oods_parameter={any} oods_x={any} oods_y={any}\n",
            .{
                qm31Words(random_coefficient),
                qm31Words(parameter),
                qm31Words(diagnostic_point.?.x),
                qm31Words(diagnostic_point.?.y),
            },
        );
    }

    const runtime_components = try allocator.alloc(RuntimeComponent, input.composition.components.len);
    defer allocator.free(runtime_components);
    const verifier_components = try allocator.alloc(air_components.Component, runtime_components.len);
    defer allocator.free(verifier_components);
    for (runtime_components, verifier_components, 0..) |*runtime, *component, index| {
        runtime.* = .{
            .allocator = allocator,
            .captured = &input.composition.components[index],
            .preprocessed_logs = input.tree_logs[0],
            .lifting_log_size = input.composition.max_evaluation_log_size,
            .lookup_z = lookup_z,
            .lookup_alpha = lookup_alpha,
            .claimed_sum = try qm31FromWords(claim_words[index * 4 ..][0..4]),
        };
        component.* = runtime.asComponent();
    }

    const shape = try sampleShape(allocator, input.composition, .{
        input.tree_logs[0].len,
        input.tree_logs[1].len,
        input.tree_logs[2].len,
    });
    defer freeSampleShape(allocator, shape);
    var proof = try decodeProofWithGeometry(
        allocator,
        input.bundle,
        .{ .trees = shape },
        protocol_geometry,
    );
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);
    if (diagnostic_point) |point| {
        const expected = proof.extractCompositionOodsEval(
            point,
            input.composition.max_evaluation_log_size,
        ) orelse return Error.InvalidProofShape;
        std.debug.print("verifier_composition expected={any}\n", .{qm31Words(expected)});
    }

    const config = proof.commitment_scheme_proof.config;
    var commitment_scheme = try pcs_verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel).init(
        allocator,
        config,
    );
    defer commitment_scheme.deinit(allocator);
    commitment_scheme.trees.deinit(allocator);
    const trees = try allocator.alloc(vcs_verifier.MerkleVerifierLifted(Hasher), 3);
    var initialized: usize = 0;
    var trees_moved = false;
    errdefer if (!trees_moved) {
        for (trees[0..initialized]) |*tree| tree.deinit(allocator);
        allocator.free(trees);
    };
    for (trees, input.tree_logs, 0..) |*tree, logs, tree_index| {
        const extended = try allocator.alloc(u32, logs.len);
        defer allocator.free(extended);
        for (logs, extended) |log_size, *value| value.* = log_size + config.fri_config.log_blowup_factor;
        var root: Hasher.Hash = undefined;
        @memcpy(
            &root,
            std.mem.sliceAsBytes(commitment_words[tree_index * proof_bundle.hash_words ..][0..proof_bundle.hash_words]),
        );
        tree.* = try vcs_verifier.MerkleVerifierLifted(Hasher).init(allocator, root, extended);
        initialized += 1;
    }
    commitment_scheme.trees = pcs.TreeVec(vcs_verifier.MerkleVerifierLifted(Hasher)).initOwned(trees);
    trees_moved = true;
    initialized = 0;

    proof_moved = true;
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_VERIFIER_DECOMMIT")) {
        std.debug.print("verifier_bundle_raw_queries={any}\n", .{input.bundle.decommitment.raw_queries});
        std.debug.print("verifier_bundle_unique_queries={any}\n", .{input.bundle.decommitment.unique_queries});
        for (input.bundle.decommitment.trees, 0..) |tree, index| {
            std.debug.print(
                "verifier_bundle_tree index={} role={} query_count={} value_count={} hash_count={} leaf_log={}\n",
                .{ index, tree.role, tree.query_count, tree.values_count, tree.hash_witness_count, tree.leaf_log_size },
            );
        }
    }
    try core_verifier.verify(
        Hasher,
        MerkleChannel,
        allocator,
        verifier_components,
        &channel,
        &commitment_scheme,
        proof,
    );
}

fn validateStatementBinding(
    allocator: std.mem.Allocator,
    input: VerifyInput,
    protocol_geometry: ProtocolGeometry,
) !void {
    const salt_words = transcriptWords(input.transcript_inputs, 1) orelse
        return Error.InvalidStatementBinding;
    if (salt_words.len != 4 or salt_words[1] != 0 or
        salt_words[2] != 0 or salt_words[3] != 0)
        return Error.InvalidStatementBinding;
    var expected = try statement_bootstrap.initFromCompositionSchedule(allocator, .{
        .channel_salt = salt_words[0],
        .pcs = .{
            .pow_bits = protocol_geometry.query_pow_bits,
            .log_blowup_factor = protocol_geometry.log_blowup_factor,
            .n_queries = @intCast(protocol_geometry.query_count),
            .log_last_layer_degree_bound = protocol_geometry.log_last_layer_degree_bound,
            .fold_step = protocol_geometry.fold_step,
            .lifting_log_size = protocol_geometry.lifting_log_size,
        },
        .composition = &input.composition,
        .prover_input = input.statement,
    });
    defer expected.deinit();
    inline for (statement_bootstrap.ORDINALS) |ordinal| {
        const actual_words = transcriptWords(input.transcript_inputs, ordinal) orelse
            return Error.InvalidStatementBinding;
        const expected_words = expected.words(ordinal) orelse unreachable;
        if (!std.mem.eql(u32, actual_words, expected_words))
            return Error.InvalidStatementBinding;
    }
}

fn enforceGlobalLookupClosure(sum_value: QM31) Error!void {
    if (!sum_value.eql(QM31.zero())) return Error.InvalidGlobalLookupSum;
}

fn transcriptWords(inputs: []const TranscriptInput, ordinal: u32) ?[]const u32 {
    for (inputs) |input| if (input.ordinal == ordinal) return input.words;
    return null;
}

fn hashWordsEqual(candidate: ?[]const u32, expected: []const u32) bool {
    const words = candidate orelse return false;
    return words.len == proof_bundle.hash_words and std.mem.eql(u32, words, expected);
}

/// Verifier-side wrapper for one captured Cairo AIR component. The captured
/// eval program is the protocol artifact used by the Metal prover; interpreting
/// the same operations on OODS samples avoids maintaining a second AIR model.
pub const RuntimeComponent = struct {
    allocator: std.mem.Allocator,
    captured: *const composition_bundle.Component,
    preprocessed_logs: []const u32,
    lifting_log_size: u32,
    lookup_z: QM31,
    lookup_alpha: QM31,
    claimed_sum: QM31,

    pub fn asComponent(self: *const RuntimeComponent) air_components.Component {
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

    fn cast(ctx: *const anyopaque) *const RuntimeComponent {
        return @ptrCast(@alignCast(ctx));
    }

    fn nConstraints(ctx: *const anyopaque) usize {
        return cast(ctx).captured.n_constraints;
    }

    fn maxConstraintLogDegreeBound(ctx: *const anyopaque) u32 {
        return cast(ctx).captured.evaluation_log_size;
    }

    fn traceLogDegreeBounds(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) !air_components.TraceLogDegreeBounds {
        const self = cast(ctx);
        const component = self.captured;
        const preprocessed = try allocator.alloc(u32, component.preprocessed_indices.len);
        errdefer allocator.free(preprocessed);
        for (component.preprocessed_indices, preprocessed) |index, *log_size| {
            if (index >= self.preprocessed_logs.len) return Error.InvalidComponentShape;
            log_size.* = self.preprocessed_logs[index];
        }
        const base = try allocator.alloc(u32, try spanLength(component.*, 1));
        errdefer allocator.free(base);
        @memset(base, component.trace_log_size);
        const interaction = try allocator.alloc(u32, try spanLength(component.*, 2));
        errdefer allocator.free(interaction);
        @memset(interaction, component.trace_log_size);
        return air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &[_][]u32{ preprocessed, base, interaction }),
        );
    }

    fn maskPoints(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
        point: Point,
        max_log_degree_bound: u32,
    ) !air_components.MaskPoints {
        const self = cast(ctx);
        try validateMaximumDegreeLog(self.lifting_log_size, max_log_degree_bound);
        const component = self.captured;
        const preprocessed = try allocator.alloc([]Point, component.preprocessed_indices.len);
        errdefer allocator.free(preprocessed);
        var pp_initialized: usize = 0;
        errdefer for (preprocessed[0..pp_initialized]) |column| allocator.free(column);
        for (preprocessed) |*column| {
            column.* = try allocator.alloc(Point, 0);
            pp_initialized += 1;
        }

        const base_offsets = try componentOffsets(allocator, component.*, 1);
        defer freeOffsetLists(allocator, base_offsets);
        const interaction_offsets = try componentOffsets(allocator, component.*, 2);
        defer freeOffsetLists(allocator, interaction_offsets);
        const trace_step_m31 = canonic.CanonicCoset.new(max_log_degree_bound).step();
        const trace_step = Point{
            .x = QM31.fromBase(trace_step_m31.x),
            .y = QM31.fromBase(trace_step_m31.y),
        };
        const base = try pointsFromOffsets(allocator, base_offsets, point, trace_step);
        errdefer freePointTree(allocator, base);
        const interaction = try pointsFromOffsets(allocator, interaction_offsets, point, trace_step);
        errdefer freePointTree(allocator, interaction);
        return air_components.MaskPoints.initOwned(
            try allocator.dupe([][]Point, &[_][][]Point{ preprocessed, base, interaction }),
        );
    }

    fn preprocessedColumnIndices(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) ![]usize {
        const indices = cast(ctx).captured.preprocessed_indices;
        const out = try allocator.alloc(usize, indices.len);
        for (indices, out) |index, *destination| destination.* = index;
        return out;
    }

    fn evaluateConstraintQuotientsAtPoint(
        ctx: *const anyopaque,
        point: Point,
        mask: *const air_components.MaskValues,
        accumulator: *air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        const self = cast(ctx);
        try validateMaximumDegreeLog(self.lifting_log_size, max_log_degree_bound);
        const component = self.captured;
        const ext_params = try self.extensionParameters();
        defer self.allocator.free(ext_params);
        const base_offsets = try componentOffsets(self.allocator, component.*, 1);
        defer freeOffsetLists(self.allocator, base_offsets);
        const interaction_offsets = try componentOffsets(self.allocator, component.*, 2);
        defer freeOffsetLists(self.allocator, interaction_offsets);
        const zeroifier = constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(max_log_degree_bound).coset(),
            point,
        );
        const denominator_inverse = try zeroifier.inv();

        for (component.parts) |part| {
            try self.evaluateProgram(
                part.program,
                part.rc_base,
                mask,
                base_offsets,
                interaction_offsets,
                ext_params,
                denominator_inverse,
                accumulator,
            );
        }
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_VERIFIER_ACCUMULATORS")) {
            std.debug.print(
                "verifier_accumulator component={s} instance={} constraint_end={} cumulative={any}\n",
                .{
                    component.label,
                    component.instance,
                    component.random_coefficient_offset + component.n_constraints,
                    qm31Words(accumulator.finalize()),
                },
            );
        }
    }

    /// Resolves the proof-transcript parameters consumed by the captured AIR.
    /// The caller owns the returned slice.
    pub fn extensionParameters(self: RuntimeComponent) ![]QM31 {
        const sources = self.captured.ext_sources;
        const out = try self.allocator.alloc(QM31, sources.len);
        const claimed_scale = try M31.fromCanonical(
            @as(u32, 1) << @intCast(self.captured.trace_log_size),
        ).inv();
        for (sources, out) |source, *value| value.* = switch (source) {
            .constant => |words| try qm31FromWords(&words),
            .lookup_z => self.lookup_z,
            .lookup_alpha_power => |power| self.lookup_alpha.pow(power),
            .lookup_alpha_power_scaled => |scaled| self.lookup_alpha
                .pow(scaled.power)
                .mulM31(M31.fromCanonical(scaled.scale)),
            .claimed_sum_scaled => self.claimed_sum.mulM31(claimed_scale),
        };
        return out;
    }

    fn evaluateProgram(
        self: RuntimeComponent,
        program: eval_program.Program,
        constraint_base: u32,
        mask: *const air_components.MaskValues,
        base_offsets: []const std.ArrayList(i32),
        interaction_offsets: []const std.ArrayList(i32),
        ext_params: []const QM31,
        denominator_inverse: QM31,
        accumulator: *air_accumulation.PointEvaluationAccumulator,
    ) !void {
        if (program.header.n_base_params != 0 or program.header.n_ext_params != ext_params.len)
            return Error.InvalidProgram;
        // Base-column expressions are evaluated at the secure OODS point, so their
        // values live in QM31 even though the underlying trace columns are M31.
        const base = try self.allocator.alloc(QM31, program.header.max_base_regs);
        defer self.allocator.free(base);
        const extension = try self.allocator.alloc(QM31, program.header.max_ext_regs);
        defer self.allocator.free(extension);
        for (program.base_insts) |instruction| {
            base[instruction.dst] = switch (instruction.op) {
                .trace_col, .preprocessed_col => try self.traceValue(
                    mask,
                    base_offsets,
                    interaction_offsets,
                    instruction.interaction,
                    instruction.a,
                    instruction.imm,
                ),
                .param => return Error.InvalidProgram,
                .constant => QM31.fromBase(M31.fromCanonical(instruction.a)),
                .add => base[instruction.a].add(base[instruction.b]),
                .sub => base[instruction.a].sub(base[instruction.b]),
                .mul => base[instruction.a].mul(base[instruction.b]),
                .neg => base[instruction.a].neg(),
                .inv => try base[instruction.a].inv(),
            };
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_VERIFIER_LOGUP_INPUTS") and
                self.captured.random_coefficient_offset == 0 and instruction.op == .trace_col and
                instruction.interaction == 2)
            {
                std.debug.print(
                    "verifier_logup_base dst={} column={} offset={} value={any}\n",
                    .{ instruction.dst, instruction.a, instruction.imm, qm31Words(base[instruction.dst]) },
                );
            }
        }
        for (program.ext_insts) |instruction| {
            extension[instruction.dst] = switch (instruction.op) {
                .secure_col => QM31.fromPartialEvals(.{
                    base[instruction.a],
                    base[instruction.b],
                    base[instruction.c],
                    base[instruction.d],
                }),
                .param => ext_params[instruction.a],
                .constant => QM31.fromU32Unchecked(
                    instruction.a,
                    instruction.b,
                    instruction.c,
                    instruction.d,
                ),
                .add => extension[instruction.a].add(extension[instruction.b]),
                .sub => extension[instruction.a].sub(extension[instruction.b]),
                .mul => extension[instruction.a].mul(extension[instruction.b]),
                .neg => extension[instruction.a].neg(),
            };
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_VERIFIER_LOGUP_INPUTS") and
                self.captured.random_coefficient_offset == 0 and
                (instruction.op == .secure_col or instruction.op == .param))
            {
                std.debug.print(
                    "verifier_logup_ext op={s} dst={} slot={} value={any}\n",
                    .{ @tagName(instruction.op), instruction.dst, instruction.a, qm31Words(extension[instruction.dst]) },
                );
            }
        }
        for (program.constraint_roots, 0..) |root, root_index| {
            const evaluation = extension[root].mul(denominator_inverse);
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_VERIFIER_CONSTRAINTS")) {
                std.debug.print(
                    "verifier_constraint component={s} local={} evaluation={any}\n",
                    .{
                        self.captured.label,
                        constraint_base + root_index,
                        qm31Words(evaluation),
                    },
                );
            }
            accumulator.accumulate(evaluation);
        }
    }

    fn traceValue(
        self: RuntimeComponent,
        mask: *const air_components.MaskValues,
        base_offsets: []const std.ArrayList(i32),
        interaction_offsets: []const std.ArrayList(i32),
        interaction: u8,
        local_column: u32,
        offset: i32,
    ) !QM31 {
        const component = self.captured;
        const selection = switch (interaction) {
            0 => blk: {
                if (local_column >= component.preprocessed_indices.len or mask.items.len <= 0)
                    return Error.MissingMaskValue;
                const global = component.preprocessed_indices[local_column];
                if (global >= mask.items[0].len or mask.items[0][global].len != 1)
                    return Error.MissingMaskValue;
                break :blk mask.items[0][global][0];
            },
            1, 2 => blk: {
                const span = try componentSpan(component.*, interaction);
                const offsets = if (interaction == 1) base_offsets else interaction_offsets;
                if (local_column >= offsets.len) return Error.MissingMaskValue;
                const sample_index = offsetIndex(offsets[local_column].items, offset) orelse
                    return Error.MissingMaskValue;
                const global = span.start + local_column;
                if (interaction >= mask.items.len or global >= mask.items[interaction].len or
                    sample_index >= mask.items[interaction][global].len)
                    return Error.MissingMaskValue;
                break :blk mask.items[interaction][global][sample_index];
            },
            else => return Error.MissingMaskValue,
        };
        return selection;
    }
};

test "resident verifier evaluates secure OODS trace samples in QM31" {
    const allocator = std.testing.allocator;
    var label = [_]u8{'t'};
    var spans = [_]composition_bundle.TraceSpan{.{ .tree = 1, .start = 0, .end = 4 }};
    var preprocessed = [_]u32{};
    var denominators = [_]u32{1};
    var sources = [_]composition_bundle.ExtSource{};
    var parts = [_]composition_bundle.Part{};
    var captured = composition_bundle.Component{
        .label = label[0..],
        .instance = 0,
        .trace_log_size = 1,
        .evaluation_log_size = 1,
        .n_constraints = 1,
        .random_coefficient_offset = 0,
        .trace_spans = spans[0..],
        .preprocessed_indices = preprocessed[0..],
        .denominator_inverses = denominators[0..],
        .ext_sources = sources[0..],
        .parts = parts[0..],
    };
    const values = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
        QM31.fromU32Unchecked(9, 10, 11, 12),
        QM31.fromU32Unchecked(13, 14, 15, 16),
    };
    var column0 = [_]QM31{values[0]};
    var column1 = [_]QM31{values[1]};
    var column2 = [_]QM31{values[2]};
    var column3 = [_]QM31{values[3]};
    var tree0 = [_][]QM31{};
    var tree1 = [_][]QM31{ column0[0..], column1[0..], column2[0..], column3[0..] };
    var tree2 = [_][]QM31{};
    var mask_items = [_][][]QM31{ tree0[0..], tree1[0..], tree2[0..] };
    const mask = air_components.MaskValues.initOwned(mask_items[0..]);

    var zero0 = [_]i32{0};
    var zero1 = [_]i32{0};
    var zero2 = [_]i32{0};
    var zero3 = [_]i32{0};
    const base_offsets = [_]std.ArrayList(i32){
        .fromOwnedSlice(zero0[0..]),
        .fromOwnedSlice(zero1[0..]),
        .fromOwnedSlice(zero2[0..]),
        .fromOwnedSlice(zero3[0..]),
    };
    const no_offsets = [_]std.ArrayList(i32){};
    const no_ext_params = [_]QM31{};
    var base_insts = [_]eval_program.BaseInst{
        .{ .op = .trace_col, .interaction = 1, .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = .trace_col, .interaction = 1, .dst = 1, .a = 1, .b = 0, .imm = 0 },
        .{ .op = .trace_col, .interaction = 1, .dst = 2, .a = 2, .b = 0, .imm = 0 },
        .{ .op = .trace_col, .interaction = 1, .dst = 3, .a = 3, .b = 0, .imm = 0 },
    };
    var ext_insts = [_]eval_program.ExtInst{
        .{ .op = .secure_col, .dst = 0, .a = 0, .b = 1, .c = 2, .d = 3 },
    };
    var roots = [_]u32{0};
    var base_consts = [_]u32{};
    var ext_consts = [_][4]u32{};
    const program = eval_program.Program{
        .allocator = allocator,
        .header = .{
            .flags = 0,
            .semantic_hash = 0,
            .capability_bits = 0,
            .n_interactions = 3,
            .n_base_params = 0,
            .n_ext_params = 0,
            .n_constraints = 1,
            .max_base_regs = 4,
            .max_ext_regs = 1,
            .domain_log_size = 1,
        },
        .base_consts = base_consts[0..],
        .ext_consts = ext_consts[0..],
        .base_insts = base_insts[0..],
        .ext_insts = ext_insts[0..],
        .constraint_roots = roots[0..],
    };
    const runtime = RuntimeComponent{
        .allocator = allocator,
        .captured = &captured,
        .preprocessed_logs = &.{},
        .lifting_log_size = 24,
        .lookup_z = QM31.zero(),
        .lookup_alpha = QM31.zero(),
        .claimed_sum = QM31.zero(),
    };
    var accumulator = air_accumulation.PointEvaluationAccumulator.init(QM31.one());

    try runtime.evaluateProgram(
        program,
        0,
        &mask,
        base_offsets[0..],
        no_offsets[0..],
        no_ext_params[0..],
        QM31.one(),
        &accumulator,
    );
    try std.testing.expect(accumulator.finalize().eql(QM31.fromPartialEvals(values)));
}

test "global LogUp closure includes every dynamic memory segment" {
    var component_sums: [16]QM31 = undefined;
    var total = QM31.zero();
    for (&component_sums, 0..) |*claimed_sum, index| {
        claimed_sum.* = QM31.fromBase(M31.fromCanonical(@intCast(index + 1)));
        total = total.add(claimed_sum.*);
    }

    var closure = total.neg();
    for (component_sums) |claimed_sum| closure = closure.add(claimed_sum);
    try enforceGlobalLookupClosure(closure);

    for (component_sums) |omitted_sum| {
        try std.testing.expectError(
            Error.InvalidGlobalLookupSum,
            enforceGlobalLookupClosure(closure.sub(omitted_sum)),
        );
    }
    try std.testing.expectError(
        Error.InvalidGlobalLookupSum,
        enforceGlobalLookupClosure(closure.add(component_sums[0])),
    );
}
