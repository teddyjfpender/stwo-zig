const std = @import("std");
const stwo_core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const core_verifier = stwo_core.verifier;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const pcs_core = stwo_core.pcs;
const prover_pcs = @import("stwo_prover_engine").pcs;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_air = @import("stwo_prover_engine").air.component_prover;
const prover_circle = @import("stwo_prover_engine").poly.circle;
const recursion = frontend.recursion;
const recursion_air = recursion.air;
const recursion_engine = recursion.engine;
const manifest_mod = recursion_air.universal_adapter_manifest;
const adapter = recursion_air.universal_typed_component;
const universal = recursion_air.universal_challenges;
const framework = recursion_air.framework_interaction;
const fri_input = recursion_air.fri_verifier_input;
const fri_relation = recursion_air.fri_verifier_input_relation;
const merkle = recursion_air.merkle_path;
const merkle_relation = recursion_air.merkle_path_relation;
const merkle_witness = recursion_air.merkle_path_witness;
const fri_leaf = recursion_air.fri_merkle_leaf;
const fri_leaf_relation = recursion_air.fri_merkle_leaf_relation;
const fri_leaf_witness = recursion_air.fri_merkle_leaf_witness;
const fri_node = recursion_air.fri_merkle_node;
const fri_node_relation = recursion_air.fri_merkle_node_relation;
const fri_node_witness = recursion_air.fri_merkle_node_witness;

const Engine = recursion_engine.ProverEngineForBackend(CpuBackend);
const VerifierScheme = stwo_core.pcs.verifier.CommitmentSchemeVerifier(
    recursion_engine.Hasher,
    recursion_engine.MerkleChannel,
);
const FriAdapter = adapter.Component(fri_input, fri_relation);
const MerkleAdapter = adapter.Component(merkle, merkle_relation);
const MerkleFramework = framework.Runtime(merkle_relation.Runtime);
const FriLeafAdapter = adapter.Component(fri_leaf, fri_leaf_relation);
const FriLeafFramework = framework.Runtime(fri_leaf_relation.Runtime);
const FriNodeAdapter = adapter.Component(fri_node, fri_node_relation);
const FriNodeFramework = framework.Runtime(fri_node_relation.Runtime);
const LOG_SIZE: u32 = 4;
const PP_COUNT = fri_input.PREPROCESSED_COLUMN_COUNT +
    merkle.PREPROCESSED_COLUMN_COUNT;
const MAIN_COUNT = fri_input.PHYSICAL_MAIN_COLUMN_COUNT +
    merkle.PHYSICAL_MAIN_COLUMN_COUNT;
const INTERACTION_COUNT = fri_input.INTERACTION_COLUMN_COUNT +
    merkle.INTERACTION_COLUMN_COUNT;

const LEAF_LAYERS = [_]fri_leaf_witness.LayerProfile{
    .{ .width = 16, .tree_height = 7 },
    .{ .width = 4, .tree_height = 3 },
    .{ .width = 2, .tree_height = 3 },
};
const LEAF_PROFILE = fri_leaf_witness.LaneProfile{
    .query_count = 2,
    .lifting_log_size = 9,
    .layers = &LEAF_LAYERS,
};

pub fn claimsFor(
    manifest: *const manifest_mod.Manifest,
    merkle_claimed_sum: QM31,
) !manifest_mod.ClaimVector {
    var claims = try manifest_mod.ClaimVector.init(manifest);
    try claims.bind(.fri_verifier_input, QM31.zero());
    try claims.bind(.merkle_path, merkle_claimed_sum);
    try claims.sealClaims(manifest);
    return claims;
}

pub fn leafClaims(
    manifest: *const manifest_mod.Manifest,
    claimed_sum: QM31,
) !manifest_mod.ClaimVector {
    var claims = try manifest_mod.ClaimVector.init(manifest);
    try claims.bind(.fri_merkle_leaf, claimed_sum);
    try claims.sealClaims(manifest);
    return claims;
}

pub fn nodeClaims(
    manifest: *const manifest_mod.Manifest,
    claimed_sum: QM31,
) !manifest_mod.ClaimVector {
    var claims = try manifest_mod.ClaimVector.init(manifest);
    try claims.bind(.fri_merkle_node, claimed_sum);
    try claims.sealClaims(manifest);
    return claims;
}

pub fn friLeafParameters(
    kind: fri_leaf_witness.ProofKind,
) [fri_leaf.PARAMETER_COUNT]M31 {
    const selectors = kind.selectors();
    return .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(fri_leaf_witness.LEAF_TAG),
    };
}

pub const LeafOpeningFixture = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    raw: [3][]M31,
    layers: [3][LEAF_LAYERS.len]fri_leaf_witness.LayerOpening,

    fn init(allocator: std.mem.Allocator) !LeafOpeningFixture {
        const words_per_lane = 2 + 2 * (16 + 4 + 2) * 4;
        const storage = try allocator.alloc(M31, 3 * words_per_lane);
        errdefer allocator.free(storage);
        for (storage, 0..) |*value, index|
            value.* = M31.fromCanonical(@intCast(index + 1));
        var result = LeafOpeningFixture{
            .allocator = allocator,
            .storage = storage,
            .raw = undefined,
            .layers = undefined,
        };
        for (0..3) |lane| {
            const lane_storage = storage[lane * words_per_lane ..][0..words_per_lane];
            result.raw[lane] = lane_storage[0..2];
            var cursor: usize = 2;
            for (&result.layers[lane], LEAF_LAYERS) |*target, profile_layer| {
                const count = 2 * @as(usize, profile_layer.width) * 4;
                target.* = .{
                    .width = profile_layer.width,
                    .values = lane_storage[cursor..][0..count],
                };
                cursor += count;
            }
        }
        return result;
    }

    fn deinit(self: *LeafOpeningFixture) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    fn opening(self: *const LeafOpeningFixture, lane: usize) fri_leaf_witness.OpeningSet {
        return .{
            .raw_queries = self.raw[lane],
            .layers = &self.layers[lane],
        };
    }
};

pub fn splitFlatColumns(
    size: usize,
    storage: []M31,
    columns: anytype,
) void {
    for (columns, 0..) |*column, index|
        column.* = storage[index * size ..][0..size];
}

pub fn commitOrderStorage(
    comptime column_count: usize,
    allocator: std.mem.Allocator,
    logical: []const M31,
    log_size: u32,
) ![]M31 {
    const size = @as(usize, 1) << @intCast(log_size);
    if (logical.len != column_count * size) return error.InvalidProofShape;
    const committed = try allocator.alloc(M31, logical.len);
    for (0..column_count) |column| for (0..size) |logical_row| {
        committed[column * size + framework.committedRow(logical_row, log_size)] =
            logical[column * size + logical_row];
    };
    return committed;
}

pub fn validateLeafRows(
    component: *const FriLeafAdapter,
    rows: []const fri_leaf_relation.Row,
    columns: *const [fri_leaf.INTERACTION_COLUMN_COUNT][]M31,
    log_size: u32,
) !void {
    const size = @as(usize, 1) << @intCast(log_size);
    for (0..size) |logical_row| {
        const committed = framework.committedRow(logical_row, log_size);
        const previous = framework.committedRow(
            (logical_row + size - 1) % size,
            log_size,
        );
        const row = if (logical_row < rows.len)
            rows[logical_row]
        else
            [_]M31{M31.zero()} ** fri_leaf.LOGICAL_INPUT_COUNT;
        var current: [fri_leaf.INTERACTION_BATCH_COUNT]QM31 = undefined;
        for (&current, 0..) |*value, batch| value.* = QM31.fromM31Array(.{
            columns[4 * batch][committed],
            columns[4 * batch + 1][committed],
            columns[4 * batch + 2][committed],
            columns[4 * batch + 3][committed],
        });
        var roots: [FriLeafAdapter.CONSTRAINT_COUNT_TOTAL]QM31 = undefined;
        try component.evaluateBaseRowInto(
            row,
            current,
            QM31.fromM31Array(.{
                columns[4 * (fri_leaf.INTERACTION_BATCH_COUNT - 1)][previous],
                columns[4 * (fri_leaf.INTERACTION_BATCH_COUNT - 1) + 1][previous],
                columns[4 * (fri_leaf.INTERACTION_BATCH_COUNT - 1) + 2][previous],
                columns[4 * (fri_leaf.INTERACTION_BATCH_COUNT - 1) + 3][previous],
            }),
            &roots,
        );
        for (roots, 0..) |root, constraint| if (!root.isZero()) {
            std.debug.print(
                "  row-25 base root failed row={d} constraint={d} root={any}\n",
                .{ logical_row, constraint, root },
            );
            return error.ConstraintsNotSatisfied;
        };
    }
}

pub fn validateNodeRows(
    component: *const FriNodeAdapter,
    rows: []const fri_node_relation.Row,
    columns: *const [fri_node.INTERACTION_COLUMN_COUNT][]M31,
    log_size: u32,
) !void {
    const size = @as(usize, 1) << @intCast(log_size);
    for (0..size) |logical_row| {
        const committed = framework.committedRow(logical_row, log_size);
        const previous = framework.committedRow(
            (logical_row + size - 1) % size,
            log_size,
        );
        const row = if (logical_row < rows.len)
            rows[logical_row]
        else
            [_]M31{M31.zero()} ** fri_node.LOGICAL_INPUT_COUNT;
        var current: [fri_node.INTERACTION_BATCH_COUNT]QM31 = undefined;
        for (&current, 0..) |*value, batch| value.* = QM31.fromM31Array(.{
            columns[4 * batch][committed],
            columns[4 * batch + 1][committed],
            columns[4 * batch + 2][committed],
            columns[4 * batch + 3][committed],
        });
        var roots: [FriNodeAdapter.CONSTRAINT_COUNT_TOTAL]QM31 = undefined;
        try component.evaluateBaseRowInto(
            row,
            current,
            QM31.fromM31Array(.{
                columns[4 * (fri_node.INTERACTION_BATCH_COUNT - 1)][previous],
                columns[4 * (fri_node.INTERACTION_BATCH_COUNT - 1) + 1][previous],
                columns[4 * (fri_node.INTERACTION_BATCH_COUNT - 1) + 2][previous],
                columns[4 * (fri_node.INTERACTION_BATCH_COUNT - 1) + 3][previous],
            }),
            &roots,
        );
        for (roots, 0..) |root, constraint| if (!root.isZero()) {
            std.debug.print(
                "  row-26 base root failed row={d} constraint={d} root={any}\n",
                .{ logical_row, constraint, root },
            );
            return error.ConstraintsNotSatisfied;
        };
    }
}

pub fn diagnoseComposition(
    allocator: std.mem.Allocator,
    scheme: *const Engine.Scheme,
    component: anytype,
    manifest: *const manifest_mod.Manifest,
) !void {
    return diagnoseCompositionAtLog(
        allocator,
        scheme,
        component,
        manifest,
        component.maxConstraintLogDegreeBound(),
    );
}

pub fn diagnoseCompositionAtLog(
    allocator: std.mem.Allocator,
    scheme: *const Engine.Scheme,
    component: anytype,
    manifest: *const manifest_mod.Manifest,
    composition_log_size: u32,
) !void {
    const binding_value = try component.binding(manifest);
    const components = prover_air.ComponentProvers{
        .components = &.{binding_value.prover},
        .n_preprocessed_columns = manifest.total_preprocessed_columns,
    };
    if (composition_log_size < components.compositionLogDegreeBound())
        return error.InvalidProofShape;
    var trace = try scheme.trace(allocator);
    defer trace.polys.deinitDeep(allocator);
    const alpha = QM31.fromU32Unchecked(3, 5, 7, 11);
    var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        alpha,
        composition_log_size,
        component.nConstraints(),
    );
    defer accumulator.deinit();
    try binding_value.prover.evaluateConstraintQuotientsOnDomain(
        &trace,
        &accumulator,
    );
    var evaluation = try accumulator.finalize();
    defer evaluation.deinit(allocator);
    var polynomial = try prover_circle.secure_poly.interpolateFromEvaluation(
        allocator,
        prover_circle.CanonicCoset.new(composition_log_size).circleDomain(),
        &evaluation,
    );
    defer polynomial.deinit(allocator);

    var diagnostic_channel = Engine.Channel{};
    diagnostic_channel.mixU32s(&.{ 0x524f_5732, composition_log_size });
    const point = stwo_core.circle.randomSecureFieldPoint(&diagnostic_channel);
    var view = try components.componentsView(allocator);
    defer view.deinit(allocator);
    const core = view.asCore();
    const split = try components.compositionLogSplit();
    const max_log_degree_bound = composition_log_size - split;
    var mask_points = try core.maskPoints(
        allocator,
        point,
        max_log_degree_bound,
        false,
    );
    defer mask_points.deinitDeep(allocator);
    var mask_values = try evaluateMasks(
        allocator,
        &trace,
        &mask_points,
        max_log_degree_bound,
    );
    defer mask_values.deinitDeep(allocator);
    const domain_value = polynomial.evalAtPoint(point);
    const point_value = try core.evalCompositionPolynomialAtPoint(
        point,
        &mask_values,
        alpha,
        max_log_degree_bound,
    );
    if (!domain_value.eql(point_value)) {
        std.debug.print(
            "  row-25 composition differential: log={d} split={d} domain={any} point={any}\n",
            .{ composition_log_size, split, domain_value, point_value },
        );
        return error.ConstraintsNotSatisfied;
    }
}

pub fn evaluateMasks(
    allocator: std.mem.Allocator,
    trace: *const prover_air.Trace,
    points: *const stwo_core.air.components.MaskPoints,
    lifting_log_size: u32,
) !stwo_core.air.components.MaskValues {
    const trees = try allocator.alloc([][]QM31, points.items.len);
    var tree_count: usize = 0;
    errdefer {
        for (trees[0..tree_count]) |columns| {
            for (columns) |values| allocator.free(values);
            allocator.free(columns);
        }
        allocator.free(trees);
    }
    for (points.items, 0..) |point_columns, tree_index| {
        const columns = try allocator.alloc([]QM31, point_columns.len);
        errdefer allocator.free(columns);
        trees[tree_index] = columns;
        var column_count: usize = 0;
        errdefer for (columns[0..column_count]) |values| allocator.free(values);
        for (point_columns, columns, 0..) |column_points, *values, column_index| {
            values.* = try allocator.alloc(QM31, column_points.len);
            column_count += 1;
            const poly = trace.polys.items[tree_index][column_index];
            const coefficients = poly.coefficients orelse
                return error.InvalidProofShape;
            const column_log_size = coefficients.logSize();
            if (column_log_size > lifting_log_size)
                return error.InvalidProofShape;
            const fold_count = lifting_log_size - column_log_size;
            for (column_points, values.*) |point, *value| value.* =
                coefficients.evalAtPoint(point.repeatedDouble(fold_count));
        }
        tree_count += 1;
    }
    return stwo_core.air.components.MaskValues.initOwned(trees);
}

pub fn commitZeroTree(
    comptime column_count: usize,
    scheme: *Engine.Scheme,
    allocator: std.mem.Allocator,
    log_size: u32,
    channel: *Engine.Channel,
) !void {
    const row_count = @as(usize, 1) << @intCast(log_size);
    const storage = try allocator.alloc(M31, column_count * row_count);
    @memset(storage, M31.zero());
    return commitTree(
        column_count,
        scheme,
        allocator,
        storage,
        log_size,
        channel,
    );
}

pub fn commitTree(
    comptime column_count: usize,
    scheme: *Engine.Scheme,
    allocator: std.mem.Allocator,
    storage: []M31,
    log_size: u32,
    channel: *Engine.Channel,
) !void {
    const row_count = @as(usize, 1) << @intCast(log_size);
    var submitted = false;
    errdefer if (!submitted) allocator.free(storage);
    if (storage.len != column_count * row_count)
        return error.InvalidProofShape;
    const evaluations = try allocator.alloc(prover_pcs.ColumnEvaluation, column_count);
    errdefer if (!submitted) allocator.free(evaluations);
    for (evaluations, 0..) |*evaluation, column| {
        evaluation.* = .{
            .log_size = log_size,
            .values = storage[column * row_count ..][0..row_count],
        };
    }
    const backing_buffers = try allocator.alloc([]M31, 1);
    errdefer if (!submitted) allocator.free(backing_buffers);
    backing_buffers[0] = storage;
    submitted = true;
    try Engine.commitWithBacking(
        scheme,
        allocator,
        evaluations,
        backing_buffers,
        null,
        channel,
    );
}

pub fn fixtureInvocation(direction: u32) merkle_witness.Invocation {
    return .{
        .tree_id = 17,
        .depth = 2,
        .index = 3,
        .child = fixtureDigest(11),
        .step = .{ .direction = direction, .sibling = fixtureDigest(101) },
        .is_leaf = false,
    };
}

pub fn fixtureDigest(start: u32) [merkle.DIGEST_WORD_COUNT]u32 {
    var result: [merkle.DIGEST_WORD_COUNT]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = start + @as(u32, @intCast(index * 7));
    return result;
}

pub fn assertRelationChallengesEqual(
    proving: *const universal.UniversalRelations,
    verifying: *const universal.UniversalRelations,
) void {
    for (proving.elements, verifying.elements) |left, right| {
        std.debug.assert(left.z.eql(right.z));
        std.debug.assert(left.alpha.eql(right.alpha));
        std.debug.assert(left.arity == right.arity);
    }
}

comptime {
    if (PP_COUNT != 20 or MAIN_COUNT != 48 or INTERACTION_COUNT != 28)
        @compileError("rows 29/33 universal proof geometry drifted");
}
