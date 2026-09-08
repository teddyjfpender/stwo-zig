//! Explicit-key parent of two real common-fold proofs. No registry sentinels
//! or grandchild leases are used. The supplied child keys must be trusted;
//! this first nested profile is not production Ethereum/root admission.
const std = @import("std");
const core = @import("stwo_core");
const recursion = @import("stwo_riscv_frontend").recursion;
const detached = @import("recursive_common_fold_detached_transcript_v2.zig");
const verifier = @import("recursive_common_fold_detached_verifier_v2.zig");
const public = @import("recursive_field_node_public_v2.zig");
const field = @import("recursive_common_fold_field_public_v2.zig");
const fixed_source = @import("recursive_common_fold_fixed_wire_v2.zig");
const manifest = @import("recursive_common_fold_universal_manifest_v2.zig");
const protocol_mod = @import("recursive_temporal_secure_parent_protocol_v1.zig");
const rows = @import("recursive_secure_transcript_rows_v1.zig");
const graph_mod = @import("recursive_common_fold_composition_graph_v2.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Sha256 = std.crypto.hash.sha2.Sha256;
pub const PRODUCTION_ACTIVATION = false;

// Derived from the successfully verified schema-15 bootstrap capture. Every
// child is checked against this selector before fixed-wire storage is allocated.
pub const DIMENSIONS: recursion.fixed_wire.Dimensions = .{
    .commitment_count = 4,
    .claimed_sum_count = 36,
    .sampled_value_count = 2520,
    .queried_value_count = 457796,
    .trace_path_count = 772,
    .fri_layer_count = 6,
    .query_count = 193,
    .maximum_fold_width = 16,
    .last_layer_coefficient_count = 1,
    .maximum_merkle_depth = 22,
};
const FRI_WIDTHS = [_]u8{ 16, 16, 16, 16, 16, 2 };
const FRI_DEPTHS = [_]u8{ 18, 14, 10, 6, 2, 1 };

/// Private storage makes verified child witness ownership immutable to users
/// of this adapter. Borrowed projections remain valid until deinit.
pub const Child = opaque {
    pub fn init(allocator: std.mem.Allocator, key: *const verifier.Key, node: *const public.NodePublicV2, claims: *const verifier.Claims, nonce: u64, proof: []const u8) !*Child {
        const value = try allocator.create(ChildStorage);
        errdefer allocator.destroy(value);
        value.witness = try detached.Owned.init(allocator, key, node, claims, nonce, proof);
        errdefer value.witness.deinit();
        try validateShape(&value.witness);
        value.composition = try detached.Composition.init(allocator, &value.witness);
        errdefer value.composition.deinit();
        value.nonce = .{ .interaction_pow_nonce = nonce };
        const inputs = try std.json.Stringify.valueAlloc(allocator, .{ .key = key.*, .node = node.*, .claims = claims.*, .nonce = nonce }, .{});
        defer allocator.free(inputs);
        var hash = Sha256.init(.{});
        hash.update("stwo-zig/detached-fold-child/v2\x00");
        hash.update(inputs);
        hash.update(proof);
        hash.update(&value.witness.execution.identity_sha256);
        hash.update(&value.composition.program.circuit.identity_digest);
        value.identity = hash.finalResult();
        return @ptrCast(value);
    }

    pub fn deinit(self: *Child) void {
        const value: *ChildStorage = @ptrCast(@alignCast(self));
        const allocator = value.witness.allocator;
        value.composition.deinit();
        value.witness.deinit();
        allocator.destroy(value);
    }

    fn storage(self: *const Child) *const ChildStorage {
        return @ptrCast(@alignCast(self));
    }
};

const Nonce = struct { interaction_pow_nonce: u64 };
const ChildStorage = struct {
    witness: detached.Owned,
    composition: detached.Composition,
    nonce: Nonce,
    identity: [32]u8,
};

const Projection = struct {
    role: @import("recursive_common_fold_child_capability_v2.zig").Role = .common_fold_field_v2,
    node_public: *const public.NodePublicV2,
    claimed_sums: []const QM31,
    capture: *const verifier.ProofCapture,
    statement: *const Nonce,
    query_words: *const [193]M31,
    query_words_identity_sha256: *const [32]u8,
    graph: @import("recursive_common_fold_child_capability_v2.zig").ProjectionGraphV2,
};

fn project(child: *const Child) Projection {
    const value = child.storage();
    const witness = &value.witness;
    const composition = &value.composition;
    return .{
        .node_public = &witness.node,
        .claimed_sums = &witness.claims.values,
        .capture = &witness.capture,
        .statement = &value.nonce,
        .query_words = &witness.query_words,
        .query_words_identity_sha256 = &value.identity,
        .graph = .{
            .capture_identity_sha256 = &value.identity,
            .layout_identity_sha256 = &composition.layout.identity,
            .query_words = &witness.query_words,
            .query_log_size = witness.query_log_size,
            .final_transcript_digest = &witness.execution.final_digest,
            .final_transcript_draw_count = witness.execution.final_draw_count,
            .query_words_identity_sha256 = &value.identity,
            .lane = .{
                .verifier_id = recursion.binary_fri_outer_source.LEFT_RECURSION_VERIFIER_ID,
                .circuit_id = @import("recursive_common_fold_composition_capture_v2.zig").CIRCUIT_ID,
                .statement_scope = recursion.binary_fri_outer_source.LEFT_COMPOSITION_STATEMENT_SCOPE,
                .graph = composition.program.circuit.graph(),
                .profile = composition.profile.graphProfile(),
                .bindings = composition.program.bindings,
            },
            .evaluation = .{ .circuit_identity = composition.program.circuit.identity_digest, .values = composition.values },
        },
    };
}

const Input = struct {
    parent_coordinate: @import("recursive_node_artifact_v2.zig").TaskCoordinateV1,
    node: public.NodePublicV2,
    pub fn outputNodePublic(self: *const Input) *const public.NodePublicV2 {
        return &self.node;
    }
};

pub const Live = struct {
    pub const FoldChild = *const Child;
    pub const CapturedFriPair = @import("recursive_common_fold_universal_cohort_v2.zig").CapturedFriPairV2;
    children: [2]*const Child,
    input: Input,
    public_schedule: field.PoseidonScheduleV2,
    identity_sha256: [32]u8,

    pub fn init(children: [2]*const Child) !Live {
        const left = &children[0].storage().witness.node;
        const right = &children[1].storage().witness.node;
        const coordinate = try @import("recursive_node_artifact_v2.zig").TaskCoordinateV1.init(try std.math.add(u8, left.coordinate.height, 1), left.coordinate.index / 2);
        const schedule = try field.PoseidonScheduleV2.build(left, right, coordinate);
        var result = Live{ .children = children, .input = .{ .parent_coordinate = coordinate, .node = schedule.parent }, .public_schedule = schedule, .identity_sha256 = undefined };
        result.identity_sha256 = result.identity();
        try result.validate();
        return result;
    }

    pub fn validate(self: *const Live) !void {
        if (self.children[0] == self.children[1] or !std.meta.eql(self.children[0].storage().witness.key, self.children[1].storage().witness.key)) return error.DetachedFoldChildMismatch;
        try self.public_schedule.validateAgainst(&self.children[0].storage().witness.node, &self.children[1].storage().witness.node, self.input.parent_coordinate);
        if (!std.meta.eql(self.input.node, self.public_schedule.parent) or !std.meta.eql(self.identity_sha256, self.identity())) return error.DetachedFoldChildMismatch;
    }

    pub fn requireFixedWireSource(self: *const Live) !void {
        try self.validate();
        for (self.children) |child| try validateShape(&child.storage().witness);
    }

    pub fn initCapturedFriPair(self: *const Live, allocator: std.mem.Allocator) !CapturedFriPair {
        try self.requireFixedWireSource();
        const protocol = protocol_mod.AuthorityV1.secureParent();
        const profile = recursion.captured_fri.ProfileConfig{ .log_blowup_factor = protocol.fri_log_blowup_factor, .log_last_layer_degree_bound = protocol.fri_log_last_layer_degree_bound, .interaction_pow_bits = protocol.interaction_pow_bits, .pcs_pow_bits = protocol.pcs_pow_bits, .claimed_sum_count = 36 };
        var left = try recursion.captured_fri.Owned.init(allocator, profile, &self.children[0].storage().witness.capture);
        errdefer left.deinit();
        const right = try recursion.captured_fri.Owned.init(allocator, profile, &self.children[1].storage().witness.capture);
        return .{ .children = .{ left, right } };
    }

    pub fn authenticatedCompositionLanes(self: *const Live) ![2]recursion.binary_fri_outer_source.AuthenticatedCompositionLane {
        try self.validate();
        var result: [2]recursion.binary_fri_outer_source.AuthenticatedCompositionLane = undefined;
        for (self.children, &result, 0..) |child, *lane, index| {
            const graph = project(child).graph;
            lane.* = .{ .circuit_id = if (index == 0) 761 else 762, .circuit_identity = graph.lane.graph.identity_digest, .graph = graph.lane.graph, .evaluation = graph.evaluation };
            try lane.validate();
        }
        return result;
    }

    fn identity(self: *const Live) [32]u8 {
        var hash = Sha256.init(.{});
        hash.update("stwo-zig/detached-fold-parent/v2\x00");
        for (self.children) |child| hash.update(&child.storage().identity);
        return hash.finalResult();
    }
};

const ParentRootPin = struct {
    identity_sha256: [32]u8,
    pub fn validateAgainst(self: ParentRootPin, live: *const Live) !void {
        try live.validate();
        if (!std.meta.eql(self.identity_sha256, live.identity_sha256)) return error.DetachedFoldChildMismatch;
    }
};

const FixedPolicy = struct {
    pub const RootPin = ParentRootPin;
    pub fn initRootPin(live: *const Live) !RootPin {
        try live.requireFixedWireSource();
        return .{ .identity_sha256 = live.identity_sha256 };
    }
    pub fn validateRootPin(pin: RootPin, live: *const Live) !void {
        try pin.validateAgainst(live);
    }
    pub fn validateDimensions(comptime dimensions: recursion.fixed_wire.Dimensions, live: *const Live) !void {
        try live.requireFixedWireSource();
        if (!std.meta.eql(dimensions, DIMENSIONS)) return error.DetachedFoldShapeMismatch;
    }
    pub fn projectChild(child: *const Child, live: *const Live) !Projection {
        if (child != live.children[0] and child != live.children[1]) return error.DetachedFoldChildMismatch;
        return project(child);
    }
    pub fn transcriptView(child: *const Child, live: *const Live) !rows.View {
        _ = try projectChild(child, live);
        return child.storage().witness.view();
    }
    pub fn validateChildCustody(actual: Projection, expected: Projection, _: *const Live) !void {
        if (!std.meta.eql(actual, expected)) return error.DetachedFoldChildMismatch;
    }
};

pub const Fixed = fixed_source.TypesForLive(DIMENSIONS, Live, FixedPolicy);
pub const ManifestPolicy = manifest.DerivedPolicyForLive(Live, Fixed, "stwo-zig/detached-fold-manifest/v2\x00");
pub const Cohort = @import("recursive_common_fold_secure_cohort_v2.zig").CohortForLiveV2(DIMENSIONS, Live, Fixed, ManifestPolicy);
pub const Graph = graph_mod.TypesForCohort(DIMENSIONS, Cohort);
pub const Kernel = Graph.KernelV2;

fn validateShape(witness: *const detached.Owned) !void {
    const capture = &witness.capture;
    if (witness.program.kind != .common_fold or capture.commitments.len != DIMENSIONS.commitment_count or witness.claims.values.len != DIMENSIONS.claimed_sum_count or capture.sampled_values.len != DIMENSIONS.sampled_value_count or capture.queried_values.len != DIMENSIONS.queried_value_count or capture.trace_paths.len * DIMENSIONS.query_count != DIMENSIONS.trace_path_count or capture.fri.layers.len != DIMENSIONS.fri_layer_count or capture.last_layer_coefficients.len != DIMENSIONS.last_layer_coefficient_count or witness.query_log_size != DIMENSIONS.maximum_merkle_depth) return error.DetachedFoldShapeMismatch;
    for (capture.trace_paths) |path| if (path.path_depth > DIMENSIONS.maximum_merkle_depth) return error.DetachedFoldShapeMismatch;
    for (capture.fri.layers, FRI_WIDTHS, FRI_DEPTHS) |layer, width, depth|
        if (layer.fold_width != width or layer.path_depth != depth) return error.DetachedFoldShapeMismatch;
}

fn loadSibling(allocator: std.mem.Allocator, directory: std.fs.Dir, index: u32) !*Child {
    const transport = @import("recursive_common_fold_verifier_command_v2.zig");
    var name_buffer: [10]u8 = undefined;
    var dir = try directory.openDir(try std.fmt.bufPrint(&name_buffer, "{d}", .{index}), .{});
    defer dir.close();
    const key_bytes = try dir.readFileAlloc(allocator, "key.json", 1024 * 1024);
    defer allocator.free(key_bytes);
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "d851a6465f6edb02cbeb8a3bc8173b40b86ad6642e07b791478e8b08975a9b37");
    const key = try transport.decodeKey(allocator, key_bytes, expected);
    const input_bytes = try dir.readFileAlloc(allocator, "inputs.json", 1024 * 1024);
    defer allocator.free(input_bytes);
    const inputs = try transport.decodeInputs(allocator, input_bytes);
    if (inputs.node.coordinate.height != 1 or inputs.node.coordinate.index != index) return error.DetachedFoldChildMismatch;
    const proof = try dir.readFileAlloc(allocator, "proof.bin", inputs.proof_bytes);
    defer allocator.free(proof);
    var digest: [32]u8 = undefined;
    Sha256.hash(proof, &digest, .{});
    if (proof.len != inputs.proof_bytes or !std.meta.eql(digest, inputs.proof_sha256)) return error.VerifierProofIdentityMismatch;
    return Child.init(allocator, &key, &inputs.node, &inputs.claims, inputs.interaction_pow_nonce, proof);
}

test "detached fold siblings close the actual parent constraint source" {
    const allocator = std.testing.allocator;
    const directory = try std.process.getEnvVarOwned(allocator, "STWO_RECURSION_SIBLING_DIR");
    defer allocator.free(directory);
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    const left = try loadSibling(allocator, dir, 106);
    defer left.deinit();
    const right = try loadSibling(allocator, dir, 107);
    defer right.deinit();
    const live = try Live.init(.{ left, right });
    try std.testing.expectEqual(@as(u8, 2), live.input.parent_coordinate.height);
    try std.testing.expectEqual(@as(u32, 53), live.input.parent_coordinate.index);
    if (Live.init(.{ right, left })) |_| return error.ReversedSiblingsAccepted else |_| {}
    if (Live.init(.{ left, left })) |_| return error.DuplicateSiblingAccepted else |_| {}
    var cohort = try Cohort.init(allocator, .{ .live = &live });
    defer cohort.deinit();
    const relations = recursion.air.universal_challenges.UniversalRelations.dummy();
    const providers = try recursion.air.universal_shared_provider.SharedProviderRelations.init(&relations);
    const generated = try cohort.rebuildGeneratedInteractions(&relations, &providers);
    var components = try cohort.initComponents(&generated, &relations, &providers);
    defer components.deinit();
    const claims = try cohort.claimVector(&generated);
    const audited = try cohort.auditGlobalClosureV2(&generated, &claims, &relations, &providers);
    try audited.validate();
    for (audited.suffix_input_boundary.domains) |boundary| {
        try std.testing.expectEqual(@as(u32, 0), boundary.tuple_count);
        try std.testing.expect(boundary.claimed_sum.isZero());
    }
    std.debug.print("DETACHED_FOLD_PARENT_SOURCE coordinate=2/53 components=36 closure_verified=true native_suffix_tuples=0 grandchild_inputs=false\n", .{});
}

test "detached fold siblings prove a parent and verify after producer destruction" {
    const allocator = std.testing.allocator;
    const directory = try std.process.getEnvVarOwned(allocator, "STWO_RECURSION_SIBLING_DIR");
    defer allocator.free(directory);
    var key: verifier.Key = undefined;
    var node: public.NodePublicV2 = undefined;
    var claims: verifier.Claims = undefined;
    var nonce: u64 = undefined;
    var terminal: [8]u32 = undefined;
    var proof_bytes: []u8 = undefined;
    var timer = try std.time.Timer.start();
    {
        var dir = try std.fs.cwd().openDir(directory, .{});
        defer dir.close();
        const left = try loadSibling(allocator, dir, 106);
        defer left.deinit();
        const right = try loadSibling(allocator, dir, 107);
        defer right.deinit();
        const live = try Live.init(.{ left, right });
        node = live.input.node;
        var cohort = try Cohort.init(allocator, .{ .live = &live });
        defer cohort.deinit();
        const session = try cohort.session();
        std.debug.print("DETACHED_FOLD_PARENT_PROVE coordinate=2/53 worker_count=1 preparation_ns={d}\n", .{timer.read()});
        var transaction = try Kernel.proveAndColdVerifyWithReplay(allocator, &cohort, session, .{ .worker_count = 1 });
        defer transaction.deinit();
        const proved = &transaction.result;
        const replay = &transaction.replay;
        var components = try cohort.initComponents(&replay.generated, &replay.relations, &replay.provider_relations);
        defer components.deinit();
        key = .{ .manifest = cohort.manifest().*, .preprocessed_root = proved.fresh.capture.commitments[0], .parameters = undefined, .poseidon_rows = components.suffix.poseidon2.component.n_rows };
        inline for (0..18) |index| key.parameters[index] = components.logical[index].parameters;
        inline for (std.meta.fields(@TypeOf(components.suffix))[0..16], 18..) |component, index|
            key.parameters[index] = @field(components.suffix, component.name).parameters;
        claims = .{ .values = replay.claims.values, .poseidon_partials = replay.generated.suffix.claims.poseidon2_partials };
        nonce = proved.artifact.statement.interaction_pow_nonce;
        terminal = proved.fresh.statement.transcript_id;
        // Retain the proof before later diagnostics, without retaining either
        // child owner, parent witness rows or the producer's capture.
        const output = try std.process.getEnvVarOwned(allocator, "STWO_RECURSION_VERIFIER_EXPORT_DIR");
        defer allocator.free(output);
        const digest = try @import("recursive_common_fold_verifier_command_v2.zig").writeBundle(allocator, output, key, node, claims, nonce, proved.artifact.proof_bytes);
        var expected_key: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected_key, "c9d86ae57770878eec3078e5f912822f3159717930d6aa224672d8b2455474ef");
        try std.testing.expectEqualDeep(expected_key, digest);
        std.debug.print("DETACHED_FOLD_PARENT_EXPORT key_sha256={s} prove_ns={d} cold_verify_ns={d} independent_key_admission=false\n", .{ std.fmt.bytesToHex(digest, .lower), proved.receipt.prove_ns, proved.receipt.cold_verify_ns });
        proof_bytes = try allocator.dupe(u8, proved.artifact.proof_bytes);
    }
    defer allocator.free(proof_bytes);
    const detached_terminal = try verifier.verify(allocator, &key, &node, &claims, nonce, proof_bytes);
    try std.testing.expectEqualDeep(terminal, detached_terminal);
    try std.testing.expectEqual(@as(u8, 2), node.coordinate.height);
    try std.testing.expectEqual(@as(u32, 53), node.coordinate.index);
    var changed_node = node;
    changed_node.output_digest[0] ^= 1;
    if (verifier.verify(allocator, &key, &changed_node, &claims, nonce, proof_bytes)) |_| return error.ChangedParentAccepted else |_| {}
    std.debug.print("DETACHED_FOLD_PARENT_VERIFIED coordinate=2/53 producer_destroyed=true children_destroyed=true proof_bytes={d} request_ns={d}\n", .{ proof_bytes.len, timer.read() });
}
