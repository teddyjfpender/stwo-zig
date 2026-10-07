//! One PCS/FRI proof for a sparse-wide S31 circuit and fused SHA256d AIR.
//! The Gate and five SHA word claims close before the interaction commitment.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const cairo = @import("stwo_cairo_frontend");
const postcard = @import("interop_postcard");
const shared = @import("sha_fused_circuit_profile.zig");
const direct = @import("sha_fused_private_join_profile.zig");
const direct_prover = @import("sha_fused_private_join_prover.zig");
const native_fixed = @import("sha_fused_circuit_native_verifier.zig");
const word_bus = @import("sha_direct_word_bus.zig");

const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const Engine = cpu.prove.Internal.Engine;
const Column = engine.pcs.ColumnEvaluation;
const sparse_trace = shared.sparse_trace;

pub const Request = struct {
    source_digest: [32]u8,
    n_vars: u32,
    statement: direct.PublicStatement,
    header: [80]u8,
    prepared_fixed: ?*const PreparedFixed = null,
    metrics: ?*Metrics = null,
};
pub const Metrics = struct {
    witness_ns: u64 = 0,
    fixed_commit_ns: u64 = 0,
    main_commit_ns: u64 = 0,
    interaction_pow_ns: u64 = 0,
    interaction_ns: u64 = 0,
    interaction_commit_ns: u64 = 0,
    fri_ns: u64 = 0,
    fri_pow_ns: u64 = 0,
    composition_eval_ns: u64 = 0,
    composition_interpolate_ns: u64 = 0,
    composition_commit_ns: u64 = 0,
    sampled_value_eval_ns: u64 = 0,
    fri_quotient_commit_ns: u64 = 0,
    fri_decommit_ns: u64 = 0,
    trace_decommit_ns: u64 = 0,
    fixed_columns: usize = 0,
    main_columns: usize = 0,
    interaction_columns: usize = 0,
};

fn findStageSeconds(nodes: []const engine.stage_profile.StageNode, id: []const u8) ?f64 {
    for (nodes) |node| {
        if (std.mem.eql(u8, node.id, id)) return node.seconds;
        if (node.children) |children| if (findStageSeconds(children, id)) |seconds| return seconds;
    }
    return null;
}
pub const Proof = struct {
    allocator: std.mem.Allocator,
    key: shared.Key,
    outputs: []QM31,
    nonce: u64,
    claims: [shared.claim_count]QM31,
    stark: core.proof.ExtendedStarkProof(shared.MC.MerkleHasher),

    pub fn deinit(self: *Proof) void {
        self.stark.deinit(self.allocator);
        self.allocator.free(self.outputs);
        self.* = undefined;
    }
};

fn cloneColumns(allocator: std.mem.Allocator, source: []const Column) ![]Column {
    const result = try allocator.alloc(Column, source.len);
    var ready: usize = 0;
    errdefer {
        for (result[0..ready]) |column| allocator.free(column.values);
        allocator.free(result);
    }
    for (source, result) |column, *slot| {
        slot.* = .{ .log_size = column.log_size, .values = try allocator.dupe(M31, column.values) };
        ready += 1;
    }
    return result;
}

fn commit(scheme: *Engine.Scheme, allocator: std.mem.Allocator, columns: []const Column, channel: *shared.MC.Channel) !void {
    try Engine.commit(scheme, allocator, try cloneColumns(allocator, columns), null, channel);
    try Engine.flushPendingCommit(scheme, allocator, channel);
}

/// Reusable canonical fixed-column commitment. The digest compares every
/// column value and log size with the proving topology before leasing its
/// Merkle tree. A trusted verifier still derives its own fixed root.
pub const PreparedFixed = struct {
    tree: Engine.Scheme.CommitmentTree,
    pcs: core.pcs.config_v2.PcsConfigV2,
    columns_digest: [32]u8,

    pub fn build(allocator: std.mem.Allocator, topology: *const shared.pp.Circuit, statement: direct.PublicStatement, pcs: core.pcs.config_v2.PcsConfigV2) !PreparedFixed {
        try statement.validate();
        if (statement.digest_visibility != .private) return error.PublicDigestForbiddenInFusedCircuitV4;
        const boundary = topology.sha_boundary orelse return error.MissingShaBoundary;
        if (!std.meta.eql(boundary.addresses, statement.config.gate_addresses) or topology.n_outputs != 8)
            return error.InvalidDirectCircuitTopology;
        const columns = try native_fixed.canonicalFixedColumns(allocator, topology, statement);
        defer native_fixed.freeCanonicalFixedColumns(allocator, columns);
        var scheme = try Engine.initRevision(allocator, pcs);
        defer Engine.deinit(&scheme, allocator);
        scheme.setStorePolynomialsCoefficients();
        var channel = shared.MC.Channel{};
        try commit(&scheme, allocator, columns, &channel);
        if (scheme.trees.items.len != 1) return error.InvalidDirectCircuitFixedTree;
        try scheme.trees.items[0].share(allocator);
        return .{
            .tree = scheme.trees.pop().?,
            .pcs = pcs,
            .columns_digest = fixedColumnsDigest(columns),
        };
    }

    pub fn deinit(self: *PreparedFixed, allocator: std.mem.Allocator) void {
        self.tree.deinit(allocator);
        self.* = undefined;
    }

    pub fn root(self: *const PreparedFixed) [32]u8 {
        return self.tree.root();
    }

    fn check(self: *const PreparedFixed, pcs: core.pcs.config_v2.PcsConfigV2, columns: []const Column) !void {
        if (!std.meta.eql(self.pcs, pcs) or !std.mem.eql(u8, &self.columns_digest, &fixedColumnsDigest(columns)))
            return error.PreparedShaFixedMismatch;
    }
};

fn fixedColumnsDigest(columns: []const Column) [32]u8 {
    comptime std.debug.assert(@sizeOf(M31) == @sizeOf(u32));
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var word: [4]u8 = undefined;
    std.mem.writeInt(u32, &word, @intCast(columns.len), .little);
    hasher.update(&word);
    for (columns) |column| {
        std.mem.writeInt(u32, &word, column.log_size, .little);
        hasher.update(&word);
        hasher.update(std.mem.sliceAsBytes(column.values));
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

pub fn prove(allocator: std.mem.Allocator, values: []const QM31, topology: *const shared.pp.Circuit, template: *const cpu.air.Bundle, pcs: core.pcs.config_v2.PcsConfigV2, request: Request) !Proof {
    var stage_timer = try std.time.Timer.start();
    try request.statement.validate();
    if (request.statement.digest_visibility != .private) return error.PublicDigestForbiddenInFusedCircuitV4;
    if (values.len != request.n_vars) return error.InvalidDirectCircuitVariableCount;
    const boundary = topology.sha_boundary orelse return error.MissingShaBoundary;
    if (!std.meta.eql(boundary.addresses, request.statement.config.gate_addresses) or topology.n_outputs != 8)
        return error.InvalidDirectCircuitTopology;
    const circuit_layout = topology.layout();
    var key = shared.Key{
        .source_digest = request.source_digest,
        .statement = request.statement,
        .n_vars = request.n_vars,
        .circuit_logs = .{
            circuit_layout.logSize("eq_in0_address") orelse return error.InvalidDirectCircuitLayout,
            circuit_layout.logSize("qm31_ops_in0_address") orelse return error.InvalidDirectCircuitLayout,
            circuit_layout.logSize("m31_to_u32_input_addr") orelse return error.InvalidDirectCircuitLayout,
            16,
        },
        .circuit_layout = circuit_layout,
        .pcs = pcs,
        .fixed_root = undefined,
        .digest = undefined,
    };
    var sha_witness = try direct_prover.Witness.init(allocator, request.header, request.statement);
    defer sha_witness.deinit();
    var circuit_witness = try sparse_trace.writeBase(allocator, values, topology);
    defer circuit_witness.deinit();
    try shared.validatePublicOutputs(circuit_witness.output_values);
    const sha_fixed = try sha_witness.fixedColumns(allocator);
    defer allocator.free(sha_fixed);
    const sha_main = try sha_witness.mainColumns(allocator);
    defer allocator.free(sha_main);
    const fixed = try allocator.alloc(Column, shared.pp.N_COLUMNS + sha_fixed.len);
    defer allocator.free(fixed);
    for (topology.columns, fixed[0..shared.pp.N_COLUMNS]) |entry, *slot|
        slot.* = .{ .log_size = entry.logSize(), .values = entry.values };
    @memcpy(fixed[shared.pp.N_COLUMNS..], sha_fixed);
    const main = try allocator.alloc(Column, sparse_trace.main_width + sha_main.len);
    defer allocator.free(main);
    @memcpy(main[0..sparse_trace.main_width], circuit_witness.columns);
    @memcpy(main[sparse_trace.main_width..], sha_main);
    if (request.metrics) |metrics| {
        metrics.witness_ns = stage_timer.lap();
        metrics.fixed_columns = fixed.len;
        metrics.main_columns = main.len;
    }
    var channel = shared.MC.Channel{};
    shared.mixProfile(&channel, key);
    var scheme = try Engine.initRevision(allocator, pcs);
    var scheme_owned = true;
    errdefer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setStorePolynomialsCoefficients();
    if (request.prepared_fixed) |cached| {
        try cached.check(pcs, fixed);
        var lease = cached.tree.retainShared();
        scheme.appendCommittedTree(allocator, lease, &channel) catch |err| {
            lease.deinit(allocator);
            return err;
        };
    } else try commit(&scheme, allocator, fixed, &channel);
    if (request.metrics) |metrics| metrics.fixed_commit_ns = stage_timer.lap();
    key.fixed_root = scheme.trees.items[0].commitment.root();
    key.digest = shared.keyDigest(key);
    try key.validate();
    shared.MC.mixRoot(&channel, key.identity());
    channel.mixFelts(circuit_witness.output_values);
    try commit(&scheme, allocator, main, &channel);
    if (request.metrics) |metrics| metrics.main_commit_ns = stage_timer.lap();
    var interaction_pow_timer = try std.time.Timer.start();
    const nonce = channel.grind(circuit.common.component_list.INTERACTION_POW_BITS);
    if (request.metrics) |metrics| metrics.interaction_pow_ns = interaction_pow_timer.read();
    channel.mixU64(nonce);
    const gate_challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const word_challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    var circuit_interaction = try sparse_trace.writeInteraction(allocator, &circuit_witness, topology, gate_challenge.z, gate_challenge.alpha);
    defer circuit_interaction.deinit();
    var sha_interaction = try sha_witness.writeInteractions(
        word_bus.Elements.init(gate_challenge.z, gate_challenge.alpha),
        word_bus.Elements.init(word_challenge.z, word_challenge.alpha),
    );
    defer sha_interaction.deinit();
    const sha_claims = sha_interaction.claims();
    try sha_claims.validate();
    if (!(try sparse_trace.lookupSum(circuit_witness.output_values, circuit_interaction.claimed_sums, gate_challenge.z, gate_challenge.alpha)).add(sha_claims.gate).isZero())
        return error.InvalidDirectCircuitGateClosure;
    const sha_interaction_columns = try sha_interaction.columns(allocator);
    defer allocator.free(sha_interaction_columns);
    const interaction = try allocator.alloc(Column, sparse_trace.interaction_width + sha_interaction_columns.len);
    defer allocator.free(interaction);
    @memcpy(interaction[0..sparse_trace.interaction_width], circuit_interaction.columns);
    @memcpy(interaction[sparse_trace.interaction_width..], sha_interaction_columns);
    if (request.metrics) |metrics| {
        metrics.interaction_ns = stage_timer.lap();
        metrics.interaction_columns = interaction.len;
    }
    const claims = circuit_interaction.claimed_sums ++ [_]QM31{sha_claims.gate} ++ sha_claims.word;
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &claims);
    try commit(&scheme, allocator, interaction, &channel);
    if (request.metrics) |metrics| metrics.interaction_commit_ns = stage_timer.lap();

    const layout = circuit_layout;
    var bound = try cpu.air.bindSparseWide(allocator, template, circuit_witness.log_sizes, &layout);
    defer bound.deinit();
    var pp_logs: [shared.pp.N_COLUMNS]u32 = undefined;
    for (layout.entries, &pp_logs) |entry, *log| log.* = entry.log_size;
    const lifting = pcs.trace_lifting_log_size - pcs.fri_config.log_blowup_factor + 1;
    var captured: [shared.circuit_components]cairo.proving.air.component.Component = undefined;
    var handles: [shared.component_count]engine.air.component_prover.ComponentProver = undefined;
    for (bound.components, &captured, handles[0..4], circuit_interaction.claimed_sums) |*source, *runtime, *handle, claim| {
        runtime.* = .init(allocator, source, &pp_logs, lifting, gate_challenge.z, gate_challenge.alpha, claim);
        runtime.native_executor = null;
        handle.* = try runtime.asProverComponent().withCompositionGeometryOverrideV1(.{
            .max_constraint_log_degree_bound_delta = 1,
            .composition_log_split = 2,
        });
    }
    var sha_components = direct.Components.init(
        request.statement,
        sha_claims,
        word_bus.Elements.init(gate_challenge.z, gate_challenge.alpha),
        word_bus.Elements.init(word_challenge.z, word_challenge.alpha),
        direct.Layout.init(shared.shaPrefix()),
    );
    const sha_handles = sha_components.proverHandles();
    @memcpy(handles[4..], &sha_handles);
    for (handles[4..]) |*handle| handle.* = try handle.withCompositionGeometryOverrideV1(.{
        .max_constraint_log_degree_bound_delta = 0,
        .composition_log_split = 2,
    });
    var recorder = engine.stage_profile.Recorder.initWithOptions(allocator, "s31_sha_fused_circuit", "prove", .{ .capture_tasks = false });
    defer recorder.deinit();
    scheme_owned = false;
    var stark = try Engine.prove(allocator, &handles, &channel, scheme, .{
        .include_all_preprocessed_columns = true,
        .recorder = if (request.metrics != null) &recorder else null,
    });
    if (request.metrics) |metrics| {
        metrics.fri_ns = stage_timer.lap();
        var stages = try recorder.snapshot(allocator);
        defer stages.deinit(allocator);
        metrics.fri_pow_ns = @intFromFloat((findStageSeconds(stages.stages, "proof_of_work") orelse 0) * std.time.ns_per_s);
        metrics.composition_eval_ns = @intFromFloat((findStageSeconds(stages.stages, "composition_evaluation") orelse 0) * std.time.ns_per_s);
        metrics.composition_interpolate_ns = @intFromFloat((findStageSeconds(stages.stages, "composition_interpolate_and_split") orelse 0) * std.time.ns_per_s);
        metrics.composition_commit_ns = @intFromFloat((findStageSeconds(stages.stages, "composition_commit") orelse 0) * std.time.ns_per_s);
        metrics.sampled_value_eval_ns = @intFromFloat((findStageSeconds(stages.stages, "sampled_value_evaluation") orelse 0) * std.time.ns_per_s);
        metrics.fri_quotient_commit_ns = @intFromFloat((findStageSeconds(stages.stages, "fri_quotient_build_and_commit") orelse 0) * std.time.ns_per_s);
        metrics.fri_decommit_ns = @intFromFloat((findStageSeconds(stages.stages, "fri_decommit") orelse 0) * std.time.ns_per_s);
        metrics.trace_decommit_ns = @intFromFloat((findStageSeconds(stages.stages, "trace_decommit") orelse 0) * std.time.ns_per_s);
    }
    errdefer stark.deinit(allocator);
    return .{
        .allocator = allocator,
        .key = key,
        .outputs = try allocator.dupe(QM31, circuit_witness.output_values),
        .nonce = nonce,
        .claims = claims,
        .stark = stark,
    };
}

pub fn serialize(allocator: std.mem.Allocator, proof: *const Proof) ![]u8 {
    try proof.key.validate();
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try bytes.appendSlice(allocator, shared.magic);
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, proof.nonce, .little);
    try bytes.appendSlice(allocator, &encoded);
    for (proof.claims) |claim| {
        for (claim.toM31Array()) |limb| {
            var part: [4]u8 = undefined;
            std.mem.writeInt(u32, &part, limb.toU32(), .little);
            try bytes.appendSlice(allocator, &part);
        }
    }
    try bytes.appendSlice(allocator, &proof.key.digest);
    try postcard.serializeProof(shared.MC.MerkleHasher, bytes.writer(allocator), proof.stark.proof);
    return bytes.toOwnedSlice(allocator);
}
