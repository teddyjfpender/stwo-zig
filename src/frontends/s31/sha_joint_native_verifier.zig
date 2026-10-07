//! Native verifier for one sparse-wide S31 circuit joined to three packed
//! SHA-256 compression calls. The caller supplies the pinned profile and
//! preprocessed root; neither is learned from the proof envelope.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const cairo = @import("stwo_cairo_frontend");
const postcard = @import("interop_postcard");
const sha = @import("s31_sha_provider");
const caller = @import("sha_caller_air.zig");
const profile_mod = @import("sha_joint_profile.zig");
const envelope = @import("sha_joint_envelope.zig");

const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
const Airs = .{ sha.Source, sha.Schedule, sha.Round, sha.FeedForward };
const names = [_][:0]const u8{ "sha_source", "sha_schedule", "sha_round", "sha_feed_forward" };
const Roster = sha.component_roster.ForAirs(Airs, &names);
const pp = circuit.common.sparse_wide;
const sparse_trace = circuit.witness.sparse_wide;
const Column = engine.pcs.ColumnEvaluation;

/// Derived from independently compiled, value-free S31 topology. The root
/// commits the circuit's fixed Gate multiplicities plus canonical SHA/table
/// fixed columns. A proof cannot nominate its own verification key.
pub const Key = struct {
    profile: profile_mod.Profile,
    layout: pp.Layout,
    preprocessed_root: [32]u8,

    pub fn admission(self: *const Key, public_outputs: []const QM31) Admission {
        return .{
            .profile = self.profile,
            .layout = &self.layout,
            .preprocessed_root = self.preprocessed_root,
            .public_outputs = public_outputs,
        };
    }
};

pub fn deriveKey(
    allocator: std.mem.Allocator,
    source_digest: [32]u8,
    topology: *const pp.Circuit,
    n_vars: u32,
    gate_addresses: [profile_mod.gate_address_count]u32,
    pcs: core.pcs.config_v2.PcsConfigV2,
) !Key {
    const boundary = topology.sha_boundary orelse return error.MissingShaBoundary;
    if (!std.meta.eql(boundary.addresses, gate_addresses)) return error.InvalidShaBoundaryKey;
    if (topology.n_outputs != profile_mod.public_output_count)
        return error.InvalidShaJointPublicOutputCount;
    const layout = topology.layout();
    const circuit_logs = [4]u32{
        layout.logSize("eq_in0_address") orelse return error.InvalidShaJointCircuitLayout,
        layout.logSize("qm31_ops_in0_address") orelse return error.InvalidShaJointCircuitLayout,
        layout.logSize("m31_to_u32_input_addr") orelse return error.InvalidShaJointCircuitLayout,
        16,
    };
    const profile = try profile_mod.Profile.canonical(source_digest, circuit_logs, n_vars, gate_addresses, pcs);
    try validateLayout(profile, &layout);
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const a = scratch.allocator();
    var fixed: std.ArrayList(Column) = .empty;
    for (topology.columns) |column|
        try fixed.append(a, .{ .log_size = column.logSize(), .values = column.values });
    try sha.preprocessed.append(a, profile_mod.call_count, false, &fixed);
    for (sha.joint_lookup_kinds) |kind| try sha.row_columns.tablePreprocessed(a, kind, &fixed);
    var channel = MC.Channel{};
    try profile.mixInto(&channel);
    core.channel.lookup_transcript.mixChannelSalt(&channel, 0);
    pcs.fri_config.mixInto(&channel);
    const Engine = cpu.prove.Internal.Engine;
    var scheme = try Engine.initRevision(allocator, pcs);
    defer Engine.deinit(&scheme, allocator);
    scheme.setStorePolynomialsCoefficients();
    const owned = try allocator.alloc(Column, fixed.items.len);
    var copied: usize = 0;
    var transferred = false;
    errdefer if (!transferred) {
        for (owned[0..copied]) |column| allocator.free(column.values);
        allocator.free(owned);
    };
    for (fixed.items, owned) |source, *target| {
        target.* = .{ .log_size = source.log_size, .values = try allocator.dupe(core.fields.m31.M31, source.values) };
        copied += 1;
    }
    try Engine.commit(&scheme, allocator, owned, null, &channel);
    transferred = true; // scheme owns the cloned columns
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    if (scheme.trees.items.len != 1) return error.InvalidShaJointPreprocessedRoot;
    return .{ .profile = profile, .layout = layout, .preprocessed_root = scheme.trees.items[0].commitment.root() };
}

pub const Admission = struct {
    profile: profile_mod.Profile,
    layout: *const pp.Layout,
    preprocessed_root: [32]u8,
    /// Eight source-order M31 words encoded as QM31(low16, high16, 0, 0),
    /// independently supplied by the relying party. Private header/digest
    /// limbs never enter this ABI.
    public_outputs: []const QM31,
};

pub fn verify(allocator: std.mem.Allocator, admission: Admission, raw: []const u8) !void {
    try admission.profile.validate();
    if (admission.public_outputs.len != profile_mod.public_output_count)
        return error.InvalidShaJointPublicOutputCount;
    try validatePublicOutputs(admission.public_outputs);
    try validateLayout(admission.profile, admission.layout);
    const official_air = @embedFile("s31_air_programs");
    try validateOfficialBundleDigest(official_air);
    var template = try cpu.air.parse(allocator, official_air);
    defer template.deinit();
    const decoded = try envelope.decodeHeader(raw, admission.profile, admission.preprocessed_root);
    const claims = decoded.claimed_sums;
    const pcs = admission.profile.pcs;
    const sha_logs = (try sha.Geometry.init(profile_mod.call_count)).logs;
    var logs = [_]std.ArrayList(u32){ .empty, .empty, .empty };
    defer for (&logs) |*list| list.deinit(allocator);
    var pp_logs: [pp.N_COLUMNS]u32 = undefined;
    for (admission.layout.entries, &pp_logs) |entry, *log| log.* = entry.log_size;
    try logs[0].appendSlice(allocator, &pp_logs);
    inline for (Airs, 0..) |Air, i| {
        try logs[0].appendNTimes(allocator, sha_logs[i], Air.PREPROCESSED_COLUMN_COUNT);
    }
    var table_fixed: [profile_mod.table_component_count]usize = undefined;
    for (sha.joint_lookup_kinds, &table_fixed) |kind, *offset| {
        offset.* = logs[0].items.len;
        try logs[0].appendNTimes(allocator, sha.schema.logSize(kind), 1 + sha.schema.arity(kind));
    }
    for (admission.profile.circuit_logs, [_]usize{ 4, 12, 4, 1 }, [_]usize{ 4, 8, 12, 4 }) |log, main_width, interaction_width| {
        try logs[1].appendNTimes(allocator, log, main_width);
        try logs[2].appendNTimes(allocator, log, interaction_width);
    }
    inline for (Airs, 0..) |Air, i| {
        try logs[1].appendNTimes(allocator, sha_logs[i], Air.PHYSICAL_MAIN_COLUMN_COUNT);
        try logs[2].appendNTimes(allocator, sha_logs[i], Air.INTERACTION_COLUMN_COUNT);
    }
    const caller_main_offset = logs[1].items.len;
    const caller_interaction_offset = logs[2].items.len;
    try logs[1].appendNTimes(allocator, caller.log_size, caller.main_width);
    try logs[2].appendNTimes(allocator, caller.log_size, caller.interaction_width);
    const table_main_offset = logs[1].items.len;
    const table_interaction_offset = logs[2].items.len;
    for (sha.joint_lookup_kinds) |kind| {
        try logs[1].append(allocator, sha.schema.logSize(kind));
        try logs[2].appendNTimes(allocator, sha.schema.logSize(kind), 4);
    }

    const decode_memory = try allocator.alloc(u8, envelope.max_proof_bytes);
    defer allocator.free(decode_memory);
    var bounded = std.heap.FixedBufferAllocator.init(decode_memory);
    var stream = std.io.fixedBufferStream(decoded.proof_bytes);
    var stark = try postcard.deserializeProof(H, bounded.allocator(), stream.reader());
    defer stark.deinit(bounded.allocator());
    if (stream.pos != decoded.proof_bytes.len or stark.commitment_scheme_proof.commitments.items.len != 4)
        return error.InvalidShaJointProof;
    if (!std.meta.eql(stark.commitment_scheme_proof.config, core.protocol_revision.Revision.proving_5a7c5ed.legacyView(pcs)))
        return error.InvalidShaJointProofConfig;
    const roots = stark.commitment_scheme_proof.commitments.items;
    if (!std.mem.eql(u8, &admission.preprocessed_root, &roots[0]))
        return error.InvalidShaJointPreprocessedRoot;

    var channel = MC.Channel{};
    try admission.profile.mixInto(&channel);
    core.channel.lookup_transcript.mixChannelSalt(&channel, 0);
    pcs.fri_config.mixInto(&channel);
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(allocator, pcs);
    defer scheme.deinit(allocator);
    try scheme.commit(allocator, roots[0], logs[0].items, &channel);
    MC.mixRoot(&channel, try admission.profile.circuitIdentity(admission.preprocessed_root));
    channel.mixFelts(admission.public_outputs);
    try scheme.commit(allocator, roots[1], logs[1].items, &channel);
    if (!channel.verifyPowNonce(circuit.common.component_list.INTERACTION_POW_BITS, decoded.nonce))
        return error.InvalidShaJointInteractionNonce;
    channel.mixU64(decoded.nonce);
    const gate_challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const vm_relations = try sha.universal.UniversalRelations.draw(allocator, &channel);
    const relations = try sha.sha_relations.draw(allocator, &channel, vm_relations);
    const providers = try sha.shared_provider_relations.SharedProviderRelations.init(&relations);
    const circuit_claims = claims[0..profile_mod.circuit_component_count].*;
    const caller_gate_claim = claims[8];
    if (!(try sparse_trace.lookupSum(admission.public_outputs, circuit_claims, gate_challenge.z, gate_challenge.alpha)).add(caller_gate_claim).isZero())
        return error.InvalidShaJointGateLookupSum;
    var wire_closure = claims[9];
    for (claims[4..8]) |claim| wire_closure = wire_closure.add(claim);
    for (claims[10..]) |claim| wire_closure = wire_closure.add(claim);
    if (!wire_closure.isZero()) return error.InvalidShaJointWireLookupSum;
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &claims);
    try scheme.commit(allocator, roots[2], logs[2].items, &channel);

    var bound = try cpu.air.bindSparseWide(allocator, &template, admission.profile.circuit_logs, admission.layout);
    defer bound.deinit();
    const lifting_bound = pcs.trace_lifting_log_size - pcs.fri_config.log_blowup_factor + 1;
    var captured: [profile_mod.circuit_component_count]cairo.proving.air.component.Component = undefined;
    var handles: [profile_mod.component_count]core.air.components.Component = undefined;
    for (bound.components, &captured, handles[0..4], circuit_claims) |*source, *runtime, *handle, claim| {
        runtime.* = .init(allocator, source, &pp_logs, lifting_bound, gate_challenge.z, gate_challenge.alpha, claim);
        handle.* = runtime.asVerifierComponent();
    }
    const roster_manifest = Roster.Manifest{
        .log_sizes = sha_logs,
        .origin = .{ .columns = .{ pp.N_COLUMNS, sparse_trace.main_width, sparse_trace.interaction_width, 0 }, .claimed_sum_index = 4 },
    };
    const parameters: [4][0]M31 = @splat(.{});
    const sha_owner = try sha.component_owner.ForRoster(Roster).init(
        allocator,
        &roster_manifest,
        parameters,
        relations,
        claims[4..8].*,
    );
    defer sha_owner.deinit();
    @memcpy(handles[4..8], &(try sha_owner.verifierHandles()));
    var caller_component = caller.Component{
        .main_offset = caller_main_offset,
        .interaction_offset = caller_interaction_offset,
        .config = .{ .gate_addresses = admission.profile.gate_addresses, .first_call_id = profile_mod.first_call_id },
        .gate_elements = caller.Elements.init(gate_challenge.z, gate_challenge.alpha),
        .wire_elements = caller.Elements.init(relations.get(.recursion_wire).z, relations.get(.recursion_wire).alpha),
        .gate_claimed_sum = claims[8],
        .sha_claimed_sum = claims[9],
    };
    handles[8] = caller_component.asVerifierComponent();
    var tables: [profile_mod.table_component_count]sha.LookupTableVerifier = undefined;
    for (&tables, sha.joint_lookup_kinds, table_fixed, 0..) |*table, kind, fixed_offset, i| {
        var indices: [sha.schema.MAX_ARITY]usize = undefined;
        for (indices[0..sha.schema.arity(kind)], 0..) |*index, j| index.* = fixed_offset + 1 + j;
        table.* = try sha.LookupTableVerifier.initVerifier(
            kind,
            fixed_offset,
            indices[0..sha.schema.arity(kind)],
            table_main_offset + i,
            table_interaction_offset + 4 * i,
            &providers.native,
            claims[10 + i],
        );
        handles[9 + i] = try sha.component_geometry.ForAirs(Airs).table(table.asVerifierComponent());
    }
    var capture: core.verifier.ProofCapture(H) = undefined;
    try core.verifier.verifyBorrowedExWithProofCapture(H, MC, allocator, &handles, &channel, &scheme, &stark, true, &capture);
    defer capture.deinit(allocator);
}

/// The verifier parses only these pinned bytes. This helper makes the bundle
/// admission rule independently testable with a one-bit mutation.
pub fn validateOfficialBundleDigest(bytes: []const u8) !void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    const pinned = profile_mod.circuitAirDigest();
    if (!std.mem.eql(u8, &hex, cpu.air.bundle_sha256) or
        !std.mem.eql(u8, &digest, &pinned))
        return error.InvalidShaJointCircuitAir;
}

fn validateLayout(profile: profile_mod.Profile, layout: *const pp.Layout) !void {
    const logs = profile.circuit_logs;
    const expected = try pp.Layout.fromSizes(
        @as(usize, 1) << @intCast(logs[0]),
        @as(usize, 1) << @intCast(logs[1]),
        @as(usize, 1) << @intCast(logs[2]),
    );
    for (layout.entries, expected.entries) |actual, want| {
        if (actual.log_size != want.log_size or !std.mem.eql(u8, actual.id, want.id))
            return error.InvalidShaJointCircuitLayout;
    }
}

fn validatePublicOutputs(outputs: []const QM31) !void {
    for (outputs) |output| {
        const limbs = output.toM31Array();
        if (limbs[0].toU32() >= 1 << 16 or limbs[1].toU32() >= 1 << 16 or
            limbs[2].toU32() != 0 or limbs[3].toU32() != 0 or
            (@as(u64, limbs[0].toU32()) + (@as(u64, limbs[1].toU32()) << 16)) >= core.fields.m31.Modulus)
            return error.InvalidShaJointPublicOutputEncoding;
    }
}
