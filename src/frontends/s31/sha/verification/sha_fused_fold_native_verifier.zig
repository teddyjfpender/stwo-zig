//! Native verifier for one Bitcoin fold circuit and fused SHA256d AIR in the
//! same PCS/FRI proof. The circuit verifies a generic child anchor; this
//! profile does not yet verify itself recursively. Its key must come from an
//! independently built, value-free topology. Proof bytes never choose the
//! fixed root, component roster, or SHA Gate addresses.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const cairo = @import("stwo_cairo_frontend");
const postcard = @import("interop_postcard");
const shared = @import("../config/sha_fused_fold_profile.zig");
const direct = @import("../config/sha_fused_private_join_profile.zig");
const caller = @import("../air/sha_caller_stream_air.zig");
const caller_bus = @import("../air/sha_caller_stream_bus.zig");
const fused = @import("../air/sha_fused_air.zig");
const feed = @import("../air/sha_feed_direct_air.zig");
const word_bus = @import("../air/sha_direct_word_bus.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
const Engine = cpu.prove.Internal.Engine;
const Column = engine.pcs.ColumnEvaluation;
const pp = shared.pp;
const trace = shared.trace;
const PerComponent = circuit.common.component_list.PerComponent;
pub const Key = shared.Key;

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

pub fn canonicalFixedColumns(allocator: std.mem.Allocator, topology: *const pp.PreprocessedCircuit, statement: direct.PublicStatement) ![]Column {
    const layout = direct.Layout.init(shared.shaPrefix());
    const columns = try allocator.alloc(Column, layout.total_fixed);
    errdefer allocator.free(columns);
    for (topology.columns, columns[0..pp.N_PREPROCESSED_COLUMNS]) |entry, *slot|
        slot.* = .{ .log_size = entry.logSize(), .values = entry.values };
    var caller_fixed = try caller.writeFixed(allocator, statement);
    defer caller_fixed.deinit();
    var bus_fixed = try caller_bus.writeFixed(allocator, statement.config);
    defer bus_fixed.deinit();
    @memcpy(columns[layout.caller_fixed..][0..caller.fixed_width], caller_fixed.values);
    @memcpy(columns[layout.caller_bus_fixed..][0..caller_bus.fixed_width], bus_fixed.values);
    var fused_fixed = try fused.writeFixed(allocator, statement.config.first_call_id);
    defer fused_fixed.deinit();
    @memcpy(columns[layout.fused_fixed..][0..fused.fixed_width], fused_fixed.values);
    var feeds: [direct.call_count]?feed.Columns = @splat(null);
    defer for (&feeds) |*value| if (value.*) |*owned| owned.deinit();
    for (0..direct.call_count) |i| {
        feeds[i] = try feed.writeFixedPrivate(allocator);
        @memcpy(columns[layout.feed_fixed[i]..][0..feed.fixed_width], feeds[i].?.values);
    }
    // All borrowed SHA columns expire at return. Copy them; circuit topology
    // columns remain borrowed and are copied by the commitment helper.
    var copied: usize = 0;
    errdefer for (columns[pp.N_PREPROCESSED_COLUMNS..][0..copied]) |column| allocator.free(column.values);
    for (columns[pp.N_PREPROCESSED_COLUMNS..]) |*column| {
        column.values = try allocator.dupe(M31, column.values);
        copied += 1;
    }
    return columns;
}

pub fn freeCanonicalFixedColumns(allocator: std.mem.Allocator, columns: []Column) void {
    for (columns[pp.N_PREPROCESSED_COLUMNS..]) |column| allocator.free(column.values);
    allocator.free(columns);
}

pub fn deriveKey(allocator: std.mem.Allocator, source_digest: [32]u8, topology: *const pp.PreprocessedCircuit, n_vars: u32, statement: direct.PublicStatement, pcs: core.pcs.config_v2.PcsConfigV2) !Key {
    try statement.validate();
    if (!std.mem.eql(u8, &source_digest, &shared.trustedFoldSourceDigest())) return error.WrongFusedFoldSourceDigest;
    if (statement.digest_visibility != .private) return error.PublicDigestForbiddenInFusedFold;
    const boundary = topology.sha_boundary orelse return error.MissingShaBoundary;
    if (!std.meta.eql(boundary.addresses, statement.config.gate_addresses) or topology.n_outputs != 8)
        return error.InvalidFusedFoldTopology;
    const layout = topology.layout();
    const logs = try circuit.common.component_list.circuitComponentLogSizes(&layout);
    var key = Key{
        .source_digest = source_digest,
        .statement = statement,
        .n_vars = n_vars,
        .circuit_logs = logs,
        .circuit_layout = layout,
        .pcs = pcs,
        .fixed_root = undefined,
        .digest = undefined,
    };
    const columns = try canonicalFixedColumns(allocator, topology, statement);
    defer freeCanonicalFixedColumns(allocator, columns);
    var channel = shared.MC.Channel{};
    shared.mixProfile(&channel, key);
    var scheme = try Engine.initRevision(allocator, pcs);
    defer Engine.deinit(&scheme, allocator);
    scheme.setStorePolynomialsCoefficients();
    try Engine.commit(&scheme, allocator, try cloneColumns(allocator, columns), null, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    key.fixed_root = scheme.trees.items[0].commitment.root();
    key.digest = shared.keyDigest(key);
    try key.validate();
    return key;
}

/// The application must cache `key` from `deriveKey` over independently
/// compiled, value-free topology. `Key.validate` checks self-consistency,
/// while `deriveKey` is what authenticates its fixed root and Gate boundary.
pub const Admission = struct { key: Key, public_outputs: []const QM31 };

/// Convenience entry point when the caller has the trusted topology rather
/// than a cached key. It derives the canonical fixed commitment before
/// checking the proof envelope and STARK.
pub fn verifyWithTopology(
    allocator: std.mem.Allocator,
    source_digest: [32]u8,
    topology: *const pp.PreprocessedCircuit,
    n_vars: u32,
    statement: direct.PublicStatement,
    pcs: core.pcs.config_v2.PcsConfigV2,
    public_outputs: []const QM31,
    bytes: []const u8,
) !void {
    const key = try deriveKey(allocator, source_digest, topology, n_vars, statement, pcs);
    return verifyBytes(allocator, .{ .key = key, .public_outputs = public_outputs }, bytes);
}

fn decodeClaims(bytes: []const u8) ![shared.claim_count]QM31 {
    if (bytes.len < shared.prefix_bytes or bytes.len > shared.prefix_bytes + shared.max_proof_bytes or
        !std.mem.eql(u8, bytes[0..shared.magic.len], shared.magic)) return error.InvalidFusedFoldProofEnvelope;
    var claims: [shared.claim_count]QM31 = undefined;
    for (&claims, 0..) |*claim, i| {
        var limbs: [4]M31 = undefined;
        for (&limbs, 0..) |*limb, j| {
            const at = shared.magic.len + 8 + 16 * i + 4 * j;
            const value = std.mem.readInt(u32, bytes[at..][0..4], .little);
            if (value >= core.fields.m31.Modulus) return error.NoncanonicalFusedFoldClaim;
            limb.* = M31.fromCanonical(value);
        }
        claim.* = QM31.fromM31Array(limbs);
    }
    return claims;
}

pub fn verifyBytes(allocator: std.mem.Allocator, admission: Admission, bytes: []const u8) !void {
    const key = admission.key;
    try key.validate();
    try shared.validatePublicOutputs(admission.public_outputs);
    const official_air = @embedFile("s31_air_programs");
    try shared.validateOfficialBundle(official_air);
    var bundle = try cpu.air.parse(allocator, official_air);
    defer bundle.deinit();
    const claims = try decodeClaims(bytes);
    if (!std.mem.eql(u8, bytes[shared.magic.len + 8 + shared.claim_bytes ..][0..32], &key.digest))
        return error.WrongFusedFoldVerificationKey;
    const nonce = std.mem.readInt(u64, bytes[shared.magic.len..][0..8], .little);
    const proof_bytes = bytes[shared.prefix_bytes..];
    const memory = try allocator.alloc(u8, shared.max_proof_bytes);
    defer allocator.free(memory);
    var bounded = std.heap.FixedBufferAllocator.init(memory);
    var stream = std.io.fixedBufferStream(proof_bytes);
    var proof = try postcard.deserializeProof(H, bounded.allocator(), stream.reader());
    defer proof.deinit(bounded.allocator());
    if (stream.pos != proof_bytes.len or proof.commitment_scheme_proof.commitments.items.len != 4)
        return error.InvalidFusedFoldProofShape;
    if (!std.meta.eql(proof.commitment_scheme_proof.config, core.protocol_revision.Revision.proving_5a7c5ed.legacyView(key.pcs)))
        return error.InvalidFusedFoldProofConfig;
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (!std.mem.eql(u8, &roots[0], &key.fixed_root)) return error.WrongFusedFoldFixedRoot;
    var channel = shared.MC.Channel{};
    shared.mixProfile(&channel, key);
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(H, shared.MC).init(allocator, key.pcs);
    defer verifier.deinit(allocator);
    const fixed_logs = try shared.fixedLogs(allocator, key);
    defer allocator.free(fixed_logs);
    const main_logs = try shared.mainLogs(allocator, key);
    defer allocator.free(main_logs);
    const interaction_logs = try shared.interactionLogs(allocator, key);
    defer allocator.free(interaction_logs);
    try verifier.commit(allocator, roots[0], fixed_logs, &channel);
    shared.MC.mixRoot(&channel, key.identity());
    channel.mixFelts(admission.public_outputs);
    try verifier.commit(allocator, roots[1], main_logs, &channel);
    if (!channel.verifyPowNonce(circuit.common.component_list.INTERACTION_POW_BITS, nonce))
        return error.InvalidFusedFoldInteractionNonce;
    channel.mixU64(nonce);
    const gate_challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const word_challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const gate_elements = word_bus.Elements.init(gate_challenge.z, gate_challenge.alpha);
    const word_elements = word_bus.Elements.init(word_challenge.z, word_challenge.alpha);
    var direct_claims: direct.Claims = undefined;
    direct_claims.gate = claims[shared.circuit_components];
    @memcpy(&direct_claims.word, claims[shared.circuit_components + 1 ..]);
    try direct_claims.validate();
    if (!(try trace.lookupSum(admission.public_outputs, PerComponent(QM31).fromArray(claims[0..shared.circuit_components].*), gate_challenge.z, gate_challenge.alpha)).add(direct_claims.gate).isZero())
        return error.InvalidFusedFoldGateClosure;
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &claims);
    try verifier.commit(allocator, roots[2], interaction_logs, &channel);
    var bound = try cpu.air.bind(allocator, &bundle, key.circuit_logs, &key.circuit_layout);
    defer bound.deinit();
    var pp_logs: [pp.N_PREPROCESSED_COLUMNS]u32 = undefined;
    for (key.circuit_layout.entries, &pp_logs) |entry, *log| log.* = entry.log_size;
    const lifting = key.pcs.trace_lifting_log_size - key.pcs.fri_config.log_blowup_factor + 1;
    var captured: [shared.circuit_components]cairo.proving.air.component.Component = undefined;
    var handles: [shared.component_count]core.air.components.Component = undefined;
    for (bound.components, &captured, handles[0..shared.circuit_components], claims[0..shared.circuit_components]) |*source, *runtime, *handle, claim| {
        runtime.* = .init(allocator, source, &pp_logs, lifting, gate_challenge.z, gate_challenge.alpha, claim);
        handle.* = try runtime.asVerifierComponent().withCompositionGeometryOverrideV1(.{
            .max_constraint_log_degree_bound_delta = 1,
            .composition_log_split = 2,
        });
    }
    var components = direct.Components.init(key.statement, direct_claims, gate_elements, word_elements, direct.Layout.init(shared.shaPrefix()));
    const direct_handles = components.verifierHandles();
    @memcpy(handles[shared.circuit_components..], &direct_handles);
    for (handles[shared.circuit_components..]) |*handle| handle.* = try handle.withCompositionGeometryOverrideV1(.{
        .max_constraint_log_degree_bound_delta = 0,
        .composition_log_split = 2,
    });
    var capture: core.verifier.ProofCapture(H) = undefined;
    try core.verifier.verifyBorrowedExWithProofCapture(H, shared.MC, allocator, &handles, &channel, &verifier, &proof, true, &capture);
    defer capture.deinit(allocator);
}
