//! Experimental two-call direct-M31 proof path. This module is deliberately
//! absent from the public package facade until source-derived S31 manifest
//! reconstruction, a versioned envelope, and native byte-mutation tests pass.
//! Transcript order on both sides: V3 profile/effective digest and plan,
//! channel salt, FRI config, preprocessed root, circuit identity, eight public
//! words, one main root, interaction PoW nonce, one lookup challenge pair,
//! five ordered claimed sums, one interaction root, then PCS/FRI proof.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const cairo = @import("stwo_cairo_frontend");
const old = @import("prove.zig");
const air = @import("air.zig");
const pair = @import("private_pair_boundary.zig");
const chip = @import("tagged_pair_chip.zig");
const bridge = @import("tagged_pair_bridge.zig");
const direct = @import("direct_arithmetic.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const MC = old.profiles.Blake2sM31MerkleChannel;
const H = MC.MerkleHasher;
const Engine = old.Internal.Engine;
const Scheme = Engine.Scheme;
const Channel = MC.Channel;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;
const CircuitView = circuit.common.preprocessed.CircuitView;
const direct_pp = circuit.common.direct_arithmetic;
const direct_trace = circuit.witness.direct_arithmetic;

pub const Plan = pair.Plan;
pub const Bundle = air.Bundle;

/// Admission geometry reconstructed from the same five verifier components
/// used by `verifyBorrowed`. It contains no lengths selected by proof bytes.
pub const PreflightGeometry = struct {
    tree_columns: [4]u32,
    sample_width_limits: [4]u32,
    max_column_log_size: u32,
};

pub fn parseBundle(allocator: std.mem.Allocator, bytes: []const u8) !Bundle {
    return air.parse(allocator, bytes);
}

pub fn preflightGeometry(
    allocator: std.mem.Allocator,
    source: CircuitView,
    template: *const air.Bundle,
    pcs: core.pcs.config_v2.PcsConfigV2,
    plan: pair.Plan,
) !PreflightGeometry {
    try validatePublicOutputShape(source);
    var pp = try plan.preprocessed(allocator, source);
    defer pp.deinit(allocator);
    const circuit_log = pp.traceLogSize();
    const layout = pp.layout();
    var bound = try air.bindDirectArithmetic(allocator, template, circuit_log, &layout);
    defer bound.deinit();
    if (bound.components.len != 1) return error.InvalidPairRoster;
    const specs = try pair.expectedSpecs(plan, circuit_log, bound.total_constraints);
    var pp_logs = [_]u32{circuit_log} ** direct_pp.N_COLUMNS;
    const lifting_bound = pcs.trace_lifting_log_size - pcs.fri_config.log_blowup_factor + 1;
    var captured = cairo.proving.air.component.Component.init(allocator, &bound.components[0], &pp_logs, lifting_bound, QM31.one(), QM31.one(), QM31.zero());
    var chips: [pair.n_calls]chip.Component = undefined;
    var bridges: [pair.n_calls]bridge.Component = undefined;
    var handles: [pair.roster.len]core.air.components.Component = undefined;
    handles[0] = captured.asVerifierComponent();
    for (plan.calls, 0..) |call, id| {
        chips[id] = .{
            .log_size = specs[1 + id].log_size,
            .call_id = call.call_id,
            .constant = call.constant,
            .main_offset = specs[1 + id].main_offset,
            .interaction_offset = specs[1 + id].interaction_offset,
            .elements = .init(QM31.one(), QM31.one()),
            .claimed_sum = QM31.zero(),
        };
        handles[1 + id] = chips[id].asVerifierComponent();
        bridges[id] = .{
            .main_offset = specs[3 + id].main_offset,
            .interaction_offset = specs[3 + id].interaction_offset,
            .boundary = call,
            .elements = .init(QM31.one(), QM31.one()),
            .claimed_sum = QM31.zero(),
        };
        handles[3 + id] = bridges[id].asVerifierComponent();
    }
    for (handles, specs) |handle, spec|
        if (handle.nConstraints() != spec.constraint_count) return error.InvalidPairRoster;
    const components: core.air.components.Components = .{
        .components = &handles,
        .n_preprocessed_columns = direct_pp.N_COLUMNS,
    };
    const split = try components.compositionLogSplit();
    const composition_log = core.verifier_types.compositionMaskLogSize(components.compositionLogDegreeBound(), split) orelse
        return error.InvalidPairRoster;
    const composition_columns = core.verifier_types.compositionColumnCount(split, QM31.SECURE_EXTENSION_DEGREE) orelse
        return error.InvalidPairRoster;
    var logs = try components.columnLogSizes(allocator);
    defer logs.deinitDeep(allocator);
    const point = core.circle.secureFieldPointFromRandomSeed(QM31.one());
    var masks = try components.maskPoints(allocator, point, composition_log, true);
    defer masks.deinitDeep(allocator);
    if (logs.items.len != 3 or masks.items.len != 3) return error.InvalidPairRoster;
    var geometry: PreflightGeometry = .{
        .tree_columns = undefined,
        .sample_width_limits = @splat(1),
        .max_column_log_size = composition_log,
    };
    for (logs.items, masks.items, 0..) |tree_logs, tree_masks, tree| {
        if (tree_logs.len != tree_masks.len) return error.InvalidPairRoster;
        geometry.tree_columns[tree] = std.math.cast(u32, tree_logs.len) orelse return error.InvalidPairRoster;
        for (tree_logs, tree_masks) |log, mask| {
            geometry.max_column_log_size = @max(geometry.max_column_log_size, log);
            geometry.sample_width_limits[tree] = @max(geometry.sample_width_limits[tree], std.math.cast(u32, mask.len) orelse return error.InvalidPairRoster);
        }
    }
    geometry.tree_columns[3] = std.math.cast(u32, composition_columns) orelse return error.InvalidPairRoster;
    return geometry;
}

pub const Request = struct {
    /// This digest is recomputed from the sealed source by the S31 wrapper.
    source_digest: [32]u8,
    /// Typed V3 generated-manifest precommitment, never the JSON view.
    manifest_digest: [32]u8,
    /// The caller must derive this from the same source semantics it seals.
    /// CircuitView alone cannot certify the high-level repeat-to-wire map.
    plan: pair.Plan,
};

pub const Proof = struct {
    allocator: std.mem.Allocator,
    pcs_config: core.pcs.config_v2.PcsConfigV2,
    output_values: []QM31,
    interaction_pow_nonce: u64,
    claimed_sums: [pair.roster.len]QM31,
    stark_proof: core.proof.ExtendedStarkProof(H),
    circuit_hash: [32]u8,

    pub fn deinit(self: *@This()) void {
        self.stark_proof.deinit(self.allocator);
        self.allocator.free(self.output_values);
        self.* = undefined;
    }
};

/// The V3 manifest digest is part of this hash before the preprocessed tree
/// is committed. The ordered plan is repeated here to make key identity
/// explicit even if a future manifest encoder changes.
pub fn identityHash(effective_digest: [32]u8, preprocessed_root: [32]u8, circuit_log: u32, blowup: u32, plan: pair.Plan) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("S31-DIRECT-M31-CHIP-PAIR-V1\x00");
    hash.update(&effective_digest);
    hash.update(&preprocessed_root);
    var word: [4]u8 = undefined;
    for ([_]u32{ circuit_log, blowup }) |value| hashU32(&hash, &word, value);
    for (plan.calls) |call| {
        for ([_]u32{ call.call_id, call.rounds, call.constant.toU32() }) |value| hashU32(&hash, &word, value);
        for (call.input ++ call.output) |address| hashU32(&hash, &word, address);
    }
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}

fn validatePublicOutputShape(source: CircuitView) !void {
    // Direct-M31 commits eight reserved public M31 words at addresses 3..10;
    // the circuit builder also yields the fixed extension unit at address 2.
    if (source.output.len != 9) return error.InvalidPairPublicStatement;
    for (source.output, 0..) |address, index|
        if (address != @as(u32, @intCast(index + 2))) return error.InvalidPairPublicStatement;
}

fn hashU32(hash: *std.crypto.hash.sha2.Sha256, word: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, word, value, .little);
    hash.update(word);
}

fn fillLogs(specs: [pair.roster.len]pair.ComponentSpec, comptime main: bool) [if (main) pair.main_width else pair.interaction_width]u32 {
    var logs: [if (main) pair.main_width else pair.interaction_width]u32 = undefined;
    for (specs) |spec| {
        const offset = if (main) spec.main_offset else spec.interaction_offset;
        const width = if (main) spec.main_columns else spec.interaction_columns;
        @memset(logs[offset..][0..width], spec.log_size);
    }
    return logs;
}

pub fn prove(
    allocator: std.mem.Allocator,
    source: CircuitView,
    values: []const QM31,
    template: *const air.Bundle,
    pcs: core.pcs.config_v2.PcsConfigV2,
    request: Request,
) !Proof {
    try validatePublicOutputShape(source);
    var pp = try request.plan.preprocessed(allocator, source);
    defer pp.deinit(allocator);
    const states = try request.plan.extract(values);
    const effective_digest = pair.effectiveDigest(request.source_digest, request.manifest_digest);
    var channel = Channel{};
    pair.mixProfile(&channel, effective_digest, request.plan);
    core.channel.lookup_transcript.mixChannelSalt(&channel, 0);
    pcs.fri_config.mixInto(&channel);
    var scheme = try Engine.initRevision(allocator, pcs);
    var scheme_owned = true;
    errdefer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setStorePolynomialsCoefficients();
    var pp_views: [direct_pp.N_COLUMNS]ColumnEvaluation = undefined;
    for (pp.columns, &pp_views) |entry, *view|
        view.* = .{ .log_size = entry.logSize(), .values = entry.values };
    try commit(&scheme, allocator, &pp_views, &channel);
    const root = scheme.trees.items[0].commitment.root();

    var base = try direct_trace.writeBase(allocator, values, &pp);
    defer base.deinit();
    if (base.output_values.len != 8) return error.InvalidPairPublicStatement;
    var chip_base: [pair.n_calls]chip.Base = undefined;
    var chip_ready: usize = 0;
    defer for (chip_base[0..chip_ready]) |*item| item.deinit();
    var bridge_base: [pair.n_calls]bridge.Base = undefined;
    var bridge_ready: usize = 0;
    defer for (bridge_base[0..bridge_ready]) |*item| item.deinit();
    for (request.plan.calls, states, 0..) |call, state, id| {
        chip_base[id] = try chip.writeBase(allocator, state.input, call.constant, call.rounds);
        chip_ready += 1;
        if (!std.meta.eql(chip_base[id].final, state.output)) return error.WrongPairChipClaim;
        bridge_base[id] = try bridge.writeBase(allocator, values, call);
        bridge_ready += 1;
    }
    const hash = identityHash(effective_digest, root, base.log_size, pcs.fri_config.log_blowup_factor, request.plan);
    MC.mixRoot(&channel, hash);
    channel.mixFelts(base.output_values);
    var main_views: [pair.main_width]ColumnEvaluation = undefined;
    try copyFive(ColumnEvaluation, &main_views, base.columns, chip_base[0].columns, chip_base[1].columns, bridge_base[0].columns, bridge_base[1].columns);
    try commit(&scheme, allocator, &main_views, &channel);
    const nonce = channel.grind(circuit.common.component_list.INTERACTION_POW_BITS);
    channel.mixU64(nonce);
    const lookup = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    var interaction = try direct_trace.writeInteraction(allocator, &base, &pp, lookup.z, lookup.alpha);
    defer interaction.deinit();
    var chip_interaction: [pair.n_calls]chip.Interaction = undefined;
    var chip_interaction_ready: usize = 0;
    defer for (chip_interaction[0..chip_interaction_ready]) |*item| item.deinit();
    var bridge_interaction: [pair.n_calls]bridge.Interaction = undefined;
    var bridge_interaction_ready: usize = 0;
    defer for (bridge_interaction[0..bridge_interaction_ready]) |*item| item.deinit();
    for (request.plan.calls, 0..) |call, id| {
        chip_interaction[id] = try chip.writeInteraction(allocator, chip_base[id].columns, call.call_id, lookup.z, lookup.alpha);
        chip_interaction_ready += 1;
        bridge_interaction[id] = try bridge.writeInteraction(allocator, bridge_base[id].columns, call, lookup.z, lookup.alpha);
        bridge_interaction_ready += 1;
    }
    const sums = [pair.roster.len]QM31{
        interaction.claimed_sum,
        chip_interaction[0].claimed_sum,
        chip_interaction[1].claimed_sum,
        bridge_interaction[0].claimed_sum,
        bridge_interaction[1].claimed_sum,
    };
    var closure = try direct_trace.lookupSum(base.output_values, sums[0], lookup.z, lookup.alpha);
    for (sums[1..]) |sum| closure = closure.add(sum);
    if (!closure.isZero()) return error.InvalidPairLookupSum;
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &sums);
    var interaction_views: [pair.interaction_width]ColumnEvaluation = undefined;
    try copyFive(ColumnEvaluation, &interaction_views, interaction.columns, chip_interaction[0].columns, chip_interaction[1].columns, bridge_interaction[0].columns, bridge_interaction[1].columns);
    try commit(&scheme, allocator, &interaction_views, &channel);

    const layout = pp.layout();
    var bound = try air.bindDirectArithmetic(allocator, template, base.log_size, &layout);
    defer bound.deinit();
    if (bound.components.len != 1) return error.InvalidPairRoster;
    const specs = try pair.expectedSpecs(request.plan, base.log_size, bound.total_constraints);
    var pp_logs = [_]u32{base.log_size} ** direct_pp.N_COLUMNS;
    const lifting_bound = pcs.trace_lifting_log_size - pcs.fri_config.log_blowup_factor + 1;
    var captured = cairo.proving.air.component.Component.init(allocator, &bound.components[0], &pp_logs, lifting_bound, lookup.z, lookup.alpha, sums[0]);
    var chips: [pair.n_calls]chip.Component = undefined;
    var bridges: [pair.n_calls]bridge.Component = undefined;
    var handles: [pair.roster.len]prover.air.component_prover.ComponentProver = undefined;
    handles[0] = captured.asProverComponent();
    for (request.plan.calls, 0..) |call, id| {
        chips[id] = .{
            .log_size = specs[1 + id].log_size,
            .call_id = call.call_id,
            .constant = call.constant,
            .main_offset = specs[1 + id].main_offset,
            .interaction_offset = specs[1 + id].interaction_offset,
            .elements = .init(lookup.z, lookup.alpha),
            .claimed_sum = sums[1 + id],
        };
        handles[1 + id] = chips[id].asProverComponent();
        bridges[id] = .{
            .main_offset = specs[3 + id].main_offset,
            .interaction_offset = specs[3 + id].interaction_offset,
            .boundary = call,
            .elements = .init(lookup.z, lookup.alpha),
            .claimed_sum = sums[3 + id],
        };
        handles[3 + id] = bridges[id].asProverComponent();
    }
    for (handles, specs) |handle, spec|
        if (handle.nConstraints() != spec.constraint_count) return error.InvalidPairRoster;
    scheme_owned = false;
    var stark = try Engine.prove(allocator, &handles, &channel, scheme, .{ .include_all_preprocessed_columns = true });
    errdefer stark.deinit(allocator);
    return .{
        .allocator = allocator,
        .pcs_config = pcs,
        .output_values = try allocator.dupe(QM31, base.output_values),
        .interaction_pow_nonce = nonce,
        .claimed_sums = sums,
        .stark_proof = stark,
        .circuit_hash = hash,
    };
}

/// Engine-level native verifier for an in-memory pair proof. The caller owns
/// the source and typed manifest digest. S31 packaging must independently
/// reconstruct both from its sealed program before using this path.
pub fn verify(
    allocator: std.mem.Allocator,
    source: CircuitView,
    template: *const air.Bundle,
    pcs: core.pcs.config_v2.PcsConfigV2,
    request: Request,
    public_words: [8]u32,
    proof: *const Proof,
) !void {
    if (!std.meta.eql(pcs, proof.pcs_config)) return error.InvalidPairPcsConfig;
    return verifyBorrowed(allocator, source, template, pcs, request, public_words, .{
        .output_values = proof.output_values,
        .interaction_pow_nonce = proof.interaction_pow_nonce,
        .claimed_sums = proof.claimed_sums,
        .stark_proof = &proof.stark_proof.proof,
        .circuit_hash = proof.circuit_hash,
    });
}

/// Decoded native envelopes own only the postcard StarkProof, not the
/// prover-only PCS auxiliary state. This is the exact same verifier schedule
/// as `verify`; the S31 wrapper must reconstruct `request` from sealed source
/// and compare its generated V3 key before calling this experimental adapter.
pub const BorrowedProof = struct {
    output_values: []const QM31,
    interaction_pow_nonce: u64,
    claimed_sums: [pair.roster.len]QM31,
    stark_proof: *const core.proof.StarkProof(H),
    circuit_hash: [32]u8,
};

pub fn verifyBorrowed(
    allocator: std.mem.Allocator,
    source: CircuitView,
    template: *const air.Bundle,
    pcs: core.pcs.config_v2.PcsConfigV2,
    request: Request,
    public_words: [8]u32,
    proof: BorrowedProof,
) !void {
    try validatePublicOutputShape(source);
    var pp = try request.plan.preprocessed(allocator, source);
    defer pp.deinit(allocator);
    var committed = try direct.PreprocessedCommitment.build(allocator, &pp, pcs);
    defer committed.deinit(allocator);
    const roots = proof.stark_proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4 or !std.mem.eql(u8, &roots[0], &committed.root()))
        return error.InvalidPairPreprocessedRoot;
    if (!std.meta.eql(
        proof.stark_proof.commitment_scheme_proof.config,
        core.protocol_revision.Revision.proving_5a7c5ed.legacyView(pcs),
    )) return error.InvalidPairPcsConfig;
    var outputs: [8]QM31 = undefined;
    for (public_words, &outputs, 0..) |word, *output, index| {
        if (word >= core.fields.m31.Modulus) return error.InvalidPairPublicStatement;
        output.* = QM31.fromBase(M31.fromCanonical(word));
        if (proof.output_values.len != 8 or !proof.output_values[index].eql(output.*))
            return error.InvalidPairPublicStatement;
    }
    const effective_digest = pair.effectiveDigest(request.source_digest, request.manifest_digest);
    const circuit_log = pp.traceLogSize();
    const expected_hash = identityHash(effective_digest, roots[0], circuit_log, pcs.fri_config.log_blowup_factor, request.plan);
    if (!std.mem.eql(u8, &proof.circuit_hash, &expected_hash)) return error.InvalidPairCircuitHash;
    var channel = Channel{};
    pair.mixProfile(&channel, effective_digest, request.plan);
    core.channel.lookup_transcript.mixChannelSalt(&channel, 0);
    pcs.fri_config.mixInto(&channel);
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(allocator, pcs);
    defer scheme.deinit(allocator);
    var pp_logs = [_]u32{circuit_log} ** direct_pp.N_COLUMNS;
    try scheme.commit(allocator, roots[0], &pp_logs, &channel);
    MC.mixRoot(&channel, expected_hash);
    channel.mixFelts(&outputs);
    const layout = pp.layout();
    var bound = try air.bindDirectArithmetic(allocator, template, circuit_log, &layout);
    defer bound.deinit();
    if (bound.components.len != 1) return error.InvalidPairRoster;
    const specs = try pair.expectedSpecs(request.plan, circuit_log, bound.total_constraints);
    const main_logs = fillLogs(specs, true);
    try scheme.commit(allocator, roots[1], &main_logs, &channel);
    if (!channel.verifyPowNonce(circuit.common.component_list.INTERACTION_POW_BITS, proof.interaction_pow_nonce))
        return error.InvalidPairInteractionNonce;
    channel.mixU64(proof.interaction_pow_nonce);
    const lookup = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    var closure = try direct_trace.lookupSum(&outputs, proof.claimed_sums[0], lookup.z, lookup.alpha);
    for (proof.claimed_sums[1..]) |sum| closure = closure.add(sum);
    if (!closure.isZero()) return error.InvalidPairLookupSum;
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &proof.claimed_sums);
    const interaction_logs = fillLogs(specs, false);
    try scheme.commit(allocator, roots[2], &interaction_logs, &channel);

    const lifting_bound = pcs.trace_lifting_log_size - pcs.fri_config.log_blowup_factor + 1;
    var captured = cairo.proving.air.component.Component.init(allocator, &bound.components[0], &pp_logs, lifting_bound, lookup.z, lookup.alpha, proof.claimed_sums[0]);
    var chips: [pair.n_calls]chip.Component = undefined;
    var bridges: [pair.n_calls]bridge.Component = undefined;
    var handles: [pair.roster.len]core.air.components.Component = undefined;
    handles[0] = captured.asVerifierComponent();
    for (request.plan.calls, 0..) |call, id| {
        chips[id] = .{
            .log_size = specs[1 + id].log_size,
            .call_id = call.call_id,
            .constant = call.constant,
            .main_offset = specs[1 + id].main_offset,
            .interaction_offset = specs[1 + id].interaction_offset,
            .elements = .init(lookup.z, lookup.alpha),
            .claimed_sum = proof.claimed_sums[1 + id],
        };
        handles[1 + id] = chips[id].asVerifierComponent();
        bridges[id] = .{
            .main_offset = specs[3 + id].main_offset,
            .interaction_offset = specs[3 + id].interaction_offset,
            .boundary = call,
            .elements = .init(lookup.z, lookup.alpha),
            .claimed_sum = proof.claimed_sums[3 + id],
        };
        handles[3 + id] = bridges[id].asVerifierComponent();
    }
    for (handles, specs) |handle, spec|
        if (handle.nConstraints() != spec.constraint_count) return error.InvalidPairRoster;
    var capture: core.verifier.ProofCapture(H) = undefined;
    try core.verifier.verifyBorrowedExWithProofCapture(
        H,
        MC,
        allocator,
        &handles,
        &channel,
        &scheme,
        proof.stark_proof,
        true,
        &capture,
    );
    defer capture.deinit(allocator);
}

fn copyFive(comptime T: type, dst: []T, a: []const T, b: []const T, c: []const T, d: []const T, e: []const T) !void {
    if (dst.len != a.len + b.len + c.len + d.len + e.len)
        return error.InvalidPairRoster;
    var offset: usize = 0;
    inline for (.{ a, b, c, d, e }) |source| {
        @memcpy(dst[offset..][0..source.len], source);
        offset += source.len;
    }
}

fn commit(scheme: *Scheme, allocator: std.mem.Allocator, source: []const ColumnEvaluation, channel: *Channel) !void {
    try Engine.commit(scheme, allocator, try cloneColumns(allocator, source), null, channel);
    try Engine.flushPendingCommit(scheme, allocator, channel);
}

fn cloneColumns(allocator: std.mem.Allocator, source: []const ColumnEvaluation) ![]ColumnEvaluation {
    const columns = try allocator.alloc(ColumnEvaluation, source.len);
    var ready: usize = 0;
    errdefer {
        for (columns[0..ready]) |entry| allocator.free(entry.values);
        allocator.free(columns);
    }
    for (source, columns) |entry, *slot| {
        slot.* = .{ .log_size = entry.log_size, .values = try allocator.dupe(M31, entry.values) };
        ready += 1;
    }
    return columns;
}

test "direct pair native proof accepts two calls and rejects transcript mutations" {
    const allocator = std.testing.allocator;
    var ctx = try circuit.builder.Context(QM31).init(allocator, 8);
    defer ctx.deinit();
    const initial = [2][4]M31{
        .{ M31.fromCanonical(3), M31.fromCanonical(3), M31.fromCanonical(7), M31.fromCanonical(11) },
        .{ M31.fromCanonical(2), M31.fromCanonical(4), M31.fromCanonical(6), M31.fromCanonical(8) },
    };
    const constants = [2]M31{ M31.fromCanonical(13), M31.fromCanonical(17) };
    const rounds = [2]u32{ 16, 32 };
    var x: [2][4]circuit.builder.Var = undefined;
    var y: [2][4]circuit.builder.Var = undefined;
    var outputs: [8]circuit.builder.Var = undefined;
    var plan = pair.Plan{ .calls = undefined };
    for (0..2) |call_id| {
        const final = try @import("repeated_step_chip.zig").direct(initial[call_id], constants[call_id], rounds[call_id]);
        plan.calls[call_id].call_id = @intCast(call_id);
        plan.calls[call_id].rounds = rounds[call_id];
        plan.calls[call_id].constant = constants[call_id];
        for (0..4) |lane| {
            if (call_id == 0 and lane == 1) {
                // Build a genuine alias in the source graph, rather than
                // merely changing the pair plan after independent guesses.
                x[call_id][lane] = x[call_id][0];
                y[call_id][lane] = y[call_id][0];
            } else {
                x[call_id][lane] = try ctx.guessM31(QM31.fromBase(initial[call_id][lane]));
                y[call_id][lane] = try ctx.guessM31(QM31.fromBase(final[lane]));
            }
            plan.calls[call_id].input[lane] = x[call_id][lane].idx;
            plan.calls[call_id].output[lane] = y[call_id][lane].idx;
        }
    }
    // Both appearances refer to one coherent source wire. The preprocessed
    // Gate multiplicity must count both, while the bridge reads one value.
    for (0..4) |lane| {
        outputs[lane] = try ctx.add(y[0][lane], y[1][lane]);
        outputs[4 + lane] = try ctx.mul(x[0][lane], x[1][lane]);
    }
    try ctx.setOutputs(&outputs);
    try ctx.finalize(false);
    try circuit.common.finalize.padToTargets(QM31, &ctx, .{
        .eq = 0,
        .qm31_ops = circuit.common.finalize.paddedSize(ctx.circuit.nQm31OpsRows()),
        .triple_xor = 0,
        .m31_to_u32 = 0,
        .blake_g_gate = 0,
    });
    try std.testing.expect(try ctx.isCircuitValid());
    const source = CircuitView.fromBuilder(&ctx.circuit);
    var pp = try plan.preprocessed(allocator, source);
    defer pp.deinit(allocator);
    const fri = try core.pcs.config_v2.FriConfigV2.init(10, 0, 1, 3, 1);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, @max(pp.traceLogSize(), @as(u32, 5)));
    const bundle_bytes = try std.fs.cwd().readFileAlloc(allocator, air.bundle_path, 1 << 20);
    defer allocator.free(bundle_bytes);
    var bundle = try air.parse(allocator, bundle_bytes);
    defer bundle.deinit();
    var source_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("s31-pair-native-test-source-v1", &source_digest, .{});
    var manifest_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("s31-pair-native-test-manifest-v1", &manifest_digest, .{});
    const request = Request{ .source_digest = source_digest, .manifest_digest = manifest_digest, .plan = plan };
    var proof = try prove(allocator, source, ctx.values(), &bundle, pcs, request);
    defer proof.deinit();
    var public_words: [8]u32 = undefined;
    for (proof.output_values, &public_words) |value, *word| {
        const limbs = value.toM31Array();
        try std.testing.expect(limbs[1].isZero() and limbs[2].isZero() and limbs[3].isZero());
        word.* = limbs[0].toU32();
    }
    const final0 = try @import("repeated_step_chip.zig").direct(initial[0], constants[0], rounds[0]);
    const final1 = try @import("repeated_step_chip.zig").direct(initial[1], constants[1], rounds[1]);
    for (0..4) |lane| {
        try std.testing.expectEqual(final0[lane].add(final1[lane]), M31.fromCanonical(public_words[lane]));
        try std.testing.expectEqual(initial[0][lane].mul(initial[1][lane]), M31.fromCanonical(public_words[4 + lane]));
    }
    try verify(allocator, source, &bundle, pcs, request, public_words, &proof);
    var wrong_output_order = try allocator.dupe(u32, source.output);
    defer allocator.free(wrong_output_order);
    std.mem.swap(u32, &wrong_output_order[1], &wrong_output_order[2]);
    var wrong_source_view = source;
    wrong_source_view.output = wrong_output_order;
    try std.testing.expectError(error.InvalidPairPublicStatement, verify(allocator, wrong_source_view, &bundle, pcs, request, public_words, &proof));
    var wrong_public = public_words;
    wrong_public[0] = M31.fromCanonical(wrong_public[0]).add(M31.one()).toU32();
    try std.testing.expectError(error.InvalidPairPublicStatement, verify(allocator, source, &bundle, pcs, request, wrong_public, &proof));
    var wrong_manifest = request;
    wrong_manifest.manifest_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidPairCircuitHash, verify(allocator, source, &bundle, pcs, wrong_manifest, public_words, &proof));
    var wrong_source = request;
    wrong_source.source_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidPairCircuitHash, verify(allocator, source, &bundle, pcs, wrong_source, public_words, &proof));
    var wrong_plan = request;
    wrong_plan.plan.calls[0].constant = wrong_plan.plan.calls[0].constant.add(M31.one());
    try std.testing.expectError(error.InvalidPairCircuitHash, verify(allocator, source, &bundle, pcs, wrong_plan, public_words, &proof));
    wrong_plan = request;
    wrong_plan.plan.calls[0].input[0] = plan.calls[1].input[0];
    try std.testing.expectError(error.InvalidPairPreprocessedRoot, verify(allocator, source, &bundle, pcs, wrong_plan, public_words, &proof));
    wrong_plan = request;
    std.mem.swap(u32, &wrong_plan.plan.calls[0].input[0], &wrong_plan.plan.calls[1].input[0]);
    try std.testing.expectError(error.InvalidPairCircuitHash, verify(allocator, source, &bundle, pcs, wrong_plan, public_words, &proof));
    wrong_plan = request;
    wrong_plan.plan.calls[0].call_id = 1;
    try std.testing.expectError(error.NonCanonicalCallId, verify(allocator, source, &bundle, pcs, wrong_plan, public_words, &proof));
    wrong_plan = request;
    std.mem.swap(pair.Call, &wrong_plan.plan.calls[0], &wrong_plan.plan.calls[1]);
    wrong_plan.plan.calls[0].call_id = 0;
    wrong_plan.plan.calls[1].call_id = 1;
    try std.testing.expectError(error.InvalidPairCircuitHash, verify(allocator, source, &bundle, pcs, wrong_plan, public_words, &proof));
    proof.claimed_sums[1] = proof.claimed_sums[1].add(QM31.one());
    try std.testing.expectError(error.InvalidPairLookupSum, verify(allocator, source, &bundle, pcs, request, public_words, &proof));
    proof.claimed_sums[1] = proof.claimed_sums[1].sub(QM31.one());
    std.mem.swap(QM31, &proof.claimed_sums[1], &proof.claimed_sums[2]);
    if (verify(allocator, source, &bundle, pcs, request, public_words, &proof)) |_| {
        return error.AcceptedSwappedPairClaims;
    } else |_| {}
    std.mem.swap(QM31, &proof.claimed_sums[1], &proof.claimed_sums[2]);
    try verify(allocator, source, &bundle, pcs, request, public_words, &proof);
    proof.stark_proof.proof.commitment_scheme_proof.commitments.items[0][0] ^= 1;
    try std.testing.expectError(error.InvalidPairPreprocessedRoot, verify(allocator, source, &bundle, pcs, request, public_words, &proof));
    proof.stark_proof.proof.commitment_scheme_proof.commitments.items[0][0] ^= 1;
    proof.stark_proof.proof.commitment_scheme_proof.commitments.items[1][0] ^= 1;
    if (verify(allocator, source, &bundle, pcs, request, public_words, &proof)) |_| {
        return error.AcceptedChangedMainCommitment;
    } else |_| {}
    proof.stark_proof.proof.commitment_scheme_proof.commitments.items[1][0] ^= 1;
    proof.stark_proof.proof.commitment_scheme_proof.commitments.items[2][0] ^= 1;
    if (verify(allocator, source, &bundle, pcs, request, public_words, &proof)) |_| {
        return error.AcceptedChangedInteractionCommitment;
    } else |_| {}
    proof.stark_proof.proof.commitment_scheme_proof.commitments.items[2][0] ^= 1;
    proof.stark_proof.proof.commitment_scheme_proof.commitments.items[3][0] ^= 1;
    if (verify(allocator, source, &bundle, pcs, request, public_words, &proof)) |_| {
        return error.AcceptedChangedCompositionCommitment;
    } else |_| {}
    proof.stark_proof.proof.commitment_scheme_proof.commitments.items[3][0] ^= 1;
    proof.interaction_pow_nonce +%= 1;
    if (verify(allocator, source, &bundle, pcs, request, public_words, &proof)) |_| {
        return error.AcceptedChangedInteractionNonce;
    } else |_| {}
}
