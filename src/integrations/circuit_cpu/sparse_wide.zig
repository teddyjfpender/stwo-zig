//! S31 sparse-wide-v5 prover: Eq, QM31, M31-to-u32, and range-16 AIRs.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const cairo = @import("stwo_cairo_frontend");
const old = @import("prove.zig");
const air = @import("air.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const MC = old.profiles.Blake2sM31MerkleChannel;
const Engine = old.Internal.Engine;
const Scheme = Engine.Scheme;
const Channel = MC.Channel;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;
const sparse_pp = circuit.common.sparse_wide;
const sparse_trace = circuit.witness.sparse_wide;
const PerComponent = circuit.common.component_list.PerComponent;

pub const profile_tag: u64 = 0x5333315350573501;
pub const Proof = old.Internal.CircuitProof;

/// A topology-owned sparse preprocessed commitment. A proof leases the tree,
/// so its Merkle root and polynomial data can be reused across assignments.
pub const PreprocessedCommitment = struct {
    tree: Scheme.CommitmentTree,
    pcs_config: core.pcs.config_v2.PcsConfigV2,
    log_sizes: [sparse_pp.N_COLUMNS]u32,

    pub fn build(
        allocator: std.mem.Allocator,
        pp: *const sparse_pp.Circuit,
        pcs_config: core.pcs.config_v2.PcsConfigV2,
    ) !PreprocessedCommitment {
        var scheme = try Engine.initRevision(allocator, pcs_config);
        defer Engine.deinit(&scheme, allocator);
        scheme.setStorePolynomialsCoefficients();
        var views: [sparse_pp.N_COLUMNS]ColumnEvaluation = undefined;
        var logs: [sparse_pp.N_COLUMNS]u32 = undefined;
        for (pp.columns, &views, &logs) |entry, *view, *log| {
            const size = entry.logSize();
            view.* = .{ .log_size = size, .values = entry.values };
            log.* = size;
        }
        var channel = Channel{};
        try commit(&scheme, allocator, try cloneColumns(allocator, &views), &channel);
        if (scheme.trees.items.len != 1) return error.PreprocessedCommitmentShape;
        try scheme.trees.items[0].share(allocator);
        return .{
            .tree = scheme.trees.pop().?,
            .pcs_config = pcs_config,
            .log_sizes = logs,
        };
    }

    pub fn deinit(self: *PreprocessedCommitment, allocator: std.mem.Allocator) void {
        self.tree.deinit(allocator);
        self.* = undefined;
    }

    pub fn root(self: *const PreprocessedCommitment) [32]u8 {
        return self.tree.root();
    }

    fn check(self: *const PreprocessedCommitment, pp: *const sparse_pp.Circuit, pcs_config: core.pcs.config_v2.PcsConfigV2) !void {
        if (!std.meta.eql(self.pcs_config, pcs_config)) return error.PreprocessedCommitmentMismatch;
        for (pp.columns, self.log_sizes) |entry, log|
            if (entry.logSize() != log) return error.PreprocessedCommitmentMismatch;
    }
};

pub const Request = struct {
    source_digest: [32]u8,
    preprocessed_commitment: ?*const PreprocessedCommitment = null,
    /// Optional execution-only timing output; never enters proof bytes.
    pow_time_ns: ?*u64 = null,
    fri_pow_time_ns: ?*u64 = null,
};

pub fn mixProfile(channel: *Channel, request: Request) void {
    channel.mixU64(profile_tag);
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i|
        word.* = std.mem.readInt(u32, request.source_digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
    channel.mixU32s(&.{ 0, 0, 0 });
}

pub fn identityHash(
    source_digest: [32]u8,
    preprocessed_root: [32]u8,
    logs: [4]u32,
    blowup: u32,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("S31-SPARSE-WIDE-V5\x00");
    hash.update(&source_digest);
    hash.update(&preprocessed_root);
    var word: [4]u8 = undefined;
    for (logs) |log| {
        std.mem.writeInt(u32, &word, log, .little);
        hash.update(&word);
    }
    std.mem.writeInt(u32, &word, blowup, .little);
    hash.update(&word);
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}

pub fn prove(
    allocator: std.mem.Allocator,
    values: []const QM31,
    pp: *const sparse_pp.Circuit,
    template: *const air.Bundle,
    pcs: core.pcs.config_v2.PcsConfigV2,
    request: Request,
) !Proof {
    var channel = Channel{};
    mixProfile(&channel, request);
    core.channel.lookup_transcript.mixChannelSalt(&channel, 0);
    pcs.fri_config.mixInto(&channel);
    var scheme = try Engine.initRevision(allocator, pcs);
    var scheme_owned = true;
    errdefer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setStorePolynomialsCoefficients();
    if (request.preprocessed_commitment) |cached| {
        try cached.check(pp, pcs);
        var lease = cached.tree.retainShared();
        errdefer lease.deinit(allocator);
        try scheme.appendCommittedTree(allocator, lease, &channel);
    } else {
        var pp_views: [sparse_pp.N_COLUMNS]ColumnEvaluation = undefined;
        for (pp.columns, &pp_views) |entry, *view|
            view.* = .{ .log_size = entry.logSize(), .values = entry.values };
        try commit(&scheme, allocator, try cloneColumns(allocator, &pp_views), &channel);
    }
    const root = scheme.trees.items[0].commitment.root();
    var base = try sparse_trace.writeBase(allocator, values, pp);
    defer base.deinit();
    const hash = identityHash(
        request.source_digest,
        root,
        base.log_sizes,
        pcs.fri_config.log_blowup_factor,
    );
    MC.mixRoot(&channel, hash);
    channel.mixFelts(base.output_values);
    try commit(&scheme, allocator, try cloneColumns(allocator, base.columns), &channel);
    var pow_timer = try std.time.Timer.start();
    const nonce = channel.grind(circuit.common.component_list.INTERACTION_POW_BITS);
    if (request.pow_time_ns) |slot| slot.* = pow_timer.read();
    channel.mixU64(nonce);
    const lookup = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    var interaction = try sparse_trace.writeInteraction(
        allocator,
        &base,
        pp,
        lookup.z,
        lookup.alpha,
    );
    defer interaction.deinit();
    if (!(try sparse_trace.lookupSum(
        base.output_values,
        interaction.claimed_sums,
        lookup.z,
        lookup.alpha,
    )).isZero()) return error.InvalidLookupSum;
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &interaction.claimed_sums);
    try commit(&scheme, allocator, try cloneColumns(allocator, interaction.columns), &channel);

    const layout = pp.layout();
    var bound = try air.bindSparseWide(allocator, template, base.log_sizes, &layout);
    defer bound.deinit();
    var pp_logs: [sparse_pp.N_COLUMNS]u32 = undefined;
    for (layout.entries, &pp_logs) |entry, *log| log.* = entry.log_size;
    const lifting_bound = pcs.trace_lifting_log_size - pcs.fri_config.log_blowup_factor + 1;
    var captured: [4]cairo.proving.air.component.Component = undefined;
    var handles: [4]prover.air.component_prover.ComponentProver = undefined;
    for (bound.components, &captured, &handles, interaction.claimed_sums) |*source, *runtime, *handle, claimed| {
        runtime.* = .init(allocator, source, &pp_logs, lifting_bound, lookup.z, lookup.alpha, claimed);
        runtime.native_executor = null;
        handle.* = runtime.asProverComponent();
    }
    var recorder = prover.stage_profile.Recorder.initWithOptions(allocator, "s31_sparse_wide", "prove", .{ .capture_tasks = false });
    defer recorder.deinit();
    scheme_owned = false;
    var stark = try Engine.prove(
        allocator,
        &handles,
        &channel,
        scheme,
        .{ .include_all_preprocessed_columns = true, .recorder = if (request.fri_pow_time_ns != null) &recorder else null },
    );
    errdefer stark.deinit(allocator);
    if (request.fri_pow_time_ns) |slot| {
        var profile = try recorder.snapshot(allocator);
        defer profile.deinit(allocator);
        const seconds = findStageSeconds(profile.stages, "proof_of_work") orelse
            return error.MissingFriProofOfWorkStage;
        slot.* = @intFromFloat(seconds * std.time.ns_per_s);
    }
    var all_sums = [_]QM31{QM31.zero()} ** circuit.common.component_list.N_COMPONENTS;
    for (sparse_pp.active_component_indices, interaction.claimed_sums) |index, sum|
        all_sums[index] = sum;
    var all_logs = [_]u32{0} ** circuit.common.component_list.N_COMPONENTS;
    for (sparse_pp.active_component_indices, base.log_sizes) |index, log|
        all_logs[index] = log;
    return .{
        .allocator = allocator,
        .pcs_config = pcs,
        .output_values = try allocator.dupe(QM31, base.output_values),
        .interaction_pow_nonce = nonce,
        .claimed_sums = PerComponent(QM31).fromArray(all_sums),
        .stark_proof = stark,
        .channel_salt = 0,
        .circuit_hash = hash,
        .component_log_sizes = PerComponent(u32).fromArray(all_logs),
        .chip_claimed_sum = null,
    };
}

fn findStageSeconds(nodes: []const prover.stage_profile.StageNode, id: []const u8) ?f64 {
    for (nodes) |node| {
        if (std.mem.eql(u8, node.id, id)) return node.seconds;
        if (node.children) |children|
            if (findStageSeconds(children, id)) |seconds| return seconds;
    }
    return null;
}

fn commit(scheme: *Scheme, allocator: std.mem.Allocator, columns: []ColumnEvaluation, channel: *Channel) !void {
    try Engine.commit(scheme, allocator, columns, null, channel);
    try Engine.flushPendingCommit(scheme, allocator, channel);
}

fn cloneColumns(allocator: std.mem.Allocator, source: []const ColumnEvaluation) ![]ColumnEvaluation {
    const result = try allocator.alloc(ColumnEvaluation, source.len);
    var ready: usize = 0;
    errdefer {
        for (result[0..ready]) |entry| allocator.free(entry.values);
        allocator.free(result);
    }
    for (source, result) |entry, *slot| {
        slot.* = .{ .log_size = entry.log_size, .values = try allocator.dupe(M31, entry.values) };
        ready += 1;
    }
    return result;
}
