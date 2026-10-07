//! S31 direct-M31 v4: one QM31 circuit component and an optional step chip.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const cairo = @import("stwo_cairo_frontend");
const old = @import("prove.zig");
const air = @import("air.zig");
const chip = @import("repeated_step_chip.zig");
const bridge = @import("private_boundary_bridge.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const MC = old.profiles.Blake2sM31MerkleChannel;
const Engine = old.Internal.Engine;
const Scheme = Engine.Scheme;
const Channel = MC.Channel;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;
const direct_pp = circuit.common.direct_arithmetic;
const direct_trace = circuit.witness.direct_arithmetic;
const PerComponent = circuit.common.component_list.PerComponent;

pub const profile_tag: u64 = 0x5333314449523401;
pub const private_profile_tag: u64 = 0x5333314449523501;
pub const Proof = old.Internal.CircuitProof;

pub const PreprocessedCommitment = struct {
    tree: Scheme.CommitmentTree,
    pcs_config: core.pcs.config_v2.PcsConfigV2,
    log_size: u32,

    pub fn build(allocator: std.mem.Allocator, pp: *const direct_pp.Circuit, pcs: core.pcs.config_v2.PcsConfigV2) !PreprocessedCommitment {
        var scheme = try Engine.initRevision(allocator, pcs);
        defer Engine.deinit(&scheme, allocator);
        scheme.setStorePolynomialsCoefficients();
        var views: [direct_pp.N_COLUMNS]ColumnEvaluation = undefined;
        for (pp.columns, &views) |entry, *view|
            view.* = .{ .log_size = entry.logSize(), .values = entry.values };
        var channel = Channel{};
        try commit(&scheme, allocator, try cloneColumns(allocator, &views), &channel);
        if (scheme.trees.items.len != 1) return error.PreprocessedCommitmentShape;
        try scheme.trees.items[0].share(allocator);
        return .{ .tree = scheme.trees.pop().?, .pcs_config = pcs, .log_size = pp.traceLogSize() };
    }

    pub fn deinit(self: *PreprocessedCommitment, allocator: std.mem.Allocator) void {
        self.tree.deinit(allocator);
        self.* = undefined;
    }

    pub fn root(self: *const PreprocessedCommitment) [32]u8 {
        return self.tree.root();
    }

    fn check(self: *const PreprocessedCommitment, pp: *const direct_pp.Circuit, pcs: core.pcs.config_v2.PcsConfigV2) !void {
        if (!std.meta.eql(self.pcs_config, pcs) or self.log_size != pp.traceLogSize())
            return error.PreprocessedCommitmentMismatch;
    }
};

pub const Request = struct {
    source_digest: [32]u8,
    chip_request: ?old.ChipRequest = null,
    private_boundary: ?bridge.Boundary = null,
    preprocessed_commitment: ?*const PreprocessedCommitment = null,
    test_mutation: ?@import("sparse_arithmetic.zig").Mutation = null,
    interaction_pow_time_ns: ?*u64 = null,
    fri_pow_time_ns: ?*u64 = null,
};

pub fn mixProfile(channel: *Channel, request: Request) void {
    channel.mixU64(if (request.private_boundary != null) private_profile_tag else profile_tag);
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i|
        word.* = std.mem.readInt(u32, request.source_digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
    if (request.chip_request) |item|
        channel.mixU32s(&.{ 1, item.rounds, item.constant.toU32() })
    else
        channel.mixU32s(&.{ 0, 0, 0 });
    if (request.private_boundary) |boundary|
        channel.mixU32s(&(boundary.input ++ boundary.output));
}

pub fn identityHash(
    source_digest: [32]u8,
    preprocessed_root: [32]u8,
    log_size: u32,
    blowup: u32,
    chip_request: ?old.ChipRequest,
) [32]u8 {
    return identityHashWithPrivateBoundary(source_digest, preprocessed_root, log_size, blowup, chip_request, null);
}

pub fn identityHashWithPrivateBoundary(
    source_digest: [32]u8,
    preprocessed_root: [32]u8,
    log_size: u32,
    blowup: u32,
    chip_request: ?old.ChipRequest,
    private_boundary: ?bridge.Boundary,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(if (private_boundary != null) "S31-DIRECT-M31-PRIVATE-V5\x00" else "S31-DIRECT-M31-V4\x00");
    hash.update(&source_digest);
    hash.update(&preprocessed_root);
    var word: [4]u8 = undefined;
    for ([_]u32{ log_size, blowup, if (chip_request != null) 1 else 0 }) |value| {
        std.mem.writeInt(u32, &word, value, .little);
        hash.update(&word);
    }
    if (chip_request) |item| for ([_]u32{ item.rounds, item.constant.toU32() }) |value| {
        std.mem.writeInt(u32, &word, value, .little);
        hash.update(&word);
    };
    if (private_boundary) |boundary| for (boundary.input ++ boundary.output) |address| {
        std.mem.writeInt(u32, &word, address, .little);
        hash.update(&word);
    };
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}

pub fn prove(
    allocator: std.mem.Allocator,
    values: []const QM31,
    pp: *const direct_pp.Circuit,
    template: *const air.Bundle,
    pcs: core.pcs.config_v2.PcsConfigV2,
    request: Request,
) !Proof {
    if ((request.private_boundary == null) != (pp.private_boundary == null) or
        (request.private_boundary != null and !std.meta.eql(request.private_boundary.?, pp.private_boundary.?)) or
        (request.private_boundary != null and request.chip_request == null))
        return error.InvalidPrivateBoundaryProfile;
    if (request.chip_request) |item|
        if (!std.mem.eql(u8, &item.source_digest, &request.source_digest))
            return error.InvalidDirectChipSource;
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
        var views: [direct_pp.N_COLUMNS]ColumnEvaluation = undefined;
        for (pp.columns, &views) |entry, *view|
            view.* = .{ .log_size = entry.logSize(), .values = entry.values };
        try commit(&scheme, allocator, try cloneColumns(allocator, &views), &channel);
    }
    const root = scheme.trees.items[0].commitment.root();
    var base = try direct_trace.writeBase(allocator, values, pp);
    defer base.deinit();
    var chip_base: ?chip.Base = null;
    defer if (chip_base) |*owned| owned.deinit();
    var bridge_base: ?bridge.Base = null;
    defer if (bridge_base) |*owned| owned.deinit();
    if (request.private_boundary) |boundary|
        bridge_base = try bridge.writeBase(allocator, values, boundary);
    if (request.chip_request) |item| {
        chip_base = try chip.writeBase(allocator, item.initial, item.constant, item.rounds);
        if (!std.meta.eql(chip_base.?.final, item.final) or base.output_values.len != 8)
            return error.InvalidChipBoundary;
        if (request.private_boundary == null) for (0..4) |lane| {
            if (!base.output_values[lane].eql(QM31.fromBase(item.initial[lane])) or
                !base.output_values[4 + lane].eql(QM31.fromBase(item.final[lane])))
                return error.InvalidChipBoundary;
        };
    }
    if (request.test_mutation) |mutation| {
        const extra = if (chip_base) |*owned| owned else return error.MutationRequiresChip;
        const log_size = try chip.validateRounds(request.chip_request.?.rounds);
        const middle = chip.storageIndex(request.chip_request.?.rounds / 2, log_size);
        const last = chip.storageIndex(request.chip_request.?.rounds - 1, log_size);
        switch (mutation) {
            .first_input => @constCast(extra.columns[1].values)[chip.storageIndex(0, log_size)] =
                extra.columns[1].values[chip.storageIndex(0, log_size)].add(M31.one()),
            .middle_output => @constCast(extra.columns[5].values)[middle] =
                extra.columns[5].values[middle].add(M31.one()),
            .duplicate_index => @constCast(extra.columns[0].values)[middle] =
                extra.columns[0].values[middle].sub(M31.one()),
            .last_output => @constCast(extra.columns[5].values)[last] =
                extra.columns[5].values[last].add(M31.one()),
            .wrong_constant, .interaction_cell, .claimed_sum => {},
        }
    }
    const hash = identityHashWithPrivateBoundary(
        request.source_digest,
        root,
        base.log_size,
        pcs.fri_config.log_blowup_factor,
        request.chip_request,
        request.private_boundary,
    );
    MC.mixRoot(&channel, hash);
    channel.mixFelts(base.output_values);
    if (chip_base) |*extra| {
        const joined = try joinedViews(allocator, base.columns, extra.columns);
        defer allocator.free(joined);
        if (bridge_base) |*boundary| {
            const all = try joinedViews(allocator, joined, boundary.columns);
            defer allocator.free(all);
            try commit(&scheme, allocator, try cloneColumns(allocator, all), &channel);
        } else try commit(&scheme, allocator, try cloneColumns(allocator, joined), &channel);
    } else try commit(&scheme, allocator, try cloneColumns(allocator, base.columns), &channel);
    var interaction_pow_timer = try std.time.Timer.start();
    const nonce = channel.grind(circuit.common.component_list.INTERACTION_POW_BITS);
    if (request.interaction_pow_time_ns) |slot| slot.* = interaction_pow_timer.read();
    channel.mixU64(nonce);
    const lookup = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    var interaction = try direct_trace.writeInteraction(allocator, &base, pp, lookup.z, lookup.alpha);
    defer interaction.deinit();
    const circuit_sum = try direct_trace.lookupSum(base.output_values, interaction.claimed_sum, lookup.z, lookup.alpha);
    if (request.private_boundary == null and !circuit_sum.isZero()) return error.InvalidLookupSum;
    var chip_interaction: ?chip.Interaction = null;
    defer if (chip_interaction) |*owned| owned.deinit();
    if (chip_base) |*extra| {
        chip_interaction = try chip.writeInteraction(allocator, extra.columns, lookup.z, lookup.alpha);
        if (request.test_mutation) |mutation| switch (mutation) {
            .interaction_cell => @constCast(chip_interaction.?.columns[0].values)[0] =
                chip_interaction.?.columns[0].values[0].add(M31.one()),
            .claimed_sum => chip_interaction.?.claimed_sum = chip_interaction.?.claimed_sum.add(QM31.one()),
            else => {},
        };
        const item = request.chip_request.?;
        if (request.private_boundary == null and !(try chip.endpointSum(
            chip_interaction.?.claimed_sum,
            .init(lookup.z, lookup.alpha),
            item.rounds,
            item.initial,
            item.final,
        )).isZero()) return error.InvalidChipLookupSum;
    }
    var bridge_interaction: ?bridge.Interaction = null;
    defer if (bridge_interaction) |*owned| owned.deinit();
    if (bridge_base) |*boundary| {
        bridge_interaction = try bridge.writeInteraction(allocator, boundary.columns, request.private_boundary.?, request.chip_request.?.rounds, lookup.z, lookup.alpha);
        if (!circuit_sum.add(chip_interaction.?.claimed_sum).add(bridge_interaction.?.claimed_sum).isZero())
            return error.InvalidPrivateBoundaryLookupSum;
    }
    var sums = [3]QM31{ interaction.claimed_sum, QM31.zero(), QM31.zero() };
    if (chip_interaction) |extra| sums[1] = extra.claimed_sum;
    if (bridge_interaction) |extra| sums[2] = extra.claimed_sum;
    core.channel.lookup_transcript.mixInteractionClaim(&channel, sums[0..if (bridge_interaction != null) 3 else if (chip_interaction != null) 2 else 1]);
    if (chip_interaction) |*extra| {
        const joined = try joinedViews(allocator, interaction.columns, extra.columns);
        defer allocator.free(joined);
        if (bridge_interaction) |*boundary| {
            const all = try joinedViews(allocator, joined, boundary.columns);
            defer allocator.free(all);
            try commit(&scheme, allocator, try cloneColumns(allocator, all), &channel);
        } else try commit(&scheme, allocator, try cloneColumns(allocator, joined), &channel);
    } else try commit(&scheme, allocator, try cloneColumns(allocator, interaction.columns), &channel);

    const layout = pp.layout();
    var bound = try air.bindDirectArithmetic(allocator, template, base.log_size, &layout);
    defer bound.deinit();
    var pp_logs = [_]u32{base.log_size} ** direct_pp.N_COLUMNS;
    const lifting_bound = pcs.trace_lifting_log_size - pcs.fri_config.log_blowup_factor + 1;
    var captured: [1]cairo.proving.air.component.Component = undefined;
    captured[0] = .init(allocator, &bound.components[0], &pp_logs, lifting_bound, lookup.z, lookup.alpha, interaction.claimed_sum);
    var handles: [3]prover.air.component_prover.ComponentProver = undefined;
    handles[0] = captured[0].asProverComponent();
    var chip_component: chip.Component = undefined;
    var component_count: usize = 1;
    if (chip_interaction) |extra| {
        const item = request.chip_request.?;
        chip_component = .{
            .log_size = try chip.validateRounds(item.rounds),
            .constant = item.constant,
            .main_offset = direct_trace.main_width,
            .interaction_offset = direct_trace.interaction_width,
            .elements = .init(lookup.z, lookup.alpha),
            .claimed_sum = extra.claimed_sum,
        };
        if (request.test_mutation == .wrong_constant)
            chip_component.constant = chip_component.constant.add(M31.one());
        handles[1] = chip_component.asProverComponent();
        component_count = 2;
    }
    var bridge_component: bridge.Component = undefined;
    if (bridge_interaction) |extra| {
        bridge_component = .{
            .main_offset = direct_trace.main_width + chip.main_width,
            .interaction_offset = direct_trace.interaction_width + chip.interaction_width,
            .boundary = request.private_boundary.?,
            .rounds = request.chip_request.?.rounds,
            .elements = .init(lookup.z, lookup.alpha),
            .claimed_sum = extra.claimed_sum,
        };
        handles[2] = bridge_component.asProverComponent();
        component_count = 3;
    }
    var recorder = prover.stage_profile.Recorder.initWithOptions(allocator, "s31_direct", "prove", .{ .capture_tasks = false });
    defer recorder.deinit();
    scheme_owned = false;
    var stark = try Engine.prove(
        allocator,
        handles[0..component_count],
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
    all_sums[1] = interaction.claimed_sum;
    var all_logs = [_]u32{0} ** circuit.common.component_list.N_COMPONENTS;
    all_logs[1] = base.log_size;
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
        .chip_claimed_sum = if (chip_interaction) |extra| extra.claimed_sum else null,
        .bridge_claimed_sum = if (bridge_interaction) |extra| extra.claimed_sum else null,
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

fn joinedViews(allocator: std.mem.Allocator, left: []const ColumnEvaluation, right: []const ColumnEvaluation) ![]ColumnEvaluation {
    const joined = try allocator.alloc(ColumnEvaluation, left.len + right.len);
    @memcpy(joined[0..left.len], left);
    @memcpy(joined[left.len..], right);
    return joined;
}
