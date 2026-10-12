//! Experimental, distinct-profile native proof for exactly four mixed calls.
//!
//! Kept separate from the fixed N=3 adapter so its transcript and proof bytes
//! remain unchanged while this bounded extension is reviewed.
//!
//! Only the source-pinned S31 wrapper may admit serialized proof bytes. This
//! adapter rechecks source bytes, AIR bundle, live geometry and fixed root,
//! but cannot parse S31 or certify a caller-supplied manifest digest itself.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const cairo = @import("stwo_cairo_frontend");
const old = @import("prove.zig");
const air = @import("air.zig");
const many = @import("private_many_boundary.zig");
const plan_admission = @import("direct_many_plan_admission.zig");
const mixed = @import("direct_mixed_schedule.zig");
const pair_chip = @import("tagged_pair_chip.zig");
const pair_bridge = @import("tagged_pair_bridge.zig");
const many_chip = @import("tagged_many_chip.zig");
const many_bridge = @import("tagged_many_bridge.zig");
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
const Sha256 = std.crypto.hash.sha2.Sha256;
const profile_tag: u64 = 0x5333314d49580201; // S31MIX, profile 2.
pub const n_calls: u8 = 4;
pub const n_components: usize = 1 + 2 * n_calls;

pub const Selected = struct {
    source_sha256: [32]u8,
    manifest_sha256: [32]u8,
    fixed_root: [32]u8,
    circuit_program_sha256: [32]u8,
    plan: many.Plan,
    geometry: mixed.Geometry,

    pub fn effectiveDigest(self: *const Selected) [32]u8 {
        var h = Sha256.init(.{});
        h.update("S31-MIXED-MANIFEST-TRANSCRIPT-V2\x00");
        h.update(&self.source_sha256);
        h.update(&self.manifest_sha256);
        var result: [32]u8 = undefined;
        h.final(&result);
        return result;
    }

    pub fn circuitIdentity(self: *const Selected) [32]u8 {
        var h = Sha256.init(.{});
        h.update("S31-MIXED-CIRCUIT-IDENTITY-V2\x00");
        const effective = self.effectiveDigest();
        h.update(&effective);
        h.update(&self.fixed_root);
        hashInt(&h, self.geometry.slots[0].trace_log_size);
        hashInt(&h, self.geometry.pcs.fri_config.log_blowup_factor);
        hashInt(&h, self.plan.count);
        for (self.plan.callSlice()) |call| hashCall(&h, call);
        var result: [32]u8 = undefined;
        h.final(&result);
        return result;
    }
};

pub const Proof = struct {
    allocator: std.mem.Allocator,
    pcs_config: core.pcs.config_v2.PcsConfigV2,
    output_values: []QM31,
    interaction_pow_nonce: u64,
    claimed_sums: [many.max_components]QM31,
    sum_count: usize,
    stark_proof: core.proof.ExtendedStarkProof(H),
    circuit_hash: [32]u8,

    pub fn deinit(self: *@This()) void {
        self.stark_proof.deinit(self.allocator);
        self.allocator.free(self.output_values);
        self.* = undefined;
    }
};

pub const BorrowedProof = struct {
    output_values: []const QM31,
    interaction_pow_nonce: u64,
    claimed_sums: [many.max_components]QM31,
    sum_count: usize,
    stark_proof: *const core.proof.StarkProof(H),
    circuit_hash: [32]u8,
};

const ChipInteraction = union(enum) {
    pair: pair_chip.Interaction,
    many: many_chip.Interaction,

    fn columns(self: *const @This()) []const ColumnEvaluation {
        return switch (self.*) {
            .pair => |value| value.columns,
            .many => |value| value.columns,
        };
    }
    fn sum(self: *const @This()) QM31 {
        return switch (self.*) {
            .pair => |value| value.claimed_sum,
            .many => |value| value.claimed_sum,
        };
    }
    fn deinit(self: *@This()) void {
        switch (self.*) {
            .pair => |*value| value.deinit(),
            .many => |*value| value.deinit(),
        }
    }
};

const BridgeBase = union(enum) {
    pair: pair_bridge.Base,
    many: many_bridge.Base,

    fn columns(self: *const @This()) []const ColumnEvaluation {
        return switch (self.*) {
            .pair => |value| value.columns,
            .many => |value| value.columns,
        };
    }
    fn deinit(self: *@This()) void {
        switch (self.*) {
            .pair => |*value| value.deinit(),
            .many => |*value| value.deinit(),
        }
    }
};

const BridgeInteraction = union(enum) {
    pair: pair_bridge.Interaction,
    many: many_bridge.Interaction,

    fn columns(self: *const @This()) []const ColumnEvaluation {
        return switch (self.*) {
            .pair => |value| value.columns,
            .many => |value| value.columns,
        };
    }
    fn sum(self: *const @This()) QM31 {
        return switch (self.*) {
            .pair => |value| value.claimed_sum,
            .many => |value| value.claimed_sum,
        };
    }
    fn deinit(self: *@This()) void {
        switch (self.*) {
            .pair => |*value| value.deinit(),
            .many => |*value| value.deinit(),
        }
    }
};

fn digest(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(bytes, &result, .{});
    return result;
}

fn hashInt(h: *Sha256, value: anytype) void {
    var bytes: [@sizeOf(@TypeOf(value))]u8 = undefined;
    std.mem.writeInt(@TypeOf(value), &bytes, value, .little);
    h.update(&bytes);
}

fn hashCall(h: *Sha256, call: many.Call) void {
    hashInt(h, call.call_id);
    hashInt(h, call.rounds);
    hashInt(h, call.constant.toU32());
    for (call.input ++ call.output) |address| hashInt(h, address);
}

fn mixProfile(channel: *Channel, selected: *const Selected) void {
    channel.mixU64(profile_tag);
    const effective = selected.effectiveDigest();
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, id| word.* = std.mem.readInt(u32, effective[4 * id ..][0..4], .little);
    channel.mixU32s(&words);
    channel.mixU32s(&.{selected.plan.count});
    for (selected.plan.callSlice()) |call| {
        channel.mixU32s(&.{ call.call_id, call.rounds, call.constant.toU32() });
        channel.mixU32s(&(call.input ++ call.output));
    }
}

fn validatePublicOutputShape(source: CircuitView) !void {
    if (source.output.len != 9) return error.InvalidMixedPublicStatement;
    for (source.output, 0..) |address, index|
        if (address != @as(u32, @intCast(index + 2))) return error.InvalidMixedPublicStatement;
}

fn validateSourceAndGeometry(
    allocator: std.mem.Allocator,
    pp: *const direct_pp.Circuit,
    template: *const air.Bundle,
    selected: *const Selected,
    source_bytes: []const u8,
    air_bytes: []const u8,
) !void {
    if (selected.plan.count != n_calls or selected.geometry.slot_count != n_components or
        selected.geometry.version != mixed.version or
        !std.meta.eql(selected.source_sha256, digest(source_bytes)))
        return error.InvalidMixedSelection;
    var bundle_digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bundle_digest, air.bundle_sha256) catch unreachable;
    if (!std.meta.eql(digest(air_bytes), bundle_digest) or
        !std.meta.eql(try pp.preprocessedRoot(allocator, 1), selected.fixed_root))
        return error.InvalidMixedSelection;
    const rebuilt = try mixed.inspect(allocator, pp, template, selected.plan);
    if (!std.meta.eql(rebuilt, selected.geometry)) return error.InvalidMixedSelection;
    const layout = pp.layout();
    var bound = try air.bindDirectArithmetic(allocator, template, pp.traceLogSize(), &layout);
    defer bound.deinit();
    if (!std.meta.eql(try air.directProgramBindingDigest(air_bytes, &bound), selected.circuit_program_sha256))
        return error.InvalidMixedSelection;
}

fn selectedColumns(
    dst: []ColumnEvaluation,
    selected: *const Selected,
    circuit_columns: []const ColumnEvaluation,
    chips: anytype,
    bridges: anytype,
    comptime is_main: bool,
) !void {
    var at: usize = 0;
    for (selected.geometry.slotSlice(), 0..) |slot, index| {
        const columns: []const ColumnEvaluation = if (index == 0) circuit_columns else blk: {
            const id: usize = @intCast(slot.call_id orelse return error.InvalidMixedSelection);
            if (id >= n_calls) return error.InvalidMixedSelection;
            break :blk if (index % 2 == 1) (if (is_main) chips[id].columns else chips[id].columns()) else bridges[id].columns();
        };
        const offset = if (is_main) slot.main_offset else slot.interaction_offset;
        const width = if (is_main) slot.main_columns else slot.interaction_columns;
        if (at != offset or columns.len != width or width > dst.len - at) return error.InvalidMixedSelection;
        @memcpy(dst[at..][0..width], columns);
        at += width;
    }
    if (at != dst.len) return error.InvalidMixedSelection;
}

fn selectedSums(selected: *const Selected, circuit_sum: QM31, chips: []const ChipInteraction, bridges: []const BridgeInteraction) ![many.max_components]QM31 {
    var sums = [_]QM31{QM31.zero()} ** many.max_components;
    for (selected.geometry.slotSlice(), 0..) |slot, index| {
        if (index == 0) {
            sums[index] = circuit_sum;
            continue;
        }
        const id: usize = @intCast(slot.call_id orelse return error.InvalidMixedSelection);
        if (id >= n_calls) return error.InvalidMixedSelection;
        sums[index] = if (index % 2 == 1) chips[id].sum() else bridges[id].sum();
    }
    return sums;
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

fn checkRuntimeHandles(comptime T: type, allocator: std.mem.Allocator, handles: []const T, selected: *const Selected) !void {
    if (handles.len != selected.geometry.slot_count) return error.InvalidMixedRuntimeRoster;
    for (handles, selected.geometry.slotSlice()) |handle, slot| {
        if (handle.nConstraints() != slot.n_constraints or
            handle.maxConstraintLogDegreeBound() != slot.evaluation_log_size or
            handle.compositionLogSplit() != selected.geometry.composition_split)
            return error.InvalidMixedRuntimeRoster;
        const indices = try handle.preprocessedColumnIndices(allocator);
        defer allocator.free(indices);
        if (indices.len != slot.preprocessed_count) return error.InvalidMixedRuntimeRoster;
        for (indices, slot.preprocessed_indices[0..slot.preprocessed_count]) |actual, expected|
            if (actual != expected) return error.InvalidMixedRuntimeRoster;
    }
}

/// The allocator must be safe for concurrent use by the composition workers.
/// The S31 wrapper constructs `selected` from literal source before calling.
pub fn proveSourceBound(
    allocator: std.mem.Allocator,
    source: CircuitView,
    values: []const QM31,
    source_bytes: []const u8,
    air_bytes: []const u8,
    selected: *const Selected,
) !Proof {
    try plan_admission.requireResourceShape(source);
    try validatePublicOutputShape(source);
    var pp = try plan_admission.BoundedPlan.fromLegacy(selected.plan).preprocessed(allocator, source);
    defer pp.deinit(allocator);
    var template = try air.parse(allocator, air_bytes);
    defer template.deinit();
    try validateSourceAndGeometry(allocator, &pp, &template, selected, source_bytes, air_bytes);
    const pcs = selected.geometry.pcs;
    const layout = pp.layout();
    var bound = try air.bindDirectArithmetic(allocator, &template, pp.traceLogSize(), &layout);
    defer bound.deinit();
    if (bound.components.len != 1) return error.InvalidMixedRuntimeRoster;
    const states = try selected.plan.extract(values);
    var channel = Channel{};
    var order: many.TranscriptOrder = .{};
    mixProfile(&channel, selected);
    try order.accept(.profile);
    core.channel.lookup_transcript.mixChannelSalt(&channel, 0);
    try order.accept(.channel_salt);
    pcs.fri_config.mixInto(&channel);
    try order.accept(.fri_config);
    var scheme = try Engine.initRevision(allocator, pcs);
    var scheme_owned = true;
    errdefer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setStorePolynomialsCoefficients();
    var pp_views: [direct_pp.N_COLUMNS]ColumnEvaluation = undefined;
    for (pp.columns, &pp_views) |entry, *view| view.* = .{ .log_size = entry.logSize(), .values = entry.values };
    try commit(&scheme, allocator, &pp_views, &channel);
    try order.accept(.preprocessed_commitment);
    const root = scheme.trees.items[0].commitment.root();
    if (!std.meta.eql(root, selected.fixed_root)) return error.InvalidMixedFixedRoot;
    var base = try direct_trace.writeBase(allocator, values, &pp);
    defer base.deinit();
    if (base.output_values.len != 8 or base.log_size != selected.geometry.slots[0].trace_log_size)
        return error.InvalidMixedPublicStatement;
    var chip_base: [n_calls]many_chip.Base = undefined;
    var bridge_base: [n_calls]BridgeBase = undefined;
    var chips_ready: usize = 0;
    var bridges_ready: usize = 0;
    defer for (chip_base[0..chips_ready]) |*item| item.deinit();
    defer for (bridge_base[0..bridges_ready]) |*item| item.deinit();
    for (selected.plan.callSlice(), states[0..n_calls], 0..) |call, state, id| {
        chip_base[id] = if (id < 2)
            try pair_chip.writeBase(allocator, state.input, call.constant, call.rounds)
        else
            try many_chip.writeBase(allocator, state.input, call.constant, call.rounds);
        chips_ready += 1;
        if (!std.meta.eql(chip_base[id].final, state.output)) return error.WrongMixedChipClaim;
        bridge_base[id] = if (id < 2)
            .{ .pair = try pair_bridge.writeBase(allocator, values, call) }
        else
            .{ .many = try many_bridge.writeBase(allocator, values, call) };
        bridges_ready += 1;
    }
    const identity = selected.circuitIdentity();
    MC.mixRoot(&channel, identity);
    try order.accept(.circuit_identity);
    channel.mixFelts(base.output_values);
    try order.accept(.public_statement);
    var main_views: [mixed.max_tree_width]ColumnEvaluation = undefined;
    const main_width: usize = selected.geometry.tree_columns[1];
    try selectedColumns(main_views[0..main_width], selected, base.columns, chip_base[0..n_calls], bridge_base[0..n_calls], true);
    try commit(&scheme, allocator, main_views[0..main_width], &channel);
    try order.accept(.main_commitment);
    const nonce = channel.grind(circuit.common.component_list.INTERACTION_POW_BITS);
    channel.mixU64(nonce);
    try order.accept(.interaction_pow_nonce);
    const lookup = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    try order.accept(.lookup_challenge);
    var circuit_interaction = try direct_trace.writeInteraction(allocator, &base, &pp, lookup.z, lookup.alpha);
    defer circuit_interaction.deinit();
    var chip_interaction: [n_calls]ChipInteraction = undefined;
    var bridge_interaction: [n_calls]BridgeInteraction = undefined;
    var chip_interactions_ready: usize = 0;
    var bridge_interactions_ready: usize = 0;
    defer for (chip_interaction[0..chip_interactions_ready]) |*item| item.deinit();
    defer for (bridge_interaction[0..bridge_interactions_ready]) |*item| item.deinit();
    for (selected.plan.callSlice(), 0..) |call, id| {
        chip_interaction[id] = if (id < 2)
            .{ .pair = try pair_chip.writeInteraction(allocator, chip_base[id].columns, call.call_id, lookup.z, lookup.alpha) }
        else
            .{ .many = try many_chip.writeInteraction(allocator, chip_base[id].columns, call.call_id, lookup.z, lookup.alpha) };
        chip_interactions_ready += 1;
        bridge_interaction[id] = if (id < 2)
            .{ .pair = try pair_bridge.writeInteraction(allocator, bridge_base[id].columns(), call, lookup.z, lookup.alpha) }
        else
            .{ .many = try many_bridge.writeInteraction(allocator, bridge_base[id].columns(), call, lookup.z, lookup.alpha) };
        bridge_interactions_ready += 1;
    }
    const sums = try selectedSums(selected, circuit_interaction.claimed_sum, &chip_interaction, &bridge_interaction);
    var closure = try direct_trace.lookupSum(base.output_values, sums[0], lookup.z, lookup.alpha);
    for (sums[1..n_components]) |sum| closure = closure.add(sum);
    if (!closure.isZero()) return error.InvalidMixedLookupSum;
    core.channel.lookup_transcript.mixInteractionClaim(&channel, sums[0..n_components]);
    try order.accept(.claimed_sums);
    var interaction_views: [mixed.max_tree_width]ColumnEvaluation = undefined;
    const interaction_width: usize = selected.geometry.tree_columns[2];
    try selectedColumns(interaction_views[0..interaction_width], selected, circuit_interaction.columns, chip_interaction[0..n_calls], bridge_interaction[0..n_calls], false);
    try commit(&scheme, allocator, interaction_views[0..interaction_width], &channel);
    try order.accept(.interaction_commitment);
    var pp_logs = [_]u32{base.log_size} ** direct_pp.N_COLUMNS;
    const lifting = pcs.trace_lifting_log_size - pcs.fri_config.log_blowup_factor + 1;
    var captured = cairo.proving.air.component.Component.init(allocator, &bound.components[0], &pp_logs, lifting, lookup.z, lookup.alpha, sums[0]);
    var pc: [n_calls]pair_chip.Component = undefined;
    var pb: [n_calls]pair_bridge.Component = undefined;
    var mc: [n_calls]many_chip.Component = undefined;
    var mb: [n_calls]many_bridge.Component = undefined;
    var handles: [n_components]prover.air.component_prover.ComponentProver = undefined;
    handles[0] = captured.asProverComponent();
    for (selected.geometry.slotSlice()[1..], 1..) |slot, index| {
        const id: usize = @intCast(slot.call_id orelse return error.InvalidMixedRuntimeRoster);
        const call = selected.plan.calls[id];
        switch (slot.kind orelse return error.InvalidMixedRuntimeRoster) {
            .pair_chip => {
                pc[id] = .{ .log_size = slot.trace_log_size, .call_id = call.call_id, .constant = call.constant, .main_offset = slot.main_offset, .interaction_offset = slot.interaction_offset, .elements = .init(lookup.z, lookup.alpha), .claimed_sum = sums[index] };
                handles[index] = pc[id].asProverComponent();
            },
            .pair_bridge => {
                pb[id] = .{ .main_offset = slot.main_offset, .interaction_offset = slot.interaction_offset, .boundary = call, .elements = .init(lookup.z, lookup.alpha), .claimed_sum = sums[index] };
                handles[index] = pb[id].asProverComponent();
            },
            .many_chip => {
                mc[id] = .{ .log_size = slot.trace_log_size, .call_id = call.call_id, .constant = call.constant, .main_offset = slot.main_offset, .interaction_offset = slot.interaction_offset, .elements = .init(lookup.z, lookup.alpha), .claimed_sum = sums[index] };
                handles[index] = mc[id].asProverComponent();
            },
            .many_bridge => {
                mb[id] = .{ .main_offset = slot.main_offset, .interaction_offset = slot.interaction_offset, .boundary = call, .elements = .init(lookup.z, lookup.alpha), .claimed_sum = sums[index] };
                handles[index] = mb[id].asProverComponent();
            },
        }
    }
    try checkRuntimeHandles(prover.air.component_prover.ComponentProver, allocator, &handles, selected);
    scheme_owned = false;
    var stark = try Engine.prove(allocator, &handles, &channel, scheme, .{ .include_all_preprocessed_columns = true });
    try order.accept(.pcs_proof);
    try order.finish();
    errdefer stark.deinit(allocator);
    return .{
        .allocator = allocator,
        .pcs_config = pcs,
        .output_values = try allocator.dupe(QM31, base.output_values),
        .interaction_pow_nonce = nonce,
        .claimed_sums = sums,
        .sum_count = n_components,
        .stark_proof = stark,
        .circuit_hash = identity,
    };
}

pub fn verifySourceBoundBorrowed(
    allocator: std.mem.Allocator,
    source: CircuitView,
    source_bytes: []const u8,
    air_bytes: []const u8,
    selected: *const Selected,
    public_words: [8]u32,
    proof: BorrowedProof,
) !void {
    try plan_admission.requireResourceShape(source);
    try validatePublicOutputShape(source);
    var pp = try plan_admission.BoundedPlan.fromLegacy(selected.plan).preprocessed(allocator, source);
    defer pp.deinit(allocator);
    var template = try air.parse(allocator, air_bytes);
    defer template.deinit();
    try validateSourceAndGeometry(allocator, &pp, &template, selected, source_bytes, air_bytes);
    const pcs = selected.geometry.pcs;
    const identity = selected.circuitIdentity();
    if (proof.sum_count != n_components or !std.meta.eql(proof.circuit_hash, identity))
        return error.InvalidMixedProofIdentity;
    for (proof.claimed_sums[n_components..]) |unused|
        if (!unused.isZero()) return error.NonCanonicalMixedClaimedSums;
    var committed = try direct.PreprocessedCommitment.build(allocator, &pp, pcs);
    defer committed.deinit(allocator);
    const roots = proof.stark_proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4 or !std.meta.eql(roots[0], committed.root()))
        return error.InvalidMixedPreprocessedRoot;
    if (!std.meta.eql(proof.stark_proof.commitment_scheme_proof.config, core.protocol_revision.Revision.proving_5a7c5ed.legacyView(pcs)))
        return error.InvalidMixedPcsConfig;
    var outputs: [8]QM31 = undefined;
    for (public_words, &outputs, 0..) |word, *output, index| {
        if (word >= core.fields.m31.Modulus or proof.output_values.len != 8)
            return error.InvalidMixedPublicStatement;
        output.* = QM31.fromBase(M31.fromCanonical(word));
        if (!proof.output_values[index].eql(output.*)) return error.InvalidMixedPublicStatement;
    }
    var channel = Channel{};
    var order: many.TranscriptOrder = .{};
    mixProfile(&channel, selected);
    try order.accept(.profile);
    core.channel.lookup_transcript.mixChannelSalt(&channel, 0);
    try order.accept(.channel_salt);
    pcs.fri_config.mixInto(&channel);
    try order.accept(.fri_config);
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(allocator, pcs);
    defer scheme.deinit(allocator);
    var pp_logs = [_]u32{pp.traceLogSize()} ** direct_pp.N_COLUMNS;
    try scheme.commit(allocator, roots[0], &pp_logs, &channel);
    try order.accept(.preprocessed_commitment);
    MC.mixRoot(&channel, identity);
    try order.accept(.circuit_identity);
    channel.mixFelts(&outputs);
    try order.accept(.public_statement);
    var main_logs: [mixed.max_tree_width]u32 = undefined;
    const main_width: usize = selected.geometry.tree_columns[1];
    for (selected.geometry.columns[1][0..main_width], main_logs[0..main_width]) |column, *log| log.* = column.log_size;
    try scheme.commit(allocator, roots[1], main_logs[0..main_width], &channel);
    try order.accept(.main_commitment);
    if (!channel.verifyPowNonce(circuit.common.component_list.INTERACTION_POW_BITS, proof.interaction_pow_nonce))
        return error.InvalidMixedInteractionNonce;
    channel.mixU64(proof.interaction_pow_nonce);
    try order.accept(.interaction_pow_nonce);
    const lookup = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    try order.accept(.lookup_challenge);
    var closure = try direct_trace.lookupSum(&outputs, proof.claimed_sums[0], lookup.z, lookup.alpha);
    for (proof.claimed_sums[1..n_components]) |sum| closure = closure.add(sum);
    if (!closure.isZero()) return error.InvalidMixedLookupSum;
    core.channel.lookup_transcript.mixInteractionClaim(&channel, proof.claimed_sums[0..n_components]);
    try order.accept(.claimed_sums);
    var interaction_logs: [mixed.max_tree_width]u32 = undefined;
    const interaction_width: usize = selected.geometry.tree_columns[2];
    for (selected.geometry.columns[2][0..interaction_width], interaction_logs[0..interaction_width]) |column, *log| log.* = column.log_size;
    try scheme.commit(allocator, roots[2], interaction_logs[0..interaction_width], &channel);
    try order.accept(.interaction_commitment);
    const layout = pp.layout();
    var bound = try air.bindDirectArithmetic(allocator, &template, pp.traceLogSize(), &layout);
    defer bound.deinit();
    if (bound.components.len != 1 or
        !std.meta.eql(try air.directProgramBindingDigest(air_bytes, &bound), selected.circuit_program_sha256))
        return error.InvalidMixedRuntimeRoster;
    const lifting = pcs.trace_lifting_log_size - pcs.fri_config.log_blowup_factor + 1;
    var captured = cairo.proving.air.component.Component.init(allocator, &bound.components[0], &pp_logs, lifting, lookup.z, lookup.alpha, proof.claimed_sums[0]);
    var pc: [n_calls]pair_chip.Component = undefined;
    var pb: [n_calls]pair_bridge.Component = undefined;
    var mc: [n_calls]many_chip.Component = undefined;
    var mb: [n_calls]many_bridge.Component = undefined;
    var handles: [n_components]core.air.components.Component = undefined;
    handles[0] = captured.asVerifierComponent();
    for (selected.geometry.slotSlice()[1..], 1..) |slot, index| {
        const id: usize = @intCast(slot.call_id orelse return error.InvalidMixedRuntimeRoster);
        if (id >= n_calls) return error.InvalidMixedRuntimeRoster;
        const call = selected.plan.calls[id];
        switch (slot.kind orelse return error.InvalidMixedRuntimeRoster) {
            .pair_chip => {
                pc[id] = .{ .log_size = slot.trace_log_size, .call_id = call.call_id, .constant = call.constant, .main_offset = slot.main_offset, .interaction_offset = slot.interaction_offset, .elements = .init(lookup.z, lookup.alpha), .claimed_sum = proof.claimed_sums[index] };
                handles[index] = pc[id].asVerifierComponent();
            },
            .pair_bridge => {
                pb[id] = .{ .main_offset = slot.main_offset, .interaction_offset = slot.interaction_offset, .boundary = call, .elements = .init(lookup.z, lookup.alpha), .claimed_sum = proof.claimed_sums[index] };
                handles[index] = pb[id].asVerifierComponent();
            },
            .many_chip => {
                mc[id] = .{ .log_size = slot.trace_log_size, .call_id = call.call_id, .constant = call.constant, .main_offset = slot.main_offset, .interaction_offset = slot.interaction_offset, .elements = .init(lookup.z, lookup.alpha), .claimed_sum = proof.claimed_sums[index] };
                handles[index] = mc[id].asVerifierComponent();
            },
            .many_bridge => {
                mb[id] = .{ .main_offset = slot.main_offset, .interaction_offset = slot.interaction_offset, .boundary = call, .elements = .init(lookup.z, lookup.alpha), .claimed_sum = proof.claimed_sums[index] };
                handles[index] = mb[id].asVerifierComponent();
            },
        }
    }
    try checkRuntimeHandles(core.air.components.Component, allocator, &handles, selected);
    var capture: core.verifier.ProofCapture(H) = undefined;
    try core.verifier.verifyBorrowedExWithProofCapture(H, MC, allocator, &handles, &channel, &scheme, proof.stark_proof, true, &capture);
    try order.accept(.pcs_proof);
    try order.finish();
    defer capture.deinit(allocator);
}

test "mixed N=4 native proof uses interleaved pair and many AIRs" {
    const allocator = std.heap.smp_allocator;
    var ctx = try circuit.builder.Context(QM31).init(allocator, 8);
    defer ctx.deinit();
    const starts = [4][4]M31{
        .{ M31.fromCanonical(3), M31.fromCanonical(5), M31.fromCanonical(7), M31.fromCanonical(11) },
        .{ M31.fromCanonical(2), M31.fromCanonical(4), M31.fromCanonical(6), M31.fromCanonical(8) },
        .{ M31.fromCanonical(9), M31.fromCanonical(10), M31.fromCanonical(12), M31.fromCanonical(14) },
        .{ M31.fromCanonical(15), M31.fromCanonical(16), M31.fromCanonical(18), M31.fromCanonical(20) },
    };
    const constants = [4]M31{ M31.fromCanonical(13), M31.fromCanonical(17), M31.fromCanonical(19), M31.fromCanonical(23) };
    const rounds = [4]u32{ 16, 32, 16, 16 };
    var plan: many.Plan = .{ .count = n_calls };
    var results: [4][4]circuit.builder.Var = undefined;
    for (0..4) |id| {
        const final = try @import("repeated_step_chip.zig").direct(starts[id], constants[id], rounds[id]);
        plan.calls[id].call_id = @intCast(id);
        plan.calls[id].constant = constants[id];
        plan.calls[id].rounds = rounds[id];
        for (0..4) |lane| {
            const input = try ctx.guessM31(QM31.fromBase(starts[id][lane]));
            const result = try ctx.guessM31(QM31.fromBase(final[lane]));
            plan.calls[id].input[lane] = input.idx;
            plan.calls[id].output[lane] = result.idx;
            results[id][lane] = result;
        }
    }
    var outputs: [8]circuit.builder.Var = undefined;
    for (0..4) |lane| {
        outputs[lane] = try ctx.add(try ctx.add(results[0][lane], results[1][lane]), try ctx.add(results[2][lane], results[3][lane]));
        outputs[4 + lane] = try ctx.add(try ctx.mul(results[0][lane], results[1][lane]), try ctx.mul(results[2][lane], results[3][lane]));
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
    const bundle_bytes = try std.fs.cwd().readFileAlloc(allocator, air.bundle_path, 1 << 20);
    defer allocator.free(bundle_bytes);
    var bundle = try air.parse(allocator, bundle_bytes);
    defer bundle.deinit();
    const geometry = try mixed.inspect(allocator, &pp, &bundle, plan);
    const layout = pp.layout();
    var bound = try air.bindDirectArithmetic(allocator, &bundle, pp.traceLogSize(), &layout);
    defer bound.deinit();
    const source_bytes = "s31-mixed-native-four-call-test-source";
    const selected: Selected = .{
        .source_sha256 = digest(source_bytes),
        .manifest_sha256 = digest("s31-mixed-native-four-call-test-manifest"),
        .fixed_root = try pp.preprocessedRoot(allocator, 1),
        .circuit_program_sha256 = try air.directProgramBindingDigest(bundle_bytes, &bound),
        .plan = plan,
        .geometry = geometry,
    };
    var proof = try proveSourceBound(allocator, source, ctx.values(), source_bytes, bundle_bytes, &selected);
    defer proof.deinit();
    try std.testing.expectEqual(n_components, proof.sum_count);
    var words: [8]u32 = undefined;
    for (proof.output_values, &words) |value, *word| {
        const limbs = value.toM31Array();
        try std.testing.expect(limbs[1].isZero() and limbs[2].isZero() and limbs[3].isZero());
        word.* = limbs[0].toU32();
    }
    var borrowed: BorrowedProof = .{
        .output_values = proof.output_values,
        .interaction_pow_nonce = proof.interaction_pow_nonce,
        .claimed_sums = proof.claimed_sums,
        .sum_count = proof.sum_count,
        .stark_proof = &proof.stark_proof.proof,
        .circuit_hash = proof.circuit_hash,
    };
    try verifySourceBoundBorrowed(allocator, source, source_bytes, bundle_bytes, &selected, words, borrowed);
    for (0..n_components) |index| {
        borrowed.claimed_sums[index] = borrowed.claimed_sums[index].add(QM31.one());
        try std.testing.expectError(error.InvalidMixedLookupSum, verifySourceBoundBorrowed(allocator, source, source_bytes, bundle_bytes, &selected, words, borrowed));
        borrowed.claimed_sums[index] = borrowed.claimed_sums[index].sub(QM31.one());
    }
    borrowed.claimed_sums[1] = borrowed.claimed_sums[1].add(QM31.one());
    borrowed.claimed_sums[2] = borrowed.claimed_sums[2].sub(QM31.one());
    if (verifySourceBoundBorrowed(allocator, source, source_bytes, bundle_bytes, &selected, words, borrowed)) |_| return error.AcceptedCompensatedMixedSums else |_| {}
    borrowed.claimed_sums[1] = borrowed.claimed_sums[1].sub(QM31.one());
    borrowed.claimed_sums[2] = borrowed.claimed_sums[2].add(QM31.one());
    borrowed.claimed_sums[n_components] = QM31.one();
    try std.testing.expectError(error.NonCanonicalMixedClaimedSums, verifySourceBoundBorrowed(allocator, source, source_bytes, bundle_bytes, &selected, words, borrowed));
    borrowed.claimed_sums[n_components] = QM31.zero();
    for ([_]usize{ 1, 2 }) |commitment_index| {
        proof.stark_proof.proof.commitment_scheme_proof.commitments.items[commitment_index][0] ^= 1;
        if (verifySourceBoundBorrowed(allocator, source, source_bytes, bundle_bytes, &selected, words, borrowed)) |_| return error.AcceptedChangedMixedCommitment else |_| {}
        proof.stark_proof.proof.commitment_scheme_proof.commitments.items[commitment_index][0] ^= 1;
    }
    var reordered = selected;
    reordered.plan.calls[0] = selected.plan.calls[1];
    reordered.plan.calls[1] = selected.plan.calls[0];
    reordered.plan.calls[0].call_id = 0;
    reordered.plan.calls[1].call_id = 1;
    if (verifySourceBoundBorrowed(allocator, source, source_bytes, bundle_bytes, &reordered, words, borrowed)) |_| return error.AcceptedReorderedMixedCalls else |_| {}
    var changed_endpoint = selected;
    changed_endpoint.plan.calls[3].input[0] = selected.plan.calls[2].input[0];
    if (verifySourceBoundBorrowed(allocator, source, source_bytes, bundle_bytes, &changed_endpoint, words, borrowed)) |_| return error.AcceptedChangedMixedEndpoint else |_| {}
    var changed_pcs = selected;
    changed_pcs.geometry.pcs.fri_config.n_queries += 1;
    if (verifySourceBoundBorrowed(allocator, source, source_bytes, bundle_bytes, &changed_pcs, words, borrowed)) |_| return error.AcceptedChangedMixedPcs else |_| {}
    var changed_role = selected;
    changed_role.geometry.slots[7].kind = .pair_chip;
    if (verifySourceBoundBorrowed(allocator, source, source_bytes, bundle_bytes, &changed_role, words, borrowed)) |_| return error.AcceptedChangedMixedRole else |_| {}
}
