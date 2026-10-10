//! Experimental bounded 1..8-call direct-M31 native proof path. S31 must
//! reconstruct the source-derived typed manifest before admitting proof
//! bytes; the source-pinned V4 envelope lives in the S31 package, not here.
//! Transcript order on both sides: V4 profile/effective digest and plan,
//! channel salt, FRI config, preprocessed root, circuit identity, eight public
//! words, one main root, interaction PoW nonce, one lookup challenge pair,
//! 1+2N ordered claimed sums, one interaction root, then PCS/FRI proof.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const cairo = @import("stwo_cairo_frontend");
const old = @import("prove.zig");
const air = @import("air.zig");
const many = @import("private_many_boundary.zig");
const preflight = @import("direct_many_preflight.zig");
const schedule = @import("direct_many_schedule.zig");
const chip = @import("tagged_many_chip.zig");
const bridge = @import("tagged_many_bridge.zig");
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

pub const Plan = many.Plan;
pub const Bundle = air.Bundle;

pub fn parseBundle(allocator: std.mem.Allocator, bytes: []const u8) !Bundle {
    return air.parse(allocator, bytes);
}

pub const Request = struct {
    /// A source-bound S31 wrapper must recompute this from its sealed source.
    source_digest: [32]u8,
    /// Typed V4 generated-manifest precommitment, never the JSON view.
    manifest_digest: [32]u8,
    /// A source-bound S31 wrapper must derive this from the source it seals.
    /// CircuitView alone cannot certify the high-level repeat-to-wire map.
    plan: many.Plan,
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

fn validatePublicOutputShape(source: CircuitView) !void {
    // Direct-M31 commits eight reserved public M31 words at addresses 3..10;
    // the circuit builder also yields the fixed extension unit at address 2.
    if (source.output.len != 9) return error.InvalidManyPublicStatement;
    for (source.output, 0..) |address, index|
        if (address != @as(u32, @intCast(index + 2))) return error.InvalidManyPublicStatement;
}

const max_main_width = many.circuit_main_width + 17 * many.max_calls;
const max_interaction_width = many.circuit_interaction_width + 28 * many.max_calls;

fn fillLogs(specs: many.Roster, comptime main: bool) [if (main) max_main_width else max_interaction_width]u32 {
    var logs: [if (main) max_main_width else max_interaction_width]u32 = undefined;
    for (specs.slice()) |spec| {
        const offset = if (main) spec.main_offset else spec.interaction_offset;
        const width = if (main) spec.main_columns else spec.interaction_columns;
        @memset(logs[offset..][0..width], spec.log_size);
    }
    return logs;
}

fn fillSelectedLogs(selected: *const schedule.SelectedSchedule, comptime main: bool) ![if (main) max_main_width else max_interaction_width]u32 {
    var logs: [if (main) max_main_width else max_interaction_width]u32 = undefined;
    var at: usize = 0;
    for (selected.slotSlice()) |slot| {
        const offset = if (main) slot.main_offset else slot.interaction_offset;
        const width = if (main) slot.main_columns else slot.interaction_columns;
        if (offset != at or width > logs.len - at) return error.InvalidManySchedule;
        @memset(logs[offset..][0..width], slot.trace_log_size);
        at += width;
    }
    const expected_width = if (main) selected.geometry.live.tree_columns[1] else selected.geometry.live.tree_columns[2];
    if (at != expected_width) return error.InvalidManySchedule;
    return logs;
}

fn copySelectedColumns(
    dst: []ColumnEvaluation,
    selected: *const schedule.SelectedSchedule,
    circuit_columns: []const ColumnEvaluation,
    chips: anytype,
    bridges: anytype,
    comptime main: bool,
) !void {
    var at: usize = 0;
    for (selected.slotSlice(), 0..) |slot, index| {
        if (slot.proof_index != index) return error.InvalidManySchedule;
        const columns: []const ColumnEvaluation = switch (slot.kind) {
            .circuit => circuit_columns,
            .chip => blk: {
                const id: usize = @intCast(slot.call_id orelse return error.InvalidManySchedule);
                if (id >= selected.geometry.call_count) return error.InvalidManySchedule;
                break :blk chips[id].columns;
            },
            .bridge => blk: {
                const id: usize = @intCast(slot.call_id orelse return error.InvalidManySchedule);
                if (id >= selected.geometry.call_count) return error.InvalidManySchedule;
                break :blk bridges[id].columns;
            },
        };
        const expected_at = if (main) slot.main_offset else slot.interaction_offset;
        const width = if (main) slot.main_columns else slot.interaction_columns;
        if (at != expected_at or columns.len != width or at > dst.len or width > dst.len - at)
            return error.InvalidManySchedule;
        @memcpy(dst[at..][0..width], columns);
        at += width;
    }
    if (at != dst.len) return error.InvalidManySchedule;
}

fn selectedSums(
    selected: *const schedule.SelectedSchedule,
    circuit_sum: QM31,
    chips: anytype,
    bridges: anytype,
) ![many.max_components]QM31 {
    var sums = [_]QM31{QM31.zero()} ** many.max_components;
    for (selected.slotSlice(), 0..) |slot, index| {
        if (slot.claimed_sum_index != index) return error.InvalidManySchedule;
        sums[index] = switch (slot.kind) {
            .circuit => circuit_sum,
            .chip => blk: {
                const id: usize = @intCast(slot.call_id orelse return error.InvalidManySchedule);
                if (id >= selected.geometry.call_count) return error.InvalidManySchedule;
                break :blk chips[id].claimed_sum;
            },
            .bridge => blk: {
                const id: usize = @intCast(slot.call_id orelse return error.InvalidManySchedule);
                if (id >= selected.geometry.call_count) return error.InvalidManySchedule;
                break :blk bridges[id].claimed_sum;
            },
        };
    }
    return sums;
}

fn copyPart(comptime T: type, dst: []T, offset: *usize, source: []const T) !void {
    if (source.len > dst.len - offset.*) return error.InvalidManyRoster;
    @memcpy(dst[offset.*..][0..source.len], source);
    offset.* += source.len;
}

fn checkRuntimeHandles(comptime T: type, allocator: std.mem.Allocator, handles: []const T, live: preflight.Inspection) !void {
    if (handles.len != live.count) return error.InvalidManyRoster;
    for (handles, live.factSlice()) |handle, fact| {
        if (handle.nConstraints() != fact.n_constraints or
            handle.maxConstraintLogDegreeBound() != fact.evaluation_log_size or
            handle.compositionLogSplit() != live.composition_split)
            return error.InvalidManyRoster;
        const indices = try handle.preprocessedColumnIndices(allocator);
        defer allocator.free(indices);
        if (indices.len != fact.preprocessed_count) return error.InvalidManyRoster;
        for (indices, fact.preprocessedSlice()) |actual, expected|
            if (actual != expected) return error.InvalidManyRoster;
    }
}

/// `allocator` must support concurrent use. The composition scheduler runs
/// chip and bridge evaluators on worker threads, and each allocates scratch
/// through the caller allocator; a plain ArenaAllocator is unsafe here.
pub fn prove(
    allocator: std.mem.Allocator,
    source: CircuitView,
    values: []const QM31,
    template: *const air.Bundle,
    pcs: core.pcs.config_v2.PcsConfigV2,
    request: Request,
) !Proof {
    return proveInternal(allocator, source, values, template, pcs, request, null);
}

/// Experimental engine adapter. This is not a source authentication API:
/// only the S31 sealed wrapper may supply the regenerated selected schedule.
/// The adapter rechecks all observable geometry before proving.
pub fn proveSelected(
    allocator: std.mem.Allocator,
    source: CircuitView,
    values: []const QM31,
    template: *const air.Bundle,
    selected: *const schedule.SelectedSchedule,
) !Proof {
    try selected.validateShape();
    return proveInternal(allocator, source, values, template, selected.geometry.live.pcs, .{
        .source_digest = selected.geometry.source_digest,
        .manifest_digest = selected.manifest_digest,
        .plan = selected.fixedCircuitPlan(),
    }, selected);
}

fn proveInternal(
    allocator: std.mem.Allocator,
    source: CircuitView,
    values: []const QM31,
    template: *const air.Bundle,
    pcs: core.pcs.config_v2.PcsConfigV2,
    request: Request,
    selected: ?*const schedule.SelectedSchedule,
) !Proof {
    try validatePublicOutputShape(source);
    var pp = try request.plan.preprocessed(allocator, source);
    defer pp.deinit(allocator);
    if (selected) |value| try value.revalidate(allocator, &pp, template);
    const live = if (selected) |value| value.geometry.live else try preflight.inspect(allocator, &pp, template, request.plan);
    if (!std.meta.eql(pcs, live.pcs)) return error.InvalidManyPcsConfig;
    const layout = pp.layout();
    var bound = try air.bindDirectArithmetic(allocator, template, pp.traceLogSize(), &layout);
    defer bound.deinit();
    if (bound.components.len != 1) return error.InvalidManyRoster;
    const specs = try many.expectedRoster(request.plan, pp.traceLogSize(), bound.total_constraints);
    if (specs.count != live.count or specs.main_width != live.tree_columns[1] or
        specs.interaction_width != live.tree_columns[2]) return error.InvalidManyRoster;
    const count = if (selected) |value| value.geometry.slot_count else specs.count;
    const main_width = if (selected != null) @as(usize, live.tree_columns[1]) else specs.main_width;
    const interaction_width = if (selected != null) @as(usize, live.tree_columns[2]) else specs.interaction_width;
    const states = try request.plan.extract(values);
    const effective_digest = if (selected) |value| value.effectiveDigest() else many.effectiveDigest(request.source_digest, request.manifest_digest);
    var channel = Channel{};
    var order: many.TranscriptOrder = .{};
    many.mixProfile(&channel, effective_digest, request.plan);
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
    for (pp.columns, &pp_views) |entry, *view|
        view.* = .{ .log_size = entry.logSize(), .values = entry.values };
    try commit(&scheme, allocator, &pp_views, &channel);
    try order.accept(.preprocessed_commitment);
    const root = scheme.trees.items[0].commitment.root();

    var base = try direct_trace.writeBase(allocator, values, &pp);
    defer base.deinit();
    if (base.output_values.len != 8) return error.InvalidManyPublicStatement;
    var chip_base: [many.n_calls]chip.Base = undefined;
    var chip_ready: usize = 0;
    defer for (chip_base[0..chip_ready]) |*item| item.deinit();
    var bridge_base: [many.n_calls]bridge.Base = undefined;
    var bridge_ready: usize = 0;
    defer for (bridge_base[0..bridge_ready]) |*item| item.deinit();
    for (request.plan.callSlice(), states[0..request.plan.count], 0..) |call, state, id| {
        chip_base[id] = try chip.writeBase(allocator, state.input, call.constant, call.rounds);
        chip_ready += 1;
        if (!std.meta.eql(chip_base[id].final, state.output)) return error.WrongManyChipClaim;
        bridge_base[id] = try bridge.writeBase(allocator, values, call);
        bridge_ready += 1;
    }
    if (selected) |value| {
        if (!std.meta.eql(root, value.geometry.fixed_root) or
            base.log_size != value.geometry.slots[0].trace_log_size)
            return error.InvalidManySchedule;
    }
    const hash = if (selected) |value| value.circuitIdentity() else many.identityHash(effective_digest, root, base.log_size, pcs.fri_config.log_blowup_factor, request.plan);
    MC.mixRoot(&channel, hash);
    try order.accept(.circuit_identity);
    channel.mixFelts(base.output_values);
    try order.accept(.public_statement);
    var main_views: [max_main_width]ColumnEvaluation = undefined;
    var main_at: usize = 0;
    if (selected) |value| {
        try copySelectedColumns(main_views[0..main_width], value, base.columns, chip_base[0..request.plan.count], bridge_base[0..request.plan.count], true);
        main_at = main_width;
    } else {
        try copyPart(ColumnEvaluation, main_views[0..main_width], &main_at, base.columns);
        for (chip_base[0..request.plan.count]) |item|
            try copyPart(ColumnEvaluation, main_views[0..main_width], &main_at, item.columns);
        for (bridge_base[0..request.plan.count]) |item|
            try copyPart(ColumnEvaluation, main_views[0..main_width], &main_at, item.columns);
        if (main_at != main_width) return error.InvalidManyRoster;
    }
    try commit(&scheme, allocator, main_views[0..main_at], &channel);
    try order.accept(.main_commitment);
    const nonce = channel.grind(circuit.common.component_list.INTERACTION_POW_BITS);
    channel.mixU64(nonce);
    try order.accept(.interaction_pow_nonce);
    const lookup = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    try order.accept(.lookup_challenge);
    var interaction = try direct_trace.writeInteraction(allocator, &base, &pp, lookup.z, lookup.alpha);
    defer interaction.deinit();
    var chip_interaction: [many.n_calls]chip.Interaction = undefined;
    var chip_interaction_ready: usize = 0;
    defer for (chip_interaction[0..chip_interaction_ready]) |*item| item.deinit();
    var bridge_interaction: [many.n_calls]bridge.Interaction = undefined;
    var bridge_interaction_ready: usize = 0;
    defer for (bridge_interaction[0..bridge_interaction_ready]) |*item| item.deinit();
    for (request.plan.callSlice(), 0..) |call, id| {
        chip_interaction[id] = try chip.writeInteraction(allocator, chip_base[id].columns, call.call_id, lookup.z, lookup.alpha);
        chip_interaction_ready += 1;
        bridge_interaction[id] = try bridge.writeInteraction(allocator, bridge_base[id].columns, call, lookup.z, lookup.alpha);
        bridge_interaction_ready += 1;
    }
    const sums = if (selected) |value| try selectedSums(value, interaction.claimed_sum, chip_interaction[0..request.plan.count], bridge_interaction[0..request.plan.count]) else blk: {
        var legacy = [_]QM31{QM31.zero()} ** many.max_components;
        legacy[0] = interaction.claimed_sum;
        for (chip_interaction[0..request.plan.count], 0..) |item, id| legacy[1 + id] = item.claimed_sum;
        for (bridge_interaction[0..request.plan.count], 0..) |item, id| legacy[1 + @as(usize, request.plan.count) + id] = item.claimed_sum;
        break :blk legacy;
    };
    const active_sums = sums[0..count];
    var closure = try direct_trace.lookupSum(base.output_values, sums[0], lookup.z, lookup.alpha);
    for (active_sums[1..]) |sum| closure = closure.add(sum);
    if (!closure.isZero()) return error.InvalidManyLookupSum;
    core.channel.lookup_transcript.mixInteractionClaim(&channel, active_sums);
    try order.accept(.claimed_sums);
    var interaction_views: [max_interaction_width]ColumnEvaluation = undefined;
    var interaction_at: usize = 0;
    if (selected) |value| {
        try copySelectedColumns(interaction_views[0..interaction_width], value, interaction.columns, chip_interaction[0..request.plan.count], bridge_interaction[0..request.plan.count], false);
        interaction_at = interaction_width;
    } else {
        try copyPart(ColumnEvaluation, interaction_views[0..interaction_width], &interaction_at, interaction.columns);
        for (chip_interaction[0..request.plan.count]) |item|
            try copyPart(ColumnEvaluation, interaction_views[0..interaction_width], &interaction_at, item.columns);
        for (bridge_interaction[0..request.plan.count]) |item|
            try copyPart(ColumnEvaluation, interaction_views[0..interaction_width], &interaction_at, item.columns);
        if (interaction_at != interaction_width) return error.InvalidManyRoster;
    }
    try commit(&scheme, allocator, interaction_views[0..interaction_at], &channel);
    try order.accept(.interaction_commitment);

    var pp_logs = [_]u32{base.log_size} ** direct_pp.N_COLUMNS;
    const lifting_bound = pcs.trace_lifting_log_size - pcs.fri_config.log_blowup_factor + 1;
    var captured = cairo.proving.air.component.Component.init(allocator, &bound.components[0], &pp_logs, lifting_bound, lookup.z, lookup.alpha, sums[0]);
    var chips: [many.n_calls]chip.Component = undefined;
    var bridges: [many.n_calls]bridge.Component = undefined;
    var handles: [many.max_components]prover.air.component_prover.ComponentProver = undefined;
    if (selected) |value| {
        for (value.slotSlice(), 0..) |slot, index| {
            if (slot.claimed_sum_index != index) return error.InvalidManySchedule;
            switch (slot.kind) {
                .circuit => {
                    if (index != 0 or slot.call_id != null) return error.InvalidManySchedule;
                    handles[index] = captured.asProverComponent();
                },
                .chip => {
                    const id: usize = @intCast(slot.call_id orelse return error.InvalidManySchedule);
                    if (id >= value.geometry.call_count) return error.InvalidManySchedule;
                    const call = value.geometry.calls[id];
                    chips[id] = .{
                        .log_size = slot.trace_log_size,
                        .call_id = call.call_id,
                        .constant = call.constant,
                        .main_offset = slot.main_offset,
                        .interaction_offset = slot.interaction_offset,
                        .elements = .init(lookup.z, lookup.alpha),
                        .claimed_sum = sums[index],
                    };
                    handles[index] = chips[id].asProverComponent();
                },
                .bridge => {
                    const id: usize = @intCast(slot.call_id orelse return error.InvalidManySchedule);
                    if (id >= value.geometry.call_count) return error.InvalidManySchedule;
                    bridges[id] = .{
                        .main_offset = slot.main_offset,
                        .interaction_offset = slot.interaction_offset,
                        .boundary = value.geometry.calls[id],
                        .elements = .init(lookup.z, lookup.alpha),
                        .claimed_sum = sums[index],
                    };
                    handles[index] = bridges[id].asProverComponent();
                },
            }
        }
    } else {
        handles[0] = captured.asProverComponent();
        for (request.plan.callSlice(), 0..) |call, id| {
            chips[id] = .{
                .log_size = specs.entries[1 + id].log_size,
                .call_id = call.call_id,
                .constant = call.constant,
                .main_offset = specs.entries[1 + id].main_offset,
                .interaction_offset = specs.entries[1 + id].interaction_offset,
                .elements = .init(lookup.z, lookup.alpha),
                .claimed_sum = sums[1 + id],
            };
            handles[1 + id] = chips[id].asProverComponent();
            bridges[id] = .{
                .main_offset = specs.entries[1 + @as(usize, request.plan.count) + id].main_offset,
                .interaction_offset = specs.entries[1 + @as(usize, request.plan.count) + id].interaction_offset,
                .boundary = call,
                .elements = .init(lookup.z, lookup.alpha),
                .claimed_sum = sums[1 + @as(usize, request.plan.count) + id],
            };
            handles[1 + @as(usize, request.plan.count) + id] = bridges[id].asProverComponent();
        }
    }
    try checkRuntimeHandles(prover.air.component_prover.ComponentProver, allocator, handles[0..count], live);
    scheme_owned = false;
    var stark = try Engine.prove(allocator, handles[0..count], &channel, scheme, .{ .include_all_preprocessed_columns = true });
    try order.accept(.pcs_proof);
    try order.finish();
    errdefer stark.deinit(allocator);
    return .{
        .allocator = allocator,
        .pcs_config = pcs,
        .output_values = try allocator.dupe(QM31, base.output_values),
        .interaction_pow_nonce = nonce,
        .claimed_sums = sums,
        .sum_count = count,
        .stark_proof = stark,
        .circuit_hash = hash,
    };
}

/// Engine-level native verifier for an in-memory many proof. The caller owns
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
    if (!std.meta.eql(pcs, proof.pcs_config)) return error.InvalidManyPcsConfig;
    return verifyBorrowed(allocator, source, template, pcs, request, public_words, .{
        .output_values = proof.output_values,
        .interaction_pow_nonce = proof.interaction_pow_nonce,
        .claimed_sums = proof.claimed_sums,
        .sum_count = proof.sum_count,
        .stark_proof = &proof.stark_proof.proof,
        .circuit_hash = proof.circuit_hash,
    });
}

/// A decoded S31 V4 envelope owns only the postcard StarkProof, not
/// prover-only PCS auxiliary state. The S31 wrapper must regenerate the
/// selected source and manifest identity before calling its selected adapter.
pub const BorrowedProof = struct {
    output_values: []const QM31,
    interaction_pow_nonce: u64,
    claimed_sums: [many.max_components]QM31,
    sum_count: usize,
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
    return verifyBorrowedInternal(allocator, source, template, pcs, request, null, public_words, proof);
}

/// Experimental selected verifier adapter. The caller must bind source,
/// manifest, and native program digests by regenerating the S31 manifest.
/// This method independently rechecks the fixed circuit and live geometry;
/// it is not a standalone authenticated-source or proof-byte admission API.
pub fn verifySelectedBorrowed(
    allocator: std.mem.Allocator,
    source: CircuitView,
    template: *const air.Bundle,
    selected: *const schedule.SelectedSchedule,
    public_words: [8]u32,
    proof: BorrowedProof,
) !void {
    try selected.validateShape();
    return verifyBorrowedInternal(allocator, source, template, selected.geometry.live.pcs, .{
        .source_digest = selected.geometry.source_digest,
        .manifest_digest = selected.manifest_digest,
        .plan = selected.fixedCircuitPlan(),
    }, selected, public_words, proof);
}

fn verifyBorrowedInternal(
    allocator: std.mem.Allocator,
    source: CircuitView,
    template: *const air.Bundle,
    pcs: core.pcs.config_v2.PcsConfigV2,
    request: Request,
    selected: ?*const schedule.SelectedSchedule,
    public_words: [8]u32,
    proof: BorrowedProof,
) !void {
    try validatePublicOutputShape(source);
    var pp = try request.plan.preprocessed(allocator, source);
    defer pp.deinit(allocator);
    if (selected) |value| try value.revalidate(allocator, &pp, template);
    const live = if (selected) |value| value.geometry.live else try preflight.inspect(allocator, &pp, template, request.plan);
    if (!std.meta.eql(pcs, live.pcs)) return error.InvalidManyPcsConfig;
    var committed = try direct.PreprocessedCommitment.build(allocator, &pp, pcs);
    defer committed.deinit(allocator);
    const roots = proof.stark_proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4 or !std.mem.eql(u8, &roots[0], &committed.root()))
        return error.InvalidManyPreprocessedRoot;
    if (!std.meta.eql(
        proof.stark_proof.commitment_scheme_proof.config,
        core.protocol_revision.Revision.proving_5a7c5ed.legacyView(pcs),
    )) return error.InvalidManyPcsConfig;
    var outputs: [8]QM31 = undefined;
    for (public_words, &outputs, 0..) |word, *output, index| {
        if (word >= core.fields.m31.Modulus) return error.InvalidManyPublicStatement;
        output.* = QM31.fromBase(M31.fromCanonical(word));
        if (proof.output_values.len != 8 or !proof.output_values[index].eql(output.*))
            return error.InvalidManyPublicStatement;
    }
    const effective_digest = if (selected) |value| value.effectiveDigest() else many.effectiveDigest(request.source_digest, request.manifest_digest);
    const circuit_log = pp.traceLogSize();
    const expected_hash = if (selected) |value| value.circuitIdentity() else many.identityHash(effective_digest, roots[0], circuit_log, pcs.fri_config.log_blowup_factor, request.plan);
    if (!std.mem.eql(u8, &proof.circuit_hash, &expected_hash)) return error.InvalidManyCircuitHash;
    var channel = Channel{};
    var order: many.TranscriptOrder = .{};
    many.mixProfile(&channel, effective_digest, request.plan);
    try order.accept(.profile);
    core.channel.lookup_transcript.mixChannelSalt(&channel, 0);
    try order.accept(.channel_salt);
    pcs.fri_config.mixInto(&channel);
    try order.accept(.fri_config);
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(allocator, pcs);
    defer scheme.deinit(allocator);
    var pp_logs = [_]u32{circuit_log} ** direct_pp.N_COLUMNS;
    try scheme.commit(allocator, roots[0], &pp_logs, &channel);
    try order.accept(.preprocessed_commitment);
    MC.mixRoot(&channel, expected_hash);
    try order.accept(.circuit_identity);
    channel.mixFelts(&outputs);
    try order.accept(.public_statement);
    const layout = pp.layout();
    var bound = try air.bindDirectArithmetic(allocator, template, circuit_log, &layout);
    defer bound.deinit();
    if (bound.components.len != 1) return error.InvalidManyRoster;
    const specs = try many.expectedRoster(request.plan, circuit_log, bound.total_constraints);
    const count = if (selected) |value| value.geometry.slot_count else specs.count;
    const main_width = if (selected != null) @as(usize, live.tree_columns[1]) else specs.main_width;
    const interaction_width = if (selected != null) @as(usize, live.tree_columns[2]) else specs.interaction_width;
    if (proof.sum_count != count or specs.count != live.count or
        specs.main_width != live.tree_columns[1] or specs.interaction_width != live.tree_columns[2])
        return error.InvalidManyRoster;
    const main_logs = if (selected) |value| try fillSelectedLogs(value, true) else fillLogs(specs, true);
    try scheme.commit(allocator, roots[1], main_logs[0..main_width], &channel);
    try order.accept(.main_commitment);
    if (!channel.verifyPowNonce(circuit.common.component_list.INTERACTION_POW_BITS, proof.interaction_pow_nonce))
        return error.InvalidManyInteractionNonce;
    channel.mixU64(proof.interaction_pow_nonce);
    try order.accept(.interaction_pow_nonce);
    const lookup = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    try order.accept(.lookup_challenge);
    var closure = try direct_trace.lookupSum(&outputs, proof.claimed_sums[0], lookup.z, lookup.alpha);
    for (proof.claimed_sums[1..proof.sum_count]) |sum| closure = closure.add(sum);
    if (!closure.isZero()) return error.InvalidManyLookupSum;
    core.channel.lookup_transcript.mixInteractionClaim(&channel, proof.claimed_sums[0..proof.sum_count]);
    try order.accept(.claimed_sums);
    const interaction_logs = if (selected) |value| try fillSelectedLogs(value, false) else fillLogs(specs, false);
    try scheme.commit(allocator, roots[2], interaction_logs[0..interaction_width], &channel);
    try order.accept(.interaction_commitment);

    const lifting_bound = pcs.trace_lifting_log_size - pcs.fri_config.log_blowup_factor + 1;
    var captured = cairo.proving.air.component.Component.init(allocator, &bound.components[0], &pp_logs, lifting_bound, lookup.z, lookup.alpha, proof.claimed_sums[0]);
    var chips: [many.n_calls]chip.Component = undefined;
    var bridges: [many.n_calls]bridge.Component = undefined;
    var handles: [many.max_components]core.air.components.Component = undefined;
    if (selected) |value| {
        for (value.slotSlice(), 0..) |slot, index| {
            if (slot.claimed_sum_index != index) return error.InvalidManySchedule;
            switch (slot.kind) {
                .circuit => {
                    if (index != 0 or slot.call_id != null) return error.InvalidManySchedule;
                    handles[index] = captured.asVerifierComponent();
                },
                .chip => {
                    const id: usize = @intCast(slot.call_id orelse return error.InvalidManySchedule);
                    if (id >= value.geometry.call_count) return error.InvalidManySchedule;
                    const call = value.geometry.calls[id];
                    chips[id] = .{
                        .log_size = slot.trace_log_size,
                        .call_id = call.call_id,
                        .constant = call.constant,
                        .main_offset = slot.main_offset,
                        .interaction_offset = slot.interaction_offset,
                        .elements = .init(lookup.z, lookup.alpha),
                        .claimed_sum = proof.claimed_sums[index],
                    };
                    handles[index] = chips[id].asVerifierComponent();
                },
                .bridge => {
                    const id: usize = @intCast(slot.call_id orelse return error.InvalidManySchedule);
                    if (id >= value.geometry.call_count) return error.InvalidManySchedule;
                    bridges[id] = .{
                        .main_offset = slot.main_offset,
                        .interaction_offset = slot.interaction_offset,
                        .boundary = value.geometry.calls[id],
                        .elements = .init(lookup.z, lookup.alpha),
                        .claimed_sum = proof.claimed_sums[index],
                    };
                    handles[index] = bridges[id].asVerifierComponent();
                },
            }
        }
    } else {
        handles[0] = captured.asVerifierComponent();
        for (request.plan.callSlice(), 0..) |call, id| {
            chips[id] = .{
                .log_size = specs.entries[1 + id].log_size,
                .call_id = call.call_id,
                .constant = call.constant,
                .main_offset = specs.entries[1 + id].main_offset,
                .interaction_offset = specs.entries[1 + id].interaction_offset,
                .elements = .init(lookup.z, lookup.alpha),
                .claimed_sum = proof.claimed_sums[1 + id],
            };
            handles[1 + id] = chips[id].asVerifierComponent();
            bridges[id] = .{
                .main_offset = specs.entries[1 + @as(usize, request.plan.count) + id].main_offset,
                .interaction_offset = specs.entries[1 + @as(usize, request.plan.count) + id].interaction_offset,
                .boundary = call,
                .elements = .init(lookup.z, lookup.alpha),
                .claimed_sum = proof.claimed_sums[1 + @as(usize, request.plan.count) + id],
            };
            handles[1 + @as(usize, request.plan.count) + id] = bridges[id].asVerifierComponent();
        }
    }
    try checkRuntimeHandles(core.air.components.Component, allocator, handles[0..count], live);
    var capture: core.verifier.ProofCapture(H) = undefined;
    try core.verifier.verifyBorrowedExWithProofCapture(
        H,
        MC,
        allocator,
        handles[0..count],
        &channel,
        &scheme,
        proof.stark_proof,
        true,
        &capture,
    );
    try order.accept(.pcs_proof);
    try order.finish();
    defer capture.deinit(allocator);
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

test "V4 native one-call proof binds roster transcript and public claim" {
    const allocator = std.testing.allocator;
    var ctx = try circuit.builder.Context(QM31).init(allocator, 8);
    defer ctx.deinit();
    const initial = [4]M31{
        M31.fromCanonical(3), M31.fromCanonical(5),
        M31.fromCanonical(7), M31.fromCanonical(11),
    };
    const constant = M31.fromCanonical(13);
    const rounds: u32 = 16;
    const final = try @import("repeated_step_chip.zig").direct(initial, constant, rounds);
    var plan: many.Plan = .{ .count = 1 };
    plan.calls[0].call_id = 0;
    plan.calls[0].rounds = rounds;
    plan.calls[0].constant = constant;
    var outputs: [8]circuit.builder.Var = undefined;
    for (0..4) |lane| {
        const input = try ctx.guessM31(QM31.fromBase(initial[lane]));
        const result = try ctx.guessM31(QM31.fromBase(final[lane]));
        plan.calls[0].input[lane] = input.idx;
        plan.calls[0].output[lane] = result.idx;
        outputs[lane] = try ctx.add(result, input);
        outputs[4 + lane] = try ctx.mul(result, input);
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
    const pcs = try preflight.fixedPcs(plan, pp.traceLogSize());
    const bundle_bytes = try std.fs.cwd().readFileAlloc(allocator, air.bundle_path, 1 << 20);
    defer allocator.free(bundle_bytes);
    var bundle = try air.parse(allocator, bundle_bytes);
    defer bundle.deinit();
    var source_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("s31-v4-native-one-call-test-source", &source_digest, .{});
    var manifest_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("s31-v4-native-one-call-test-manifest", &manifest_digest, .{});
    const request = Request{ .source_digest = source_digest, .manifest_digest = manifest_digest, .plan = plan };
    var proof = try prove(allocator, source, ctx.values(), &bundle, pcs, request);
    defer proof.deinit();
    try std.testing.expectEqual(@as(usize, 3), proof.sum_count);
    var public_words: [8]u32 = undefined;
    for (proof.output_values, &public_words) |value, *word| {
        const limbs = value.toM31Array();
        try std.testing.expect(limbs[1].isZero() and limbs[2].isZero() and limbs[3].isZero());
        word.* = limbs[0].toU32();
    }
    for (0..4) |lane| {
        try std.testing.expectEqual(final[lane].add(initial[lane]).toU32(), public_words[lane]);
        try std.testing.expectEqual(final[lane].mul(initial[lane]).toU32(), public_words[4 + lane]);
    }
    try verify(allocator, source, &bundle, pcs, request, public_words, &proof);
    var wrong_words = public_words;
    wrong_words[0] = M31.fromCanonical(wrong_words[0]).add(M31.one()).toU32();
    try std.testing.expectError(error.InvalidManyPublicStatement, verify(allocator, source, &bundle, pcs, request, wrong_words, &proof));
    var wrong_digest = request;
    wrong_digest.manifest_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidManyCircuitHash, verify(allocator, source, &bundle, pcs, wrong_digest, public_words, &proof));
    var wrong_plan = request;
    wrong_plan.plan.calls[0].constant = constant.add(M31.one());
    try std.testing.expectError(error.InvalidManyCircuitHash, verify(allocator, source, &bundle, pcs, wrong_plan, public_words, &proof));
    wrong_plan = request;
    wrong_plan.plan.calls[0].call_id = 1;
    try std.testing.expectError(error.NonCanonicalManyCallId, verify(allocator, source, &bundle, pcs, wrong_plan, public_words, &proof));
    proof.claimed_sums[1] = proof.claimed_sums[1].add(QM31.one());
    try std.testing.expectError(error.InvalidManyLookupSum, verify(allocator, source, &bundle, pcs, request, public_words, &proof));
    proof.claimed_sums[1] = proof.claimed_sums[1].sub(QM31.one());
    proof.stark_proof.proof.commitment_scheme_proof.commitments.items[1][0] ^= 1;
    if (verify(allocator, source, &bundle, pcs, request, public_words, &proof)) |_| return error.AcceptedChangedMainCommitment else |_| {}
}

test "V4 native three-call proof uses seven ordered component sums" {
    const allocator = std.testing.allocator;
    var ctx = try circuit.builder.Context(QM31).init(allocator, 8);
    defer ctx.deinit();
    const starts = [3][4]M31{
        .{ M31.fromCanonical(3), M31.fromCanonical(5), M31.fromCanonical(7), M31.fromCanonical(11) },
        .{ M31.fromCanonical(2), M31.fromCanonical(4), M31.fromCanonical(6), M31.fromCanonical(8) },
        .{ M31.fromCanonical(9), M31.fromCanonical(10), M31.fromCanonical(12), M31.fromCanonical(14) },
    };
    const constants = [3]M31{ M31.fromCanonical(13), M31.fromCanonical(17), M31.fromCanonical(19) };
    const rounds = [3]u32{ 16, 32, 16 };
    var plan: many.Plan = .{ .count = 3 };
    var results: [3][4]circuit.builder.Var = undefined;
    for (0..3) |id| {
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
        outputs[lane] = try ctx.add(try ctx.add(results[0][lane], results[1][lane]), results[2][lane]);
        outputs[4 + lane] = try ctx.add(try ctx.mul(results[0][lane], results[1][lane]), results[2][lane]);
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
    const pcs = try preflight.fixedPcs(plan, pp.traceLogSize());
    const bundle_bytes = try std.fs.cwd().readFileAlloc(allocator, air.bundle_path, 1 << 20);
    defer allocator.free(bundle_bytes);
    var bundle = try air.parse(allocator, bundle_bytes);
    defer bundle.deinit();
    var source_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("s31-v4-native-three-call-test-source", &source_digest, .{});
    var manifest_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("s31-v4-native-three-call-test-manifest", &manifest_digest, .{});
    const request = Request{ .source_digest = source_digest, .manifest_digest = manifest_digest, .plan = plan };
    var proof = try prove(allocator, source, ctx.values(), &bundle, pcs, request);
    defer proof.deinit();
    try std.testing.expectEqual(@as(usize, 7), proof.sum_count);
    var words: [8]u32 = undefined;
    for (proof.output_values, &words) |value, *word| {
        const limbs = value.toM31Array();
        try std.testing.expect(limbs[1].isZero() and limbs[2].isZero() and limbs[3].isZero());
        word.* = limbs[0].toU32();
    }
    try verify(allocator, source, &bundle, pcs, request, words, &proof);
    for (0..proof.sum_count) |index| {
        proof.claimed_sums[index] = proof.claimed_sums[index].add(QM31.one());
        try std.testing.expectError(error.InvalidManyLookupSum, verify(allocator, source, &bundle, pcs, request, words, &proof));
        proof.claimed_sums[index] = proof.claimed_sums[index].sub(QM31.one());
    }
    var reordered = request;
    reordered.plan.calls[0] = request.plan.calls[1];
    reordered.plan.calls[1] = request.plan.calls[0];
    reordered.plan.calls[0].call_id = 0;
    reordered.plan.calls[1].call_id = 1;
    if (verify(allocator, source, &bundle, pcs, reordered, words, &proof)) |_| return error.AcceptedReorderedCalls else |_| {}
    var changed_endpoint = request;
    changed_endpoint.plan.calls[0].input[0] = request.plan.calls[1].input[0];
    if (verify(allocator, source, &bundle, pcs, changed_endpoint, words, &proof)) |_| return error.AcceptedChangedEndpoint else |_| {}
    proof.sum_count -= 1;
    try std.testing.expectError(error.InvalidManyRoster, verify(allocator, source, &bundle, pcs, request, words, &proof));
}
