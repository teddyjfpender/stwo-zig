//! Source-derived candidate selection for the experimental bounded V4 AIR.
//!
//! A candidate is only metadata. Its digests and native program bindings must
//! be reconstructed by the source-pinned caller; this module checks the
//! observable live handles, fixed circuit, order, spans, and PCS geometry.
//! It does not admit proof bytes or establish witness confidentiality.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const air = @import("air.zig");
const many = @import("private_many_boundary.zig");
const preflight = @import("direct_many_preflight.zig");

const DirectCircuit = circuit.common.direct_arithmetic.Circuit;
const n_fixed = circuit.common.direct_arithmetic.N_COLUMNS;

pub const SourceKind = enum(u8) { bundled_circuit, tagged_chip, tagged_bridge };

pub const Slot = struct {
    kind: many.ComponentKind,
    source_kind: SourceKind,
    call_id: ?u32,
    proof_index: u32,
    claimed_sum_index: u32,
    trace_log_size: u32,
    evaluation_log_size: u32,
    main_offset: usize,
    main_columns: usize,
    interaction_offset: usize,
    interaction_columns: usize,
    constraint_offset: usize,
    n_constraints: usize,
    preprocessed_indices: [n_fixed]u32 = [_]u32{0} ** n_fixed,
    preprocessed_count: usize = 0,
    relation_ids: [2]u32 = .{ 0, 0 },
    relation_count: usize = 0,
    /// For bundled_circuit only. The selected direct arithmetic source is 1.
    bundle_index: ?u32 = null,
    bundle_sha256: [32]u8 = [_]u8{0} ** 32,
    /// S31 checks this digest against its source-derived program binding.
    program_binding_sha256: [32]u8,
};

pub const Profile = struct {
    pow_bits: u32,
    log_blowup_factor: u32,
    last_layer_degree_bound: u32,
    queries: u32,
    fold_step: u32,
};

pub const CandidateSchedule = struct {
    source_digest: [32]u8,
    fixed_root: [32]u8,
    calls: [many.max_calls]many.Call,
    call_count: u8,
    slots: [many.max_components]Slot,
    slot_count: usize,
    pcs_profile: Profile,
};

/// An in-process selection result. Its arrays are checked copies of the
/// candidate, and `live` comes from actual verifier handles. Source integrity
/// remains the responsibility of the source-pinned wrapper that calls
/// `selectGeometry` and then binds the generated manifest digest.
pub const GeometrySelection = struct {
    source_digest: [32]u8,
    fixed_root: [32]u8,
    calls: [many.max_calls]many.Call,
    call_count: u8,
    slots: [many.max_components]Slot,
    slot_count: usize,
    live: preflight.Inspection,

    pub fn callSlice(self: *const GeometrySelection) []const many.Call {
        return self.calls[0..self.call_count];
    }

    pub fn slotSlice(self: *const GeometrySelection) []const Slot {
        return self.slots[0..self.slot_count];
    }

    /// Compatibility projection for the current fixed-circuit constructor.
    /// It is derived solely from selected calls, never supplied separately.
    pub fn fixedCircuitPlan(self: *const GeometrySelection) many.Plan {
        var plan: many.Plan = .{ .count = self.call_count };
        @memcpy(plan.calls[0..self.call_count], self.callSlice());
        return plan;
    }

    /// The V4 manifest commits `native_preflight`, so its digest is available
    /// only after this geometry has been selected. The source-pinned caller
    /// computes that digest from its regenerated typed manifest.
    pub fn bindManifestDigest(self: GeometrySelection, digest: [32]u8) SelectedSchedule {
        return .{ .geometry = self, .manifest_digest = digest };
    }
};

pub const SelectedSchedule = struct {
    geometry: GeometrySelection,
    manifest_digest: [32]u8,

    pub fn effectiveDigest(self: *const SelectedSchedule) [32]u8 {
        return many.effectiveDigest(self.geometry.source_digest, self.manifest_digest);
    }

    pub fn circuitIdentity(self: *const SelectedSchedule) [32]u8 {
        return many.identityHash(
            self.effectiveDigest(),
            self.geometry.fixed_root,
            self.geometry.slots[0].trace_log_size,
            self.geometry.live.pcs.fri_config.log_blowup_factor,
            self.fixedCircuitPlan(),
        );
    }

    pub fn callSlice(self: *const SelectedSchedule) []const many.Call {
        return self.geometry.callSlice();
    }

    pub fn slotSlice(self: *const SelectedSchedule) []const Slot {
        return self.geometry.slotSlice();
    }

    pub fn fixedCircuitPlan(self: *const SelectedSchedule) many.Plan {
        return self.geometry.fixedCircuitPlan();
    }
};

/// Check a source-derived typed candidate against the actual V4 verifier
/// handles. In particular, candidate offsets and widths are equality claims,
/// not instructions for allocating trace trees or choosing PCS geometry.
pub fn selectGeometry(
    allocator: std.mem.Allocator,
    pp: *const DirectCircuit,
    template: *const air.Bundle,
    candidate: CandidateSchedule,
) !GeometrySelection {
    if (candidate.call_count == 0 or candidate.call_count > many.max_calls or
        candidate.slot_count != 1 + 2 * @as(usize, candidate.call_count) or
        candidate.slot_count > many.max_components)
        return error.InvalidManySchedule;
    var plan: many.Plan = .{ .count = candidate.call_count };
    @memcpy(plan.calls[0..candidate.call_count], candidate.calls[0..candidate.call_count]);
    for (plan.callSlice(), 0..) |call, id|
        if (call.call_id != id) return error.NonCanonicalManyCallId;
    const live = try preflight.inspect(allocator, pp, template, plan);
    const actual_root = try pp.preprocessedRoot(allocator, 1);
    if (!std.meta.eql(candidate.fixed_root, actual_root))
        return error.InvalidManySchedule;
    const pcs = live.pcs.fri_config;
    if (candidate.pcs_profile.pow_bits != pcs.pow_bits or
        candidate.pcs_profile.log_blowup_factor != pcs.log_blowup_factor or
        candidate.pcs_profile.last_layer_degree_bound != pcs.log_last_layer_degree_bound + 1 or
        candidate.pcs_profile.queries != pcs.n_queries or
        candidate.pcs_profile.fold_step != pcs.fold_step or
        live.count != candidate.slot_count)
        return error.InvalidManySchedule;
    const roster = try many.expectedRoster(plan, pp.traceLogSize(), live.facts[0].n_constraints);
    if (roster.count != candidate.slot_count or
        roster.main_width != live.tree_columns[1] or
        roster.interaction_width != live.tree_columns[2])
        return error.InvalidManySchedule;
    var bundle_digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bundle_digest, air.bundle_sha256);
    for (candidate.slots[0..candidate.slot_count], roster.slice(), live.factSlice(), 0..) |slot, expected, fact, index| {
        if (slot.preprocessed_count > n_fixed or slot.relation_count > 2)
            return error.InvalidManySchedule;
        const wanted_source: SourceKind = switch (expected.kind) {
            .circuit => .bundled_circuit,
            .chip => .tagged_chip,
            .bridge => .tagged_bridge,
        };
        if (slot.kind != expected.kind or slot.source_kind != wanted_source or
            slot.call_id != expected.call_id or slot.proof_index != index or
            slot.claimed_sum_index != index or
            slot.trace_log_size != expected.log_size or
            slot.evaluation_log_size != fact.evaluation_log_size or
            slot.main_offset != expected.main_offset or
            slot.main_columns != expected.main_columns or
            slot.interaction_offset != expected.interaction_offset or
            slot.interaction_columns != expected.interaction_columns or
            slot.constraint_offset != expected.constraint_offset or
            slot.n_constraints != expected.constraint_count or
            slot.preprocessed_count != fact.preprocessed_count or
            slot.relation_count != fact.relation_count or
            !std.mem.eql(u32, slot.preprocessed_indices[0..slot.preprocessed_count], fact.preprocessedSlice()) or
            !std.mem.eql(u32, slot.relation_ids[0..slot.relation_count], fact.relationSlice()))
            return error.InvalidManySchedule;
        if (index == 0) {
            if (slot.bundle_index != @as(u32, @intCast(circuit.common.direct_arithmetic.active_component_indices[0])) or
                !std.meta.eql(slot.bundle_sha256, bundle_digest))
                return error.InvalidManySchedule;
        } else {
            if (slot.bundle_index != null or
                !std.meta.eql(slot.bundle_sha256, [_]u8{0} ** 32))
                return error.InvalidManySchedule;
            const id: usize = @intCast(slot.call_id orelse return error.InvalidManySchedule);
            if (id >= candidate.call_count) return error.InvalidManySchedule;
            const call = candidate.calls[id];
            if (slot.kind == .chip) {
                if (fact.chip_constant == null or fact.chip_constant.? != call.constant.toU32() or
                    fact.bridge_boundary != null or
                    !std.meta.eql(fact.air_source_sha256, preflight.chipSourceDigest()))
                    return error.InvalidManySchedule;
            } else {
                if (fact.bridge_boundary == null or !std.meta.eql(fact.bridge_boundary.?, call) or
                    fact.chip_constant != null or
                    !std.meta.eql(fact.air_source_sha256, preflight.bridgeSourceDigest()))
                    return error.InvalidManySchedule;
            }
        }
    }
    return .{
        .source_digest = candidate.source_digest,
        .fixed_root = candidate.fixed_root,
        .calls = candidate.calls,
        .call_count = candidate.call_count,
        .slots = candidate.slots,
        .slot_count = candidate.slot_count,
        .live = live,
    };
}
