//! Exact original B5CF components, reconstructed from independent admission.
//! Owns headers/mask metadata only; immutable capture/challenges outlive Owner.
const std = @import("std");
const core = @import("stwo_core");
const Admission = @import("../../prover/block_v5_native_capacity_fused_recursive_admission_v1.zig");
const Fused = @import("../../prover/block_v5_native_capacity_fused_proof_v1.zig");
const Capture = @import("../../prover/block_v5_native_capacity_fused_recursive_capture_v1.zig");
const Adapter = @import("../../prover/block_v5_native_capacity_fused_component_v1.zig");
const Source = @import("../../prover/block_v5_native_capacity_fused_source_v1.zig");
const Integer = @import("../../prover/block_execution_integer_bridge_v2.zig");
const Eval = @import("../../prover/block_v5_opcode_sidecar_eval_v1.zig");
pub const Owner = struct {
    allocator: std.mem.Allocator,
    projections: []Adapter.ProjectionComponent,
    accesses: []Adapter.AccessComponent,
    handles: []core.air.components.Component,
    main_mask: []bool,
    pub fn init(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8) !Owner {
        try admitted.validate(expected);
        try capture.validate(admitted, expected);
        return initForClaims(a, admitted, capture.metadata.claims, capture.metadata.memory_claims, &capture.word_challenges, &capture.challenges);
    }
    /// Header reconstruction only. This exposes the shipped point evaluator for
    /// source parity; it does not admit a proof, capture or transported receipt.
    pub fn initForClaims(a: std.mem.Allocator, admitted: *const Admission.Prepared, claims: []const Fused.Claim, memory_claims: []const @import("../../prover/block_v5_opcode_memory_sidecar_proof_v1.zig").Claim, word_challenges: *const @import("../../prover/block_v5_word_memory_protocol_v1.zig").Challenges, challenges: *const @import("../../prover/block_memory_relation_v2.zig").Challenges) !Owner {
        if (claims.len != admitted.projections.len or memory_claims.len != admitted.slots.len) return error.InvalidV5FullFusedClaims;
        try admitted.limits.fused.require(admitted.native.shape, admitted.native.external_retirements, admitted.projections, admitted.slots);
        const projections = try a.alloc(Adapter.ProjectionComponent, admitted.projections.len);
        errdefer a.free(projections);
        const accesses = try a.alloc(Adapter.AccessComponent, admitted.slots.len);
        errdefer a.free(accesses);
        const handles = try a.alloc(core.air.components.Component, try std.math.add(usize, projections.len, accesses.len));
        errdefer a.free(handles);
        const main_mask = try Fused.mainMask(a, admitted.logs[1].len, admitted.projections, admitted.slots, admitted.native.shape, admitted.native.external_retirements);
        errdefer a.free(main_mask);
        const interactions = admitted.logs[admitted.tree_count - 1];
        const split = Fused.compositionSplit(admitted.projections);
        for (admitted.projections, claims, projections, 0..) |slot, claim, *component, i| {
            component.* = try (Adapter.ProjectionComponent{ .binding = try Source.binding(admitted.native.shape, admitted.native.external_retirements, slot.main_offset, slot.log_size, slot.n_rows), .inner = .{ .has_access_witness = accesses.len != 0, .inner = .{ .slot = slot, .fixed_logs = admitted.logs[0], .main_logs = admitted.logs[1], .root_owner = i == 0, .main_open_mask = main_mask, .interaction_offset = 4 * i, .interaction_logs = interactions, .claim = claim.sum, .relations = &word_challenges.universal_prefix, .composition_split = split } } }).init();
            handles[i] = component.asVerifierComponent();
        }
        for (admitted.slots, memory_claims, accesses, 0..) |slot, claim, *component, i| {
            component.* = try (Adapter.AccessComponent{ .binding = try Source.binding(admitted.native.shape, admitted.native.external_retirements, slot.main_offset, slot.log_size, null), .inner = .{ .composition_split = split, .inner = .{ .register_custody_mode = admitted.native.sealed.register_custody_mode, .family = slot.family, .slot = slot.slot, .log_size = slot.log_size, .base_clock = try Integer.baseClockFromPublicFrame(slot.frame), .fixed_logs = admitted.logs[0], .main_logs = admitted.logs[1], .witness_logs = admitted.logs[2], .interaction_logs = interactions, .root_owner = false, .main_offset = slot.main_offset, .witness_offset = i * Integer.COLUMN_COUNT, .interaction_offset = projections.len * 4 + i * Eval.INTERACTION_COUNT, .transition_claim = claim.transition_sum, .transition_count = claim.active_count, .range_claims = claim.range_claims, .challenges = challenges, .v5_packed = .{ .elements = word_challenges }, .v5_universal = .{ .claim = claim.universal_sum, .elements = word_challenges.universal_prefix.get(.memory_access) } } } }).init();
            handles[projections.len + i] = component.asVerifierComponent();
        }
        return .{ .allocator = a, .projections = projections, .accesses = accesses, .handles = handles, .main_mask = main_mask };
    }
    pub fn all(self: *const Owner, fixed_count: usize) core.air.components.Components {
        return .{ .components = self.handles, .n_preprocessed_columns = fixed_count };
    }
    pub fn deinit(self: *Owner) void {
        self.allocator.free(self.projections);
        self.allocator.free(self.accesses);
        self.allocator.free(self.handles);
        self.allocator.free(self.main_mask);
        self.* = undefined;
    }
};
