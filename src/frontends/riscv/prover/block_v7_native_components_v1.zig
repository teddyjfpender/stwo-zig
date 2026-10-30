//! Versioned source assembly reuses every original equation and opening mask.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Source = @import("block_v7_native_source_v1.zig");
const Epoch = @import("block_v7_execution_epoch_v1.zig");
const Layout = Source.Layout;
const Fused = @import("block_v5_native_projection_fused_proof_v2.zig");
const Adapter = @import("block_v5_native_projection_fused_component_v2.zig");
const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const Template = @import("block_v5_native_template_protocol_v3.zig");
const Joint = @import("block_v6_joint_components_v1.zig");
pub const Owner = struct {
    a: std.mem.Allocator,
    layout: Layout,
    slots: []Memory.Slot,
    fixed: []u32,
    main: []u32,
    witness: []u32,
    interactions: []u32,
    mask: []bool,
    projections: []Adapter.ProjectionComponent,
    access: []Adapter.AccessComponent,
    provers: []engine.air.component_prover.ComponentProver,
    verifiers: []core.air.components.Component,
    base: *@import("block_v6_partitioned_native_components_v1.zig").Owner,
    pub fn init(a: std.mem.Allocator, pin: Source.Pin, claims: []const Fused.Claim, memory: []const Memory.Claim, drawn: *const Epoch.Drawn) !Owner {
        try pin.validate();
        var layout = try pin.layout(a);
        errdefer layout.deinit();
        const slots = try @import("block_execution_sidecar_batch_v2.zig").slotsFromStatementForMode(a, pin.shape, pin.frame, 1);
        errdefer a.free(slots);
        if (layout.slots.len != claims.len or slots.len != memory.len) return error.InvalidV7NativeClaims;
        const fixed = try Template.columnLogs(a, pin.shape, pin.template.external_retirements, .fixed);
        errdefer a.free(fixed);
        const main = try Template.columnLogs(a, pin.shape, pin.template.external_retirements, .main);
        errdefer a.free(main);
        const witness = try Fused.witnessLogs(a, slots);
        errdefer a.free(witness);
        const Frame = @import("block_v5_native_frame_v1.zig");
        const interactions = if (Frame.required(pin.shape)) try a.dupe(u32, &.{Frame.LOG_SIZE}) else try Fused.interactionLogs(a, layout.slots, slots);
        if (Frame.required(pin.shape) and (layout.slots.len != 0 or slots.len != 0 or claims.len != 0 or memory.len != 0)) {
            a.free(interactions);
            return error.InvalidV7ExternalNativeEnvelope;
        }
        errdefer a.free(interactions);
        const mask = try Fused.mainMask(a, main.len, layout.slots, slots);
        errdefer a.free(mask);
        const projections = try a.alloc(Adapter.ProjectionComponent, claims.len);
        errdefer a.free(projections);
        const access = try a.alloc(Adapter.AccessComponent, slots.len);
        errdefer a.free(access);
        const provers = try a.alloc(engine.air.component_prover.ComponentProver, claims.len + slots.len);
        errdefer a.free(provers);
        const verifiers = try a.alloc(core.air.components.Component, provers.len);
        errdefer a.free(verifiers);
        const base = try @import("block_v6_partitioned_native_components_v1.zig").Owner.init(a, pin.shape, pin.template.external_retirements);
        errdefer base.deinit();
        if (Frame.required(pin.shape)) {
            // The legacy nonempty projection validator deliberately rejects
            // this finite physical frame. All column bounds here are derived
            // from Template, and the original frame owns the six equations.
            if (base.frame == null or fixed.len != Frame.FIXED_COLUMNS or main.len != Frame.MAIN_COLUMNS or witness.len != 0 or interactions.len != Frame.INTERACTION_COLUMNS) return error.InvalidV7ExternalNativeEnvelope;
            for (fixed) |log| if (log != Frame.LOG_SIZE) return error.InvalidV7ExternalNativeEnvelope;
            for (main) |log| if (log != Frame.LOG_SIZE) return error.InvalidV7ExternalNativeEnvelope;
        } else try Fused.validateRoster(layout.slots, slots, main, 1);
        for (layout.slots, claims, projections, 0..) |slot, claim, *component, i| {
            if (claim.row_count != slot.n_rows) return error.InvalidV7NativeClaims;
            component.* = try (Adapter.ProjectionComponent{ .has_access_witness = slots.len != 0, .inner = .{ .slot = slot, .fixed_logs = fixed, .main_logs = main, .root_owner = i == 0, .main_open_mask = mask, .interaction_offset = 4 * i, .interaction_logs = interactions, .claim = claim.sum, .relations = &drawn.word.universal_prefix, .composition_split = Fused.compositionSplit(layout.slots) } }).init();
            provers[i] = component.asProverComponent();
            verifiers[i] = component.asVerifierComponent();
        }
        for (slots, memory, access, 0..) |slot, claim, *component, i| {
            component.* = try Fused.accessComponent(slot, i, claims.len, fixed, main, witness, interactions, claim, &drawn.bytes, &drawn.word, Fused.compositionSplit(layout.slots), 1);
            provers[claims.len + i] = component.asProverComponent();
            verifiers[claims.len + i] = component.asVerifierComponent();
        }
        return .{ .a = a, .layout = layout, .slots = slots, .fixed = fixed, .main = main, .witness = witness, .interactions = interactions, .mask = mask, .projections = projections, .access = access, .provers = provers, .verifiers = verifiers, .base = base };
    }
    pub fn deinit(self: *Owner) void {
        const a = self.a;
        self.base.deinit();
        a.free(self.verifiers);
        a.free(self.provers);
        a.free(self.access);
        a.free(self.projections);
        a.free(self.mask);
        a.free(self.interactions);
        a.free(self.witness);
        a.free(self.main);
        a.free(self.fixed);
        a.free(self.slots);
        self.layout.deinit();
        self.* = undefined;
    }
    /// Producer-only immutable evaluation reuse. Set once before the joined
    /// core proof and detach afterward; verifier equations and masks ignore it.
    pub fn setQuotientCache(self: *Owner, cache: ?*@import("block_v7_leased_quotient_cache_v1.zig").Cache) void {
        for (self.projections) |*component| component.inner.leased_quotient_cache = cache;
        for (self.access) |*component| component.inner.leased_quotient_cache = cache;
    }
    pub fn proving(self: *const Owner) !Joint.Combined(true) {
        return Joint.Combined(true).initWithLayout(self.a, self.base.provers, self.provers, self.slots.len != 0, true);
    }
    pub fn verifying(self: *const Owner) !Joint.Combined(false) {
        return Joint.Combined(false).initWithLayout(self.a, self.base.verifiers, self.verifiers, self.slots.len != 0, true);
    }
};
