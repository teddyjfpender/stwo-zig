//! New finite native+same-ROM macro mode; V2 remains unchanged.
//! Experimental original native+endpoint-source assembly. Native direct AIR
//! and the complete typed partition roster are proved in the SAME STARK.
//! There is no access-witness tree, integer-copy sidecar or per-access WORD
//! transition component. ROM/tables/endpoint/global providers remain external
//! obligations until the enclosing new B8 protocol closes them.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Layout = @import("bulk_memcpy_byte_loop_native_layout_v1.zig");
const Projection = @import("block_v5_native_projection_fused_component_v1.zig").Component;
const Fused = @import("block_v5_native_projection_fused_proof_v2.zig");
const Template = @import("block_v5_native_template_protocol_v3.zig");
const Native = @import("block_v6_partitioned_native_components_v1.zig").Owner;
const Joint = @import("block_v6_joint_components_v1.zig");
const Universal = @import("../recursion/air/universal_challenges.zig").UniversalRelations;
const Halt = @import("block_v8_native_halt_policy_v1.zig");
const Guard = @import("block_v8_native_halt_component_v1.zig").Component;
const Column = engine.pcs.ColumnEvaluation;
pub const Claim = Fused.Claim;
pub const production_active = false;
pub const Owner = struct {
    a: std.mem.Allocator,
    layout: Layout.Layout,
    fixed: []u32,
    main: []u32,
    interactions: []u32,
    mask: []bool,
    projections: []Projection,
    provers: []engine.air.component_prover.ComponentProver,
    verifiers: []core.air.components.Component,
    base: *Native,
    relations: Universal,
    guards: []Guard,
    direct_provers: []engine.air.component_prover.ComponentProver,
    direct_verifiers: []core.air.components.Component,
    /// Heap-stable owner: projection components borrow this owner's admitted
    /// relation bundle, not the init stack or a caller's temporary draw value.
    pub fn init(a: std.mem.Allocator, shape: *const Shape, claims: []const Claim, prefix: *const Universal, halt: Halt.Policy, external: u32) !*Owner {
        try halt.validate();
        if (@import("block_v5_native_frame_v1.zig").required(shape)) return error.UnsupportedEndpointNativeFrame;
        const self = try a.create(Owner);
        errdefer a.destroy(self);
        self.a = a;
        self.relations = prefix.*;
        try self.relations.validate();
        self.layout = try Layout.Layout.init(a, shape, external);
        errdefer self.layout.deinit();
        if (self.layout.slots.len != claims.len) return error.InvalidEndpointNativeClaims;
        self.fixed = try Template.columnLogs(a, shape, external, .fixed);
        errdefer a.free(self.fixed);
        self.main = try mainLogs(a, shape, external);
        errdefer a.free(self.main);
        self.interactions = try Fused.interactionLogs(a, self.layout.slots, &.{});
        errdefer a.free(self.interactions);
        self.mask = try Fused.mainMask(a, self.main.len, self.layout.slots, &.{});
        errdefer a.free(self.mask);
        self.projections = try a.alloc(Projection, claims.len);
        errdefer a.free(self.projections);
        self.provers = try a.alloc(engine.air.component_prover.ComponentProver, claims.len);
        errdefer a.free(self.provers);
        self.verifiers = try a.alloc(core.air.components.Component, claims.len);
        errdefer a.free(self.verifiers);
        self.base = try Native.init(a, shape, external);
        errdefer self.base.deinit();
        self.guards = try a.alloc(Guard, Halt.count(shape));
        errdefer a.free(self.guards);
        self.direct_provers = try a.alloc(engine.air.component_prover.ComponentProver, self.base.provers.len + self.guards.len);
        errdefer a.free(self.direct_provers);
        self.direct_verifiers = try a.alloc(core.air.components.Component, self.direct_provers.len);
        errdefer a.free(self.direct_verifiers);
        @memcpy(self.direct_provers[0..self.base.provers.len], self.base.provers);
        @memcpy(self.direct_verifiers[0..self.base.verifiers.len], self.base.verifiers);
        var main_offset: usize = 0;
        var guard_index: usize = 0;
        const original_count = self.main.len - 2 * self.guards.len;
        for (shape.component_descs[0..shape.n_components], 0..) |desc, index| {
            defer main_offset += desc.n_columns;
            if (desc.family != .load_store) continue;
            self.guards[guard_index] = .{ .log_size = desc.log_size, .active_column = 2 * index + 1, .main_offset = main_offset, .aux_offset = original_count + 2 * guard_index, .policy = halt, .providers = self.base.verifiers };
            self.direct_provers[self.base.provers.len + guard_index] = self.guards[guard_index].asProverComponent();
            self.direct_verifiers[self.base.verifiers.len + guard_index] = self.guards[guard_index].asVerifierComponent();
            guard_index += 1;
        }
        const split = Fused.compositionSplit(self.layout.slots);
        for (self.layout.slots, claims, self.projections, 0..) |slot, claim, *component, index| {
            if (claim.row_count != slot.n_rows) return error.InvalidEndpointNativeClaims;
            for (claim.sum.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidEndpointNativeClaims;
            component.* = try (Projection{ .slot = slot, .fixed_logs = self.fixed, .main_logs = self.main, .root_owner = index == 0, .main_open_mask = self.mask, .interaction_offset = 4 * index, .interaction_logs = self.interactions, .claim = claim.sum, .relations = &self.relations, .composition_split = split }).init();
            self.provers[index] = component.asProverComponent();
            self.verifiers[index] = component.asVerifierComponent();
        }
        return self;
    }
    pub fn deinit(self: *Owner) void {
        const a = self.a;
        a.free(self.direct_verifiers);
        a.free(self.direct_provers);
        a.free(self.guards);
        self.base.deinit();
        a.free(self.verifiers);
        a.free(self.provers);
        a.free(self.projections);
        a.free(self.mask);
        a.free(self.interactions);
        a.free(self.main);
        a.free(self.fixed);
        self.layout.deinit();
        a.destroy(self);
    }
    /// Direct native handles own shared main columns; projection wrappers
    /// remove duplicate declarations only after checking every opening point.
    pub fn proving(self: *const Owner) !Joint.Combined(true) {
        return Joint.Combined(true).initWithLayout(self.a, self.direct_provers, self.provers, false, true);
    }
    pub fn verifying(self: *const Owner) !Joint.Combined(false) {
        return Joint.Combined(false).initWithLayout(self.a, self.direct_verifiers, self.verifiers, false, true);
    }
    pub fn setQuotientCache(self: *Owner, cache: ?*@import("block_v7_leased_quotient_cache_v1.zig").Cache) void {
        for (self.projections) |*component| component.leased_quotient_cache = cache;
        for (self.guards) |*component| component.leased_quotient_cache = cache;
    }
};
pub const Interactions = struct {
    a: std.mem.Allocator,
    claims: []Claim,
    columns: []Column,
    layout_digest: [32]u8,
    pub fn generate(a: std.mem.Allocator, shape: *const Shape, main: []const Column, prefix: *const Universal, external: u32) !Interactions {
        var layout = try Layout.Layout.init(a, shape, external);
        defer layout.deinit();
        const original = try Template.columnLogs(a, shape, external, .main);
        defer a.free(original);
        const guarded = main.len == original.len + 2 * Halt.count(shape);
        const logs = if (guarded) try mainLogs(a, shape, external) else try a.dupe(u32, original);
        defer a.free(logs);
        if (main.len != logs.len) return error.InvalidEndpointNativeColumns;
        for (main, logs) |column, log| if (column.log_size != log or column.values.len != @as(usize, 1) << @intCast(log)) return error.InvalidEndpointNativeColumns;
        const claims = try a.alloc(Claim, layout.slots.len);
        errdefer a.free(claims);
        const columns = try a.alloc(Column, try std.math.mul(usize, layout.slots.len, 4));
        errdefer a.free(columns);
        var ready: usize = 0;
        errdefer for (columns[0..ready]) |column| a.free(column.values);
        for (layout.slots, claims, 0..) |slot, *claim, index| {
            const generated = try Fused.generateProjection(a, main, slot, prefix);
            claim.* = .{ .sum = generated.sum, .row_count = slot.n_rows };
            for (generated.columns, 0..) |values, limb| columns[4 * index + limb] = .{ .log_size = slot.log_size, .values = values };
            ready += 4;
        }
        return .{ .a = a, .claims = claims, .columns = columns, .layout_digest = layout.digest };
    }
    pub fn deinit(self: *Interactions) void {
        for (self.columns) |column| self.a.free(column.values);
        self.a.free(self.columns);
        self.a.free(self.claims);
        self.* = undefined;
    }
};
/// New protocol domain. Every physical scalar/count must enter the transcript
/// BEFORE the interaction root. Aggregated partition claims are insufficient.
pub fn recordClaims(channel: anytype, layout_digest: [32]u8, claims: []const Claim) !void {
    channel.mixU32s(&.{ 0x42384e4d, 1, @intCast(claims.len) });
    channel.mixRoot(layout_digest);
    for (claims) |claim| {
        for (claim.sum.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidEndpointNativeClaims;
        channel.mixU64(claim.row_count);
        channel.mixFelts(&.{claim.sum});
    }
}

pub fn mainLogs(a: std.mem.Allocator, shape: *const Shape, external: u32) ![]u32 {
    const original = try Template.columnLogs(a, shape, external, .main);
    defer a.free(original);
    const logs = try a.alloc(u32, original.len + 2 * Halt.count(shape));
    @memcpy(logs[0..original.len], original);
    var at = original.len;
    for (shape.component_descs[0..shape.n_components]) |desc| if (desc.family == .load_store) {
        @memset(logs[at..][0..2], desc.log_size);
        at += 2;
    };
    return logs;
}
pub fn prepareMain(a: std.mem.Allocator, shape: *const Shape, original: []const Column, policy: Halt.Policy, external: u32) !Halt.Owned {
    const logs = try mainLogs(a, shape, external);
    defer a.free(logs);
    const expected_original = logs.len - 2 * Halt.count(shape);
    if (original.len != expected_original) return error.InvalidByteLoopNativeMain;
    for (original, logs[0..expected_original]) |column, log| if (column.log_size != log or column.values.len != @as(usize, 1) << @intCast(log)) return error.InvalidByteLoopNativeMain;
    const columns = try a.alloc(Column, logs.len);
    errdefer a.free(columns);
    @memcpy(columns[0..expected_original], original);
    var ready = expected_original;
    errdefer for (columns[expected_original..ready]) |column| a.free(column.values);
    var offset: usize = 0;
    for (shape.component_descs[0..shape.n_components]) |desc| {
        defer offset += desc.n_columns;
        if (desc.family != .load_store) continue;
        const rows = @as(usize, 1) << @intCast(desc.log_size);
        for (0..2) |_| {
            columns[ready] = .{ .log_size = desc.log_size, .values = try a.alloc(core.fields.m31.M31, rows) };
            ready += 1;
        }
        for (0..rows) |physical| {
            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, desc.log_size), desc.log_size);
            const aux = try Halt.witness(logical < desc.n_rows, original[offset + Halt.NativeColumns.quarter].values[physical].mul(core.fields.m31.M31.fromCanonical(4)), policy);
            @constCast(columns[ready - 2].values)[physical] = aux[0];
            @constCast(columns[ready - 1].values)[physical] = aux[1];
        }
    }
    return .{ .allocator = a, .original_count = expected_original, .columns = columns };
}
pub fn extract(a: std.mem.Allocator, shape: *const Shape, external: u32, slots: []const @import("block_v5_native_projection_fused_source_v1.zig").Slot, claims: []const Claim) !@import("block_v8_native_endpoint_closure_v1.zig").Partitions {
    try Layout.requireCoverage(a, shape, external, slots);
    if (slots.len != claims.len) return error.InvalidByteLoopNativeClaims;
    var out = @import("block_v8_native_endpoint_closure_v1.zig").Partitions{};
    for (slots, claims) |slot, claim| {
        if (claim.row_count != slot.n_rows) return error.InvalidByteLoopNativeClaims;
        for (claim.sum.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidByteLoopNativeClaims;
        switch (slot.kind) {
            .program => {
                out.program_sum = out.program_sum.add(claim.sum);
                out.fetch_count += claim.row_count;
            },
            .lookup => |lookup| switch (lookup.partition) {
                .registers_state => out.state_sum = out.state_sum.add(claim.sum),
                .register_memory_access => out.register_sum = out.register_sum.add(claim.sum),
                .register_clock_memory_access => out.register_clock_sum = out.register_clock_sum.add(claim.sum),
                .ordinary_memory_access => out.ordinary_ram_sum = out.ordinary_ram_sum.add(claim.sum),
                .clock_memory_access => out.ram_clock_sum = out.ram_clock_sum.add(claim.sum),
                else => {
                    const index = @intFromEnum(lookup.partition);
                    if (index >= out.table_requests.len) return error.InvalidByteLoopNativeClaims;
                    out.table_requests[index] = out.table_requests[index].add(claim.sum);
                },
            },
        }
    }
    return out;
}
