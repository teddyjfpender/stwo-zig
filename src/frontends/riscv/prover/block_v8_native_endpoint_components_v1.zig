//! Experimental original native+endpoint-source assembly. Native direct AIR
//! and the complete typed partition roster are proved in the SAME STARK.
//! There is no access-witness tree, integer-copy sidecar or per-access WORD
//! transition component. ROM/tables/endpoint/global providers remain external
//! obligations until the enclosing new B8 protocol closes them.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Layout = @import("block_v8_native_endpoint_layout_v1.zig");
const Projection = @import("block_v5_native_projection_fused_component_v1.zig").Component;
const Fused = @import("block_v5_native_projection_fused_proof_v2.zig");
const Template = @import("block_v5_native_template_protocol_v3.zig");
const Native = @import("block_v6_partitioned_native_components_v1.zig").Owner;
const Joint = @import("block_v6_joint_components_v1.zig");
const Epoch = @import("block_v7_execution_epoch_v1.zig");
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
    projection_batch: ?*@import("block_v8_native_projection_domain_batch_v1.zig").Owned = null,
    projection_batch_handle: [1]engine.air.component_prover.ComponentProver = undefined,
    provers: []engine.air.component_prover.ComponentProver,
    verifiers: []core.air.components.Component,
    base: *Native,
    relations: Universal,
    guards: []Guard,
    clock_v3: []@import("block_v8_ram_clock_v3_component.zig").Component,
    infra_v3: []@import("block_v8_ram_clock_v3_infrastructure.zig").Component,
    direct_provers: []engine.air.component_prover.ComponentProver,
    direct_verifiers: []core.air.components.Component,
    /// Heap-stable owner: projection components borrow this owner's admitted
    /// relation bundle, not the init stack or a caller's temporary draw value.
    pub fn init(a: std.mem.Allocator, shape: *const Shape, claims: []const Claim, drawn: *const Epoch.Drawn) !*Owner {
        return initWithHalt(a, shape, claims, drawn, null);
    }
    pub fn initWithHalt(a: std.mem.Allocator, shape: *const Shape, claims: []const Claim, drawn: *const Epoch.Drawn, halt: ?Halt.Policy) !*Owner {
        return initWithExternalAndHalt(a, shape, claims, drawn, 0, halt);
    }
    pub fn initWithExternalAndHalt(a: std.mem.Allocator, shape: *const Shape, claims: []const Claim, drawn: *const Epoch.Drawn, external: u32, halt: ?Halt.Policy) !*Owner {
        return initProfile(a, shape, claims, drawn, external, halt, false);
    }
    pub fn initDirectRamV3(a: std.mem.Allocator, shape: *const Shape, claims: []const Claim, drawn: *const Epoch.Drawn, halt: Halt.Policy) !*Owner {
        return initProfile(a, shape, claims, drawn, 0, halt, true);
    }
    fn initProfile(a: std.mem.Allocator, shape: *const Shape, claims: []const Claim, drawn: *const Epoch.Drawn, external: u32, halt: ?Halt.Policy, direct_v3: bool) !*Owner {
        if (direct_v3 and (external != 0 or halt == null)) return error.UnsupportedDirectRamClockProfile;
        if (halt) |policy| try policy.validate();
        if (@import("block_v5_native_frame_v1.zig").required(shape)) return error.UnsupportedEndpointNativeFrame;
        const self = try a.create(Owner);
        errdefer a.destroy(self);
        self.a = a;
        self.projection_batch = null;
        self.relations = drawn.word.universal_prefix;
        try self.relations.validate();
        self.layout = if (direct_v3) try @import("block_v8_native_endpoint_layout_v3.zig").init(a, shape, external) else if (external == 0) try Layout.Layout.init(a, shape, 0) else try @import("block_v8_native_mixed_layout_v1.zig").init(a, shape, external);
        errdefer self.layout.deinit();
        const clock_count = if (direct_v3) Halt.count(shape) else 0;
        if (self.layout.slots.len + clock_count != claims.len) return error.InvalidEndpointNativeClaims;
        self.fixed = try Template.columnLogs(a, shape, external, .fixed);
        errdefer a.free(self.fixed);
        self.main = if (direct_v3) try @import("block_v8_ram_clock_v3_stage.zig").mainLogs(a, shape) else if (halt != null) try Halt.mainLogsWithExternal(a, shape, external) else try Template.columnLogs(a, shape, external, .main);
        errdefer a.free(self.main);
        const projection_logs = try Fused.interactionLogs(a, self.layout.slots, &.{});
        if (direct_v3) {
            defer a.free(projection_logs);
            self.interactions = try a.alloc(u32, projection_logs.len + 4 * clock_count);
            var group: usize = 0;
            for (shape.component_descs[0..shape.n_components]) |desc| if (desc.family == .load_store) {
                @memset(self.interactions[4 * group ..][0..4], desc.log_size);
                group += 1;
            };
            @memcpy(self.interactions[4 * clock_count ..], projection_logs);
        } else self.interactions = projection_logs;
        errdefer a.free(self.interactions);
        self.mask = try Fused.mainMask(a, self.main.len, self.layout.slots, &.{});
        errdefer a.free(self.mask);
        self.projections = try a.alloc(Projection, self.layout.slots.len);
        errdefer a.free(self.projections);
        self.provers = try a.alloc(engine.air.component_prover.ComponentProver, self.layout.slots.len);
        errdefer a.free(self.provers);
        self.verifiers = try a.alloc(core.air.components.Component, self.layout.slots.len);
        errdefer a.free(self.verifiers);
        self.base = try Native.init(a, shape, external);
        errdefer self.base.deinit();
        self.guards = try a.alloc(Guard, if (halt != null) Halt.count(shape) else 0);
        errdefer a.free(self.guards);
        self.clock_v3 = try a.alloc(@import("block_v8_ram_clock_v3_component.zig").Component, clock_count);
        errdefer a.free(self.clock_v3);
        self.infra_v3 = try a.alloc(@import("block_v8_ram_clock_v3_infrastructure.zig").Component, if (direct_v3) self.base.direct.len else 0);
        errdefer a.free(self.infra_v3);
        self.direct_provers = try a.alloc(engine.air.component_prover.ComponentProver, self.base.provers.len + self.guards.len + clock_count);
        errdefer a.free(self.direct_provers);
        self.direct_verifiers = try a.alloc(core.air.components.Component, self.direct_provers.len);
        errdefer a.free(self.direct_verifiers);
        @memcpy(self.direct_provers[0..self.base.provers.len], self.base.provers);
        @memcpy(self.direct_verifiers[0..self.base.verifiers.len], self.base.verifiers);
        var main_offset: usize = 0;
        var guard_index: usize = 0;
        const original_count = self.main.len - 2 * self.guards.len - 3 * clock_count;
        for (shape.component_descs[0..shape.n_components], 0..) |desc, index| {
            defer main_offset += desc.n_columns;
            if (desc.family != .load_store or halt == null) continue;
            self.guards[guard_index] = .{ .log_size = desc.log_size, .active_column = 2 * index + 1, .main_offset = main_offset, .aux_offset = original_count + 2 * guard_index, .policy = halt.?, .providers = self.base.verifiers };
            self.direct_provers[self.base.provers.len + guard_index] = self.guards[guard_index].asProverComponent();
            self.direct_verifiers[self.base.verifiers.len + guard_index] = self.guards[guard_index].asVerifierComponent();
            guard_index += 1;
        }
        for (self.base.direct[0..self.infra_v3.len], self.infra_v3, 0..) |old, *component, i| {
            component.* = .{ .log_size = old.log_size, .active_column = old.active_column, .main_offset = old.main_offset };
            self.direct_provers[self.base.semantics.len + i] = component.asProverComponent();
            self.direct_verifiers[self.base.semantics.len + i] = component.asVerifierComponent();
        }
        if (direct_v3) {
            var offset: usize = 0;
            var group: usize = 0;
            for (shape.component_descs[0..shape.n_components], 0..) |desc, i| {
                defer offset += desc.n_columns;
                if (desc.family != .load_store) continue;
                const claim = claims[self.layout.slots.len + group];
                if (claim.row_count != desc.n_rows) return error.InvalidEndpointNativeClaims;
                const direct_index = self.base.provers.len + self.guards.len + group;
                self.clock_v3[group] = .{ .log_size = desc.log_size, .active_column = 2 * i + 1, .main_offset = offset, .aux_offset = original_count + 2 * self.guards.len + 3 * group, .interaction_offset = 4 * group, .relation = .from(drawn.word.range16), .sum = claim.sum, .providers = self.base.verifiers };
                self.direct_provers[direct_index] = self.clock_v3[group].asProverComponent();
                self.direct_verifiers[direct_index] = self.clock_v3[group].asVerifierComponent();
                group += 1;
            }
        }
        const split = Fused.compositionSplit(self.layout.slots);
        for (self.layout.slots, claims[0..self.layout.slots.len], self.projections, 0..) |slot, claim, *component, index| {
            if (claim.row_count != slot.n_rows) return error.InvalidEndpointNativeClaims;
            for (claim.sum.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidEndpointNativeClaims;
            component.* = try (Projection{ .slot = slot, .fixed_logs = self.fixed, .main_logs = self.main, .root_owner = index == 0, .main_open_mask = self.mask, .interaction_offset = 4 * (clock_count + index), .interaction_logs = self.interactions, .claim = claim.sum, .relations = &self.relations, .composition_split = split }).init();
            self.provers[index] = component.asProverComponent();
            self.verifiers[index] = component.asVerifierComponent();
        }
        return self;
    }
    pub fn deinit(self: *Owner) void {
        const a = self.a;
        if (self.projection_batch) |batch| batch.deinit();
        a.free(self.direct_verifiers);
        a.free(self.direct_provers);
        a.free(self.guards);
        a.free(self.clock_v3);
        a.free(self.infra_v3);
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
        return Joint.Combined(true).initWithLayout(self.a, self.direct_provers, if (self.projection_batch != null) &self.projection_batch_handle else self.provers, false, true);
    }
    pub fn verifying(self: *const Owner) !Joint.Combined(false) {
        return Joint.Combined(false).initWithLayout(self.a, self.direct_verifiers, self.verifiers, false, true);
    }
    /// Prover-only schedule optimization. Enable before creating the proving
    /// handle roster. Verifier equations and physical claim inventory stay exact.
    pub fn enableProjectionBatch(self: *Owner, options: @import("block_v8_native_projection_domain_batch_v1.zig").Options) !void {
        if (self.projection_batch != null) return error.ProjectionBatchAlreadyEnabled;
        const batch = try @import("block_v8_native_projection_domain_batch_v1.zig").Owned.init(self.a, self.projections, self.verifiers, options);
        self.projection_batch = batch;
        self.projection_batch_handle[0] = batch.asProverComponent();
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
    pub fn generate(a: std.mem.Allocator, shape: *const Shape, main: []const Column, drawn: *const Epoch.Drawn) !Interactions {
        return generateWithExternal(a, shape, main, drawn, 0);
    }
    pub fn generateWithExternal(a: std.mem.Allocator, shape: *const Shape, main: []const Column, drawn: *const Epoch.Drawn, external: u32) !Interactions {
        var layout = if (external == 0) try Layout.Layout.init(a, shape, 0) else try @import("block_v8_native_mixed_layout_v1.zig").init(a, shape, external);
        defer layout.deinit();
        const original = try Template.columnLogs(a, shape, external, .main);
        defer a.free(original);
        const guarded = main.len == original.len + 2 * Halt.count(shape);
        const logs = if (guarded) try Halt.mainLogsWithExternal(a, shape, external) else try a.dupe(u32, original);
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
            const generated = try Fused.generateProjection(a, main, slot, &drawn.word.universal_prefix);
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
    channel.mixU32s(&.{ 0x42384e43, 1, @intCast(claims.len) });
    channel.mixRoot(layout_digest);
    for (claims) |claim| {
        for (claim.sum.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidEndpointNativeClaims;
        channel.mixU64(claim.row_count);
        channel.mixFelts(&.{claim.sum});
    }
}
