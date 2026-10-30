//! Source-local B8 native/endpoint/ROM/lookup assembly. Every original
//! equation remains authoritative; global RAM is deliberately deferred.
//! This context confers no proof authority before the original STARK verifies.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Scope = @import("block_v8_endpoint_local_scope_v1.zig");
const Ledger = @import("block_v8_endpoint_local_ledger_v1.zig");
const Placement = @import("block_v8_endpoint_local_placement_v1.zig");
const Native = @import("block_v8_native_endpoint_components_v1.zig");
const Local = @import("block_v8_native_endpoint_local_source_v1.zig");
const Collector = @import("block_v8_ram_endpoint_collector_v1.zig");
const Range = @import("block_v8_endpoint_range_provider_v1.zig");
const Endpoint = @import("block_v8_ram_endpoint_component_v1.zig");
const T = @import("block_v7_memory_trace_v1.zig");
const Epoch = @import("block_v7_execution_epoch_v1.zig");
const Program = @import("block_v8_endpoint_local_rom_dispatch_v1.zig");
const Lookup = @import("block_v7_complete_union_lookup_v1.zig");
const ROMSource = @import("block_v7_program_provider_v1.zig");
const LookupSource = @import("block_v7_lookup_compact_proof_v1.zig");
const Joint = @import("block_v6_joint_components_v1.zig");
const Column = engine.pcs.ColumnEvaluation;
pub const production_active = false;
pub const Limits = struct {
    max_interaction_bytes: usize = 2 << 30,
    lookup: LookupSource.Limits = .{},
};
pub const Stages = struct {
    batch_native_projections: bool = false,
    native_batch_options: @import("block_v8_native_projection_domain_batch_v1.zig").Options = .{},
    native_main: []const Column,
    endpoints: *const Collector.Owned,
    endpoint_range: *const Range.Owned,
    program: *ROMSource.ForBackend(Cpu).FirstRound,
    program_allocator: std.mem.Allocator,
    lookup: *LookupSource.For(Cpu).Stage,
};
pub fn For(comptime proving: bool) type {
    return struct {
        const Self = @This();
        const Placed = Placement.For(proving);
        a: std.mem.Allocator,
        scope: *const Scope.Owned,
        input: Scope.Input,
        draw_arena: std.heap.ArenaAllocator,
        drawn: Epoch.Drawn,
        claims: Ledger.Claims,
        local: ?*Local.Owner = null,
        native_combined: ?Joint.Combined(proving) = null,
        program: ?*Program.Context = null,
        lookup: ?*Lookup.Context = null,
        combined: ?Placed = null,
        native_generated: ?Native.Interactions = null,
        endpoint_generated: ?T.Generated(Endpoint.PLANES) = null,
        range_generated: ?T.Generated(Range.Spec.PLANES) = null,
        pub fn create(a: std.mem.Allocator, scope: *const Scope.Owned, input: Scope.Input, stages: ?Stages, proposed: ?Ledger.Claims, limits: Limits) !*Self {
            if ((proving and (stages == null or proposed != null)) or
                (!proving and (stages != null or proposed == null))) return error.InvalidEndpointLocalPhase;
            const self = try a.create(Self);
            self.* = .{ .a = a, .scope = scope, .input = input, .draw_arena = std.heap.ArenaAllocator.init(a), .drawn = undefined, .claims = undefined };
            errdefer self.deinit();
            self.drawn = try scope.epoch.draw(self.draw_arena.allocator());
            if (proving) {
                const source = stages.?;
                if (source.endpoints.endpoints.len != input.endpoint_count or
                    !std.meta.eql(source.endpoints.policy, scope.descriptor.scope.policy) or
                    source.endpoint_range.counts.endpoints != input.endpoint_count)
                    return error.UntrustedEndpointLocalStages;
                self.native_generated = if (input.native_profile.isDirect()) try @import("block_v8_native_endpoint_interactions_v3.zig").generate(a, input.shape, source.native_main, &self.drawn) else try Native.Interactions.generate(a, input.shape, source.native_main, &self.drawn);
                self.endpoint_generated = try Local.endpointInteractions(a, source.endpoints.matrix, scope.descriptor.scope, &self.drawn, limits.max_interaction_bytes);
                self.range_generated = try source.endpoint_range.interactions(a, self.drawn.memory, limits.max_interaction_bytes);
                self.program = try Program.prepare(a, source.program, scope, input);
                self.lookup = try Lookup.prepare(Cpu, a, source.lookup, scope.lookupPolicy(input));
                self.claims = .{ .native = self.native_generated.?.claims, .endpoint = self.endpoint_generated.?.sums, .endpoint_range = self.range_generated.?.sums, .program = self.program.?.claims, .lookup = self.lookup.?.claims };
            } else {
                self.claims = proposed.?;
                self.program = try Program.verifier(a, scope, input, self.claims.program);
                self.lookup = try Lookup.verifier(Cpu, a, scope.lookupPolicy(input), self.claims.lookup, limits.lookup);
            }
            self.local = try Local.Owner.init(a, input.shape, scope.descriptor.scope, self.claims.native, self.claims.endpoint, self.claims.endpoint_range, &self.drawn);
            if (proving) if (stages.?.batch_native_projections) try self.local.?.native.enableProjectionBatch(stages.?.native_batch_options);
            self.native_combined = if (proving) try self.local.?.native.proving() else try self.local.?.native.verifying();
            const H = if (proving) engine.air.component_prover.ComponentProver else core.air.components.Component;
            const endpoint: H = if (proving) self.local.?.endpoint.asProverComponent() else self.local.?.endpoint.asVerifierComponent();
            const range: H = if (proving) self.local.?.range.asProverComponent() else self.local.?.range.asVerifierComponent();
            self.combined = try Placed.init(a, .{
                self.native_combined.?.handles,                                    &.{endpoint},                                                    &.{range},
                if (proving) self.program.?.provers else self.program.?.verifiers, if (proving) self.lookup.?.provers else self.lookup.?.verifiers,
            }, .{ self.local.?.native.fixed.len, Endpoint.Spec.FIXED_COUNT, Range.Spec.FIXED_COUNT, self.program.?.fixed_columns.len, self.lookup.?.fixed_columns.len });
            return self;
        }
        pub fn deinit(self: *Self) void {
            if (self.combined) |*value| value.deinit(self.a);
            if (self.native_combined) |*value| value.deinit(self.a);
            if (self.local) |value| value.deinit();
            if (self.lookup) |value| value.deinit();
            if (self.program) |value| value.deinit();
            if (self.range_generated) |*value| value.deinit();
            if (self.endpoint_generated) |*value| value.deinit();
            if (self.native_generated) |*value| value.deinit();
            self.draw_arena.deinit();
            self.a.destroy(self);
        }
        /// All original source and provider claims are bound before the first
        /// of five interaction commitments. The epoch binds all first roots.
        pub fn channel(self: *const Self) !core.proof_suites.Blake3.Channel {
            var result = self.scope.beginProofChannel(self.drawn);
            try Local.recordClaims(&result, self.local.?.native.layout.digest, self.claims.native, self.claims.endpoint, self.claims.endpoint_range);
            try self.program.?.recordAfterChallenges(&result);
            try self.lookup.?.recordAfterChallenges(&result);
            return result;
        }
        pub fn close(self: *const Self) !Ledger.Summary {
            return Ledger.close(self.a, self.scope, self.input, self.claims, &self.drawn);
        }
        /// Caller owns descriptors, but values remain borrowed from this live
        /// context. The local native/endpoint/range fixed values are separately
        /// owned by the returned value and independently reconstructed.
        pub fn fixedColumns(self: *const Self) !Fixed {
            var local = try Local.fixedColumns(self.a, self.input.shape, self.input.endpoint_count);
            errdefer local.deinit();
            var list: std.ArrayList(Column) = .empty;
            errdefer list.deinit(self.a);
            try list.appendSlice(self.a, local.columns);
            try list.appendSlice(self.a, self.program.?.fixed_columns);
            try list.appendSlice(self.a, self.lookup.?.fixed_columns);
            return .{ .a = self.a, .local = local, .columns = try list.toOwnedSlice(self.a) };
        }
        pub fn interactionColumns(self: *const Self) ![5][]const Column {
            if (!proving) return error.InvalidEndpointLocalPhase;
            return .{ self.native_generated.?.columns, self.endpoint_generated.?.matrix.columns, self.range_generated.?.matrix.columns, self.program.?.interaction, self.lookup.?.interaction };
        }
    };
}
pub const Fixed = struct {
    a: std.mem.Allocator,
    local: Local.Fixed,
    columns: []Column,
    pub fn deinit(self: *Fixed) void {
        self.a.free(self.columns);
        self.local.deinit();
        self.* = undefined;
    }
};
