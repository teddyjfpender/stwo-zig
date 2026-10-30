//! One native+caller+endpoint+provider original. No WORD/access commitment.
//! Metadata and algebra remain conditional until this original verifies, then
//! the exact endpoint root still requires late bridge/global RAM closure.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Scope = @import("block_v8_endpoint_mixed_scope_v1.zig");
const Ledger = @import("block_v8_endpoint_mixed_ledger_v1.zig");
const Native = @import("block_v8_native_endpoint_components_v1.zig");
const Local = @import("block_v8_native_endpoint_local_source_v1.zig");
const Caller = @import("block_v8_caller_ram_owner_v1.zig");
const CallerHalt = @import("block_v8_caller_halt_component_v1.zig");
const Raw = @import("block_v8_endpoint_caller_raw_stage_v1.zig");
const P = @import("blake3_ethereum_sha_profile.zig");
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
const EndpointAdapter = @import("block_v5_word_quotient_adapter_v1.zig").For(Endpoint.Spec);
const RangeAdapter = @import("block_v5_word_quotient_adapter_v1.zig").For(Range.Spec);
pub const production_active = false;
pub const TRACE_TREES = 14;
pub const maps = .{ [_]usize{ 0, 1, 7 }, [_]usize{ 0, 2, 8 }, [_]usize{ 0, 3, 9 }, [_]usize{ 0, 4, 10 }, [_]usize{ 0, 5, 11 }, [_]usize{ 0, 6, 12, 13 } };
pub const Limits = @import("block_v8_endpoint_local_context_v1.zig").Limits;
pub const Stages = struct {
    batch_native_projections: bool = false,
    native_main: []const Column,
    caller: *const Raw.Owned,
    caller_main: []const Column,
    endpoints: *const Collector.Owned,
    endpoint_range: *const Range.Owned,
    program: *ROMSource.ForBackend(Cpu).FirstRound,
    program_allocator: std.mem.Allocator,
    lookup: *LookupSource.For(Cpu).Stage,
};
pub fn For(comptime proving: bool) type {
    const H = if (proving) engine.air.component_prover.ComponentProver else core.air.components.Component;
    const Placed = @import("block_v7_heterogeneous_components_v1.zig").For(maps, TRACE_TREES, proving);
    return struct {
        const Self = @This();
        a: std.mem.Allocator,
        scope: *const Scope.Owned,
        input: Scope.Input,
        draw_arena: std.heap.ArenaAllocator,
        fixed_arena: std.heap.ArenaAllocator,
        drawn: Epoch.Drawn,
        relations: P.Relations,
        extension_channel: core.proof_suites.Blake3.Channel,
        claims: Ledger.Claims,
        native: ?*Native.Owner = null,
        native_combined: ?Joint.Combined(proving) = null,
        caller: ?*Caller.Owner(proving) = null,
        caller_guard: CallerHalt.Component = undefined,
        endpoint: EndpointAdapter = undefined,
        range: RangeAdapter = undefined,
        caller_fixed: []Column = &.{},
        program: ?*Program.Context = null,
        lookup: ?*Lookup.Context = null,
        combined: ?Placed = null,
        native_generated: ?Native.Interactions = null,
        endpoint_generated: ?T.Generated(Endpoint.PLANES) = null,
        range_generated: ?T.Generated(Range.Spec.PLANES) = null,
        caller_arithmetic: ?@import("guest_precompile/ethereum_sha_columns.zig").Interaction = null,
        caller_generated: ?Caller.CompleteInteractions = null,
        caller_arithmetic_columns: []Column = &.{},
        pub fn create(a: std.mem.Allocator, scope: *const Scope.Owned, input: Scope.Input, stages: ?Stages, proposed: ?Ledger.Claims, limits: Limits) !*Self {
            if ((proving and (stages == null or proposed != null)) or (!proving and (stages != null or proposed == null))) return error.InvalidEndpointMixedPhase;
            const self = try a.create(Self);
            self.* = .{ .a = a, .scope = scope, .input = input, .draw_arena = std.heap.ArenaAllocator.init(a), .fixed_arena = std.heap.ArenaAllocator.init(a), .drawn = undefined, .relations = undefined, .extension_channel = undefined, .claims = undefined };
            errdefer self.deinit();
            self.drawn = try scope.epoch.draw(self.draw_arena.allocator());
            self.extension_channel = scope.beginProofChannel(self.drawn);
            self.extension_channel.mixU32s(&.{ 0x42384d58, 1 });
            self.relations = try P.Relations.drawAfterVm(self.draw_arena.allocator(), &self.extension_channel, self.drawn.word.universal_prefix);
            const f = self.fixed_arena.allocator();
            self.caller_fixed = try scope.caller_plan.layout.columns(f, 0, try P.preprocessed(f, input.caller_statement));
            if (proving) {
                const source = stages.?;
                if (source.endpoints.endpoints.len != input.endpoint_count or !std.meta.eql(source.endpoints.policy, scope.endpoint_policy) or source.endpoint_range.counts.endpoints != input.endpoint_count or !std.meta.eql(source.caller.plan.digest, scope.caller_plan.digest) or source.caller_main.len != scope.caller_plan.arithmetic_main_columns + scope.caller_plan.halt_main_columns) return error.UntrustedEndpointMixedStages;
                if (try std.math.mul(u64, scope.caller_plan.interaction_cells, 4) > limits.max_interaction_bytes) return error.EndpointMixedInteractionLimit;
                self.native_generated = try Native.Interactions.generateWithExternal(a, input.shape, source.native_main, &self.drawn, scope.external);
                self.endpoint_generated = try Local.endpointInteractions(a, source.endpoints.matrix, scope.descriptor.scope, &self.drawn, limits.max_interaction_bytes);
                self.range_generated = try source.endpoint_range.interactions(a, self.drawn.memory, limits.max_interaction_bytes);
                self.program = try prepareProgram(a, source.program, scope, input);
                self.lookup = try Lookup.prepare(Cpu, a, source.lookup, scope.lookupPolicy(input));
                self.caller_arithmetic = try @import("block_v7_caller_active_columns_v1.zig").interactions(a, &source.caller.witness, &self.relations, engine.work_pool.currentScopedPool() orelse return error.MissingWorkPool);
                self.caller_arithmetic_columns = try scope.caller_plan.layout.columns(a, 2, self.caller_arithmetic.?.columns);
                self.caller_generated = try Caller.CompleteInteractions.generate(a, &scope.caller_plan.ram, input.caller_statement, input.frame.cycle_count, input.frame, source.caller.fixed, source.caller.main, &self.drawn, &self.relations);
                self.claims = .{ .native = self.native_generated.?.claims, .caller_arithmetic = self.caller_arithmetic.?.claim, .caller_basic = self.caller_generated.?.basic.claims, .caller_ram = self.caller_generated.?.ram.sums, .endpoint = self.endpoint_generated.?.sums, .endpoint_range = self.range_generated.?.sums, .program = self.program.?.claims, .lookup = self.lookup.?.claims };
            } else {
                self.claims = proposed.?;
                self.program = try verifyProgram(a, scope, input, self.claims.program);
                self.lookup = try Lookup.verifier(Cpu, a, scope.lookupPolicy(input), self.claims.lookup, limits.lookup);
            }
            self.native = try Native.Owner.initWithExternalAndHalt(a, input.shape, self.claims.native, &self.drawn, scope.external, scope.halt);
            if (proving) if (stages.?.batch_native_projections) try self.native.?.enableProjectionBatch(.{});
            self.native_combined = if (proving) try self.native.?.proving() else try self.native.?.verifying();
            self.caller = try Caller.Owner(proving).initComplete(a, input.caller_statement, input.frame.cycle_count, input.frame, &self.drawn, &self.relations, &self.claims.caller_arithmetic, self.claims.caller_ram, &self.claims.caller_basic);
            self.caller_guard = try (CallerHalt.Component{ .inner = self.caller.?.context.asVerifierComponent(), .prover = if (proving) self.caller.?.context.asProverComponent() else null, .plan = &scope.caller_plan, .policy = scope.callerHalt() }).init(a);
            const endpoint_log = try Local.endpointLog(input.endpoint_count);
            self.endpoint = .{ .log_size = endpoint_log, .spec = .{ .policy = scope.endpoint_policy, .challenges = Endpoint.fromEpoch(self.drawn), .sums = self.claims.endpoint } };
            self.range = .{ .log_size = 16, .spec = .{ .challenges = self.drawn.memory, .sums = self.claims.endpoint_range } };
            const endpoint: H = if (proving) self.endpoint.asProverComponent() else self.endpoint.asVerifierComponent();
            const range: H = if (proving) self.range.asProverComponent() else self.range.asVerifierComponent();
            const caller: H = if (proving) self.caller_guard.asProverComponent() else self.caller_guard.asVerifierComponent();
            self.combined = try Placed.init(a, .{ self.native_combined.?.handles, &.{endpoint}, &.{range}, if (proving) self.program.?.provers else self.program.?.verifiers, if (proving) self.lookup.?.provers else self.lookup.?.verifiers, &.{caller} }, .{ self.native.?.fixed.len, Endpoint.Spec.FIXED_COUNT, Range.Spec.FIXED_COUNT, self.program.?.fixed_columns.len, self.lookup.?.fixed_columns.len, self.caller_fixed.len });
            return self;
        }
        pub fn deinit(self: *Self) void {
            if (self.combined) |*value| value.deinit(self.a);
            if (self.caller) |value| value.deinit();
            if (self.native_combined) |*value| value.deinit(self.a);
            if (self.native) |value| value.deinit();
            if (self.lookup) |value| value.deinit();
            if (self.program) |value| value.deinit();
            if (self.caller_generated) |*value| value.deinit();
            self.a.free(self.caller_arithmetic_columns);
            if (self.caller_arithmetic) |*value| value.deinit(self.a);
            if (self.range_generated) |*value| value.deinit();
            if (self.endpoint_generated) |*value| value.deinit();
            if (self.native_generated) |*value| value.deinit();
            self.fixed_arena.deinit();
            self.draw_arena.deinit();
            self.a.destroy(self);
        }
        pub fn channel(self: *const Self) !core.proof_suites.Blake3.Channel {
            var ch = self.extension_channel;
            try self.recordPhysicalClaims(&ch);
            return ch;
        }
        /// Shared physical-claim framing for native and symbolic transcript recorders.
        pub fn recordPhysicalClaims(self: *const Self, ch: anytype) !void {
            try Native.recordClaims(ch, self.scope.layout.digest, self.claims.native);
            ch.mixU32s(&.{ 0x42384d50, 1, Endpoint.PLANES, Range.Spec.PLANES });
            for (self.claims.endpoint) |sum| {
                for (sum.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidEndpointMixedClaims;
                ch.mixFelts(&.{sum});
            }
            for (self.claims.endpoint_range) |sum| {
                for (sum.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidEndpointMixedClaims;
                ch.mixFelts(&.{sum});
            }
            try Caller.recordCompleteClaims(ch, &self.scope.caller_plan.layout, &self.scope.caller_plan.schedule, &self.claims.caller_arithmetic, &self.claims.caller_basic, self.claims.caller_ram);
            try self.program.?.recordAfterChallenges(ch);
            try self.lookup.?.recordAfterChallenges(ch);
        }
        pub fn close(self: *const Self) !Ledger.Summary {
            return Ledger.close(self.a, self.scope, self.input, self.claims, &self.drawn);
        }
        pub fn fixedColumns(self: *const Self) !Fixed {
            var local = try fixedLocal(self.a, self.input.shape, self.scope.external, self.input.endpoint_count);
            errdefer local.deinit();
            const columns = try std.mem.concat(self.a, Column, &.{ local.columns, self.program.?.fixed_columns, self.lookup.?.fixed_columns, self.caller_fixed });
            return .{ .a = self.a, .local = local, .columns = columns };
        }
        pub fn interactionColumns(self: *const Self) ![7][]const Column {
            if (!proving) return error.InvalidEndpointMixedPhase;
            return .{ self.native_generated.?.columns, self.endpoint_generated.?.matrix.columns, self.range_generated.?.matrix.columns, self.program.?.interaction, self.lookup.?.interaction, self.caller_arithmetic_columns, self.caller_generated.?.columns };
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
    }
};
fn fixedLocal(a: std.mem.Allocator, shape: *const @import("../air/statement.zig").Blake3ExecutionStatement, external: u32, count: u32) !Local.Fixed {
    var list: std.ArrayList(Column) = .empty;
    errdefer {
        for (list.items) |column| a.free(column.values);
        list.deinit(a);
    }
    try @import("blake3_execution_protocol.zig").nativePreprocessedWithExternal(a, shape, external, &list);
    const log = try Local.endpointLog(count);
    for (0..2) |kind| {
        const rows = @as(usize, 1) << @intCast(log);
        const values = try a.alloc(core.fields.m31.M31, rows);
        errdefer a.free(values);
        for (0..rows) |row| values[core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(row, log), log)] = core.fields.m31.M31.fromCanonical(@intFromBool(if (kind == 0) row < count else row == 0));
        try list.append(a, .{ .log_size = log, .values = values });
    }
    for (0..2) |kind| {
        const values = try a.alloc(core.fields.m31.M31, 65536);
        errdefer a.free(values);
        for (0..65536) |row| values[core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(row, 16), 16)] = if (kind == 0) core.fields.m31.M31.one() else core.fields.m31.M31.fromCanonical(@intCast(row));
        try list.append(a, .{ .log_size = 16, .values = values });
    }
    return .{ .a = a, .columns = try list.toOwnedSlice(a) };
}
fn wrapProgram(a: std.mem.Allocator, value: anytype) !*Program.Context {
    errdefer value.deinit();
    const self = try a.create(Program.Context);
    self.* = .{ .allocator = a, .claims = value.claims, .logs = value.logs, .fixed_columns = value.fixed_columns, .interaction = value.interaction, .provers = value.provers, .verifiers = value.verifiers };
    if (@TypeOf(value) == *@import("block_v7_complete_union_program_v1.zig").Context) self.legacy = value else self.sparse = value;
    return self;
}
fn prepareProgram(a: std.mem.Allocator, first: *const ROMSource.ForBackend(Cpu).FirstRound, scope: *const Scope.Owned, input: Scope.Input) !*Program.Context {
    return switch (input.rom_flavor) {
        .legacy_complete => wrapProgram(a, try @import("block_v7_complete_union_program_v1.zig").prepare(Cpu, a, first, scope.programPolicy(input))),
        .sparse_elf => wrapProgram(a, try @import("block_v8_sparse_rom_provider_v1.zig").prepare(Cpu, a, first, scope.sparseProgramPolicy(input))),
    };
}
fn verifyProgram(a: std.mem.Allocator, scope: *const Scope.Owned, input: Scope.Input, claim: core.fields.qm31.QM31) !*Program.Context {
    return switch (input.rom_flavor) {
        .legacy_complete => wrapProgram(a, try @import("block_v7_complete_union_program_v1.zig").verifier(Cpu, a, scope.programPolicy(input), claim)),
        .sparse_elf => wrapProgram(a, try @import("block_v8_sparse_rom_provider_v1.zig").verifier(Cpu, a, scope.sparseProgramPolicy(input), claim)),
    };
}
