//! Bounded group original: per-member native/caller/endpoint equations,
//! ONE range provider, ONE ROM and ONE lookup provider. No residual CPU or
//! RAM claim may cancel another member's residual. Global RAM remains open.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Scope = @import("block_v8_endpoint_group_scope_v1.zig");
const Ledger = @import("block_v8_endpoint_group_ledger_v1.zig");
const Layout = @import("block_v8_endpoint_group_layout_v1.zig");
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
pub const Limits = @import("block_v8_endpoint_local_context_v1.zig").Limits;
pub const MemberStages = struct { native_main: []const Column, endpoints: *const Collector.Owned, caller: ?*const Raw.Owned = null, caller_main: []const Column = &.{} };
pub const Stages = struct { batch_native_projections: bool = false, members: []const MemberStages, endpoint_range: *const Range.Owned, program: *ROMSource.ForBackend(Cpu).FirstRound, program_allocator: std.mem.Allocator, lookup: *LookupSource.For(Cpu).Stage };
pub fn For(comptime proving: bool) type {
    const H = if (proving) engine.air.component_prover.ComponentProver else core.air.components.Component;
    const Placed = @import("block_v7_heterogeneous_components_v1.zig").Dynamic(proving);
    const Member = struct {
        native: ?*Native.Owner = null,
        combined: ?Joint.Combined(proving) = null,
        endpoint: EndpointAdapter = undefined,
        ep_handle: [1]H = undefined,
        caller: ?*Caller.Owner(proving) = null,
        guard: CallerHalt.Component = undefined,
        caller_handle: [1]H = undefined,
        caller_fixed: []Column = &.{},
        relations: ?P.Relations = null,
        native_generated: ?Native.Interactions = null,
        endpoint_generated: ?T.Generated(Endpoint.PLANES) = null,
        caller_arithmetic: ?@import("guest_precompile/ethereum_sha_columns.zig").Interaction = null,
        caller_generated: ?Caller.CompleteInteractions = null,
        caller_arithmetic_columns: []Column = &.{},
        fn deinit(self: *@This(), a: std.mem.Allocator) void {
            if (self.caller) |v| v.deinit();
            if (self.combined) |*v| v.deinit(a);
            if (self.native) |v| v.deinit();
            if (self.caller_generated) |*v| v.deinit();
            a.free(self.caller_arithmetic_columns);
            if (self.caller_arithmetic) |*v| v.deinit(a);
            if (self.endpoint_generated) |*v| v.deinit();
            if (self.native_generated) |*v| v.deinit();
        }
    };
    return struct {
        const Self = @This();
        a: std.mem.Allocator,
        scope: *const Scope.Owned,
        input: Scope.Input,
        layout: Layout.Plan,
        arena: std.heap.ArenaAllocator,
        drawn: Epoch.Drawn,
        extension_channel: core.proof_suites.Blake3.Channel,
        members: []Member = &.{},
        owned_claims: []Ledger.MemberClaims = &.{},
        claims: Ledger.Claims = undefined,
        range: RangeAdapter = undefined,
        range_handle: [1]H = undefined,
        range_generated: ?T.Generated(Range.Spec.PLANES) = null,
        program: ?*Program.Context = null,
        lookup: ?*Lookup.Context = null,
        combined: ?Placed = null,
        pub fn create(a: std.mem.Allocator, scope: *const Scope.Owned, input: Scope.Input, stages: ?Stages, proposed: ?Ledger.Claims, limits: Limits) !*Self {
            if ((proving and (stages == null or proposed != null)) or (!proving and (stages != null or proposed == null))) return error.InvalidEndpointGroupPhase;
            var callers: usize = 0;
            for (scope.member) |member| callers += @intFromBool(member.caller_plan != null);
            const layout = try Layout.Plan.initWithProfile(input.members.len, callers, input.profile);
            const self = try a.create(Self);
            self.* = .{ .a = a, .scope = scope, .input = input, .layout = layout, .arena = std.heap.ArenaAllocator.init(a), .drawn = undefined, .extension_channel = undefined };
            errdefer self.deinit();
            const t = self.arena.allocator();
            self.drawn = try scope.epoch.draw(t);
            self.extension_channel = scope.beginProofChannel(self.drawn);
            self.members = try a.alloc(Member, layout.n);
            for (self.members) |*member| member.* = .{};
            for (scope.member, input.members, self.members, 0..) |*admitted, member_input, *member, i| if (admitted.caller_plan) |*plan| {
                self.extension_channel.mixU32s(&.{ 0x42384758, 1, @intCast(i) });
                member.relations = try P.Relations.drawAfterVm(t, &self.extension_channel, self.drawn.word.universal_prefix);
                member.caller_fixed = try plan.layout.columns(t, 0, try P.preprocessed(t, member_input.caller.?.statement));
            };
            if (proving) {
                const source = stages.?;
                if (source.members.len != layout.n or source.endpoint_range.counts.endpoints != scope.endpoint_count_total) return error.UntrustedEndpointGroupStages;
                self.owned_claims = try a.alloc(Ledger.MemberClaims, layout.n);
                for (scope.member, input.members, source.members, self.members, self.owned_claims) |*admitted, member_input, st, *member, *claim| {
                    if (st.endpoints.endpoints.len != member_input.endpoint_count or !std.meta.eql(st.endpoints.policy, admitted.endpoint_policy)) return error.UntrustedEndpointGroupStages;
                    member.native_generated = try Native.Interactions.generateWithExternal(a, member_input.shape, st.native_main, &self.drawn, admitted.external);
                    if (st.endpoints.matrix.log != try Local.endpointLog(member_input.endpoint_count) or st.endpoints.matrix.columns.len != Endpoint.Spec.FIXED_COUNT + Endpoint.Spec.MAIN_COUNT) return error.UntrustedEndpointGroupStages;
                    member.endpoint_generated = try T.interactions(Endpoint.PLANES, a, st.endpoints.matrix, Local.EndpointContext{ .policy = admitted.endpoint_policy, .challenges = Endpoint.fromEpoch(self.drawn) }, limits.max_interaction_bytes);
                    claim.* = .{ .native = member.native_generated.?.claims, .endpoint = member.endpoint_generated.?.sums, .caller = null };
                    if (admitted.caller_plan) |*plan| {
                        const raw = st.caller orelse return error.MissingGroupCallerStage;
                        if (!std.meta.eql(plan.digest, raw.plan.digest) or st.caller_main.len != plan.arithmetic_main_columns + plan.halt_main_columns or try std.math.mul(u64, plan.interaction_cells, 4) > limits.max_interaction_bytes) return error.UntrustedEndpointGroupStages;
                        member.caller_arithmetic = try @import("block_v7_caller_active_columns_v1.zig").interactions(a, &raw.witness, &member.relations.?, engine.work_pool.currentScopedPool() orelse return error.MissingWorkPool);
                        member.caller_arithmetic_columns = try plan.layout.columns(a, 2, member.caller_arithmetic.?.columns);
                        member.caller_generated = try Caller.CompleteInteractions.generate(a, &plan.ram, member_input.caller.?.statement, member_input.frame.cycle_count, member_input.frame, raw.fixed, raw.main, &self.drawn, &member.relations.?);
                        claim.caller = .{ .arithmetic = member.caller_arithmetic.?.claim, .basic = member.caller_generated.?.basic.claims, .ram = member.caller_generated.?.ram.sums };
                    } else if (st.caller != null or st.caller_main.len != 0) return error.UnexpectedGroupCallerStage;
                }
                self.range_generated = try source.endpoint_range.interactions(a, self.drawn.memory, limits.max_interaction_bytes);
                self.program = try prepareProgram(a, source.program, scope, input);
                self.lookup = try Lookup.prepare(Cpu, a, source.lookup, scope.lookupPolicy(input));
                self.claims = .{ .members = self.owned_claims, .endpoint_range = self.range_generated.?.sums, .program = self.program.?.claims, .lookup = self.lookup.?.claims };
            } else {
                self.claims = proposed.?;
                if (self.claims.members.len != layout.n) return error.InvalidEndpointGroupClaims;
                self.program = try verifyProgram(a, scope, input, self.claims.program);
                self.lookup = try Lookup.verifier(Cpu, a, scope.lookupPolicy(input), self.claims.lookup, limits.lookup);
            }
            for (scope.member, input.members, self.members, self.claims.members) |*admitted, member_input, *member, claim| {
                if ((admitted.caller_plan != null) != (claim.caller != null)) return error.InvalidEndpointGroupCallerClaims;
                member.native = try Native.Owner.initWithExternalAndHalt(a, member_input.shape, claim.native, &self.drawn, admitted.external, scope.halt);
                if (proving) if (stages.?.batch_native_projections) try member.native.?.enableProjectionBatch(.{});
                member.combined = if (proving) try member.native.?.proving() else try member.native.?.verifying();
                member.endpoint = .{ .log_size = try Local.endpointLog(member_input.endpoint_count), .spec = .{ .policy = admitted.endpoint_policy, .challenges = Endpoint.fromEpoch(self.drawn), .sums = claim.endpoint } };
                member.ep_handle[0] = if (proving) member.endpoint.asProverComponent() else member.endpoint.asVerifierComponent();
                if (admitted.caller_plan) |*plan| {
                    member.caller = try Caller.Owner(proving).initComplete(a, member_input.caller.?.statement, member_input.frame.cycle_count, member_input.frame, &self.drawn, &member.relations.?, &claim.caller.?.arithmetic, claim.caller.?.ram, &claim.caller.?.basic);
                    member.guard = try (CallerHalt.Component{ .inner = member.caller.?.context.asVerifierComponent(), .prover = if (proving) member.caller.?.context.asProverComponent() else null, .plan = plan, .policy = scope.halt }).init(a);
                    member.caller_handle[0] = if (proving) member.guard.asProverComponent() else member.guard.asVerifierComponent();
                }
            }
            self.range = .{ .log_size = 16, .spec = .{ .challenges = self.drawn.memory, .sums = self.claims.endpoint_range } };
            self.range_handle[0] = if (proving) self.range.asProverComponent() else self.range.asVerifierComponent();
            const parts = try t.alloc(Placed.Part, layout.partCount());
            for (self.members, 0..) |*member, i| {
                const native_map = try t.dupe(usize, &layout.native(i));
                const endpoint_map = try t.dupe(usize, &layout.endpoint(i));
                parts[i] = .{ .map = native_map, .handles = member.combined.?.handles, .fixed_count = member.native.?.fixed.len };
                parts[layout.n + i] = .{ .map = endpoint_map, .handles = &member.ep_handle, .fixed_count = Endpoint.Spec.FIXED_COUNT };
            }
            parts[2 * layout.n] = .{ .map = try t.dupe(usize, &layout.range()), .handles = &self.range_handle, .fixed_count = Range.Spec.FIXED_COUNT };
            parts[2 * layout.n + 1] = .{ .map = try t.dupe(usize, &layout.program()), .handles = if (proving) self.program.?.provers else self.program.?.verifiers, .fixed_count = self.program.?.fixed_columns.len };
            parts[2 * layout.n + 2] = .{ .map = try t.dupe(usize, &layout.lookup()), .handles = if (proving) self.lookup.?.provers else self.lookup.?.verifiers, .fixed_count = self.lookup.?.fixed_columns.len };
            for (scope.member, self.members) |admitted, *member| if (admitted.caller_index) |index| {
                parts[2 * layout.n + 3 + index] = .{ .map = try t.dupe(usize, &layout.caller(index)), .handles = &member.caller_handle, .fixed_count = member.caller_fixed.len };
            };
            self.combined = try Placed.init(a, parts, layout.traces());
            return self;
        }
        pub fn deinit(self: *Self) void {
            if (self.combined) |*v| v.deinit(self.a);
            for (self.members) |*member| member.deinit(self.a);
            self.a.free(self.members);
            self.a.free(self.owned_claims);
            if (self.lookup) |v| v.deinit();
            if (self.program) |v| v.deinit();
            if (self.range_generated) |*v| v.deinit();
            self.arena.deinit();
            self.a.destroy(self);
        }
        pub fn channel(self: *const Self) !core.proof_suites.Blake3.Channel {
            var ch = self.extension_channel;
            try self.recordPhysicalClaims(&ch);
            return ch;
        }
        pub fn recordPhysicalClaims(self: *const Self, ch: anytype) !void {
            ch.mixU32s(&.{ 0x42384750, 1, @intCast(self.layout.n), @intCast(self.layout.m) });
            for (self.scope.member, self.claims.members, 0..) |*admitted, claim, i| {
                ch.mixU32s(&.{@intCast(i)});
                ch.mixRoot(admitted.identity);
                try Native.recordClaims(ch, admitted.layout.digest, claim.native);
                for (claim.endpoint) |sum| {
                    try canonical(sum);
                    ch.mixFelts(&.{sum});
                }
                if (claim.caller) |caller| try Caller.recordCompleteClaims(ch, &admitted.caller_plan.?.layout, &admitted.caller_plan.?.schedule, &caller.arithmetic, &caller.basic, caller.ram);
            }
            for (self.claims.endpoint_range) |sum| {
                try canonical(sum);
                ch.mixFelts(&.{sum});
            }
            try self.program.?.recordAfterChallenges(ch);
            try self.lookup.?.recordAfterChallenges(ch);
        }
        pub fn close(self: *const Self) !Ledger.Summary {
            return Ledger.close(self.a, self.scope, self.input, self.claims, &self.drawn);
        }
        pub fn interactionColumns(self: *const Self, a: std.mem.Allocator) ![][]const Column {
            if (!proving) return error.InvalidEndpointGroupPhase;
            const out = try a.alloc([]const Column, self.layout.traces() - self.layout.firstRoots());
            for (self.members, 0..) |member, i| {
                out[self.layout.native(i)[2] - self.layout.firstRoots()] = member.native_generated.?.columns;
                out[self.layout.endpoint(i)[2] - self.layout.firstRoots()] = member.endpoint_generated.?.matrix.columns;
            }
            out[self.layout.range()[2] - self.layout.firstRoots()] = self.range_generated.?.matrix.columns;
            out[self.layout.program()[2] - self.layout.firstRoots()] = self.program.?.interaction;
            out[self.layout.lookup()[2] - self.layout.firstRoots()] = self.lookup.?.interaction;
            for (self.scope.member, self.members) |admitted, member| if (admitted.caller_index) |index| {
                out[self.layout.caller(index)[2] - self.layout.firstRoots()] = member.caller_arithmetic_columns;
                out[self.layout.caller(index)[3] - self.layout.firstRoots()] = member.caller_generated.?.columns;
            };
            return out;
        }
        pub fn fixedColumns(self: *const Self) !Fixed {
            var arena = std.heap.ArenaAllocator.init(self.a);
            errdefer arena.deinit();
            const t = arena.allocator();
            var out: std.ArrayList(Column) = .empty;
            for (self.input.members, self.scope.member) |input, admitted| try @import("blake3_execution_protocol.zig").nativePreprocessedWithExternal(t, input.shape, admitted.external, &out);
            for (self.input.members) |input| {
                const log = try Local.endpointLog(input.endpoint_count);
                var prefix = try T.Matrix.init(t, log, 2, 1 << 30);
                for (0..input.endpoint_count) |i| prefix.set(0, i, core.fields.m31.M31.one());
                prefix.set(1, 0, core.fields.m31.M31.one());
                try out.appendSlice(t, prefix.columns);
            }
            var ranges = try T.Matrix.init(t, 16, 2, 2 << 20);
            for (0..65536) |i| {
                ranges.set(0, i, core.fields.m31.M31.one());
                ranges.set(1, i, core.fields.m31.M31.fromCanonical(@intCast(i)));
            }
            try out.appendSlice(t, ranges.columns);
            try out.appendSlice(t, self.program.?.fixed_columns);
            try out.appendSlice(t, self.lookup.?.fixed_columns);
            for (self.members) |member| if (member.caller != null) {
                try out.appendSlice(t, member.caller_fixed);
            };
            return .{ .arena = arena, .columns = try out.toOwnedSlice(t) };
        }
    };
}
pub const Fixed = struct {
    arena: std.heap.ArenaAllocator,
    columns: []Column,
    pub fn deinit(self: *Fixed) void {
        self.arena.deinit();
    }
};
fn canonical(sum: core.fields.qm31.QM31) !void {
    for (sum.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidEndpointGroupClaims;
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
