//! Experimental original active caller arithmetic + exact RAM projection.
//! No integer-copy/WORD access witness is allocated. The original arithmetic
//! equation roster and all physical claims remain intact. ROM/state/register/
//! table and endpoint local closure remain OPEN in this first vertical slice.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Q = core.fields.qm31.QM31;
const P = @import("blake3_ethereum_sha_profile.zig");
const Schedule = @import("block_v7_caller_active_schedule_v1.zig");
const Layout = @import("block_v7_caller_active_layout_v1.zig").Layout;
const Projection = @import("block_v8_caller_ram_projection_v1.zig");
const Ram = @import("block_v8_caller_ram_component_v1.zig");
const Wrapped = @import("block_v5_composite_projection_adapter_v1.zig").Projection(Ram.Component);
const CC = @import("block_v6_caller_joint_components_v1.zig");
const Assembly = @import("block_v7_caller_active_assembly_v1.zig").Assembly;
const Column = engine.pcs.ColumnEvaluation;
const Frame = @import("../air/block/memory_event.zig").Frame;
const E = @import("block_v7_execution_epoch_v1.zig");
const Fused = @import("block_v5_caller_fused_proof_v1.zig");
pub const production_active = false;
pub fn Owner(comptime proving: bool) type {
    const Arithmetic = Assembly(if (proving) .prover else .verifier);
    const H = if (proving) engine.air.component_prover.ComponentProver else core.air.components.Component;
    return struct {
        a: std.mem.Allocator,
        schedule: Schedule.Schedule,
        layout: Layout,
        arithmetic: *Arithmetic,
        ram: []Wrapped,
        ram_handles: []H,
        ram_logs: []u32,
        arithmetic_logs: []u32,
        state_offsets: []usize,
        context: *CC.Owner(proving),
        relations: P.Relations,
        basic: ?*Fused.Components = null,
        complete_projection: bool = false,
        const Self = @This();
        pub fn init(a: std.mem.Allocator, statement: *const P.admission.Statement, steps: u32, frame: Frame, drawn: *const E.Drawn, relations: *const P.Relations, arithmetic_claims: *const P.ExtensionClaim, ram_sums: []const Q) !*Self {
            return initInternal(a, statement, steps, frame, drawn, relations, arithmetic_claims, ram_sums, null);
        }
        pub fn initComplete(a: std.mem.Allocator, statement: *const P.admission.Statement, steps: u32, frame: Frame, drawn: *const E.Drawn, relations: *const P.Relations, arithmetic_claims: *const P.ExtensionClaim, ram_sums: []const Q, basic_claims: *const Fused.ClaimFrames) !*Self {
            return initInternal(a, statement, steps, frame, drawn, relations, arithmetic_claims, ram_sums, basic_claims);
        }
        fn initInternal(a: std.mem.Allocator, statement: *const P.admission.Statement, steps: u32, frame: Frame, drawn: *const E.Drawn, relations: *const P.Relations, arithmetic_claims: *const P.ExtensionClaim, ram_sums: []const Q, basic_claims: ?*const Fused.ClaimFrames) !*Self {
            // Extension challenges may differ by source, but every native bus
            // must remain exactly the supplied independently drawn epoch bus.
            const expected_relations = try P.Relations.fromDraws(drawn.word.universal_prefix, &relations.draws());
            if (!std.meta.eql(expected_relations, relations.*)) return error.UntrustedCallerRamRelations;
            const self = try a.create(Self);
            errdefer a.destroy(self);
            self.a = a;
            self.relations = relations.*;
            self.basic = null;
            self.complete_projection = basic_claims != null;
            self.schedule = try Schedule.derive(a, statement, steps, frame);
            errdefer self.schedule.deinit();
            self.layout = try Layout.derive(statement, steps);
            if (self.schedule.memory.len != ram_sums.len or ram_sums.len == 0) return error.InvalidCallerRamClaims;
            var basic_schedule = self.schedule;
            basic_schedule.memory = &.{};
            basic_schedule.rw_events = 0;
            const basic_logs = if (basic_claims != null) try basic_schedule.interactionLogs() else try a.alloc(u32, 0);
            defer a.free(basic_logs);
            if (basic_claims) |claims| {
                var checked = core.proof_suites.Blake3.Channel{};
                try Fused.mixClaimBodies(&checked, &basic_schedule, claims.program_claims, claims.state_claims, claims.table_claims, claims.memory_claims);
            }
            self.ram_logs = try a.alloc(u32, try std.math.add(usize, basic_logs.len, try std.math.mul(usize, ram_sums.len, 4)));
            @memcpy(self.ram_logs[0..basic_logs.len], basic_logs);
            errdefer a.free(self.ram_logs);
            var states: std.ArrayList(usize) = .empty;
            errdefer states.deinit(a);
            for (self.schedule.memory, 0..) |descriptor, index| {
                @memset(self.ram_logs[basic_logs.len + 4 * index ..][0..4], descriptor.log_size);
                if (descriptor.kind == .keccak) {
                    const offset = descriptor.main_offset + @import("../air/guest_precompile/keccakf_trace.zig").Layout.state;
                    if (std.mem.indexOfScalar(usize, states.items, offset) == null) try states.append(a, offset);
                }
            }
            self.state_offsets = try states.toOwnedSlice(a);
            errdefer a.free(self.state_offsets);
            self.arithmetic_logs = try self.layout.columnLogs(a, 2);
            errdefer a.free(self.arithmetic_logs);
            self.arithmetic = try Arithmetic.init(a, statement, steps, &self.relations, arithmetic_claims);
            errdefer self.arithmetic.destroy(a);
            self.ram = try a.alloc(Wrapped, ram_sums.len);
            errdefer a.free(self.ram);
            self.ram_handles = try a.alloc(H, ram_sums.len);
            errdefer a.free(self.ram_handles);
            const native_relation = try Projection.nativeRelation(&drawn.word.universal_prefix);
            for (self.schedule.memory, ram_sums, self.ram, 0..) |descriptor, claim, *component, index| {
                component.* = try (Wrapped{ .inner = .{ .descriptor = descriptor, .fixed_logs = self.schedule.fixed, .main_logs = self.schedule.main, .interaction_logs = self.ram_logs, .interaction_offset = basic_logs.len + 4 * index, .root_owner = index == 0, .keccak_state_offsets = self.state_offsets, .relation = native_relation, .claim = claim }, .composition_split = 2 }).init();
                self.ram_handles[index] = if (proving) component.asProverComponent() else component.asVerifierComponent();
            }
            const total = try std.math.add(usize, self.ram_handles.len, if (basic_claims != null) self.schedule.projectionCount() else 0);
            const handles = try a.alloc(H, total);
            defer a.free(handles);
            @memcpy(handles[0..self.ram_handles.len], self.ram_handles);
            if (basic_claims) |claims| {
                const basic = try a.create(Fused.Components);
                errdefer a.destroy(basic);
                basic.* = try Fused.Components.init(a, &basic_schedule, claims, &self.relations, &drawn.bytes, &drawn.word, self.ram_logs, &.{}, 1);
                errdefer basic.deinit();
                self.basic = basic;
                var at = self.ram_handles.len;
                inline for (.{ basic.program, basic.tables }) |partition| for (partition) |*component| {
                    handles[at] = if (proving) component.asProverComponent() else component.asVerifierComponent();
                    at += 1;
                };
                if (at != total or basic.memory.len != 0) return error.InvalidCallerRamProjectionRoster;
            }
            errdefer if (self.basic) |basic| {
                basic.deinit();
                a.destroy(basic);
            };
            self.context = try CC.Owner(proving).create(a, self.arithmetic.active(), handles, .{ self.schedule.fixed, self.schedule.main, &.{}, self.arithmetic_logs, self.ram_logs }, if (basic_claims != null) self.ram_handles.len else 0);
            return self;
        }
        pub fn deinit(self: *Self) void {
            const a = self.a;
            self.context.destroy();
            if (self.basic) |basic| {
                basic.deinit();
                a.destroy(basic);
            }
            a.free(self.ram_handles);
            a.free(self.ram);
            self.arithmetic.destroy(a);
            a.free(self.arithmetic_logs);
            a.free(self.state_offsets);
            a.free(self.ram_logs);
            self.schedule.deinit();
            a.destroy(self);
        }
    };
}
pub const Interactions = struct {
    a: std.mem.Allocator,
    sums: []Q,
    columns: []Column,
    pub fn generate(a: std.mem.Allocator, plan: *const Projection.Plan, fixed: []const Column, main: []const Column, drawn: *const E.Drawn) !Interactions {
        const relation = try Projection.nativeRelation(&drawn.word.universal_prefix);
        const sums = try a.alloc(Q, plan.descriptors.len);
        errdefer a.free(sums);
        const columns = try a.alloc(Column, try std.math.mul(usize, sums.len, 4));
        errdefer a.free(columns);
        var ready: usize = 0;
        errdefer for (columns[0..ready]) |column| a.free(column.values);
        for (plan.descriptors, sums, 0..) |descriptor, *sum, index| {
            try descriptor.validate(fixed, main);
            const Context = struct {
                const Self = @This();
                descriptor: Projection.Descriptor,
                relation: @TypeOf(relation),
                fixed: []const Column,
                main: []const Column,
                pub fn fill(self: @This(), physical: usize, fractions: []engine.air.logup_columns.Fraction) !void {
                    const Samples = struct {
                        owner: Self,
                        physical: usize,
                        pub fn at(self_: @This(), tree: usize, column: usize, ordinal: usize) !Q {
                            const source = if (tree == 0) self_.owner.fixed else if (tree == 1) self_.owner.main else return error.InvalidCallerRamTree;
                            if (column >= source.len) return error.InvalidCallerRamColumn;
                            const row = if (ordinal == 0) self_.physical else if (ordinal == 1 and tree == 1 and self_.owner.descriptor.kind == .keccak)
                                core.utils.offsetBitReversedCircleDomainIndex(self_.physical, self_.owner.descriptor.log_size, self_.owner.descriptor.log_size, 27)
                            else
                                return error.InvalidCallerRamOrdinal;
                            if (row >= source[column].values.len) return error.InvalidCallerRamColumn;
                            return Q.fromBase(source[column].values[row]);
                        }
                    };
                    const point = try Ram.fromSamples(self.descriptor, self.relation, Samples{ .owner = self, .physical = physical });
                    for (point.pair_constraints) |value| if (!value.isZero()) return error.InvalidCallerRamPair;
                    const term = point.term;
                    if (term.left.isZero() or term.right.isZero()) return error.DivisionByZero;
                    fractions[0] = .{ .numerator = term.wl.mul(term.right).add(term.wr.mul(term.left)), .denominator = term.left.mul(term.right) };
                }
            };
            const generated = try engine.air.logup_columns.build(a, descriptor.log_size, 1, Context{ .descriptor = descriptor, .relation = relation, .fixed = fixed, .main = main }, Context.fill);
            sum.* = generated.claimed_sum;
            @memcpy(columns[4 * index ..][0..4], generated.columns);
            a.free(generated.columns);
            ready += 4;
        }
        return .{ .a = a, .sums = sums, .columns = columns };
    }
    pub fn deinit(self: *Interactions) void {
        for (self.columns) |column| self.a.free(column.values);
        self.a.free(self.columns);
        self.a.free(self.sums);
        self.* = undefined;
    }
};
pub fn recordClaims(channel: anytype, layout: *const Layout, arithmetic: *const P.ExtensionClaim, ram: []const Q) !void {
    try arithmetic.validateCanonicalFields();
    channel.mixU32s(&.{ 0x42384341, 1, @intCast(ram.len) });
    layout.mix(channel);
    arithmetic.mixInto(channel);
    for (ram) |claim| {
        for (claim.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidCallerRamClaim;
        channel.mixFelts(&.{claim});
    }
}

/// Complete relation projection preparation, still sharing the original caller
/// fixed/main columns. The old generator is used only for its ROM/state/table
/// equation bodies: its local structural view has no memory sidecars, and no
/// old source seal, receipt, caller Pin or admission rule is invoked.
pub const CompleteInteractions = struct {
    a: std.mem.Allocator,
    basic: @import("block_v6_caller_joint_interaction_v1.zig").Generated,
    ram: Interactions,
    columns: []Column,
    pub fn generate(a: std.mem.Allocator, plan: *const Projection.Plan, statement: *const P.admission.Statement, steps: u32, frame: Frame, fixed: []const Column, main: []const Column, drawn: *const E.Drawn, relations: *const P.Relations) !CompleteInteractions {
        try plan.require(statement, steps, frame);
        var schedule = try Schedule.derive(a, statement, steps, frame);
        defer schedule.deinit();
        var no_memory = schedule;
        no_memory.memory = &.{};
        no_memory.rw_events = 0;
        const selected = @import("block_v5_committed_projection_columns_v1.zig").Columns{ .fixed = @constCast(fixed), .main = @constCast(main) };
        var basic = try @import("block_v6_caller_joint_interaction_v1.zig").generate(a, &selected, &no_memory, &[_]@import("block_v5_external_memory_sidecar_proof_v1.zig").Input{}, &[_]@import("block_execution_byte_range_v2.zig").SNAPSHOT{}, relations, &drawn.word);
        errdefer basic.deinit(a);
        var ram = try Interactions.generate(a, plan, fixed, main, drawn);
        errdefer ram.deinit();
        const columns = try std.mem.concat(a, Column, &.{ basic.columns, ram.columns });
        return .{ .a = a, .basic = basic, .ram = ram, .columns = columns };
    }
    pub fn deinit(self: *CompleteInteractions) void {
        self.a.free(self.columns);
        self.basic.deinit(self.a);
        self.ram.deinit();
        self.* = undefined;
    }
};
pub fn recordCompleteClaims(channel: anytype, layout: *const Layout, schedule: *const Schedule.Schedule, arithmetic: *const P.ExtensionClaim, basic: *const Fused.ClaimFrames, ram: []const Q) !void {
    channel.mixU32s(&.{ 0x42384341, 2, @intCast(schedule.projectionCount()), @intCast(ram.len) });
    layout.mix(channel);
    try arithmetic.validateCanonicalFields();
    arithmetic.mixInto(channel);
    var no_memory = schedule.*;
    no_memory.memory = &.{};
    no_memory.rw_events = 0;
    // This lower-level grammar validates every physical count/sum. It grants
    // no old protocol authority: the enclosing version/header above is B8.
    try Fused.mixClaimBodies(channel, &no_memory, basic.program_claims, basic.state_claims, basic.table_claims, basic.memory_claims);
    if (ram.len != schedule.memory.len) return error.InvalidCallerRamClaims;
    for (ram) |claim| {
        for (claim.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidCallerRamClaim;
        channel.mixFelts(&.{claim});
    }
}
pub const CompleteOpen = struct {
    program_sum: Q,
    fetch_count: u64,
    state_sum: Q,
    register_sum: Q,
    table_requests: [@import("../air/lookups/tables/schema.zig").KIND_COUNT]Q,
    ram_sum: Q,
    logical_ram_accesses: u64,
    internal_residual: Q,
};
/// Pure algebra, only AFTER the original/exact recursive caller verifier has
/// authenticated every arithmetic and projection claim in this same source.
/// These claims remain open to window state/register/ROM/table/endpoint closure.
pub fn closeComplete(schedule: *const Schedule.Schedule, arithmetic: *const P.ExtensionClaim, basic: *const Fused.ClaimFrames, ram: []const Q) !CompleteOpen {
    var checked = core.proof_suites.Blake3.Channel{};
    var no_memory = schedule.*;
    no_memory.memory = &.{};
    no_memory.rw_events = 0;
    try Fused.mixClaimBodies(&checked, &no_memory, basic.program_claims, basic.state_claims, basic.table_claims, basic.memory_claims);
    try arithmetic.validateCanonicalFields();
    if (ram.len != schedule.memory.len) return error.InvalidCallerRamClaims;
    var out = CompleteOpen{ .program_sum = Q.zero(), .fetch_count = 0, .state_sum = Q.zero(), .register_sum = Q.zero(), .table_requests = @splat(Q.zero()), .ram_sum = Q.zero(), .logical_ram_accesses = schedule.rw_events, .internal_residual = Q.zero() };
    for (basic.program_claims, basic.state_claims) |program, state| {
        out.program_sum = out.program_sum.add(program.sum);
        out.state_sum = out.state_sum.add(state.sum);
        out.fetch_count = try std.math.add(u64, out.fetch_count, program.fetch_count);
    }
    for (schedule.tables, basic.table_claims) |slot, claim| {
        if (slot.table == .register_memory) out.register_sum = out.register_sum.add(claim.sum) else out.table_requests[@intFromEnum(slot.table)] = out.table_requests[@intFromEnum(slot.table)].add(claim.sum);
    }
    for (ram) |claim| {
        for (claim.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidCallerRamClaim;
        out.ram_sum = out.ram_sum.add(claim);
    }
    out.internal_residual = arithmetic.componentSum().sub(out.program_sum).sub(out.state_sum).sub(out.register_sum).sub(out.ram_sum);
    for (out.table_requests) |claim| out.internal_residual = out.internal_residual.sub(claim);
    if (!out.internal_residual.isZero()) return error.UnclosedCallerRamArithmetic;
    return out;
}
