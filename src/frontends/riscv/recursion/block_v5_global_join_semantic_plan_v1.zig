//! Independently derived original semantic exports, never caller coordinates.
//! Supported equations use exact typed slot/partition order. Missing boundary,
//! window and source proofs are explicit obligations and block complete admission.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Raw = @import("air/block_v5_global_join_source_values_v1.zig");
const R = @import("air/composition_graph_recorder.zig");
const H = @import("block_v5_heterogeneous_policy_v1.zig");
const F = @import("block_v5_heterogeneous_child_frames_v1.zig");
const C = @import("../prover/block_v5_recursive_coverage_plan_v1.zig");
const Join = @import("../prover/block_v5_global_join_algebra_v1.zig");
const Schema = @import("../air/lookups/tables/schema.zig");
const Lookup = @import("../prover/block_v5_native_lookup_plan_v1.zig");
const Range = @import("../prover/block_execution_byte_range_v2.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const Role = enum { native_compensation, native_open, caller_open, program_request, native_state, caller_state, table_request, table_provider, auxiliary_clock, register_memory, register_clock_memory, transition_request, ordinary_memory_opposite, external_memory_opposite, byte_request, ram_transition, ram_link, ram_initial, ram_endpoint, ram_range, range_provider, program_provider };
pub const Export = struct { role: Role, owner: u32, slot: u32 = 0, coordinate: u32 = 0, field: Raw.Field };
pub const ObligationKind = enum { terminal_program_boundary, register_window_compensation, complete_source_proof, ram_initial_endpoint_sources, register_endpoint_sources, authenticated_request_census };
pub const Obligation = struct { kind: ObligationKind, index: u32, identity: [32]u8, count: u64 };
pub const Limits = struct { max_exports: usize = 65_536, max_children: usize = 1024, max_owned_bytes: usize = 256 << 20 };
pub const Derived = struct {
    budget: *Budget,
    arena: std.heap.ArenaAllocator,
    exports: []const Export,
    obligations: []const Obligation,
    groups: []const Lookup.Plan,
    execution_count: u32,
    coverage: [32]u8,
    child_seals: []const [32]u8,
    limits: Limits,
    seal: [32]u8,
    pub const complete_block_authority = false;
    pub fn deinit(self: *Derived) void {
        self.arena.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
    pub fn identity(self: *const Derived) [32]u8 {
        var c = core.channel.blake3.Channel{};
        c.mixU32s(&.{ 0x4235474d, 1, self.execution_count });
        c.mixRoot(sourceAuthority());
        c.mixRoot(self.coverage);
        c.mixU64(self.exports.len);
        c.mixU64(self.groups.len);
        c.mixU64(self.obligations.len);
        c.mixU64(self.child_seals.len);
        for (self.child_seals) |seal| c.mixRoot(seal);
        for (self.exports) |entry| {
            c.mixU32s(&.{ @intFromEnum(entry.role), entry.owner, entry.slot, entry.coordinate, entry.field.child, @intFromEnum(std.meta.activeTag(entry.field.form)) });
            switch (entry.field.form) {
                .felt => |field| c.mixU32s(&.{ field.frame, field.index }),
                .words => |limbs| for (limbs) |word| c.mixU32s(&.{ word.frame, word.word }),
            }
        }
        for (self.groups) |group| {
            c.mixU32s(&.{ group.index, group.first_execution, group.execution_count });
            for (group.max_requests) |count| c.mixU64(count);
        }
        for (self.obligations) |needed| {
            c.mixU32s(&.{ @intFromEnum(needed.kind), needed.index });
            c.mixRoot(needed.identity);
            c.mixU64(needed.count);
        }
        return c.digestBytes();
    }
    /// Genuine same-parent integration of the supported typed subset. The
    /// original rows own child captures; this adds no substitute receipt.
    pub fn attachOpen(self: *const Derived, rows: *@import("block_v5_heterogeneous_parent_preparation_v1.zig").Prepared, max_bytes: usize) !void {
        var recorded = try self.recordOpen(rows.allocator, rows.values.policy, max_bytes);
        defer recorded.deinit();
        try rows.attachGraph(.{ .circuit = &recorded.circuit, .inputs = recorded.inputs, .values = recorded.values, .sources = recorded.sources });
        for (&rows.recursive.context.graph_ids) |*digest| {
            var c = core.channel.blake3.Channel{};
            c.mixU32s(&.{ 0x4235474e, 1 });
            c.mixRoot(digest.*);
            c.mixRoot(self.identity());
            digest.* = c.digestBytes();
        }
    }
    pub fn validateIntegrity(self: *const Derived) !void {
        if (!std.meta.eql(self.seal, self.identity())) return error.MutatedGlobalJoinSemanticPlan;
    }
    pub fn requireComplete(self: *const Derived) !void {
        try self.validateIntegrity();
        if (self.obligations.len != 0) return error.MissingAuthenticatedGlobalJoinObligations;
        // This version has no source-proof receiver. Even an empty forged
        // obligation list cannot manufacture complete-block authority.
        return error.GlobalJoinCompleteAuthorityUnavailable;
    }
    pub fn validateAgainst(self: *const Derived, policy: H.Policy) !void {
        try self.validateIntegrity();
        // An unkeyed mutation seal is not mapping authority. Reconstruct all
        // selectors/roles/scopes from this exact independently admitted policy.
        // This also rejects a caller-created, correctly re-sealed arbitrary map.
        var independently = try derive(self.arena.child_allocator, policy, self.limits);
        defer independently.deinit();
        try self.requireDerived(&independently);
    }
    fn requireDerived(self: *const Derived, independently: *const Derived) !void {
        try self.validateIntegrity();
        try independently.validateIntegrity();
        if (!std.meta.eql(self.seal, independently.seal)) return error.UntrustedGlobalJoinSemanticPlan;
    }
    /// Records all presently supported state/group/transition joins. Public
    /// program/window/residual closure is deliberately NOT represented as zero.
    pub fn recordOpen(self: *const Derived, backing: std.mem.Allocator, policy: H.Policy, max_bytes: usize) !Raw.Prepared {
        try self.validateAgainst(policy);
        const a = self.arena.child_allocator;
        const fields = try a.alloc(Raw.Field, self.exports.len);
        defer a.free(fields);
        for (self.exports, fields) |entry, *field| field.* = entry.field;
        const views = try a.alloc(Raw.View, policy.children.len);
        defer a.free(views);
        for (policy.children, views) |child, *view| view.* = .{ .frames = child.frames, .cells = child.cells };
        return Raw.record(backing, views, fields, OpenEquations{ .derived = self }, max_bytes);
    }
};
const Build = struct {
    a: std.mem.Allocator,
    max_exports: usize,
    exports: std.ArrayList(Export) = .empty,
    obligations: std.ArrayList(Obligation) = .empty,
    groups: std.ArrayList(Lookup.Plan) = .empty,
    fn add(self: *Build, entry: Export) !void {
        if (self.exports.items.len == self.max_exports) return error.GlobalJoinResourceLimit;
        try self.exports.append(self.a, entry);
    }
    fn felt(self: *Build, child: *const F.Child, ordinal: u32, role: Role, frame: u32, field: u32, slot: u32, coordinate: u32) !void {
        const source = Raw.Field{ .child = ordinal, .form = .{ .felt = .{ .frame = frame, .index = field } } };
        _ = try Raw.read(&.{.{ .frames = child.frames, .cells = child.cells }}, .{ .child = 0, .form = source.form });
        try self.add(.{ .role = role, .owner = child.physical.index, .slot = slot, .coordinate = coordinate, .field = source });
    }
    fn words(self: *Build, child: *const F.Child, ordinal: u32, role: Role, selectors: [4]Raw.Word, slot: u32, coordinate: u32) !void {
        const source = Raw.Field{ .child = ordinal, .form = .{ .words = selectors } };
        _ = try Raw.read(&.{.{ .frames = child.frames, .cells = child.cells }}, .{ .child = 0, .form = source.form });
        try self.add(.{ .role = role, .owner = child.physical.index, .slot = slot, .coordinate = coordinate, .field = source });
    }
};
fn feltFrame(child: *const F.Child, ordinal: usize, expected_len: ?usize) !u32 {
    var at: usize = 0;
    for (child.frames, 0..) |frame, index| if (frame.operation == .felts) {
        if (at == ordinal) {
            if (expected_len) |len| if (frame.operation.felts.len != len) return error.UntrustedGlobalJoinTypedLayout;
            return @intCast(index);
        }
        at += 1;
    };
    return error.UntrustedGlobalJoinTypedLayout;
}
fn lastFeltFrame(child: *const F.Child) !u32 {
    var last: ?u32 = null;
    for (child.frames, 0..) |frame, index| if (frame.operation == .felts) {
        last = @intCast(index);
    };
    const at = last orelse return error.UntrustedGlobalJoinTypedLayout;
    if (child.frames[at].operation.felts.len != 1) return error.UntrustedGlobalJoinTypedLayout;
    return at;
}
pub fn derive(backing: std.mem.Allocator, policy: H.Policy, limits: Limits) !Derived {
    if (limits.max_exports == 0 or limits.max_exports > 65_536 or limits.max_children == 0 or limits.max_children > 1024 or policy.children.len == 0 or policy.children.len > limits.max_children or limits.max_owned_bytes == 0) return error.GlobalJoinResourceLimit;
    try policy.validate();
    const budget = try Budget.create(backing, limits.max_owned_bytes);
    errdefer budget.destroy();
    var arena = std.heap.ArenaAllocator.init(budget.allocator());
    errdefer arena.deinit();
    const a = arena.allocator();
    var build = Build{ .a = a, .max_exports = limits.max_exports };
    const seals = try a.alloc([32]u8, policy.children.len);
    const executions = std.math.cast(u32, policy.plan.meta.sources[@intFromEnum(C.SourceKind.native_catalog)].count) orelse return error.GlobalJoinResourceLimit;
    for (policy.children, policy.expected, 0..) |*child, expected, ordinal_usize| {
        const ordinal: u32 = @intCast(ordinal_usize);
        seals[ordinal] = child.seal;
        switch (expected) {
            .native_v3, .capacity_v1 => {
                const frame = try feltFrame(child, 1, 2);
                try build.felt(child, ordinal, .native_compensation, frame, 0, 0, 0);
                try build.felt(child, ordinal, .native_open, frame, 1, 0, 0);
                try build.obligations.append(a, .{ .kind = .terminal_program_boundary, .index = child.physical.index, .identity = child.public_input_digest, .count = 1 });
                try build.obligations.append(a, .{ .kind = .register_window_compensation, .index = child.physical.index, .identity = policy.plan.meta.sources[@intFromEnum(C.SourceKind.register_windows)].identity, .count = 1 });
            },
            .capacity_fused_v1 => |typed| try nativeFused(&build, child, ordinal, typed),
            .caller_family11_v1 => try build.felt(child, ordinal, .caller_open, try lastFeltFrame(child), 0, 0, 0),
            .caller_fused_v1 => |typed| try callerFused(&build, child, ordinal, typed),
            .rom_v1 => try build.felt(child, ordinal, .program_provider, try feltFrame(child, 1, 1), 0, 0, 0),
            .range16_v1 => try build.felt(child, ordinal, .range_provider, try feltFrame(child, 1, 1), 0, 0, 0),
            .six_table_lookup_v1 => |typed| {
                const frame = try feltFrame(child, 1, Schema.KIND_COUNT);
                for (0..Schema.KIND_COUNT) |kind| try build.felt(child, ordinal, .table_provider, frame, @intCast(kind), 0, @intCast(kind));
                try build.groups.append(a, typed.admitted.plan);
            },
            .ram_lanes_v1 => |typed| try ram(&build, child, ordinal, typed),
            .native_fused_v2 => return error.MissingGenuineNativeV3FusedAdapter,
        }
    }
    try Lookup.validateRoster(build.groups.items, executions);
    // These are typed requirements for genuine source verifiers, not hashes
    // upgraded to proof acceptance or obligations a caller can mark satisfied.
    for (policy.plan.meta.sources, 0..) |source, index| try build.obligations.append(a, .{ .kind = .complete_source_proof, .index = @intCast(index), .identity = source.identity, .count = source.count });
    inline for (.{ C.SourceKind.initial_image, C.SourceKind.final_image }) |kind| {
        const source = policy.plan.meta.sources[@intFromEnum(kind)];
        try build.obligations.append(a, .{ .kind = .ram_initial_endpoint_sources, .index = @intFromEnum(kind), .identity = source.identity, .count = source.count });
    }
    const windows = policy.plan.meta.sources[@intFromEnum(C.SourceKind.register_windows)];
    try build.obligations.append(a, .{ .kind = .register_endpoint_sources, .index = 0, .identity = windows.identity, .count = windows.count });
    const demand = policy.plan.meta.sources[@intFromEnum(C.SourceKind.lookup_demand_roster)];
    try build.obligations.append(a, .{ .kind = .authenticated_request_census, .index = 0, .identity = demand.identity, .count = demand.count });
    var result = Derived{ .budget = budget, .arena = arena, .exports = try build.exports.toOwnedSlice(a), .obligations = try build.obligations.toOwnedSlice(a), .groups = try build.groups.toOwnedSlice(a), .execution_count = executions, .coverage = policy.plan.pinned_digest, .child_seals = seals, .limits = limits, .seal = undefined };
    result.seal = result.identity();
    return result;
}
fn nativeFused(b: *Build, child: *const F.Child, ordinal: u32, typed: F.PolicyForSubtype(.capacity_fused_v1)) !void {
    const p = typed.admitted;
    const frame = try feltFrame(child, 1, p.projections.len + 2 * p.slots.len);
    for (p.projections, 0..) |slot, index| switch (slot.kind) {
        .program => try b.felt(child, ordinal, .program_request, frame, @intCast(index), @intCast(index), 0),
        .lookup => |projection| {
            const partition: usize = @intFromEnum(projection.partition);
            const role: Role = switch (projection.partition) {
                .registers_state => .native_state,
                .clock_memory_access => .auxiliary_clock,
                .register_memory_access => .register_memory,
                .register_clock_memory_access => .register_clock_memory,
                else => .table_request,
            };
            try b.felt(child, ordinal, role, frame, @intCast(index), @intCast(index), @intCast(if (partition < Schema.KIND_COUNT) partition else 0));
        },
    };
    const D = @import("block_v5_heterogeneous_leaf_definition_v1.zig").ForSubtype(.capacity_fused_v1);
    var values = try D.Bus.Values.init(b.a, p, .{ .projection = typed.proposal.projections, .memory = typed.proposal.memory });
    defer values.deinit();
    if (frame == 0) return error.UntrustedGlobalJoinTypedLayout;
    const words_frame = frame - 1;
    if (child.frames[words_frame].operation != .words or !std.mem.eql(u32, child.frames[words_frame].operation.words, values.statement.words)) return error.UntrustedGlobalJoinTypedLayout;
    var memory: usize = 0;
    for (values.statement.claims, 0..) |step, at| if (step == .felts and step.felts.len == 2) {
        if (memory >= p.slots.len or step.felts.first != p.projections.len + 2 * memory) return error.UntrustedGlobalJoinTypedLayout;
        const field = p.projections.len + 2 * memory;
        try b.felt(child, ordinal, .transition_request, frame, @intCast(field), @intCast(memory), 0);
        try b.felt(child, ordinal, .ordinary_memory_opposite, frame, @intCast(field + 1), @intCast(memory), 0);
        if (at + 1 + 4 * Range.BATCH_COUNT >= values.statement.claims.len) return error.UntrustedGlobalJoinTypedLayout;
        // Exact builder recipe: range header, then four single-word steps per
        // batch. Select ordinal offsets, never search for equal/zero values.
        const header = values.statement.claims[at + 1];
        if (header != .words or header.words.len != 5) return error.UntrustedGlobalJoinTypedLayout;
        for (0..Range.BATCH_COUNT) |batch| {
            var selectors: [4]Raw.Word = undefined;
            for (&selectors, 0..) |*selector, limb| {
                const item = values.statement.claims[at + 2 + batch * 4 + limb];
                if (item != .words or item.words.len != 1) return error.UntrustedGlobalJoinTypedLayout;
                selector.* = .{ .frame = words_frame, .word = item.words.first };
            }
            try b.words(child, ordinal, .byte_request, selectors, @intCast(memory), @intCast(batch));
        }
        memory += 1;
    };
    if (memory != p.slots.len) return error.UntrustedGlobalJoinTypedLayout;
}
fn callerFused(b: *Build, child: *const F.Child, ordinal: u32, typed: F.PolicyForSubtype(.caller_fused_v1)) !void {
    const schedule = &typed.admitted.schedule;
    const program = schedule.program.len;
    const tables = schedule.tables.len;
    const access = schedule.memory.len;
    const frame = try feltFrame(child, 1, 2 * program + tables + (2 + Range.BATCH_COUNT) * access);
    for (0..program) |slot| {
        try b.felt(child, ordinal, .program_request, frame, @intCast(slot), @intCast(slot), 0);
        try b.felt(child, ordinal, .caller_state, frame, @intCast(program + slot), @intCast(slot), 0);
    }
    for (schedule.tables, 0..) |slot, index| {
        const register = slot.table == .register_memory;
        try b.felt(child, ordinal, if (register) .register_memory else .table_request, frame, @intCast(2 * program + index), @intCast(index), if (register) 0 else @intFromEnum(slot.table));
    }
    for (0..access) |slot| {
        const first = 2 * program + tables + (2 + Range.BATCH_COUNT) * slot;
        try b.felt(child, ordinal, .transition_request, frame, @intCast(first), @intCast(slot), 0);
        try b.felt(child, ordinal, .external_memory_opposite, frame, @intCast(first + 1), @intCast(slot), 0);
        for (0..Range.BATCH_COUNT) |batch| try b.felt(child, ordinal, .byte_request, frame, @intCast(first + 2 + batch), @intCast(slot), @intCast(batch));
    }
}
const Counter = struct {
    frames: u32 = 0,
    pub fn mixU32s(self: *@This(), _: []const u32) void {
        self.frames += 1;
    }
    pub fn mixRoot(self: *@This(), _: [32]u8) void {
        self.frames += 1;
    }
    pub fn mixFelts(self: *@This(), _: []const Q) void {
        self.frames += 1;
    }
    pub fn mixU64(self: *@This(), _: u64) void {
        self.frames += 1;
    }
};
fn ram(b: *Build, child: *const F.Child, ordinal: u32, typed: F.PolicyForSubtype(.ram_lanes_v1)) !void {
    var cursor = Counter{};
    // Original reusable admission prefix: proof header, actual config mixes,
    // expected key root. Count actual config invocations rather than guessing.
    cursor.mixU32s(&.{});
    child.key.config.mixInto(&cursor);
    cursor.mixRoot(child.expected_id);
    cursor.mixU32s(&.{});
    cursor.mixRoot(typed.admitted.template_id);
    cursor.mixRoot(typed.admitted.sealed.digest);
    typed.admitted.pin.claim.mix(&cursor);
    for (typed.admitted.pin.roots) |root| cursor.mixRoot(root);
    cursor.mixRoot(typed.admitted.pin.counter_digest);
    cursor.mixU64(typed.admitted.pin.request_count);
    cursor.mixU32s(&.{typed.admitted.pin.index});
    typed.admitted.pin.config.mixInto(&cursor);
    cursor.mixU64(typed.proposal.sums.event_count);
    for (0..4 + typed.proposal.sums.range_sums.len) |sum| {
        const role: Role = switch (sum) {
            0 => .ram_transition,
            1 => .ram_link,
            2 => .ram_initial,
            3 => .ram_endpoint,
            else => .ram_range,
        };
        var selectors: [4]Raw.Word = undefined;
        for (&selectors, 0..) |*selector, limb| selector.* = .{ .frame = cursor.frames + @as(u32, @intCast(sum * 4 + limb)), .word = 0 };
        try b.words(child, ordinal, role, selectors, 0, @intCast(if (sum < 4) 0 else sum - 4));
    }
}
const Sink = struct {
    builder: *R.Builder,
    pub fn zero(self: *@This(), value: R.Scalar, _: anyerror) !void {
        if (self.builder.failure) |err| return err;
        try self.builder.constrainZero(value);
    }
};
fn selected(comptime S: type, exports: []const Export, claims: []const S, role: Role, owner: ?u32, coordinate: ?u32) S {
    var total = S.zero();
    for (exports, claims) |entry, claim| if (entry.role == role and (owner == null or entry.owner == owner.?) and (coordinate == null or entry.coordinate == coordinate.?)) {
        total = total.add(claim);
    };
    return total;
}
const OpenEquations = struct {
    derived: *const Derived,
    pub fn record(self: @This(), a: std.mem.Allocator, builder: *R.Builder, claims: []const R.Scalar) !void {
        const S = R.Scalar;
        const A = Join.Algebra(S);
        const d = self.derived;
        var sink = Sink{ .builder = builder };
        const states = try a.alloc(S, d.execution_count);
        defer a.free(states);
        for (states, 0..) |*state, index| state.* = selected(S, d.exports, claims, .native_compensation, @intCast(index), null).add(selected(S, d.exports, claims, .native_state, @intCast(index), null)).add(selected(S, d.exports, claims, .caller_state, @intCast(index), null));
        try A.states(&sink, states);
        const Part = struct { sum: S };
        for (d.groups) |group| {
            var supply: A.TableClaims = undefined;
            for (&supply, 0..) |*value, kind| value.* = selected(S, d.exports, claims, .table_provider, group.index, @intCast(kind));
            const requests = try a.alloc(A.TableClaims, group.execution_count);
            defer a.free(requests);
            const bytes = try a.alloc(Part, group.execution_count);
            defer a.free(bytes);
            for (requests, bytes, 0..) |*request, *part, local| {
                const index = group.first_execution + @as(u32, @intCast(local));
                for (request, 0..) |*value, kind| value.* = selected(S, d.exports, claims, .table_request, index, @intCast(kind));
                part.* = .{ .sum = selected(S, d.exports, claims, .byte_request, index, null) };
            }
            _ = try A.lookupGroup(&sink, supply, requests, bytes);
        }
        try A.transition(&sink, selected(S, d.exports, claims, .transition_request, null, null), selected(S, d.exports, claims, .ram_transition, null, null));
    }
};

/// Trusted source recipe identity, not a file claim or proof-verification seal.
pub fn sourceAuthority() [32]u8 {
    var channel = core.channel.blake3.Channel{};
    inline for (.{
        @embedFile("block_v5_global_join_semantic_plan_v1.zig"),
        @embedFile("air/block_v5_global_join_source_values_v1.zig"),
        @embedFile("../prover/block_v5_global_join_algebra_v1.zig"),
        @embedFile("block_v5_heterogeneous_child_frames_v1.zig"),
        @embedFile("block_v5_heterogeneous_policy_v1.zig"),
        @embedFile("block_v5_recursive_fused_public_bus_v1.zig"),
        @embedFile("air/block_v5_native_capacity_fused_statement_v1.zig"),
        @embedFile("air/block_v5_caller_fused_statement_v1.zig"),
        @embedFile("block_v5_ram_lanes_recursive_public_bus_v1.zig"),
        @embedFile("../prover/block_v5_ram_lanes_proof_v1.zig"),
        @embedFile("../prover/block_v5_native_lookup_plan_v1.zig"),
    }) |source| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(source, &digest, .{});
        channel.mixRoot(digest);
    }
    return channel.digestBytes();
}

/// Pure metadata/equation hooks. Literal fixtures passed here never become
/// admitted child captures or receive complete-block authority.
pub const testing = struct {
    pub const ordinalFeltFrame = feltFrame;
    pub const requireIndependentDerivation = Derived.requireDerived;
    pub fn recordSubset(backing: std.mem.Allocator, views: []const Raw.View, fields: []const Raw.Field, derived: *const Derived, max_bytes: usize) !Raw.Prepared {
        try derived.validateIntegrity();
        if (fields.len != derived.exports.len) return error.MutatedGlobalJoinSemanticPlan;
        for (fields, derived.exports) |field, entry| if (!std.meta.eql(field, entry.field)) return error.MutatedGlobalJoinSemanticPlan;
        return Raw.record(backing, views, fields, OpenEquations{ .derived = derived }, max_bytes);
    }
};
