//! Independent fixed verifier join for the complete finite v7 source roster.
//! Builds every family from original policy/claims; no captures or MAIN rows.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Bus = @import("block_v7_mixed_public_v1.zig");
const Inputs = @import("block_v7_mixed_inputs_v1.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Namespace = @import("air/block_v5_recursive_fixed_namespace_v1.zig");
const Rebase = @import("air/blake3_parent_rebase.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Prefix = @import("block_v7_shared_epoch_prefix_v1.zig");
const Bridge = @import("block_v7_shared_epoch_bridge_v1.zig");
const SharedTranscript = @import("air/block_v7_shared_epoch_transcript_v1.zig");
pub const Limits = struct {
    max_bytes: usize = 8 << 30,
    family_max_bytes: ?usize = null,
    max_row_log: u32 = 25,
    native_compilers: ?[]const ?*const @import("block_v7_native_compiler_capsule_v1.zig").Capsule = null,
    caller_compilers: ?[]const ?*const @import("block_v7_caller_joint_compiler_capsule_v1.zig").Capsule = null,
    active_caller_compilers: ?[]const ?*const @import("block_v7_caller_family_v1.zig").Active.Capsule.Capsule = null,
};
const Lists = blk: {
    var entries: [Storage.Airs.len]type = undefined;
    for (Storage.Airs, &entries) |Air, *T| T.* = std.ArrayList(Storage.FixedRow(Air));
    break :blk std.meta.Tuple(&entries);
};
const Builder = struct {
    a: std.mem.Allocator,
    rows: Lists,
    wires: std.ArrayList(Bus.Wire) = .empty,
    bridges: std.ArrayList(Bridge.Child) = .empty,
    contexts: [5]core.channel.blake3.Channel = @splat(.{}),
    next_namespace: u32 = 1,
    max_row_log: u32,
    fn init(a: std.mem.Allocator, expected: []const Bus.Expected, max_row_log: u32) !@This() {
        var result: @This() = .{ .a = a, .rows = undefined, .max_row_log = max_row_log };
        inline for (0..Storage.Airs.len) |i| result.rows[i] = .empty;
        for (&result.contexts, 0..) |*channel, i| channel.mixU32s(&.{ 0x42374d47, Bus.VERSION, @intCast(i), @intCast(expected.len) });
        result.contexts[0].mixRoot(try Bus.rosterDigest(expected));
        return result;
    }
    fn deinit(self: *@This()) void {
        inline for (0..Storage.Airs.len) |i| self.rows[i].deinit(self.a);
        self.wires.deinit(self.a);
        self.bridges.deinit(self.a);
    }
    fn append(self: *@This(), comptime kind: Bus.Kind, piece: anytype, ordinal: usize) !void {
        const ids = try self.a.dupe(u32, piece.namespace.original.old);
        var outer = Rebase.Plan{ .allocator = self.a, .first = self.next_namespace, .old = ids };
        defer outer.deinit();
        const identity = try outer.identity();
        self.next_namespace = try outer.end();
        const ports = piece.shared_epoch orelse return error.MissingSharedEpochChild;
        if (ports.source.circuit != SharedTranscript.STATE_CIRCUIT or ports.source.first_wire != 0) return error.InvalidSharedEpochChild;
        try self.bridges.append(self.a, .{ .state = outer.map(SharedTranscript.STATE_CIRCUIT) orelse return error.InvalidSharedEpochChild, .challenges = outer.map(SharedTranscript.CHALLENGE_CIRCUIT) orelse return error.InvalidSharedEpochChild, .uses = ports.uses });
        for (piece.wires) |wire| {
            try self.wires.append(self.a, .{ .circuit = outer.map(wire.circuit) orelse return error.MissingMixedDirectNamespace, .wire = wire.wire, .uses = wire.uses, .child = @intCast(ordinal), .source = @unionInit(Bus.Source, @tagName(kind), wire.source), .coordinate = wire.coordinate });
        }
        const plan = Namespace.Plan{ .original = outer, .main_identifier_rows = 0, .lease = null };
        try Namespace.apply(&piece.fixed, &plan, identity);
        inline for (0..Storage.Airs.len) |i| {
            const count = try std.math.add(usize, self.rows[i].items.len, piece.fixed[i].len);
            if (count > @as(usize, 1) << @intCast(self.max_row_log)) return error.MixedDirectResourceLimit;
            try self.rows[i].appendSlice(self.a, piece.fixed[i]);
        }
        self.contexts[0].mixRoot(piece.context.child_key_id);
        for (self.contexts[1..4], piece.context.graph_ids) |*channel, digest| {
            channel.mixRoot(digest);
            channel.mixRoot(identity);
        }
        self.contexts[4].mixRoot(piece.context.transcript_plan_id);
        self.contexts[4].mixRoot(identity);
    }
};
pub const Owned = struct {
    allocator: std.mem.Allocator,
    budget: *Budget,
    fixed: Storage.FixedTuple(false),
    wires: []Bus.Wire,
    expected: []Bus.Expected,
    context: Base.Context,
    pub const fixed_setup_only = true;
    pub const complete_family_setup = true;
    pub const whole_family_live_parity_qualified = false;
    pub const complete_block_authority = false;
    /// Canonical direct root emits one original verifier piece per roster child.
    /// Public reconstruction checks the entire source/claim/order binding before
    /// any key rows are derived; the eventual proof still enforces every claim.
    pub fn derive(backing: std.mem.Allocator, input: Inputs.Input, capacity: u32, limits: Limits) !Owned {
        const total = try input.count();
        return deriveWindow(backing, input, 0, total, Bus.MAX_CHILDREN, capacity, limits);
    }
    /// Independently compile one OPEN contiguous batch from a fully admitted
    /// job. The explicit whole limit does not enlarge the direct proof fan-in.
    pub fn deriveWindow(backing: std.mem.Allocator, input: Inputs.Input, first: usize, count: usize, max_entries: usize, capacity: u32, limits: Limits) !Owned {
        if (limits.max_bytes == 0 or limits.max_row_log == 0 or limits.max_row_log > 30 or capacity == 0) return error.InvalidMixedDirectLimits;
        if (limits.native_compilers) |capsules| if (capsules.len != input.natives.len) return error.NativeCompilerCountMismatch;
        if (limits.caller_compilers) |capsules| if (capsules.len != input.callers.len) return error.CallerCompilerCountMismatch;
        if (limits.active_caller_compilers) |capsules| if (capsules.len != input.active_callers.len) return error.CallerCompilerCountMismatch;
        const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        var public = try Inputs.Owned.initWhole(a, input, max_entries);
        defer public.deinit();
        _ = try public.window(first, count);
        const selected = public.expected[first..][0..count];
        if (first != 0 or count != public.children.len or count < 2 or selected[0].kind != .native) return error.InvalidSharedEpochRoster;
        var builder = try Builder.init(a, selected, limits.max_row_log);
        defer builder.deinit();
        for (selected, 0..) |pin, ordinal| switch (pin.kind) {
            .native => {
                const native = input.natives[pin.index];
                const Module = @import("block_v7_native_fixed_roster_v1.zig");
                const capsule = if (limits.native_compilers) |capsules| capsules[pin.index] else null;
                if (capsule) |compiled| try compiled.requireProfile(native.profile);
                const child_limits = try familyLimits(Module.Limits, limits);
                var piece = if (capsule) |compiled| try Module.Owned.deriveFromCapsule(a, compiled, native.claims, capacity, child_limits) else try Module.Owned.derive(a, native.profile, native.claims, capacity, child_limits);
                defer piece.deinit();
                try builder.append(.native, &piece, ordinal);
            },
            .caller_active => {
                const FactoryModule = @import("block_v7_caller_family_v1.zig").Active.FixedRoster;
                const Factory = FactoryModule.Owned;
                const child_limits = try familyLimits(FactoryModule.Limits, limits);
                const capsule = if (limits.active_caller_compilers) |capsules| capsules[pin.index] else null;
                if (capsule) |compiled| try compiled.requireProfile(a, input.active_callers[pin.index]);
                var piece = if (capsule) |compiled| try Factory.deriveFromCapsule(a, compiled, capacity, child_limits) else try Factory.derive(a, input.active_callers[pin.index].input(), capacity, child_limits);
                defer piece.deinit();
                try builder.append(.caller_active, &piece, ordinal);
            },
            .caller => {
                const FactoryModule = @import("block_v7_caller_joint_fixed_roster_v1.zig");
                const Factory = FactoryModule.Owned;
                const child_limits = try familyLimits(FactoryModule.Limits, limits);
                const capsule = if (limits.caller_compilers) |capsules| capsules[pin.index] else null;
                if (capsule) |compiled| try compiled.requireProfile(a, input.callers[pin.index]);
                var piece = if (capsule) |compiled| try Factory.deriveFromCapsule(a, compiled, capacity, child_limits) else try Factory.derive(a, input.callers[pin.index].input(), capacity, child_limits);
                defer piece.deinit();
                try builder.append(.caller, &piece, ordinal);
            },
            inline .program, .lookup => |kind| {
                const Module = switch (kind) {
                    .program => @import("block_v7_program_fixed_roster_v1.zig"),
                    .lookup => @import("block_v7_lookup_compact_fixed_roster_v1.zig"),
                    else => unreachable,
                };
                var piece = try Module.Owned.derive(a, @field(input, @tagName(kind)).input, capacity, try familyLimits(Module.Limits, limits));
                defer piece.deinit();
                try builder.append(kind, &piece, ordinal);
            },
            .memory => {
                var piece = try @import("block_v7_memory_joint_fixed_roster_v1.zig").Owned.derive(a, (input.memory orelse return error.InvalidV7CompleteMixedRoster).input, capacity, try familyLimits(@import("block_v7_memory_joint_fixed_roster_v1.zig").Limits, limits));
                defer piece.deinit();
                try builder.append(.memory, &piece, ordinal);
            },
            .window_memory => {
                const Module = @import("block_v7_window_memory_family_v1.zig").FixedRoster;
                var piece = try Module.Owned.derive(a, (input.window_memory orelse return error.InvalidV7CompleteMixedRoster).input, capacity, try familyLimits(Module.Limits, limits));
                defer piece.deinit();
                try builder.append(.window_memory, &piece, ordinal);
            },
            inline .ram, .interval, .range16, .terminal => |kind| {
                const Module = @import("block_v7_memory_component_recursive_v1.zig").For(@field(@import("air/block_v7_memory_composition_v1.zig").Family, @tagName(kind))).FixedRoster;
                const memory = input.separate_memory orelse return error.InvalidV7CompleteMixedRoster;
                const profile = if (kind == .ram) memory.ram[pin.index] else @field(memory, @tagName(kind));
                var piece = try Module.Owned.derive(a, profile.input, capacity, try familyLimits(Module.Limits, limits));
                defer piece.deinit();
                try builder.append(kind, &piece, ordinal);
            },
        };
        var prefix = try Prefix.Owned.create(a, input.epoch, capacity, selected.len);
        defer prefix.deinit();
        var prefix_namespace = try Namespace.prepare(a, prefix.fixed, builder.next_namespace);
        defer prefix_namespace.deinit();
        try prefix_namespace.requireIndependentMainPort();
        const prefix_identity = try prefix_namespace.identity();
        try Namespace.apply(&prefix.fixed, &prefix_namespace, prefix_identity);
        var bridge = try Bridge.Owned.create(a, &prefix, &prefix_namespace.original, builder.bridges.items, false);
        defer bridge.deinit();
        inline for (0..Storage.Airs.len) |slot| try builder.rows[slot].appendSlice(a, prefix.fixed[slot]);
        for (bridge.words) |row| try builder.rows[7].append(a, Storage.compactFixed(Storage.Airs[7], row));
        for (bridge.scalars) |row| try builder.rows[12].append(a, Storage.compactFixed(Storage.Airs[12], row));
        inline for (0..Storage.Airs.len) |slot| if (builder.rows[slot].items.len > @as(usize, 1) << @intCast(limits.max_row_log)) return error.MixedDirectResourceLimit;
        if (prefix.plan.fixed.root_reads.len != 1) return error.InvalidSharedEpochPublicPorts;
        const epoch_read = prefix.plan.fixed.root_reads[0];
        const epoch_offset = public.children[0].value.native.statement.sealed_offset;
        for (epoch_read.uses, 0..) |uses, i| try builder.wires.append(a, .{ .circuit = prefix_namespace.original.map(epoch_read.source.circuit) orelse return error.InvalidSharedEpochPublicPorts, .wire = epoch_read.source.first_wire + @as(u32, @intCast(i)), .uses = uses, .child = 0, .source = .{ .native = .word }, .coordinate = epoch_offset + @as(u32, @intCast(i)) });
        var fixed: Storage.FixedTuple(false) = undefined;
        inline for (0..Storage.Airs.len) |i| fixed[i] = &.{};
        errdefer inline for (0..Storage.Airs.len) |i| a.free(fixed[i]);
        inline for (0..Storage.Airs.len) |i| fixed[i] = try builder.rows[i].toOwnedSlice(a);
        try @import("block_v6_mixed_direct_fixed_v1.zig").partitionFixed(a, &fixed);
        std.mem.sort(Bus.Wire, builder.wires.items, {}, struct {
            fn less(_: void, l: Bus.Wire, r: Bus.Wire) bool {
                return l.circuit < r.circuit or (l.circuit == r.circuit and l.wire < r.wire);
            }
        }.less);
        _ = try Bus.scheduleDigest(builder.wires.items);
        const wires = try builder.wires.toOwnedSlice(a);
        errdefer a.free(wires);
        const pins = try a.dupe(Bus.Expected, selected);
        return .{ .allocator = a, .budget = budget, .fixed = fixed, .wires = wires, .expected = pins, .context = @import("block_v7_shared_epoch_context_v1.zig").finish(builder.contexts, input.epoch.config, prefix.plan.id, prefix_identity, bridge.identity) };
    }
    pub fn validateLive(self: *const Owned, live: *@import("block_v7_shared_epoch_mixed_preparation_v1.zig").Prepared) !void {
        try live.recursive.rows.partitionHashRows();
        if (!std.meta.eql(self.context, live.recursive.context)) return error.MixedFixedContextMismatch;
        if (self.wires.len != live.wires.len) return error.MixedFixedWireCountMismatch;
        if (self.expected.len != live.expected.len) return error.MixedFixedRosterCountMismatch;
        for (self.expected, live.expected) |got, want| if (!std.meta.eql(got, want)) return error.MixedFixedRosterMismatch;
        for (self.wires, live.wires) |got, want| if (!std.meta.eql(got, want)) return error.MixedFixedWireMismatch;
        inline for (0..Storage.Airs.len) |i| {
            if (self.fixed[i].len != live.recursive.rows.fixed[i].len) {
                std.log.warn("v7 mixed fixed component {d}: cold rows {d}, live rows {d}", .{ i, self.fixed[i].len, live.recursive.rows.fixed[i].len });
                return error.MixedFixedRowCountMismatch;
            }
            for (self.fixed[i], live.recursive.rows.fixed[i], 0..) |got, want, row| if (!std.meta.eql(got, want)) {
                std.log.warn("v7 mixed fixed component {d}: row {d} differs", .{ i, row });
                return error.MixedFixedRowMismatch;
            };
        }
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        const budget = self.budget;
        inline for (0..Storage.Airs.len) |i| a.free(self.fixed[i]);
        a.free(self.wires);
        a.free(self.expected);
        self.* = undefined;
        budget.destroy();
    }
};

fn familyLimits(comptime T: type, parent: Limits) !T {
    var child = try @import("block_v7_family_resource_limits_v1.zig").forSetup(T, parent.max_bytes, parent.family_max_bytes);
    child.shared_epoch = true;
    return child;
}
