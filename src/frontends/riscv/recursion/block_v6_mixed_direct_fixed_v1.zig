//! Independently compile the complete direct mixed verifier from original policy.
//! Claim records determine public framing only; no original proof/capture/MAIN,
//! proposed key, or self-authenticated circuit metadata enters this factory.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Bus = @import("block_v6_mixed_direct_public_v1.zig");
const Types = @import("block_v6_mixed_claim_types_v1.zig");
const Reconstruct = @import("block_v6_mixed_claim_reconstruct_v1.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Namespace = @import("air/block_v5_recursive_fixed_namespace_v1.zig");
const Rebase = @import("air/blake3_parent_rebase.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Protocol = @import("block_v6_mixed_direct_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Native = @import("block_v6_partitioned_fixed_roster_v1.zig");
const Providers = @import("block_v6_provider_fixed_singletons_v1.zig");
const Pages = @import("block_v6_page_auxiliary_fixed_v1.zig");
const Fused = @import("block_v6_caller_fused_auxiliary_fixed_v1.zig");
pub const Limits = struct {
    max_bytes: usize = 8 << 30,
    max_row_log: u32 = 25,
    native: Native.Limits = .{},
    word: @import("block_v5_word_recursive_fixed_roster_v1.zig").Limits = .{},
    provider: @import("block_v6_provider_fixed_roster_v1.zig").Limits = .{},
    page: @import("block_v5_memory_source_page_recursive_fixed_roster_v1.zig").Limits = .{},
    fused: @import("block_v6_caller_fused_fixed_roster_v1.zig").Limits = .{},
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
    contexts: [5]core.channel.blake3.Channel = @splat(.{}),
    next_namespace: u32 = 1,
    max_row_log: u32,
    fn init(a: std.mem.Allocator, expected: []const Bus.Expected, max_row_log: u32) !@This() {
        var result: @This() = .{ .a = a, .rows = undefined, .max_row_log = max_row_log };
        inline for (0..Storage.Airs.len) |i| result.rows[i] = .empty;
        for (&result.contexts, 0..) |*channel, i| channel.mixU32s(&.{ 0x42364d47, Bus.VERSION, @intCast(i), @intCast(expected.len) });
        result.contexts[0].mixRoot(try Bus.rosterDigest(expected));
        return result;
    }
    fn deinit(self: *@This()) void {
        inline for (0..Storage.Airs.len) |i| self.rows[i].deinit(self.a);
        self.wires.deinit(self.a);
    }
    fn append(self: *@This(), comptime kind: Bus.Kind, piece: anytype, ordinal: usize) !void {
        var outer = if (kind == .native) blk: {
            const ids = try self.a.dupe(u32, piece.namespace.original.old);
            break :blk Rebase.Plan{ .allocator = self.a, .first = self.next_namespace, .old = ids };
        } else try piece.outerNamespace(self.a, self.next_namespace);
        defer outer.deinit();
        const identity = try outer.identity();
        self.next_namespace = try outer.end();
        for (piece.wires) |wire| {
            if (kind != .native and wire.child != 0) return error.NonSingletonMixedFixedInput;
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
    profile: Base.Profile,
    pub const fixed_setup_only = true;
    pub const complete_family_setup = true;
    pub const whole_family_live_parity_qualified = false;
    pub const complete_block_authority = false;
    /// Canonical direct root emits one original verifier piece per roster child.
    /// Public reconstruction checks the entire source/claim/order binding before
    /// any key rows are derived; the eventual proof still enforces every claim.
    pub fn derive(backing: std.mem.Allocator, records: []const Types.Record, expected: []const Bus.Expected, inputs: []const Reconstruct.Input, capacity: u32, profile: Base.Profile, limits: Limits) !Owned {
        if (limits.max_bytes == 0 or limits.max_row_log == 0 or limits.max_row_log > 30 or capacity == 0 or inputs.len < 2 or inputs.len > Bus.MAX_CHILDREN) return error.InvalidMixedDirectLimits;
        const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        var public = try Reconstruct.reconstruct(a, records, expected, inputs);
        defer public.deinit();
        var builder = try Builder.init(a, expected, limits.max_row_log);
        defer builder.deinit();
        for (inputs, records, 0..) |input, record, ordinal| switch (input) {
            .native => |admitted| {
                var piece = try Native.Owned.derive(a, admitted, record.claim.native, capacity, profile, limits.native);
                defer piece.deinit();
                try builder.append(.native, &piece, ordinal);
            },
            inline .range16, .ram_lanes, .program_table, .native_lookup => |admitted, tag| {
                const family = @field(Bus.Provider.Family, @tagName(tag));
                var piece = try Providers.ForFamily(family).Owned.derive(a, admitted, admitted.template_id, {}, capacity, profile, if (tag == .range16 or tag == .ram_lanes) limits.word else limits.provider);
                defer piece.deinit();
                try builder.append(.provider, &piece, ordinal);
            },
            .caller_arithmetic => |admitted| {
                var piece = try Providers.CallerArithmetic.Owned.derive(a, admitted, admitted.template_id, {}, capacity, profile, limits.provider);
                defer piece.deinit();
                try builder.append(.auxiliary, &piece, ordinal);
            },
            .caller_fused => |admitted| {
                var piece = try Fused.Owned.derive(a, admitted, admitted.template_id, record.claim.caller_fused, capacity, profile, limits.fused);
                defer piece.deinit();
                try builder.append(.auxiliary, &piece, ordinal);
            },
            inline .source_raw, .source_fold => |admitted, tag| {
                const kind = if (tag == .source_raw) .raw else .fold;
                var piece = try Pages.ForKind(kind).Owned.derive(a, admitted, admitted.template_id, @field(record.claim, @tagName(tag)).semantic.claims, capacity, profile, limits.page);
                defer piece.deinit();
                try builder.append(.auxiliary, &piece, ordinal);
            },
        };
        var fixed: Storage.FixedTuple(false) = undefined;
        inline for (0..Storage.Airs.len) |i| fixed[i] = &.{};
        errdefer inline for (0..Storage.Airs.len) |i| a.free(fixed[i]);
        inline for (0..Storage.Airs.len) |i| fixed[i] = try builder.rows[i].toOwnedSlice(a);
        try partitionFixed(a, &fixed);
        std.mem.sort(Bus.Wire, builder.wires.items, {}, struct {
            fn less(_: void, l: Bus.Wire, r: Bus.Wire) bool {
                return l.circuit < r.circuit or (l.circuit == r.circuit and l.wire < r.wire);
            }
        }.less);
        _ = try Bus.scheduleDigest(builder.wires.items);
        const wires = try builder.wires.toOwnedSlice(a);
        errdefer a.free(wires);
        const pins = try a.dupe(Bus.Expected, expected);
        return .{ .allocator = a, .budget = budget, .fixed = fixed, .wires = wires, .expected = pins, .profile = profile, .context = .{ .child_key_id = builder.contexts[0].digestBytes(), .child_config = profile.config(), .graph_ids = .{ builder.contexts[1].digestBytes(), builder.contexts[2].digestBytes(), builder.contexts[3].digestBytes() }, .transcript_plan_id = builder.contexts[4].digestBytes() } };
    }
    pub fn validateLive(self: *const Owned, live: *@import("block_v6_mixed_direct_prepare_v1.zig").Prepared) !void {
        try live.recursive.rows.partitionHashRows();
        if (!std.meta.eql(self.context, live.recursive.context) or self.wires.len != live.wires.len or self.expected.len != live.expected.len) return error.UntrustedMixedFixedRoster;
        for (self.expected, live.expected) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedMixedFixedRoster;
        for (self.wires, live.wires) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedMixedFixedRoster;
        inline for (0..Storage.Airs.len) |i| {
            if (self.fixed[i].len != live.recursive.rows.fixed[i].len) return error.UntrustedMixedFixedRoster;
            for (self.fixed[i], live.recursive.rows.fixed[i]) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedMixedFixedRoster;
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
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub const KeyAndSchedule = struct {
            allocator: std.mem.Allocator,
            key: Protocol.Key,
            wires: []Bus.Wire,
            pub fn deinit(self: *@This()) void {
                self.allocator.free(self.wires);
                self.* = undefined;
            }
        };
        pub fn deriveKeyAndSchedule(a: std.mem.Allocator, records: []const Types.Record, expected: []const Bus.Expected, inputs: []const Reconstruct.Input, capacity: u32, profile: Base.Profile, limits: Limits) !KeyAndSchedule {
            var owned = try Owned.derive(a, records, expected, inputs, capacity, profile, limits);
            defer owned.deinit();
            const base = try Parent.ForBackend(Backend).deriveKeyFromFixed(a, owned.fixed, owned.context, profile);
            const key = try Protocol.Key.fromGeometry(base, owned.wires, expected);
            _ = try key.identity();
            return .{ .allocator = a, .key = key, .wires = try a.dupe(Bus.Wire, owned.wires) };
        }
    };
}
test "mixed complete independent fixed factory instantiates all original families" {
    std.mem.doNotOptimizeAway(&Owned.derive);
    std.mem.doNotOptimizeAway(&Owned.validateLive);
    std.mem.doNotOptimizeAway(&ForBackend(@import("stwo_cpu_backend").CpuBackend).deriveKeyAndSchedule);
}

/// Match the original final live partition exactly, including its deliberate
/// no-op when a child already populated any secondary G shard.
// Shared by independently compiled mixed-batch reduction setup.
pub fn partitionFixed(a: std.mem.Allocator, fixed: *Storage.FixedTuple(false)) !void {
    const Partition = @import("air/blake3_g_partition.zig");
    if (fixed.*[0].len <= 1 << 20) return;
    inline for (Partition.SHARDS[1..]) |slot| if (fixed.*[slot].len != 0) return;
    const geometry = try Partition.geometry(fixed.*[0].len);
    var replacement: [Partition.SHARDS.len][]Storage.FixedRow(Storage.Airs[0]) = @splat(&.{});
    errdefer for (replacement) |rows| a.free(rows);
    var offset: usize = 0;
    for (geometry.counts, 0..) |count, i| {
        replacement[i] = try a.dupe(Storage.FixedRow(Storage.Airs[0]), fixed.*[0][offset..][0..count]);
        offset += count;
    }
    inline for (Partition.SHARDS, 0..) |slot, i| {
        a.free(fixed.*[slot]);
        fixed.*[slot] = replacement[i];
    }
}
test "mixed fixed final G partition preserves boundary order and existing shards" {
    const a = std.testing.allocator;
    const Partition = @import("air/blake3_g_partition.zig");
    var fixed: Storage.FixedTuple(false) = undefined;
    inline for (0..Storage.Airs.len) |i| fixed[i] = &.{};
    defer inline for (0..Storage.Airs.len) |i| a.free(fixed[i]);
    const count = (1 << 20) + 3;
    fixed[0] = try a.alloc(Storage.FixedRow(Storage.Airs[0]), count);
    for (fixed[0], 0..) |*row, i| row.* = @splat(core.fields.m31.M31.fromCanonical(@intCast(i)));
    fixed[Partition.REMAINDER] = try a.alloc(Storage.FixedRow(Storage.Airs[0]), 1);
    fixed[Partition.REMAINDER][0] = @splat(core.fields.m31.M31.one());
    const before = fixed[0].ptr;
    try partitionFixed(a, &fixed);
    try std.testing.expectEqual(before, fixed[0].ptr);
    a.free(fixed[Partition.REMAINDER]);
    fixed[Partition.REMAINDER] = &.{};
    try partitionFixed(a, &fixed);
    const geometry = try Partition.geometry(count);
    var offset: usize = 0;
    inline for (Partition.SHARDS, 0..) |slot, i| {
        try std.testing.expectEqual(geometry.counts[i], fixed[slot].len);
        for (fixed[slot], 0..) |row, n| try std.testing.expectEqual(@as(u32, @intCast(offset + n)), row[0].toU32());
        offset += fixed[slot].len;
    }
    try std.testing.expectEqual(count, offset);
    const after = fixed[0].ptr;
    try partitionFixed(a, &fixed);
    try std.testing.expectEqual(after, fixed[0].ptr);
}
