//! Opt-in mixed parent: one epoch transcript, exact cross-child wire bridges.
//! Inputs remain owned by their callers and MUST be deinitialized after this
//! call, including on error. Their rows may have been rebased or drained.
//! Returned rows, public values and wires are independently owned.
const std = @import("std");
const core = @import("stwo_core");
const Bus = @import("block_v7_mixed_public_v1.zig");
const Parent = @import("blake3_execution_parent_preparation.zig");
const Rebase = @import("air/blake3_parent_rebase.zig");
const Join = @import("air/blake3_parent_join.zig");
const E = @import("../prover/block_v7_execution_epoch_v1.zig");
const Prefix = @import("block_v7_shared_epoch_prefix_v1.zig");
const Bridge = @import("block_v7_shared_epoch_bridge_v1.zig");
const SharedTranscript = @import("air/block_v7_shared_epoch_transcript_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub fn PreparedFor(comptime kind: Bus.Kind) type {
    return switch (kind) {
        .native => @import("block_v7_native_preparation_v1.zig").Prepared,
        .caller_active => @import("block_v7_caller_family_v1.zig").Active.Preparation.Prepared,
        .caller => @import("block_v7_caller_joint_preparation_v1.zig").Prepared,
        .program => @import("block_v7_program_preparation_v1.zig").Prepared,
        .lookup => @import("block_v7_lookup_compact_preparation_v1.zig").Prepared,
        .memory => @import("block_v7_memory_joint_preparation_v1.zig").Prepared,
        .window_memory => @import("block_v7_window_memory_family_v1.zig").Preparation.Prepared,
        inline .ram, .interval, .range16, .terminal => |family| @import("block_v7_memory_component_recursive_v1.zig").For(@field(@import("air/block_v7_memory_composition_v1.zig").Family, @tagName(family))).Preparation.Prepared,
    };
}
pub const Input = union(Bus.Kind) {
    native: struct { index: u32, prepared: *PreparedFor(.native) },
    caller_active: struct { index: u32, prepared: *PreparedFor(.caller_active) },
    caller: struct { index: u32, prepared: *PreparedFor(.caller) },
    program: struct { index: u32, prepared: *PreparedFor(.program) },
    lookup: struct { index: u32, prepared: *PreparedFor(.lookup) },
    ram: struct { index: u32, prepared: *PreparedFor(.ram) },
    interval: struct { index: u32, prepared: *PreparedFor(.interval) },
    range16: struct { index: u32, prepared: *PreparedFor(.range16) },
    terminal: struct { index: u32, prepared: *PreparedFor(.terminal) },
    memory: struct { index: u32, prepared: *PreparedFor(.memory) },
    window_memory: struct { index: u32, prepared: *PreparedFor(.window_memory) },
    fn recursive(self: Input) *Parent.Prepared {
        return switch (self) {
            inline else => |v| &v.prepared.recursive,
        };
    }
    fn child(self: Input) Bus.Child {
        return switch (self) {
            inline else => |v, kind| .{ .index = v.index, .value = @unionInit(Bus.Value, @tagName(kind), v.prepared.values) },
        };
    }
};
pub const Prepared = struct {
    budget: *Budget,
    allocator: std.mem.Allocator,
    recursive: Parent.Prepared,
    wires: []Bus.Wire,
    children: []Bus.Child,
    expected: []Bus.Expected,
    pub fn values(self: *const Prepared) Bus.Values {
        return .{ .children = self.children };
    }
    pub fn deinit(self: *Prepared) void {
        const budget = self.budget;
        self.recursive.deinit();
        for (self.children) |*child| child.deinit();
        self.allocator.free(self.children);
        self.allocator.free(self.wires);
        self.allocator.free(self.expected);
        self.* = undefined;
        budget.destroy();
    }
};
pub const Limits = struct { max_row_log: u32 = 25, max_join_bytes: usize = 8 << 30 };
pub fn prepareDraining(a: std.mem.Allocator, inputs: []const Input, expected: []const Bus.Expected, epoch: E.Epoch, capacity: u32) !Prepared {
    return prepareDrainingWithLimits(a, inputs, expected, epoch, capacity, .{});
}
pub fn prepareDrainingWithLimits(backing: std.mem.Allocator, inputs: []const Input, expected: []const Bus.Expected, epoch: E.Epoch, capacity: u32, limits: Limits) !Prepared {
    if (limits.max_row_log == 0 or limits.max_row_log > 25 or limits.max_join_bytes == 0) return error.InvalidMixedDirectLimits;
    const budget = try Budget.createRetainingParent(backing, limits.max_join_bytes);
    errdefer budget.destroy();
    const a = budget.allocator();
    if (inputs.len < 2 or inputs.len > Bus.MAX_CHILDREN) return error.InvalidMixedDirectCount;
    _ = try Bus.rosterDigest(expected);
    if (capacity == 0 or expected.len != inputs.len or expected[0].kind != .native) return error.InvalidSharedEpochRoster;
    for (expected) |pin| if (!std.meta.eql(pin.epoch, epoch.digest)) return error.UntrustedSharedEpoch;
    if (!std.meta.eql(epoch.config, inputs[0].recursive().context.child_config)) return error.UntrustedSharedEpoch;
    var prefix = try Prefix.Owned.create(a, epoch, capacity, inputs.len);
    defer prefix.deinit();
    var count: usize = 0;
    for (inputs, 0..) |input, i| {
        count = try std.math.add(usize, count, 1);
        if (count > Bus.MAX_CHILDREN) return error.InvalidMixedDirectCount;
        if (!std.meta.eql(input.recursive().context.child_config, inputs[0].recursive().context.child_config)) return error.MixedDirectSecurityMismatch;
        for (inputs[0..i]) |previous| if (previous.recursive() == input.recursive()) return error.AliasedMixedDirectInput;
    }
    if (count != expected.len) return error.UntrustedMixedDirectRoster;
    const storage = @import("air/blake3_parent_row_storage.zig");
    var row_counts: [storage.Airs.len]usize = @splat(0);
    var retained: usize = 0;
    for (inputs) |input| {
        // The independent family compiler partitions its G cohort before the
        // mixed join. Canonicalize at that same boundary: splitting the total
        // after concatenation is a different physical key when one child is
        // already above the partition threshold. No constraints are omitted.
        try input.recursive().rows.partitionHashRows();
        retained = try std.math.add(usize, retained, try input.recursive().rows.retainedBytes());
        inline for (0..storage.Airs.len) |i| {
            row_counts[i] = try std.math.add(usize, row_counts[i], input.recursive().rows.fixed[i].len);
            if (row_counts[i] > @as(usize, 1) << @intCast(limits.max_row_log)) return error.MixedDirectResourceLimit;
        }
    }
    // Bound destination allocation before cloning or rebasing inputs. Child
    // partitioning above is destructive; callers must deinit on every path.
    if (try std.math.mul(usize, retained, 2) > limits.max_join_bytes) return error.MixedDirectResourceLimit;
    const children = try a.alloc(Bus.Child, count);
    var initialized: usize = 0;
    errdefer {
        for (children[0..initialized]) |*child| child.deinit();
        a.free(children);
    }
    for (inputs) |input| {
        children[initialized] = try input.child().clone(a);
        initialized += 1;
    }
    try (Bus.Values{ .children = children }).requireRoster(expected);
    const pins = try a.dupe(Bus.Expected, expected);
    errdefer a.free(pins);
    var wires: std.ArrayList(Bus.Wire) = .empty;
    errdefer wires.deinit(a);
    var row_owners: [Bus.MAX_CHILDREN + 1]*storage.Prepared = undefined;
    var ranges: [Bus.MAX_CHILDREN + 1]Join.Range = undefined;
    var bridges: [Bus.MAX_CHILDREN]Bridge.Child = undefined;
    var next_namespace: u32 = 1;
    var child_first: usize = 0;
    var contexts: [5]core.channel.blake3.Channel = @splat(.{});
    for (&contexts, 0..) |*channel, i| channel.mixU32s(&.{ 0x42374d47, Bus.VERSION, @intCast(i), @intCast(count) });
    contexts[0].mixRoot(try Bus.rosterDigest(expected));
    for (inputs, 0..) |input, ordinal| {
        const piece = input.recursive();
        var namespace = try Rebase.prepare(a, &piece.rows, next_namespace);
        defer namespace.deinit();
        next_namespace = try namespace.end();
        const identity = try namespace.identity();
        const ports = switch (input) {
            inline else => |v| v.prepared.shared_epoch orelse return error.MissingSharedEpochChild,
        };
        if (ports.source.circuit != SharedTranscript.STATE_CIRCUIT or ports.source.first_wire != 0) return error.InvalidSharedEpochChild;
        bridges[ordinal] = .{ .state = namespace.map(SharedTranscript.STATE_CIRCUIT) orelse return error.InvalidSharedEpochChild, .challenges = namespace.map(SharedTranscript.CHALLENGE_CIRCUIT) orelse return error.InvalidSharedEpochChild, .uses = ports.uses };
        switch (input) {
            inline else => |v, kind| for (v.prepared.wires) |wire| try wires.append(a, .{ .circuit = namespace.map(wire.circuit) orelse return error.MissingMixedDirectNamespace, .wire = wire.wire, .uses = wire.uses, .child = @intCast(child_first), .source = @unionInit(Bus.Source, @tagName(kind), wire.source), .coordinate = wire.coordinate }),
        }
        try Rebase.apply(&piece.rows, &namespace, identity);
        row_owners[ordinal] = &piece.rows;
        ranges[ordinal] = .{ .first = namespace.first, .end = next_namespace };
        contexts[0].mixRoot(piece.context.child_key_id);
        for (contexts[1..4], piece.context.graph_ids) |*channel, digest| {
            channel.mixRoot(digest);
            channel.mixRoot(identity);
        }
        contexts[4].mixRoot(piece.context.transcript_plan_id);
        contexts[4].mixRoot(identity);
        child_first += 1;
    }
    var prefix_rows = try prefix.emit();
    defer prefix_rows.deinit();
    var prefix_namespace = try Rebase.prepare(a, &prefix_rows, next_namespace);
    defer prefix_namespace.deinit();
    const prefix_identity = try prefix_namespace.identity();
    try Rebase.apply(&prefix_rows, &prefix_namespace, prefix_identity);
    row_owners[inputs.len] = &prefix_rows;
    ranges[inputs.len] = .{ .first = next_namespace, .end = try prefix_namespace.end() };
    var bridge = try Bridge.Owned.create(a, &prefix, &prefix_namespace, bridges[0..inputs.len], true);
    defer bridge.deinit();
    var bridge_rows = try bridge.emit();
    defer bridge_rows.deinit();
    // Count the prefix and bridges as well as every child before allocating
    // the final output. The budget separately covers all new scratch owners.
    inline for (0..storage.Airs.len) |slot| {
        var total = bridge_rows.fixed[slot].len;
        for (row_owners[0 .. inputs.len + 1]) |owner| total = try std.math.add(usize, total, owner.fixed[slot].len);
        if (total > @as(usize, 1) << @intCast(limits.max_row_log)) return error.MixedDirectResourceLimit;
    }
    if (prefix.plan.fixed.root_reads.len != 1) return error.InvalidSharedEpochPublicPorts;
    const epoch_read = prefix.plan.fixed.root_reads[0];
    const epoch_offset = children[0].value.native.statement.sealed_offset;
    for (epoch_read.uses, 0..) |uses, i| try wires.append(a, .{ .circuit = prefix_namespace.map(epoch_read.source.circuit) orelse return error.InvalidSharedEpochPublicPorts, .wire = epoch_read.source.first_wire + @as(u32, @intCast(i)), .uses = uses, .child = 0, .source = .{ .native = .word }, .coordinate = epoch_offset + @as(u32, @intCast(i)) });
    var rows = Parent.Prepared{
        .rows = try @import("block_v7_shared_epoch_join_v1.zig").concatenate(a, row_owners[0 .. inputs.len + 1], ranges[0 .. inputs.len + 1], &bridge_rows),
        .context = @import("block_v7_shared_epoch_context_v1.zig").finish(contexts, epoch.config, prefix.plan.id, prefix_identity, bridge.identity),
    };
    errdefer rows.deinit();
    std.mem.sort(Bus.Wire, wires.items, {}, struct {
        fn less(_: void, l: Bus.Wire, r: Bus.Wire) bool {
            return l.circuit < r.circuit or (l.circuit == r.circuit and l.wire < r.wire);
        }
    }.less);
    _ = try Bus.scheduleDigest(wires.items);
    const owned_wires = try wires.toOwnedSlice(a);
    return .{ .budget = budget, .allocator = a, .recursive = rows, .children = children, .expected = pins, .wires = owned_wires };
}
