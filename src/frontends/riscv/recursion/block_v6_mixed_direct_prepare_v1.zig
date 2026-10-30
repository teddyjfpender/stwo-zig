//! Destructively join original verifier rows before their sole parent proof.
//! Inputs remain owned by their callers and MUST be deinitialized after this
//! call, including on error. Their rows may have been rebased or drained.
//! Returned rows, public values and wires are independently owned.
const std = @import("std");
const core = @import("stwo_core");
const Bus = @import("block_v6_mixed_direct_public_v1.zig");
const Parent = @import("blake3_execution_parent_preparation.zig");
const Provider = @import("block_v6_provider_batch_prepare_v1.zig");
const Auxiliary = @import("block_v6_auxiliary_direct_prepare_v1.zig");
const Rebase = @import("air/blake3_parent_rebase.zig");
const Join = @import("air/blake3_parent_join.zig");
pub const Input = union(Bus.Kind) {
    native: struct { index: u32, prepared: *Bus.Native.Prepared },
    provider: *Provider.Prepared,
    auxiliary: *Auxiliary.Prepared,
    fn recursive(self: Input) *Parent.Prepared {
        return switch (self) {
            .native => |v| &v.prepared.recursive,
            .provider => |v| &v.recursive,
            .auxiliary => |v| &v.recursive,
        };
    }
    fn count(self: Input) usize {
        return switch (self) {
            .native => 1,
            .provider => |v| v.children.len,
            .auxiliary => |v| v.children.len,
        };
    }
    fn child(self: Input, i: usize) Bus.Child {
        return switch (self) {
            .native => |v| .{ .native = .{ .index = v.index, .value = v.prepared.values } },
            .provider => |v| .{ .provider = v.children[i] },
            .auxiliary => |v| .{ .auxiliary = v.children[i] },
        };
    }
};
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    recursive: Parent.Prepared,
    wires: []Bus.Wire,
    children: []Bus.Child,
    expected: []Bus.Expected,
    pub fn values(self: *const Prepared) Bus.Values {
        return .{ .children = self.children };
    }
    pub fn deinit(self: *Prepared) void {
        self.recursive.deinit();
        for (self.children) |*child| child.deinit();
        self.allocator.free(self.children);
        self.allocator.free(self.wires);
        self.allocator.free(self.expected);
        self.* = undefined;
    }
};
pub const Limits = struct { max_row_log: u32 = 25, max_join_bytes: usize = 8 << 30 };
pub fn prepareDraining(a: std.mem.Allocator, inputs: []const Input, expected: []const Bus.Expected) !Prepared {
    return prepareDrainingWithLimits(a, inputs, expected, .{});
}
pub fn prepareDrainingWithLimits(a: std.mem.Allocator, inputs: []const Input, expected: []const Bus.Expected, limits: Limits) !Prepared {
    if (inputs.len < 2 or inputs.len > Bus.MAX_CHILDREN) return error.InvalidMixedDirectCount;
    _ = try Bus.rosterDigest(expected);
    if (limits.max_row_log == 0 or limits.max_row_log > 30 or limits.max_join_bytes == 0) return error.InvalidMixedDirectLimits;
    const storage = @import("air/blake3_parent_row_storage.zig");
    var row_counts: [storage.Airs.len]usize = @splat(0);
    var retained: usize = 0;
    for (inputs) |input| {
        retained = try std.math.add(usize, retained, try input.recursive().rows.retainedBytes());
        inline for (0..storage.Airs.len) |i| {
            row_counts[i] = try std.math.add(usize, row_counts[i], input.recursive().rows.fixed[i].len);
            if (row_counts[i] > @as(usize, 1) << @intCast(limits.max_row_log)) return error.MixedDirectResourceLimit;
        }
    }
    // A merged power-of-two column extent is below twice the sum of input
    // extents. Bound destination allocation before cloning or mutating inputs.
    if (try std.math.mul(usize, retained, 2) > limits.max_join_bytes) return error.MixedDirectResourceLimit;
    var count: usize = 0;
    for (inputs, 0..) |input, i| {
        count = try std.math.add(usize, count, input.count());
        if (count > Bus.MAX_CHILDREN) return error.InvalidMixedDirectCount;
        if (!std.meta.eql(input.recursive().context.child_config, inputs[0].recursive().context.child_config)) return error.MixedDirectSecurityMismatch;
        for (inputs[0..i]) |previous| if (previous.recursive() == input.recursive()) return error.AliasedMixedDirectInput;
    }
    if (count != expected.len) return error.UntrustedMixedDirectRoster;
    const children = try a.alloc(Bus.Child, count);
    var initialized: usize = 0;
    errdefer {
        for (children[0..initialized]) |*child| child.deinit();
        a.free(children);
    }
    for (inputs) |input| for (0..input.count()) |i| {
        children[initialized] = try input.child(i).clone(a);
        initialized += 1;
    };
    try (Bus.Values{ .children = children }).requireRoster(expected);
    const pins = try a.dupe(Bus.Expected, expected);
    errdefer a.free(pins);
    var wires: std.ArrayList(Bus.Wire) = .empty;
    errdefer wires.deinit(a);
    var row_owners: [Bus.MAX_CHILDREN]*storage.Prepared = undefined;
    var ranges: [Bus.MAX_CHILDREN]Join.Range = undefined;
    var next_namespace: u32 = 1;
    var child_first: usize = 0;
    var contexts: [5]core.channel.blake3.Channel = @splat(.{});
    for (&contexts, 0..) |*channel, i| channel.mixU32s(&.{ 0x42364d47, Bus.VERSION, @intCast(i), @intCast(count) });
    contexts[0].mixRoot(try Bus.rosterDigest(expected));
    for (inputs, 0..) |input, ordinal| {
        const piece = input.recursive();
        var namespace = try Rebase.prepare(a, &piece.rows, next_namespace);
        defer namespace.deinit();
        next_namespace = try namespace.end();
        const identity = try namespace.identity();
        switch (input) {
            .native => |v| for (v.prepared.wires) |wire| try wires.append(a, .{ .circuit = namespace.map(wire.circuit) orelse return error.MissingMixedDirectNamespace, .wire = wire.wire, .uses = wire.uses, .child = @intCast(child_first), .source = .{ .native = wire.source }, .coordinate = wire.coordinate }),
            inline else => |v, kind| for (v.wires) |wire| try wires.append(a, .{ .circuit = namespace.map(wire.circuit) orelse return error.MissingMixedDirectNamespace, .wire = wire.wire, .uses = wire.uses, .child = @intCast(child_first + wire.child), .source = @unionInit(Bus.Source, @tagName(kind), wire.source), .coordinate = wire.coordinate }),
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
        child_first += input.count();
    }
    // All namespace admissions precede one destination allocation per column;
    // the growing prefix is never recopied for each additional provider.
    var rows = Parent.Prepared{
        .rows = try Join.joinManyDraining(a, row_owners[0..inputs.len], ranges[0..inputs.len]),
        .context = .{ .child_key_id = contexts[0].digestBytes(), .child_config = inputs[0].recursive().context.child_config, .graph_ids = .{ contexts[1].digestBytes(), contexts[2].digestBytes(), contexts[3].digestBytes() }, .transcript_plan_id = contexts[4].digestBytes() },
    };
    errdefer rows.deinit();
    std.mem.sort(Bus.Wire, wires.items, {}, struct {
        fn less(_: void, l: Bus.Wire, r: Bus.Wire) bool {
            return l.circuit < r.circuit or (l.circuit == r.circuit and l.wire < r.wire);
        }
    }.less);
    _ = try Bus.scheduleDigest(wires.items);
    const owned_wires = try wires.toOwnedSlice(a);
    return .{ .allocator = a, .recursive = rows, .children = children, .expected = pins, .wires = owned_wires };
}
