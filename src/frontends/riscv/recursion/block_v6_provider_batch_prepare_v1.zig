//! One direct verifier AIR for original heterogeneous provider proofs. No
//! per-provider wrapper is proved; global requester/source obligations stay open.
const std = @import("std");
const core = @import("stwo_core");
const Bus = @import("block_v6_provider_batch_public_v1.zig");
const Parent = @import("blake3_execution_parent_preparation.zig");
const Rebase = @import("air/blake3_parent_rebase.zig");
const Join = @import("air/blake3_parent_join.zig");
pub fn Capture(comptime family: Bus.Family) type {
    return switch (family) {
        .range16 => @import("../prover/block_v5_range16_recursive_capture_v1.zig").VerifiedCapture,
        .ram_lanes => @import("../prover/block_v5_ram_lanes_recursive_capture_v1.zig").VerifiedCapture,
        .program_table => @import("../prover/block_v5_program_table_recursive_capture_v1.zig").VerifiedCapture,
        .native_lookup => @import("../prover/block_v5_native_lookup_recursive_capture_v1.zig").VerifiedCapture,
    };
}
pub fn InputFor(comptime family: Bus.Family) type {
    return struct { admitted: *const Bus.Definition(family).Prepared, capture: *const Capture(family) };
}
pub const Input = union(Bus.Family) {
    range16: InputFor(.range16),
    ram_lanes: InputFor(.ram_lanes),
    program_table: InputFor(.program_table),
    native_lookup: InputFor(.native_lookup),
    pub fn config(self: Input) core.pcs.PcsConfig {
        return switch (self) {
            inline else => |input| input.admitted.config,
        };
    }
    pub fn publicChild(self: Input) !Bus.Child {
        return switch (self) {
            inline else => |input, family| child: {
                try input.capture.validate(input.admitted, input.admitted.template_id);
                const value = try Bus.Definition(family).values(input.admitted, input.capture.receipt);
                break :child @unionInit(Bus.Child, @tagName(family), value);
            },
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
        self.allocator.free(self.wires);
        self.allocator.free(self.children);
        self.allocator.free(self.expected);
        self.* = undefined;
    }
};
const Builder = struct {
    a: std.mem.Allocator,
    rows: ?Parent.Prepared = null,
    wires: std.ArrayList(Bus.Wire) = .empty,
    next_namespace: u32 = 1,
    contexts: [5]core.channel.blake3.Channel = @splat(.{}),
    fn append(self: *@This(), comptime family: Bus.Family, input: InputFor(family), child: u8, expected_value: Bus.Child, capacity: u32) !void {
        const D = Bus.Definition(family);
        var piece = try D.Bus.prepare(self.a, input.admitted, input.capture, capacity);
        var moved = false;
        defer if (!moved) piece.deinit();
        if (!std.meta.eql(piece.values, @field(expected_value, @tagName(family)))) return error.UntrustedProviderBatchChild;
        var namespace = try Rebase.prepare(self.a, &piece.recursive.rows, self.next_namespace);
        defer namespace.deinit();
        self.next_namespace = try namespace.end();
        const identity = try namespace.identity();
        for (piece.wires) |wire| try self.wires.append(self.a, .{
            .circuit = namespace.map(wire.circuit) orelse return error.MissingProviderBatchNamespace,
            .wire = wire.wire,
            .uses = wire.uses,
            .child = child,
            .source = @unionInit(Bus.Source, @tagName(family), wire.source),
            .coordinate = wire.coordinate,
        });
        try Rebase.apply(&piece.recursive.rows, &namespace, identity);
        self.contexts[0].mixU32s(&.{@intFromEnum(family)});
        self.contexts[0].mixRoot(input.admitted.template_id);
        for (self.contexts[1..4], piece.recursive.context.graph_ids) |*channel, digest| {
            channel.mixRoot(digest);
            channel.mixRoot(identity);
        }
        self.contexts[4].mixRoot(piece.recursive.context.transcript_plan_id);
        self.contexts[4].mixRoot(identity);
        if (self.rows) |*previous| {
            const combined = try Join.joinDraining(self.a, &previous.rows, &piece.recursive.rows, .{
                .{ .first = 1, .end = namespace.first }, .{ .first = namespace.first, .end = self.next_namespace },
            });
            const context = previous.context;
            previous.deinit();
            previous.* = .{ .rows = combined, .context = context };
        } else {
            // Original buses own a separate cap allocator. Transfer it with
            // the first rows; later joins copy/drain before destroying it.
            if (piece.recursive.allocation_budget != null) return error.UnsupportedProviderBatchNestedBudget;
            piece.allocator.free(piece.wires);
            piece.recursive.allocation_budget = piece.budget;
            self.rows = piece.recursive;
            moved = true;
        }
    }
};
pub fn prepare(a: std.mem.Allocator, inputs: []const Input, expected: []const Bus.Expected, capacity: u32) !Prepared {
    if (inputs.len == 0 or inputs.len > Bus.MAX_CHILDREN or inputs.len != expected.len or capacity == 0) return error.InvalidProviderBatchCount;
    _ = try Bus.rosterDigest(expected);
    const children = try a.alloc(Bus.Child, inputs.len);
    errdefer a.free(children);
    for (inputs, children) |input, *child| {
        if (!std.meta.eql(input.config(), inputs[0].config())) return error.ProviderBatchSecurityMismatch;
        child.* = try input.publicChild();
    }
    try (Bus.Values{ .children = children }).requireRoster(expected);
    const owned_expected = try a.dupe(Bus.Expected, expected);
    errdefer a.free(owned_expected);
    var builder = Builder{ .a = a };
    errdefer {
        if (builder.rows) |*rows| rows.deinit();
        builder.wires.deinit(a);
    }
    for (&builder.contexts, 0..) |*channel, i| channel.mixU32s(&.{ 0x42365047, Bus.VERSION, @intCast(i), @intCast(inputs.len) });
    for (inputs, children, 0..) |input, child, i| switch (input) {
        inline else => |value, family| try builder.append(family, value, @intCast(i), child, capacity),
    };
    builder.rows.?.context = .{
        .child_key_id = builder.contexts[0].digestBytes(),
        .child_config = inputs[0].config(),
        .graph_ids = .{ builder.contexts[1].digestBytes(), builder.contexts[2].digestBytes(), builder.contexts[3].digestBytes() },
        .transcript_plan_id = builder.contexts[4].digestBytes(),
    };
    std.mem.sort(Bus.Wire, builder.wires.items, {}, struct {
        fn less(_: void, a_wire: Bus.Wire, b_wire: Bus.Wire) bool {
            return a_wire.circuit < b_wire.circuit or (a_wire.circuit == b_wire.circuit and a_wire.wire < b_wire.wire);
        }
    }.less);
    _ = try Bus.scheduleDigest(builder.wires.items);
    const wires = try builder.wires.toOwnedSlice(a);
    return .{ .allocator = a, .recursive = builder.rows.?, .wires = wires, .children = children, .expected = owned_expected };
}
