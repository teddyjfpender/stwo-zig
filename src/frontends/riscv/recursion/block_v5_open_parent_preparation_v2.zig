//! Genuine bounded two/four-child v3 recursive verifier fold. It verifies each
//! child's complete STARK verifier and public-supply closure, then constrains
//! exact PC/clock/index adjacency. It exports open global obligations only.
const std = @import("std");
const core = @import("stwo_core");
const bus = @import("block_v5_open_parent_public_bus_v2.zig");
const parent = @import("blake3_execution_parent_preparation.zig");
const verified_mod = @import("blake3_native_parent_verifier.zig");
const spans = @import("block_v5_pc_clock_span_v1.zig");
const child_frames = @import("block_v5_open_child_frames_v2.zig");
const rebase = @import("air/blake3_parent_rebase.zig");
const join = @import("air/blake3_parent_join.zig");
const lower = @import("air/verifier_arithmetic_lowering.zig");
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    recursive: parent.Prepared,
    wires: []bus.Wire,
    /// Borrows independent child policy, never proof-envelope metadata.
    values: bus.Values,
    pub fn deinit(self: *Prepared) void {
        self.recursive.deinit();
        self.allocator.free(self.wires);
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, purpose: bus.Purpose, children: []const bus.Child, captures: []const *const verified_mod.Verified, capacity: u32) !Prepared {
    const values = bus.Values{ .purpose = purpose, .children = children };
    try values.validate();
    if (captures.len != children.len) return error.InvalidV5OpenParentChildren;
    var span_list: [32]spans.Span = undefined;
    for (children, span_list[0..children.len]) |child, *span| span.* = child.span;
    var wires: std.ArrayList(bus.Wire) = .empty;
    errdefer wires.deinit(a);
    var accumulated: ?parent.Prepared = null;
    errdefer if (accumulated) |*owned| owned.deinit();
    var next_namespace: u32 = 1;
    var context_channels: [5]core.channel.blake3.Channel = @splat(.{});
    for (&context_channels, 0..) |*channel, index| channel.mixU32s(&.{ 0x42354f47, bus.VERSION, @intCast(index), @intCast(children.len) });
    for (children, captures, 0..) |child, capture, index| {
        if (!std.meta.eql(child.key.config, children[0].key.config) or
            child.key.profile != children[0].key.profile) return error.V5OpenParentSecurityMismatch;
        const admitted = child_frames.Admission.init(&children[index], if (index == 0) span_list[0..children.len] else &.{});
        var planned = try parent.State.plan(a, &admitted, capture, admitted.expected_id, capacity);
        defer planned.deinit();
        const at = wires.items.len;
        try collect(a, &wires, &planned, admitted, @intCast(index));
        const emitted = try planned.emit();
        defer emitted.deinit();
        var prepared = try emitted.finishReleasingRows();
        var transferred = false;
        defer if (!transferred) prepared.deinit();
        var namespace = try rebase.prepare(a, &prepared.rows, next_namespace);
        defer namespace.deinit();
        next_namespace = try namespace.end();
        const namespace_id = try namespace.identity();
        for (wires.items[at..]) |*wire| wire.circuit = namespace.map(wire.circuit) orelse return error.MissingV5OpenParentPublicNamespace;
        try rebase.apply(&prepared.rows, &namespace, namespace_id);
        context_channels[0].mixRoot(child.expected_id);
        for (context_channels[1..4], prepared.context.graph_ids) |*channel, digest| {
            channel.mixRoot(digest);
            channel.mixRoot(namespace_id);
        }
        context_channels[4].mixRoot(prepared.context.transcript_plan_id);
        context_channels[4].mixRoot(namespace_id);
        if (accumulated) |*previous| {
            const combined = try join.joinDraining(a, &previous.rows, &prepared.rows, .{
                .{ .first = 1, .end = namespace.first },
                .{ .first = namespace.first, .end = next_namespace },
            });
            previous.rows.deinit();
            prepared.rows.deinit();
            previous.rows = combined;
            transferred = true;
        } else {
            accumulated = prepared;
            transferred = true;
        }
    }
    var result = accumulated.?;
    accumulated = null;
    errdefer result.deinit();
    result.context = .{
        .child_key_id = context_channels[0].digestBytes(),
        .child_config = children[0].key.config,
        .graph_ids = .{ context_channels[1].digestBytes(), context_channels[2].digestBytes(), context_channels[3].digestBytes() },
        .transcript_plan_id = context_channels[4].digestBytes(),
    };
    std.mem.sort(bus.Wire, wires.items, {}, struct {
        fn less(_: void, left: bus.Wire, right: bus.Wire) bool {
            return left.circuit < right.circuit or (left.circuit == right.circuit and left.wire < right.wire);
        }
    }.less);
    _ = try bus.scheduleDigest(wires.items);
    return .{ .allocator = a, .recursive = result, .wires = try wires.toOwnedSlice(a), .values = values };
}
fn collect(a: std.mem.Allocator, wires: *std.ArrayList(bus.Wire), planned: *const parent.Planned, admission: child_frames.Admission, child: u8) !void {
    const transcript = &planned.transcript.?;
    for (transcript.plan.fixed.root_reads) |receipt| if (receipt.source.circuit == bus.PUBLIC_CIRCUIT) {
        for (receipt.uses, 0..) |uses, coordinate| if (uses != 0) try wires.append(a, .{
            .circuit = bus.PUBLIC_CIRCUIT,
            .wire = receipt.source.first_wire + @as(u32, @intCast(coordinate)),
            .uses = uses,
            .child = child,
            .kind = .frame_cell,
            .coordinate = @intCast(receipt.source.first_wire + coordinate),
        });
    };
    for (transcript.plan.fixed.payload_reads) |receipt| if (receipt.source.circuit == bus.PUBLIC_CIRCUIT) {
        for (receipt.uses, 0..) |uses, coordinate| if (uses != 0) try wires.append(a, .{
            .circuit = bus.PUBLIC_CIRCUIT,
            .wire = receipt.source.first_wire + @as(u32, @intCast(coordinate)),
            .uses = uses,
            .child = child,
            .kind = .frame_cell,
            .coordinate = @intCast(receipt.source.first_wire + coordinate),
        });
    };
    const composition = &planned.state.?.composition;
    const counts = try a.alloc(u32, composition.circuit.nodes.len);
    defer a.free(counts);
    const uses = try lower.computeUseCountsInto(composition.circuit.graph(), counts);
    for (composition.sources, 0..) |source, node| {
        if (source == .packed_public_input and source.packed_public_input % 4 == 0) {
            const index = source.packed_public_input / 4;
            if (index >= admission.source.terms.len) return error.InvalidV5NestedPublicSchedule;
            try wires.append(a, .{ .circuit = @import("air/block_v5_open_parent_packed_sources_v2.zig").CIRCUIT, .wire = index, .uses = 1, .negative = true, .child = child, .kind = .child_supply_packed, .coordinate = index });
        } else if (source == .public_input and uses[node] != 0) {
            const closure_end = 4 * admission.source.terms.len;
            if (source.public_input < closure_end) return error.InvalidV5NestedPublicSchedule;
            const span_coordinate = source.public_input - closure_end;
            const wire = bus.Wire{ .circuit = 1500, .wire = @intCast(node), .uses = uses[node], .child = @intCast(span_coordinate / 6), .kind = .span, .coordinate = @intCast(span_coordinate % 6) };
            const value = core.fields.m31.M31.fromCanonical(@import("block_v5_open_parent_public_bus_v1.zig").spanWords(admission.pc_clock_children[wire.child])[wire.coordinate]);
            if (!composition.inputs[node].eql(core.fields.qm31.QM31.fromBase(value))) return error.UntrustedV5OpenParentInputs;
            try wires.append(a, wire);
        }
    }
}
