//! One reduction layer over freshly verified direct mixed-batch STARKs.
//! Rows are joined once, after all public transcript/supply namespaces rebase.
//! No native-only leaf span, dummy leaf, or aggregate-only claim is introduced.
const std = @import("std");
const core = @import("stwo_core");
const Capture = @import("block_v7_mixed_batch_capture_v1.zig");
const Bus = @import("block_v7_mixed_batch_public_v1.zig");
const Parent = @import("blake3_execution_parent_preparation.zig");
const Rebase = @import("air/blake3_parent_rebase.zig");
const Join = @import("air/blake3_parent_join.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Lower = @import("air/verifier_arithmetic_lowering.zig");
pub const Limits = struct { circuit_capacity: u32 = 2, max_row_log: u32 = 25, max_join_bytes: usize = 8 << 30 };
pub const Prepared = struct {
    a: std.mem.Allocator,
    recursive: Parent.Prepared,
    wires: []Bus.Wire,
    children: []*const Capture.Source,
    expected: []Bus.Expected,
    /// Sources borrow captures; every capture must outlive Prepared.
    pub fn values(self: *const Prepared) Bus.Values {
        return .{ .children = self.children };
    }
    pub fn deinit(self: *Prepared) void {
        self.recursive.deinit();
        self.a.free(self.wires);
        self.a.free(self.children);
        self.a.free(self.expected);
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, captures: []const *const Capture.Captured, expected: []const Bus.Expected, limits: Limits) !Prepared {
    if (captures.len == 0 or captures.len > Bus.MAX_CHILDREN or captures.len != expected.len) return error.InvalidMixedBatchFanIn;
    if (limits.max_row_log == 0 or limits.max_row_log > 30 or limits.max_join_bytes == 0 or limits.circuit_capacity == 0) return error.InvalidMixedBatchLimits;
    const children = try a.alloc(*const Capture.Source, captures.len);
    errdefer a.free(children);
    for (captures, children) |capture, *child| child.* = capture.source;
    try (Bus.Values{ .children = children }).requireRoster(expected);
    const pins = try a.dupe(Bus.Expected, expected);
    errdefer a.free(pins);
    var pieces: [Bus.MAX_CHILDREN]Parent.Prepared = undefined;
    var count: usize = 0;
    defer for (pieces[0..count]) |*piece| piece.deinit();
    var owners: [Bus.MAX_CHILDREN]*Storage.Prepared = undefined;
    var ranges: [Bus.MAX_CHILDREN]Join.Range = undefined;
    var row_counts: [Storage.Airs.len]usize = @splat(0);
    var retained: usize = 0;
    var wires: std.ArrayList(Bus.Wire) = .empty;
    errdefer wires.deinit(a);
    var next_namespace: u32 = 1;
    var contexts: [5]core.channel.blake3.Channel = @splat(.{});
    for (&contexts, 0..) |*channel, i| channel.mixU32s(&.{ 0x42375247, Bus.VERSION, @intCast(i), @intCast(captures.len) });
    contexts[0].mixRoot(try Bus.rosterDigest(expected));
    for (captures, 0..) |capture, i| {
        if (!std.meta.eql(capture.source.original_key.config, captures[0].source.original_key.config)) return error.MixedBatchSecurityMismatch;
        const admission = Capture.Admission.init(capture.source);
        var planned = try capture.plan(a, limits.circuit_capacity);
        defer planned.deinit();
        const wire_first = wires.items.len;
        try collect(a, &wires, &planned, admission, @intCast(i));
        const emitted = try planned.emit();
        defer emitted.deinit();
        pieces[i] = try emitted.finishReleasingRows();
        count += 1;
        const piece = &pieces[i];
        // Cold setup partitions each original verifier before namespace rebasing.
        try piece.rows.partitionHashRows();
        retained = try std.math.add(usize, retained, try piece.rows.retainedBytes());
        inline for (0..Storage.Airs.len) |j| {
            row_counts[j] = try std.math.add(usize, row_counts[j], piece.rows.fixed[j].len);
            if (row_counts[j] > @as(usize, 1) << @intCast(limits.max_row_log)) return error.MixedBatchResourceLimit;
        }
        if (try std.math.mul(usize, retained, 2) > limits.max_join_bytes) return error.MixedBatchResourceLimit;
        var namespace = try Rebase.prepare(a, &piece.rows, next_namespace);
        defer namespace.deinit();
        next_namespace = try namespace.end();
        const identity = try namespace.identity();
        for (wires.items[wire_first..]) |*wire| wire.circuit = namespace.map(wire.circuit) orelse return error.MissingMixedBatchNamespace;
        try Rebase.apply(&piece.rows, &namespace, identity);
        owners[i] = &piece.rows;
        ranges[i] = .{ .first = namespace.first, .end = next_namespace };
        contexts[0].mixRoot(capture.source.expected_id);
        for (contexts[1..4], piece.context.graph_ids) |*channel, digest| {
            channel.mixRoot(digest);
            channel.mixRoot(identity);
        }
        contexts[4].mixRoot(piece.context.transcript_plan_id);
        contexts[4].mixRoot(identity);
    }
    var result = if (count == 1) single: {
        const moved = pieces[0];
        count = 0; // Transfer rows and their allocator lease without a dummy sibling.
        break :single moved;
    } else Parent.Prepared{ .rows = try Join.joinManyDraining(a, owners[0..count], ranges[0..count]), .context = undefined };
    result.context = .{
        .child_key_id = contexts[0].digestBytes(),
        .child_config = captures[0].source.original_key.config,
        .graph_ids = .{ contexts[1].digestBytes(), contexts[2].digestBytes(), contexts[3].digestBytes() },
        .transcript_plan_id = contexts[4].digestBytes(),
    };
    errdefer result.deinit();
    std.mem.sort(Bus.Wire, wires.items, {}, struct {
        fn less(_: void, l: Bus.Wire, r: Bus.Wire) bool {
            return l.circuit < r.circuit or (l.circuit == r.circuit and l.wire < r.wire);
        }
    }.less);
    _ = try Bus.scheduleDigest(wires.items);
    return .{ .a = a, .recursive = result, .wires = try wires.toOwnedSlice(a), .children = children, .expected = pins };
}
fn collect(a: std.mem.Allocator, wires: *std.ArrayList(Bus.Wire), planned: *const Parent.Planned, admission: Capture.Admission, child: u8) !void {
    return collectFixed(a, wires, &planned.transcript.?.plan, &planned.state.?.composition, admission.source.terms.len, child);
}
/// Same public schedule recipe for live rows and independent fixed setup.
pub fn collectFixed(a: std.mem.Allocator, wires: *std.ArrayList(Bus.Wire), transcript: *const @import("air/blake3_transcript_plan.zig").Plan, composition: anytype, term_count: usize, child: u8) !void {
    inline for (.{ transcript.fixed.root_reads, transcript.fixed.payload_reads }) |receipts| {
        for (receipts) |receipt| if (receipt.source.circuit == Bus.PUBLIC_CIRCUIT) {
            for (receipt.uses, 0..) |uses, coordinate| if (uses != 0) try wires.append(a, .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = receipt.source.first_wire + @as(u32, @intCast(coordinate)), .uses = uses, .child = child, .kind = .frame_cell, .coordinate = @intCast(receipt.source.first_wire + coordinate) });
        };
    }
    const counts = try a.alloc(u32, composition.circuit.nodes.len);
    defer a.free(counts);
    const uses = try Lower.computeUseCountsInto(composition.circuit.graph(), counts);
    for (composition.sources, 0..) |source, node| {
        if (source == .packed_public_input and source.packed_public_input % 4 == 0) {
            const index = source.packed_public_input / 4;
            if (index >= term_count) return error.InvalidMixedBatchSchedule;
            try wires.append(a, .{ .circuit = @import("air/block_v5_open_parent_packed_sources_v2.zig").CIRCUIT, .wire = index, .uses = 1, .negative = true, .child = child, .kind = .child_supply_packed, .coordinate = index });
        } else if (source == .public_input and uses[node] != 0) {
            // This lane has no native PC/span authority; any unexpected public
            // composition operand is an error rather than an omitted supply.
            return error.UnexpectedMixedBatchPublicInput;
        }
    }
}
test "mixed batch reduction original preparation and protocol instantiate" {
    std.mem.doNotOptimizeAway(&prepare);
    std.mem.doNotOptimizeAway(&@import("block_v7_mixed_batch_protocol_v1.zig").Admission.init);
}
