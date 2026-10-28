//! Bounded direct-native verifier batch. No intermediate recursive leaf proof
//! is produced. Uses original native equations and public supply unchanged.
const std = @import("std");
const core = @import("stwo_core");
const native_bus = @import("block_v5_recursive_public_bus_v1.zig");
const bus = @import("block_v6_native_batch_public_v1.zig");
const spans = @import("block_v5_pc_clock_span_v1.zig");
const parent = @import("blake3_execution_parent_preparation.zig");
const rebase = @import("air/blake3_parent_rebase.zig");
const join = @import("air/blake3_parent_join.zig");
pub const NativeAdmission = @import("../prover/block_v5_native_recursive_admission_v3.zig").Prepared;
pub const Capture = @import("../prover/block_v5_native_execution_proof_v3.zig").VerifiedCapture;
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    recursive: parent.Prepared,
    wires: []bus.Wire,
    children: []bus.Child,
    pub fn values(self: *const Prepared) bus.Values {
        return .{ .children = self.children };
    }
    pub fn deinit(self: *Prepared) void {
        self.recursive.deinit();
        self.allocator.free(self.wires);
        self.allocator.free(self.children);
        self.* = undefined;
    }
};
/// A fresh receiver derives these from independent native policies and exported
/// native receipts; the aggregate artifact cannot select the statements.
pub fn publicChild(a: std.mem.Allocator, admitted: *const NativeAdmission, receipt: @import("../prover/block_v5_native_execution_proof_v3.zig").OpenReceipt) !bus.Child {
    return .{ .native = try native_bus.Values.fromNative(a, admitted, receipt), .span = try spans.leaf(admitted.pin, admitted.shape, admitted.sealed.digest, admitted.sealed.execution_instance_count) };
}
pub fn prepare(a: std.mem.Allocator, admissions: []const *const NativeAdmission, captures: []const *const Capture, capacity: u32) !Prepared {
    if (admissions.len == 0 or admissions.len > bus.MAX_CHILDREN or captures.len != admissions.len) return error.InvalidNativeBatchCount;
    const children = try a.alloc(bus.Child, admissions.len);
    errdefer a.free(children);
    for (admissions, captures, children) |admitted, capture, *child| {
        if (!std.meta.eql(admitted.config, admissions[0].config)) return error.NativeBatchSecurityMismatch;
        try capture.validate(admitted, admitted.expected_id);
        child.* = try publicChild(a, admitted, capture.receipt);
    }
    try (bus.Values{ .children = children }).validate();
    var wires: std.ArrayList(bus.Wire) = .empty;
    errdefer wires.deinit(a);
    var accumulated: ?parent.Prepared = null;
    errdefer if (accumulated) |*owned| owned.deinit();
    var next_namespace: u32 = 1;
    var contexts: [5]core.channel.blake3.Channel = @splat(.{});
    for (&contexts, 0..) |*channel, i| channel.mixU32s(&.{ 0x42364e47, bus.VERSION, @intCast(i), @intCast(children.len) });
    for (admissions, captures, 0..) |admitted, capture, index| {
        var piece = try native_bus.prepare(a, admitted, capture, capacity);
        defer a.free(piece.wires);
        var moved = false;
        defer if (!moved) piece.recursive.deinit();
        if (!std.meta.eql(piece.values, children[index].native)) return error.UntrustedNativeBatchChild;
        var namespace = try rebase.prepare(a, &piece.recursive.rows, next_namespace);
        defer namespace.deinit();
        next_namespace = try namespace.end();
        const identity = try namespace.identity();
        for (piece.wires) |wire| try wires.append(a, .{
            .circuit = namespace.map(wire.circuit) orelse return error.MissingNativeBatchNamespace,
            .wire = wire.wire,
            .uses = wire.uses,
            .child = @intCast(index),
            .source = .{ .native = wire.source },
            .coordinate = wire.coordinate,
        });
        try rebase.apply(&piece.recursive.rows, &namespace, identity);
        contexts[0].mixRoot(admitted.expected_id);
        for (contexts[1..4], piece.recursive.context.graph_ids) |*channel, digest| {
            channel.mixRoot(digest);
            channel.mixRoot(identity);
        }
        contexts[4].mixRoot(piece.recursive.context.transcript_plan_id);
        contexts[4].mixRoot(identity);
        if (accumulated) |*previous| {
            const combined = try join.joinDraining(a, &previous.rows, &piece.recursive.rows, .{
                .{ .first = 1, .end = namespace.first }, .{ .first = namespace.first, .end = next_namespace },
            });
            previous.rows.deinit();
            previous.rows = combined;
        } else {
            accumulated = piece.recursive;
            moved = true;
        }
    }
    const edges = try @import("air/block_v6_native_batch_edges_v1.zig").append(&accumulated.?.rows, children, next_namespace, &wires);
    contexts[1].mixRoot(edges);
    contexts[1].mixU32s(&.{next_namespace});
    accumulated.?.context = .{
        .child_key_id = contexts[0].digestBytes(),
        .child_config = admissions[0].config,
        .graph_ids = .{ contexts[1].digestBytes(), contexts[2].digestBytes(), contexts[3].digestBytes() },
        .transcript_plan_id = contexts[4].digestBytes(),
    };
    std.mem.sort(bus.Wire, wires.items, {}, struct {
        fn less(_: void, left: bus.Wire, right: bus.Wire) bool {
            return left.circuit < right.circuit or (left.circuit == right.circuit and left.wire < right.wire);
        }
    }.less);
    _ = try bus.scheduleDigest(wires.items);
    const owned_wires = try wires.toOwnedSlice(a);
    const recursive = accumulated.?;
    accumulated = null;
    return .{ .allocator = a, .recursive = recursive, .wires = owned_wires, .children = children };
}
