//! Genuine existing parent verifier rows with statically admitted lazy source
//! coordinates. No span is inferred, no original transcript is extended, and
//! callers must separately constrain every new public extension byte.
const std = @import("std");
const Parent = @import("../blake3_execution_parent_preparation.zig");
const Verified = @import("../blake3_native_parent_verifier.zig").Verified;
const Bus = @import("../block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Lower = @import("verifier_arithmetic_lowering.zig");
const Rebase = @import("blake3_parent_rebase.zig");
pub const Prepared = struct {
    recursive: Parent.Prepared,
    wires: []Bus.Wire,
    next_namespace: u32,
    namespace_identity: [32]u8,
    pub fn deinit(self: *Prepared) void {
        self.recursive.rows.allocator.free(self.wires);
        self.recursive.deinit();
        self.* = undefined;
    }
};
/// Admission's concrete type is chosen by the independently reconstructed
/// caller policy. State.plan validates the real capture, full original AIR,
/// transcript, paths and DEEP/FRI equations before emitting its existing rows.
/// PUBLIC_CIRCUIT must be the exact independently admitted source replay ID.
pub fn prepare(a: std.mem.Allocator, admission: anytype, capture: *const Verified, child: u32, comptime PUBLIC_CIRCUIT: u32, namespace_start: u32, transcript_capacity: u32) !Prepared {
    if (namespace_start == 0 or transcript_capacity == 0 or admission.pc_clock_children.len != 0) return error.InvalidScopedChildVerifierConfiguration;
    var planned = try Parent.State.plan(a, &admission, capture, admission.expected_id, transcript_capacity);
    defer planned.deinit();
    var wires: std.ArrayList(Bus.Wire) = .empty;
    errdefer wires.deinit(a);
    try collect(a, &wires, &planned, admission, child, PUBLIC_CIRCUIT);
    const emitted = try planned.emit();
    defer emitted.deinit();
    var recursive = try emitted.finishReleasingRows();
    errdefer recursive.deinit();
    var namespace = try Rebase.prepare(a, &recursive.rows, namespace_start);
    defer namespace.deinit();
    const next = try namespace.end();
    const identity = try namespace.identity();
    for (wires.items) |*wire| wire.circuit = namespace.map(wire.circuit) orelse return error.MissingScopedChildVerifierNamespace;
    try Rebase.apply(&recursive.rows, &namespace, identity);
    return .{ .recursive = recursive, .wires = try wires.toOwnedSlice(a), .next_namespace = next, .namespace_identity = identity };
}
fn collect(a: std.mem.Allocator, wires: *std.ArrayList(Bus.Wire), planned: *const Parent.Planned, admission: anytype, child: u32, comptime PUBLIC_CIRCUIT: u32) !void {
    const transcript = &planned.transcript.?;
    for (transcript.plan.fixed.root_reads) |receipt| if (receipt.source.circuit == PUBLIC_CIRCUIT) {
        for (receipt.uses, 0..) |uses, coordinate| if (uses != 0) try wires.append(a, .{
            .circuit = PUBLIC_CIRCUIT,
            .wire = receipt.source.first_wire + @as(u32, @intCast(coordinate)),
            .uses = uses,
            .child = child,
            .kind = .child_cell,
            .coordinate = @intCast(receipt.source.first_wire + coordinate),
        });
    };
    for (transcript.plan.fixed.payload_reads) |receipt| if (receipt.source.circuit == PUBLIC_CIRCUIT) {
        for (receipt.uses, 0..) |uses, coordinate| if (uses != 0) try wires.append(a, .{
            .circuit = PUBLIC_CIRCUIT,
            .wire = receipt.source.first_wire + @as(u32, @intCast(coordinate)),
            .uses = uses,
            .child = child,
            .kind = .child_cell,
            .coordinate = @intCast(receipt.source.first_wire + coordinate),
        });
    };
    const composition = &planned.state.?.composition;
    const counts = try a.alloc(u32, composition.circuit.nodes.len);
    defer a.free(counts);
    const uses = try Lower.computeUseCountsInto(composition.circuit.graph(), counts);
    for (composition.sources, 0..) |source, node| {
        if (source == .packed_public_input and source.packed_public_input % 4 == 0) {
            const index = source.packed_public_input / 4;
            if (index >= admission.source.terms.len) return error.InvalidV5NestedPublicSchedule;
            try wires.append(a, .{ .circuit = @import("block_v5_open_parent_packed_sources_v2.zig").CIRCUIT, .wire = index, .uses = 1, .negative = true, .child = child, .kind = .child_term, .coordinate = index });
        } else if (source == .public_input and uses[node] != 0) {
            // The empty typed native-span roster is deliberate: a separate
            // new extension graph supplies full-width authenticated spans.
            return error.UnexpectedScopedChildSpanInput;
        }
    }
}
