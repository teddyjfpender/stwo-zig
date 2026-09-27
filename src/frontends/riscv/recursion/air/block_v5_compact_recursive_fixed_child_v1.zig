//! Original packed parent compiler, namespace identifiers and suppliers once.
//! The family derives the expected key before constructing this setup view.
const std = @import("std");
const Base = @import("../blake3_execution_parent_protocol.zig");
const PiecesModule = @import("../block_v5_recursive_parent_fixed_pieces_v1.zig");
const RosterModule = @import("../block_v5_recursive_parent_fixed_roster_v1.zig");
const Suppliers = @import("block_v5_recursive_fixed_child_suppliers_v1.zig");
const Identifiers = @import("block_v5_requester_public_fixed_identifier_ports_v1.zig");
const Circuit = @import("composition_circuit.zig").CircuitGraph;
const Attach = @import("../block_v5_recursive_fixed_attachments_v1.zig").Scoped;
pub const Attachment = struct { namespace: [32]u8, context: Base.Context };
pub fn append(a: std.mem.Allocator, builder: *Attach, admission: anytype, child: u32, comptime public_circuit: u32, capacity: u32, limits: PiecesModule.Limits) !Attachment {
    const Admission = @TypeOf(admission);
    const Pieces = PiecesModule.ForAdmission(Admission);
    const Roster = RosterModule.ForPackedAdmission(Admission);
    const pieces = try Pieces.Owned.init(a, &admission, capacity, limits);
    defer pieces.deinit();
    const rows = try Roster.Owned.init(a, pieces, &admission);
    defer rows.deinit();
    const wires = try Suppliers.collect(a, pieces.transcript.fixed.fixed, &pieces.composition, admission.source.terms.len, child, public_circuit);
    defer a.free(wires);
    const graphs = [3]Circuit{ pieces.composition.circuit.graph(), pieces.arithmetic.deep_graph.graph(), pieces.arithmetic.fri_graph.graph() };
    var identifiers = try Identifiers.Owned.init(a, &graphs, &.{ 1500, 1502, 1504 });
    defer identifiers.deinit();
    try builder.appendChildWithArithmetic(rows.fixed, wires, try identifiers.port());
    return .{ .namespace = builder.attachments.items[builder.attachments.items.len - 1], .context = .{ .child_key_id = admission.key.context.child_key_id, .child_config = admission.key.config, .graph_ids = rows.graph_ids, .transcript_plan_id = rows.transcript_id } };
}
