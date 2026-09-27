//! Instance-pinned closure of the original recursion_wire supply. Every tuple
//! is emitted by shipped Boundary AIR with enabled main=fixed constraints.
//! No host-computed sum is substituted. Expected keys must independently
//! reconstruct these fixed rows from the actual child public policy.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Storage = @import("blake3_parent_row_storage.zig");
const Boundary = @import("blake3_boundary.zig");
const Direct = @import("blake3_direct_cohort_columns_v1.zig").ForAir(Boundary);
const committed = @import("framework_interaction.zig").committedRow;
const Bus = @import("../block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Session = @import("../block_v5_public_supply_session_v2.zig");
pub const Limits = Session.Limits;
pub fn row(wire: Bus.Wire, coordinates: [4]M) !Boundary.Row {
    if (wire.uses == 0 or wire.uses >= core.fields.m31.Modulus) return error.InvalidClosedPublicSupply;
    for (coordinates) |value| if (value.v >= core.fields.m31.Modulus) return error.InvalidClosedPublicSupply;
    const weight = M.fromCanonical(wire.uses);
    return Boundary.logicalCoordinates(wire.circuit, wire.wire, if (wire.negative) weight.neg() else weight, coordinates);
}
/// Failure atomic: the old main/fixed columns remain owned and unchanged until
/// all allocations, admission guards and exact rows complete. Namespace overlap
/// is intentional: these rows supply the original consumer tuple identities.
pub fn append(a: std.mem.Allocator, parent: *Storage.Prepared, wires: []const Bus.Wire, values: anytype, limits: Limits) ![32]u8 {
    if (a.ptr != parent.allocator.ptr or a.vtable != parent.allocator.vtable) return error.InvalidClosedPublicSupplyAllocator;
    var session = try Session.ForValues(@TypeOf(values)).begin(values, wires, limits);
    const old_count = parent.fixed[2].len;
    const count = try std.math.add(usize, old_count, wires.len);
    if (parent.main[2].len != Boundary.PHYSICAL_MAIN_COLUMN_COUNT) return error.InvalidClosedPublicSupply;
    const old_log = try @import("blake3_direct_cohort_columns_v1.zig").rowLog(old_count);
    for (parent.main[2]) |column| if (column.log_size != old_log or column.values.len != @as(usize, 1) << @intCast(old_log)) return error.InvalidClosedPublicSupply;
    var direct = try Direct.init(a, count);
    defer direct.deinit();
    for (0..old_count) |logical| {
        var original: Boundary.Row = undefined;
        for (parent.main[2], original[0..4]) |column, *value| value.* = column.values[committed(logical, old_log)];
        original[4..].* = parent.fixed[2][logical];
        try direct.append(original);
    }
    for (wires, 0..) |wire, ordinal| try direct.append(try row(wire, try session.at(ordinal)));
    const identity = try session.finish();
    const taken = try direct.take();
    parent.releaseCohort(2);
    parent.main[2] = taken.main;
    parent.fixed[2] = taken.fixed;
    return identity;
}
