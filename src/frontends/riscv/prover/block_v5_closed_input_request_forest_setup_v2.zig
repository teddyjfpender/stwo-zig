//! Expected-key construction for the additive instance-pinned closed route.
//! Callers must obtain original leaf/node captures through their independently
//! admitted genuine receivers. This is NOT reusable geometry or a standalone
//! block key recipe: some original verifier fixed schedules depend on captures.
const std = @import("std");
const CpuRows = @import("../recursion/block_v5_closed_input_request_forest_preparation_v2.zig");
const Bus = @import("../recursion/block_v5_closed_input_request_forest_bus_v2.zig");
const Layout = @import("../recursion/block_v5_input_request_forest_public_v1.zig");
const Protocol = @import("../recursion/block_v5_closed_input_request_forest_protocol_v2.zig");
const Carrier = @import("../recursion/block_v5_input_tail_receiver_v1.zig");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub fn derive(backing: std.mem.Allocator, public: *const Bus.Owner, original: []const CpuRows.Verified, carrier: ?*const Carrier.Fresh, profile: Base.Profile, transcript_capacity: u32, limits: CpuRows.Limits) !Layout.Spec {
            var rows = try CpuRows.prepare(backing, public, original, carrier, transcript_capacity, limits);
            defer rows.deinit();
            if (rows.wires.len != 0) return error.ClosedInputRequestNodeHasNoPublicTerms;
            const geometry = try Parent.ForBackend(Backend).deriveKeyWithProfile(backing, &rows.recursive, profile);
            const key = try Protocol.Key.fromGeometry(geometry, &.{});
            return .{ .geometry = geometry, .schedule = &.{}, .expected_id = try key.identity() };
        }
    };
}
