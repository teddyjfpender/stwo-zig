//! Verifier-derived authority boundary from expected public input and admitted geometry.
const std = @import("std");
const core = @import("stwo_core");
const authority = @import("segment_expected_authority_hash_v2.zig");
const call_source = @import("segment_authority_wire_v2.zig");
const statement = @import("../air/statement_geometry.zig");
const preimage = @import("../air/statement_v2_authority_preimage.zig");
const PublicDataV2 = @import("../air/public_data_v2.zig").PublicDataV2;
const universal = @import("air/universal_challenges.zig");
const poseidon_call = @import("../air/memory_commitment/poseidon2_call.zig");
const QM31 = core.fields.qm31.QM31;
const max_calls = authority.authorityHashCallCount(statement.MAX_COMPONENTS, statement.MAX_INFRA_COMPONENTS) catch unreachable;

pub const DescriptorsV1 = struct {
    components: []const statement.FamilyComponentDesc,
    infrastructure: []const statement.InfraComponentDesc,

    pub fn callCount(self: DescriptorsV1) !usize {
        return authority.authorityHashCallCount(self.components.len, self.infrastructure.len);
    }

    /// Hash only geometry words from the shared native preimage emitter.
    /// Public scalar/digest placeholders below are never emitted into this key
    /// identity; they are supplied by the caller's expected statement at use.
    pub fn mixIdentity(self: DescriptorsV1, hash: *std.crypto.hash.sha2.Sha256) !void {
        _ = try self.callCount();
        var sink = GeometryHashSink{ .hash = hash };
        preimage.emit(&sink, .{
            .initial_pc = 0,
            .final_pc = 0,
            .cycle_count = 0,
            .wire_id = @splat(0),
            .component_descs = self.components,
            .infra_descs = self.infrastructure,
        });
    }
};

const GeometryHashSink = struct {
    hash: *std.crypto.hash.sha2.Sha256,
    pub fn word(self: *GeometryHashSink, source: preimage.Source, value: u32) void {
        if (source != .admitted_geometry) return;
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .little);
        self.hash.update(&bytes);
    }
};

pub const BoundaryV1 = struct { term_count: u32, claimed_sum: QM31 };

pub fn derive(
    expected: *const PublicDataV2,
    descriptors: DescriptorsV1,
    relations: *const universal.UniversalRelations,
) !BoundaryV1 {
    const count = try descriptors.callCount();
    // Fixed native descriptor caps bound this scratch before any proof input
    // is used. Only the active prefix is initialized and read.
    var call_storage: [max_calls]poseidon_call.Call = undefined;
    const calls = call_storage[0..count];
    _ = try authority.appendExpectedAuthorityHashCalls(calls, expected, descriptors.components, descriptors.infrastructure);
    const challenge = try relations.getExact(.recursion_wire);
    var sum = QM31.zero();
    for (calls, 0..) |call, index| {
        for (call_source.callWireTuples(index, call)) |tuple| {
            sum = sum.sub(try (try challenge.combineBase(&tuple)).inv());
        }
    }
    return .{ .term_count = @intCast(count * call_source.CALL_WIRE_GROUP_COUNT), .claimed_sum = sum };
}
