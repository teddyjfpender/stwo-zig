//! Public boundary for the dynamic native statement-authority hash calls.
//! Exact call words come from expected public input and admitted native
//! geometry. Row13 supplies the matching uniquely indexed AIR wire emissions.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const recursion = frontend.recursion;
const authority = recursion.segment_leaf_authority_v2;
const call_source = recursion.segment_public_claim_hash_authority_v2;
const statement = frontend.air.statement;
const preimage = frontend.air.statement_v2.authority_preimage;
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
    expected: *const frontend.air.public_data_v2.PublicDataV2,
    descriptors: DescriptorsV1,
    relations: *const recursion.air.universal_challenges.UniversalRelations,
) !BoundaryV1 {
    const count = try descriptors.callCount();
    // Fixed native descriptor caps bound this scratch before any proof input
    // is used. Only the active prefix is initialized and read.
    var call_storage: [max_calls]frontend.air.memory_commitment.poseidon2_air.Call = undefined;
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
