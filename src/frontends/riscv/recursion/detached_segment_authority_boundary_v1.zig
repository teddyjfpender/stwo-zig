//! Verifier-derived authority boundary from expected public input and admitted geometry.
const std = @import("std");
const core = @import("stwo_core");
const authority = @import("segment_expected_authority_hash_v2.zig");
const call_source = @import("segment_authority_wire_v2.zig");
const statement = @import("../air/statement_geometry.zig");
const preimage = @import("../air/statement_v2_authority_preimage.zig");
const PublicDataV2 = @import("../air/public_data_v2.zig").PublicDataV2;
const native_statement = @import("../air/statement.zig");
const opcode_order = @import("../air/component_order.zig");
const opcode_trace = @import("../runner/trace.zig");
const table_schema = @import("../air/lookups/tables/schema.zig");
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

    /// Reject a newly pinned but geometrically false catalog before proof
    /// decoding or the first transcript frame. The public segment fixes the
    /// number of retired native instructions independently of this key.
    pub fn validateAgainstExpected(self: DescriptorsV1, expected: *const PublicDataV2) !void {
        const metadata = try expected.metadata();
        if (self.components.len == 0 or self.components.len > statement.MAX_COMPONENTS or
            self.infrastructure.len > statement.MAX_INFRA_COMPONENTS)
            return error.InvalidNativeDescriptorGeometry;
        var rows: u64 = 0;
        var previous_family: ?usize = null;
        var previous_rows: u32 = 0;
        for (self.components) |desc| {
            if (desc.n_rows == 0 or desc.n_rows > (1 << 16) or
                desc.log_size != @max(@as(u32, 4), std.math.log2_int_ceil(u32, desc.n_rows)) or
                desc.n_columns != opcode_trace.nColumnsForFamily(desc.family))
                return error.InvalidNativeDescriptorGeometry;
            const rank = opcode_order.opcodeFamilyIndex(desc.family);
            if (previous_family) |previous|
                if (rank < previous or (rank == previous and previous_rows != (1 << 16)))
                    return error.InvalidNativeDescriptorGeometry;
            previous_family = rank;
            previous_rows = desc.n_rows;
            rows += desc.n_rows;
        }
        if (metadata.global_cycle_end < metadata.global_cycle_start or
            rows != @as(u64, metadata.global_cycle_end - metadata.global_cycle_start))
            return error.InvalidNativeDescriptorGeometry;

        for (self.infrastructure) |desc| {
            if (desc.log_size == 0 or desc.log_size > 30 or
                desc.n_rows > (@as(u32, 1) << @intCast(desc.log_size)))
                return error.InvalidNativeDescriptorGeometry;
            if (native_statement.tableKind(desc.kind)) |kind| {
                if (desc.log_size != table_schema.logSize(kind) or
                    desc.n_rows != table_schema.size(kind) or desc.n_columns != 1)
                    return error.InvalidNativeDescriptorGeometry;
            } else if (desc.kind == .clock_update) {
                if (desc.n_columns != @import("../infra_trace.zig").CLOCK_UPDATE_COLS or
                    desc.log_size != @max(@as(u32, 4), std.math.log2_int_ceil(u32, @max(desc.n_rows, 1))))
                    return error.InvalidNativeDescriptorGeometry;
            } else {
                if (desc.n_rows == 0 or
                    desc.log_size != @max(@as(u32, if (desc.kind == .program) 1 else 4), std.math.log2_int_ceil(u32, desc.n_rows)))
                    return error.InvalidNativeDescriptorGeometry;
                const expected_columns: u32 = switch (desc.kind) {
                    .program => @import("../air/program/commitment.zig").N_MAIN_COLUMNS,
                    .memory => @import("../air/memory_commitment/trace.zig").N_COLUMNS,
                    .merkle => @import("../air/memory_commitment/merkle_node.zig").N_MAIN_COLUMNS,
                    .poseidon2 => @import("../air/memory_commitment/poseidon2_air.zig").N_MAIN_COLUMNS,
                    else => unreachable,
                };
                if (desc.n_columns != expected_columns)
                    return error.InvalidNativeDescriptorGeometry;
            }
        }
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
