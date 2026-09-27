//! Standalone compression proof fixture; no production roster or profile changes.
const std = @import("std");
pub const core = @import("stwo_core");
pub const prover = @import("stwo_prover_engine");
pub const g = @import("blake3_g_call.zig");
pub const xor = @import("blake3_xor_call.zig");
pub const boundary = @import("blake3_boundary.zig");
pub const binding = @import("universal_relation_binding.zig");
pub const framework = @import("framework_interaction.zig");
pub const universal = @import("universal_challenges.zig");
pub const schema = @import("../../air/lookups/tables/schema.zig");
pub const Counter = @import("../../air/lookups/tables/counter.zig").Counter;
pub const Table = @import("../../air/lookups/tables/component.zig").LookupTableComponent;
pub const table_interaction = @import("../../air/lookups/tables/interaction.zig");
pub const M31 = core.fields.m31.M31;
pub const QM31 = core.fields.qm31.QM31;
pub const Column = prover.pcs.ColumnEvaluation;
pub const Cpu = @import("stwo_cpu_backend").CpuBackend;
pub const Hasher = core.vcs_lifted.blake3_merkle.MerkleHasher;
pub const MerkleChannel = core.vcs_lifted.blake3_merkle.MerkleChannel;
pub const Channel = core.channel.blake3.Channel;
pub const Scheme = prover.pcs.CommitmentSchemeProver(Cpu, Hasher, MerkleChannel);
pub const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel);
pub const Airs = .{ g, xor, boundary };
pub const logs = [_]u32{ 6, 4, 6 };
pub const kinds = [_]schema.Kind{ .bitwise, .range_check_8_8 };

// Only the three typed adapters consume this fixture interface. Production
// lookup-table adapters carry their own explicit indices and trusted schemas.
pub const TREE_COUNT = 3;
pub const PREPROCESSED_TREE_INDEX = 0;
pub const MAIN_TREE_INDEX = 1;
pub const INTERACTION_TREE_INDEX = 2;
pub const ComponentKey = enum(u8) { g, xor, boundary };
pub const Geometry = @import("universal_manifest_contract.zig").Geometry;
pub const Placement = @import("universal_manifest_contract.zig").Placement;
pub fn keyIndex(key: ComponentKey) u8 {
    return @intFromEnum(key);
}
pub const Manifest = struct {
    pub fn placement(_: *const Manifest, key: ComponentKey) !Placement {
        var offsets: [4]u32 = @splat(0);
        inline for (Airs, logs, 0..) |Air, log, i| {
            const geometry = @import("universal_typed_geometry.zig").manifestGeometryForAir(Air, ThisModule(), @enumFromInt(i), log);
            if (@intFromEnum(key) == i) return .{ .geometry = geometry, .preprocessed_offset = offsets[0], .main_offset = offsets[1], .interaction_offset = offsets[2], .constraint_offset = offsets[3], .claimed_sum_index = i };
            offsets[0] += Air.PREPROCESSED_COLUMN_COUNT;
            offsets[1] += Air.PHYSICAL_MAIN_COLUMN_COUNT;
            offsets[2] += Air.INTERACTION_COLUMN_COUNT;
            offsets[3] += Air.DIRECT_CONSTRAINT_COUNT + Air.INTERACTION_BATCH_COUNT;
        }
        return error.InvalidFixtureComponent;
    }
};
fn ThisModule() type {
    return @import("blake3_proof_fixture.zig");
}
pub fn Component(comptime Air: type) type {
    return @import("universal_typed_component.zig").ComponentForManifest(Air, binding.Binding(Air), ThisModule());
}
pub fn padded(comptime Air: type, allocator: std.mem.Allocator, rows: []const Air.Row, log: u32) ![]Air.Row {
    const result = try allocator.alloc(Air.Row, @as(usize, 1) << @intCast(log));
    @memset(result, @splat(M31.zero()));
    @memcpy(result[0..rows.len], rows);
    return result;
}
pub fn project(comptime Air: type, allocator: std.mem.Allocator, rows: []const Air.Row, log: u32, comptime tree: usize, columns: *std.ArrayList(Column)) !void {
    const count = if (tree == 0) Air.PREPROCESSED_COLUMN_COUNT else Air.PHYSICAL_MAIN_COLUMN_COUNT;
    var values: [count][]M31 = undefined;
    for (&values) |*column| {
        column.* = try allocator.alloc(M31, @as(usize, 1) << @intCast(log));
        @memset(column.*, M31.zero());
        try columns.append(allocator, .{ .log_size = log, .values = column.* });
    }
    @import("framework_device_interaction.zig").writeColumns(Air, rows, log, tree, &values);
}
pub fn register(comptime Air: type, plan: *const binding.Binding(Air).Plan, rows: []const Air.Row, counters: *[2]Counter) !void {
    const lang = @import("../../air/lang/mod.zig");
    for (rows) |row| for (plan.preparedEntries(row)) |entry| {
        const index: usize = if (entry.schema == lang.relation.id(.bitwise)) 0 else if (entry.schema == lang.relation.id(.range_check_8_8)) 1 else continue;
        try counters[index].registerRaw(entry.numerator, entry.values[0..entry.arity]);
    };
}
pub fn tablePreprocessed(allocator: std.mem.Allocator, kind: schema.Kind, columns: *std.ArrayList(Column)) !void {
    const log = schema.logSize(kind);
    const count = schema.arity(kind) + 1;
    var values: [schema.MAX_ARITY + 1][]M31 = undefined;
    for (values[0..count]) |*column| {
        column.* = try allocator.alloc(M31, schema.size(kind));
        try columns.append(allocator, .{ .log_size = log, .values = column.* });
    }
    for (0..schema.size(kind)) |row| {
        const dst = framework.committedRow(row, log);
        values[0][dst] = if (row == 0) M31.one() else M31.zero();
        const tuple = try schema.tupleAt(kind, row);
        for (tuple.slice(), values[1..count]) |value, column| column[dst] = value;
    }
}
pub fn columnLogs(allocator: std.mem.Allocator, columns: []const Column) ![]u32 {
    const result = try allocator.alloc(u32, columns.len);
    for (result, columns) |*log, column| log.* = column.log_size;
    return result;
}
pub fn mixClaims(channel: *Channel, claims: [5]QM31) void {
    channel.mixU32s(&.{ 0x42334343, 1 });
    channel.mixFelts(&claims);
}

/// Derive preprocessing from public inputs/output and the canonical graph only.
/// Dummy main words are discarded by project; no private round trace is read.
pub fn trustedPreprocessed(a: std.mem.Allocator, circuit: u32, initial: [32]u32, output: [16]u32) ![]Column {
    const plan = @import("blake3_compression_plan.zig").canonical();
    var g_rows: [56]g.Row = undefined;
    for (plan.g, &g_rows) |call, *row| {
        var uses: [4]u32 = undefined;
        for (call.output, &uses) |id, *count| count.* = plan.uses[id];
        row.* = try g.logicalRow(.{ .circuit = circuit, .input = call.input, .output = call.output, .uses = uses }, @splat(0));
    }
    var xor_rows: [16]xor.Row = undefined;
    for (plan.xor, &xor_rows) |call, *row| row.* = try xor.logicalRow(.{ .circuit = circuit, .input = call.input, .output = call.output, .uses = plan.uses[call.output] }, @splat(0));
    var boundaries: [48]boundary.Row = undefined;
    for (initial, 0..) |word, i| boundaries[i] = try boundary.logicalRow(circuit, @intCast(i), M31.fromCanonical(plan.uses[i]), word);
    for (output, plan.output, 0..) |word, id, i| boundaries[32 + i] = try boundary.logicalRow(circuit, id, M31.one().neg(), word);
    var columns: std.ArrayList(Column) = .empty;
    try project(g, a, &g_rows, 6, 0, &columns);
    try project(xor, a, &xor_rows, 4, 0, &columns);
    try project(boundary, a, &boundaries, 6, 0, &columns);
    for (kinds) |kind| try tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}

pub fn admitPreprocessedRoot(trusted: Hasher.Hash, supplied: Hasher.Hash) !void {
    if (!std.mem.eql(u8, &trusted, &supplied)) return error.UntrustedBlake3Preprocessing;
}
