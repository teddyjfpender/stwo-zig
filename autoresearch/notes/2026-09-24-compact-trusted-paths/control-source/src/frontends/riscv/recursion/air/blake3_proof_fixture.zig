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
const suite = @import("../blake3_engine_protocol.zig");
pub const Hasher = suite.Hasher;
pub const MerkleChannel = suite.MerkleChannel;
pub const Channel = suite.Channel;
pub const Scheme = prover.pcs.CommitmentSchemeProver(Cpu, Hasher, MerkleChannel);
pub const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel);
pub const Airs = .{ g, xor, boundary };
pub const logs = [_]u32{ 6, 4, 6 };
pub const kinds = [_]schema.Kind{ .bitwise, .range_check_8_8 };

pub const PublicFixture = @import("blake3_fixture_roster.zig").Fixture(false);
pub const Manifest = PublicFixture.Manifest;
pub const Component = PublicFixture.Component;
const row_columns = @import("blake3_row_columns.zig");
pub const padded = row_columns.padded;
pub const project = row_columns.project;
pub const register = row_columns.register;
pub const tablePreprocessed = row_columns.tablePreprocessed;
pub const columnLogs = row_columns.columnLogs;
pub fn mixClaims(channel: *Channel, claims: []const QM31) void {
    channel.mixU32s(&.{ 0x42334343, 1 });
    channel.mixFelts(claims);
}

/// Derive preprocessing from public inputs/output and the canonical graph only.
/// Dummy main words are discarded by project; no private round trace is read.
pub fn trustedPreprocessed(a: std.mem.Allocator, circuit: u32, initial: [32]u32, output: [16]u32) ![]Column {
    const plan = @import("blake3_compression_plan.zig").canonical();
    var g_rows: [56]g.Row = undefined;
    for (plan.g, &g_rows) |call, *row| {
        var uses: [4]u32 = undefined;
        for (call.output, &uses) |id, *count| count.* = plan.uses[id];
        row.* = try g.fixedRow(.{ .circuit = circuit, .input = call.input, .output = call.output, .uses = uses });
    }
    var xor_rows: [16]xor.Row = undefined;
    for (plan.xor, &xor_rows) |call, *row| row.* = try xor.fixedRow(.{ .circuit = circuit, .input = call.input, .output = call.output, .uses = plan.uses[call.output] });
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

const Base = @This();
/// Explicit backend injection for integration gates; no frontend/backend import coupling.
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub const Cpu = Backend;
        pub const Scheme = Base.prover.pcs.CommitmentSchemeProver(Backend, Base.Hasher, Base.MerkleChannel);
        pub const core = Base.core;
        pub const prover = Base.prover;
        pub const g = Base.g;
        pub const xor = Base.xor;
        pub const boundary = Base.boundary;
        pub const binding = Base.binding;
        pub const framework = Base.framework;
        pub const universal = Base.universal;
        pub const schema = Base.schema;
        pub const Counter = Base.Counter;
        pub const Table = Base.Table;
        pub const table_interaction = Base.table_interaction;
        pub const M31 = Base.M31;
        pub const QM31 = Base.QM31;
        pub const Column = Base.Column;
        pub const Hasher = Base.Hasher;
        pub const MerkleChannel = Base.MerkleChannel;
        pub const Channel = Base.Channel;
        pub const Verifier = Base.Verifier;
        pub const Airs = Base.Airs;
        pub const logs = Base.logs;
        pub const kinds = Base.kinds;
        pub const PublicFixture = Base.PublicFixture;
        pub const Manifest = Base.Manifest;
        pub const Component = Base.Component;
        pub const padded = Base.padded;
        pub const project = Base.project;
        pub const register = Base.register;
        pub const tablePreprocessed = Base.tablePreprocessed;
        pub const columnLogs = Base.columnLogs;
        pub const mixClaims = Base.mixClaims;
        pub const trustedPreprocessed = Base.trustedPreprocessed;
        pub const admitPreprocessedRoot = Base.admitPreprocessedRoot;
    };
}
