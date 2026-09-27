//! Full-width execution transcript and verifier-owned native preprocessing.
//! The caller must authenticate the commitment plan before using this protocol.
const std = @import("std");
const core = @import("stwo_core");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const statement = @import("../air/statement.zig");
const admission = @import("blake3_commitment_plan.zig");
const opcode = @import("opcode_trace.zig");
const tables = @import("../recursion/air/blake3_row_columns.zig");
const Q = core.fields.qm31.QM31;
pub fn mix(channel: anytype, config: core.pcs.PcsConfig, shape: *const statement.Blake3ExecutionStatement, pin: admission.Admission) !void {
    try validateConfig(config);
    try shape.validateBlake3Execution();
    try pin.validatePublic(&shape.public_data);
    channel.mixU32s(&.{ 0x42334558, 2 }); // B3EX / version 2: native authority binding
    config.mixInto(channel);
    channel.mixU32s(&.{@intFromBool(config.lifting_log_size != null)});
    mixDigest(channel, @import("../air/lang/relation.zig").registryOrderDigest());
    for (shape.component_descs[0..shape.n_components]) |desc| {
        mixDigest(channel, @import("../air/lang/opcode_composition_manifest.zig").BY_FAMILY[@intFromEnum(desc.family)].authority_digest);
    }
    shape.public_data.mixInto(channel);
    shape.mixShardManifest(channel);
    var limbs: [16]u32 = undefined;
    for (&limbs, 0..) |*limb, i| limb.* = std.mem.readInt(u16, pin.expected_id[i * 2 ..][0..2], .little);
    channel.mixU32s(&limbs);
}
pub fn mixClaims(channel: anytype, shape: *const statement.Blake3ExecutionStatement, claims: *const statement.RiscVInteractionClaim, hashes: []const Q) !void {
    if (claims.n_components != shape.n_components or claims.n_infra != shape.n_infra or hashes.len != @import("blake3_commitment_components.zig").Airs.len) return error.InvalidInteractionClaim;
    channel.mixU32s(&.{ 0x42334543, 1 });
    for (shape.component_descs[0..shape.n_components], 0..) |desc, i| channel.mixFelts(try claims.opcodeClaims(desc.family, i));
    for (shape.infra_descs[0..shape.n_infra], 0..) |desc, i| channel.mixFelts(try claims.infraClaims(desc.kind, i));
    channel.mixFelts(hashes);
}
/// Append fixed execution columns without consulting any execution witness.
/// Destination allocations belong to the caller (normally a preparation arena).
pub fn nativePreprocessed(a: std.mem.Allocator, shape: *const statement.Blake3ExecutionStatement, out: *std.ArrayList(Column)) !void {
    try shape.validateBlake3Execution();
    for (shape.component_descs[0..shape.n_components]) |desc| try flags(a, desc.log_size, desc.n_rows, out);
    for (shape.infra_descs[0..shape.n_infra]) |desc| {
        if (desc.kind == .clock_update) {
            try flags(a, desc.log_size, desc.n_rows, out);
        } else {
            const kind = statement.tableKind(desc.kind) orelse return error.LegacyCommitmentInBlake3Execution;
            try tables.tablePreprocessed(a, kind, out);
        }
    }
}
fn flags(a: std.mem.Allocator, log: u32, rows: u32, out: *std.ArrayList(Column)) !void {
    try out.append(a, .{ .log_size = log, .values = try opcode.generateIsFirst(a, log) });
    try out.append(a, .{ .log_size = log, .values = try opcode.generateIsActive(a, log, rows) });
}

/// PCS geometry derives only from admitted statements and the typed roster.
/// No prover-owned column buffer is an authority for verifier log sizes.
pub fn columnLogs(a: std.mem.Allocator, shape: *const statement.Blake3ExecutionStatement, hash_logs: [@import("blake3_commitment_components.zig").Airs.len]u32, comptime tree: enum { main, interaction }) ![]u32 {
    try shape.validateBlake3Execution();
    var logs: std.ArrayList(u32) = .empty;
    errdefer logs.deinit(a);
    for (shape.component_descs[0..shape.n_components]) |desc| {
        const count = if (tree == .main) desc.n_columns else @import("../air/lookups/opcode_interaction.zig").nColumns(desc.family);
        try logs.appendNTimes(a, desc.log_size, count);
    }
    for (shape.infra_descs[0..shape.n_infra]) |desc| {
        const count = if (tree == .main) desc.n_columns else statement.nInteractionColsForInfra(desc.kind);
        try logs.appendNTimes(a, desc.log_size, count);
    }
    inline for (@import("blake3_commitment_components.zig").Airs, 0..) |Air, i| {
        if (hash_logs[i] == 0 or hash_logs[i] > 24) return error.InvalidTraceShape;
        try logs.appendNTimes(a, hash_logs[i], if (tree == .main) Air.PHYSICAL_MAIN_COLUMN_COUNT else Air.INTERACTION_COLUMN_COUNT);
    }
    return logs.toOwnedSlice(a);
}

pub fn mixDigest(channel: anytype, digest: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[i * 4 ..][0..4], .little);
    channel.mixU32s(&words);
}
pub fn validateConfig(config: core.pcs.PcsConfig) !void {
    const fri = config.fri_config;
    _ = try core.fri.FriConfig.init(fri.log_last_layer_degree_bound, fri.log_blowup_factor, fri.n_queries);
    if (config.pow_bits > core.channel.blake3.MAX_POW_BITS or fri.n_queries == 0 or fri.n_queries > 65536 or fri.fold_step == 0 or fri.fold_step > 4) return error.InvalidExecutionConfig;
    if (config.lifting_log_size) |log| if (log > 30) return error.InvalidExecutionConfig;
}
