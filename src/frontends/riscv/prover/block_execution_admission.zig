//! Deterministic execution-instance descriptors for the block PCS manifest.
//! Each field is independently derived from the prepared verifier or the
//! admitted span; no caller-provided identity is used as another field's alias.
const std = @import("std");
const manifest = @import("block_commitment_manifest.zig");
const spans = @import("../recursion/span_statement_blake3.zig");
const Profile = @import("../isa/execution_profile.zig").ExecutionProfile;

pub fn derive(prepared: anytype, expected: [32]u8, statement: spans.SpanStatement, profile: Profile, index: u32) !manifest.Admission {
    try prepared.validate(expected);
    try statement.validate();
    if (statement.body != .executed or statement.slots.height != 0 or statement.body.executed.segment_count != 1 or statement.slots.first != index) return error.InvalidExecutionSpan;
    const executed = statement.body.executed;
    const words = try statement.canonicalWords();
    const statement_id = (try spans.identity.hash(&words, .statement)).bytes;
    const relation_id = @import("../air/lang/relation.zig").registryOrderDigest();
    var air = std.crypto.hash.Blake3.init(.{});
    air.update("stwo.block.execution-air.v1\x00");
    var profile_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &profile_bytes, @intFromEnum(profile), .little);
    air.update(&profile_bytes);
    air.update(&relation_id);
    var air_id: [32]u8 = undefined;
    air.final(&air_id);
    var geometry = std.crypto.hash.Blake3.init(.{});
    geometry.update("stwo.block.execution-geometry.v1\x00");
    var source_bytes: u64 = 0;
    var max_log: u8 = 1;
    for (prepared.logs) |tree| {
        var count: [4]u8 = undefined;
        std.mem.writeInt(u32, &count, @intCast(tree.len), .little);
        geometry.update(&count);
        for (tree) |log| {
            if (log == 0 or log > 30) return error.InvalidComponentGeometry;
            max_log = @max(max_log, @as(u8, @intCast(log)));
            var encoded: [4]u8 = undefined;
            std.mem.writeInt(u32, &encoded, log, .little);
            geometry.update(&encoded);
            source_bytes = try std.math.add(u64, source_bytes, @as(u64, 4) << @intCast(log));
        }
    }
    var geometry_id: [32]u8 = undefined;
    geometry.final(&geometry_id);
    if (executed.cycle_count > (@as(u64, 1) << @as(u6, @intCast(max_log)))) return error.InvalidComponentGeometry;
    return .{
        .instance = .{ .index = index, .kind = .execution, .first_row = executed.first_cycle, .rows = executed.cycle_count, .log_rows = max_log, .source_bytes = source_bytes },
        .air_id = air_id,
        .key_id = expected,
        .statement_id = statement_id,
        .geometry_id = geometry_id,
        .fixed_root = prepared.root,
    };
}

pub fn context(statements: [2]spans.SpanStatement, config: @import("stwo_core").pcs.PcsConfig) !manifest.Context {
    for (statements) |statement| try statement.validate();
    const combined = try spans.SpanStatement.fold(statements[0], statements[1]);
    const words = try statements[0].canonicalWords();
    const job_id = (try spans.identity.hash(&words, .job)).bytes;
    var rows: [@typeInfo(@import("block_component_plan.zig").Kind).@"enum".fields.len]u64 = @splat(0);
    rows[@intFromEnum(@import("block_component_plan.zig").Kind.execution)] = combined.body.executed.cycle_count;
    return .{ .job_id = job_id, .relation_abi_id = @import("../air/lang/relation.zig").registryOrderDigest(), .config = config, .rows = rows };
}
