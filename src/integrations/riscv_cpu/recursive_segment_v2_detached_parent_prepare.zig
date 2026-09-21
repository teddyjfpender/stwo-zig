//! Assemble the two genuinely verified child witnesses into one parent cohort.
//! Admission topology is explicit. Every temporary child/graph/row owner can be
//! destroyed when this returns: PreparedV1 owns the complete immutable snapshot.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const child_mod = @import("recursive_segment_v2_detached_child_transcript.zig");
const cohort = @import("stwo_riscv_frontend").recursion.detached_parent_prepared_v1;
const protocol = @import("stwo_riscv_frontend").recursion.detached_parent_protocol_v1;
const command = @import("recursive_segment_v2_detached_command.zig");
// Compatibility exports for the shared recursion owner.
const shared_owner = @import("stwo_riscv_frontend").recursion.detached_parent_preparation_v1;
pub const ProfileV1 = shared_owner.ProfileV1;
pub const TINY_MEMORY_PROFILE_V1 = shared_owner.TINY_MEMORY_PROFILE_V1;
pub const TINY_MEMORY_CONTINUATION_PROFILE_V1 = shared_owner.TINY_MEMORY_CONTINUATION_PROFILE_V1;
pub const Prepared = shared_owner.Prepared;
pub const prepare = shared_owner.prepare;
pub const prepareWithMode = shared_owner.prepareWithMode;
pub const prepareParents = shared_owner.prepareParents;

/// Repository fixture ingress keeps independent expected inputs/key pins outside
/// producer directories. It checks bytes before any recursive preparation.
fn loadFixture(comptime family: child_mod.Family, allocator: std.mem.Allocator, comptime side: []const u8) !*child_mod.OwnedFor(family) {
    const dir_name = try std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_PARENT_" ++ side ++ "_BUNDLE");
    defer allocator.free(dir_name);
    const pin = try std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_PARENT_" ++ side ++ "_KEY_SHA256");
    defer allocator.free(pin);
    const expected_path = try std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_PARENT_" ++ side ++ "_EXPECTED_WIRE");
    defer allocator.free(expected_path);
    const args = try command.parseArguments(&.{ dir_name, pin, expected_path });
    return loadAdmitted(family, allocator, args);
}
pub fn loadAdmittedChild(allocator: std.mem.Allocator, args: command.ArgumentsV1) !*child_mod.OwnedV1 {
    return loadAdmitted(.segment, allocator, args);
}
pub fn loadAdmittedParent(allocator: std.mem.Allocator, args: command.ArgumentsV1) !*child_mod.ParentOwnedV1 {
    return loadAdmitted(.parent, allocator, args);
}
fn loadAdmitted(comptime family: child_mod.Family, allocator: std.mem.Allocator, args: command.ArgumentsV1) !*child_mod.OwnedFor(family) {
    const Command = if (family == .segment) command else @import("recursive_segment_v2_detached_parent_command.zig");
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var dir = try std.fs.cwd().openDir(args.directory, .{});
    defer dir.close();
    const key = try dir.readFileAlloc(a, "key.json", Command.MAX_KEY_BYTES);
    const expected_bytes = try std.fs.cwd().readFileAlloc(a, args.expected_wire_path, Command.MAX_INPUT_BYTES);
    const expected = if (family == .segment) try command.OwnedExpectedV1.decode(a, expected_bytes) else try Command.decodeExpected(a, expected_bytes);
    const claims_bytes = try dir.readFileAlloc(a, "claims.json", Command.MAX_INPUT_BYTES);
    const claims = try Command.decodeClaims(a, claims_bytes);
    const proof = try dir.readFileAlloc(a, "proof.bin", claims.proof_bytes);
    if (proof.len != claims.proof_bytes or !std.meta.eql(Command.hash(proof), claims.proof_sha256)) return error.DetachedParentFixtureBytesChanged;
    return child_mod.OwnedFor(family).init(allocator, key, args.independent_key_sha256, if (family == .segment) &expected.data else &expected, claims.claims, proof);
}

test "detached parent prepares two genuine children with one exact routing plan" {
    const allocator = std.testing.allocator;
    const family_text = std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_PARENT_INPUT_FAMILY") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => try allocator.dupe(u8, "segment"),
        else => return err,
    };
    defer allocator.free(family_text);
    const family = std.meta.stringToEnum(child_mod.Family, family_text) orelse return error.InvalidDetachedChildFamily;
    var prepared = blk: {
        if (family == .parent) {
            const left = try loadFixture(.parent, allocator, "LEFT");
            defer left.deinit();
            const right = try loadFixture(.parent, allocator, "RIGHT");
            defer right.deinit();
            break :blk try prepareParents(allocator, .{ left, right }, .root, null);
        }
        const left = try loadFixture(.segment, allocator, "LEFT");
        defer left.deinit();
        const right = try loadFixture(.segment, allocator, "RIGHT");
        defer right.deinit();
        break :blk prepare(allocator, .{ left, right }, TINY_MEMORY_PROFILE_V1) catch |err| {
            std.debug.print("DETACHED_PARENT_PREPARE_ERROR {s}\n", .{@errorName(err)});
            return err;
        };
    };
    defer prepared.deinit();
    try protocol.validateExpected(&prepared.expected);
    try prepared.cohort.parameters().validate(prepared.cohort.manifest());
    const Engine = @import("recursive_segment_v2_detached_parent_proof.zig").CpuEngine;
    const TreeStorage = @import("stwo_riscv_frontend").recursion.transaction_storage_v2.TreeStorageForManifest(Engine, cohort.manifest_mod);
    var main = try TreeStorage.init(allocator, prepared.cohort.manifest(), 1);
    defer main.deinit();
    try prepared.cohort.fillMainInto(main.columns);
    const closure = try prepared.cohort.auditExactTupleClosure(&prepared.expected, main.columns);
    // Borrowed public inputs must survive destination writes unchanged.
    const alias_words = main.columns[0][0..prepared.expected.len];
    const original_words = alias_words.*;
    @memcpy(alias_words, &prepared.expected);
    try std.testing.expectError(error.DestinationAlias, prepared.cohort.finalizeMainInto(alias_words, main.columns));
    try std.testing.expectEqualSlices(core.fields.m31.M31, &prepared.expected, alias_words);
    alias_words.* = original_words;
    var cold_main_hash = std.crypto.hash.sha2.Sha256.init(.{});
    for (main.columns) |column| cold_main_hash.update(std.mem.sliceAsBytes(column));
    const fused_closure = try prepared.cohort.finalizeMainInto(&prepared.expected, main.columns);
    try std.testing.expectEqualDeep(closure, fused_closure);
    var fused_main_hash = std.crypto.hash.sha2.Sha256.init(.{});
    for (main.columns) |column| fused_main_hash.update(std.mem.sliceAsBytes(column));
    try std.testing.expectEqual(cold_main_hash.finalResult(), fused_main_hash.finalResult());
    std.debug.print("DETACHED_PARENT_EXACT_CLOSURE {any}\n", .{closure});
    const range_placement = prepared.cohort.manifest().placements[35].?;
    const range_row = frontend.recursion.air.range_check_8_8_bridge.committedRow(0);
    const multiplicity = &main.columns[range_placement.main_offset][range_row];
    const original = multiplicity.*;
    defer multiplicity.* = original;
    multiplicity.* = original.add(core.fields.m31.M31.one());
    try std.testing.expectError(error.DetachedParentRangeMainChanged, prepared.cohort.auditExactTupleClosure(&prepared.expected, main.columns));
    multiplicity.* = original;
    var wrong_expected = prepared.expected;
    const session_start = frontend.recursion.span_continuation_v1.SESSION_START;
    wrong_expected[session_start] = wrong_expected[session_start].add(core.fields.m31.M31.one());
    try std.testing.expectError(error.DetachedParentExactTupleClosureMismatch, prepared.cohort.finalizeMainInto(&wrong_expected, main.columns));
    for (main.columns) |column| for (column) |word| try std.testing.expect(word.isZero());
    try std.testing.expectError(error.DetachedParentMainNotGenerated, prepared.cohort.auditExactTupleClosure(&prepared.expected, main.columns));
    _ = try prepared.cohort.finalizeMainInto(&prepared.expected, main.columns);
    std.debug.print("DETACHED_PARENT_MAIN_FINALIZATION cold_columns_equal=true exact_closure_equal=true failed_columns_zeroed=true failed_state_unpublished=true retry_closed=true\n", .{});
    std.debug.print("DETACHED_PARENT_ACTUAL_PREPARE preparation_ns={d} child_owners_destroyed=true root_words={d} proof_verified=false\n", .{ prepared.preparation_ns, prepared.expected.len });
}
