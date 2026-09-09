//! Assemble the two genuinely verified child witnesses into one parent cohort.
//! Admission topology is explicit. Every temporary child/graph/row owner can be
//! destroyed when this returns: PreparedV1 owns the complete immutable snapshot.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const child_mod = @import("recursive_segment_v2_detached_child_transcript.zig");
const prefix_mod = @import("recursive_segment_v2_detached_prefix.zig");
const transcript_mod = @import("recursive_segment_v2_detached_pcs_rows.zig");
const pcs_mod = @import("recursive_segment_v2_detached_pcs_checks.zig");
const boundary_mod = @import("recursive_segment_v2_detached_boundary.zig");
const composition_mod = @import("recursive_segment_v2_detached_composition.zig");
const statement_mod = @import("recursive_segment_v2_detached_parent_statement.zig");
const arithmetic_mod = @import("recursive_segment_v2_detached_parent_arithmetic.zig");
const base_mod = @import("recursive_segment_v2_detached_parent_base_rows.zig");
const cohort = @import("recursive_segment_v2_detached_parent_cohort.zig");
const protocol = @import("recursive_segment_v2_detached_parent_protocol.zig");
const command = @import("recursive_segment_v2_detached_command.zig");
pub const ProfileV1 = struct {
    sections: [2]boundary_mod.SectionProfileV1,
    memory: [2]boundary_mod.MemoryProfileV1,
};
pub const TINY_MEMORY_PROFILE_V1 = ProfileV1{
    .sections = .{ .{ .counts = .{ 1, 1, 0, 1 } }, .{ .counts = .{ 1, 1, 1, 1 } } },
    .memory = .{ .{ .entry_addresses = &.{1048832}, .exit_addresses = &.{1048832} }, .{ .entry_addresses = &.{1048832}, .exit_addresses = &.{1048832} } },
};
pub const Prepared = struct {
    cohort: *cohort.PreparedV1,
    expected: protocol.ExpectedV1,
    child_key_sha256: [2][32]u8,
    preparation_ns: u64,
    publication_mode: protocol.PublicationMode,
    pub fn deinit(self: *Prepared) void {
        self.cohort.deinit();
        self.* = undefined;
    }
};
pub fn prepare(allocator: std.mem.Allocator, children: [2]*const child_mod.OwnedV1, profile: ProfileV1) !Prepared {
    return prepareWithMode(allocator, children, profile, .root);
}
pub fn prepareWithMode(allocator: std.mem.Allocator, children: [2]*const child_mod.OwnedV1, profile: ProfileV1, mode: protocol.PublicationMode) !Prepared {
    var timer = try std.time.Timer.start();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var prefixes: [2]*const prefix_mod.OwnedV1 = undefined;
    var transcripts: [2]*const transcript_mod.OwnedV1 = undefined;
    var checks: [2]*const pcs_mod.OwnedV1 = undefined;
    var boundaries: [2]*const boundary_mod.OwnedV1 = undefined;
    var compositions: [2]*const composition_mod.OwnedV1 = undefined;
    for (children, 0..) |child, i| {
        const lane: u32 = @intCast(i + 1);
        prefixes[i] = try prefix_mod.OwnedV1.init(a, child, lane);
        transcripts[i] = try transcript_mod.OwnedV1.init(a, child, prefixes[i], lane);
        checks[i] = try pcs_mod.OwnedV1.init(a, child, lane);
        boundaries[i] = try boundary_mod.OwnedV1.init(a, child, profile.sections[i], profile.memory[i]);
        compositions[i] = try composition_mod.OwnedV1.init(a, child);
        std.debug.print("DETACHED_PARENT_CHILD lane={d} preparation_ns={d}\n", .{ lane, timer.read() });
    }
    const statement = try statement_mod.OwnedV1.initWithMode(a, boundaries[0], boundaries[1], mode);
    const arithmetic = try arithmetic_mod.OwnedV1.init(a, .{ .composition = compositions, .boundary = boundaries, .pcs = checks }, statement);
    const base = try base_mod.OwnedV1.init(a, prefixes, transcripts, checks);
    var logical = base.logicalRows();
    const graph = arithmetic.view();
    inline for (.{ 11, 12, 13, 30, 31, 32 }) |row| {
        const index = cohort.logicalIndex(row);
        if (logical[index].len != 0) return error.DetachedParentDuplicateRowAuthority;
        logical[index] = graph.logical[index];
    }
    var calls: std.ArrayList(cohort.ProviderCall) = .empty;
    try calls.appendSlice(a, base.providerCalls());
    try calls.appendSlice(a, graph.provider);
    var logical_bytes: usize = 0;
    inline for (cohort.LOGICAL_ROWS, 0..) |entry, index| {
        const bytes = logical[index].len * entry.Air.LOGICAL_INPUT_COUNT * @sizeOf(core.fields.m31.M31);
        logical_bytes += bytes;
        std.debug.print("DETACHED_PARENT_ROW row={d} rows={d} logical_bytes={d}\n", .{ @intFromEnum(entry.row), logical[index].len, bytes });
    }
    std.debug.print("DETACHED_PARENT_PREPARATION rows_bytes={d} providers={d} graph_ns={d} snapshot_pending=true\n", .{ logical_bytes, calls.items.len, timer.read() });
    const prepared = try cohort.PreparedV1.init(allocator, logical, calls.items);
    errdefer prepared.deinit();
    return .{ .cohort = prepared, .expected = graph.parent_words, .child_key_sha256 = .{ children[0].keySha256(), children[1].keySha256() }, .preparation_ns = timer.read(), .publication_mode = mode };
}

/// Repository fixture ingress keeps independent expected inputs/key pins outside
/// producer directories. It checks bytes before any recursive preparation.
fn loadChild(allocator: std.mem.Allocator, comptime side: []const u8) !*child_mod.OwnedV1 {
    const dir_name = try std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_PARENT_" ++ side ++ "_BUNDLE");
    defer allocator.free(dir_name);
    const pin = try std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_PARENT_" ++ side ++ "_KEY_SHA256");
    defer allocator.free(pin);
    const expected_path = try std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_PARENT_" ++ side ++ "_EXPECTED_WIRE");
    defer allocator.free(expected_path);
    const args = try command.parseArguments(&.{ dir_name, pin, expected_path });
    return loadAdmittedChild(allocator, args);
}
pub fn loadAdmittedChild(allocator: std.mem.Allocator, args: command.ArgumentsV1) !*child_mod.OwnedV1 {
    var dir = try std.fs.cwd().openDir(args.directory, .{});
    defer dir.close();
    const key = try dir.readFileAlloc(allocator, "key.json", command.MAX_KEY_BYTES);
    defer allocator.free(key);
    const expected_bytes = try std.fs.cwd().readFileAlloc(allocator, args.expected_wire_path, command.MAX_INPUT_BYTES);
    defer allocator.free(expected_bytes);
    var expected = try command.OwnedExpectedV1.decode(allocator, expected_bytes);
    defer expected.deinit();
    const claims_bytes = try dir.readFileAlloc(allocator, "claims.json", command.MAX_INPUT_BYTES);
    defer allocator.free(claims_bytes);
    const claims = try command.decodeClaims(allocator, claims_bytes);
    const proof = try dir.readFileAlloc(allocator, "proof.bin", claims.proof_bytes);
    defer allocator.free(proof);
    if (proof.len != claims.proof_bytes or !std.meta.eql(command.hash(proof), claims.proof_sha256)) return error.DetachedParentFixtureBytesChanged;
    return child_mod.OwnedV1.init(allocator, key, args.independent_key_sha256, &expected.data, claims.claims, proof);
}
test "detached parent prepares two genuine children with one exact routing plan" {
    const allocator = std.testing.allocator;
    var prepared = blk: {
        const left = try loadChild(allocator, "LEFT");
        defer left.deinit();
        const right = try loadChild(allocator, "RIGHT");
        defer right.deinit();
        break :blk prepare(allocator, .{ left, right }, TINY_MEMORY_PROFILE_V1) catch |err| {
            std.debug.print("DETACHED_PARENT_PREPARE_ERROR {s}\n", .{@errorName(err)});
            return err;
        };
    };
    defer prepared.deinit();
    try protocol.validateExpected(&prepared.expected);
    try prepared.cohort.parameters().validate(prepared.cohort.manifest());
    const Engine = @import("recursive_segment_v2_outer_engine.zig").Engine;
    const TreeStorage = @import("recursive_segment_v2_outer_engine_storage.zig").TreeStorageForManifest(Engine, cohort.manifest_mod);
    var main = try TreeStorage.init(allocator, prepared.cohort.manifest(), 1);
    defer main.deinit();
    try prepared.cohort.fillMainInto(main.columns);
    const closure = try prepared.cohort.auditExactTupleClosure(&prepared.expected, main.columns);
    std.debug.print("DETACHED_PARENT_EXACT_CLOSURE {any}\n", .{closure});
    std.debug.print("DETACHED_PARENT_ACTUAL_PREPARE preparation_ns={d} child_owners_destroyed=true root_words={d} proof_verified=false\n", .{ prepared.preparation_ns, prepared.expected.len });
}
