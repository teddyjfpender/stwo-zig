//! Maintained development producer for one detached two-child parent candidate.
//! Child and optional parent admission come from explicit command arguments.
//! Emitted artifacts must be accepted by the separate parent verifier process.
const std = @import("std");
const child_command = @import("recursive_segment_v2_detached_command.zig");
const prepare = @import("recursive_segment_v2_detached_parent_prepare.zig");
const proof = @import("recursive_segment_v2_detached_parent_proof.zig");
const command = @import("recursive_segment_v2_detached_parent_command.zig");
const protocol = @import("recursive_segment_v2_detached_parent_protocol.zig");
pub const PROFILE = "tiny-memory-root-v2";
pub const INTERMEDIATE_PROFILE = "tiny-memory-span-v2";
pub const CONTINUATION_PROFILE = "tiny-memory-continuation-span-v2";
pub const PARENT_ROOT_PROFILE = "tiny-parent-root-v2";
pub const PARENT_SPAN_PROFILE = "tiny-parent-span-v2";
pub const ArgumentsV1 = struct {
    output: []const u8,
    proof_profile: protocol.ProfileV1 = .detached_continuation_development_q3_v2,
    publication_mode: protocol.PublicationMode = .root,
    memory_profile: enum { initial, continuation } = .initial,
    child_family: @import("recursive_segment_v2_detached_child_transcript.zig").Family = .segment,
    children: [2]child_command.ArgumentsV1,
    parent_key: ?struct { path: []const u8, sha256: [32]u8 } = null,
};

/// Reviewed fixture topologies and one unambiguous argument order.
pub fn parseArguments(args: []const []const u8) !ArgumentsV1 {
    if ((args.len < 9 or (args.len - 9) % 2 != 0) or !std.mem.eql(u8, args[0], "--profile") or
        (!std.mem.eql(u8, args[1], PROFILE) and !std.mem.eql(u8, args[1], INTERMEDIATE_PROFILE) and !std.mem.eql(u8, args[1], CONTINUATION_PROFILE) and !std.mem.eql(u8, args[1], PARENT_ROOT_PROFILE) and !std.mem.eql(u8, args[1], PARENT_SPAN_PROFILE)) or args[2].len == 0 or std.mem.startsWith(u8, args[2], "--"))
        return error.ExpectedExplicitTinyProfileOutputAndTwoAdmittedChildren;
    var result = ArgumentsV1{ .child_family = if (std.mem.eql(u8, args[1], PARENT_ROOT_PROFILE) or std.mem.eql(u8, args[1], PARENT_SPAN_PROFILE)) .parent else .segment, .memory_profile = if (std.mem.eql(u8, args[1], CONTINUATION_PROFILE)) .continuation else .initial, .publication_mode = if (std.mem.eql(u8, args[1], PROFILE) or std.mem.eql(u8, args[1], PARENT_ROOT_PROFILE)) .root else .intermediate, .output = args[2], .children = .{ try child_command.parseArguments(args[3..6]), try child_command.parseArguments(args[6..9]) } };
    var key_path: ?[]const u8 = null;
    var key_pin: ?[32]u8 = null;
    var profile_seen = false;
    var index: usize = 9;
    while (index < args.len) : (index += 2) {
        const option = args[index];
        const value = args[index + 1];
        if (std.mem.eql(u8, option, "--proof-profile")) {
            if (profile_seen) return error.DuplicateParentOption;
            profile_seen = true;
            result.proof_profile = std.meta.stringToEnum(protocol.ProfileV1, value) orelse return error.DetachedParentProfileMismatch;
        } else if (std.mem.eql(u8, option, "--parent-key")) {
            if (key_path != null) return error.DuplicateParentOption;
            if (value.len == 0 or std.mem.startsWith(u8, value, "--")) return error.ExpectedIndependentParentKeyAndHash;
            key_path = value;
        } else if (std.mem.eql(u8, option, "--parent-key-sha256")) {
            if (key_pin != null) return error.DuplicateParentOption;
            if (value.len != 64) return error.ExpectedIndependentParentKeyAndHash;
            var pin: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&pin, value);
            key_pin = pin;
        } else return error.UnknownParentOption;
    }
    if ((key_path == null) != (key_pin == null)) return error.ExpectedIndependentParentKeyAndHash;
    if (key_path) |path| result.parent_key = .{ .path = path, .sha256 = key_pin.? };
    return result;
}

pub const CandidateReportV1 = struct {
    endpoint: []const u8 = "segment_v2_detached_two_child_parent_candidate_development_q3",
    profile: []const u8,
    publication_mode: protocol.PublicationMode,
    proof_profile: protocol.ProfileV1,
    status: []const u8 = "unverified_candidate",
    verified: bool = false,
    development_only: bool = true,
    child_owners_destroyed: bool = true,
    producer_destroyed: bool = true,
    reused_admitted_parent_key: bool,
    child_key_sha256: [2][32]u8,
    artifacts: command.CandidateHashesV1,
    candidate_root_words_sha256: [32]u8,
    circuit_identity: [32]u8,
    preparation_ns: u64,
    key_preparation_ns: u64,
    proof_ns: u64,
    request_ns: u64,
};

pub fn run(allocator: std.mem.Allocator, args: ArgumentsV1) !CandidateReportV1 {
    return runWithEngine(proof.CpuEngine, allocator, args);
}

pub fn runWithEngine(comptime Engine: type, allocator: std.mem.Allocator, args: ArgumentsV1) !CandidateReportV1 {
    var timer = try std.time.Timer.start();
    var report = try runInner(Engine, allocator, args);
    report.request_ns = timer.read(); // Includes candidate/key/producer cleanup.
    return report;
}
fn runInner(comptime Engine: type, allocator: std.mem.Allocator, args: ArgumentsV1) !CandidateReportV1 {
    try requireNewOutput(args.output);
    if (@hasDecl(Engine.Backend, "admitHostProving"))
        try Engine.Backend.admitHostProving(.recursive_preparation);
    var admitted_key: ?*command.OwnedKeyV1 = null;
    defer if (admitted_key) |key| key.deinit();
    if (args.parent_key) |input| {
        const bytes = try std.fs.cwd().readFileAlloc(allocator, input.path, command.MAX_KEY_BYTES);
        defer allocator.free(bytes);
        admitted_key = try command.OwnedKeyV1.admit(allocator, bytes, input.sha256);
        if (admitted_key.?.key().profile != args.proof_profile) return error.DetachedParentProfileMismatch;
    }
    var expected: protocol.ExpectedV1 = undefined;
    var child_pins: [2][32]u8 = undefined;
    var preparation_ns: u64 = undefined;
    var candidate = blk: {
        var prepared = child_scope: {
            if (args.child_family == .parent) {
                const left = try prepare.loadAdmittedParent(allocator, args.children[0]);
                defer left.deinit();
                const right = try prepare.loadAdmittedParent(allocator, args.children[1]);
                defer right.deinit();
                try requireChildProfiles(args.proof_profile, left, right);
                break :child_scope try prepare.prepareParents(allocator, .{ left, right }, args.publication_mode);
            }
            const left = try prepare.loadAdmittedChild(allocator, args.children[0]);
            defer left.deinit();
            const right = try prepare.loadAdmittedChild(allocator, args.children[1]);
            defer right.deinit();
            try requireChildProfiles(args.proof_profile, left, right);
            break :child_scope try prepare.prepareWithMode(allocator, .{ left, right }, switch (args.memory_profile) {
                .initial => prepare.TINY_MEMORY_PROFILE_V1,
                .continuation => prepare.TINY_MEMORY_CONTINUATION_PROFILE_V1,
            }, args.publication_mode);
        };
        // Both verified child owners are already destroyed here. Prepared owns
        // copied logical rows, provider calls, and canonical public root words.
        defer prepared.deinit();
        expected = prepared.expected;
        child_pins = prepared.child_key_sha256;
        preparation_ns = prepared.preparation_ns;
        break :blk try proof.produceWithEngine(Engine, allocator, prepared.cohort, &expected, child_pins, prepared.publication_mode, if (admitted_key) |key| key.key() else null, args.proof_profile);
    };
    // The cohort and every original proof/prover component have been destroyed.
    // Only durable candidate bytes and fixed claims survive this boundary.
    defer candidate.deinit();
    const expected_json = try command.encodeExpected(allocator, &expected);
    defer allocator.free(expected_json);
    const artifacts = try command.retainCandidate(allocator, args.output, candidate.key_json, candidate.claims, candidate.proof_bytes);
    var dir = try std.fs.cwd().openDir(args.output, .{});
    defer dir.close();
    var expected_file = try dir.createFile("candidate-rootwords.json", .{ .exclusive = true });
    defer expected_file.close();
    try expected_file.writeAll(expected_json);
    return .{
        .profile = if (args.child_family == .parent) (if (args.publication_mode == .root) PARENT_ROOT_PROFILE else PARENT_SPAN_PROFILE) else if (args.memory_profile == .continuation) CONTINUATION_PROFILE else if (args.publication_mode == .root) PROFILE else INTERMEDIATE_PROFILE,
        .endpoint = if (args.proof_profile == .recursive_q193_v1) "segment_v2_detached_two_child_parent_candidate_q193" else "segment_v2_detached_two_child_parent_candidate_development_q3",
        .proof_profile = args.proof_profile,
        .publication_mode = args.publication_mode,
        .reused_admitted_parent_key = admitted_key != null,
        .child_key_sha256 = child_pins,
        .artifacts = artifacts,
        .candidate_root_words_sha256 = command.hash(expected_json),
        .circuit_identity = candidate.circuit_identity,
        .preparation_ns = preparation_ns,
        .key_preparation_ns = candidate.prepare_ns,
        .proof_ns = candidate.prove_ns,
        .request_ns = 0,
    };
}

/// Owners have already verified their child proofs against independent keys.
/// This policy reads that immutable admission once, before AIR allocation.
fn requireChildProfiles(profile: protocol.ProfileV1, left: anytype, right: @TypeOf(left)) !void {
    if (profile == .recursive_q193_v1 and
        (left.key().profile != .recursive_q193_v1 or right.key().profile != .recursive_q193_v1))
        return error.DetachedParentChildSecurityMismatch;
}

fn requireNewOutput(path: []const u8) !void {
    // Fail before witness preparation if the directory cannot be created.
    // retainCandidate repeats exclusive creation after proving to cover races.
    var parent = try std.fs.cwd().openDir(std.fs.path.dirname(path) orelse ".", .{});
    defer parent.close();
    parent.access(std.fs.path.basename(path), .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    return error.DetachedParentOutputAlreadyExists;
}

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const report = try run(allocator, try parseArguments(args[1..]));
    const json = try std.json.Stringify.valueAlloc(allocator, report, .{});
    defer allocator.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}

test "detached parent producer requires explicit profile and independent child and parent pins" {
    const pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const valid = [_][]const u8{ "--profile", PROFILE, "out", "left", pin, "left-wire.json", "right", pin, "right-wire.json" };
    const args = try parseArguments(&valid);
    try std.testing.expect(args.parent_key == null);
    try std.testing.expectEqualStrings("right-wire.json", args.children[1].expected_wire_path);
    const with_parent = valid ++ .{ "--parent-key", "parent.json", "--parent-key-sha256", pin };
    const pinned = try parseArguments(&with_parent);
    try std.testing.expectEqualStrings("parent.json", pinned.parent_key.?.path);
    try std.testing.expectError(error.ExpectedExplicitTinyProfileOutputAndTwoAdmittedChildren, parseArguments(valid[2..]));
    try std.testing.expectError(error.ExpectedIndependentParentKeyAndHash, parseArguments(with_parent[0..11]));
    const strong = try parseArguments(&(valid ++ .{ "--proof-profile", "recursive_q193_v1" }));
    try std.testing.expectEqual(.recursive_q193_v1, strong.proof_profile);
    try std.testing.expectError(error.DuplicateParentOption, parseArguments(&(valid ++ .{ "--proof-profile", "recursive_q193_v1", "--proof-profile", "recursive_q193_v1" })));
    try std.testing.expectError(error.DetachedParentProfileMismatch, parseArguments(&(valid ++ .{ "--proof-profile", "unsupported" })));
    var continuation = valid;
    continuation[1] = CONTINUATION_PROFILE;
    const continued = try parseArguments(&continuation);
    try std.testing.expectEqual(.intermediate, continued.publication_mode);
    try std.testing.expectEqual(.continuation, continued.memory_profile);
    var recursive = valid;
    recursive[1] = PARENT_ROOT_PROFILE;
    const parent_inputs = try parseArguments(&recursive);
    try std.testing.expectEqual(.parent, parent_inputs.child_family);
    try std.testing.expectEqual(.root, parent_inputs.publication_mode);
    var unsupported = valid;
    unsupported[1] = "unreviewed-profile";
    try std.testing.expectError(error.ExpectedExplicitTinyProfileOutputAndTwoAdmittedChildren, parseArguments(&unsupported));
}
