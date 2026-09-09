//! Maintained development producer for one detached two-child parent candidate.
//! Child and optional parent admission come from explicit command arguments.
//! Emitted artifacts must be accepted by the separate parent verifier process.
const std = @import("std");
const child_command = @import("recursive_segment_v2_detached_command.zig");
const prepare = @import("recursive_segment_v2_detached_parent_prepare.zig");
const proof = @import("recursive_segment_v2_detached_parent_proof.zig");
const command = @import("recursive_segment_v2_detached_parent_command.zig");
const protocol = @import("recursive_segment_v2_detached_parent_protocol.zig");
pub const PROFILE = "tiny-memory-v1";
pub const ArgumentsV1 = struct {
    output: []const u8,
    children: [2]child_command.ArgumentsV1,
    parent_key: ?struct { path: []const u8, sha256: [32]u8 } = null,
};

/// Deliberately one reviewed fixture profile and one unambiguous argument order.
pub fn parseArguments(args: []const []const u8) !ArgumentsV1 {
    if ((args.len != 9 and args.len != 13) or !std.mem.eql(u8, args[0], "--profile") or
        !std.mem.eql(u8, args[1], PROFILE) or args[2].len == 0 or std.mem.startsWith(u8, args[2], "--"))
        return error.ExpectedExplicitTinyProfileOutputAndTwoAdmittedChildren;
    var result = ArgumentsV1{ .output = args[2], .children = .{ try child_command.parseArguments(args[3..6]), try child_command.parseArguments(args[6..9]) } };
    if (args.len == 13) {
        if (!std.mem.eql(u8, args[9], "--parent-key") or args[10].len == 0 or
            !std.mem.eql(u8, args[11], "--parent-key-sha256") or args[12].len != 64)
            return error.ExpectedIndependentParentKeyAndHash;
        var pin: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&pin, args[12]);
        result.parent_key = .{ .path = args[10], .sha256 = pin };
    }
    return result;
}

pub const CandidateReportV1 = struct {
    endpoint: []const u8 = "segment_v2_detached_two_child_parent_candidate_development_q3",
    profile: []const u8 = PROFILE,
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
    var timer = try std.time.Timer.start();
    var report = try runInner(allocator, args);
    report.request_ns = timer.read(); // Includes candidate/key/producer cleanup.
    return report;
}
fn runInner(allocator: std.mem.Allocator, args: ArgumentsV1) !CandidateReportV1 {
    try requireNewOutput(args.output);
    var admitted_key: ?*command.OwnedKeyV1 = null;
    defer if (admitted_key) |key| key.deinit();
    if (args.parent_key) |input| {
        const bytes = try std.fs.cwd().readFileAlloc(allocator, input.path, command.MAX_KEY_BYTES);
        defer allocator.free(bytes);
        admitted_key = try command.OwnedKeyV1.admit(allocator, bytes, input.sha256);
    }
    var expected: protocol.ExpectedV1 = undefined;
    var child_pins: [2][32]u8 = undefined;
    var preparation_ns: u64 = undefined;
    var candidate = blk: {
        var prepared = child_scope: {
            const left = try prepare.loadAdmittedChild(allocator, args.children[0]);
            defer left.deinit();
            const right = try prepare.loadAdmittedChild(allocator, args.children[1]);
            defer right.deinit();
            break :child_scope try prepare.prepare(allocator, .{ left, right }, prepare.TINY_MEMORY_PROFILE_V1);
        };
        // Both verified child owners are already destroyed here. Prepared owns
        // copied logical rows, provider calls, and canonical public root words.
        defer prepared.deinit();
        expected = prepared.expected;
        child_pins = prepared.child_key_sha256;
        preparation_ns = prepared.preparation_ns;
        break :blk try proof.produce(allocator, prepared.cohort, &expected, child_pins, if (admitted_key) |key| key.key() else null);
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
    try std.testing.expectError(error.ExpectedExplicitTinyProfileOutputAndTwoAdmittedChildren, parseArguments(with_parent[0..11]));
    var unsupported = valid;
    unsupported[1] = "unreviewed-profile";
    try std.testing.expectError(error.ExpectedExplicitTinyProfileOutputAndTwoAdmittedChildren, parseArguments(&unsupported));
}
