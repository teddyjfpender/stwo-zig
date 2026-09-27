//! Fresh-process receiver contract for an exact-count V2 proof roster.
//! The trusted digest is supplied independently of these members. Admission
//! and complete-span checks happen before any proof body is decoded.
const std = @import("std");
const spans = @import("span_statement_blake3.zig");
const protocol = @import("blake3_exact_forest_protocol.zig");
const parent = @import("blake3_execution_parent_protocol.zig");
const codec = @import("blake3_native_parent_codec.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
const tree = @import("blake3_execution_tree.zig");
const frontier = @import("blake3_stream_frontier.zig");

pub const VERSION = protocol.VERSION;
pub const Member = struct {
    statement: spans.SpanStatement,
    admission: parent.Admission,
    proof_bytes: []const u8,
};
pub const FileMember = struct {
    statement: spans.SpanStatement,
    admission: parent.Admission,
    proof_path: []const u8,
};

/// Verifies the independently pinned roster and its complete ordered span
/// before allocating a proof. A later `verify` still must check every proof.
pub fn preflight(
    job: spans.JobContext,
    members: []const Member,
    trusted_roster_digest: [32]u8,
) !void {
    if (members.len == 0 or members.len > spans.MAX_SLOT_HEIGHT + 1)
        return error.IncompleteStream;
    var entries: [spans.MAX_SLOT_HEIGHT + 1]protocol.Entry = undefined;
    for (members, 0..) |member, index| {
        try member.admission.validate();
        if (member.admission.key.profile != .csp_q70_pow26)
            return error.ExpectedCanonicalBlockSecurity;
        entries[index] = .{
            .statement = member.statement,
            .expected_key_id = member.admission.expected_id,
        };
    }
    const digest = try protocol.digest(job, entries[0..members.len]);
    if (!std.mem.eql(u8, &digest, &trusted_roster_digest))
        return error.UntrustedExactForestRoster;
}

/// Returns owning, independently verified members only after all proofs pass.
/// The caller must retain the external digest pin as the root of trust.
pub fn verify(
    allocator: std.mem.Allocator,
    job: spans.JobContext,
    members: []const Member,
    trusted_roster_digest: [32]u8,
) !frontier.Frontier.ExactForest {
    try preflight(job, members, trusted_roster_digest);
    var result = frontier.Frontier.ExactForest{ .job = job };
    errdefer result.deinit();
    for (members) |member| {
        var decoded: artifact.Owned = try codec.decode(
            allocator,
            member.proof_bytes,
            member.admission,
        );
        const node = try tree.Node.verifyOwned(
            &decoded,
            member.admission,
            member.admission.expected_id,
            member.statement,
        );
        result.nodes[result.count] = node;
        result.count += 1;
    }
    _ = try result.validate();
    if (!std.mem.eql(u8, &try result.rosterDigest(), &trusted_roster_digest))
        return error.UntrustedExactForestRoster;
    return result;
}

/// Proves authority for an already loaded roster with only one verified
/// capture live at a time. Input proof bytes remain caller owned.
pub fn verifyStreamingBytes(
    allocator: std.mem.Allocator,
    job: spans.JobContext,
    members: []const Member,
    trusted_roster_digest: [32]u8,
) !spans.ExecutedSpan {
    try preflight(job, members, trusted_roster_digest);
    for (members) |member| try verifyOne(allocator, member);
    var entries: [spans.MAX_SLOT_HEIGHT + 1]protocol.Entry = undefined;
    for (members, 0..) |member, index| entries[index] = .{
        .statement = member.statement,
        .expected_key_id = member.admission.expected_id,
    };
    return protocol.validate(job, entries[0..members.len]);
}

pub const verifyStreaming = verifyStreamingBytes;

/// The bounded file receiver: the trusted descriptor pin is checked before
/// opening the first proof path. Each body and proof capture is released before
/// the next file is opened, so proof memory is independent of roster length.
pub fn verifyStreamingFiles(
    allocator: std.mem.Allocator,
    job: spans.JobContext,
    members: []const FileMember,
    trusted_roster_digest: [32]u8,
) !spans.ExecutedSpan {
    if (members.len == 0 or members.len > spans.MAX_SLOT_HEIGHT + 1)
        return error.IncompleteStream;
    var descriptors: [spans.MAX_SLOT_HEIGHT + 1]Member = undefined;
    for (members, 0..) |member, index| descriptors[index] = .{
        .statement = member.statement,
        .admission = member.admission,
        .proof_bytes = &.{},
    };
    try preflight(job, descriptors[0..members.len], trusted_roster_digest);
    for (members, 0..) |member, index| {
        const bytes = try std.fs.cwd().readFileAlloc(
            allocator,
            member.proof_path,
            codec.HEADER_BYTES + codec.MAX_PROOF_BYTES,
        );
        defer allocator.free(bytes);
        descriptors[index].proof_bytes = bytes;
        try verifyOne(allocator, descriptors[index]);
        descriptors[index].proof_bytes = &.{};
    }
    var entries: [spans.MAX_SLOT_HEIGHT + 1]protocol.Entry = undefined;
    for (members, 0..) |member, index| entries[index] = .{
        .statement = member.statement,
        .expected_key_id = member.admission.expected_id,
    };
    return protocol.validate(job, entries[0..members.len]);
}

fn verifyOne(allocator: std.mem.Allocator, member: Member) !void {
    var decoded: artifact.Owned = try codec.decode(
        allocator,
        member.proof_bytes,
        member.admission,
    );
    var node = try tree.Node.verifyOwned(
        &decoded,
        member.admission,
        member.admission.expected_id,
        member.statement,
    );
    defer node.deinit();
    try node.validate();
}

test "exact-count V2 transport rejects empty roster before proof allocation" {
    const fixture = @import("span_statement_blake3_test_fixture.zig");
    const job = try fixture.job(3);
    const empty: []const Member = &.{};
    const untrusted: [32]u8 = @splat(0);
    try std.testing.expectError(error.IncompleteStream, preflight(job, empty, untrusted));
    try std.testing.expectError(error.IncompleteStream, verify(std.testing.allocator, job, empty, untrusted));
    try std.testing.expectError(error.IncompleteStream, verifyStreamingBytes(std.testing.allocator, job, empty, untrusted));
    const no_files: []const FileMember = &.{};
    try std.testing.expectError(error.IncompleteStream, verifyStreamingFiles(std.testing.allocator, job, no_files, untrusted));
}
