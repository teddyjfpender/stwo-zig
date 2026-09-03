//! Canonical create-only JSON publications for the streamed leaf product.

const std = @import("std");
const contract = @import("ethereum_block_leaf_contract.zig");

pub const Timing = struct {
    wall_ns: u64,
    user_ns: u64,
    system_ns: u64,
};

pub const Clock = struct {
    wall: std.time.Timer,
    usage: std.posix.rusage,

    pub fn start() !Clock {
        return .{
            .wall = try std.time.Timer.start(),
            .usage = std.posix.getrusage(std.posix.rusage.SELF),
        };
    }

    pub fn finish(self: *Clock) !Timing {
        const after = std.posix.getrusage(std.posix.rusage.SELF);
        return .{
            .wall_ns = self.wall.read(),
            .user_ns = try subtractTimeval(self.usage.utime, after.utime),
            .system_ns = try subtractTimeval(self.usage.stime, after.stime),
        };
    }
};

pub const FileIdentity = struct {
    bytes: u64,
    path: []const u8,
    sha256: [32]u8,
};

pub const LeafResultInput = struct {
    expected_authority_sha256: [32]u8,
    proof: FileIdentity,
    prove_timing: Timing,
    request_sha256: [32]u8,
    root_sha256: [32]u8,
    segment_index: u32,
    statement_sha256: [32]u8,
};

pub fn encodeLeafResult(
    allocator: std.mem.Allocator,
    input: LeafResultInput,
) ![]u8 {
    const authority = std.fmt.bytesToHex(input.expected_authority_sha256, .lower);
    const proof = std.fmt.bytesToHex(input.proof.sha256, .lower);
    const request = std.fmt.bytesToHex(input.request_sha256, .lower);
    const root = std.fmt.bytesToHex(input.root_sha256, .lower);
    const statement = std.fmt.bytesToHex(input.statement_sha256, .lower);
    const unsigned = try std.fmt.allocPrint(allocator, "{{\"expected_authority_sha256\":\"{s}\",\"proof\":{{\"bytes\":{d},\"path\":\"{s}\",\"sha256\":\"{s}\"}},\"prove_timing\":{{\"system_ns\":{d},\"user_ns\":{d},\"wall_ns\":{d}}},\"request_sha256\":\"{s}\",\"root_sha256\":\"{s}\",\"schema\":\"{s}\",\"segment_index\":{d},\"statement_sha256\":\"{s}\",\"status\":\"proved\"}}", .{
        &authority,
        input.proof.bytes,
        input.proof.path,
        &proof,
        input.prove_timing.system_ns,
        input.prove_timing.user_ns,
        input.prove_timing.wall_ns,
        &request,
        &root,
        contract.leaf_result_schema,
        input.segment_index,
        &statement,
    });
    defer allocator.free(unsigned);
    return seal(allocator, unsigned);
}

pub const ProgressInput = struct {
    proof: FileIdentity,
    request_sha256: [32]u8,
    result: FileIdentity,
    segment_index: u32,
    stream_session_sha256: [32]u8,
};

pub fn encodeProgress(
    allocator: std.mem.Allocator,
    input: ProgressInput,
) ![]u8 {
    const proof = std.fmt.bytesToHex(input.proof.sha256, .lower);
    const request = std.fmt.bytesToHex(input.request_sha256, .lower);
    const result = std.fmt.bytesToHex(input.result.sha256, .lower);
    const session = std.fmt.bytesToHex(input.stream_session_sha256, .lower);
    const unsigned = try std.fmt.allocPrint(allocator, "{{\"proof\":{{\"bytes\":{d},\"path\":\"{s}\",\"sha256\":\"{s}\"}},\"request_sha256\":\"{s}\",\"result\":{{\"bytes\":{d},\"path\":\"{s}\",\"sha256\":\"{s}\"}},\"schema\":\"{s}\",\"segment_index\":{d},\"stream_session_sha256\":\"{s}\"}}", .{
        input.proof.bytes,
        input.proof.path,
        &proof,
        &request,
        input.result.bytes,
        input.result.path,
        &result,
        contract.progress_record_schema,
        input.segment_index,
        &session,
    });
    defer allocator.free(unsigned);
    return seal(allocator, unsigned);
}

pub const StreamPublication = struct {
    progress_record_sha256: [32]u8,
    proof: FileIdentity,
    result: FileIdentity,
    segment_index: u32,
};

pub const StreamResultInput = struct {
    first_segment_index: u32,
    producer_sha256: [32]u8,
    publications: []const StreamPublication,
    request_sha256: [32]u8,
    stream_session_sha256: [32]u8,
};

pub fn encodeStreamResult(
    allocator: std.mem.Allocator,
    input: StreamResultInput,
) ![]u8 {
    var publications: std.ArrayList(u8) = .empty;
    defer publications.deinit(allocator);
    const writer = publications.writer(allocator);
    try writer.writeByte('[');
    for (input.publications, 0..) |publication, index| {
        if (index != 0) try writer.writeByte(',');
        const progress = std.fmt.bytesToHex(
            publication.progress_record_sha256,
            .lower,
        );
        const proof = std.fmt.bytesToHex(publication.proof.sha256, .lower);
        const result = std.fmt.bytesToHex(publication.result.sha256, .lower);
        try writer.print(
            "{{\"progress_record_sha256\":\"{s}\",\"proof\":{{\"bytes\":{d},\"path\":\"{s}\",\"sha256\":\"{s}\"}},\"result\":{{\"bytes\":{d},\"path\":\"{s}\",\"sha256\":\"{s}\"}},\"segment_index\":{d}}}",
            .{
                &progress,
                publication.proof.bytes,
                publication.proof.path,
                &proof,
                publication.result.bytes,
                publication.result.path,
                &result,
                publication.segment_index,
            },
        );
    }
    try writer.writeByte(']');
    const producer = std.fmt.bytesToHex(input.producer_sha256, .lower);
    const request = std.fmt.bytesToHex(input.request_sha256, .lower);
    const session = std.fmt.bytesToHex(input.stream_session_sha256, .lower);
    const unsigned = try std.fmt.allocPrint(allocator, "{{\"first_segment_index\":{d},\"producer_sha256\":\"{s}\",\"publications\":{s},\"request_sha256\":\"{s}\",\"schema\":\"{s}\",\"status\":\"complete\",\"stream_session_sha256\":\"{s}\"}}", .{
        input.first_segment_index,
        &producer,
        publications.items,
        &request,
        contract.stream_result_schema,
        &session,
    });
    defer allocator.free(unsigned);
    return seal(allocator, unsigned);
}

pub const VerifierResultInput = struct {
    level: u32,
    node_index: u32,
    proof_bytes: u64,
    proof_sha256: [32]u8,
    request_sha256: [32]u8,
    root_sha256: [32]u8,
    scope: []const u8,
    statement_sha256: [32]u8,
    verifier_sha256: [32]u8,
};

pub fn encodeVerifierResult(
    allocator: std.mem.Allocator,
    input: VerifierResultInput,
) ![]u8 {
    const proof = std.fmt.bytesToHex(input.proof_sha256, .lower);
    const request = std.fmt.bytesToHex(input.request_sha256, .lower);
    const root = std.fmt.bytesToHex(input.root_sha256, .lower);
    const statement = std.fmt.bytesToHex(input.statement_sha256, .lower);
    const verifier = std.fmt.bytesToHex(input.verifier_sha256, .lower);
    const receipt = try std.fmt.allocPrint(allocator, "{{\"fresh_verification\":true,\"level\":{d},\"node_index\":{d},\"proof_bytes\":{d},\"proof_sha256\":\"{s}\",\"root_sha256\":\"{s}\",\"schema\":\"{s}\",\"scope\":\"{s}\",\"statement_sha256\":\"{s}\",\"status\":\"verified\",\"verifier_sha256\":\"{s}\"}}", .{
        input.level,
        input.node_index,
        input.proof_bytes,
        &proof,
        &root,
        contract.verifier_receipt_schema,
        input.scope,
        &statement,
        &verifier,
    });
    defer allocator.free(receipt);
    const unsigned = try std.fmt.allocPrint(allocator, "{{\"proof_bytes\":{d},\"proof_sha256\":\"{s}\",\"request_sha256\":\"{s}\",\"root_sha256\":\"{s}\",\"schema\":\"{s}\",\"statement_sha256\":\"{s}\",\"status\":\"verified\",\"verification_receipt\":{s},\"verifier_sha256\":\"{s}\"}}", .{
        input.proof_bytes,
        &proof,
        &request,
        &root,
        contract.verifier_result_schema,
        &statement,
        receipt,
        &verifier,
    });
    defer allocator.free(unsigned);
    return seal(allocator, unsigned);
}

pub fn identity(path: []const u8, bytes: []const u8) FileIdentity {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return .{ .bytes = bytes.len, .path = path, .sha256 = digest };
}

pub fn seal(allocator: std.mem.Allocator, unsigned: []const u8) ![]u8 {
    if (unsigned.len < 2 or unsigned[0] != '{' or
        unsigned[unsigned.len - 1] != '}')
    {
        return error.InvalidUnsignedJson;
    }
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(unsigned);
    hash.update("\n");
    const digest = hash.finalResult();
    const encoded = std.fmt.bytesToHex(digest, .lower);
    return std.fmt.allocPrint(
        allocator,
        "{{\"content_sha256\":\"{s}\",{s}\n",
        .{ &encoded, unsigned[1..] },
    );
}

fn subtractTimeval(before: anytype, after: @TypeOf(before)) !u64 {
    const before_ns = try timevalNs(before);
    const after_ns = try timevalNs(after);
    return std.math.sub(u64, after_ns, before_ns) catch
        error.ProcessClockRegressed;
}

fn timevalNs(value: anytype) !u64 {
    if (value.sec < 0 or value.usec < 0 or value.usec >= 1_000_000)
        return error.InvalidProcessClock;
    const seconds: u64 = @intCast(value.sec);
    const micros: u64 = @intCast(value.usec);
    return std.math.add(
        u64,
        try std.math.mul(u64, seconds, std.time.ns_per_s),
        try std.math.mul(u64, micros, std.time.ns_per_us),
    );
}
