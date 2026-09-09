//! Sealed telemetry for the single-pass provider call/prepared-segment seam.

const std = @import("std");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");

pub const schema = "stwo.ethereum.poseidon-provider-prepared-capture.v1";
pub const status = "single-pass-call-custody-prepared-nonproduction";
pub const max_receipt_bytes: usize = 1024 * 1024;

pub const Receipt = struct {
    content_sha256: []const u8,
    call_artifact: contract.Identity,
    call_artifact_content_sha256: []const u8,
    call_authority_build_count: u32,
    call_authority_build_timing: evidence.Timing,
    call_list_commitment_sha256: []const u8,
    executable_sha256: []const u8,
    execution_pass_count: u32,
    execution_timing: evidence.Timing,
    geometry_snapshot: contract.Identity,
    prepared_identity_sha256: []const u8,
    prepare_timing: evidence.Timing,
    production_eligible: bool,
    public_data_wire_id_sha256: []const u8,
    recursive_admissible: bool,
    reexecution_eliminated: bool,
    request: contract.Identity,
    request_content_sha256: []const u8,
    schema: []const u8,
    segment_index: u32,
    status: []const u8,
    total_timing: evidence.Timing,

    pub fn validate(self: Receipt) !void {
        const sequential_wall_ns = std.math.add(
            u64,
            self.execution_timing.wall_ns,
            self.prepare_timing.wall_ns,
        ) catch return error.InvalidProviderPreparedCaptureReceipt;
        if (!std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.status, status) or
            self.execution_pass_count != 1 or
            self.call_authority_build_count != 1 or
            !self.reexecution_eliminated or self.production_eligible or
            self.recursive_admissible or self.execution_timing.wall_ns == 0 or
            self.call_authority_build_timing.wall_ns == 0 or
            self.prepare_timing.wall_ns == 0 or self.total_timing.wall_ns == 0 or
            self.call_authority_build_timing.wall_ns > self.prepare_timing.wall_ns or
            self.total_timing.wall_ns < sequential_wall_ns)
        {
            return error.InvalidProviderPreparedCaptureReceipt;
        }
        try validateFile(self.call_artifact);
        try validateFile(self.geometry_snapshot);
        try validateFile(self.request);
        inline for (.{
            self.content_sha256,
            self.call_artifact_content_sha256,
            self.call_list_commitment_sha256,
            self.executable_sha256,
            self.prepared_identity_sha256,
            self.public_data_wire_id_sha256,
            self.request_content_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
    }
};

pub fn encode(allocator: std.mem.Allocator, value: Receipt) ![]u8 {
    try value.validate();
    const placeholder = [_]u8{'0'} ** 64;
    var temporary = value;
    temporary.content_sha256 = &placeholder;
    const canonical = try std.json.Stringify.valueAlloc(
        allocator,
        temporary,
        .{},
    );
    defer allocator.free(canonical);
    const unsigned = try removeContent(allocator, canonical);
    defer allocator.free(unsigned);
    const bytes = try evidence.seal(allocator, unsigned);
    errdefer allocator.free(bytes);
    var parsed = try parse(allocator, bytes);
    parsed.deinit();
    return bytes;
}

pub fn parse(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(Receipt) {
    if (bytes.len == 0 or bytes.len > max_receipt_bytes or
        bytes[bytes.len - 1] != '\n') return error.InvalidCanonicalJson;
    var parsed = try std.json.parseFromSlice(Receipt, allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    errdefer parsed.deinit();
    const canonical = try std.json.Stringify.valueAlloc(
        allocator,
        parsed.value,
        .{},
    );
    defer allocator.free(canonical);
    if (canonical.len + 1 != bytes.len or
        !std.mem.eql(u8, canonical, bytes[0..canonical.len]))
    {
        return error.InvalidCanonicalJson;
    }
    try parsed.value.validate();
    try validateContent(allocator, bytes, parsed.value.content_sha256);
    return parsed;
}

pub fn publishCreateOnly(path: []const u8, bytes: []const u8) !void {
    return artifact_io.publishCreateOnlyDurable(path, bytes);
}

fn validateFile(value: contract.Identity) !void {
    try value.validate(false);
    if (!std.fs.path.isAbsolute(value.path))
        return error.InvalidProviderPreparedCaptureReceipt;
}

fn removeContent(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, bytes, prefix))
        return error.InvalidProviderPreparedCaptureReceipt;
    const end = prefix.len + 64;
    if (end + 1 >= bytes.len or bytes[end] != '"' or bytes[end + 1] != ',')
        return error.InvalidProviderPreparedCaptureReceipt;
    return std.fmt.allocPrint(allocator, "{{{s}", .{bytes[end + 2 ..]});
}

fn validateContent(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected: []const u8,
) !void {
    _ = try contract.parseSha256(expected);
    const prefix = "{\"content_sha256\":\"";
    const end = prefix.len + 64;
    if (!std.mem.startsWith(u8, bytes, prefix) or end + 1 >= bytes.len or
        bytes[end] != '"' or bytes[end + 1] != ',' or
        !std.mem.eql(u8, bytes[prefix.len..end], expected))
    {
        return error.InvalidContentSha256;
    }
    const unsigned = try std.fmt.allocPrint(
        allocator,
        "{{{s}",
        .{bytes[end + 2 ..]},
    );
    defer allocator.free(unsigned);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(unsigned, &digest, .{});
    const actual = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &actual, expected)) return error.InvalidContentSha256;
}

pub const testing = struct {
    pub fn canonicalRoundTrip(allocator: std.mem.Allocator) !void {
        const digest = [_]u8{'1'} ** 64;
        const timing = evidence.Timing{
            .wall_ns = 7,
            .user_ns = 5,
            .system_ns = 1,
        };
        const total_timing = evidence.Timing{
            .wall_ns = 21,
            .user_ns = 15,
            .system_ns = 3,
        };
        const placeholder = [_]u8{'0'} ** 64;
        const value = Receipt{
            .content_sha256 = &placeholder,
            .call_artifact = .{
                .bytes = 11,
                .path = "/retained/calls.json",
                .sha256 = &digest,
            },
            .call_artifact_content_sha256 = &digest,
            .call_authority_build_count = 1,
            .call_authority_build_timing = timing,
            .call_list_commitment_sha256 = &digest,
            .executable_sha256 = &digest,
            .execution_pass_count = 1,
            .execution_timing = timing,
            .geometry_snapshot = .{
                .bytes = 12,
                .path = "/retained/geometry.json",
                .sha256 = &digest,
            },
            .prepared_identity_sha256 = &digest,
            .prepare_timing = timing,
            .production_eligible = false,
            .public_data_wire_id_sha256 = &digest,
            .recursive_admissible = false,
            .reexecution_eliminated = true,
            .request = .{
                .bytes = 13,
                .path = "/retained/request.json",
                .sha256 = &digest,
            },
            .request_content_sha256 = &digest,
            .schema = schema,
            .segment_index = 0,
            .status = status,
            .total_timing = total_timing,
        };
        const bytes = try encode(allocator, value);
        defer allocator.free(bytes);
        var parsed = try parse(allocator, bytes);
        defer parsed.deinit();
        try std.testing.expectEqual(@as(u32, 1), parsed.value.execution_pass_count);
        try std.testing.expect(parsed.value.reexecution_eliminated);

        var mutated = value;
        mutated.execution_pass_count = 2;
        try std.testing.expectError(
            error.InvalidProviderPreparedCaptureReceipt,
            encode(allocator, mutated),
        );
    }
};
