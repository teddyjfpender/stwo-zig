//! Compact create-only custody for the exact admitted narrow Poseidon calls.
//!
//! The raw STWEPC01 file stores only `(left, right, output)` as three LE u32
//! words per call; all other `poseidon2_air.Call` fields are canonically zero.
//! Its sealed JSON metadata binds the exact request, geometry, resource plan,
//! public-data wire, session, producer, and ordered-call commitment. Reopen
//! reconstructs every full typed call and recomputes that commitment.
//!
//! This transport deliberately does not prove call order. It is durable
//! custody for Stage-A/Stage-B recomputation; only the provider V2 AIR may
//! upgrade ordered calls to proof authority.

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const resource = @import("ethereum_poseidon_provider_resource_plan_v1.zig");
const support = @import("ethereum_block_leaf_support.zig");

const authority = frontend.testing.narrow_memory_provider_shard_authority;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;

pub const raw_magic = "STWEPC01";
pub const raw_format_version: u32 = 1;
pub const raw_header_bytes: usize = raw_magic.len + @sizeOf(u32) + @sizeOf(u64);
pub const raw_call_bytes: usize = 3 * @sizeOf(u32);
pub const max_call_count: u64 = 32 * 1024 * 1024;
pub const max_raw_bytes: usize = raw_header_bytes +
    @as(usize, max_call_count) * raw_call_bytes;
pub const max_metadata_bytes: usize = 1024 * 1024;
pub const schema = "stwo.ethereum.poseidon-provider-call-artifact.v1";
pub const status = "authenticated-call-custody-nonproduction";

comptime {
    if (poseidon2_air.WIDTH != 16 or raw_magic.len != 8)
        @compileError("provider call wire geometry drifted");
}

pub const Artifact = struct {
    content_sha256: []const u8,
    call_count: u64,
    call_list_commitment_sha256: []const u8,
    calls: contract.Identity,
    geometry_snapshot: contract.Identity,
    geometry_snapshot_content_sha256: []const u8,
    ordered_calls_air_bound: bool,
    producer_sha256: []const u8,
    production_eligible: bool,
    public_data_wire_id_sha256: []const u8,
    recursive_admissible: bool,
    request: contract.Identity,
    request_content_sha256: []const u8,
    resource_plan_identity_sha256: []const u8,
    schema: []const u8,
    segment_index: u32,
    session_sha256: []const u8,
    status: []const u8,
    wire_magic: []const u8,
    wire_version: u32,

    pub fn validate(self: Artifact) !void {
        if (!std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.status, status) or
            !std.mem.eql(u8, self.wire_magic, raw_magic) or
            self.wire_version != raw_format_version or
            self.call_count == 0 or self.call_count > max_call_count or
            self.ordered_calls_air_bound or self.production_eligible or
            self.recursive_admissible)
        {
            return error.InvalidProviderCallArtifact;
        }
        try self.calls.validate(false);
        try self.geometry_snapshot.validate(false);
        try self.request.validate(false);
        inline for (.{
            self.calls.path,
            self.geometry_snapshot.path,
            self.request.path,
        }) |path| if (!std.fs.path.isAbsolute(path))
            return error.InvalidProviderCallArtifact;
        const expected_raw_bytes: u64 = @intCast(try rawLength(self.call_count));
        if (self.calls.bytes != expected_raw_bytes)
            return error.InvalidProviderCallArtifact;
        inline for (.{
            self.content_sha256,
            self.call_list_commitment_sha256,
            self.geometry_snapshot_content_sha256,
            self.producer_sha256,
            self.public_data_wire_id_sha256,
            self.request_content_sha256,
            self.resource_plan_identity_sha256,
            self.session_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
    }
};

pub const Input = struct {
    calls: []const poseidon2_air.Call,
    calls_path: []const u8,
    geometry_snapshot: evidence.FileIdentity,
    geometry_snapshot_content_sha256: [32]u8,
    producer_sha256: [32]u8,
    public_data_wire_id: [32]u8,
    request: evidence.FileIdentity,
    request_content_sha256: [32]u8,
    resource_plan: *const resource.ProviderResourcePlanV1,
    session: [32]u8,
};

pub const Encoded = struct {
    metadata: []u8,
    raw: []u8,

    pub fn deinit(self: *Encoded, allocator: std.mem.Allocator) void {
        allocator.free(self.raw);
        allocator.free(self.metadata);
        self.* = undefined;
    }
};

pub fn encode(
    allocator: std.mem.Allocator,
    input: Input,
) !Encoded {
    try input.resource_plan.validate();
    const call_count = std.math.cast(u64, input.calls.len) orelse
        return error.ProviderCallArtifactResourceLimitExceeded;
    if (call_count != input.resource_plan
        .shard_planning.logical_row_count or
        call_count != input.resource_plan.geometry.legacy_poseidon.n_rows or
        !std.meta.eql(
            input.geometry_snapshot.sha256,
            input.resource_plan.geometry.snapshot_file_sha256,
        ) or
        !std.meta.eql(
            input.geometry_snapshot_content_sha256,
            input.resource_plan.geometry.snapshot_content_sha256,
        ) or
        !std.fs.path.isAbsolute(input.calls_path) or
        !std.fs.path.isAbsolute(input.geometry_snapshot.path) or
        !std.fs.path.isAbsolute(input.request.path))
    {
        return error.InvalidProviderCallArtifact;
    }
    const raw = try encodeRaw(allocator, input.calls);
    errdefer allocator.free(raw);
    const raw_identity = evidence.identity(input.calls_path, raw);
    const call_list_commitment = try authority.orderedCallListCommitment(
        input.calls,
    );
    const metadata = try encodeMetadata(
        allocator,
        input,
        raw_identity,
        call_list_commitment,
    );
    return .{ .metadata = metadata, .raw = raw };
}

/// Publishes payload before metadata. A crash can leave an inert orphan raw
/// file, but never metadata claiming that an absent payload is resumable.
pub fn publishCreateOnly(
    allocator: std.mem.Allocator,
    calls_path: []const u8,
    metadata_path: []const u8,
    encoded: Encoded,
) !void {
    if (!std.fs.path.isAbsolute(calls_path) or
        !std.fs.path.isAbsolute(metadata_path) or
        std.mem.eql(u8, calls_path, metadata_path))
    {
        return error.InvalidProviderCallArtifactPath;
    }
    var parsed = try parse(allocator, encoded.metadata);
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.calls.path, calls_path) or
        parsed.value.calls.bytes != encoded.raw.len or
        !std.meta.eql(
            try contract.parseSha256(parsed.value.calls.sha256),
            support.sha256(encoded.raw),
        ))
    {
        return error.InvalidProviderCallArtifactPath;
    }
    try artifact_io.publishCreateOnlyDurable(calls_path, encoded.raw);
    try artifact_io.publishCreateOnlyDurable(metadata_path, encoded.metadata);
}

pub fn parse(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(Artifact) {
    if (bytes.len == 0 or bytes.len > max_metadata_bytes or
        bytes[bytes.len - 1] != '\n' or
        (bytes.len > 1 and bytes[bytes.len - 2] == '\n'))
    {
        return error.InvalidCanonicalJson;
    }
    var parsed = try std.json.parseFromSlice(Artifact, allocator, bytes, .{
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
    try validateContentSha256(allocator, bytes, parsed.value.content_sha256);
    return parsed;
}

pub const Reopened = struct {
    calls: []poseidon2_air.Call,
    call_list_commitment: [32]u8,
    public_data_wire_id: [32]u8,
    session: [32]u8,

    pub fn deinit(self: *Reopened, allocator: std.mem.Allocator) void {
        allocator.free(self.calls);
        self.* = undefined;
    }
};

pub fn reopen(
    allocator: std.mem.Allocator,
    artifact: Artifact,
    resource_plan: *const resource.ProviderResourcePlanV1,
) !Reopened {
    try artifact.validate();
    try resource_plan.validate();
    if (!std.mem.eql(
        u8,
        artifact.resource_plan_identity_sha256,
        &hex(resource_plan.identity),
    ) or !std.mem.eql(
        u8,
        artifact.geometry_snapshot.sha256,
        &hex(resource_plan.geometry.snapshot_file_sha256),
    ) or !std.mem.eql(
        u8,
        artifact.geometry_snapshot_content_sha256,
        &hex(resource_plan.geometry.snapshot_content_sha256),
    ) or artifact.call_count != resource_plan.shard_planning.logical_row_count or
        artifact.call_count != resource_plan.geometry.legacy_poseidon.n_rows)
    {
        return error.ProviderCallArtifactAuthorityMismatch;
    }
    const raw = try support.readIdentity(
        allocator,
        artifact.calls,
        max_raw_bytes,
    );
    defer allocator.free(raw);
    const calls = try decodeRaw(allocator, raw, artifact.call_count);
    errdefer allocator.free(calls);
    const commitment = try authority.orderedCallListCommitment(calls);
    if (!std.mem.eql(
        u8,
        artifact.call_list_commitment_sha256,
        &hex(commitment),
    )) return error.ProviderCallArtifactAuthorityMismatch;
    return .{
        .calls = calls,
        .call_list_commitment = commitment,
        .public_data_wire_id = try contract.parseSha256(
            artifact.public_data_wire_id_sha256,
        ),
        .session = try contract.parseSha256(artifact.session_sha256),
    };
}

fn encodeRaw(
    allocator: std.mem.Allocator,
    calls: []const poseidon2_air.Call,
) ![]u8 {
    const call_count = std.math.cast(u64, calls.len) orelse
        return error.ProviderCallArtifactResourceLimitExceeded;
    if (call_count == 0 or call_count > max_call_count)
        return error.ProviderCallArtifactResourceLimitExceeded;
    const length = try rawLength(calls.len);
    const bytes = try allocator.alloc(u8, length);
    errdefer allocator.free(bytes);
    @memcpy(bytes[0..raw_magic.len], raw_magic);
    std.mem.writeInt(
        u32,
        bytes[raw_magic.len..][0..4],
        raw_format_version,
        .little,
    );
    std.mem.writeInt(
        u64,
        bytes[raw_magic.len + 4 ..][0..8],
        call_count,
        .little,
    );
    var cursor: usize = raw_header_bytes;
    for (calls) |call| {
        try validateCall(call);
        inline for (.{ call.input[0], call.input[1], call.narrow_output.? }) |value| {
            std.mem.writeInt(u32, bytes[cursor..][0..4], value, .little);
            cursor += 4;
        }
    }
    if (cursor != bytes.len) return error.InvalidProviderCallArtifact;
    return bytes;
}

fn decodeRaw(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected_count: u64,
) ![]poseidon2_air.Call {
    if (bytes.len != try rawLength(expected_count) or
        !std.mem.eql(u8, bytes[0..raw_magic.len], raw_magic) or
        std.mem.readInt(u32, bytes[raw_magic.len..][0..4], .little) !=
            raw_format_version or
        std.mem.readInt(u64, bytes[raw_magic.len + 4 ..][0..8], .little) !=
            expected_count)
    {
        return error.InvalidProviderCallArtifactWire;
    }
    const count = std.math.cast(usize, expected_count) orelse
        return error.ProviderCallArtifactResourceLimitExceeded;
    const calls = try allocator.alloc(poseidon2_air.Call, count);
    errdefer allocator.free(calls);
    var cursor: usize = raw_header_bytes;
    for (calls) |*call| {
        const left = std.mem.readInt(u32, bytes[cursor..][0..4], .little);
        cursor += 4;
        const right = std.mem.readInt(u32, bytes[cursor..][0..4], .little);
        cursor += 4;
        const output = std.mem.readInt(u32, bytes[cursor..][0..4], .little);
        cursor += 4;
        call.* = poseidon2_air.Call.narrowWithOutput(left, right, output);
        try validateCall(call.*);
    }
    if (cursor != bytes.len) return error.InvalidProviderCallArtifactWire;
    return calls;
}

fn encodeMetadata(
    allocator: std.mem.Allocator,
    input: Input,
    raw_identity: evidence.FileIdentity,
    call_list_commitment: [32]u8,
) ![]u8 {
    const placeholder = [_]u8{'0'} ** 64;
    const calls_sha = hex(raw_identity.sha256);
    const call_list = hex(call_list_commitment);
    const geometry_sha = hex(input.geometry_snapshot.sha256);
    const geometry_content = hex(input.geometry_snapshot_content_sha256);
    const producer = hex(input.producer_sha256);
    const public_wire = hex(input.public_data_wire_id);
    const request_sha = hex(input.request.sha256);
    const request_content = hex(input.request_content_sha256);
    const resource_identity = hex(input.resource_plan.identity);
    const session = hex(input.session);
    const value = Artifact{
        .content_sha256 = &placeholder,
        .call_count = @intCast(input.calls.len),
        .call_list_commitment_sha256 = &call_list,
        .calls = identity(raw_identity, &calls_sha),
        .geometry_snapshot = identity(input.geometry_snapshot, &geometry_sha),
        .geometry_snapshot_content_sha256 = &geometry_content,
        .ordered_calls_air_bound = false,
        .producer_sha256 = &producer,
        .production_eligible = false,
        .public_data_wire_id_sha256 = &public_wire,
        .recursive_admissible = false,
        .request = identity(input.request, &request_sha),
        .request_content_sha256 = &request_content,
        .resource_plan_identity_sha256 = &resource_identity,
        .schema = schema,
        .segment_index = input.resource_plan.geometry.segment_index,
        .session_sha256 = &session,
        .status = status,
        .wire_magic = raw_magic,
        .wire_version = raw_format_version,
    };
    const with_placeholder = try std.json.Stringify.valueAlloc(
        allocator,
        value,
        .{},
    );
    defer allocator.free(with_placeholder);
    const unsigned = try removeContentPlaceholder(allocator, with_placeholder);
    defer allocator.free(unsigned);
    const bytes = try evidence.seal(allocator, unsigned);
    errdefer allocator.free(bytes);
    var parsed = try parse(allocator, bytes);
    parsed.deinit();
    return bytes;
}

fn validateCall(call: poseidon2_air.Call) !void {
    if (call.wide or call.io or call.narrow_output == null)
        return error.NonCanonicalProviderCall;
    inline for (.{ call.input[0], call.input[1], call.narrow_output.? }) |value| if (value >= core.fields.m31.Modulus)
        return error.NonCanonicalProviderCall;
    for (call.input[2..]) |value|
        if (value != 0) return error.NonCanonicalProviderCall;
}

fn rawLength(count_value: anytype) !usize {
    const count = std.math.cast(usize, count_value) orelse
        return error.ProviderCallArtifactResourceLimitExceeded;
    if (count == 0 or count > @as(usize, @intCast(max_call_count)))
        return error.ProviderCallArtifactResourceLimitExceeded;
    return std.math.add(
        usize,
        raw_header_bytes,
        try std.math.mul(usize, count, raw_call_bytes),
    ) catch error.ProviderCallArtifactResourceLimitExceeded;
}

fn identity(value: evidence.FileIdentity, digest: *const [64]u8) contract.Identity {
    return .{ .bytes = value.bytes, .path = value.path, .sha256 = digest };
}

fn removeContentPlaceholder(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) ![]u8 {
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, bytes, prefix))
        return error.InvalidProviderCallArtifact;
    const end = prefix.len + 64;
    if (end + 1 >= bytes.len or bytes[end] != '"' or bytes[end + 1] != ',')
        return error.InvalidProviderCallArtifact;
    return std.fmt.allocPrint(allocator, "{{{s}", .{bytes[end + 2 ..]});
}

fn validateContentSha256(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected: []const u8,
) !void {
    _ = try contract.parseSha256(expected);
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, bytes, prefix))
        return error.InvalidContentSha256;
    const start = prefix.len;
    const end = start + 64;
    if (end + 1 >= bytes.len or bytes[end] != '"' or bytes[end + 1] != ',' or
        !std.mem.eql(u8, bytes[start..end], expected))
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
    if (!std.mem.eql(u8, &hex(digest), expected))
        return error.InvalidContentSha256;
}

fn hex(value: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(value, .lower);
}

pub const testing = struct {
    pub fn rawRoundTrip(allocator: std.mem.Allocator) !void {
        const calls = [_]poseidon2_air.Call{
            poseidon2_air.Call.narrowWithOutput(1, 2, 3),
            poseidon2_air.Call.narrowWithOutput(4, 5, 6),
        };
        const raw = try encodeRaw(allocator, &calls);
        defer allocator.free(raw);
        const decoded = try decodeRaw(allocator, raw, calls.len);
        defer allocator.free(decoded);
        try std.testing.expectEqual(calls.len, decoded.len);
        for (calls, decoded) |expected, actual|
            try std.testing.expect(std.meta.eql(expected, actual));

        var mutated = try allocator.dupe(u8, raw);
        defer allocator.free(mutated);
        mutated[raw_header_bytes] = 0xff;
        mutated[raw_header_bytes + 1] = 0xff;
        mutated[raw_header_bytes + 2] = 0xff;
        mutated[raw_header_bytes + 3] = 0xff;
        try std.testing.expectError(
            error.NonCanonicalProviderCall,
            decodeRaw(allocator, mutated, calls.len),
        );
    }
};
