//! In-memory single-pass segment projection and provider call custody.
//!
//! This capability borrows the still-live runner segment.  It derives the
//! local V2 projection, public data, and exact provider call list once, then
//! lets a fused command publish call custody and feed the same values into the
//! omitted-core/provider pipeline.  It is deliberately not serializable.

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const call_artifact = @import("ethereum_poseidon_provider_call_artifact_v1.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const geometry_contract = @import("ethereum_poseidon_leaf_geometry_snapshot.zig");
const product = @import("ethereum_poseidon_leaf_product_contract.zig");
const product_support = @import("ethereum_poseidon_leaf_product_support.zig");
const resource = @import("ethereum_poseidon_provider_resource_plan_v1.zig");
const support = @import("ethereum_block_leaf_support.zig");

const authority = frontend.testing.narrow_memory_provider_shard_authority;
const M31 = core.fields.m31.M31;
const Call = frontend.air.memory_commitment.poseidon2_air.Call;

pub const identity_domain =
    "stwo-zig/ethereum/provider-prepared-segment/v1\x00";

pub const PreparedSegmentV1 = struct {
    allocator: std.mem.Allocator,
    global_source: frontend.recursion.segment_leaf_local_authority_v3.SourceV3,
    projection: frontend.recursion.segment_leaf_local_projection_v3.ProjectionV3,
    local_source: frontend.recursion.segment_statement_v2.SourceV2,
    public_words: []M31,
    public_data: frontend.air.public_data_v2.PublicDataV2,
    calls: frontend.prover_mod.EthereumSegmentProviderCallAuthorityV1,
    call_list_commitment: [32]u8,
    identity: [32]u8,

    pub fn validateAgainst(
        self: *const PreparedSegmentV1,
        expected: *const support.source_wire.Source,
        segment: *const frontend.runner.EthereumSegmentResult,
        session_sha256: [32]u8,
    ) !void {
        try expected.metadata.validate();
        try self.global_source.validate();
        if (self.global_source.result != &segment.base or
            !std.meta.eql(try self.global_source.metadata(), expected.metadata))
        {
            return error.PreparedSegmentSourceMismatch;
        }
        try self.projection.validateAgainst(&self.global_source);
        const expected_local = try self.projection.sourceV2(
            &self.global_source,
            support.sessionDigest(session_sha256),
        );
        if (!std.meta.eql(self.local_source, expected_local) or
            self.public_data.words().ptr != self.public_words.ptr or
            self.public_data.words().len != self.public_words.len)
        {
            return error.PreparedSegmentProjectionMismatch;
        }
        try self.public_data.validate();
        if (!std.meta.eql(
            self.calls.public_data_wire_id,
            self.public_data.wireId(),
        ) or self.calls.calls.len == 0 or
            !std.meta.eql(
                self.call_list_commitment,
                try authority.orderedCallListCommitment(self.calls.calls),
            ) or !std.meta.eql(self.identity, try preparedIdentity(self)))
        {
            return error.PreparedSegmentCallAuthorityMismatch;
        }
    }

    pub fn deinit(self: *PreparedSegmentV1) void {
        self.calls.deinit();
        self.allocator.free(self.public_words);
        self.* = undefined;
    }
};

pub const PreparationV1 = struct {
    prepared: PreparedSegmentV1,
    prepare_timing: evidence.Timing,
    call_authority_build_timing: evidence.Timing,

    pub fn deinit(self: *PreparationV1) void {
        self.prepared.deinit();
        self.* = undefined;
    }
};

pub const PublishedCallCustodyV1 = struct {
    artifact_file: evidence.FileIdentity,
    content_sha256: [32]u8,
};

/// Exact parity check between the still-live provider call projection and a
/// cold-reopened call artifact.  This is intentionally independent of proof
/// construction so the fused route can reject custody drift before Stage A.
pub fn requireCallCustodyParity(
    live_calls: []const Call,
    reopened_calls: []const Call,
    live_call_list_commitment: [32]u8,
    reopened_call_list_commitment: [32]u8,
    live_public_data_wire_id: [8]u32,
    reopened_public_data_wire_id: [32]u8,
) !void {
    if (live_calls.len != reopened_calls.len or
        !std.meta.eql(
            live_call_list_commitment,
            reopened_call_list_commitment,
        ) or !std.meta.eql(
        product_support.fieldDigestBytes(live_public_data_wire_id),
        reopened_public_data_wire_id,
    )) return error.PreparedCallCustodyMismatch;
    for (live_calls, reopened_calls) |live, reopened|
        if (!std.meta.eql(live, reopened))
            return error.PreparedCallCustodyMismatch;
}

pub fn prepare(
    allocator: std.mem.Allocator,
    expected: *const support.source_wire.Source,
    segment: *const frontend.runner.EthereumSegmentResult,
    session_sha256: [32]u8,
) !PreparationV1 {
    var prepare_clock = try evidence.Clock.start();
    const global_statement = try frontend.recursion.span_statement
        .SpanStatement.fromCanonicalWords(&expected.metadata.base_statement_words);
    const global_source = try frontend.recursion.segment_leaf_local_authority_v3
        .SourceV3.fromSegmentResult(global_statement, &segment.base);
    if (!std.meta.eql(try global_source.metadata(), expected.metadata))
        return error.PreparedSegmentSourceMismatch;
    const projection = try frontend.recursion.segment_leaf_local_projection_v3
        .ProjectionV3.init(&global_source);
    const local_source = try projection.sourceV2(
        &global_source,
        support.sessionDigest(session_sha256),
    );
    const encoded_public = try support.encodeLocalPublicData(
        allocator,
        &local_source,
    );
    errdefer allocator.free(encoded_public.words);
    var call_clock = try evidence.Clock.start();
    var calls = try frontend.prover_mod.buildEthereumSegmentProviderCallAuthorityV1(
        allocator,
        &projection.local_result,
        &segment.keccakf_calls,
        &segment.keccakf_execution_rows,
        &segment.signer_recovery_calls,
        &segment.signer_recovery_execution_rows,
        encoded_public.value,
    );
    errdefer calls.deinit();
    const call_timing = try call_clock.finish();
    const call_list_commitment = try authority.orderedCallListCommitment(
        calls.calls,
    );
    var prepared = PreparedSegmentV1{
        .allocator = allocator,
        .global_source = global_source,
        .projection = projection,
        .local_source = local_source,
        .public_words = encoded_public.words,
        .public_data = encoded_public.value,
        .calls = calls,
        .call_list_commitment = call_list_commitment,
        .identity = undefined,
    };
    prepared.identity = try preparedIdentity(&prepared);
    try prepared.validateAgainst(expected, segment, session_sha256);
    return .{
        .prepared = prepared,
        .prepare_timing = try prepare_clock.finish(),
        .call_authority_build_timing = call_timing,
    };
}

pub fn publishCallCustody(
    allocator: std.mem.Allocator,
    prepared: *const PreparedSegmentV1,
    calls_path: []const u8,
    metadata_path: []const u8,
    request: *const product.Request,
    request_file: evidence.FileIdentity,
    geometry: geometry_contract.Snapshot,
    geometry_file: evidence.FileIdentity,
    resource_plan: *const resource.ProviderResourcePlanV1,
    executable_sha256: [32]u8,
) !PublishedCallCustodyV1 {
    try resource_plan.validateAgainst(&geometry, geometry_file.sha256);
    const encoded = try call_artifact.encode(allocator, .{
        .calls = prepared.calls.calls,
        .calls_path = calls_path,
        .geometry_snapshot = geometry_file,
        .geometry_snapshot_content_sha256 = try contract.parseSha256(
            geometry.content_sha256,
        ),
        .producer_sha256 = executable_sha256,
        .public_data_wire_id = product_support.fieldDigestBytes(
            prepared.public_data.wireId(),
        ),
        .request = request_file,
        .request_content_sha256 = try contract.parseSha256(
            request.content_sha256,
        ),
        .resource_plan = resource_plan,
        .session = try contract.parseSha256(request.session_id),
    });
    var owned = encoded;
    defer owned.deinit(allocator);
    var parsed = try call_artifact.parse(allocator, encoded.metadata);
    defer parsed.deinit();
    if (!std.meta.eql(
        prepared.call_list_commitment,
        try contract.parseSha256(parsed.value.call_list_commitment_sha256),
    )) return error.PreparedSegmentCallAuthorityMismatch;
    try call_artifact.publishCreateOnly(
        allocator,
        calls_path,
        metadata_path,
        encoded,
    );
    return .{
        .artifact_file = evidence.identity(metadata_path, encoded.metadata),
        .content_sha256 = try contract.parseSha256(
            parsed.value.content_sha256,
        ),
    };
}

fn preparedIdentity(value: *const PreparedSegmentV1) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(identity_domain);
    const metadata = try value.global_source.metadata();
    for (try metadata.identity()) |word| hashInt(&hash, u32, word);
    for (value.public_data.wireId()) |word| hashInt(&hash, u32, word);
    hash.update(&value.call_list_commitment);
    hashInt(&hash, u64, value.calls.calls.len);
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub const testing = struct {
    pub fn callCustodyParity() !void {
        const calls = [_]Call{
            Call.narrowWithOutput(1, 2, 3),
            Call.narrowWithOutput(4, 5, 6),
        };
        const commitment = try authority.orderedCallListCommitment(&calls);
        const public_wire = [_]u32{ 7, 8, 9, 10, 11, 12, 13, 14 };
        const public_wire_bytes = product_support.fieldDigestBytes(public_wire);
        try requireCallCustodyParity(
            &calls,
            &calls,
            commitment,
            commitment,
            public_wire,
            public_wire_bytes,
        );

        var mutated = calls;
        mutated[1].narrow_output = mutated[1].narrow_output.? + 1;
        try std.testing.expectError(
            error.PreparedCallCustodyMismatch,
            requireCallCustodyParity(
                &calls,
                &mutated,
                commitment,
                commitment,
                public_wire,
                public_wire_bytes,
            ),
        );
        var wrong_commitment = commitment;
        wrong_commitment[0] ^= 1;
        try std.testing.expectError(
            error.PreparedCallCustodyMismatch,
            requireCallCustodyParity(
                &calls,
                &calls,
                commitment,
                wrong_commitment,
                public_wire,
                public_wire_bytes,
            ),
        );
    }
};
