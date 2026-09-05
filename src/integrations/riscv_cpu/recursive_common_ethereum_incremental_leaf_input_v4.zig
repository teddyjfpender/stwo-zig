//! Fresh stage-102 input for one full Ethereum incremental V4 leaf.
//!
//! The only constructor decodes the canonical stage-101 proof artifact and
//! reruns the complete joined native verifier.  The retained proof capture is
//! therefore a process-local capability, never a digest-derived or durable
//! admission token.  SHA-256 fields below are custody diagnostics only.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_mod = @import("recursive_node_artifact_v1.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const full_leaf = @import("ethereum_incremental_full_leaf_proof_v4.zig");
const proof_artifact =
    @import("ethereum_incremental_full_leaf_proof_artifact_v4.zig");

const M31 = @import("stwo_core").fields.m31.M31;
const Sha256 = std.crypto.hash.sha2.Sha256;
const segment_v2 = frontend.recursion.segment_statement_v2;
const span = frontend.recursion.span_statement;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 2;
pub const ROLE = registry_mod.CircuitRoleV4
    .ethereum_incremental_leaf_wrapper_v4;
pub const STATEMENT_WORD_COUNT: usize = artifact_mod.STATEMENT_WORD_COUNT;

pub const PRODUCTION_ACTIVATION = false;
pub const WRAPPER_PROOF_AVAILABLE = false;
pub const DURABLE_FRESH_CAPABILITY = false;

const CAPABILITY_DOMAIN =
    "stwo-zig/recursive-common-ethereum-incremental-leaf-input/v4\x00";

pub const Error = artifact_mod.Error || error{
    ArtifactCustodyMismatch,
    InvalidEthereumIncrementalLeafInputV4,
    InvalidEthereumIncrementalLeafStatementV4,
};

/// Borrowed stage-102 handoff.  The owner must outlive this view and no field
/// in the view may be serialized as a verifier lease.
pub fn FreshViewV4(comptime Engine: type) type {
    return struct {
        stage101: *const full_leaf.FreshVerifiedCaptureV4(Engine),
        statement_words: *const [STATEMENT_WORD_COUNT]u32,
        coordinate: artifact_mod.TaskCoordinateV1,
        role: registry_mod.CircuitRoleV4 = ROLE,
        capability_identity_sha256: [32]u8,
    };
}

/// Owned, process-local verifier capability.  `coldOpen` is its only mint.
pub fn FreshInputV4(comptime Engine: type) type {
    return struct {
        allocator: std.mem.Allocator,
        stage101: full_leaf.FreshVerifiedCaptureV4(Engine),
        statement_words: [STATEMENT_WORD_COUNT]u32,
        coordinate: artifact_mod.TaskCoordinateV1,
        artifact_byte_count: u64,
        artifact_sha256: [32]u8,
        capability_identity_sha256: [32]u8,

        const Self = @This();

        /// Decode -> destroyable proof ownership -> complete cold verifier ->
        /// owned ProofCapture.  The decoded proof is consumed on every
        /// verifier path and no artifact hash can reach the success result.
        pub fn coldOpen(
            allocator: std.mem.Allocator,
            artifact_bytes: []const u8,
            coordinate: artifact_mod.TaskCoordinateV1,
            limits: proof_artifact.Limits,
        ) !Self {
            return coldOpenInternal(
                allocator,
                artifact_bytes,
                coordinate,
                limits,
                null,
                null,
            );
        }

        /// Cold-open against independently retained STWESG31 roots. Exactly
        /// one full retained-root authentication occurs while decoding the
        /// statement; the resulting lease is moved into the fresh capture.
        pub fn coldOpenWithRetainedSnapshots(
            allocator: std.mem.Allocator,
            artifact_bytes: []const u8,
            coordinate: artifact_mod.TaskCoordinateV1,
            limits: proof_artifact.Limits,
            retained: frontend.air.public_data_v2.PublicDataV2
                .RetainedSnapshots,
            counters: ?*frontend.air.public_data_v2.PublicDataV2
                .ValidationCountersV2,
        ) !Self {
            return coldOpenInternal(
                allocator,
                artifact_bytes,
                coordinate,
                limits,
                retained,
                counters,
            );
        }

        fn coldOpenInternal(
            allocator: std.mem.Allocator,
            artifact_bytes: []const u8,
            coordinate: artifact_mod.TaskCoordinateV1,
            limits: proof_artifact.Limits,
            retained: ?frontend.air.public_data_v2.PublicDataV2
                .RetainedSnapshots,
            counters: ?*frontend.air.public_data_v2.PublicDataV2
                .ValidationCountersV2,
        ) !Self {
            comptime requireStage102Engine(Engine);
            try validateLeafCoordinate(coordinate);
            var decoded = if (retained) |snapshots|
                try proof_artifact.decodeAllocWithRetainedLease(
                    Engine,
                    allocator,
                    artifact_bytes,
                    limits,
                    snapshots,
                    counters,
                )
            else
                try proof_artifact.decodeAlloc(
                    Engine,
                    allocator,
                    artifact_bytes,
                    limits,
                );
            var proof_moved = false;
            defer if (proof_moved)
                decoded.deinitAfterProofMoved(allocator)
            else
                decoded.deinit(allocator);

            var fresh: full_leaf.FreshVerifiedCaptureV4(Engine) = undefined;
            var channel = Engine.Channel{};
            proof_moved = true;
            if (decoded.statement_lease != null) {
                try full_leaf.verifyWithEngineUsingChannelAndCaptureTakingLease(
                    Engine,
                    allocator,
                    &decoded.statement,
                    &decoded.extension,
                    &decoded.role_aware_public.value,
                    &decoded.profile,
                    decoded.proof,
                    decoded.base_claim,
                    &decoded.extension_claim,
                    decoded.bridge_claim,
                    &decoded.statement_lease,
                    &channel,
                    &fresh,
                );
            } else {
                try full_leaf.verifyWithEngineUsingChannelAndCapture(
                    Engine,
                    allocator,
                    &decoded.statement,
                    &decoded.extension,
                    &decoded.role_aware_public.value,
                    &decoded.profile,
                    decoded.proof,
                    decoded.base_claim,
                    &decoded.extension_claim,
                    decoded.bridge_claim,
                    &channel,
                    &fresh,
                );
            }
            var fresh_owned = true;
            errdefer if (fresh_owned) fresh.deinit(allocator);
            try fresh.validate();

            const statement_words = try statementWordsFromFresh(
                Engine,
                &fresh,
            );
            try validateStatementCoordinate(statement_words, coordinate);
            if (fresh.profile.coordinate.segment_index != coordinate.index)
                return error.InvalidEthereumIncrementalLeafStatementV4;

            var result = Self{
                .allocator = allocator,
                .stage101 = fresh,
                .statement_words = statement_words,
                .coordinate = coordinate,
                .artifact_byte_count = @intCast(artifact_bytes.len),
                .artifact_sha256 = sha256(artifact_bytes),
                .capability_identity_sha256 = undefined,
            };
            result.capability_identity_sha256 = capabilityIdentity(
                Engine,
                &result,
            );
            try result.validateAgainstArtifact(artifact_bytes);
            fresh_owned = false;
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.stage101.deinit(self.allocator);
            self.* = undefined;
        }

        /// Rechecks live ownership and exact artifact custody.  This does not
        /// replace `coldOpen`: only an already-owned fresh capture can call it.
        pub fn validateAgainstArtifact(
            self: *const Self,
            artifact_bytes: []const u8,
        ) !void {
            try self.validate();
            const expected_sha = sha256(artifact_bytes);
            if (self.artifact_byte_count !=
                @as(u64, @intCast(artifact_bytes.len)) or
                !std.mem.eql(u8, &self.artifact_sha256, &expected_sha))
            {
                return error.ArtifactCustodyMismatch;
            }
        }

        /// Revalidates the live verifier-owned capability without consulting
        /// a durable digest or reopening transport bytes.
        pub fn validate(self: *const Self) !void {
            try self.stage101.validate();
            try validateLeafCoordinate(self.coordinate);
            const expected_words = try statementWordsFromFresh(
                Engine,
                &self.stage101,
            );
            try validateStatementCoordinate(expected_words, self.coordinate);
            if (self.stage101.profile.coordinate.segment_index !=
                self.coordinate.index or
                !std.meta.eql(self.statement_words, expected_words) or
                self.artifact_byte_count == 0 or
                std.mem.allEqual(u8, &self.artifact_sha256, 0) or
                !std.mem.eql(
                    u8,
                    &self.capability_identity_sha256,
                    &capabilityIdentity(Engine, self),
                ))
            {
                return error.InvalidEthereumIncrementalLeafInputV4;
            }
        }

        pub fn freshView(self: *const Self) FreshViewV4(Engine) {
            return .{
                .stage101 = &self.stage101,
                .statement_words = &self.statement_words,
                .coordinate = self.coordinate,
                .capability_identity_sha256 = self.capability_identity_sha256,
            };
        }
    };
}

fn statementWordsFromFresh(
    comptime Engine: type,
    fresh: *const full_leaf.FreshVerifiedCaptureV4(Engine),
) ![STATEMENT_WORD_COUNT]u32 {
    const authenticated = try fresh.public_data.data.authenticatedView();
    var result: [STATEMENT_WORD_COUNT]u32 = undefined;
    for (
        &result,
        authenticated.statement.base_statement_words,
    ) |*destination, word| destination.* = word.toU32();
    return result;
}

fn validateLeafCoordinate(
    coordinate: artifact_mod.TaskCoordinateV1,
) !void {
    try coordinate.validate();
    if (coordinate.height != 0 or
        try artifact_mod.expectedNodeKind(coordinate) != .real)
    {
        return error.InvalidEthereumIncrementalLeafStatementV4;
    }
}

fn validateStatementCoordinate(
    words: [STATEMENT_WORD_COUNT]u32,
    coordinate: artifact_mod.TaskCoordinateV1,
) !void {
    var canonical: [STATEMENT_WORD_COUNT]M31 = undefined;
    for (&canonical, words) |*destination, word|
        destination.* = M31.fromCanonical(word);
    const statement = span.SpanStatement.fromCanonicalWords(&canonical) catch
        return error.InvalidEthereumIncrementalLeafStatementV4;
    if (statement.slots.height != coordinate.height or
        statement.slots.nodeIndex() != coordinate.index)
    {
        return error.InvalidEthereumIncrementalLeafStatementV4;
    }
    switch (statement.body) {
        .executed => {},
        .empty => return error.InvalidEthereumIncrementalLeafStatementV4,
    }
}

fn capabilityIdentity(
    comptime Engine: type,
    value: *const FreshInputV4(Engine),
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(CAPABILITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u8, @intFromEnum(ROLE));
    hashInt(&hash, u8, value.coordinate.height);
    hashInt(&hash, u32, value.coordinate.index);
    hashInt(&hash, u32, value.coordinate.global_ordinal);
    hashInt(&hash, u64, value.artifact_byte_count);
    hash.update(&value.artifact_sha256);
    hash.update(&value.stage101.identity_sha256);
    for (value.stage101.transcript_final_digest) |word|
        hashInt(&hash, u32, word);
    hashInt(
        &hash,
        u32,
        value.stage101.transcript_final_draw_count,
    );
    for (value.statement_words) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn sha256(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(bytes, &result, .{});
    return result;
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn requireStage102Engine(comptime Engine: type) void {
    if (Engine.Hasher.Hash != frontend.recursion.poseidon2_channel.Digest or
        Engine.Channel != frontend.recursion.poseidon2_channel.Channel)
    {
        @compileError("stage-102 V4 requires the q193 Poseidon2 engine");
    }
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 2 or
        @intFromEnum(ROLE) != 0 or STATEMENT_WORD_COUNT != 412 or
        PRODUCTION_ACTIVATION or WRAPPER_PROOF_AVAILABLE or
        DURABLE_FRESH_CAPABILITY)
    {
        @compileError("Ethereum incremental stage-102 input V4 drifted");
    }
}
