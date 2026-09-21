//! Canonical product boundary for one secure Ethereum H1 parent proof.
//!
//! The nested secure-parent artifact is exact canonical custody, not proof
//! authority. Production minting requires a live verifier-minted leaf pair and
//! the non-serializable `FreshVerificationV1` returned by the q193 verifier.
//! Decoding never recreates either capability. Cold re-admission reopens the
//! 210-to-256 plan, revalidates the live pair, and reruns the secure verifier.

const std = @import("std");
const builtin = @import("builtin");

const batch_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_batch_v1.zig");
const parent_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");
const parent_engine =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");
const statement_plan =
    @import("recursive_temporal_statement_plan_v1.zig");

const channel = @import("stwo_riscv_frontend").recursion.poseidon2_channel;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const PRODUCT_HEADER_BYTE_COUNT: usize = 8;
pub const STATEMENT_ENCODED_BYTE_COUNT: usize = 504;

const PRODUCT_MAGIC = [PRODUCT_HEADER_BYTE_COUNT]u8{
    'S', 'T', 'W', 'H', '1', 'P', '1', 0,
};
const STATEMENT_DOMAIN =
    "stwo-zig/typed-air/ethereum-poseidon-h1-product/v1\x00";

pub const StatementV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    arm_kind: batch_mod.ArmKindV1,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: u16 = 0,
    parent_ordinal: u32,
    parent_index: u32,
    canonical_secure_artifact_byte_count: u64,
    batch_identity_sha256: [32]u8,
    statement_plan_identity_sha256: [32]u8,
    breadth_schedule_identity_sha256: [32]u8,
    task_identity_sha256: [32]u8,
    pair_admission_identity_sha256: [32]u8,
    ingress_identity_sha256: [32]u8,
    session_identity_sha256: [32]u8,
    parent_statement_sha256: [32]u8,
    profile_identity_sha256: [32]u8,
    secure_parent_statement_identity_sha256: [32]u8,
    canonical_secure_artifact_sha256: [32]u8,
    proof_id: channel.Digest,
    capture_id: channel.Digest,
    transcript_id: channel.Digest,
    identity_sha256: [32]u8,

    pub fn validate(self: *const StatementV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or self.reserved != 0 or
            self.parent_ordinal >= batch_mod.REAL_H1_PAIR_COUNT or
            self.parent_index != self.parent_ordinal or
            self.canonical_secure_artifact_byte_count <=
                parent_artifact.ARTIFACT_HEADER_BYTE_COUNT +
                    parent_artifact.STATEMENT_ENCODED_BYTE_COUNT)
        {
            return error.InvalidEthereumPoseidonH1ProductStatement;
        }
        inline for (.{
            self.batch_identity_sha256,
            self.statement_plan_identity_sha256,
            self.breadth_schedule_identity_sha256,
            self.task_identity_sha256,
            self.pair_admission_identity_sha256,
            self.ingress_identity_sha256,
            self.session_identity_sha256,
            self.parent_statement_sha256,
            self.profile_identity_sha256,
            self.secure_parent_statement_identity_sha256,
            self.canonical_secure_artifact_sha256,
            self.identity_sha256,
        }) |value| try requireSha(value);
        inline for (.{ self.proof_id, self.capture_id, self.transcript_id }) |value|
            try requireDigest(value);
        if (!std.mem.eql(u8, &self.identity_sha256, &statementIdentity(self)))
            return error.InvalidEthereumPoseidonH1ProductStatement;
    }

    pub fn validateAgainst(
        self: *const StatementV1,
        allocator: std.mem.Allocator,
        source: *const statement_plan.MaterializedPlanV1,
        batch: *const batch_mod.BatchPlanV1,
        pair: *const batch_mod.FreshPairAdmissionV1,
        session: *const parent_artifact.SessionV1,
        secure: *const parent_artifact.StatementV1,
    ) !void {
        try self.validate();
        try batch.validateAgainst(allocator, source);
        try pair.validateAgainst(batch);
        try session.validate();
        try secure.validateAgainstSession(session);
        const task = &batch.tasks[self.parent_ordinal];
        if (pair.ordinal != self.parent_ordinal or
            pair.parent_index != self.parent_index or
            self.arm_kind != pair.arm_kind or
            !std.mem.eql(u8, &self.batch_identity_sha256, &batch.identity_sha256) or
            !std.mem.eql(u8, &self.statement_plan_identity_sha256, &source.identity) or
            !std.mem.eql(u8, &self.breadth_schedule_identity_sha256, &batch.breadth_schedule_identity_sha256) or
            !std.mem.eql(u8, &self.task_identity_sha256, &task.identity_sha256) or
            !std.mem.eql(u8, &self.pair_admission_identity_sha256, &pair.identity_sha256) or
            !std.mem.eql(u8, &self.ingress_identity_sha256, &pair.ingress_identity_sha256) or
            !std.mem.eql(u8, &self.ingress_identity_sha256, &session.ingress_identity_sha256) or
            !std.mem.eql(u8, &self.session_identity_sha256, &session.identity_sha256) or
            !std.mem.eql(u8, &self.parent_statement_sha256, &task.parent_statement_sha256) or
            !std.mem.eql(u8, &self.parent_statement_sha256, &session.parent_statement_sha256) or
            !std.mem.eql(u8, &self.profile_identity_sha256, &task.profile_identity_sha256) or
            !std.mem.eql(u8, &self.profile_identity_sha256, &session.profile_identity_sha256) or
            !std.mem.eql(u8, &self.secure_parent_statement_identity_sha256, &secure.identity_sha256) or
            !std.meta.eql(self.proof_id, secure.proof_id) or
            !std.meta.eql(self.capture_id, secure.capture_id) or
            !std.meta.eql(self.transcript_id, secure.transcript_id))
        {
            return error.EthereumPoseidonH1ProductAuthorityMismatch;
        }
    }
};

/// Owned bytes for one task-bound H1 proof. The nested artifact remains
/// untrusted until `coldReadmit` succeeds.
pub const OwnedProductV1 = struct {
    allocator: std.mem.Allocator,
    statement: StatementV1,
    secure_artifact_bytes: []u8,

    pub fn initFromFreshVerifier(
        allocator: std.mem.Allocator,
        source: *const statement_plan.MaterializedPlanV1,
        batch: *const batch_mod.BatchPlanV1,
        ordinal: usize,
        verifier_minted: anytype,
        session: *const parent_artifact.SessionV1,
        artifact: *const parent_artifact.OwnedArtifactV1,
        fresh: *const parent_engine.FreshVerificationV1,
    ) !OwnedProductV1 {
        try batch.validateAgainst(allocator, source);
        const pair = try batch_mod.admitVerifierMintedPair(
            allocator,
            batch,
            ordinal,
            verifier_minted,
        );
        try artifact.validateCustody();
        if (!std.meta.eql(artifact.statement, fresh.statement))
            return error.EthereumPoseidonH1ProductFreshnessMismatch;
        const secure_bytes = try artifact.encodeCanonicalAlloc(allocator);
        errdefer allocator.free(secure_bytes);
        const secure_sha256 = sha256(secure_bytes);
        var statement = StatementV1{
            .arm_kind = pair.arm_kind,
            .parent_ordinal = @intCast(ordinal),
            .parent_index = pair.parent_index,
            .canonical_secure_artifact_byte_count = @intCast(secure_bytes.len),
            .batch_identity_sha256 = batch.identity_sha256,
            .statement_plan_identity_sha256 = source.identity,
            .breadth_schedule_identity_sha256 = batch.breadth_schedule_identity_sha256,
            .task_identity_sha256 = batch.tasks[ordinal].identity_sha256,
            .pair_admission_identity_sha256 = pair.identity_sha256,
            .ingress_identity_sha256 = pair.ingress_identity_sha256,
            .session_identity_sha256 = session.identity_sha256,
            .parent_statement_sha256 = session.parent_statement_sha256,
            .profile_identity_sha256 = session.profile_identity_sha256,
            .secure_parent_statement_identity_sha256 = artifact.statement.identity_sha256,
            .canonical_secure_artifact_sha256 = secure_sha256,
            .proof_id = artifact.statement.proof_id,
            .capture_id = artifact.statement.capture_id,
            .transcript_id = artifact.statement.transcript_id,
            .identity_sha256 = undefined,
        };
        statement.identity_sha256 = statementIdentity(&statement);
        try statement.validateAgainst(
            allocator,
            source,
            batch,
            &pair,
            session,
            &artifact.statement,
        );
        var result = OwnedProductV1{
            .allocator = allocator,
            .statement = statement,
            .secure_artifact_bytes = secure_bytes,
        };
        try result.validateCustody();
        return result;
    }

    pub fn deinit(self: *OwnedProductV1) void {
        self.allocator.free(self.secure_artifact_bytes);
        self.* = undefined;
    }

    /// Validates canonical nested custody only. It never returns fresh proof
    /// authority and deliberately does not accept a detached success digest.
    pub fn validateCustody(self: *const OwnedProductV1) !void {
        try self.statement.validate();
        if (@as(u64, @intCast(self.secure_artifact_bytes.len)) !=
            self.statement.canonical_secure_artifact_byte_count or
            !std.mem.eql(u8, &sha256(self.secure_artifact_bytes), &self.statement.canonical_secure_artifact_sha256))
        {
            return error.InvalidEthereumPoseidonH1ProductArtifact;
        }
        var decoded = parent_artifact.OwnedArtifactV1.decodeCanonical(
            self.allocator,
            self.secure_artifact_bytes,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidEthereumPoseidonH1ProductArtifact,
        };
        defer decoded.deinit();
        if (!std.mem.eql(u8, &decoded.statement.identity_sha256, &self.statement.secure_parent_statement_identity_sha256) or
            !std.meta.eql(decoded.statement.proof_id, self.statement.proof_id) or
            !std.meta.eql(decoded.statement.capture_id, self.statement.capture_id) or
            !std.meta.eql(decoded.statement.transcript_id, self.statement.transcript_id))
        {
            return error.InvalidEthereumPoseidonH1ProductArtifact;
        }
    }

    pub fn encodeCanonicalAlloc(
        self: *const OwnedProductV1,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        try self.validateCustody();
        const byte_count = std.math.add(
            usize,
            PRODUCT_HEADER_BYTE_COUNT + STATEMENT_ENCODED_BYTE_COUNT,
            self.secure_artifact_bytes.len,
        ) catch return error.InvalidEthereumPoseidonH1ProductArtifact;
        const result = try allocator.alloc(u8, byte_count);
        errdefer allocator.free(result);
        @memcpy(result[0..PRODUCT_HEADER_BYTE_COUNT], &PRODUCT_MAGIC);
        var writer = Writer{
            .bytes = result[PRODUCT_HEADER_BYTE_COUNT..][0..STATEMENT_ENCODED_BYTE_COUNT],
        };
        writeStatement(&writer, &self.statement);
        std.debug.assert(writer.at == STATEMENT_ENCODED_BYTE_COUNT);
        @memcpy(
            result[PRODUCT_HEADER_BYTE_COUNT + STATEMENT_ENCODED_BYTE_COUNT ..],
            self.secure_artifact_bytes,
        );
        return result;
    }

    pub fn decodeCanonical(
        allocator: std.mem.Allocator,
        bytes: []const u8,
    ) !OwnedProductV1 {
        const fixed = PRODUCT_HEADER_BYTE_COUNT + STATEMENT_ENCODED_BYTE_COUNT;
        if (bytes.len <= fixed or
            !std.mem.eql(u8, bytes[0..PRODUCT_HEADER_BYTE_COUNT], &PRODUCT_MAGIC))
        {
            return error.InvalidEthereumPoseidonH1ProductArtifact;
        }
        var reader = Reader{
            .bytes = bytes[PRODUCT_HEADER_BYTE_COUNT..][0..STATEMENT_ENCODED_BYTE_COUNT],
        };
        const statement = try readStatement(&reader);
        if (reader.at != reader.bytes.len)
            return error.InvalidEthereumPoseidonH1ProductArtifact;
        const owned = try allocator.dupe(u8, bytes[fixed..]);
        var result = OwnedProductV1{
            .allocator = allocator,
            .statement = statement,
            .secure_artifact_bytes = owned,
        };
        errdefer result.deinit();
        try result.validateCustody();
        const canonical = try result.encodeCanonicalAlloc(allocator);
        defer allocator.free(canonical);
        if (!std.mem.eql(u8, bytes, canonical))
            return error.InvalidEthereumPoseidonH1ProductArtifact;
        return result;
    }

    pub fn requireProductionPublication(self: *const OwnedProductV1) !void {
        try self.validateCustody();
        if (!PRODUCTION_ACTIVATION)
            return error.EthereumPoseidonH1ProductPublicationUnavailable;
    }
};

/// The only transport re-admission edge. The live pair is revalidated, the
/// nested artifact is decoded canonically, and the q193 kernel is rerun before
/// its non-serializable result is returned.
pub fn coldReadmit(
    comptime Kernel: type,
    allocator: std.mem.Allocator,
    authority_inputs: anytype,
    verifier_minted: anytype,
    source: *const statement_plan.MaterializedPlanV1,
    batch: *const batch_mod.BatchPlanV1,
    session: *const parent_artifact.SessionV1,
    product: *const OwnedProductV1,
) !parent_engine.FreshVerificationV1 {
    try product.validateCustody();
    try batch.validateAgainst(allocator, source);
    const pair = try batch_mod.admitVerifierMintedPair(
        allocator,
        batch,
        @intCast(product.statement.parent_ordinal),
        verifier_minted,
    );
    var secure = try parent_artifact.OwnedArtifactV1.decodeCanonical(
        allocator,
        product.secure_artifact_bytes,
    );
    defer secure.deinit();
    try product.statement.validateAgainst(
        allocator,
        source,
        batch,
        &pair,
        session,
        &secure.statement,
    );
    var fresh = try Kernel.verifyCold(
        allocator,
        authority_inputs,
        session,
        &secure,
    );
    errdefer fresh.deinit();
    if (!std.meta.eql(fresh.statement, secure.statement))
        return error.EthereumPoseidonH1ProductFreshnessMismatch;
    return fresh;
}

fn statementIdentity(value: *const StatementV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(STATEMENT_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.arm_kind));
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hashInt(&hash, u16, value.reserved);
    hashInt(&hash, u32, value.parent_ordinal);
    hashInt(&hash, u32, value.parent_index);
    hashInt(&hash, u64, value.canonical_secure_artifact_byte_count);
    inline for (.{
        value.batch_identity_sha256,
        value.statement_plan_identity_sha256,
        value.breadth_schedule_identity_sha256,
        value.task_identity_sha256,
        value.pair_admission_identity_sha256,
        value.ingress_identity_sha256,
        value.session_identity_sha256,
        value.parent_statement_sha256,
        value.profile_identity_sha256,
        value.secure_parent_statement_identity_sha256,
        value.canonical_secure_artifact_sha256,
    }) |item| hash.update(&item);
    hashDigest(&hash, value.proof_id);
    hashDigest(&hash, value.capture_id);
    hashDigest(&hash, value.transcript_id);
    return hash.finalResult();
}

fn writeStatement(writer: *Writer, value: *const StatementV1) void {
    writer.u16Value(value.format_version);
    writer.u16Value(value.schema_version);
    writer.u8Value(@intFromEnum(value.arm_kind));
    writer.u8Value(@intFromBool(value.production_activation));
    writer.u16Value(value.reserved);
    writer.u32Value(value.parent_ordinal);
    writer.u32Value(value.parent_index);
    writer.u64Value(value.canonical_secure_artifact_byte_count);
    inline for (.{
        value.batch_identity_sha256,
        value.statement_plan_identity_sha256,
        value.breadth_schedule_identity_sha256,
        value.task_identity_sha256,
        value.pair_admission_identity_sha256,
        value.ingress_identity_sha256,
        value.session_identity_sha256,
        value.parent_statement_sha256,
        value.profile_identity_sha256,
        value.secure_parent_statement_identity_sha256,
        value.canonical_secure_artifact_sha256,
    }) |item| writer.sha(item);
    writer.digest(value.proof_id);
    writer.digest(value.capture_id);
    writer.digest(value.transcript_id);
    writer.sha(value.identity_sha256);
}

fn readStatement(reader: *Reader) !StatementV1 {
    var result = StatementV1{
        .format_version = reader.u16Value(),
        .schema_version = reader.u16Value(),
        .arm_kind = std.meta.intToEnum(
            batch_mod.ArmKindV1,
            reader.u8Value(),
        ) catch return error.InvalidEthereumPoseidonH1ProductStatement,
        .production_activation = try reader.boolValue(),
        .reserved = reader.u16Value(),
        .parent_ordinal = reader.u32Value(),
        .parent_index = reader.u32Value(),
        .canonical_secure_artifact_byte_count = reader.u64Value(),
        .batch_identity_sha256 = reader.sha(),
        .statement_plan_identity_sha256 = reader.sha(),
        .breadth_schedule_identity_sha256 = reader.sha(),
        .task_identity_sha256 = reader.sha(),
        .pair_admission_identity_sha256 = reader.sha(),
        .ingress_identity_sha256 = reader.sha(),
        .session_identity_sha256 = reader.sha(),
        .parent_statement_sha256 = reader.sha(),
        .profile_identity_sha256 = reader.sha(),
        .secure_parent_statement_identity_sha256 = reader.sha(),
        .canonical_secure_artifact_sha256 = reader.sha(),
        .proof_id = reader.digest(),
        .capture_id = reader.digest(),
        .transcript_id = reader.digest(),
        .identity_sha256 = reader.sha(),
    };
    try result.validate();
    return result;
}

const Writer = struct {
    bytes: []u8,
    at: usize = 0,

    fn bytesValue(self: *Writer, value: []const u8) void {
        @memcpy(self.bytes[self.at..][0..value.len], value);
        self.at += value.len;
    }
    fn u8Value(self: *Writer, value: u8) void {
        self.bytes[self.at] = value;
        self.at += 1;
    }
    fn u16Value(self: *Writer, value: u16) void {
        std.mem.writeInt(u16, self.bytes[self.at..][0..2], value, .little);
        self.at += 2;
    }
    fn u32Value(self: *Writer, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.at..][0..4], value, .little);
        self.at += 4;
    }
    fn u64Value(self: *Writer, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.at..][0..8], value, .little);
        self.at += 8;
    }
    fn sha(self: *Writer, value: [32]u8) void {
        self.bytesValue(&value);
    }
    fn digest(self: *Writer, value: channel.Digest) void {
        for (value) |word| self.u32Value(word);
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,

    fn take(self: *Reader, count: usize) []const u8 {
        const result = self.bytes[self.at..][0..count];
        self.at += count;
        return result;
    }
    fn u8Value(self: *Reader) u8 {
        const result = self.bytes[self.at];
        self.at += 1;
        return result;
    }
    fn boolValue(self: *Reader) !bool {
        return switch (self.u8Value()) {
            0 => false,
            1 => true,
            else => error.InvalidEthereumPoseidonH1ProductStatement,
        };
    }
    fn u16Value(self: *Reader) u16 {
        return std.mem.readInt(u16, self.take(2)[0..2], .little);
    }
    fn u32Value(self: *Reader) u32 {
        return std.mem.readInt(u32, self.take(4)[0..4], .little);
    }
    fn u64Value(self: *Reader) u64 {
        return std.mem.readInt(u64, self.take(8)[0..8], .little);
    }
    fn sha(self: *Reader) [32]u8 {
        return self.take(32)[0..32].*;
    }
    fn digest(self: *Reader) channel.Digest {
        var result: channel.Digest = undefined;
        for (&result) |*word| word.* = self.u32Value();
        return result;
    }
};

fn sha256(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(bytes, &result, .{});
    return result;
}

fn requireSha(value: [32]u8) !void {
    if (std.mem.allEqual(u8, &value, 0))
        return error.InvalidEthereumPoseidonH1ProductStatement;
}

fn requireDigest(value: channel.Digest) !void {
    var nonzero = false;
    for (value) |word| {
        if (word >= @import("stwo_core").fields.m31.Modulus)
            return error.InvalidEthereumPoseidonH1ProductStatement;
        nonzero = nonzero or word != 0;
    }
    if (!nonzero) return error.InvalidEthereumPoseidonH1ProductStatement;
}

fn hashDigest(hash: *Sha256, value: channel.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub const testing = struct {
    pub fn resealStatement(value: *StatementV1) void {
        requireTest();
        value.identity_sha256 = statementIdentity(value);
    }

    pub fn initCustodyOnly(
        allocator: std.mem.Allocator,
        statement: StatementV1,
        secure_artifact: *const parent_artifact.OwnedArtifactV1,
    ) !OwnedProductV1 {
        requireTest();
        const bytes = try secure_artifact.encodeCanonicalAlloc(allocator);
        errdefer allocator.free(bytes);
        var result = OwnedProductV1{
            .allocator = allocator,
            .statement = statement,
            .secure_artifact_bytes = bytes,
        };
        try result.validateCustody();
        return result;
    }

    fn requireTest() void {
        if (!builtin.is_test)
            @panic("Ethereum H1 product testing helper used outside test build");
    }
};

comptime {
    if (STATEMENT_ENCODED_BYTE_COUNT != 504 or
        PRODUCT_HEADER_BYTE_COUNT != PRODUCT_MAGIC.len or
        @sizeOf(channel.Digest) != 32 or PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum Poseidon h1 product ABI drifted");
    }
}
