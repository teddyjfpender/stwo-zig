//! Canonical cold transport for one full Ethereum + incremental-memory V4 proof.
//!
//! The envelope retains the complete authenticated V2 statement, exact
//! role-aware V1 public boundary, fourteen-component Ethereum statement,
//! pointer-free V4 profile, every interaction claim, and postcard proof bytes.
//! Its SHA seal is transport custody only; decode never mints proof admission.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const postcard = @import("interop_postcard");

const profile_mod = @import("ethereum_incremental_full_leaf_profile_v4.zig");
const support = @import("ethereum_incremental_full_leaf_profile_v4_wire.zig");

const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const public_data = frontend.air.public_data;
const public_data_v2 = frontend.air.public_data_v2;
const statement_mod = frontend.air.statement;
const statement_v2 = frontend.air.statement_v2;
const ethereum_statement = frontend.air.guest_precompile.ethereum_statement;
const prover = frontend.prover_mod;
const statement_wire = prover.guest_precompile
    .ethereum_segment_artifact_statement_wire;
const ethereum_wire = prover.guest_precompile.ethereum_proof_artifact_wire;
const base_wire = prover.guest_precompile.proof_artifact_wire;
const ethereum_types = prover.guest_precompile.ethereum_types;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 2;
pub const MAGIC = [8]u8{ 'S', 'T', 'W', 'I', 'E', 'F', '0', '4' };
pub const Limits = base_wire.Limits;
pub const PRODUCTION_ACTIVE = false;

const CONTENT_DOMAIN =
    "stwo.ethereum.incremental-full-leaf-proof.v4\x00";
const SECTION_COUNT: usize = 6;
const HEADER_BYTES: usize = 8 + 2 + 2 + 4 + (1 + SECTION_COUNT) * @sizeOf(u64);
const SEAL_BYTES: usize = 32;
const QM31_BYTES: usize = 4 * @sizeOf(u32);

pub fn EncodeInput(comptime Engine: type) type {
    return struct {
        statement: *const statement_v2.RiscVStatementV2,
        role_aware_public: *const public_data.PublicData,
        extension: *const ethereum_statement.Statement,
        profile: *const profile_mod.AuthorityV4,
        base_claim: *const statement_mod.RiscVInteractionClaim,
        extension_claim: *const ethereum_types.ExtensionClaim,
        bridge_claim: QM31,
        proof: *const prover.ProofForEngine(Engine),
    };
}

pub fn Decoded(comptime Engine: type) type {
    return struct {
        statement: statement_v2.RiscVStatementV2,
        role_aware_public: support.OwnedRolePublicTransportV4,
        extension: ethereum_statement.Statement,
        profile: profile_mod.AuthorityV4,
        base_claim: *statement_mod.RiscVInteractionClaim,
        extension_claim: ethereum_types.ExtensionClaim,
        bridge_claim: QM31,
        proof: prover.ProofForEngine(Engine),
        canonical_words: ?[]M31,
        statement_lease: ?public_data_v2.PublicDataV2.OwnedValidatedLeaseV2,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            self.releaseMetadata(allocator);
        }

        pub fn deinitAfterProofMoved(
            self: *Self,
            allocator: std.mem.Allocator,
        ) void {
            self.releaseMetadata(allocator);
        }

        fn releaseMetadata(self: *Self, allocator: std.mem.Allocator) void {
            allocator.destroy(self.base_claim);
            self.role_aware_public.deinit();
            if (self.statement_lease) |*lease|
                lease.deinit()
            else if (self.canonical_words) |words|
                allocator.free(words);
            self.* = undefined;
        }
    };
}

pub fn encodeAlloc(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    input: EncodeInput(Engine),
    limits: Limits,
) ![]u8 {
    try limits.validate();
    try input.statement.validate();
    try input.extension.validateV2(input.statement);
    try input.extension_claim.validate(input.extension);
    try input.profile.validateAgainstStatement(
        input.statement,
        input.extension,
        input.role_aware_public,
    );
    if (input.role_aware_public.io_entries.input_len > limits.max_input_bytes or
        input.role_aware_public.io_entries.output_len > limits.max_output_bytes or
        !std.meta.eql(
            try input.profile.pcsConfig(),
            input.proof.commitment_scheme_proof.config,
        ) or input.proof.commitment_scheme_proof.commitments.items.len != 4)
    {
        return error.InvalidIncrementalFullLeafProofArtifactV4;
    }

    var statement_section: std.ArrayList(u8) = .empty;
    defer statement_section.deinit(allocator);
    try statement_wire.encode(
        statement_section.writer(allocator),
        input.statement,
        limits.max_artifact_bytes,
    );
    var public_section: std.ArrayList(u8) = .empty;
    defer public_section.deinit(allocator);
    try support.encodeRolePublic(
        public_section.writer(allocator),
        input.role_aware_public,
    );
    var extension_section: std.ArrayList(u8) = .empty;
    defer extension_section.deinit(allocator);
    try ethereum_wire.encodeExtension(
        extension_section.writer(allocator),
        input.extension,
    );
    if (extension_section.items.len != ethereum_wire.extension_encoded_size)
        return error.InvalidIncrementalFullLeafProofArtifactV4;
    var profile_section: std.ArrayList(u8) = .empty;
    defer profile_section.deinit(allocator);
    try support.encodeProfile(
        profile_section.writer(allocator),
        input.profile,
        input.statement,
        input.extension,
        input.role_aware_public,
    );
    var claim_section: std.ArrayList(u8) = .empty;
    defer claim_section.deinit(allocator);
    try ethereum_wire.encodeClaim(
        claim_section.writer(allocator),
        &input.statement.core,
        input.extension,
        input.base_claim,
        input.extension_claim,
    );
    try base_wire.writeQm31(claim_section.writer(allocator), input.bridge_claim);
    var proof_section: std.ArrayList(u8) = .empty;
    defer proof_section.deinit(allocator);
    try postcard.serializeProof(
        Engine.Hasher,
        proof_section.writer(allocator),
        input.proof.*,
    );
    if (proof_section.items.len == 0 or
        proof_section.items.len > limits.max_proof_bytes)
    {
        return error.ProofResourceLimitExceeded;
    }

    const sections = .{
        statement_section.items,
        public_section.items,
        extension_section.items,
        profile_section.items,
        claim_section.items,
        proof_section.items,
    };
    var total = HEADER_BYTES + SEAL_BYTES;
    inline for (sections) |section| total = std.math.add(
        usize,
        total,
        section.len,
    ) catch return error.ArtifactResourceLimitExceeded;
    if (total > limits.max_artifact_bytes)
        return error.ArtifactResourceLimitExceeded;
    const bytes = try allocator.alloc(u8, total);
    errdefer allocator.free(bytes);
    var stream = std.io.fixedBufferStream(bytes);
    const writer = stream.writer();
    try writer.writeAll(&MAGIC);
    try base_wire.writeInt(writer, u16, FORMAT_VERSION);
    try base_wire.writeInt(writer, u16, SCHEMA_VERSION);
    try base_wire.writeInt(writer, u32, 0);
    try base_wire.writeInt(writer, u64, @intCast(total));
    inline for (sections) |section|
        try base_wire.writeInt(writer, u64, @intCast(section.len));
    inline for (sections) |section| try writer.writeAll(section);
    const seal = contentIdentity(bytes[0..stream.pos]);
    try writer.writeAll(&seal);
    if (stream.pos != bytes.len)
        return error.InvalidIncrementalFullLeafProofArtifactV4;
    return bytes;
}

pub fn decodeAlloc(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    bytes: []const u8,
    limits: Limits,
) !Decoded(Engine) {
    return decodeAllocWithRetained(
        Engine,
        allocator,
        bytes,
        limits,
        null,
        null,
    );
}

/// Independent cold-boundary decoder. The retained roots are external
/// STWESG31 authority, not fields trusted from this proof envelope.
pub fn decodeAllocWithRetainedLease(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    bytes: []const u8,
    limits: Limits,
    retained: public_data_v2.PublicDataV2.RetainedSnapshots,
    counters: ?*public_data_v2.PublicDataV2.ValidationCountersV2,
) !Decoded(Engine) {
    return decodeAllocWithRetained(
        Engine,
        allocator,
        bytes,
        limits,
        retained,
        counters,
    );
}

fn decodeAllocWithRetained(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    bytes: []const u8,
    limits: Limits,
    retained: ?public_data_v2.PublicDataV2.RetainedSnapshots,
    counters: ?*public_data_v2.PublicDataV2.ValidationCountersV2,
) !Decoded(Engine) {
    try limits.validate();
    if (bytes.len < HEADER_BYTES + SEAL_BYTES or
        bytes.len > limits.max_artifact_bytes)
    {
        return error.InvalidIncrementalFullLeafProofArtifactV4;
    }
    var cursor = base_wire.Cursor.init(bytes);
    if (!std.mem.eql(u8, try cursor.take(MAGIC.len), &MAGIC) or
        try cursor.readInt(u16) != FORMAT_VERSION or
        try cursor.readInt(u16) != SCHEMA_VERSION or
        try cursor.readInt(u32) != 0 or
        try cursor.readInt(u64) != @as(u64, @intCast(bytes.len)))
    {
        return error.InvalidIncrementalFullLeafProofArtifactV4;
    }
    var lengths: [SECTION_COUNT]usize = undefined;
    for (&lengths) |*length| length.* = std.math.cast(
        usize,
        try cursor.readInt(u64),
    ) orelse return error.ArtifactResourceLimitExceeded;
    if (lengths[5] == 0 or lengths[5] > limits.max_proof_bytes or
        lengths[2] != ethereum_wire.extension_encoded_size)
    {
        return error.ProofResourceLimitExceeded;
    }
    const statement_bytes = try cursor.take(lengths[0]);
    const public_bytes = try cursor.take(lengths[1]);
    const extension_bytes = try cursor.take(lengths[2]);
    const profile_bytes = try cursor.take(lengths[3]);
    const claim_bytes = try cursor.take(lengths[4]);
    const proof_bytes = try cursor.take(lengths[5]);
    const sealed_prefix_len = cursor.position;
    const retained_seal = try cursor.take(SEAL_BYTES);
    try cursor.requireDone();
    const expected_seal = contentIdentity(bytes[0..sealed_prefix_len]);
    if (!std.mem.eql(u8, retained_seal, &expected_seal))
        return error.IncrementalFullLeafProofArtifactContentMismatchV4;

    var owned_statement: ?statement_wire.Owned = null;
    var retained_statement: ?statement_wire.RetainedOwned = null;
    if (retained) |snapshots| {
        retained_statement = try statement_wire.decodeWithRetainedLease(
            allocator,
            statement_bytes,
            limits.max_artifact_bytes,
            snapshots,
            counters,
        );
    } else {
        owned_statement = try statement_wire.decode(
            allocator,
            statement_bytes,
            limits.max_artifact_bytes,
        );
    }
    var statement_owned = true;
    errdefer if (statement_owned) {
        if (retained_statement) |*value|
            value.deinit()
        else
            owned_statement.?.deinit(allocator);
    };
    const statement_value = if (retained_statement) |*value|
        &value.value
    else
        &owned_statement.?.value;
    var role_public = try support.decodeRolePublic(
        allocator,
        public_bytes,
        statement_value,
        limits,
    );
    var role_owned = true;
    errdefer if (role_owned) role_public.deinit();
    const extension = try ethereum_wire.decodeExtension(extension_bytes);
    try extension.validateV2(statement_value);
    const profile = try support.decodeProfile(
        profile_bytes,
        statement_value,
        &extension,
        &role_public.value,
    );
    if (claim_bytes.len < QM31_BYTES)
        return error.InvalidIncrementalFullLeafProofArtifactV4;
    var claims = try ethereum_wire.decodeClaim(
        allocator,
        claim_bytes[0 .. claim_bytes.len - QM31_BYTES],
        &statement_value.core,
        &extension,
    );
    var claim_owned = true;
    errdefer if (claim_owned) claims.deinit(allocator);
    var claim_cursor = base_wire.Cursor.init(
        claim_bytes[claim_bytes.len - QM31_BYTES ..],
    );
    const bridge_claim = try claim_cursor.readQm31();
    try claim_cursor.requireDone();

    var proof_stream = std.io.fixedBufferStream(proof_bytes);
    var proof = try postcard.deserializeProof(
        Engine.Hasher,
        allocator,
        proof_stream.reader(),
    );
    var proof_owned = true;
    errdefer if (proof_owned) proof.deinit(allocator);
    if (proof_stream.pos != proof_bytes.len or
        !std.meta.eql(
            try profile.pcsConfig(),
            proof.commitment_scheme_proof.config,
        ) or proof.commitment_scheme_proof.commitments.items.len != 4)
    {
        return error.InvalidIncrementalFullLeafProofArtifactV4;
    }
    const result = Decoded(Engine){
        .statement = statement_value.*,
        .role_aware_public = role_public,
        .extension = extension,
        .profile = profile,
        .base_claim = claims.base,
        .extension_claim = claims.extension,
        .bridge_claim = bridge_claim,
        .proof = proof,
        .canonical_words = if (owned_statement) |value|
            value.canonical_words
        else
            null,
        .statement_lease = if (retained_statement) |value|
            value.lease
        else
            null,
    };
    statement_owned = false;
    role_owned = false;
    claim_owned = false;
    proof_owned = false;
    return result;
}

fn contentIdentity(bytes: []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CONTENT_DOMAIN);
    hash.update(bytes);
    return hash.finalResult();
}

comptime {
    if (PRODUCTION_ACTIVE or FORMAT_VERSION != 4 or SCHEMA_VERSION != 2 or
        SECTION_COUNT != 6 or HEADER_BYTES != 72 or SEAL_BYTES != 32)
    {
        @compileError("incremental full-leaf proof artifact V4 drifted");
    }
}
