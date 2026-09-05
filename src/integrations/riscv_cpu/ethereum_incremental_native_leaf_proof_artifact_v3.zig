//! Canonical cold transport for one incremental-memory native V3 leaf proof.
//!
//! The envelope retains the complete SegmentV2 statement, pointer-free V3
//! profile, active base/bridge claims, and canonical postcard proof bytes.
//! Its SHA-256 seal is transport custody only: decoding never mints a proof
//! capability, and the sibling fresh verifier must still execute AIR/PCS/FRI.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const postcard = @import("interop_postcard");

const profile_mod = @import("ethereum_incremental_native_leaf_profile_v3.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const statement_mod = frontend.air.statement;
const statement_v2 = frontend.air.statement_v2;
const prover = frontend.prover_mod;
const statement_wire = prover.guest_precompile
    .ethereum_segment_artifact_statement_wire;
const base_wire = prover.guest_precompile.proof_artifact_wire;

pub const FORMAT_VERSION: u16 = 3;
pub const SCHEMA_VERSION: u16 = 1;
pub const MAGIC = [8]u8{ 'S', 'T', 'W', 'I', 'N', 'P', '0', '3' };
pub const Limits = base_wire.Limits;
pub const PRODUCTION_ACTIVE = false;

const CONTENT_DOMAIN =
    "stwo.ethereum.incremental-native-leaf-proof.v3\x00";
const HEADER_BYTES: usize = 8 + 2 + 2 + 4 + 5 * @sizeOf(u64);
const SEAL_BYTES: usize = 32;

pub fn EncodeInput(comptime Engine: type) type {
    return struct {
        statement: *const statement_v2.RiscVStatementV2,
        profile: *const profile_mod.AuthorityV3,
        base_claim: *const statement_mod.RiscVInteractionClaim,
        bridge_claim: QM31,
        proof: *const prover.ProofForEngine(Engine),
    };
}

pub fn Decoded(comptime Engine: type) type {
    return struct {
        statement: statement_v2.RiscVStatementV2,
        profile: profile_mod.AuthorityV3,
        base_claim: *statement_mod.RiscVInteractionClaim,
        bridge_claim: QM31,
        proof: prover.ProofForEngine(Engine),
        canonical_words: []M31,

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
            allocator.free(self.canonical_words);
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
    try input.profile.validateAgainstStatement(input.statement);
    const pcs_config = try input.profile.protocol.pcs.config();
    if (!std.meta.eql(
        pcs_config,
        input.proof.commitment_scheme_proof.config,
    ) or input.proof.commitment_scheme_proof.commitments.items.len !=
        prover.incremental_native_verifier_v3.COMMITMENT_TREE_COUNT)
    {
        return error.InvalidIncrementalNativeProofArtifact;
    }

    var statement_section: std.ArrayList(u8) = .empty;
    defer statement_section.deinit(allocator);
    try statement_wire.encode(
        statement_section.writer(allocator),
        input.statement,
        limits.max_artifact_bytes,
    );
    var profile_section: std.ArrayList(u8) = .empty;
    defer profile_section.deinit(allocator);
    try encodeProfile(
        profile_section.writer(allocator),
        input.profile,
        input.statement,
    );
    var claim_section: std.ArrayList(u8) = .empty;
    defer claim_section.deinit(allocator);
    try base_wire.encodeBaseClaim(
        claim_section.writer(allocator),
        &input.statement.core,
        input.base_claim,
    );
    try base_wire.writeQm31(
        claim_section.writer(allocator),
        input.bridge_claim,
    );
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

    const lengths = [4]usize{
        statement_section.items.len,
        profile_section.items.len,
        claim_section.items.len,
        proof_section.items.len,
    };
    var total = HEADER_BYTES + SEAL_BYTES;
    for (lengths) |length| total = std.math.add(usize, total, length) catch
        return error.ArtifactResourceLimitExceeded;
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
    for (lengths) |length|
        try base_wire.writeInt(writer, u64, @intCast(length));
    try writer.writeAll(statement_section.items);
    try writer.writeAll(profile_section.items);
    try writer.writeAll(claim_section.items);
    try writer.writeAll(proof_section.items);
    const seal = contentIdentity(bytes[0..stream.pos]);
    try writer.writeAll(&seal);
    if (stream.pos != bytes.len)
        return error.InvalidIncrementalNativeProofArtifact;
    return bytes;
}

pub fn decodeAlloc(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    bytes: []const u8,
    limits: Limits,
) !Decoded(Engine) {
    try limits.validate();
    if (bytes.len < HEADER_BYTES + SEAL_BYTES or
        bytes.len > limits.max_artifact_bytes)
    {
        return error.InvalidIncrementalNativeProofArtifact;
    }
    var cursor = base_wire.Cursor.init(bytes);
    if (!std.mem.eql(u8, try cursor.take(MAGIC.len), &MAGIC) or
        try cursor.readInt(u16) != FORMAT_VERSION or
        try cursor.readInt(u16) != SCHEMA_VERSION or
        try cursor.readInt(u32) != 0 or
        try cursor.readInt(u64) != @as(u64, @intCast(bytes.len)))
    {
        return error.InvalidIncrementalNativeProofArtifact;
    }
    var lengths: [4]usize = undefined;
    for (&lengths) |*length| length.* = std.math.cast(
        usize,
        try cursor.readInt(u64),
    ) orelse return error.ArtifactResourceLimitExceeded;
    if (lengths[3] == 0 or lengths[3] > limits.max_proof_bytes)
        return error.ProofResourceLimitExceeded;
    const statement_bytes = try cursor.take(lengths[0]);
    const profile_bytes = try cursor.take(lengths[1]);
    const claim_bytes = try cursor.take(lengths[2]);
    const proof_bytes = try cursor.take(lengths[3]);
    const sealed_prefix_len = cursor.position;
    const retained_seal = try cursor.take(SEAL_BYTES);
    try cursor.requireDone();
    const expected_seal = contentIdentity(bytes[0..sealed_prefix_len]);
    if (!std.mem.eql(u8, retained_seal, &expected_seal))
        return error.IncrementalNativeProofArtifactContentMismatch;

    var owned_statement = try statement_wire.decode(
        allocator,
        statement_bytes,
        limits.max_artifact_bytes,
    );
    var statement_owned = true;
    errdefer if (statement_owned) owned_statement.deinit(allocator);
    const profile = try decodeProfile(profile_bytes, &owned_statement.value);
    const base_claim = try allocator.create(statement_mod.RiscVInteractionClaim);
    var claim_owned = true;
    errdefer if (claim_owned) allocator.destroy(base_claim);
    var claim_cursor = base_wire.Cursor.init(claim_bytes);
    try base_wire.decodeBaseClaimInto(
        &claim_cursor,
        &owned_statement.value.core,
        base_claim,
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
            try profile.protocol.pcs.config(),
            proof.commitment_scheme_proof.config,
        ) or proof.commitment_scheme_proof.commitments.items.len != 4)
    {
        return error.InvalidIncrementalNativeProofArtifact;
    }

    const result = Decoded(Engine){
        .statement = owned_statement.value,
        .profile = profile,
        .base_claim = base_claim,
        .bridge_claim = bridge_claim,
        .proof = proof,
        .canonical_words = owned_statement.canonical_words,
    };
    statement_owned = false;
    claim_owned = false;
    proof_owned = false;
    return result;
}

fn encodeProfile(
    writer: anytype,
    value: *const profile_mod.AuthorityV3,
    statement: *const statement_v2.RiscVStatementV2,
) !void {
    try value.validateAgainstStatement(statement);
    try base_wire.writeInt(writer, u16, value.format_version);
    try base_wire.writeInt(writer, u16, value.schema_version);
    try writeBool(writer, value.production_active);
    try writeBool(writer, value.proof_admissible);
    try writeBool(writer, value.fresh_verification_available);
    try base_wire.writeInt(writer, u8, value.reserved);
    try writeEnum(writer, value.statement_family);
    try writeEnum(writer, value.boundary_policy);
    try base_wire.writeInt(writer, u32, value.coordinate.segment_index);
    try base_wire.writeInt(writer, u32, value.coordinate.segment_count);
    try writeU32s(writer, &value.segment_public_wire_id);
    try base_wire.writeInt(writer, u32, value.continuation_roots.entry);
    try base_wire.writeInt(writer, u32, value.continuation_roots.exit);
    try writer.writeAll(&value.boundary_artifact_content_sha256);

    const base = value.base_geometry;
    try base_wire.writeInt(writer, u32, base.component_count);
    try base_wire.writeInt(writer, u32, base.infrastructure_count);
    try writeU32s(writer, &base.compatibility_tree_columns);
    try writeU32s(writer, &base.physical_tree_columns);
    try base_wire.writeInt(writer, u32, base.maximum_column_log_size);
    try writeU32s(writer, &base.statement_authority_id);
    const activation = base.lookup_activation;
    try base_wire.writeInt(writer, u16, activation.format_version);
    try writer.writeAll(&activation.manifest_identity);
    try writer.writeAll(&activation.statement_identity);
    try writer.writeAll(&activation.activation_identity);
    try base_wire.writeInt(writer, u32, activation.component_count);
    try base_wire.writeInt(writer, u32, activation.opcode_main_columns);
    try base_wire.writeInt(writer, u32, activation.opcode_interaction_columns);
    try base_wire.writeInt(writer, u32, activation.detailed_claim_count);
    try writer.writeAll(&base.identity_sha256);

    const bridge = value.bridge_geometry;
    try base_wire.writeInt(writer, u16, bridge.format_version);
    try base_wire.writeInt(writer, u32, bridge.n_rows);
    try base_wire.writeInt(writer, u32, bridge.log_size);
    try base_wire.writeInt(
        writer,
        u64,
        @intCast(bridge.placement.is_first_col_idx),
    );
    try base_wire.writeInt(
        writer,
        u64,
        @intCast(bridge.placement.is_active_col_idx),
    );
    try base_wire.writeInt(
        writer,
        u64,
        @intCast(bridge.placement.main_col_offset),
    );
    try base_wire.writeInt(
        writer,
        u64,
        @intCast(bridge.placement.interaction_col_offset),
    );
    try base_wire.writeInt(writer, u32, bridge.total_preprocessed_columns);
    try base_wire.writeInt(writer, u32, bridge.total_main_columns);
    try base_wire.writeInt(writer, u32, bridge.total_interaction_columns);
    try writer.writeAll(&bridge.identity_sha256);

    const protocol = value.protocol;
    try writeU32s(writer, &protocol.profile_words);
    try writeU32s(writer, &protocol.protocol_id);
    try writer.writeAll(&protocol.proof_security_identity_sha256);
    inline for (.{
        protocol.pcs.pow_bits,
        protocol.pcs.log_blowup_factor,
        protocol.pcs.query_count,
        protocol.pcs.fold_step,
        protocol.pcs.log_last_layer_degree_bound,
        protocol.pcs.lifting_mode,
        protocol.pcs.configured_security_bits,
    }) |field| try base_wire.writeInt(writer, u32, field);
    try writer.writeAll(&protocol.pcs.identity_sha256);
    try writer.writeAll(&protocol.identity_sha256);
    try writer.writeAll(&value.identity_sha256);
}

fn decodeProfile(
    bytes: []const u8,
    statement: *const statement_v2.RiscVStatementV2,
) !profile_mod.AuthorityV3 {
    var cursor = base_wire.Cursor.init(bytes);
    var result: profile_mod.AuthorityV3 = undefined;
    result.format_version = try cursor.readInt(u16);
    result.schema_version = try cursor.readInt(u16);
    result.production_active = try readBool(&cursor);
    result.proof_admissible = try readBool(&cursor);
    result.fresh_verification_available = try readBool(&cursor);
    result.reserved = try cursor.readInt(u8);
    result.statement_family = try cursor.readKnownEnum(
        @TypeOf(result.statement_family),
    );
    result.boundary_policy = try cursor.readKnownEnum(
        @TypeOf(result.boundary_policy),
    );
    result.coordinate.segment_index = try cursor.readInt(u32);
    result.coordinate.segment_count = try cursor.readInt(u32);
    try cursor.readU32Array(&result.segment_public_wire_id);
    result.continuation_roots.entry = try cursor.readInt(u32);
    result.continuation_roots.exit = try cursor.readInt(u32);
    try cursor.readExact(&result.boundary_artifact_content_sha256);

    var base = &result.base_geometry;
    base.component_count = try cursor.readInt(u32);
    base.infrastructure_count = try cursor.readInt(u32);
    try cursor.readU32Array(&base.compatibility_tree_columns);
    try cursor.readU32Array(&base.physical_tree_columns);
    base.maximum_column_log_size = try cursor.readInt(u32);
    try cursor.readU32Array(&base.statement_authority_id);
    var activation = &base.lookup_activation;
    activation.format_version = try cursor.readInt(u16);
    try cursor.readExact(&activation.manifest_identity);
    try cursor.readExact(&activation.statement_identity);
    try cursor.readExact(&activation.activation_identity);
    activation.component_count = try cursor.readInt(u32);
    activation.opcode_main_columns = try cursor.readInt(u32);
    activation.opcode_interaction_columns = try cursor.readInt(u32);
    activation.detailed_claim_count = try cursor.readInt(u32);
    try cursor.readExact(&base.identity_sha256);

    var bridge = &result.bridge_geometry;
    bridge.format_version = try cursor.readInt(u16);
    bridge.n_rows = try cursor.readInt(u32);
    bridge.log_size = try cursor.readInt(u32);
    bridge.placement.is_first_col_idx = try readUsize(&cursor);
    bridge.placement.is_active_col_idx = try readUsize(&cursor);
    bridge.placement.main_col_offset = try readUsize(&cursor);
    bridge.placement.interaction_col_offset = try readUsize(&cursor);
    bridge.total_preprocessed_columns = try cursor.readInt(u32);
    bridge.total_main_columns = try cursor.readInt(u32);
    bridge.total_interaction_columns = try cursor.readInt(u32);
    try cursor.readExact(&bridge.identity_sha256);

    var protocol = &result.protocol;
    try cursor.readU32Array(&protocol.profile_words);
    try cursor.readU32Array(&protocol.protocol_id);
    try cursor.readExact(&protocol.proof_security_identity_sha256);
    protocol.pcs.pow_bits = try cursor.readInt(u32);
    protocol.pcs.log_blowup_factor = try cursor.readInt(u32);
    protocol.pcs.query_count = try cursor.readInt(u32);
    protocol.pcs.fold_step = try cursor.readInt(u32);
    protocol.pcs.log_last_layer_degree_bound = try cursor.readInt(u32);
    protocol.pcs.lifting_mode = try cursor.readInt(u32);
    protocol.pcs.configured_security_bits = try cursor.readInt(u32);
    try cursor.readExact(&protocol.pcs.identity_sha256);
    try cursor.readExact(&protocol.identity_sha256);
    try cursor.readExact(&result.identity_sha256);
    try cursor.requireDone();
    try result.validateAgainstStatement(statement);
    return result;
}

fn writeBool(writer: anytype, value: bool) !void {
    try base_wire.writeInt(writer, u8, @intFromBool(value));
}

fn readBool(cursor: *base_wire.Cursor) !bool {
    return switch (try cursor.readInt(u8)) {
        0 => false,
        1 => true,
        else => error.InvalidBoolean,
    };
}

fn writeEnum(writer: anytype, value: anytype) !void {
    const T = @TypeOf(value);
    const Tag = @typeInfo(T).@"enum".tag_type;
    try base_wire.writeInt(writer, Tag, @intFromEnum(value));
}

fn writeU32s(writer: anytype, values: []const u32) !void {
    for (values) |value| try base_wire.writeInt(writer, u32, value);
}

fn readUsize(cursor: *base_wire.Cursor) !usize {
    return std.math.cast(usize, try cursor.readInt(u64)) orelse
        error.ArtifactResourceLimitExceeded;
}

fn contentIdentity(bytes: []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CONTENT_DOMAIN);
    hash.update(bytes);
    return hash.finalResult();
}

comptime {
    if (PRODUCTION_ACTIVE or FORMAT_VERSION != 3 or SCHEMA_VERSION != 1 or
        HEADER_BYTES != 56 or SEAL_BYTES != 32 or
        profile_mod.PRODUCTION_ACTIVE)
    {
        @compileError("incremental native proof artifact V3 contract drifted");
    }
    if (@sizeOf(profile_mod.AuthorityV3) == 0)
        @compileError("incremental native profile type unavailable");
}
