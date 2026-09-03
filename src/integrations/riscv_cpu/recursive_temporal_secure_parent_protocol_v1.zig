//! Append-only security authority for temporal parent outer proofs.
//!
//! The existing temporal-parent engine intentionally uses a functional
//! q=3/fold-one outer PCS profile.  This module does not alter that route.  It
//! gives a future secure sibling an exact, canonical authority for q=193,
//! fold-four, interaction PoW 10, and PCS PoW 16 while retaining a byte-exact
//! projection of the legacy functional default for regression checks.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const proof_security = @import("recursive_temporal_proof_security_v1.zig");

const admission = frontend.recursion.outer_parent_child_admission;
const recursion_protocol = frontend.recursion.protocol;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const PROFILE_BYTE_COUNT: usize = 36;
pub const ENCODED_BYTE_COUNT: usize = 116;

const AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-secure-parent-protocol/v1\x00";

pub const KindV1 = enum(u8) {
    functional_default = 1,
    secure_parent = 2,
};

/// Exact historical outer-parent profile.  This literal is deliberately not
/// derived from the secure profile and therefore detects accidental default
/// route changes in either direction.
pub const FUNCTIONAL_DEFAULT_PROFILE_BYTES = [PROFILE_BYTE_COUNT]u8{
    0, 0, 0, 0, // interaction PoW
    0, 0, 0, 0, // PCS PoW
    1, 0, 0, 0, // log blowup
    3, 0, 0, 0, // queries
    1, 0, 0, 0, // fold step
    0, 0, 0, 0, // last layer degree bound
    0, 0, 0, 0, // lifting mode: none
    3, 0, 0, 0, // configured PCS ledger
    0, 0, 0, 0, // conjectured security
};

pub const SECURE_PARENT_PROFILE_BYTES = [PROFILE_BYTE_COUNT]u8{
    10, 0, 0, 0, // interaction PoW
    16, 0, 0, 0, // PCS PoW
    1, 0, 0, 0, // log blowup
    193, 0, 0, 0, // queries
    4, 0, 0, 0, // fold step
    0, 0, 0, 0, // last layer degree bound
    0, 0, 0, 0, // lifting mode: none
    209, 0, 0, 0, // configured PCS ledger
    120, 0, 0, 0, // conjectured security
};

/// Pointer-free protocol selection.  No proof, artifact, or caller-provided
/// dimensions can select these fields.  `production_activation` stays false
/// until the secure prover, codec, and cold verifier have all landed.
pub const AuthorityV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    kind: KindV1,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: u16 = 0,
    field_id: u32,
    hash_suite: proof_security.HashSuiteV1,
    recursive_ingress: proof_security.RecursiveIngressV1,
    security_reserved: u16 = 0,
    interaction_pow_bits: u32,
    pcs_pow_bits: u32,
    fri_log_blowup_factor: u32,
    fri_query_count: u32,
    fri_fold_step: u32,
    fri_log_last_layer_degree_bound: u32,
    pcs_lifting_mode: u32,
    configured_pcs_bits: u32,
    conjectured_security_bits: u32,
    proof_security_sha256: [32]u8,
    identity_sha256: [32]u8,

    pub fn functionalDefault() AuthorityV1 {
        return initUnchecked(.functional_default);
    }

    pub fn secureParent() AuthorityV1 {
        return initUnchecked(.secure_parent);
    }

    pub fn validate(self: *const AuthorityV1) !void {
        if (!std.meta.eql(self.*, initUnchecked(self.kind)))
            return error.InvalidTemporalParentProtocolAuthority;
    }

    pub fn pcsConfig(self: *const AuthorityV1) !stwo_core.pcs.PcsConfig {
        try self.validate();
        return .{
            .pow_bits = self.pcs_pow_bits,
            .fri_config = .{
                .log_blowup_factor = self.fri_log_blowup_factor,
                .log_last_layer_degree_bound = self.fri_log_last_layer_degree_bound,
                .n_queries = self.fri_query_count,
                .fold_step = self.fri_fold_step,
            },
            .lifting_log_size = null,
        };
    }

    pub fn profileBytes(self: *const AuthorityV1) ![PROFILE_BYTE_COUNT]u8 {
        try self.validate();
        return profileBytesUnchecked(self);
    }

    pub fn encodeCanonical(self: *const AuthorityV1) ![ENCODED_BYTE_COUNT]u8 {
        try self.validate();
        var result: [ENCODED_BYTE_COUNT]u8 = undefined;
        var writer = Writer{ .bytes = &result };
        writeAuthority(&writer, self);
        std.debug.assert(writer.at == result.len);
        return result;
    }

    pub fn decodeCanonical(bytes: []const u8) !AuthorityV1 {
        if (bytes.len != ENCODED_BYTE_COUNT)
            return error.InvalidTemporalParentProtocolAuthority;
        var reader = Reader{ .bytes = bytes };
        const result = AuthorityV1{
            .format_version = reader.u16Value(),
            .schema_version = reader.u16Value(),
            .kind = std.meta.intToEnum(
                KindV1,
                reader.u8Value(),
            ) catch return error.InvalidTemporalParentProtocolAuthority,
            .production_activation = try reader.boolValue(),
            .reserved = reader.u16Value(),
            .field_id = reader.u32Value(),
            .hash_suite = std.meta.intToEnum(
                proof_security.HashSuiteV1,
                reader.u8Value(),
            ) catch return error.InvalidTemporalParentProtocolAuthority,
            .recursive_ingress = std.meta.intToEnum(
                proof_security.RecursiveIngressV1,
                reader.u8Value(),
            ) catch return error.InvalidTemporalParentProtocolAuthority,
            .security_reserved = reader.u16Value(),
            .interaction_pow_bits = reader.u32Value(),
            .pcs_pow_bits = reader.u32Value(),
            .fri_log_blowup_factor = reader.u32Value(),
            .fri_query_count = reader.u32Value(),
            .fri_fold_step = reader.u32Value(),
            .fri_log_last_layer_degree_bound = reader.u32Value(),
            .pcs_lifting_mode = reader.u32Value(),
            .configured_pcs_bits = reader.u32Value(),
            .conjectured_security_bits = reader.u32Value(),
            .proof_security_sha256 = reader.array(32),
            .identity_sha256 = reader.array(32),
        };
        if (reader.at != bytes.len)
            return error.InvalidTemporalParentProtocolAuthority;
        try result.validate();
        const canonical = try result.encodeCanonical();
        if (!std.mem.eql(u8, bytes, &canonical))
            return error.InvalidTemporalParentProtocolAuthority;
        return result;
    }

    pub fn requireSecure(self: *const AuthorityV1) !void {
        try self.validate();
        if (self.kind != .secure_parent)
            return error.SecureTemporalParentProtocolRequired;
    }

    pub fn requireProduction(self: *const AuthorityV1) !void {
        try self.requireSecure();
        if (!PRODUCTION_ACTIVATION)
            return error.SecureTemporalParentProductionUnavailable;
    }
};

fn initUnchecked(kind: KindV1) AuthorityV1 {
    const security = switch (kind) {
        .functional_default => proof_security.ProofSecurityV1
            .recursiveParentFunctional(),
        .secure_parent => proof_security.ProofSecurityV1
            .recursiveParentSecure(),
    };
    var result = AuthorityV1{
        .kind = kind,
        .field_id = security.field_id,
        .hash_suite = security.hash_suite,
        .recursive_ingress = security.recursive_ingress,
        .interaction_pow_bits = security.interaction_pow_bits,
        .pcs_pow_bits = security.pcs_pow_bits,
        .fri_log_blowup_factor = security.fri_log_blowup_factor,
        .fri_query_count = security.fri_query_count,
        .fri_fold_step = security.fri_fold_step,
        .fri_log_last_layer_degree_bound = security.fri_log_last_layer_degree_bound,
        .pcs_lifting_mode = security.pcs_lifting_mode,
        .configured_pcs_bits = security.configured_pcs_bits,
        .conjectured_security_bits = security.conjectured_security_bits,
        .proof_security_sha256 = security.identity,
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = authorityIdentity(&result);
    return result;
}

fn authorityIdentity(value: *const AuthorityV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    var bytes: [ENCODED_BYTE_COUNT - 32]u8 = undefined;
    var writer = Writer{ .bytes = &bytes };
    writeAuthorityWithoutIdentity(&writer, value);
    std.debug.assert(writer.at == bytes.len);
    hash.update(&bytes);
    return hash.finalResult();
}

fn profileBytesUnchecked(
    value: *const AuthorityV1,
) [PROFILE_BYTE_COUNT]u8 {
    var result: [PROFILE_BYTE_COUNT]u8 = undefined;
    var writer = Writer{ .bytes = &result };
    inline for (.{
        value.interaction_pow_bits,
        value.pcs_pow_bits,
        value.fri_log_blowup_factor,
        value.fri_query_count,
        value.fri_fold_step,
        value.fri_log_last_layer_degree_bound,
        value.pcs_lifting_mode,
        value.configured_pcs_bits,
        value.conjectured_security_bits,
    }) |field| writer.u32Value(field);
    std.debug.assert(writer.at == result.len);
    return result;
}

fn writeAuthority(writer: *Writer, value: *const AuthorityV1) void {
    writeAuthorityWithoutIdentity(writer, value);
    writer.bytesValue(&value.identity_sha256);
}

fn writeAuthorityWithoutIdentity(
    writer: *Writer,
    value: *const AuthorityV1,
) void {
    writer.u16Value(value.format_version);
    writer.u16Value(value.schema_version);
    writer.u8Value(@intFromEnum(value.kind));
    writer.u8Value(@intFromBool(value.production_activation));
    writer.u16Value(value.reserved);
    writer.u32Value(value.field_id);
    writer.u8Value(@intFromEnum(value.hash_suite));
    writer.u8Value(@intFromEnum(value.recursive_ingress));
    writer.u16Value(value.security_reserved);
    writer.bytesValue(&profileBytesUnchecked(value));
    writer.bytesValue(&value.proof_security_sha256);
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
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,

    fn take(self: *Reader, count: usize) []const u8 {
        const result = self.bytes[self.at..][0..count];
        self.at += count;
        return result;
    }

    fn array(self: *Reader, comptime count: usize) [count]u8 {
        return self.take(count)[0..count].*;
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
            else => error.InvalidTemporalParentProtocolAuthority,
        };
    }

    fn u16Value(self: *Reader) u16 {
        return std.mem.readInt(u16, self.take(2)[0..2], .little);
    }

    fn u32Value(self: *Reader) u32 {
        return std.mem.readInt(u32, self.take(4)[0..4], .little);
    }
};

comptime {
    @setEvalBranchQuota(100_000);
    const functional = AuthorityV1.functionalDefault();
    const secure = AuthorityV1.secureParent();
    if (ENCODED_BYTE_COUNT != 116 or PROFILE_BYTE_COUNT != 36 or
        PRODUCTION_ACTIVATION or admission.INTERACTION_POW_BITS != 0 or
        admission.PCS_POW_BITS != 0 or admission.LOG_BLOWUP_FACTOR != 1 or
        admission.QUERY_COUNT != 3 or admission.FOLD_STEP != 1 or
        admission.LOG_LAST_LAYER_DEGREE_BOUND != 0 or
        recursion_protocol.INTERACTION_POW_BITS != 10 or
        recursion_protocol.PCS_POW_BITS != 16 or
        recursion_protocol.FRI_LOG_BLOWUP_FACTOR != 1 or
        recursion_protocol.FRI_QUERY_COUNT != 193 or
        recursion_protocol.FRI_FOLD_STEP != 4 or
        recursion_protocol.FRI_LOG_LAST_LAYER_DEGREE_BOUND != 0 or
        !std.meta.eql(
            profileBytesUnchecked(&functional),
            FUNCTIONAL_DEFAULT_PROFILE_BYTES,
        ) or !std.meta.eql(
        profileBytesUnchecked(&secure),
        SECURE_PARENT_PROFILE_BYTES,
    )) {
        @compileError("temporal secure-parent protocol authority drifted");
    }
}
