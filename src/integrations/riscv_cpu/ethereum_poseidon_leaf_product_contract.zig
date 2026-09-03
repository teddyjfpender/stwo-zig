//! Closed one-leaf contract for the pre-descriptor Poseidon SegmentV3 product.

const std = @import("std");
const base = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");

pub const request_schema =
    "stwo.ethereum.poseidon-v4-leaf-product-request.v1";
pub const producer_result_schema =
    "stwo.ethereum.poseidon-v4-leaf-producer-result.v1";
pub const verifier_result_schema =
    "stwo.ethereum.poseidon-v4-leaf-verifier-result.v1";
pub const verifier_timing_receipt_schema =
    "stwo.ethereum.poseidon-v4-leaf-verifier-timing-receipt.v1";
pub const verifier_timing_scope =
    "verify-poseidon-v4-artifact-with-capture-v1";
pub const descriptor_unavailable_status =
    "verifier_minted_recursive_descriptor_unavailable";

pub const Request = struct {
    content_sha256: []const u8,
    expected_recursive_statement_sha256: []const u8,
    expected_source_public_statement_sha256: []const u8,
    producer_sha256: []const u8,
    schema: []const u8,
    segment_index: u32,
    session_id: []const u8,
    source_request: base.TypedIdentity,
    source_segment: base.Identity,
    verifier_sha256: []const u8,

    pub fn validate(self: Request) !void {
        if (!std.mem.eql(u8, self.schema, request_schema) or
            !std.mem.eql(
                u8,
                self.source_request.schema,
                base.recursive_source_schema,
            )) return error.RequestAuthorityMismatch;
        try self.source_request.validate();
        try self.source_segment.validate(false);
        if (!std.fs.path.isAbsolute(self.source_request.path) or
            !std.fs.path.isAbsolute(self.source_segment.path))
        {
            return error.RequestAuthorityMismatch;
        }
        inline for (.{
            self.content_sha256,
            self.expected_recursive_statement_sha256,
            self.expected_source_public_statement_sha256,
            self.producer_sha256,
            self.session_id,
            self.verifier_sha256,
        }) |digest| _ = try base.parseSha256(digest);
    }
};

pub const RequestInput = struct {
    expected_recursive_statement_sha256: []const u8,
    expected_source_public_statement_sha256: []const u8,
    producer_sha256: []const u8,
    schema: []const u8 = request_schema,
    segment_index: u32,
    session_id: []const u8,
    source_request: base.TypedIdentity,
    source_segment: base.Identity,
    verifier_sha256: []const u8,
};

pub const Timing = struct {
    system_ns: u64,
    user_ns: u64,
    wall_ns: u64,
};

pub const ProducerResult = struct {
    content_sha256: []const u8,
    descriptor_status: []const u8,
    producer_sha256: []const u8,
    proof: base.Identity,
    prove_timing: Timing,
    recursive_admissible: bool,
    recursive_statement_sha256: []const u8,
    request_sha256: []const u8,
    root_sha256: []const u8,
    schema: []const u8,
    security_identity_sha256: []const u8,
    segment_index: u32,
    source_public_statement_sha256: []const u8,
    status: []const u8,
    transcript_state_sha256: []const u8,
    verified_capture_sha256: []const u8,
    verified_link_id_m31_le: []const u8,

    pub fn validate(self: ProducerResult) !void {
        if (!std.mem.eql(u8, self.schema, producer_result_schema) or
            !std.mem.eql(u8, self.status, "proved") or
            !std.mem.eql(
                u8,
                self.descriptor_status,
                descriptor_unavailable_status,
            ) or
            self.recursive_admissible)
        {
            return error.ProducerResultMismatch;
        }
        try self.proof.validate(false);
        if (!std.fs.path.isAbsolute(self.proof.path))
            return error.ProducerResultMismatch;
        inline for (.{
            self.content_sha256,
            self.producer_sha256,
            self.recursive_statement_sha256,
            self.request_sha256,
            self.root_sha256,
            self.security_identity_sha256,
            self.source_public_statement_sha256,
            self.transcript_state_sha256,
            self.verified_capture_sha256,
        }) |digest| _ = try base.parseSha256(digest);
        _ = try base.parseM31Digest(self.verified_link_id_m31_le);
    }
};

pub const ProducerResultInput = struct {
    descriptor_status: []const u8 = descriptor_unavailable_status,
    producer_sha256: []const u8,
    proof: base.Identity,
    prove_timing: Timing,
    recursive_admissible: bool = false,
    recursive_statement_sha256: []const u8,
    request_sha256: []const u8,
    root_sha256: []const u8,
    schema: []const u8 = producer_result_schema,
    security_identity_sha256: []const u8,
    segment_index: u32,
    source_public_statement_sha256: []const u8,
    status: []const u8 = "proved",
    transcript_state_sha256: []const u8,
    verified_capture_sha256: []const u8,
    verified_link_id_m31_le: []const u8,
};

pub const VerifierResult = struct {
    content_sha256: []const u8,
    descriptor_status: []const u8,
    fresh_verification: bool,
    proof_bytes: u64,
    proof_sha256: []const u8,
    recursive_admissible: bool,
    recursive_statement_sha256: []const u8,
    request_sha256: []const u8,
    root_sha256: []const u8,
    schema: []const u8,
    security_identity_sha256: []const u8,
    segment_index: u32,
    source_public_statement_sha256: []const u8,
    status: []const u8,
    transcript_state_sha256: []const u8,
    verified_capture_sha256: []const u8,
    verified_link_id_m31_le: []const u8,
    verifier_sha256: []const u8,

    pub fn validate(self: VerifierResult) !void {
        if (!std.mem.eql(u8, self.schema, verifier_result_schema) or
            !std.mem.eql(u8, self.status, "verified") or
            !std.mem.eql(
                u8,
                self.descriptor_status,
                descriptor_unavailable_status,
            ) or
            !self.fresh_verification or self.recursive_admissible or
            self.proof_bytes == 0)
        {
            return error.VerifierResultMismatch;
        }
        inline for (.{
            self.content_sha256,
            self.proof_sha256,
            self.recursive_statement_sha256,
            self.request_sha256,
            self.root_sha256,
            self.security_identity_sha256,
            self.source_public_statement_sha256,
            self.transcript_state_sha256,
            self.verified_capture_sha256,
            self.verifier_sha256,
        }) |digest| _ = try base.parseSha256(digest);
        _ = try base.parseM31Digest(self.verified_link_id_m31_le);
    }
};

pub const VerifierResultInput = struct {
    descriptor_status: []const u8 = descriptor_unavailable_status,
    fresh_verification: bool = true,
    proof_bytes: u64,
    proof_sha256: []const u8,
    recursive_admissible: bool = false,
    recursive_statement_sha256: []const u8,
    request_sha256: []const u8,
    root_sha256: []const u8,
    schema: []const u8 = verifier_result_schema,
    security_identity_sha256: []const u8,
    segment_index: u32,
    source_public_statement_sha256: []const u8,
    status: []const u8 = "verified",
    transcript_state_sha256: []const u8,
    verified_capture_sha256: []const u8,
    verified_link_id_m31_le: []const u8,
    verifier_sha256: []const u8,
};

/// Append-only evidence for the exact fresh verification operation. The
/// frozen verifier-result V1 remains the semantic result; this receipt names
/// its exact retained bytes and is the final evidence-completion marker.
pub const VerifierTimingReceipt = struct {
    content_sha256: []const u8,
    fresh_verification: bool,
    proof: base.Identity,
    request: base.Identity,
    request_content_sha256: []const u8,
    schema: []const u8,
    segment_index: u32,
    status: []const u8,
    timing_scope: []const u8,
    verifier_result: base.Identity,
    verifier_sha256: []const u8,
    verify_timing: Timing,

    pub fn validate(self: VerifierTimingReceipt) !void {
        if (!std.mem.eql(u8, self.schema, verifier_timing_receipt_schema) or
            !std.mem.eql(u8, self.status, "verified") or
            !std.mem.eql(u8, self.timing_scope, verifier_timing_scope) or
            !self.fresh_verification or self.verify_timing.wall_ns == 0)
        {
            return error.VerifierTimingReceiptMismatch;
        }
        try self.proof.validate(false);
        try self.request.validate(false);
        try self.verifier_result.validate(false);
        inline for (.{
            self.proof.path,
            self.request.path,
            self.verifier_result.path,
        }) |path| if (!std.fs.path.isAbsolute(path))
            return error.VerifierTimingReceiptMismatch;
        inline for (.{
            self.content_sha256,
            self.request_content_sha256,
            self.verifier_sha256,
        }) |digest| _ = try base.parseSha256(digest);
    }

    /// Cross-binds this transport receipt to the canonical files reopened by
    /// a controller or evidence join. File hashes are intentionally distinct
    /// from the request's self-sealing content digest.
    pub fn validateAgainst(
        self: VerifierTimingReceipt,
        request_value: Request,
        verifier_value: VerifierResult,
        request_identity: base.Identity,
        proof_identity: base.Identity,
        verifier_result_identity: base.Identity,
    ) !void {
        try self.validate();
        try request_value.validate();
        try verifier_value.validate();
        try request_identity.validate(false);
        try proof_identity.validate(false);
        try verifier_result_identity.validate(false);
        if (!identityEql(self.request, request_identity) or
            !identityEql(self.proof, proof_identity) or
            !identityEql(self.verifier_result, verifier_result_identity) or
            self.segment_index != request_value.segment_index or
            self.segment_index != verifier_value.segment_index or
            !std.mem.eql(
                u8,
                self.request_content_sha256,
                request_value.content_sha256,
            ) or
            self.proof.bytes != verifier_value.proof_bytes or
            !std.mem.eql(u8, self.proof.sha256, verifier_value.proof_sha256) or
            !std.mem.eql(u8, self.verifier_sha256, request_value.verifier_sha256) or
            !std.mem.eql(u8, self.verifier_sha256, verifier_value.verifier_sha256))
        {
            return error.VerifierTimingCustodyMismatch;
        }
    }
};

pub const VerifierTimingReceiptInput = struct {
    fresh_verification: bool = true,
    proof: base.Identity,
    request: base.Identity,
    request_content_sha256: []const u8,
    schema: []const u8 = verifier_timing_receipt_schema,
    segment_index: u32,
    status: []const u8 = "verified",
    timing_scope: []const u8 = verifier_timing_scope,
    verifier_result: base.Identity,
    verifier_sha256: []const u8,
    verify_timing: Timing,
};

pub const VerifierEvidenceStatus = enum {
    absent,
    nonpromotable_missing_verifier_timing,
    complete,
};

/// A V1 verifier result without its final timing receipt remains a valid proof
/// result but is explicitly incomplete and cannot support a performance claim.
pub fn verifierEvidenceStatus(
    verifier_result_present: bool,
    timing_receipt_present: bool,
) !VerifierEvidenceStatus {
    if (timing_receipt_present and !verifier_result_present)
        return error.OrphanVerifierTimingReceipt;
    if (!verifier_result_present) return .absent;
    return if (timing_receipt_present)
        .complete
    else
        .nonpromotable_missing_verifier_timing;
}

pub fn encodeRequest(
    allocator: std.mem.Allocator,
    input: RequestInput,
) ![]u8 {
    const result = try encodeSealed(allocator, input);
    errdefer allocator.free(result);
    var parsed = try parseRequest(allocator, result);
    parsed.deinit();
    return result;
}

pub fn encodeProducerResult(
    allocator: std.mem.Allocator,
    input: ProducerResultInput,
) ![]u8 {
    const result = try encodeSealed(allocator, input);
    errdefer allocator.free(result);
    var parsed = try parseProducerResult(allocator, result);
    parsed.deinit();
    return result;
}

pub fn encodeVerifierResult(
    allocator: std.mem.Allocator,
    input: VerifierResultInput,
) ![]u8 {
    const result = try encodeSealed(allocator, input);
    errdefer allocator.free(result);
    var parsed = try parseVerifierResult(allocator, result);
    parsed.deinit();
    return result;
}

pub fn encodeVerifierTimingReceipt(
    allocator: std.mem.Allocator,
    input: VerifierTimingReceiptInput,
) ![]u8 {
    const result = try encodeSealed(allocator, input);
    errdefer allocator.free(result);
    var parsed = try parseVerifierTimingReceipt(allocator, result);
    parsed.deinit();
    return result;
}

pub fn parseRequest(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(Request) {
    var parsed = try parseCanonical(Request, allocator, bytes);
    errdefer parsed.deinit();
    try parsed.value.validate();
    try validateContentSha256(allocator, bytes, parsed.value.content_sha256);
    return parsed;
}

pub fn parseProducerResult(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(ProducerResult) {
    var parsed = try parseCanonical(ProducerResult, allocator, bytes);
    errdefer parsed.deinit();
    try parsed.value.validate();
    try validateContentSha256(allocator, bytes, parsed.value.content_sha256);
    return parsed;
}

pub fn parseVerifierResult(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(VerifierResult) {
    var parsed = try parseCanonical(VerifierResult, allocator, bytes);
    errdefer parsed.deinit();
    try parsed.value.validate();
    try validateContentSha256(allocator, bytes, parsed.value.content_sha256);
    return parsed;
}

pub fn parseVerifierTimingReceipt(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(VerifierTimingReceipt) {
    var parsed = try parseCanonical(VerifierTimingReceipt, allocator, bytes);
    errdefer parsed.deinit();
    try parsed.value.validate();
    try validateContentSha256(allocator, bytes, parsed.value.content_sha256);
    return parsed;
}

fn identityEql(left: base.Identity, right: base.Identity) bool {
    return left.bytes == right.bytes and
        std.mem.eql(u8, left.path, right.path) and
        std.mem.eql(u8, left.sha256, right.sha256);
}

fn parseCanonical(
    comptime T: type,
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(T) {
    if (bytes.len == 0 or bytes.len > base.max_json_bytes or
        bytes[bytes.len - 1] != '\n' or
        (bytes.len > 1 and bytes[bytes.len - 2] == '\n'))
    {
        return error.InvalidCanonicalJson;
    }
    var parsed = try std.json.parseFromSlice(T, allocator, bytes, .{
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
    return parsed;
}

fn encodeSealed(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    const unsigned = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(unsigned);
    return evidence.seal(allocator, unsigned);
}

fn validateContentSha256(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected: []const u8,
) !void {
    _ = try base.parseSha256(expected);
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, bytes, prefix))
        return error.InvalidContentSha256;
    const start = prefix.len;
    const end = start + 64;
    if (end >= bytes.len or bytes[end] != '"' or bytes[end + 1] != ',' or
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
    const encoded = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &encoded, expected))
        return error.InvalidContentSha256;
}
