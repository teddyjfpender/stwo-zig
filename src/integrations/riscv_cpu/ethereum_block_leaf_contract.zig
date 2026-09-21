//! Closed JSON contracts for the persistent Ethereum leaf stream.
//!
//! Python owns controller scheduling; this module owns the producer-side
//! semantic source and exact session/task request admission. Every struct is
//! declared in lexicographic key order so re-encoding is the same canonical
//! ASCII JSON used by the controller.

const std = @import("std");

pub const source_schema =
    "stwo.ethereum.block-proof-leaf-stream-source.v1";
pub const recursive_source_schema =
    "stwo.ethereum.block-proof-leaf-stream-source.v2";
pub const native_proof_profile_name =
    "stwo.ethereum-segment-v3-native-blake2s-v1";
pub const materialization_result_schema =
    "stwo.ethereum.block-proof-source-materialization-result.v1";
pub const recursive_materialization_result_schema =
    "stwo.ethereum.block-proof-source-materialization-result.v2";
pub const stream_request_schema =
    "stwo.ethereum.block-proof-leaf-stream-request.v1";
pub const task_request_schema = "stwo.ethereum.block-proof-task-request.v2";
pub const stream_result_schema =
    "stwo.ethereum.block-proof-leaf-stream-result.v1";
pub const leaf_result_schema = "stwo.ethereum.block-proof-leaf-result.v1";
pub const progress_record_schema =
    "stwo.ethereum.block-proof-leaf-progress-record.v1";
pub const verifier_result_schema =
    "stwo.ethereum.block-proof-verifier-result.v1";
pub const verifier_receipt_schema =
    "stwo.ethereum.block-proof-verification-receipt.v1";
pub const profile_name = "rv32im-zkvm-ethereum-v1";
pub const recursive_proof_profile_name =
    "stwo.ethereum-segment-v3-recursive-poseidon2-m31-v1";
pub const recursive_proof_kind = "ethereum_segment_v3_poseidon2";
pub const recursive_ingress = "ethereum_segment_v3_full";
pub const recursive_hash_suite = "Poseidon2-M31";
pub const recursive_extension_component_count: u16 = 14;
pub const recursive_configured_pcs_bits: u32 = 209;
pub const recursive_conjectured_security_bits: u32 = 120;
pub const recursive_interaction_pow_bits: u32 = 10;
pub const recursive_security_identity_sha256 =
    "bc339bc9bcf2d57ed49caccff618e944ddd03b401d528e7b3cb0d2f514306b04";
pub const recursive_descriptor_authority =
    "fresh-verifier-minted-dynamic-child-v1";
pub const recursive_execution_semantics_authority =
    "source_request.profile_semantic_digest";
pub const recursive_verifier_identity_authority =
    "stream_request.verifier_sha256";
pub const clock_frame = "leaf_local";
pub const segment_magic = "STWESG31";
pub const max_json_bytes: usize = 64 * 1024 * 1024;

pub const Identity = struct {
    bytes: u64,
    path: []const u8,
    sha256: []const u8,

    pub fn validate(self: Identity, allow_empty: bool) !void {
        if ((!allow_empty and self.bytes == 0) or self.path.len == 0)
            return error.InvalidFileIdentity;
        try validatePath(self.path, true);
        _ = try parseSha256(self.sha256);
    }
};

pub const TypedIdentity = struct {
    bytes: u64,
    path: []const u8,
    schema: []const u8,
    sha256: []const u8,

    pub fn validate(self: TypedIdentity) !void {
        try (Identity{
            .bytes = self.bytes,
            .path = self.path,
            .sha256 = self.sha256,
        }).validate(true);
        if (self.schema.len == 0) return error.InvalidSchema;
        try requireAscii(self.schema);
    }
};

pub const PcsAuthority = struct {
    commitment_hash: []const u8,
    field: []const u8,
    fold_step: u32,
    lifting_log_size: ?u32,
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    n_queries: usize,
    pow_bits: u32,
    transcript_hash: []const u8,
};

pub const SourceRequest = struct {
    clock_frame: []const u8,
    elf: Identity,
    execution_journal: Identity,
    execution_profile: []const u8,
    expected_output: Identity,
    input: Identity,
    pcs: PcsAuthority,
    profile_abi_version: u16,
    profile_semantic_digest: []const u8,
    profile_wire_id: u16,
    schema: []const u8,
    segment_authority_magic: []const u8,
    segment_authority_version: u16,
    segment_count: u32,
    segment_step_budget: usize,
    strict_completion: bool,

    pub fn validate(self: SourceRequest) !void {
        if (!std.mem.eql(u8, self.schema, source_schema) or
            !std.mem.eql(u8, self.execution_profile, profile_name) or
            !std.mem.eql(u8, self.clock_frame, clock_frame) or
            !std.mem.eql(u8, self.segment_authority_magic, segment_magic) or
            self.profile_wire_id != 3 or self.profile_abi_version != 1 or
            self.segment_authority_version != 1 or self.segment_count < 2 or
            self.segment_step_budget == 0 or !self.strict_completion)
        {
            return error.SourceAuthorityMismatch;
        }
        try self.elf.validate(false);
        try self.input.validate(true);
        try self.expected_output.validate(false);
        try self.execution_journal.validate(false);
        const expected_profile = @import("stwo_riscv_frontend")
            .isa.execution_profile.ethereum_semantic_digest;
        if (!std.meta.eql(
            try parseSha256(self.profile_semantic_digest),
            expected_profile,
        )) return error.SourceAuthorityMismatch;
        try validateNativePcs(self.pcs);
    }
};

/// Pre-proof policy carried by SourceRequest V2. The 210 real leaves have
/// heterogeneous base shard rosters, so no predicted manifest, AIR program,
/// profile or VK is admitted here. The exact verifier executable is bound by
/// StreamRequest and mints a per-leaf typed descriptor after proof.
pub const RecursiveProofPolicyV1 = struct {
    configured_pcs_bits: u32,
    conjectured_security_bits: u32,
    descriptor_authority: []const u8,
    execution_semantics_authority: []const u8,
    extension_component_count: u16,
    hash_suite: []const u8,
    interaction_pow_bits: u32,
    profile_name: []const u8,
    proof_kind: []const u8,
    recursive_ingress: []const u8,
    security_identity_sha256: []const u8,
    verifier_identity_authority: []const u8,

    pub fn validate(self: RecursiveProofPolicyV1) !void {
        if (self.extension_component_count !=
            recursive_extension_component_count or
            self.configured_pcs_bits != recursive_configured_pcs_bits or
            self.conjectured_security_bits !=
                recursive_conjectured_security_bits or
            self.interaction_pow_bits != recursive_interaction_pow_bits or
            !std.mem.eql(
                u8,
                self.descriptor_authority,
                recursive_descriptor_authority,
            ) or
            !std.mem.eql(
                u8,
                self.execution_semantics_authority,
                recursive_execution_semantics_authority,
            ) or
            !std.mem.eql(u8, self.hash_suite, recursive_hash_suite) or
            !std.mem.eql(u8, self.profile_name, recursive_proof_profile_name) or
            !std.mem.eql(u8, self.proof_kind, recursive_proof_kind) or
            !std.mem.eql(u8, self.recursive_ingress, recursive_ingress) or
            !std.mem.eql(
                u8,
                self.security_identity_sha256,
                recursive_security_identity_sha256,
            ) or !std.mem.eql(
            u8,
            self.verifier_identity_authority,
            recursive_verifier_identity_authority,
        )) {
            return error.RecursiveProofProfileMismatch;
        }
    }
};

/// Append-only recursive SourceRequest. V1 retains its exact native Blake2s
/// meaning; V2 selects the Poseidon2-M31 proof and full Ethereum outer.
pub const RecursiveSourceRequestV2 = struct {
    clock_frame: []const u8,
    elf: Identity,
    execution_journal: Identity,
    execution_profile: []const u8,
    expected_output: Identity,
    input: Identity,
    pcs: PcsAuthority,
    profile_abi_version: u16,
    profile_semantic_digest: []const u8,
    profile_wire_id: u16,
    proof_policy: RecursiveProofPolicyV1,
    schema: []const u8,
    segment_authority_magic: []const u8,
    segment_authority_version: u16,
    segment_count: u32,
    segment_step_budget: usize,
    strict_completion: bool,

    pub fn validate(self: RecursiveSourceRequestV2) !void {
        if (!std.mem.eql(u8, self.schema, recursive_source_schema) or
            !std.mem.eql(u8, self.execution_profile, profile_name) or
            !std.mem.eql(u8, self.clock_frame, clock_frame) or
            !std.mem.eql(u8, self.segment_authority_magic, segment_magic) or
            self.profile_wire_id != 3 or self.profile_abi_version != 1 or
            self.segment_authority_version != 1 or self.segment_count < 2 or
            self.segment_step_budget == 0 or !self.strict_completion)
        {
            return error.SourceAuthorityMismatch;
        }
        try self.elf.validate(false);
        try self.input.validate(true);
        try self.expected_output.validate(false);
        try self.execution_journal.validate(false);
        const expected_profile = @import("stwo_riscv_frontend")
            .isa.execution_profile.ethereum_semantic_digest;
        if (!std.meta.eql(
            try parseSha256(self.profile_semantic_digest),
            expected_profile,
        )) return error.SourceAuthorityMismatch;
        try validateRecursivePcs(self.pcs);
        try self.proof_policy.validate();
    }
};

pub const SourceKind = enum {
    native_blake2s_v1,
    recursive_poseidon2_v2,
};

/// SHA-256 and native-field authorities emitted before any leaf proof exists.
/// Native digests use eight canonical M31 words encoded as 32 little-endian
/// bytes and then lowercase hexadecimal; they are never interchangeable with
/// the SHA-256 fields beside them.
pub const MaterializedJob = struct {
    final_state_sha256: []const u8,
    initial_state_sha256: []const u8,
    job_sha256: []const u8,
    program_m31_le: []const u8,
    public_input_m31_le: []const u8,
    public_output_m31_le: []const u8,

    pub fn validate(self: MaterializedJob) !void {
        inline for (.{
            self.final_state_sha256,
            self.initial_state_sha256,
            self.job_sha256,
        }) |digest| _ = try parseSha256(digest);
        inline for (.{
            self.program_m31_le,
            self.public_input_m31_le,
            self.public_output_m31_le,
        }) |digest| _ = try parseM31Digest(digest);
    }
};

pub const MaterializedLeaf = struct {
    authority: Identity,
    metadata_id_m31_le: []const u8,
    segment_index: u32,
    statement_id_m31_le: []const u8,
    statement_sha256: []const u8,

    pub fn validate(self: MaterializedLeaf, index: usize) !void {
        if (self.segment_index != index) return error.LeafOrderMismatch;
        try self.authority.validate(false);
        _ = try parseM31Digest(self.metadata_id_m31_le);
        _ = try parseM31Digest(self.statement_id_m31_le);
        _ = try parseSha256(self.statement_sha256);
    }
};

pub const MaterializationResult = struct {
    content_sha256: []const u8,
    execution_journal: Identity,
    execution_profile: []const u8,
    expected_output: Identity,
    input: Identity,
    job: MaterializedJob,
    leaf_sources: []const MaterializedLeaf,
    pcs: PcsAuthority,
    schema: []const u8,
    segment_authority_magic: []const u8,
    segment_authority_version: u16,
    segment_count: u32,
    source_request: TypedIdentity,
    status: []const u8,
    total_cycles: u64,

    pub fn validate(self: MaterializationResult) !void {
        if (!std.mem.eql(u8, self.status, "materialized") or
            !std.mem.eql(u8, self.execution_profile, profile_name) or
            !std.mem.eql(u8, self.segment_authority_magic, segment_magic) or
            self.segment_authority_version != 1 or self.segment_count < 2 or
            self.segment_count != self.leaf_sources.len or
            self.total_cycles == 0)
        {
            return error.MaterializationAuthorityMismatch;
        }
        _ = try parseSha256(self.content_sha256);
        try self.execution_journal.validate(false);
        try self.expected_output.validate(false);
        try self.input.validate(true);
        try self.job.validate();
        try self.source_request.validate();
        if (std.mem.eql(u8, self.source_request.schema, source_schema)) {
            if (!std.mem.eql(u8, self.schema, materialization_result_schema))
                return error.MaterializationAuthorityMismatch;
            try validateNativePcs(self.pcs);
        } else if (std.mem.eql(
            u8,
            self.source_request.schema,
            recursive_source_schema,
        )) {
            if (!std.mem.eql(
                u8,
                self.schema,
                recursive_materialization_result_schema,
            )) return error.MaterializationAuthorityMismatch;
            try validateRecursivePcs(self.pcs);
        } else return error.MaterializationAuthorityMismatch;
        for (self.leaf_sources, 0..) |leaf, index|
            try leaf.validate(index);
    }
};

pub const CommittedLeaf = struct {
    proof: Identity,
    record_sha256: []const u8,
    root_sha256: []const u8,
    statement_sha256: []const u8,
    verification_receipt: Identity,

    pub fn validate(self: CommittedLeaf) !void {
        try self.proof.validate(false);
        try self.verification_receipt.validate(false);
        _ = try parseSha256(self.record_sha256);
        _ = try parseSha256(self.root_sha256);
        _ = try parseSha256(self.statement_sha256);
    }
};

pub const StreamSegment = struct {
    committed: ?CommittedLeaf,
    expected_authority: Identity,
    expected_statement_sha256: []const u8,
    segment_index: u32,

    pub fn validate(self: StreamSegment, index: usize, first: usize) !void {
        if (self.segment_index != index) return error.SegmentOrderMismatch;
        try self.expected_authority.validate(false);
        _ = try parseSha256(self.expected_statement_sha256);
        if (index < first) {
            const committed = self.committed orelse
                return error.CommittedPrefixMissing;
            try committed.validate();
            if (!std.mem.eql(
                u8,
                committed.statement_sha256,
                self.expected_statement_sha256,
            )) return error.CommittedStatementMismatch;
        } else if (self.committed != null) {
            return error.NonPrefixCommitment;
        }
    }
};

pub const DurableProgress = struct {
    path: []const u8,
    publication_prefix: []const u8,
    schema: []const u8,
};

pub const StreamRequest = struct {
    content_sha256: []const u8,
    durable_progress: DurableProgress,
    first_uncommitted_segment: u32,
    plan_sha256: []const u8,
    producer_sha256: []const u8,
    real_segment_count: u32,
    schema: []const u8,
    segments: []const StreamSegment,
    session_id: []const u8,
    source_request: TypedIdentity,
    stream_session_sha256: []const u8,
    verifier_sha256: []const u8,

    pub fn validate(self: StreamRequest) !void {
        if (!std.mem.eql(u8, self.schema, stream_request_schema) or
            self.real_segment_count < 2 or
            self.real_segment_count != self.segments.len or
            self.first_uncommitted_segment > self.real_segment_count or
            !std.mem.eql(u8, self.durable_progress.schema, progress_record_schema))
        {
            return error.StreamAuthorityMismatch;
        }
        try validatePath(self.durable_progress.path, true);
        try validatePath(self.durable_progress.publication_prefix, false);
        try self.source_request.validate();
        inline for (.{
            self.content_sha256,
            self.plan_sha256,
            self.producer_sha256,
            self.session_id,
            self.stream_session_sha256,
            self.verifier_sha256,
        }) |digest| _ = try parseSha256(digest);
        for (self.segments, 0..) |segment, index|
            try segment.validate(index, self.first_uncommitted_segment);
    }
};

pub const RealLeafTaskRequest = struct {
    children: []const std.json.Value,
    content_sha256: []const u8,
    covered_segments: []const u32,
    expected_statement_sha256: []const u8,
    level: u32,
    node_index: u32,
    plan_sha256: []const u8,
    proof_path: []const u8,
    receipt_path: []const u8,
    schema: []const u8,
    scope: []const u8,
    session_id: []const u8,
    source_segment: Identity,
    task_id: []const u8,
    task_kind: []const u8,

    pub fn validate(self: RealLeafTaskRequest) !void {
        if (!std.mem.eql(u8, self.schema, task_request_schema) or
            !std.mem.eql(u8, self.scope, "leaf") or
            !std.mem.eql(u8, self.task_kind, "real_leaf_proof") or
            self.level != 0 or self.children.len != 0 or
            self.covered_segments.len != 1 or
            self.covered_segments[0] != self.node_index)
        {
            return error.TaskAuthorityMismatch;
        }
        try self.source_segment.validate(false);
        inline for (.{
            self.content_sha256,
            self.expected_statement_sha256,
            self.plan_sha256,
            self.session_id,
        }) |digest| _ = try parseSha256(digest);
        try validatePath(self.proof_path, false);
        try validatePath(self.receipt_path, false);
        try requireAscii(self.task_id);
    }
};

pub const VerificationReceipt = struct {
    fresh_verification: bool,
    level: u32,
    node_index: u32,
    proof_bytes: u64,
    proof_sha256: []const u8,
    root_sha256: []const u8,
    schema: []const u8,
    scope: []const u8,
    statement_sha256: []const u8,
    status: []const u8,
    verifier_sha256: []const u8,

    pub fn validate(self: VerificationReceipt) !void {
        if (!std.mem.eql(u8, self.schema, verifier_receipt_schema) or
            !std.mem.eql(u8, self.status, "verified") or
            !std.mem.eql(u8, self.scope, "leaf") or
            !self.fresh_verification or self.level != 0 or
            self.proof_bytes == 0)
        {
            return error.VerificationReceiptMismatch;
        }
        inline for (.{
            self.proof_sha256,
            self.root_sha256,
            self.statement_sha256,
            self.verifier_sha256,
        }) |digest| _ = try parseSha256(digest);
    }
};

pub fn parseSource(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(SourceRequest) {
    var parsed = try parseCanonical(SourceRequest, allocator, bytes);
    errdefer parsed.deinit();
    try parsed.value.validate();
    return parsed;
}

/// Dispatch-only schema probe. Callers must still invoke the corresponding
/// exact canonical parser; this function never admits source bytes by itself.
pub fn sourceKind(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !SourceKind {
    const Probe = struct { schema: []const u8 };
    var parsed = try std.json.parseFromSlice(Probe, allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    if (std.mem.eql(u8, parsed.value.schema, source_schema))
        return .native_blake2s_v1;
    if (std.mem.eql(u8, parsed.value.schema, recursive_source_schema))
        return .recursive_poseidon2_v2;
    return error.UnsupportedSourceSchema;
}

pub fn parseRecursiveSource(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(RecursiveSourceRequestV2) {
    var parsed = try parseCanonical(RecursiveSourceRequestV2, allocator, bytes);
    errdefer parsed.deinit();
    try parsed.value.validate();
    return parsed;
}

pub fn parseStream(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(StreamRequest) {
    var parsed = try parseCanonical(StreamRequest, allocator, bytes);
    errdefer parsed.deinit();
    try parsed.value.validate();
    try validateContentSha256(allocator, bytes, parsed.value.content_sha256);
    return parsed;
}

pub fn parseMaterializationResult(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(MaterializationResult) {
    var parsed = try parseCanonical(MaterializationResult, allocator, bytes);
    errdefer parsed.deinit();
    try parsed.value.validate();
    try validateContentSha256(allocator, bytes, parsed.value.content_sha256);
    return parsed;
}

pub fn parseRealLeafTask(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(RealLeafTaskRequest) {
    var parsed = try parseCanonical(RealLeafTaskRequest, allocator, bytes);
    errdefer parsed.deinit();
    try parsed.value.validate();
    try validateContentSha256(allocator, bytes, parsed.value.content_sha256);
    return parsed;
}

pub fn parseVerificationReceipt(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(VerificationReceipt) {
    var parsed = try parseCanonical(VerificationReceipt, allocator, bytes);
    errdefer parsed.deinit();
    try parsed.value.validate();
    return parsed;
}

pub fn parseSha256(encoded: []const u8) ![32]u8 {
    if (encoded.len != 64) return error.InvalidSha256;
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch return error.InvalidSha256;
    const canonical = std.fmt.bytesToHex(result, .lower);
    if (!std.mem.eql(u8, encoded, &canonical)) return error.InvalidSha256;
    return result;
}

pub fn parseM31Digest(encoded: []const u8) ![8]u32 {
    const bytes = try parseSha256(encoded);
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index| {
        word.* = std.mem.readInt(u32, bytes[4 * index ..][0..4], .little);
        if (word.* >= @import("stwo_core").fields.m31.Modulus)
            return error.InvalidM31Digest;
    }
    return result;
}

fn parseCanonical(
    comptime T: type,
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(T) {
    if (bytes.len == 0 or bytes.len > max_json_bytes or
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
    const canonical = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
    defer allocator.free(canonical);
    if (canonical.len + 1 != bytes.len or
        !std.mem.eql(u8, canonical, bytes[0..canonical.len]))
    {
        return error.InvalidCanonicalJson;
    }
    return parsed;
}

fn validateContentSha256(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected: []const u8,
) !void {
    _ = try parseSha256(expected);
    const marker = "\"content_sha256\":\"";
    const start = std.mem.indexOf(u8, bytes, marker) orelse
        return error.MissingContentSha256;
    if (std.mem.indexOfPos(u8, bytes, start + marker.len, marker) != null)
        return error.DuplicateContentSha256;
    const value_start = start + marker.len;
    const value_end = value_start + 64;
    if (value_end >= bytes.len or bytes[value_end] != '"' or
        !std.mem.eql(u8, bytes[value_start..value_end], expected))
    {
        return error.InvalidContentSha256;
    }
    const field_start = if (start > 0 and bytes[start - 1] == ',') start - 1 else start;
    var field_end = value_end + 1;
    if (field_start == start) {
        if (field_end >= bytes.len or bytes[field_end] != ',')
            return error.InvalidContentSha256;
        field_end += 1;
    }
    const unsigned = try allocator.alloc(u8, bytes.len - (field_end - field_start));
    defer allocator.free(unsigned);
    @memcpy(unsigned[0..field_start], bytes[0..field_start]);
    @memcpy(unsigned[field_start..], bytes[field_end..]);
    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(unsigned, &actual, .{});
    const actual_hex = std.fmt.bytesToHex(actual, .lower);
    if (!std.mem.eql(u8, &actual_hex, expected))
        return error.InvalidContentSha256;
}

fn validateNativePcs(value: PcsAuthority) !void {
    const prover = @import("stwo_riscv_frontend").prover_mod;
    const expected = prover.SECURE_PCS_CONFIG;
    if (!std.mem.eql(u8, value.field, "M31") or
        !std.mem.eql(u8, value.commitment_hash, "Blake2s") or
        !std.mem.eql(u8, value.transcript_hash, "Blake2s") or
        value.pow_bits != expected.pow_bits or
        value.log_blowup_factor != expected.fri_config.log_blowup_factor or
        value.n_queries != expected.fri_config.n_queries or
        value.log_last_layer_degree_bound !=
            expected.fri_config.log_last_layer_degree_bound or
        value.fold_step != expected.fri_config.fold_step or
        value.lifting_log_size != expected.lifting_log_size)
    {
        return error.PcsAuthorityMismatch;
    }
}

fn validateRecursivePcs(value: PcsAuthority) !void {
    const expected = @import("stwo_riscv_frontend").recursion.protocol.PCS_CONFIG;
    if (!std.mem.eql(u8, value.field, "M31") or
        !std.mem.eql(u8, value.commitment_hash, recursive_hash_suite) or
        !std.mem.eql(u8, value.transcript_hash, recursive_hash_suite) or
        value.pow_bits != expected.pow_bits or
        value.log_blowup_factor != expected.fri_config.log_blowup_factor or
        value.n_queries != expected.fri_config.n_queries or
        value.log_last_layer_degree_bound !=
            expected.fri_config.log_last_layer_degree_bound or
        value.fold_step != expected.fri_config.fold_step or
        value.lifting_log_size != expected.lifting_log_size)
    {
        return error.PcsAuthorityMismatch;
    }
}

fn requireNonzeroM31Digest(value: [8]u32) !void {
    var nonzero = false;
    for (value) |word| {
        if (word >= @import("stwo_core").fields.m31.Modulus)
            return error.InvalidM31Digest;
        nonzero = nonzero or word != 0;
    }
    if (!nonzero) return error.RecursiveLeafProfileUnavailable;
}

fn requireNonzeroSha256(value: [32]u8) !void {
    if (std.mem.allEqual(u8, &value, 0))
        return error.RecursiveLeafProfileUnavailable;
}

fn validatePath(value: []const u8, allow_absolute: bool) !void {
    if (value.len == 0 or (!allow_absolute and std.fs.path.isAbsolute(value)))
        return error.InvalidPath;
    try requireAscii(value);
    var iterator = std.mem.splitScalar(u8, value, std.fs.path.sep);
    while (iterator.next()) |component|
        if (std.mem.eql(u8, component, "..")) return error.InvalidPath;
}

fn requireAscii(value: []const u8) !void {
    for (value) |byte| if (byte < 0x20 or byte > 0x7e or
        byte == '"' or byte == '\\') return error.NonCanonicalAscii;
}
