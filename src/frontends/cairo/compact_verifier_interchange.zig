//! Authenticated compact Metal proof interchange for the pinned Rust verifier.
const std = @import("std");
const compact_geometry = @import("compact_protocol_geometry.zig");
const envelope = @import("compact_verifier_envelope.zig");

pub const RuntimeProtocolGeometryV1 = compact_geometry.RuntimeProtocolGeometryV1;

pub const protocol_magic = [_]u8{ 'S', 'T', 'W', 'Z', 'C', 'P', '1', 0 };
pub const protocol_version: u16 = 1;
pub const protocol_header_bytes: usize = 112;
pub const component_enable_count: u32 = 83;
pub const trace_tree_column_counts = [4]u32{ 161, 3449, 2268, 8 };
pub const sn2_interaction_claim_words: u32 = 58 * 4;
pub const sn2_sampled_value_words: u32 = 24_440;
pub const sn2_decommitment_capacity_words: u32 = 2_077_800;

pub fn sn2ProofLayout() CompactProofLayoutV1 {
    return .{
        .interaction_claim_words = sn2_interaction_claim_words,
        .sampled_value_words = sn2_sampled_value_words,
        .decommitment_capacity_words = sn2_decommitment_capacity_words,
    };
}

pub const PreprocessedTraceVariantV1 = enum(u32) {
    canonical = 1,
    canonical_without_pedersen = 2,
    canonical_small = 3,

    pub fn fromTraceTree0ColumnCount(count: u32) Error!PreprocessedTraceVariantV1 {
        return switch (count) {
            161 => .canonical,
            105 => .canonical_without_pedersen,
            156 => .canonical_small,
            else => Error.InvalidPreprocessedTraceGeometry,
        };
    }

    pub fn traceTree0ColumnCount(self: PreprocessedTraceVariantV1) u32 {
        return switch (self) {
            .canonical => 161,
            .canonical_without_pedersen => 105,
            .canonical_small => 156,
        };
    }
};

pub const envelope_magic = envelope.envelope_magic;
pub const envelope_version = envelope.envelope_version;
pub const envelope_header_bytes = envelope.envelope_header_bytes;
pub const section_header_bytes = envelope.section_header_bytes;
pub const section_count = envelope.section_count;
pub const section_flag_mandatory = envelope.section_flag_mandatory;
pub const max_envelope_bytes = envelope.max_envelope_bytes;
pub const compact_provenance_source = envelope.compact_provenance_source;
pub const compact_proof_serialization = envelope.compact_proof_serialization;
pub const compact_provenance_bytes = envelope.compact_provenance_bytes;

const trace_tree_count = compact_geometry.trace_tree_count;
const legacy_max_log_degree_bound = compact_geometry.legacy_max_log_degree_bound;
const minimumDecommitmentWords = compact_geometry.minimumDecommitmentWords;
const minimum_decommitment_words = minimumDecommitmentWords(12, 70) catch unreachable;

pub const Error = error{
    InvalidInteractionClaimWordCount,
    InvalidInteractionSumCount,
    InvalidSampledValueWordCount,
    InvalidDecommitmentCapacity,
    InvalidTraceTreeColumnCounts,
    InvalidPreprocessedTraceGeometry,
    InvalidProtocolGeometry,
    InvalidIdentityDigest,
    EmptyStatement,
    InvalidStatementFile,
    StatementFileChanged,
    ProofLengthMismatch,
    InvalidProofFile,
    ProofFileChanged,
    SectionTooLarge,
    EnvelopeTooLarge,
    LengthOverflow,
    NoncanonicalProvenanceLength,
};

pub const CompactProofLayoutV1 = struct {
    interaction_claim_words: u32,
    sampled_value_words: u32,
    decommitment_capacity_words: u32,
    final_line_coefficient_count: u32 = 1,

    pub fn protocol(self: CompactProofLayoutV1, channel_salt: u32) Error!CompactProtocolV1 {
        if (self.interaction_claim_words == 0 or self.interaction_claim_words % 4 != 0)
            return Error.InvalidInteractionClaimWordCount;
        return self.protocolRuntime(channel_salt, .sn2(), trace_tree_column_counts);
    }

    pub fn protocolRuntime(
        self: CompactProofLayoutV1,
        channel_salt: u32,
        geometry: RuntimeProtocolGeometryV1,
        trace_columns: [trace_tree_count]u32,
    ) Error!CompactProtocolV1 {
        if (self.interaction_claim_words == 0 or self.interaction_claim_words % 4 != 0)
            return Error.InvalidInteractionClaimWordCount;
        try geometry.validate();
        const preprocessed_variant = try PreprocessedTraceVariantV1.fromTraceTree0ColumnCount(
            trace_columns[0],
        );
        const result = CompactProtocolV1{
            .preprocessed_variant = preprocessed_variant,
            .channel_salt = channel_salt,
            .query_pow_bits = geometry.query_pow_bits,
            .log_blowup_factor = geometry.log_blowup_factor,
            .query_count = geometry.query_count,
            .log_last_layer_degree_bound = geometry.log_last_layer_degree_bound,
            .fri_fold_step = geometry.fri_fold_step,
            .fri_lifting_log_size = geometry.fri_lifting_log_size,
            .interaction_pow_bits = geometry.interaction_pow_bits,
            .commitment_count = geometry.commitment_count,
            .sampled_tree_count = geometry.sampled_tree_count,
            .fri_tree_count = geometry.fri_tree_count,
            .final_line_coefficient_count = self.final_line_coefficient_count,
            .decommitment_record_count = geometry.decommitment_record_count,
            .max_log_degree_bound = geometry.max_log_degree_bound,
            .interaction_sum_count = self.interaction_claim_words / 4,
            .sampled_value_words = self.sampled_value_words,
            .decommitment_capacity_words = self.decommitment_capacity_words,
            .trace_columns = trace_columns,
        };
        try result.validate();
        return result;
    }
};

/// The exact bounded protocol accepted by Rust `CompactProtocolV1::decode`.
pub const CompactProtocolV1 = struct {
    preprocessed_variant: PreprocessedTraceVariantV1 = .canonical,
    channel_salt: u32 = 0,
    query_pow_bits: u32 = 26,
    log_blowup_factor: u32 = 1,
    query_count: u32 = 70,
    log_last_layer_degree_bound: u32 = 0,
    fri_fold_step: u32 = 3,
    fri_lifting_log_size: ?u32 = null,
    interaction_pow_bits: u32 = 24,
    commitment_count: u32 = trace_tree_count,
    sampled_tree_count: u32 = trace_tree_count,
    fri_tree_count: u32 = 8,
    final_line_coefficient_count: u32 = 1,
    decommitment_record_count: u32 = 12,
    max_log_degree_bound: u32 = legacy_max_log_degree_bound,
    interaction_sum_count: u32,
    sampled_value_words: u32,
    decommitment_capacity_words: u32,
    trace_columns: [4]u32 = trace_tree_column_counts,

    pub fn validate(self: CompactProtocolV1) Error!void {
        try (RuntimeProtocolGeometryV1{
            .query_pow_bits = self.query_pow_bits,
            .log_blowup_factor = self.log_blowup_factor,
            .query_count = self.query_count,
            .log_last_layer_degree_bound = self.log_last_layer_degree_bound,
            .fri_fold_step = self.fri_fold_step,
            .fri_lifting_log_size = self.fri_lifting_log_size,
            .interaction_pow_bits = self.interaction_pow_bits,
            .commitment_count = self.commitment_count,
            .sampled_tree_count = self.sampled_tree_count,
            .fri_tree_count = self.fri_tree_count,
            .decommitment_record_count = self.decommitment_record_count,
            .max_log_degree_bound = self.max_log_degree_bound,
        }).validate();
        if (self.interaction_sum_count == 0 or
            self.interaction_sum_count > component_enable_count)
        {
            return Error.InvalidInteractionSumCount;
        }
        if (self.sampled_value_words == 0 or self.sampled_value_words % 4 != 0)
            return Error.InvalidSampledValueWordCount;
        const minimum_words = try minimumDecommitmentWords(
            self.decommitment_record_count,
            self.query_count,
        );
        if (self.decommitment_capacity_words < minimum_words)
            return Error.InvalidDecommitmentCapacity;
        for (self.trace_columns) |count| if (count == 0)
            return Error.InvalidTraceTreeColumnCounts;
        const derived_variant = try PreprocessedTraceVariantV1.fromTraceTree0ColumnCount(
            self.trace_columns[0],
        );
        if (derived_variant != self.preprocessed_variant or
            self.trace_columns[0] != self.preprocessed_variant.traceTree0ColumnCount())
        {
            return Error.InvalidPreprocessedTraceGeometry;
        }
        const maximum_coefficients: u32 = @as(u32, 1) << @intCast(self.log_last_layer_degree_bound);
        if (self.final_line_coefficient_count == 0 or
            self.final_line_coefficient_count > maximum_coefficients)
            return Error.InvalidProtocolGeometry;
    }

    pub fn proofWordCount(self: CompactProtocolV1) Error!usize {
        try self.validate();
        var words = try mulLength(self.commitment_count, 8);
        words = try addLength(words, try mulLength(self.interaction_sum_count, 4));
        words = try addLength(words, 2); // Interaction PoW nonce.
        words = try addLength(words, self.sampled_value_words);
        words = try addLength(words, try mulLength(self.fri_tree_count, 8));
        words = try addLength(words, try mulLength(self.final_line_coefficient_count, 4));
        words = try addLength(words, 2); // Query PoW nonce.
        words = try addLength(words, self.decommitment_capacity_words);
        return words;
    }

    pub fn proofByteCount(self: CompactProtocolV1) Error!usize {
        return mulLength(try self.proofWordCount(), 4);
    }

    pub fn encode(self: CompactProtocolV1) Error![protocol_header_bytes]u8 {
        try self.validate();
        var bytes = [_]u8{0} ** protocol_header_bytes;
        @memcpy(bytes[0..protocol_magic.len], &protocol_magic);
        putU16(&bytes, 8, protocol_version);
        putU16(&bytes, 10, protocol_header_bytes);
        putU32(&bytes, 16, 1); // Blake2s channel.
        putU32(&bytes, 20, 1); // resident_sn2_bundle_v1 serialization.
        putU32(&bytes, 24, @intFromEnum(self.preprocessed_variant));
        putU32(&bytes, 28, self.channel_salt);
        putU32(&bytes, 32, self.query_pow_bits);
        putU32(&bytes, 36, self.log_blowup_factor);
        putU32(&bytes, 40, self.query_count);
        putU32(&bytes, 44, self.log_last_layer_degree_bound);
        putU32(&bytes, 48, self.fri_fold_step);
        putU32(&bytes, 52, self.fri_lifting_log_size orelse std.math.maxInt(u32));
        putU32(&bytes, 56, self.interaction_pow_bits);
        putU32(&bytes, 60, self.commitment_count);
        putU32(&bytes, 64, self.sampled_tree_count);
        putU32(&bytes, 68, self.fri_tree_count);
        putU32(&bytes, 72, self.final_line_coefficient_count);
        putU32(&bytes, 76, self.decommitment_record_count);
        putU32(&bytes, 80, self.interaction_sum_count);
        putU32(&bytes, 84, self.sampled_value_words);
        putU32(&bytes, 88, self.decommitment_capacity_words);
        for (self.trace_columns, 0..) |count, index| {
            putU32(&bytes, 92 + index * 4, count);
        }
        putU32(
            &bytes,
            108,
            if (self.max_log_degree_bound == legacy_max_log_degree_bound)
                0
            else
                self.max_log_degree_bound,
        );
        // Flags at 12 remain canonical zeroes.
        return bytes;
    }
};

pub const CompactProvenanceIdentities = envelope.CompactProvenanceIdentities;
pub const EnvelopeSummary = envelope.EnvelopeSummary;
pub const encodeCompactProvenanceV1 = envelope.encodeCompactProvenanceV1;

pub fn writeEnvelopeV1(
    writer: *std.Io.Writer,
    protocol: CompactProtocolV1,
    statement: []const u8,
    proof: []const u8,
    identities: CompactProvenanceIdentities,
) !EnvelopeSummary {
    return envelope.writeEnvelopeV1(writer, protocol, statement, proof, identities);
}

pub fn writeEnvelopeFromProofPathV1(
    writer: *std.Io.Writer,
    protocol: CompactProtocolV1,
    statement: []const u8,
    proof_path: []const u8,
    identities: CompactProvenanceIdentities,
) !EnvelopeSummary {
    return envelope.writeEnvelopeFromProofPathV1(
        writer,
        protocol,
        statement,
        proof_path,
        identities,
    );
}

pub fn writeEnvelopeFromPathsV1(
    allocator: std.mem.Allocator,
    writer: *std.Io.Writer,
    protocol: CompactProtocolV1,
    statement_path: []const u8,
    proof_path: []const u8,
    identities: CompactProvenanceIdentities,
) !EnvelopeSummary {
    return envelope.writeEnvelopeFromPathsV1(
        allocator,
        writer,
        protocol,
        statement_path,
        proof_path,
        identities,
    );
}

fn sha256(payload: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
    return digest;
}

fn addLength(left: anytype, right: anytype) Error!usize {
    const right_usize = std.math.cast(usize, right) orelse return Error.LengthOverflow;
    return std.math.add(usize, left, right_usize) catch Error.LengthOverflow;
}

fn mulLength(left: anytype, right: anytype) Error!usize {
    const left_usize = std.math.cast(usize, left) orelse return Error.LengthOverflow;
    const right_usize = std.math.cast(usize, right) orelse return Error.LengthOverflow;
    return std.math.mul(usize, left_usize, right_usize) catch Error.LengthOverflow;
}

fn putU16(bytes: []u8, offset: usize, value: anytype) void {
    std.mem.writeInt(u16, bytes[offset..][0..2], @intCast(value), .little);
}

fn putU32(bytes: []u8, offset: usize, value: u32) void {
    std.mem.writeInt(u32, bytes[offset..][0..4], value, .little);
}

fn digestFromHex(encoded: []const u8) ![32]u8 {
    var digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&digest, encoded);
    return digest;
}

test "compact protocol matches the Rust-accepted SN2 golden bytes" {
    const protocol = try sn2ProofLayout().protocol(0);
    const encoded = try protocol.encode();
    const encoded_hex = std.fmt.bytesToHex(encoded, .lower);
    try std.testing.expectEqualStrings(
        "5354575a43503100010070000000000001000000010000000100000000000000" ++
            "1a00000001000000460000000000000003000000ffffffff1800000004000000" ++
            "0400000008000000010000000c0000003a000000785f000068b41f00a1000000" ++
            "790d0000dc0800000800000000000000",
        &encoded_hex,
    );
    const digest_hex = std.fmt.bytesToHex(sha256(&encoded), .lower);
    try std.testing.expectEqualStrings(
        "539751a53034c0b279bd023a04a54b203cda5a9a4acdbba83159a9790dc1cfa4",
        &digest_hex,
    );
    try std.testing.expectEqual(@as(usize, 2_102_576), try protocol.proofWordCount());
    try std.testing.expectEqual(@as(usize, 8_410_304), try protocol.proofByteCount());
}

test "compact protocol encodes Fib-like runtime geometry and preprocessed variant" {
    var geometry = RuntimeProtocolGeometryV1.sn2();
    geometry.max_log_degree_bound = 20;
    geometry.fri_tree_count = 7;
    geometry.decommitment_record_count = 11;
    const decommitment_words = try minimumDecommitmentWords(
        geometry.decommitment_record_count,
        geometry.query_count,
    );
    const protocol = try (CompactProofLayoutV1{
        .interaction_claim_words = 8,
        .sampled_value_words = 32,
        .decommitment_capacity_words = decommitment_words,
    }).protocolRuntime(9, geometry, .{ 105, 7, 3, 8 });
    const encoded = try protocol.encode();
    const encoded_hex = std.fmt.bytesToHex(encoded, .lower);
    try std.testing.expectEqualStrings(
        "5354575a43503100010070000000000001000000010000000200000009000000" ++
            "1a00000001000000460000000000000003000000ffffffff1800000004000000" ++
            "0400000007000000010000000b00000002000000200000004401000069000000" ++
            "07000000030000000800000014000000",
        &encoded_hex,
    );
    const digest_hex = std.fmt.bytesToHex(sha256(&encoded), .lower);
    try std.testing.expectEqualStrings(
        "95fb7e321bdc9c4ac69c87921d0f274654ff3597a642ed247b5c6d0f07a812bd",
        &digest_hex,
    );
    try std.testing.expectEqual(PreprocessedTraceVariantV1.canonical_without_pedersen, protocol.preprocessed_variant);
    try std.testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, encoded[24..28], .little));
    try std.testing.expectEqual(@as(u32, 4), std.mem.readInt(u32, encoded[60..64], .little));
    try std.testing.expectEqual(@as(u32, 7), std.mem.readInt(u32, encoded[68..72], .little));
    try std.testing.expectEqual(@as(u32, 11), std.mem.readInt(u32, encoded[76..80], .little));
    try std.testing.expectEqual(@as(u32, 20), std.mem.readInt(u32, encoded[108..112], .little));
    try std.testing.expectEqual(@as(usize, 460), try protocol.proofWordCount());

    geometry.decommitment_record_count = 12;
    try std.testing.expectError(
        Error.InvalidProtocolGeometry,
        (CompactProofLayoutV1{
            .interaction_claim_words = 8,
            .sampled_value_words = 32,
            .decommitment_capacity_words = decommitment_words,
        }).protocolRuntime(9, geometry, .{ 105, 7, 3, 8 }),
    );
}

test "compact protocol derives stable preprocessed tags from tree zero width" {
    const cases = [_]struct {
        variant: PreprocessedTraceVariantV1,
        tree_zero_columns: u32,
        tag: u32,
    }{
        .{ .variant = .canonical, .tree_zero_columns = 161, .tag = 1 },
        .{ .variant = .canonical_without_pedersen, .tree_zero_columns = 105, .tag = 2 },
        .{ .variant = .canonical_small, .tree_zero_columns = 156, .tag = 3 },
    };
    const layout = CompactProofLayoutV1{
        .interaction_claim_words = 4,
        .sampled_value_words = 4,
        .decommitment_capacity_words = minimum_decommitment_words,
    };
    for (cases) |case| {
        const protocol = try layout.protocolRuntime(
            0,
            .sn2(),
            .{ case.tree_zero_columns, 1, 1, 1 },
        );
        try std.testing.expectEqual(case.variant, protocol.preprocessed_variant);
        const encoded = try protocol.encode();
        try std.testing.expectEqual(case.tag, std.mem.readInt(u32, encoded[24..28], .little));
        try std.testing.expectEqual(case.tree_zero_columns, std.mem.readInt(u32, encoded[92..96], .little));
    }
}

test "compact protocol rejects unknown or mismatched preprocessed geometry" {
    const layout = CompactProofLayoutV1{
        .interaction_claim_words = 4,
        .sampled_value_words = 4,
        .decommitment_capacity_words = minimum_decommitment_words,
    };
    try std.testing.expectError(
        Error.InvalidPreprocessedTraceGeometry,
        layout.protocolRuntime(0, .sn2(), .{ 160, 1, 1, 1 }),
    );

    var protocol = try layout.protocolRuntime(0, .sn2(), .{ 105, 1, 1, 1 });
    protocol.preprocessed_variant = .canonical;
    try std.testing.expectError(Error.InvalidPreprocessedTraceGeometry, protocol.encode());
}

test "runner proof layout rejects a partial interaction sum" {
    try std.testing.expectError(
        Error.InvalidInteractionClaimWordCount,
        (CompactProofLayoutV1{
            .interaction_claim_words = 231,
            .sampled_value_words = 24_440,
            .decommitment_capacity_words = 2_077_800,
        }).protocol(0),
    );
}

test "compact provenance exactly matches the Rust diagnostic envelope" {
    const diagnostic_identity =
        "1497eb76b21031ce730621b4be360b634fbf99e528d2827e479e63823fbabbc3";
    const provenance = try encodeCompactProvenanceV1(
        try digestFromHex("539751a53034c0b279bd023a04a54b203cda5a9a4acdbba83159a9790dc1cfa4"),
        try digestFromHex("36c41bd4fd5bb256dcef94d15084e46dc1c30c1b99f82de1036162dfb9fb2623"),
        try digestFromHex("5c9fe8577d83aac0c9a42d3e482e471c653e3d459304cb9310c411b283aa9052"),
        .{
            .adapted_input_sha256 = diagnostic_identity,
            .artifact_manifest_sha256 = diagnostic_identity,
            .runner_executable_sha256 = diagnostic_identity,
            .backend_executable_sha256 = diagnostic_identity,
        },
    );
    try std.testing.expectEqualStrings(
        "{\"schema_version\":1,\"source\":\"metal_prover_service_v1\"," ++
            "\"proof_serialization\":\"resident_sn2_bundle_v1\"," ++
            "\"protocol_sha256\":\"539751a53034c0b279bd023a04a54b203cda5a9a4acdbba83159a9790dc1cfa4\"," ++
            "\"statement_sha256\":\"36c41bd4fd5bb256dcef94d15084e46dc1c30c1b99f82de1036162dfb9fb2623\"," ++
            "\"proof_sha256\":\"5c9fe8577d83aac0c9a42d3e482e471c653e3d459304cb9310c411b283aa9052\"," ++
            "\"adapted_input_sha256\":\"1497eb76b21031ce730621b4be360b634fbf99e528d2827e479e63823fbabbc3\"," ++
            "\"artifact_manifest_sha256\":\"1497eb76b21031ce730621b4be360b634fbf99e528d2827e479e63823fbabbc3\"," ++
            "\"runner_executable_sha256\":\"1497eb76b21031ce730621b4be360b634fbf99e528d2827e479e63823fbabbc3\"," ++
            "\"backend_executable_sha256\":\"1497eb76b21031ce730621b4be360b634fbf99e528d2827e479e63823fbabbc3\"}",
        &provenance,
    );
    const digest_hex = std.fmt.bytesToHex(sha256(&provenance), .lower);
    try std.testing.expectEqualStrings(
        "d136a422d855fa43c287410cf19f9402d17ceb038442fe2f26aacf7636d46b65",
        &digest_hex,
    );
}

test "envelope writer emits canonical ordered mandatory sections" {
    const protocol = CompactProtocolV1{
        .interaction_sum_count = 1,
        .sampled_value_words = 4,
        .decommitment_capacity_words = minimum_decommitment_words,
    };
    const proof = [_]u8{0x5a} ** (try protocol.proofByteCount());
    const statement = "compact-statement";
    const identities = CompactProvenanceIdentities{
        .adapted_input_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .artifact_manifest_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        .runner_executable_sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        .backend_executable_sha256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    };
    const expected_len = envelope_header_bytes + 4 * section_header_bytes +
        protocol_header_bytes + statement.len + proof.len + compact_provenance_bytes;
    var encoded: [expected_len]u8 = undefined;
    var writer = std.Io.Writer.fixed(&encoded);
    const summary = try writeEnvelopeV1(&writer, protocol, statement, &proof, identities);
    try std.testing.expectEqual(expected_len, writer.buffered().len);
    try std.testing.expectEqual(@as(u64, expected_len), summary.total_bytes);
    try std.testing.expectEqualSlices(u8, &envelope_magic, encoded[0..8]);
    try std.testing.expectEqual(envelope_version, std.mem.readInt(u16, encoded[8..10], .little));
    try std.testing.expectEqual(@as(u16, envelope_header_bytes), std.mem.readInt(u16, encoded[10..12], .little));
    try std.testing.expectEqual(section_count, std.mem.readInt(u32, encoded[16..20], .little));
    try std.testing.expectEqual(@as(u64, expected_len), std.mem.readInt(u64, encoded[24..32], .little));

    const protocol_payload = try protocol.encode();
    const provenance_payload = try encodeCompactProvenanceV1(
        summary.protocol_sha256,
        summary.statement_sha256,
        summary.proof_sha256,
        identities,
    );
    const payloads = [_][]const u8{ &protocol_payload, statement, &proof, &provenance_payload };
    var cursor: usize = envelope_header_bytes;
    for (payloads, 1..) |payload, kind| {
        try std.testing.expectEqual(@as(u16, @intCast(kind)), std.mem.readInt(u16, encoded[cursor..][0..2], .little));
        try std.testing.expectEqual(section_flag_mandatory, std.mem.readInt(u16, encoded[cursor + 2 ..][0..2], .little));
        try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, encoded[cursor + 4 ..][0..4], .little));
        try std.testing.expectEqual(@as(u64, payload.len), std.mem.readInt(u64, encoded[cursor + 8 ..][0..8], .little));
        try std.testing.expectEqualSlices(u8, &sha256(payload), encoded[cursor + 16 .. cursor + 48]);
        cursor += section_header_bytes;
        try std.testing.expectEqualSlices(u8, payload, encoded[cursor .. cursor + payload.len]);
        cursor += payload.len;
    }
    try std.testing.expectEqual(encoded.len, cursor);
}

test "proof-path writer streams the same canonical envelope as proof bytes" {
    const protocol = try (CompactProofLayoutV1{
        .interaction_claim_words = 4,
        .sampled_value_words = 4,
        .decommitment_capacity_words = minimum_decommitment_words,
    }).protocol(0);
    const proof = [_]u8{0x73} ** 1808;
    try std.testing.expectEqual(proof.len, try protocol.proofByteCount());
    const statement = "compact-statement";
    const identities = CompactProvenanceIdentities{
        .adapted_input_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .artifact_manifest_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        .runner_executable_sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        .backend_executable_sha256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    };
    const expected_len = envelope_header_bytes + 4 * section_header_bytes +
        protocol_header_bytes + statement.len + proof.len + compact_provenance_bytes;
    var direct_bytes: [expected_len]u8 = undefined;
    var direct_writer = std.Io.Writer.fixed(&direct_bytes);
    const direct_summary = try writeEnvelopeV1(
        &direct_writer,
        protocol,
        statement,
        &proof,
        identities,
    );

    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    {
        const file = try temporary.dir.createFile("proof.bin", .{ .exclusive = true });
        defer file.close();
        try file.writeAll(&proof);
        try file.sync();
    }
    {
        const file = try temporary.dir.createFile("statement.bin", .{ .exclusive = true });
        defer file.close();
        try file.writeAll(statement);
        try file.sync();
    }
    const proof_path = try temporary.dir.realpathAlloc(std.testing.allocator, "proof.bin");
    defer std.testing.allocator.free(proof_path);
    var streamed_bytes: [expected_len]u8 = undefined;
    var streamed_writer = std.Io.Writer.fixed(&streamed_bytes);
    const streamed_summary = try writeEnvelopeFromProofPathV1(
        &streamed_writer,
        protocol,
        statement,
        proof_path,
        identities,
    );
    try std.testing.expectEqual(direct_summary, streamed_summary);
    try std.testing.expectEqualSlices(u8, &direct_bytes, &streamed_bytes);

    const statement_path = try temporary.dir.realpathAlloc(std.testing.allocator, "statement.bin");
    defer std.testing.allocator.free(statement_path);
    var path_bytes: [expected_len]u8 = undefined;
    var path_writer = std.Io.Writer.fixed(&path_bytes);
    const path_summary = try writeEnvelopeFromPathsV1(
        std.testing.allocator,
        &path_writer,
        protocol,
        statement_path,
        proof_path,
        identities,
    );
    try std.testing.expectEqual(direct_summary, path_summary);
    try std.testing.expectEqualSlices(u8, &direct_bytes, &path_bytes);
}

test "interchange rejects invalid geometry and provenance before writing" {
    const bad_protocol = CompactProtocolV1{
        .interaction_sum_count = 0,
        .sampled_value_words = 4,
        .decommitment_capacity_words = minimum_decommitment_words,
    };
    try std.testing.expectError(Error.InvalidInteractionSumCount, bad_protocol.encode());

    const protocol = CompactProtocolV1{
        .interaction_sum_count = 1,
        .sampled_value_words = 4,
        .decommitment_capacity_words = minimum_decommitment_words,
    };
    var encoded: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&encoded);
    try std.testing.expectError(Error.ProofLengthMismatch, writeEnvelopeV1(
        &writer,
        protocol,
        "statement",
        "short-proof",
        .{
            .adapted_input_sha256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            .artifact_manifest_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            .runner_executable_sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            .backend_executable_sha256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        },
    ));
    try std.testing.expectEqual(@as(usize, 0), writer.buffered().len);

    const proof = [_]u8{0} ** (try protocol.proofByteCount());
    try std.testing.expectError(Error.InvalidIdentityDigest, writeEnvelopeV1(
        &writer,
        protocol,
        "statement",
        &proof,
        .{
            .adapted_input_sha256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            .artifact_manifest_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            .runner_executable_sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            .backend_executable_sha256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        },
    ));
    try std.testing.expectEqual(@as(usize, 0), writer.buffered().len);
}
