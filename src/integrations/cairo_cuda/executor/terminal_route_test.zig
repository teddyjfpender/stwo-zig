const std = @import("std");
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const prover = @import("stwo_cairo_frontend").prover;
const decommit = @import(
    "../../../backends/cuda/runtime/proof_assembly/decommit_bundle.zig",
);
const common = @import("../../native_cuda/common/proof_bundle.zig");
const terminal = @import("terminal_bundle.zig");
const decode = @import("terminal_decode.zig");
const route = @import("proof_route.zig");

const Fixture = struct {
    protocol: compact.CompactProtocolV1,
    descriptor: terminal.Bundle,
    transport: []u32,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var geometry = compact.RuntimeProtocolGeometryV1.sn2();
        geometry.max_log_degree_bound = 20;
        geometry.fri_tree_count = 7;
        geometry.decommitment_record_count = 11;
        const protocol = try (compact.CompactProofLayoutV1{
            .interaction_claim_words = 8,
            .sampled_value_words = 32,
            .decommitment_capacity_words = 324,
        }).protocolRuntime(9, geometry, .{ 105, 7, 3, 8 });
        var descriptor = try terminal.Bundle.init(
            allocator,
            .{ .protocol = protocol },
            .{ .capacity_words = protocol.decommitment_capacity_words },
        );
        errdefer descriptor.deinit(allocator);
        const transport = try allocator.alloc(u32, descriptor.total_words);
        errdefer allocator.free(transport);
        @memset(transport, 0);
        @memcpy(transport[0..common.header_words], descriptor.static_header);
        transport[common.fixed_header_words - 1] = 0;

        const trace = section(descriptor, transport, .trace_commitments);
        for (trace, 0..) |*word, index| word.* = @intCast(10 + index);
        const samples = section(descriptor, transport, .sampled_values);
        for (samples, 0..) |*word, index| word.* = @intCast(100 + index);
        const fri = section(descriptor, transport, .fri_commitments);
        for (fri, 0..) |*word, index| word.* = @intCast(200 + index);
        const last = section(descriptor, transport, .fri_last_layer);
        for (last, 0..) |*word, index| word.* = @intCast(300 + index);
        const pow = section(descriptor, transport, .proof_of_work);
        pow[0..4].* = .{ 0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444 };
        try fillDecommitment(
            section(descriptor, transport, .decommitment),
            protocol,
        );
        return .{
            .protocol = protocol,
            .descriptor = descriptor,
            .transport = transport,
        };
    }

    fn deinit(self: *Fixture, allocator: std.mem.Allocator) void {
        allocator.free(self.transport);
        self.descriptor.deinit(allocator);
        self.* = undefined;
    }

    fn evidence(self: Fixture) decode.MeasuredTerminalRead {
        return .{
            .measured = true,
            .d2h_proof_operations = 1,
            .d2h_proof_bytes = self.transport.len * @sizeOf(u32),
            .runtime_compile_attempts = 0,
            .cpu_fallback_attempts = 0,
        };
    }
};

fn fillDecommitment(
    capacity: []u32,
    protocol: compact.CompactProtocolV1,
) !void {
    @memset(capacity, 0);
    const tree_count: usize = protocol.decommitment_record_count;
    const raw_count: usize = protocol.query_count;
    const raw_offset = decommit.header_words + tree_count * decommit.tree_meta_words;
    const unique_offset = raw_offset + raw_count;
    var cursor = unique_offset + 1;
    if (cursor + tree_count > capacity.len)
        return error.TestFixtureTooSmall;
    capacity[0..decommit.header_words].* = .{
        decommit.magic,
        decommit.version,
        @intCast(tree_count),
        @intCast(raw_count),
        1,
        @intCast(raw_offset),
        @intCast(unique_offset),
        @intCast(cursor + tree_count),
    };
    // Raw and unique query zero are already canonical zero words.
    for (0..tree_count) |index| {
        const meta = capacity[decommit.header_words + index * decommit.tree_meta_words ..][0..decommit.tree_meta_words];
        meta[0] = @intFromEnum(
            if (index < protocol.commitment_count)
                decommit.TreeKind.trace
            else
                decommit.TreeKind.fri,
        );
        meta[1] = @intCast(index);
        meta[2] = @intCast(cursor);
        meta[3] = 1;
        meta[14] = 1;
        meta[15] = 1;
        cursor += 1;
    }
}

fn section(
    descriptor: terminal.Bundle,
    transport: []u32,
    kind: common.SectionKind,
) []u32 {
    const selected = descriptor.section(kind);
    return transport[selected.offset_words .. selected.offset_words + selected.words];
}

test "Cairo CUDA terminal reconstruction emits exact canonical proof order" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit(allocator);
    var canonical = try decode.CanonicalProof.decode(
        allocator,
        fixture.protocol,
        fixture.transport,
        fixture.evidence(),
    );
    defer canonical.deinit(allocator);
    try std.testing.expectEqual(
        try fixture.protocol.proofWordCount(),
        canonical.words.len,
    );

    const layout = canonical.structural.layout;
    const source_trace = section(
        fixture.descriptor,
        fixture.transport,
        .trace_commitments,
    );
    try std.testing.expectEqualSlices(
        u32,
        source_trace[0..32],
        canonical.words[layout.commitments.start..layout.commitments.end],
    );
    try std.testing.expectEqualSlices(
        u32,
        source_trace[32..],
        canonical.words[layout.interaction_claim.start..layout.interaction_claim.end],
    );
    try std.testing.expectEqualSlices(
        u32,
        &.{ 0x1111_1111, 0x2222_2222 },
        canonical.words[layout.interaction_pow.start..layout.interaction_pow.end],
    );
    try std.testing.expectEqualSlices(
        u32,
        &.{ 0x3333_3333, 0x4444_4444 },
        canonical.words[layout.query_pow.start..layout.query_pow.end],
    );
    try std.testing.expectEqual(
        canonical.words.len * @sizeOf(u32),
        canonical.bytes().len,
    );
    var expected_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(canonical.bytes(), &expected_digest, .{});
    try std.testing.expectEqual(expected_digest, canonical.sha256());
}

test "Cairo CUDA terminal transport binds the full golden SN2 proof capacity" {
    const protocol = try compact.sn2ProofLayout().protocol(0);
    try std.testing.expectEqual(
        @as(usize, 2_102_576),
        try protocol.proofWordCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 2_102_576 + common.header_words),
        try decode.transportWordCount(std.testing.allocator, protocol),
    );
    try std.testing.expectEqual(
        @as(usize, 8_410_304),
        try protocol.proofByteCount(),
    );
}

test "Cairo CUDA terminal route rejects fabricated residency and malformed output" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit(allocator);

    var evidence = fixture.evidence();
    evidence.measured = false;
    try std.testing.expectError(
        error.IncompleteTerminalReadEvidence,
        decode.CanonicalProof.decode(
            allocator,
            fixture.protocol,
            fixture.transport,
            evidence,
        ),
    );
    evidence = fixture.evidence();
    evidence.runtime_compile_attempts = 1;
    try std.testing.expectError(
        error.RuntimeCompilationObserved,
        decode.CanonicalProof.decode(
            allocator,
            fixture.protocol,
            fixture.transport,
            evidence,
        ),
    );
    evidence = fixture.evidence();
    evidence.cpu_fallback_attempts = 1;
    try std.testing.expectError(
        error.CpuFallbackObserved,
        decode.CanonicalProof.decode(
            allocator,
            fixture.protocol,
            fixture.transport,
            evidence,
        ),
    );

    fixture.transport[1] ^= 1;
    try std.testing.expectError(
        error.InvalidTerminalHeader,
        decode.CanonicalProof.decode(
            allocator,
            fixture.protocol,
            fixture.transport,
            fixture.evidence(),
        ),
    );
    fixture.transport[1] ^= 1;
    const tail = section(
        fixture.descriptor,
        fixture.transport,
        .decommitment,
    );
    tail[tail.len - 1] = 1;
    try std.testing.expectError(
        error.NonzeroDecommitmentTail,
        decode.CanonicalProof.decode(
            allocator,
            fixture.protocol,
            fixture.transport,
            fixture.evidence(),
        ),
    );
}

test "Cairo CUDA route envelopes canonical bytes and exposes Rust oracle hook" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit(allocator);
    var canonical = try decode.CanonicalProof.decode(
        allocator,
        fixture.protocol,
        fixture.transport,
        fixture.evidence(),
    );
    defer canonical.deinit(allocator);
    const statement = "authenticated Cairo statement";
    const identities = route.ProvenanceIdentities{
        .adapted_input_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .artifact_manifest_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        .runner_executable_sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        .backend_executable_sha256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    };
    const envelope_len = compact.envelope_header_bytes +
        compact.section_count * compact.section_header_bytes +
        compact.protocol_header_bytes + statement.len + canonical.bytes().len +
        compact.compact_provenance_bytes;
    const encoded = try allocator.alloc(u8, envelope_len);
    defer allocator.free(encoded);
    var writer = std.Io.Writer.fixed(encoded);
    const summary = try route.writeEnvelope(
        &writer,
        canonical,
        statement,
        identities,
    );
    try std.testing.expectEqual(envelope_len, writer.buffered().len);
    try std.testing.expectEqual(canonical.sha256(), summary.proof_sha256);
    const proof_payload_offset = compact.envelope_header_bytes +
        compact.section_header_bytes + compact.protocol_header_bytes +
        compact.section_header_bytes + statement.len +
        compact.section_header_bytes;
    try std.testing.expectEqualSlices(
        u8,
        canonical.bytes(),
        encoded[proof_payload_offset .. proof_payload_offset + canonical.bytes().len],
    );

    const MockOracle = struct {
        called: bool = false,

        pub fn verifyCairo(
            self: *@This(),
            _: std.mem.Allocator,
            path: []const u8,
        ) !prover.OracleEvidence {
            if (!std.mem.eql(u8, path, "/tmp/cairo-cuda-proof.stwzcve"))
                return error.UnexpectedEnvelopePath;
            self.called = true;
            return .{
                .verified = true,
                .envelope_sha256 = [_]u8{0x5a} ** 32,
                .envelope_abi = prover.canonical_envelope_abi,
                .verification_mode = prover.canonical_verification_mode,
                .stwo_cairo_revision = prover.pinned_stwo_cairo_revision,
                .stwo_revision = prover.pinned_stwo_revision,
            };
        }
    };
    var oracle = MockOracle{};
    const evidence = try route.verifyWithOracle(
        MockOracle,
        &oracle,
        allocator,
        "/tmp/cairo-cuda-proof.stwzcve",
    );
    try std.testing.expect(oracle.called);
    try std.testing.expect(evidence.verified);
}
