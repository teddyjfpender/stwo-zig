const std = @import("std");
const stwo = @import("stwo");
const build_identity = @import("build_identity");
const artifact_validation = @import("artifact_validation.zig");
const pcs_profile = @import("pcs_profile.zig");
const transcript_state = @import("transcript_state.zig");
const verify_receipt = @import("verify_receipt.zig");
const wire_reconstruct = @import("wire_reconstruct.zig");

const Protocol = pcs_profile.Protocol;
const stagedPcsConfig = pcs_profile.select;

pub fn verify(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    artifact: stwo.interop.riscv_artifact.Artifact,
    requested_policy: Protocol,
    expected_statement_digest: [32]u8,
    elf_path: []const u8,
) !void {
    const artifact_mod = stwo.interop.riscv_artifact;
    const prover = stwo.frontends.riscv.prover_mod;

    const suites = stwo.core.proof_suites;
    const expected_suite: artifact_mod.ProofSuite = if (comptime Engine.Hasher == suites.Blake3.Hasher and Engine.Channel == suites.Blake3.Channel and Engine.MerkleChannel == suites.Blake3.MerkleChannel)
        .blake3
    else if (comptime Engine.Hasher == suites.Blake2s.Hasher and Engine.Channel == suites.Blake2s.Channel and Engine.MerkleChannel == suites.Blake2s.MerkleChannel)
        .blake2s
    else
        return error.UnsupportedProofSuite;
    try artifact_mod.requireProofSuite(artifact, expected_suite);

    try artifact_mod.validateForPolicy(artifact, switch (requested_policy) {
        .secure => .secure,
        .functional => .functional,
        .smoke => .smoke,
    });
    try artifact_validation.validateLocalProvenance(artifact.provenance);
    try artifact_validation.validateElfBinding(allocator, artifact, elf_path);
    const actual_statement_digest = artifact_mod.statementDigest(
        artifact.protocol,
        artifact.pcs_config,
        artifact.source,
        artifact.statement,
    );
    if (!std.mem.eql(u8, &expected_statement_digest, &actual_statement_digest))
        return error.StatementDigestMismatch;

    var reconstructed = try wire_reconstruct.Reconstruction.init(allocator, artifact);
    defer reconstructed.deinit(allocator);

    if (artifact.proof_bytes_hex.len % 2 != 0) return error.InvalidArtifact;
    const proof_raw = try allocator.alloc(u8, artifact.proof_bytes_hex.len / 2);
    defer allocator.free(proof_raw);
    _ = std.fmt.hexToBytes(proof_raw, artifact.proof_bytes_hex) catch
        return error.InvalidArtifact;
    try admitProofBytesTo(
        std.fs.File.stderr(),
        proof_raw,
        try artifact_validation.proofPreflightShape(artifact),
    );
    var stream = std.io.fixedBufferStream(proof_raw);
    var proof = try stwo.interop.postcard.deserializeProof(
        Engine.Hasher,
        allocator,
        stream.reader(),
    );
    if (stream.pos != proof_raw.len) {
        proof.deinit(allocator);
        return error.InvalidArtifact;
    }

    const config = @TypeOf(stagedPcsConfig(.secure)){
        .pow_bits = artifact.pcs_config.pow_bits,
        .fri_config = .{
            .log_blowup_factor = artifact.pcs_config.fri_config.log_blowup_factor,
            .log_last_layer_degree_bound = artifact.pcs_config.fri_config.log_last_layer_degree_bound,
            .n_queries = artifact.pcs_config.fri_config.n_queries,
        },
    };
    if (!artifact_validation.pcsConfigsEqual(config, proof.commitment_scheme_proof.config)) {
        proof.deinit(allocator);
        return error.ProofConfigMismatch;
    }
    var verify_channel = Engine.Channel{};
    try prover.verifyRiscVWithEngineUsingChannel(
        Engine,
        allocator,
        config,
        reconstructed.statement,
        proof,
        &reconstructed.claim,
        &verify_channel,
    );

    var proof_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(proof_raw, &proof_digest, .{});
    const process_identity = try artifact_validation.measureProcessIdentity(allocator);
    const receipt = try verify_receipt.encodeWithReceipt(allocator, .{
        .artifact_kind = artifact.artifact_kind,
        .artifact_schema_version = artifact.schema_version,
        .release_status = artifact.release_status,
        .security_policy = @tagName(requested_policy),
        .statement_sha256 = actual_statement_digest,
        .proof_bytes = proof_raw.len,
        .proof_sha256 = proof_digest,
        .implementation_commit = build_identity.implementation_commit,
        .implementation_dirty = build_identity.implementation_dirty,
        .executable_sha256 = process_identity.executable_sha256,
    }, transcript_state.fromChannel(verify_channel));
    defer allocator.free(receipt);
    try std.fs.File.stdout().writeAll(receipt);
    try std.fs.File.stdout().writeAll("\n");
}

// Keep origin admission beside the real allocating decoder. The parser is an
// independent named module; exact structural equality rejects ABI drift in
// either direction without importing its source into the provider twice.
fn admitProofBytesTo(writer: anytype, raw: []const u8, shape: stwo.interop.postcard.proof_preflight.Shape) stwo.interop.postcard.proof_preflight.Error!void {
    const preflight = stwo.interop.postcard.proof_preflight;
    const codes = stwo.recursion_wire.error_codes;
    comptime {
        if (@typeInfo(@TypeOf(codes.fromPostcard)).@"fn".params[0].type.? != preflight.Error)
            @compileError("postcard diagnostic error contract must equal the owned parser error set");
    }
    preflight.validate(raw, shape) catch |err| {
        const entry = codes.fromPostcard(err);
        var storage: [320]u8 = undefined;
        const line = std.fmt.bufPrint(&storage, "{{\"schema\":\"recursion_postcard_rejection_v1\",\"provider\":\"stwo_circuit_recursion_wire\",\"origin\":\"postcard.preflight\",\"code\":{d},\"class\":\"{s}\"}}\n", .{ entry.code, @tagName(entry.class) }) catch unreachable;
        writer.writeAll(line) catch {};
        return err;
    };
}

test "riscv artifact postcard admission executes exact physical wire and coded refusals" {
    const preflight = stwo.interop.postcard.proof_preflight;
    const Cases = struct {
        fn shape() preflight.Shape {
            return .{ .config = .{ .pow_bits = 10, .log_blowup_factor = 1, .n_queries = 3, .log_last_layer_degree_bound = 0, .fold_step = 1, .lifting_log_size = null }, .tree_columns = .{ 1, 1, 1, 8 }, .max_column_log_size = 1, .hash_size = 32, .max_wire_bytes = 1 << 20 };
        }
        fn wire(a: std.mem.Allocator) ![]u8 {
            // Serializer-only borrowed fixture: shape admission is not STARK acceptance.
            const core = stwo.core;
            const H = core.proof_suites.Blake2s.Hasher;
            const Q = core.fields.qm31.QM31;
            const M = core.fields.m31.M31;
            var zero = [_]Q{ Q.zero(), Q.zero() };
            var columns = [_][]Q{zero[0..1]} ** 8;
            var pair = [_][]Q{zero[0..2]};
            var samples = [_][][]Q{ columns[0..1], columns[0..1], &pair, &columns };
            var no_values = [_][]M{&.{}} ** 8;
            var queried = [_][][]M{ no_values[0..1], no_values[0..1], no_values[0..1], &no_values };
            var roots = [_]H.Hash{@splat(0)} ** 4;
            var paths = [_]core.vcs_lifted.verifier.MerkleDecommitmentLifted(H){.{ .hash_witness = &.{} }} ** 4;
            const proof = core.proof.StarkProof(H){ .commitment_scheme_proof = .{
                .config = .{ .pow_bits = 10, .fri_config = try core.fri.FriConfig.init(0, 1, 3) },
                .commitments = .{ .items = &roots },
                .sampled_values = .{ .items = &samples },
                .decommitments = .{ .items = &paths },
                .queried_values = .{ .items = &queried },
                .proof_of_work = 0,
                .fri_proof = .{ .first_layer = .{ .fri_witness = &.{}, .decommitment = .{ .hash_witness = &.{} }, .commitment = @splat(0) }, .inner_layers = &.{}, .last_layer_poly = .{ .coeffs = zero[0..1], .log_size = 0 } },
            } };
            var bytes: std.ArrayList(u8) = .empty;
            errdefer bytes.deinit(a);
            try stwo.interop.postcard.serializeProof(H, bytes.writer(a), proof);
            return bytes.toOwnedSlice(a);
        }
        fn rejects(expected: preflight.Error, code: u16, raw: []const u8, expected_shape: preflight.Shape) !void {
            var storage: [320]u8 = undefined;
            var writer = std.Io.Writer.fixed(&storage);
            try std.testing.expectError(expected, admitProofBytesTo(&writer, raw, expected_shape));
            var expected_storage: [320]u8 = undefined;
            const line = try std.fmt.bufPrint(&expected_storage, "{{\"schema\":\"recursion_postcard_rejection_v1\",\"provider\":\"stwo_circuit_recursion_wire\",\"origin\":\"postcard.preflight\",\"code\":{d},\"class\":\"{s}\"}}\n", .{ code, if (code == 0x5108) "resource_exhausted" else "invalid_input" });
            try std.testing.expectEqualStrings(line, writer.buffered());
        }
    };
    const a = std.testing.allocator;
    const raw = try Cases.wire(a);
    defer a.free(raw);
    const before = std.hash.Wyhash.hash(0, raw);
    var storage: [320]u8 = undefined;
    var writer = std.Io.Writer.fixed(&storage);
    try admitProofBytesTo(&writer, raw, Cases.shape());
    try std.testing.expectEqual(@as(usize, 0), writer.buffered().len);
    try std.testing.expectEqual(before, std.hash.Wyhash.hash(0, raw));
    for (0..raw.len) |end| try Cases.rejects(error.EndOfStream, 0x5101, raw[0..end], Cases.shape());
    var changed = try a.dupe(u8, raw);
    defer a.free(changed);
    changed[0] = 9;
    try Cases.rejects(error.InvalidProofConfig, 0x5103, changed, Cases.shape());
    @memcpy(changed, raw);
    changed[5] = 2;
    try Cases.rejects(error.InvalidOptionTag, 0x5102, changed, Cases.shape());
    @memcpy(changed, raw);
    changed[6] = 3;
    try Cases.rejects(error.InvalidProofShape, 0x5104, changed, Cases.shape());
    var bounds = Cases.shape();
    bounds.hash_size = 0;
    try Cases.rejects(error.InvalidPreflightShape, 0x5105, raw, bounds);
    bounds = Cases.shape();
    bounds.max_wire_bytes = raw.len - 1;
    try Cases.rejects(error.ProofResourceLimitExceeded, 0x5108, raw, bounds);
    const noncanonical = try std.mem.concat(a, u8, &.{ &.{ 0x8a, 0 }, raw[1..] });
    defer a.free(noncanonical);
    try Cases.rejects(error.NonCanonicalVarint, 0x5107, noncanonical, Cases.shape());
    const scalar = try std.mem.concat(a, u8, &.{ raw[0 .. raw.len - 4], &.{ 0xff, 0xff, 0xff, 0xff, 0x07 }, raw[raw.len - 3 ..] });
    defer a.free(scalar);
    try Cases.rejects(error.NonCanonicalM31, 0x5106, scalar, Cases.shape());
    const trailing = try std.mem.concat(a, u8, &.{ raw, &.{0} });
    defer a.free(trailing);
    try Cases.rejects(error.TrailingProofBytes, 0x5109, trailing, Cases.shape());
    try Cases.rejects(error.VarintOverflow, 0x510a, &([_]u8{0xff} ** 10), Cases.shape());
}

test "riscv artifact postcard writer same-tag error preserves primary parser failure" {
    const Failing = struct {
        calls: usize = 0,
        correct_code: bool = false,
        pub fn writeAll(self: *@This(), line: []const u8) error{EndOfStream}!void {
            self.calls += 1;
            self.correct_code = std.mem.indexOf(u8, line, "\"code\":20739") != null;
            return error.EndOfStream;
        }
    };
    var writer = Failing{};
    const shape: stwo.interop.postcard.proof_preflight.Shape = .{ .config = .{ .pow_bits = 10, .log_blowup_factor = 1, .n_queries = 3, .log_last_layer_degree_bound = 0, .fold_step = 1, .lifting_log_size = null }, .tree_columns = .{ 1, 1, 1, 8 }, .max_column_log_size = 1, .hash_size = 32, .max_wire_bytes = 1024 };
    try std.testing.expectError(error.InvalidProofConfig, admitProofBytesTo(&writer, &.{9}, shape));
    try std.testing.expectEqual(@as(usize, 1), writer.calls);
    try std.testing.expect(writer.correct_code);
}
