//! Fresh process two: decode and verify one joined Ethereum v2 artifact.

const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("stwo_riscv_frontend");
const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const support = @import("ethereum_precompile_artifact_support.zig");

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    if (arguments.len != 2) {
        std.debug.print("usage: ethereum-precompile-artifact-verifier <artifact>\n", .{});
        return error.InvalidArguments;
    }
    try verifyArtifact(allocator, arguments[1]);
}

fn verifyArtifact(allocator: std.mem.Allocator, path: []const u8) !void {
    const encoded = try artifact_io.readFileBounded(
        allocator,
        path,
        support.artifact_limits.max_artifact_bytes,
    );
    defer allocator.free(encoded);
    var decoded = try support.proof_artifact.decodeAllocForConfig(
        allocator,
        encoded,
        support.pcs_config,
        support.artifact_limits,
    );
    var proof_moved = false;
    defer if (proof_moved)
        decoded.deinitAfterProofMoved(allocator)
    else
        decoded.deinit(allocator);
    const statement_sha256 = statementDigest(encoded);
    const roots_sha256 = rootsDigest(&decoded.proof);
    var channel = support.Engine.Channel{};
    proof_moved = true;
    try frontend.prover_mod.verifyEthereumWithEngineUsingChannel(
        support.Engine,
        allocator,
        support.pcs_config,
        decoded.statement,
        decoded.extension,
        decoded.proof,
        decoded.base_claim,
        &decoded.extension_claim,
        &channel,
    );
    var artifact_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &artifact_sha256, .{});
    const transcript_sha256 = artifact_io.transcriptReceiptDigest(
        channel.digestBytes(),
        channel.n_draws,
    );
    const executable_sha256 = try artifact_io.executableSha256(allocator);
    const receipt = try encodeReceipt(allocator, .{
        .artifact_bytes = encoded.len,
        .artifact_sha256 = artifact_sha256,
        .statement_sha256 = statement_sha256,
        .roots_sha256 = roots_sha256,
        .transcript_state_blake2s = transcript_sha256,
        .executable_sha256 = executable_sha256,
    });
    defer allocator.free(receipt);
    try std.fs.File.stdout().writeAll(receipt);
    try std.fs.File.stdout().writeAll("\n");
}

const ReceiptInput = struct {
    artifact_bytes: usize,
    artifact_sha256: [32]u8,
    statement_sha256: [32]u8,
    roots_sha256: [32]u8,
    transcript_state_blake2s: [32]u8,
    executable_sha256: [32]u8,
};

fn encodeReceipt(
    allocator: std.mem.Allocator,
    input: ReceiptInput,
) ![]u8 {
    const artifact_hex = std.fmt.bytesToHex(input.artifact_sha256, .lower);
    const statement_hex = std.fmt.bytesToHex(input.statement_sha256, .lower);
    const roots_hex = std.fmt.bytesToHex(input.roots_sha256, .lower);
    const transcript_hex = std.fmt.bytesToHex(input.transcript_state_blake2s, .lower);
    const executable_hex = std.fmt.bytesToHex(input.executable_sha256, .lower);
    return std.json.Stringify.valueAlloc(allocator, .{
        .schema = "stwo_ethereum_leaf_verify_v1",
        .status = "verified",
        .artifact_kind = "stwo_riscv_ethereum_leaf_proof",
        .artifact_schema_version = support.proof_artifact.format_version,
        .artifact_magic = "STWGPF01",
        .security_policy = "functional-test-pow0-q3",
        .statement_sha256 = &statement_hex,
        .commitment_roots_sha256 = &roots_hex,
        .artifact_bytes = input.artifact_bytes,
        .artifact_sha256 = &artifact_hex,
        .transcript_state_blake2s = &transcript_hex,
        .pcs_pow_bits = support.pcs_config.pow_bits,
        .pcs_log_blowup_factor = support.pcs_config.fri_config.log_blowup_factor,
        .pcs_n_queries = support.pcs_config.fri_config.n_queries,
        .pcs_fold_step = support.pcs_config.fri_config.fold_step,
        .verifier_runtime = @tagName(builtin.mode),
        .verifier_executable_sha256 = &executable_hex,
        .final_aggregate = false,
    }, .{});
}

fn statementDigest(encoded: []const u8) [32]u8 {
    const statement_length = readHeaderU32(
        encoded,
        support.proof_artifact.HeaderOffset.statement_length,
    );
    const extension_length = readHeaderU32(
        encoded,
        support.proof_artifact.HeaderOffset.extension_length,
    );
    const end = support.proof_artifact.header_size +
        @as(usize, statement_length) + @as(usize, extension_length);
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(
        encoded[support.proof_artifact.header_size..end],
        &result,
        .{},
    );
    return result;
}

fn rootsDigest(proof: *const frontend.prover_mod.Proof) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-leaf.commitment-roots.v1\x00");
    for (proof.commitment_scheme_proof.commitments.items) |root|
        hash.update(std.mem.asBytes(&root));
    return hash.finalResult();
}

fn readHeaderU32(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

test "Ethereum verifier receipt is canonical JSON without an embedded newline" {
    const zero = [_]u8{0} ** 32;
    const receipt = try encodeReceipt(std.testing.allocator, .{
        .artifact_bytes = 80,
        .artifact_sha256 = zero,
        .statement_sha256 = zero,
        .roots_sha256 = zero,
        .transcript_state_blake2s = zero,
        .executable_sha256 = zero,
    });
    defer std.testing.allocator.free(receipt);
    try std.testing.expect(std.mem.indexOfScalar(u8, receipt, '\n') == null);
}
