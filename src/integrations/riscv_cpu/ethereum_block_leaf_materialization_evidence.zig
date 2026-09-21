//! Canonical terminal evidence for Ethereum segment-source materialization.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");

pub const NativeDigest = [8]u32;
pub const machine_state_sha256_domain =
    "stwo.ethereum.block-proof-machine-state-m31/v1\x00";
pub const job_sha256_domain =
    "stwo.ethereum.block-proof-job-context-m31/v1\x00";

pub const JobAuthority = struct {
    final_state_sha256: [32]u8,
    initial_state_sha256: [32]u8,
    job_sha256: [32]u8,
    program: NativeDigest,
    public_input: NativeDigest,
    public_output: NativeDigest,
};

pub const LeafSource = struct {
    authority: evidence.FileIdentity,
    metadata_id: NativeDigest,
    segment_index: u32,
    statement_id: NativeDigest,
    statement_sha256: [32]u8,
};

pub const ManifestInput = struct {
    execution_journal: evidence.FileIdentity,
    expected_output: evidence.FileIdentity,
    input: evidence.FileIdentity,
    job: JobAuthority,
    leaf_sources: []const LeafSource,
    pcs: contract.PcsAuthority,
    source_schema: []const u8,
    source_request: evidence.FileIdentity,
    total_cycles: u64,
};

pub fn encodeSourceRequest(
    allocator: std.mem.Allocator,
    value: contract.SourceRequest,
) ![]u8 {
    try value.validate();
    const payload = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(payload);
    const result = try std.mem.concat(allocator, u8, &.{ payload, "\n" });
    errdefer allocator.free(result);
    var parsed = try contract.parseSource(allocator, result);
    parsed.deinit();
    return result;
}

pub fn encodeRecursiveSourceRequest(
    allocator: std.mem.Allocator,
    value: contract.RecursiveSourceRequestV2,
) ![]u8 {
    try value.validate();
    const payload = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(payload);
    const result = try std.mem.concat(allocator, u8, &.{ payload, "\n" });
    errdefer allocator.free(result);
    var parsed = try contract.parseRecursiveSource(allocator, result);
    parsed.deinit();
    return result;
}

pub fn encodeManifest(
    allocator: std.mem.Allocator,
    input: ManifestInput,
) ![]u8 {
    if (input.leaf_sources.len < 2 or
        input.leaf_sources.len > std.math.maxInt(u32))
    {
        return error.InvalidLeafCount;
    }
    const manifest_schema = if (std.mem.eql(
        u8,
        input.source_schema,
        contract.source_schema,
    )) contract.materialization_result_schema else if (std.mem.eql(
        u8,
        input.source_schema,
        contract.recursive_source_schema,
    )) contract.recursive_materialization_result_schema else return error.UnsupportedSourceSchema;
    var leaves: std.ArrayList(u8) = .empty;
    defer leaves.deinit(allocator);
    const leaf_writer = leaves.writer(allocator);
    try leaf_writer.writeByte('[');
    for (input.leaf_sources, 0..) |leaf, index| {
        if (leaf.segment_index != index) return error.LeafOrderMismatch;
        if (index != 0) try leaf_writer.writeByte(',');
        const authority_sha = hex(leaf.authority.sha256);
        const metadata = nativeHex(leaf.metadata_id);
        const statement_id = nativeHex(leaf.statement_id);
        const statement = hex(leaf.statement_sha256);
        try leaf_writer.print(
            "{{\"authority\":{{\"bytes\":{d},\"path\":\"{s}\",\"sha256\":\"{s}\"}},\"metadata_id_m31_le\":\"{s}\",\"segment_index\":{d},\"statement_id_m31_le\":\"{s}\",\"statement_sha256\":\"{s}\"}}",
            .{
                leaf.authority.bytes,
                leaf.authority.path,
                &authority_sha,
                &metadata,
                leaf.segment_index,
                &statement_id,
                &statement,
            },
        );
    }
    try leaf_writer.writeByte(']');

    const journal_sha = hex(input.execution_journal.sha256);
    const output_sha = hex(input.expected_output.sha256);
    const input_sha = hex(input.input.sha256);
    const final_state = hex(input.job.final_state_sha256);
    const initial_state = hex(input.job.initial_state_sha256);
    const job_sha = hex(input.job.job_sha256);
    const program = nativeHex(input.job.program);
    const public_input = nativeHex(input.job.public_input);
    const public_output = nativeHex(input.job.public_output);
    const source_sha = hex(input.source_request.sha256);
    var lifting_buffer: [10]u8 = undefined;
    const lifting = if (input.pcs.lifting_log_size) |value|
        try std.fmt.bufPrint(&lifting_buffer, "{d}", .{value})
    else
        "null";
    var unsigned: std.ArrayList(u8) = .empty;
    defer unsigned.deinit(allocator);
    const writer = unsigned.writer(allocator);
    try writer.print(
        "{{\"execution_journal\":{{\"bytes\":{d},\"path\":\"{s}\",\"sha256\":\"{s}\"}},\"execution_profile\":\"{s}\",\"expected_output\":{{\"bytes\":{d},\"path\":\"{s}\",\"sha256\":\"{s}\"}},\"input\":{{\"bytes\":{d},\"path\":\"{s}\",\"sha256\":\"{s}\"}},\"job\":{{\"final_state_sha256\":\"{s}\",\"initial_state_sha256\":\"{s}\",\"job_sha256\":\"{s}\",\"program_m31_le\":\"{s}\",\"public_input_m31_le\":\"{s}\",\"public_output_m31_le\":\"{s}\"}},\"leaf_sources\":{s},",
        .{
            input.execution_journal.bytes,
            input.execution_journal.path,
            &journal_sha,
            contract.profile_name,
            input.expected_output.bytes,
            input.expected_output.path,
            &output_sha,
            input.input.bytes,
            input.input.path,
            &input_sha,
            &final_state,
            &initial_state,
            &job_sha,
            &program,
            &public_input,
            &public_output,
            leaves.items,
        },
    );
    try writer.print(
        "\"pcs\":{{\"commitment_hash\":\"{s}\",\"field\":\"{s}\",\"fold_step\":{d},\"lifting_log_size\":{s},\"log_blowup_factor\":{d},\"log_last_layer_degree_bound\":{d},\"n_queries\":{d},\"pow_bits\":{d},\"transcript_hash\":\"{s}\"}},\"schema\":\"{s}\",\"segment_authority_magic\":\"{s}\",\"segment_authority_version\":1,\"segment_count\":{d},\"source_request\":{{\"bytes\":{d},\"path\":\"{s}\",\"schema\":\"{s}\",\"sha256\":\"{s}\"}},\"status\":\"materialized\",\"total_cycles\":{d}}}",
        .{
            input.pcs.commitment_hash,
            input.pcs.field,
            input.pcs.fold_step,
            lifting,
            input.pcs.log_blowup_factor,
            input.pcs.log_last_layer_degree_bound,
            input.pcs.n_queries,
            input.pcs.pow_bits,
            input.pcs.transcript_hash,
            manifest_schema,
            contract.segment_magic,
            input.leaf_sources.len,
            input.source_request.bytes,
            input.source_request.path,
            input.source_schema,
            &source_sha,
            input.total_cycles,
        },
    );
    const result = try evidence.seal(allocator, unsigned.items);
    errdefer allocator.free(result);
    var parsed = try contract.parseMaterializationResult(allocator, result);
    parsed.deinit();
    return result;
}

pub fn nativeHex(value: NativeDigest) [64]u8 {
    var bytes: [32]u8 = undefined;
    for (value, 0..) |word, index|
        std.mem.writeInt(u32, bytes[4 * index ..][0..4], word, .little);
    return std.fmt.bytesToHex(bytes, .lower);
}

/// SHA-256 authority over an exact ordered M31 word slice. The count and each
/// canonical word are little-endian, so replay never depends on host layout.
pub fn canonicalM31Sha256(
    domain: []const u8,
    words: []const M31,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(domain);
    var count: [8]u8 = undefined;
    std.mem.writeInt(u64, &count, @intCast(words.len), .little);
    hash.update(&count);
    var encoded: [4]u8 = undefined;
    for (words) |word| {
        std.mem.writeInt(u32, &encoded, word.toU32(), .little);
        hash.update(&encoded);
    }
    return hash.finalResult();
}

fn hex(value: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(value, .lower);
}
