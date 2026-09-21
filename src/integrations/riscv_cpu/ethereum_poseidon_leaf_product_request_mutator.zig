//! Test-only resealer that swaps an honest request to another admitted source.

const std = @import("std");
const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const product = @import("ethereum_poseidon_leaf_product_contract.zig");
const product_support = @import("ethereum_poseidon_leaf_product_support.zig");
const statement_plan = @import("recursive_temporal_statement_plan_v1.zig");
const support = @import("ethereum_block_leaf_support.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const arguments = try std.process.argsAlloc(allocator);
    if (arguments.len != 4) return error.InvalidArguments;
    const honest_path = try artifact_io.resolveAbsolute(allocator, arguments[1]);
    const replacement_path = try artifact_io.resolveAbsolute(
        allocator,
        arguments[2],
    );
    const output_path = try artifact_io.resolveAbsolute(allocator, arguments[3]);
    const honest_bytes = try artifact_io.readFileBounded(
        allocator,
        honest_path,
        contract.max_json_bytes,
    );
    var honest = try product.parseRequest(allocator, honest_bytes);
    defer honest.deinit();
    const replacement_bytes = try artifact_io.readFileBounded(
        allocator,
        replacement_path,
        support.source_wire.encoded_size,
    );
    const replacement = try support.source_wire.decode(replacement_bytes);
    const replacement_sha = product_support.digestHex(
        support.sha256(replacement_bytes),
    );
    const source_statement = product_support.digestHex(
        try replacement.statementSha256(),
    );
    const recursive_statement = product_support.digestHex(
        statement_plan.statementSha256(
            &replacement.metadata.base_statement_words,
        ),
    );
    const encoded = try product.encodeRequest(allocator, .{
        .expected_recursive_statement_sha256 = &recursive_statement,
        .expected_source_public_statement_sha256 = &source_statement,
        .producer_sha256 = honest.value.producer_sha256,
        .segment_index = replacement.metadata.segment_index,
        .session_id = honest.value.session_id,
        .source_request = honest.value.source_request,
        .source_segment = .{
            .bytes = replacement_bytes.len,
            .path = replacement_path,
            .sha256 = &replacement_sha,
        },
        .verifier_sha256 = honest.value.verifier_sha256,
    });
    try artifact_io.publishCreateOnlyDurable(output_path, encoded);
}
