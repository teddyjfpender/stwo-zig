//! Final root-chain acceptance. Collection descriptors only frame the expected
//! job count; the canonical receiver derives genesis and checks every physical
//! proof, adjacency, service span and optional terminal certificate afresh.
const std = @import("std");
const Request = @import("rv64_ethereum_request.zig");
const Expected = @import("rv64_ethereum_worker_expected.zig");
const Receiver = @import("rv64_ethereum_verify_chain.zig");
const Receipt = @import("rv64_ethereum_batch_receipt.zig");
const Packet = @import("rv64_prepared_work_packet.zig");
const Collection = @import("rv64_ethereum_native_prepare.zig").Summary;
pub fn run(a: std.mem.Allocator, config: Request.Config) !Receiver.Result {
    try Request.validateBudget(config);
    var expected = try Expected.Owner.init(a, config);
    defer expected.deinit();
    var directory = try std.fs.cwd().openDir(config.output_directory, .{});
    defer directory.close();
    const bytes = try directory.readFileAlloc(a, "collection.json", 16384);
    defer a.free(bytes);
    const descriptor = try std.json.parseFromSlice(Collection, a, bytes, .{});
    defer descriptor.deinit();
    if (!std.mem.eql(u8, descriptor.value.schema, "rv64-native-work-collection-v1") or !std.meta.eql(descriptor.value.identity, try Packet.identityFor(config, &expected.authority, &expected.policy)) or descriptor.value.global_chain_accepted or descriptor.value.recursive_aggregation) return error.InvalidEthereumCollection;
    // This is the only path that can upgrade open fragments to a chain. A
    // missing/out-of-order/forked fragment or forged completed flag rejects.
    const result = try Receiver.verifyExpectedCount(a, expected.context(), config, descriptor.value.collected_batches, descriptor.value.completed);
    if (result.instructions != descriptor.value.instructions) return error.InvalidEthereumCollection;
    const summary = try std.json.Stringify.valueAlloc(a, .{
        .schema = "rv64-ethereum-authenticated-execution-v1",
        .completed = result.full_block_proof_verified,
        .full_block_proof_verified = result.full_block_proof_verified,
        .verified_batches = result.batches,
        .instructions = result.instructions,
        .calls = result.calls,
        .final_root = result.final_root,
        .final_pc = result.final_pc,
        .recursive_aggregation = false,
        .root_chain_fragments = true,
    }, .{ .whitespace = .indent_2 });
    defer a.free(summary);
    try Receipt.writeExclusive(directory, "summary.json", summary);
    try std.posix.fsync(directory.fd);
    return result;
}
