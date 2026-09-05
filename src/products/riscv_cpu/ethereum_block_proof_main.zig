//! Dedicated create-only Ethereum block proof producer/verifier multiplexer.

const std = @import("std");
const integration = @import("stwo_riscv_cpu_integration");

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    if (arguments.len < 2) return error.MissingSubcommand;
    const command = arguments[1];
    const options = arguments[2..];
    if (std.mem.eql(u8, command, "ethereum-block-leaf-materialize")) {
        try integration.ethereum_block_leaf_materializer.run(
            allocator,
            options,
        );
    } else if (std.mem.eql(
        u8,
        command,
        integration.ethereum_incremental_capture_materializer_v3.command_name,
    )) {
        try integration.ethereum_incremental_capture_materializer_v3.run(
            allocator,
            options,
        );
    } else if (std.mem.eql(
        u8,
        command,
        integration.ethereum_incremental_capture_materializer_v4.command_name,
    )) {
        try integration.ethereum_incremental_capture_materializer_v4.run(
            allocator,
            options,
        );
    } else if (std.mem.eql(
        u8,
        command,
        integration.ethereum_incremental_capture_postprocess_command_v4.command_name,
    )) {
        try integration.ethereum_incremental_capture_postprocess_command_v4.run(
            allocator,
            options,
        );
    } else if (std.mem.eql(
        u8,
        command,
        integration.ethereum_incremental_full_leaf_replay_command_v4.command_name,
    )) {
        try integration.ethereum_incremental_full_leaf_replay_command_v4.run(
            allocator,
            options,
        );
    } else if (std.mem.eql(
        u8,
        command,
        "ethereum-block-compact-replay",
    )) {
        try integration.ethereum_block_compact_replay.run(
            allocator,
            options,
        );
    } else if (std.mem.eql(u8, command, "ethereum-block-leaf-producer")) {
        try integration.ethereum_block_leaf_producer.run(allocator, options);
    } else if (std.mem.eql(u8, command, "ethereum-leaf-verifier")) {
        try integration.ethereum_block_leaf_verifier.run(allocator, options);
    } else if (std.mem.eql(
        u8,
        command,
        "ethereum-poseidon-v4-leaf-geometry",
    )) {
        try integration.ethereum_poseidon_leaf_geometry_command.run(
            allocator,
            options,
        );
    } else if (std.mem.eql(
        u8,
        command,
        integration.ethereum_poseidon_provider_combined_v1.command_name,
    )) {
        try integration.ethereum_poseidon_provider_combined_v1.run(
            allocator,
            options,
        );
    } else if (std.mem.eql(
        u8,
        command,
        integration.bulk_memcpy_retained_microproof_command_v1.command_name,
    )) {
        try integration.bulk_memcpy_retained_microproof_command_v1.run(
            allocator,
            options,
        );
    } else if (std.mem.eql(
        u8,
        command,
        integration.ethereum_candidate_combined_execution_capture_command_v1.command_name,
    )) {
        try integration.ethereum_candidate_combined_execution_capture_command_v1.run(
            allocator,
            options,
        );
    } else if (std.mem.eql(
        u8,
        command,
        integration.ethereum_candidate_combined_execution_replay_command_v1.command_name,
    )) {
        try integration.ethereum_candidate_combined_execution_replay_command_v1.run(
            allocator,
            options,
        );
    } else if (std.mem.eql(
        u8,
        command,
        integration.ethereum_poseidon_leaf_matched_ab_baseline_command_v1.command_name,
    )) {
        try integration.ethereum_poseidon_leaf_matched_ab_baseline_command_v1.run(
            allocator,
            options,
        );
    } else if (std.mem.eql(
        u8,
        command,
        integration.ethereum_matched_ab_rematerialization_command_v1.command_name,
    )) {
        try integration.ethereum_matched_ab_rematerialization_command_v1.run(
            allocator,
            options,
        );
    } else if (std.mem.eql(
        u8,
        command,
        integration.ethereum_matched_ab_geometry_audit_v1.command_name,
    )) {
        try integration.ethereum_matched_ab_geometry_audit_v1.run(
            allocator,
            options,
        );
    } else if (std.mem.eql(
        u8,
        command,
        "ethereum-poseidon-v4-leaf-producer",
    )) {
        try integration.ethereum_poseidon_leaf_product_producer.run(
            allocator,
            options,
        );
    } else if (std.mem.eql(
        u8,
        command,
        "ethereum-poseidon-v4-leaf-request",
    )) {
        try integration.ethereum_poseidon_leaf_product_request.run(
            allocator,
            options,
        );
    } else if (std.mem.eql(
        u8,
        command,
        "ethereum-poseidon-v4-leaf-verifier",
    )) {
        try integration.ethereum_poseidon_leaf_product_verifier.run(
            allocator,
            options,
        );
    } else {
        return error.UnsupportedSubcommand;
    }
}
