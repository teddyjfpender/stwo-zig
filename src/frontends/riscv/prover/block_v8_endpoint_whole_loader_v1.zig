//! Detached public metadata admission for the endpoint original proof. Source
//! snapshots and ELF are independently pinned receiver policy. Parsing and
//! reconstructing metadata authenticate no original or recursive proof.
const std = @import("std");
const Metadata = @import("block_v8_endpoint_whole_statement_wire_v1.zig");
const Statement = @import("block_v8_endpoint_whole_statement_v1.zig");
const Window = @import("block_v7_real_window_policy_v2.zig");
const Receiver = @import("block_v7_execution_receiver_v1.zig");
pub const External = @import("block_v7_window_union_loader_v1.zig").External;
pub const Limits = struct {
    metadata: Metadata.Limits = .{},
    original: @import("block_v8_endpoint_whole_codec_v1.zig").Limits = .{},
    initial: @import("block_v7_initial_intervals_v1.zig").Limits = .{},
};
pub fn admitMetadata(a: std.mem.Allocator, bytes: []const u8, external: External, limits: Limits) !*Statement.Owned {
    const parsed = try Metadata.Parsed.init(a, bytes, limits.metadata);
    defer parsed.deinit();
    const addresses = parsed.selection();
    var window = if (addresses.len == 0)
        try Window.Owned.derive(a, external.elf, external.incoming, external.outgoing, external.trusted, limits.initial)
    else
        try Window.Owned.deriveForAddresses(a, external.elf, external.incoming, external.outgoing, external.trusted, addresses, limits.initial);
    defer window.deinit();
    const info = window.initial.info;
    const trusted = Receiver.Trusted{ .elf = external.elf, .elf_sha256 = external.trusted.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = external.config, .window = &window, .terminal = .{ .final_cycle = external.trusted.window.cycles, .halt_address = info.halt_flag, .length_address = info.output_len, .data_address = info.output_data, .output_end = info.output_end, .output = @splat(0) } };
    return parsed.decodeTrusted(a, trusted, limits.metadata);
}

/// Complete byte receiver. Both metadata and source proof can originate from
/// untrusted storage; ELF, snapshot hashes and security are external policy.
pub fn verify(a: std.mem.Allocator, proof: []const u8, metadata: []const u8, external: External, limits: Limits) !@import("block_v8_endpoint_whole_ledger_v1.zig").Summary {
    const statement = try admitMetadata(a, metadata, external, limits);
    defer statement.deinit();
    return @import("block_v8_endpoint_whole_codec_v1.zig").verifyBytes(a, proof, statement.trusted, statement.input, limits.original);
}
