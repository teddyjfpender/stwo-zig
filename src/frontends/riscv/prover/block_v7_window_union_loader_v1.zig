//! Complete original-union receiver from durable artifacts and separately
//! pinned complete endpoints. No producer statement, trace or receipt needed.
const std = @import("std");
const core = @import("stwo_core");
const Capture = @import("block_v7_real_window_capture_v1.zig");
const Window = @import("block_v7_real_window_policy_v2.zig");
const Receiver = @import("block_v7_execution_receiver_v1.zig");
const Metadata = @import("block_v7_multi_union_statement_wire_v1.zig").ForMode(true);
const Codec = @import("block_v7_multi_union_codec_v1.zig").ForMode(true);
pub const External = struct {
    elf: []const u8,
    incoming: Capture.Snapshot,
    outgoing: Capture.Snapshot,
    trusted: Window.Trusted,
    config: core.pcs.PcsConfig,
    boundary: @import("block_v8_execution_boundary_ports_v1.zig").Options = .{},
};
pub const Limits = struct {
    metadata: Metadata.Limits = .{},
    wire: Codec.Limits,
    initial: @import("block_v7_initial_intervals_v1.zig").Limits = .{},
};
pub fn verify(a: std.mem.Allocator, proof: []const u8, metadata: []const u8, external: External, limits: Limits) !Receiver.Verified {
    const detached = try admitMetadata(a, metadata, external, limits);
    defer detached.deinit();
    return Codec.verifyBytes(a, proof, detached.trusted, detached.input, limits.wire);
}
/// Independent owned metadata reconstruction for saved-original recursive
/// production. This authenticates no proof: the caller MUST freshly verify the
/// exact original artifact before deriving any recursive witness from it.
pub fn admitMetadata(a: std.mem.Allocator, metadata: []const u8, external: External, limits: Limits) !*@import("block_v7_multi_union_statement_v1.zig").ForMode(true).Owned {
    const addresses = try Metadata.selectionAddresses(a, metadata, limits.metadata);
    defer a.free(addresses);
    var window = if (addresses.len == 0)
        try Window.Owned.derive(a, external.elf, external.incoming, external.outgoing, external.trusted, limits.initial)
    else
        try Window.Owned.deriveForAddresses(a, external.elf, external.incoming, external.outgoing, external.trusted, addresses, limits.initial);
    defer window.deinit();
    const info = window.initial.info;
    const trusted = Receiver.Trusted{
        .elf = external.elf,
        .elf_sha256 = external.trusted.elf_sha256,
        .profile = .rv32im_zkvm_ethereum_sha_v1,
        .config = external.config,
        .window = &window,
        .terminal = .{ .final_cycle = external.trusted.window.cycles, .halt_address = info.halt_flag, .length_address = info.output_len, .data_address = info.output_data, .output_end = info.output_end, .output = @splat(0) },
    };
    // Metadata.decode clones the external window and ELF into its own owner;
    // no pointer to this stack-local reconstruction escapes.
    return Metadata.decode(a, metadata, trusted, limits.metadata);
}
