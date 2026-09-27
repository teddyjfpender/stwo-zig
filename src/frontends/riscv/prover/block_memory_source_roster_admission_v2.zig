//! Receiver-side derivation of program/hash source descriptors from trusted
//! Ethereum SHA verifier preparations. This runs before block-v2 challenges.
const std = @import("std");
const core = @import("stwo_core");
const seal_mod = @import("block_memory_source_seal_v2.zig");
const roster = @import("block_memory_source_roster_v2.zig");
const sha = @import("blake3_ethereum_sha_proof.zig");

pub fn EthereumShaPin(comptime Backend: type) type {
    return struct {
        prepared: *sha.ForBackend(Backend).PreparedVerifier,
        expected_key_id: [32]u8,
    };
}

/// `pinned_program_root` comes from the independently admitted public job/ELF,
/// never from the proof. Each prepared verifier validates its own key and
/// hash commitment plan before contributing the per-instance descriptor.
pub fn admitEthereumSha(
    comptime Backend: type,
    a: std.mem.Allocator,
    sealed: seal_mod.SourceSeal,
    entries: []const roster.Entry,
    recomputed_rw_digest: [32]u8,
    pinned_program_root: [32]u8,
    pins: []const EthereumShaPin(Backend),
    config: core.pcs.PcsConfig,
) !void {
    if (pins.len != sealed.execution_instance_count) return error.InvalidPreparedExecutionSourceCensus;
    const hashes = try a.alloc([32]u8, pins.len);
    defer a.free(hashes);
    for (pins, hashes, 0..) |pin, *expected, index| {
        try pin.prepared.validate(pin.expected_key_id);
        if (!std.meta.eql(pin.prepared.config, config)) return error.InvalidPreparedExecutionSecurity;
        const native_program = pin.prepared.native.public_data.program_root orelse
            return error.MissingPreparedProgramRoot;
        if (!std.meta.eql(native_program.bytes, pinned_program_root))
            return error.UntrustedPreparedProgramRoot;
        expected.* = roster.hashDescriptor(@intCast(index), pin.prepared.plan_id, pin.expected_key_id);
    }
    const program = [_][32]u8{roster.programDescriptor(pinned_program_root)};
    try roster.admitExpected(entries, &program, hashes);
    try roster.admit(sealed, entries, recomputed_rw_digest);
}
