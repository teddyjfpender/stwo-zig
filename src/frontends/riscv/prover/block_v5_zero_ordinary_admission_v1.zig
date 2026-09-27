//! Source admission for a real precompile-only segment. This descriptor is
//! neither an execution receipt nor a substitute for fresh family11/13 proofs.
//! An empty native PCS must never be invented or relabeled from a v4 sentinel.
const std = @import("std");
const core = @import("stwo_core");
const shape_mod = @import("../air/statement.zig");
pub const VERSION: u32 = 1;
pub const Calls = struct { sha: u32 = 0, keccak: u32 = 0, signer: u32 = 0 };
pub const Mode = enum { external_only, external_with_native_clock };
pub const SourceAdmission = struct {
    mode: Mode,
    calls: Calls,
    total_external_retirements: u32,
    public_statement_digest: [32]u8,
    /// Complete verification must freshly close the precompile arithmetic,
    /// external transition, endpoint and global program/memory relations.
    requires_family11_and13: bool = true,
};
pub fn admit(shape: *const shape_mod.Blake3ExecutionStatement, calls: Calls, ordinary_event_count: u32, opcode_slots: usize, opcode_wire: []const u8, opcode_range_claims: []const core.fields.qm31.QM31) !SourceAdmission {
    const external = try std.math.add(u32, try std.math.add(u32, calls.sha, calls.keccak), calls.signer);
    if (external == 0 or shape.n_components != 0 or ordinary_event_count != 0 or
        opcode_slots != 0 or opcode_wire.len != 0 or opcode_range_claims.len != 0)
        return error.InvalidZeroOrdinaryV5Source;
    try shape.validateBlake3ExecutionWithExternal(external);
    for (shape.infra_descs[0..shape.n_infra]) |desc|
        if (desc.kind != .clock_update) return error.InvalidZeroOrdinaryV5Source;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42355a4f, VERSION, external, calls.sha, calls.keccak, calls.signer });
    shape.public_data.mixInto(&channel);
    shape.mixShardManifest(&channel);
    return .{ .mode = if (shape.n_infra == 0) .external_only else .external_with_native_clock, .calls = calls, .total_external_retirements = external, .public_statement_digest = channel.digestBytes() };
}
