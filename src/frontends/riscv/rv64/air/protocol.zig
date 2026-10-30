//! Fixed proof suite and transcript schema. No prover-supplied security knobs.
const core = @import("stwo_core");
const S = @import("statement.zig");
const L = @import("layout.zig");
pub const Hasher = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
pub const MerkleChannel = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
pub const Channel = core.channel.blake2s.Blake2sChannel;
pub const Proof = core.proof.StarkProof(Hasher);
pub fn config() core.pcs.PcsConfig {
    return .{ .pow_bits = 26, .fri_config = core.fri.FriConfig.init(0, 1, 70) catch unreachable };
}
pub fn mix(channel: *Channel, public: S.Statement, metadata: S.Metadata, log_size: u32) !void {
    try metadata.validate(public);
    channel.mixU32s(&.{ 0x52563634, 0x424e4431, if (public.program_addresses.len == 0) 2 else 3, L.fixed.COUNT, L.MAIN, L.INTERACTION, L.MAX_DEGREE, log_size, public.steps });
    config().mixInto(channel);
    channel.mixU64(public.program_base);
    channel.mixU64(public.initial_pc);
    channel.mixU64(public.final_pc);
    channel.mixU64(public.program.len);
    channel.mixU32s(public.program);
    if (public.program_addresses.len != 0) {
        channel.mixU64(public.program_addresses.len);
        for (public.program_addresses) |pc| channel.mixU64(pc);
    }
    for (public.initial_registers) |value| channel.mixU64(value);
    for (public.final_registers) |value| channel.mixU64(value);
    channel.mixU64(public.memory.len);
    for (public.memory) |cell| {
        channel.mixU64(cell.address);
        channel.mixU64(cell.initial);
        channel.mixU64(cell.final);
        channel.mixU32s(&.{ @intFromBool(cell.readable), @intFromBool(cell.writable) });
    }
    for (metadata.path) |pc| channel.mixU64(pc);
    for (metadata.register_clocks) |clock| channel.mixU32s(&.{clock});
    for (metadata.memory_clocks) |clock| channel.mixU32s(&.{clock});
}
