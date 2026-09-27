//! One block-v5 universal challenge prefix. Every native, ROM, sorted-memory,
//! range, hash, and precompile relation must draw the frozen 47 challenges
//! from this exact SourceSeal digest before family-specific transcript work.
const core = @import("stwo_core");

pub const VERSION: u32 = 1;
pub const TAG: u32 = 0x42355353; // B5SS

pub fn init(source_seal_digest: [32]u8) core.proof_suites.Blake3.Channel {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ TAG, VERSION });
    channel.mixRoot(source_seal_digest);
    return channel;
}
