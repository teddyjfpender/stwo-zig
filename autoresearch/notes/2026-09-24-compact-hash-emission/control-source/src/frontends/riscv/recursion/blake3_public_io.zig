//! Versioned full-width identities of application-visible I/O. Output access
//! clocks belong to the execution claim, not the application output identity.
const core = @import("stwo_core");
const public = @import("../air/public_data.zig");
pub const Digest = @import("blake3_identity_digest.zig").Digest;
pub const VERSION: u32 = 1;
pub fn input(data: *const public.Blake3PublicData) !Digest {
    try data.validate();
    var channel = core.channel.blake3.Channel{};
    const io = data.io_entries;
    channel.mixU32s(&.{ 0x42334949, VERSION, io.input_start, io.input_len });
    channel.mixU64(io.input_words.len);
    channel.mixU32s(io.input_words);
    return .{ .bytes = channel.digestBytes() };
}
pub fn output(data: *const public.Blake3PublicData) !Digest {
    try data.validate();
    var channel = core.channel.blake3.Channel{};
    const io = data.io_entries;
    channel.mixU32s(&.{ 0x4233494f, VERSION, io.output_len_addr, io.output_data_addr, io.output_len });
    channel.mixU64(io.output_words.len);
    for (io.output_words) |word| channel.mixU32s(&.{ word.addr, word.value });
    return .{ .bytes = channel.digestBytes() };
}
