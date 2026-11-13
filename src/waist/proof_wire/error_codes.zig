//! Append-only diagnostic meanings owned by proof-wire decoding, never error ordinals.
const Entry = @import("stwo_core").error_codes.Entry;
pub const CodecError = error{
    NonCanonicalM31,
    ValueOutOfRange,
    InvalidBinaryProof,
    UnsupportedBinaryVersion,
    NonCanonicalPoseidonDigest,
};

pub const table = [_]Entry{
    .{ .tag = "NonCanonicalM31", .code = 0x4001, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "ValueOutOfRange", .code = 0x4002, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidBinaryProof", .code = 0x4003, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "UnsupportedBinaryVersion", .code = 0x4004, .class = .unsupported, .since = "1.0.0-rc.2" },
    .{ .tag = "NonCanonicalPoseidonDigest", .code = 0x4005, .class = .invalid_input, .since = "1.0.0-rc.2" },
};

pub fn fromCodec(err: CodecError) Entry {
    return switch (err) {
        error.NonCanonicalM31 => table[0],
        error.ValueOutOfRange => table[1],
        error.InvalidBinaryProof => table[2],
        error.UnsupportedBinaryVersion => table[3],
        error.NonCanonicalPoseidonDigest => table[4],
    };
}

pub fn lookup(code: u16) ?Entry {
    for (table) |entry| if (entry.code == code) return entry;
    return null;
}
