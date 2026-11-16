//! Append-only diagnostic meanings owned by proof-wire decoding, never error ordinals.
const std = @import("std");
const Entry = @import("stwo_core").error_codes.Entry;
pub const JsonInputError = std.json.ParseError(std.json.Scanner);
pub const ConfigError = @import("stwo_core").fri.FriConfig.Error;
pub const DecodeError = CodecError || JsonInputError || ConfigError;

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
    .{ .tag = "SyntaxError", .code = 0x4101, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "UnexpectedEndOfInput", .code = 0x4102, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "UnexpectedToken", .code = 0x4103, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidNumber", .code = 0x4104, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "Overflow", .code = 0x4105, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidEnumTag", .code = 0x4106, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "DuplicateField", .code = 0x4107, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "UnknownField", .code = 0x4108, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "MissingField", .code = 0x4109, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "LengthMismatch", .code = 0x410a, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidCharacter", .code = 0x410b, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "BufferUnderrun", .code = 0x410c, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "ValueTooLong", .code = 0x410d, .class = .resource_exhausted, .since = "1.0.0-rc.3" },
    .{ .tag = "OutOfMemory", .code = 0x410e, .class = .resource_exhausted, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidLastLayerDegreeBound", .code = 0x4201, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidBlowupFactor", .code = 0x4202, .class = .invalid_input, .since = "1.0.0-rc.3" },
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

pub fn fromJsonInput(err: JsonInputError) Entry {
    return switch (err) {
        error.SyntaxError => table[5],
        error.UnexpectedEndOfInput => table[6],
        error.UnexpectedToken => table[7],
        error.InvalidNumber => table[8],
        error.Overflow => table[9],
        error.InvalidEnumTag => table[10],
        error.DuplicateField => table[11],
        error.UnknownField => table[12],
        error.MissingField => table[13],
        error.LengthMismatch => table[14],
        error.InvalidCharacter => table[15],
        error.BufferUnderrun => table[16],
        error.ValueTooLong => table[17],
        error.OutOfMemory => table[18],
    };
}
pub fn fromConfig(err: ConfigError) Entry {
    return switch (err) {
        error.InvalidLastLayerDegreeBound => table[19],
        error.InvalidBlowupFactor => table[20],
    };
}
/// Complete owned byte-buffer decode union, never generic reader callbacks.
pub fn fromDecode(err: DecodeError) Entry {
    return switch (err) {
        error.NonCanonicalM31 => fromCodec(error.NonCanonicalM31),
        error.ValueOutOfRange => fromCodec(error.ValueOutOfRange),
        error.InvalidBinaryProof => fromCodec(error.InvalidBinaryProof),
        error.UnsupportedBinaryVersion => fromCodec(error.UnsupportedBinaryVersion),
        error.NonCanonicalPoseidonDigest => fromCodec(error.NonCanonicalPoseidonDigest),
        error.InvalidLastLayerDegreeBound => fromConfig(error.InvalidLastLayerDegreeBound),
        error.InvalidBlowupFactor => fromConfig(error.InvalidBlowupFactor),
        error.SyntaxError => fromJsonInput(error.SyntaxError),
        error.UnexpectedEndOfInput => fromJsonInput(error.UnexpectedEndOfInput),
        error.UnexpectedToken => fromJsonInput(error.UnexpectedToken),
        error.InvalidNumber => fromJsonInput(error.InvalidNumber),
        error.Overflow => fromJsonInput(error.Overflow),
        error.InvalidEnumTag => fromJsonInput(error.InvalidEnumTag),
        error.DuplicateField => fromJsonInput(error.DuplicateField),
        error.UnknownField => fromJsonInput(error.UnknownField),
        error.MissingField => fromJsonInput(error.MissingField),
        error.LengthMismatch => fromJsonInput(error.LengthMismatch),
        error.InvalidCharacter => fromJsonInput(error.InvalidCharacter),
        error.BufferUnderrun => fromJsonInput(error.BufferUnderrun),
        error.ValueTooLong => fromJsonInput(error.ValueTooLong),
        error.OutOfMemory => fromJsonInput(error.OutOfMemory),
    };
}

pub fn lookup(code: u16) ?Entry {
    for (table) |entry| if (entry.code == code) return entry;
    return null;
}
