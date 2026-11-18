//! Error projection shared by the circuit wire and the narrow Postcard consumer.
const Entry = @import("stwo_core").error_codes.Entry;

// Structural ABI contract: the actual postcard consumer asserts exact equality
// with its separately owned parser Error set before mapping any rejection.
pub const Error = error{
    EndOfStream,
    InvalidOptionTag,
    InvalidProofConfig,
    InvalidProofShape,
    InvalidPreflightShape,
    NonCanonicalM31,
    NonCanonicalVarint,
    ProofResourceLimitExceeded,
    TrailingProofBytes,
    VarintOverflow,
};

pub const table = [_]Entry{
    .{ .tag = "EndOfStream", .code = 0x5101, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidOptionTag", .code = 0x5102, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidProofConfig", .code = 0x5103, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidProofShape", .code = 0x5104, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidPreflightShape", .code = 0x5105, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "NonCanonicalM31", .code = 0x5106, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "NonCanonicalVarint", .code = 0x5107, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "ProofResourceLimitExceeded", .code = 0x5108, .class = .resource_exhausted, .since = "1.0.0-rc.2" },
    .{ .tag = "TrailingProofBytes", .code = 0x5109, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "VarintOverflow", .code = 0x510a, .class = .invalid_input, .since = "1.0.0-rc.2" },
};

/// Only an exact parser-owned catch may call this typed ABI projection.
pub fn fromPostcard(err: Error) Entry {
    return switch (err) {
        error.EndOfStream => table[0],
        error.InvalidOptionTag => table[1],
        error.InvalidProofConfig => table[2],
        error.InvalidProofShape => table[3],
        error.InvalidPreflightShape => table[4],
        error.NonCanonicalM31 => table[5],
        error.NonCanonicalVarint => table[6],
        error.ProofResourceLimitExceeded => table[7],
        error.TrailingProofBytes => table[8],
        error.VarintOverflow => table[9],
    };
}
