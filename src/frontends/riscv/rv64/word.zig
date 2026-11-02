//! Lossless byte decomposition for future M31 constraints and lookup tuples.
//! This representation alone does not constrain a witness.
const std = @import("std");
pub const Word = struct {
    bytes: [8]u8,

    pub fn fromInt(value: u64) Word {
        var result: Word = undefined;
        std.mem.writeInt(u64, &result.bytes, value, .little);
        return result;
    }

    pub fn toInt(self: Word) u64 {
        return std.mem.readInt(u64, &self.bytes, .little);
    }
};
