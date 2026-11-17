//! OP Stack public statement: the 43-byte guest output bound by the terminal
//! AIR. Layout (Kona guest `public_output`):
//!
//!   digest[32] || version (= 1) || chain_id (u64 LE) || schema[2]
//!
//! Schema `OP` is a single-block execution result; `OD` is an anchored
//! derivation (transition) result. The digest is the guest's own commitment;
//! this module never recomputes it, it only decodes and binds bytes.
const std = @import("std");

pub const OUTPUT_BYTES = 43;
pub const VERSION: u8 = 1;

pub const Schema = enum {
    /// `OP`: execution of a payload range against an authenticated prior state.
    execution,
    /// `OD`: anchored derivation plus execution of one transition.
    derivation,

    pub fn tag(self: Schema) [2]u8 {
        return switch (self) {
            .execution => "OP".*,
            .derivation => "OD".*,
        };
    }
    pub fn fromTag(bytes: [2]u8) ?Schema {
        if (std.mem.eql(u8, &bytes, "OP")) return .execution;
        if (std.mem.eql(u8, &bytes, "OD")) return .derivation;
        return null;
    }
};

pub const Output = struct {
    digest: [32]u8,
    chain_id: u64,
    schema: Schema,

    pub fn encode(self: Output) [OUTPUT_BYTES]u8 {
        var bytes: [OUTPUT_BYTES]u8 = undefined;
        @memcpy(bytes[0..32], &self.digest);
        bytes[32] = VERSION;
        std.mem.writeInt(u64, bytes[33..41], self.chain_id, .little);
        @memcpy(bytes[41..43], &self.schema.tag());
        return bytes;
    }
};

pub const Error = error{ InvalidOutputVersion, InvalidOutputSchema, InvalidOutputHex };

/// Strict decode: unknown versions and schemas are rejected, never defaulted.
pub fn decode(bytes: *const [OUTPUT_BYTES]u8) Error!Output {
    if (bytes[32] != VERSION) return error.InvalidOutputVersion;
    const schema = Schema.fromTag(bytes[41..43].*) orelse return error.InvalidOutputSchema;
    return .{ .digest = bytes[0..32].*, .chain_id = std.mem.readInt(u64, bytes[33..41], .little), .schema = schema };
}

/// Decode the request's `expected_output` (86 lowercase or uppercase hex
/// characters) into the exact bytes the terminal AIR must bind.
pub fn expectedFromHex(hex: []const u8) Error![OUTPUT_BYTES]u8 {
    if (hex.len != 2 * OUTPUT_BYTES) return error.InvalidOutputHex;
    var bytes: [OUTPUT_BYTES]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch return error.InvalidOutputHex;
    _ = try decode(&bytes);
    return bytes;
}

/// The receiver's acceptance predicate on the proven output: byte equality
/// with the independently pinned expectation, plus a well-formed statement.
pub fn binds(proven: *const [OUTPUT_BYTES]u8, expected: *const [OUTPUT_BYTES]u8) Error!bool {
    _ = try decode(proven);
    return std.mem.eql(u8, proven, expected);
}
