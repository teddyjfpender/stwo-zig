//! Proof-format boundary selected by a trusted verifier profile, before a
//! proof decoder can allocate or interpret proof-controlled lengths.
//!
//! CAS05 has a distinct byte format and verifier, but has no production PCS
//! dispatcher or established native security profile. A CAS05 key therefore
//! fails closed here. Returning `legacy_postcard` only permits the existing
//! structural preflight to run; it does not accept a proof.

const std = @import("std");
const cas05 = @import("paired_sparse_cascade_wire.zig");
const CAS07_RESERVED_MAGIC = "S31CAS07";

pub const Mode = enum {
    legacy_postcard,
    cas05_sparse_v6,
};

pub const Error = error{
    WrongProofFormat,
    UnsupportedProofVersion,
    MalformedProofHeader,
    Cas05NotProduction,
};

pub fn candidate(mode: Mode, bytes: []const u8) Error!Mode {
    const has_cas05_magic = bytes.len >= cas05.MAGIC.len and
        std.mem.eql(u8, bytes[0..cas05.MAGIC.len], cas05.MAGIC);
    const has_cas07_magic = bytes.len >= CAS07_RESERVED_MAGIC.len and
        std.mem.eql(u8, bytes[0..CAS07_RESERVED_MAGIC.len], CAS07_RESERVED_MAGIC);
    switch (mode) {
        .legacy_postcard => {
            // The current trusted legacy profiles cannot start with this
            // reserved prefix. Keep CAS05 bytes out of the unversioned
            // postcard parser even if a future profile resembles its header.
            if (has_cas05_magic or has_cas07_magic) return error.WrongProofFormat;
            return .legacy_postcard;
        },
        .cas05_sparse_v6 => {
            if (!has_cas05_magic) return error.WrongProofFormat;
            // The fixed header is 8-byte magic, 2-byte version, 2-byte
            // reserved field, and 4-byte exact total length.
            if (bytes.len < 16) return error.MalformedProofHeader;
            if (std.mem.readInt(u16, bytes[8..10], .little) != cas05.VERSION)
                return error.UnsupportedProofVersion;
            if (std.mem.readInt(u16, bytes[10..12], .little) != 0 or
                std.mem.readInt(u32, bytes[12..16], .little) != bytes.len or
                bytes.len > cas05.MAX_WIRE_BYTES)
                return error.MalformedProofHeader;
            // A validated header is deliberately insufficient to activate
            // the experimental checker as production PCS.
            return error.Cas05NotProduction;
        },
    }
}

test "trusted mode keeps legacy bytes and CAS05 bytes separate" {
    const legacy = "\x0a\x02\x46\x01\x04\x00";
    try std.testing.expectEqual(Mode.legacy_postcard, try candidate(.legacy_postcard, legacy));
    try std.testing.expectError(error.WrongProofFormat, candidate(.cas05_sparse_v6, legacy));

    var cas05_header = [_]u8{ 'S', '3', '1', 'C', 'A', 'S', '0', '5', 6, 0, 0, 0, 16, 0, 0, 0 };
    try std.testing.expectError(error.WrongProofFormat, candidate(.legacy_postcard, &cas05_header));
    try std.testing.expectError(error.Cas05NotProduction, candidate(.cas05_sparse_v6, &cas05_header));
    cas05_header[8] = 5;
    try std.testing.expectError(error.UnsupportedProofVersion, candidate(.cas05_sparse_v6, &cas05_header));
    cas05_header[8] = 6;
    cas05_header[10] = 1;
    try std.testing.expectError(error.MalformedProofHeader, candidate(.cas05_sparse_v6, &cas05_header));
    cas05_header[10] = 0;
    cas05_header[12] = 17;
    try std.testing.expectError(error.MalformedProofHeader, candidate(.cas05_sparse_v6, &cas05_header));
    try std.testing.expectError(error.MalformedProofHeader, candidate(.cas05_sparse_v6, cas05_header[0..15]));

    const cas07_header = [_]u8{ 'S', '3', '1', 'C', 'A', 'S', '0', '7', 7, 0, 0, 0, 16, 0, 0, 0 };
    try std.testing.expectError(error.WrongProofFormat, candidate(.legacy_postcard, &cas07_header));
    try std.testing.expectError(error.WrongProofFormat, candidate(.cas05_sparse_v6, &cas07_header));
}
