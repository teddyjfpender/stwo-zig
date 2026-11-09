//! Allocation-free Blake2s-256 primitives for the isolated aggregation
//! reference. These domains are research artifact identities, not an activated
//! recursive-proof protocol.

const std = @import("std");

pub const Digest = [32]u8;

pub const Blake2s256 = blk: {
    if (@hasDecl(std.crypto.hash, "Blake2s256")) {
        break :blk std.crypto.hash.Blake2s256;
    }
    if (@hasDecl(std.crypto.hash, "blake2") and
        @hasDecl(std.crypto.hash.blake2, "Blake2s256"))
    {
        break :blk std.crypto.hash.blake2.Blake2s256;
    }
    @compileError("Blake2s256 not found in std.crypto.hash");
};

pub const SESSION_DOMAIN = "stwo-zig/aggregation/session/v1\x00";
pub const CHALLENGE_DOMAIN =
    "stwo-zig/aggregation/shared-relations/v1\x00";
pub const EMPTY_CALLS_DOMAIN =
    "stwo-zig/aggregation/empty-calls/v1\x00";
pub const REQUEST_LEAF_DOMAIN =
    "stwo-zig/aggregation/request-leaf/v1\x00";
pub const REQUEST_NODE_DOMAIN =
    "stwo-zig/aggregation/request-node/v1\x00";
pub const CALL_LEAF_DOMAIN =
    "stwo-zig/aggregation/call-leaf/v1\x00";
pub const CALL_NODE_DOMAIN =
    "stwo-zig/aggregation/call-node/v1\x00";
pub const STATEMENT_LEAF_DOMAIN =
    "stwo-zig/aggregation/statement-leaf/v1\x00";
pub const STATEMENT_NODE_DOMAIN =
    "stwo-zig/aggregation/statement-node/v1\x00";
pub const ARTIFACT_LEAF_DOMAIN =
    "stwo-zig/aggregation/artifact-leaf/v1\x00";
pub const ARTIFACT_NODE_DOMAIN =
    "stwo-zig/aggregation/artifact-node/v1\x00";
pub const DESCRIPTOR_DOMAIN =
    "stwo-zig/aggregation/descriptor/v1\x00";
pub const LEAF_SUMMARY_DOMAIN =
    "stwo-zig/aggregation/leaf-summary/v1\x00";
pub const NODE_SUMMARY_DOMAIN =
    "stwo-zig/aggregation/node-summary/v1\x00";

pub const HashSink = struct {
    hasher: Blake2s256,

    pub fn init(domain: []const u8) HashSink {
        var hasher = Blake2s256.init(.{});
        hasher.update(domain);
        return .{ .hasher = hasher };
    }

    pub fn writeAll(self: *HashSink, bytes: []const u8) !void {
        self.hasher.update(bytes);
    }

    pub fn finalize(self: *HashSink) Digest {
        var digest: Digest = undefined;
        self.hasher.final(&digest);
        return digest;
    }
};

pub const SliceSink = struct {
    destination: []u8,
    offset: usize = 0,

    pub fn writeAll(self: *SliceSink, bytes: []const u8) !void {
        const end = std.math.add(usize, self.offset, bytes.len) catch
            return error.BufferTooSmall;
        if (end > self.destination.len) return error.BufferTooSmall;
        @memcpy(self.destination[self.offset..end], bytes);
        self.offset = end;
    }
};

pub fn hashDomain(domain: []const u8, payload: []const u8) Digest {
    var sink = HashSink.init(domain);
    sink.writeAll(payload) catch unreachable;
    return sink.finalize();
}

pub fn hashPair(
    domain: []const u8,
    left: Digest,
    right: Digest,
) Digest {
    var sink = HashSink.init(domain);
    sink.writeAll(&left) catch unreachable;
    sink.writeAll(&right) catch unreachable;
    return sink.finalize();
}

pub fn emptyCallCommitment() Digest {
    return hashDomain(EMPTY_CALLS_DOMAIN, &.{});
}

pub fn isZero(digest: Digest) bool {
    var combined: u8 = 0;
    for (digest) |byte| combined |= byte;
    return combined == 0;
}

pub fn eql(lhs: Digest, rhs: Digest) bool {
    return std.mem.eql(u8, &lhs, &rhs);
}

pub fn lessThan(lhs: Digest, rhs: Digest) bool {
    return std.mem.order(u8, &lhs, &rhs) == .lt;
}

pub fn writeU16(sink: anytype, value: u16) !void {
    var bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &bytes, value, .little);
    try sink.writeAll(&bytes);
}

pub fn writeU32(sink: anytype, value: u32) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    try sink.writeAll(&bytes);
}

pub fn writeU64(sink: anytype, value: u64) !void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    try sink.writeAll(&bytes);
}
