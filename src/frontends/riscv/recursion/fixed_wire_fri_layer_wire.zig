//! Internal fixed wire authority shard; use fixed_wire.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const fixed_profile = @import("fixed_profile.zig");
pub const channel = @import("poseidon2_channel.zig");
pub const protocol = @import("protocol.zig");

pub const M31_MODULUS = stwo_core.fields.m31.Modulus;

pub const M31_WORD_BYTES: usize = @sizeOf(u32);
pub const QM31_BYTES: usize = 4 * M31_WORD_BYTES;
pub const DIGEST_BYTES: usize = channel.RATE * M31_WORD_BYTES;
pub const U64_BYTES: usize = @sizeOf(u64);

pub const Qm31Wire = [4]u32;

pub const Error = fixed_profile.Error || error{
    AliasedBuffer,
    ByteLengthMismatch,
    InvalidDimensions,
    NonCanonicalM31,
    NonZeroFriValuePadding,
    NonZeroMerklePadding,
    MerklePathDepthMismatch,
    FriLayerWidthMismatch,
    FriPathDepthMismatch,
    WireByteCountMismatch,
    WireCountMismatch,
};

pub fn MerklePathWire(comptime maximum_depth: usize) type {
    if (maximum_depth == 0 or maximum_depth > fixed_profile.MAX_DOMAIN_LOG)
        @compileError("invalid fixed Merkle-path capacity");
    return struct {
        active_depth: u32,
        siblings: [maximum_depth]channel.Digest,

        const Self = @This();

        pub fn validate(self: *const Self, expected_depth: u32) Error!void {
            if (expected_depth > maximum_depth or self.active_depth != expected_depth)
                return error.MerklePathDepthMismatch;
            for (self.siblings, 0..) |sibling, index| {
                try validateDigest(sibling);
                if (index >= expected_depth and !isZeroDigest(sibling))
                    return error.NonZeroMerklePadding;
            }
        }
    };
}

pub fn FriQueryWire(
    comptime maximum_fold_width: usize,
    comptime maximum_merkle_depth: usize,
) type {
    return struct {
        values: [maximum_fold_width]Qm31Wire,
        path: MerklePathWire(maximum_merkle_depth),

        const Self = @This();

        fn validate(
            self: *const Self,
            active_width: u32,
            expected_path_depth: u32,
        ) Error!void {
            if (active_width == 0 or active_width > maximum_fold_width)
                return error.FriLayerWidthMismatch;
            for (self.values, 0..) |value, index| {
                try validateQm31(value);
                if (index >= active_width and !isZeroQm31(value))
                    return error.NonZeroFriValuePadding;
            }
            self.path.validate(expected_path_depth) catch |err| switch (err) {
                error.MerklePathDepthMismatch => return error.FriPathDepthMismatch,
                else => return err,
            };
        }
    };
}

pub fn FriLayerWire(
    comptime query_count: usize,
    comptime maximum_fold_width: usize,
    comptime maximum_merkle_depth: usize,
) type {
    if (query_count == 0) @compileError("FRI wire requires raw query slots");
    return struct {
        active_width: u32,
        commitment: channel.Digest,
        queries: [query_count]FriQueryWire(
            maximum_fold_width,
            maximum_merkle_depth,
        ),

        const Self = @This();

        pub fn validate(self: *const Self, round: fixed_profile.FriRound) Error!void {
            if (self.active_width != round.fold_width or
                self.active_width > maximum_fold_width)
            {
                return error.FriLayerWidthMismatch;
            }
            try validateDigest(self.commitment);
            for (&self.queries) |*query| {
                try query.validate(
                    self.active_width,
                    round.authentication_path_depth,
                );
            }
        }
    };
}

pub fn preflightPath(
    maximum_depth: usize,
    reader: *ByteReader,
    expected_depth: u32,
    is_fri: bool,
) Error!void {
    const active_depth = reader.readU32();
    if (active_depth != expected_depth or active_depth > maximum_depth) {
        return if (is_fri)
            error.FriPathDepthMismatch
        else
            error.MerklePathDepthMismatch;
    }
    var index: usize = 0;
    while (index < maximum_depth) : (index += 1) {
        const sibling = reader.readDigest();
        try validateDigest(sibling);
        if (index >= expected_depth and !isZeroDigest(sibling))
            return error.NonZeroMerklePadding;
    }
}

pub fn writePath(
    comptime maximum_depth: usize,
    writer: *ByteWriter,
    path: MerklePathWire(maximum_depth),
) void {
    writer.writeU32(path.active_depth);
    for (path.siblings) |sibling| writer.writeDigest(sibling);
}

pub fn readPath(
    comptime maximum_depth: usize,
    reader: *ByteReader,
    path: *MerklePathWire(maximum_depth),
) void {
    path.active_depth = reader.readU32();
    for (&path.siblings) |*sibling| sibling.* = reader.readDigest();
}

pub const ByteWriter = struct {
    bytes: []u8,
    at: usize,

    pub fn init(bytes: []u8) ByteWriter {
        return .{ .bytes = bytes, .at = 0 };
    }

    pub fn writeU32(self: *ByteWriter, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.at..][0..4], value, .little);
        self.at += 4;
    }

    pub fn writeU64(self: *ByteWriter, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.at..][0..8], value, .little);
        self.at += 8;
    }

    pub fn writeQm31(self: *ByteWriter, value: Qm31Wire) void {
        for (value) |word| self.writeU32(word);
    }

    pub fn writeDigest(self: *ByteWriter, value: channel.Digest) void {
        for (value) |word| self.writeU32(word);
    }

    pub fn done(self: ByteWriter) bool {
        return self.at == self.bytes.len;
    }
};

pub const ByteReader = struct {
    bytes: []const u8,
    at: usize,

    pub fn init(bytes: []const u8) ByteReader {
        return .{ .bytes = bytes, .at = 0 };
    }

    pub fn readU32(self: *ByteReader) u32 {
        const value = std.mem.readInt(u32, self.bytes[self.at..][0..4], .little);
        self.at += 4;
        return value;
    }

    pub fn readU64(self: *ByteReader) u64 {
        const value = std.mem.readInt(u64, self.bytes[self.at..][0..8], .little);
        self.at += 8;
        return value;
    }

    pub fn readQm31(self: *ByteReader) Qm31Wire {
        var value: Qm31Wire = undefined;
        for (&value) |*word| word.* = self.readU32();
        return value;
    }

    pub fn readDigest(self: *ByteReader) channel.Digest {
        var value: channel.Digest = undefined;
        for (&value) |*word| word.* = self.readU32();
        return value;
    }

    pub fn done(self: ByteReader) bool {
        return self.at == self.bytes.len;
    }
};

pub fn slicesOverlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch
        return true;
    const right_end = std.math.add(usize, right_start, right.len) catch
        return true;
    return left_start < right_end and right_start < left_end;
}

pub fn merklePathBytes(maximum_depth: usize) Error!usize {
    return checkedAdd(
        M31_WORD_BYTES,
        try checkedMul(maximum_depth, DIGEST_BYTES),
    );
}

pub fn friQueryBytes(
    maximum_fold_width: usize,
    maximum_merkle_depth: usize,
) Error!usize {
    return checkedAdd(
        try checkedMul(maximum_fold_width, QM31_BYTES),
        try merklePathBytes(maximum_merkle_depth),
    );
}

pub fn friLayerBytes(
    query_count: usize,
    maximum_fold_width: usize,
    maximum_merkle_depth: usize,
) Error!usize {
    var bytes = try checkedAdd(M31_WORD_BYTES, DIGEST_BYTES);
    bytes = try checkedAdd(
        bytes,
        try checkedMul(
            query_count,
            try friQueryBytes(maximum_fold_width, maximum_merkle_depth),
        ),
    );
    return bytes;
}

pub fn validateM31(value: u32) Error!void {
    if (value >= M31_MODULUS) return error.NonCanonicalM31;
}

pub fn validateQm31(value: Qm31Wire) Error!void {
    for (value) |word| try validateM31(word);
}

pub fn validateDigest(value: channel.Digest) Error!void {
    for (value) |word| try validateM31(word);
}

pub fn isZeroQm31(value: Qm31Wire) bool {
    var aggregate: u32 = 0;
    for (value) |word| aggregate |= word;
    return aggregate == 0;
}

pub fn isZeroDigest(value: channel.Digest) bool {
    var aggregate: u32 = 0;
    for (value) |word| aggregate |= word;
    return aggregate == 0;
}

pub fn checkedAdd(left: usize, right: usize) Error!usize {
    return std.math.add(usize, left, right) catch error.ArithmeticOverflow;
}

pub fn checkedMul(left: usize, right: usize) Error!usize {
    return std.math.mul(usize, left, right) catch error.ArithmeticOverflow;
}
