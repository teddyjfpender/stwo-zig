//! One byte encoding owner for native hashing and recursive message witnesses.
//! This changes no bytes of stwo.blake3.experimental.v1.
const std = @import("std");
const primitive = @import("../vcs/blake3_hash.zig");
const M31 = @import("../fields/m31.zig").M31;
const QM31 = @import("../fields/qm31.zig").QM31;
pub const Digest = primitive.Blake3Hash;
pub const PROTOCOL_ID = "stwo.blake3.experimental.v1";
pub const Domain = enum(u8) { init = 0, words = 1, felts = 2, integer = 3, root = 4, draw = 5, pow = 6, leaf = 7, node = 8 };
pub const DigestRole = enum { state, root, left, right };
pub const PayloadRole = enum { words, felts, leaf, integer, nonce, draw_index };
fn writeWord(sink: anytype, role: PayloadRole, index: usize, value: u32) void {
    if (@hasDecl(@TypeOf(sink.*), "protocolWord")) sink.protocolWord(role, index, value) else writeInt(sink, u32, value);
}
fn writeU64(sink: anytype, role: PayloadRole, value: u64) void {
    writeWord(sink, role, 0, @truncate(value));
    writeWord(sink, role, 1, @truncate(value >> 32));
}
fn writeDigest(sink: anytype, role: DigestRole, value: Digest) void {
    if (@hasDecl(@TypeOf(sink.*), "protocolDigest")) sink.protocolDigest(role, value) else sink.update(&value);
}
pub fn writeInt(sink: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    sink.update(&bytes);
}
pub fn writePrefix(sink: anytype, domain: Domain) void {
    sink.update(PROTOCOL_ID);
    sink.update(&.{@intFromEnum(domain)});
}
pub fn start(domain: Domain) primitive.Blake3Hasher {
    var h = primitive.Blake3Hasher.init();
    writePrefix(&h, domain);
    return h;
}
pub fn writeLeaf(sink: anytype, values: []const M31) void {
    if (@hasDecl(@TypeOf(sink.*), "protocolWord")) {
        for (values, 0..) |value, i| writeWord(sink, .leaf, i, value.toU32());
    } else if (@import("builtin").cpu.arch.endian() == .little) {
        // Canonical M31 storage is one u32. Witness sinks retain word roles;
        // byte sinks can absorb exactly the same encoding in one update.
        comptime std.debug.assert(@sizeOf(M31) == 4);
        sink.update(std.mem.sliceAsBytes(values));
    } else {
        var bytes: [256]u8 = undefined;
        var at: usize = 0;
        while (at < values.len) {
            const count = @min(bytes.len / 4, values.len - at);
            for (values[at..][0..count], 0..) |value, i|
                std.mem.writeInt(u32, bytes[4 * i ..][0..4], value.toU32(), .little);
            sink.update(bytes[0 .. count * 4]);
            at += count;
        }
    }
}
pub fn writePowPrefix(sink: anytype, state: Digest, bits: u32) void {
    writePrefix(sink, .pow);
    writeDigest(sink, .state, state);
    writeInt(sink, u32, bits);
}
pub const Frame = union(Domain) {
    init: void,
    words: struct { state: Digest, values: []const u32 },
    felts: struct { state: Digest, values: []const QM31 },
    integer: struct { state: Digest, value: u64 },
    root: struct { state: Digest, value: Digest },
    draw: struct { state: Digest, index: u64 },
    pow: struct { state: Digest, bits: u32, nonce: u64 },
    leaf: []const M31,
    node: struct { left: Digest, right: Digest },

    pub fn write(self: Frame, sink: anytype) void {
        if (self == .pow) {
            writePowPrefix(sink, self.pow.state, self.pow.bits);
            writeU64(sink, .nonce, self.pow.nonce);
            return;
        }
        writePrefix(sink, std.meta.activeTag(self));
        switch (self) {
            .init => {},
            .words => |v| {
                writeDigest(sink, .state, v.state);
                writeInt(sink, u64, @intCast(v.values.len));
                if (!@hasDecl(@TypeOf(sink.*), "protocolWord") and @import("builtin").cpu.arch.endian() == .little) {
                    sink.update(std.mem.sliceAsBytes(v.values));
                } else {
                    for (v.values, 0..) |word, i| writeWord(sink, .words, i, word);
                }
            },
            .felts => |v| {
                writeDigest(sink, .state, v.state);
                writeInt(sink, u64, @intCast(v.values.len));
                for (v.values, 0..) |felt, i| for (felt.toM31Array(), 0..) |word, j| writeWord(sink, .felts, 4 * i + j, word.toU32());
            },
            .integer => |v| {
                writeDigest(sink, .state, v.state);
                writeU64(sink, .integer, v.value);
            },
            .root => |v| {
                writeDigest(sink, .state, v.state);
                writeDigest(sink, .root, v.value);
            },
            .draw => |v| {
                writeDigest(sink, .state, v.state);
                writeU64(sink, .draw_index, v.index);
            },
            .pow => unreachable,
            .leaf => |v| writeLeaf(sink, v),
            .node => |v| {
                writeDigest(sink, .left, v.left);
                writeDigest(sink, .right, v.right);
            },
        }
    }
    pub fn hash(self: Frame) Digest {
        // Fixed frames fit in two compression blocks. Encode through the same
        // authority once, avoiding a streaming update for every small field.
        switch (self) {
            .init, .integer, .root, .draw, .pow, .node => {
                var bytes: [PROTOCOL_ID.len + 1 + 64]u8 = undefined;
                var sink = Buffer{ .bytes = &bytes };
                self.write(&sink);
                return primitive.Blake3Hasher.hash(bytes[0..sink.offset]);
            },
            else => {},
        }
        var h = primitive.Blake3Hasher.init();
        self.write(&h);
        return h.finalize();
    }
    pub fn encodedSize(self: Frame) !usize {
        const payload = switch (self) {
            .init => @as(usize, 0),
            .words => |v| try std.math.add(usize, 40, try std.math.mul(usize, 4, v.values.len)),
            .felts => |v| try std.math.add(usize, 40, try std.math.mul(usize, 16, v.values.len)),
            .integer, .draw => 40,
            .root, .node => 64,
            .pow => 44,
            .leaf => |v| try std.math.mul(usize, 4, v.len),
        };
        return std.math.add(usize, PROTOCOL_ID.len + 1, payload);
    }
    pub fn encode(self: Frame, allocator: std.mem.Allocator) ![]u8 {
        const result = try allocator.alloc(u8, try self.encodedSize());
        var sink = Buffer{ .bytes = result };
        self.write(&sink);
        std.debug.assert(sink.offset == result.len);
        return result;
    }
};
const Buffer = struct {
    bytes: []u8,
    offset: usize = 0,
    pub fn update(self: *Buffer, values: []const u8) void {
        @memcpy(self.bytes[self.offset..][0..values.len], values);
        self.offset += values.len;
    }
};
