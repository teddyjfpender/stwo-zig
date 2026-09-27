//! Full-width BLAKE3 byte-memory commitments; distinct from legacy scalar roots.
const std = @import("std");
const Hasher = @import("stwo_core").vcs.blake3_hash.Blake3Hasher;
const topology = @import("byte_tree_topology.zig");
pub const Digest = @import("../../recursion/blake3_identity_digest.zig").Digest;
pub const DEPTH = 30;
pub const ADDRESS_LIMIT: u32 = 1 << DEPTH;
pub const Kind = enum(u32) { memory = 1, program = 2, io = 3 };
pub const Leaf = struct { index: u32, value: u32 };
pub const DOMAIN = "stwo.riscv.blake3.byte-tree.v1";
pub const Frame = union(enum) {
    leaf: struct { kind: Kind, value: u8 },
    node: struct { kind: Kind, left: Digest, right: Digest },
    pub fn write(self: Frame, sink: anytype) void {
        var domain: [32]u8 = @splat(0);
        @memcpy(domain[0..DOMAIN.len], DOMAIN);
        sink.update(&domain);
        var header: [12]u8 = undefined;
        std.mem.writeInt(u32, header[0..4], 1, .little);
        std.mem.writeInt(u32, header[4..8], switch (self) {
            .leaf => 1,
            .node => 2,
        }, .little);
        std.mem.writeInt(u32, header[8..12], @intFromEnum(switch (self) {
            .leaf => |v| v.kind,
            .node => |v| v.kind,
        }), .little);
        sink.update(&header);
        switch (self) {
            .leaf => |v| sink.update(&.{v.value}),
            .node => |v| {
                const Sink = @typeInfo(@TypeOf(sink)).pointer.child;
                if (@hasDecl(Sink, "protocolDigest")) {
                    sink.protocolDigest(.left, v.left.bytes);
                    sink.protocolDigest(.right, v.right.bytes);
                } else {
                    sink.update(&v.left.bytes);
                    sink.update(&v.right.bytes);
                }
            },
        }
    }
    pub fn encodedSize(self: Frame) !usize {
        return switch (self) { .leaf => 45, .node => 108 };
    }
    pub fn encode(self: Frame, a: std.mem.Allocator) ![]u8 {
        const bytes = try a.alloc(u8, try self.encodedSize());
        var sink = Buffer{ .bytes = bytes };
        self.write(&sink);
        std.debug.assert(sink.at == bytes.len);
        return bytes;
    }
    const Buffer = struct {
        bytes: []u8,
        at: usize = 0,
        pub fn update(self: *Buffer, bytes: []const u8) void {
            @memcpy(self.bytes[self.at..][0..bytes.len], bytes);
            self.at += bytes.len;
        }
    };
    pub fn hash(self: Frame) Digest {
        var hasher = Hasher.init();
        self.write(&hasher);
        return .{ .bytes = hasher.finalize() };
    }
};
pub const TreeHasher = struct {
    kind: Kind,
    defaults: [DEPTH + 1]Digest,
    pub fn init(kind: Kind) TreeHasher {
        var self: TreeHasher = .{ .kind = kind, .defaults = undefined };
        self.defaults[DEPTH] = self.leaf(0);
        var depth: usize = DEPTH;
        while (depth != 0) {
            depth -= 1;
            self.defaults[depth] = self.pair(self.defaults[depth + 1], self.defaults[depth + 1]);
        }
        return self;
    }
    pub fn emptyRoot(self: *const TreeHasher, depth: u32) Digest {
        return self.defaults[depth];
    }
    pub fn leaf(self: *const TreeHasher, value: u32) Digest {
        std.debug.assert(value <= 255);
        return (Frame{ .leaf = .{ .kind = self.kind, .value = @intCast(value) } }).hash();
    }
    pub fn pair(self: *const TreeHasher, left: Digest, right: Digest) Digest {
        return (Frame{ .node = .{ .kind = self.kind, .left = left, .right = right } }).hash();
    }
    /// Sorted sparse bytes; explicitly stored zero is identical to implicit zero.
    /// All entries are validated before traversal. No heap memory is allocated.
    pub fn root(self: *const TreeHasher, leaves: []const Leaf) !Digest {
        for (leaves, 0..) |entry, i| {
            if (entry.index >= ADDRESS_LIMIT) return error.ByteAddressOutOfRange;
            if (entry.value > 255) return error.NonByteLeaf;
            if (i != 0 and leaves[i - 1].index >= entry.index) return error.UnsortedOrDuplicateByte;
        }
        var iterator = Iterator{ .values = leaves, .current = if (leaves.len == 0) null else leaves[0] };
        const result = topology.root(&iterator, 0, 0, ADDRESS_LIMIT, self);
        std.debug.assert(iterator.current == null);
        return result;
    }
};
const Iterator = struct {
    values: []const Leaf,
    at: usize = 0,
    current: ?Leaf,
    pub fn consume(self: *Iterator) Leaf {
        const value = self.current.?;
        self.at += 1;
        self.current = if (self.at == self.values.len) null else self.values[self.at];
        return value;
    }
};
