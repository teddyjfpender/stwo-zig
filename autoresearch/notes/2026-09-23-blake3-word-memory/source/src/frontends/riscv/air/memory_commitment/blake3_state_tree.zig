//! Versioned full-width BLAKE3 state commitments. Memory/I/O leaves are u32
//! words indexed by aligned byte address / 4; program leaves are decoded M31.
//! Keep a common 30-level topology. The top two memory-index bits are zero;
//! this retains one canonical path shape without changing program addressing.
const std = @import("std");
const Hasher = @import("stwo_core").vcs.blake3_hash.Blake3Hasher;
const topology = @import("byte_tree_topology.zig");
pub const Digest = @import("../../recursion/blake3_identity_digest.zig").Digest;
pub const DEPTH = 30;
pub const ADDRESS_LIMIT: u32 = 1 << DEPTH;
pub const MEMORY_WORD_LIMIT: u32 = ADDRESS_LIMIT / 4;
pub const Kind = enum(u32) { memory = 1, program = 2, io = 3 };
pub const Leaf = struct { index: u32, value: u32 };
pub const DOMAIN = "stwo.riscv.blake3.state-tree.v2";
pub const Frame = union(enum) {
    leaf: struct { kind: Kind, value: u32 },
    program_field: u32,
    node: struct { kind: Kind, left: Digest, right: Digest },
    pub fn write(self: Frame, sink: anytype) void {
        var domain: [32]u8 = @splat(0);
        @memcpy(domain[0..DOMAIN.len], DOMAIN);
        sink.update(&domain);
        var header: [12]u8 = undefined;
        std.mem.writeInt(u32, header[0..4], 2, .little);
        std.mem.writeInt(u32, header[4..8], switch (self) {
            .leaf => 1,
            .node => 2,
            .program_field => 3,
        }, .little);
        std.mem.writeInt(u32, header[8..12], @intFromEnum(switch (self) {
            .leaf => |v| v.kind,
            .node => |v| v.kind,
            .program_field => .program,
        }), .little);
        sink.update(&header);
        switch (self) {
            .leaf => |v| {
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &bytes, v.value, .little);
                sink.update(&bytes);
            },
            .program_field => |value| {
                std.debug.assert(value < @import("stwo_core").fields.m31.Modulus);
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &bytes, value, .little);
                sink.update(&bytes);
            },
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
        return switch (self) {
            .leaf => 48,
            .program_field => 48,
            .node => 108,
        };
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
        if (self.kind == .program) return (Frame{ .program_field = value }).hash();
        return (Frame{ .leaf = .{ .kind = self.kind, .value = value } }).hash();
    }
    pub fn pair(self: *const TreeHasher, left: Digest, right: Digest) Digest {
        return (Frame{ .node = .{ .kind = self.kind, .left = left, .right = right } }).hash();
    }
    /// Sorted sparse words/fields; explicitly stored zero is identical to implicit zero.
    /// All entries are validated before traversal. No heap memory is allocated.
    pub fn root(self: *const TreeHasher, leaves: []const Leaf) !Digest {
        try validateLeaves(leaves, self.kind);
        var iterator = Iterator{ .values = leaves, .current = if (leaves.len == 0) null else leaves[0] };
        const result = topology.root(&iterator, 0, 0, ADDRESS_LIMIT, self);
        std.debug.assert(iterator.current == null);
        return result;
    }
    /// Extract one opening while computing the root. Unvisited empty subtrees
    /// contribute cached defaults; no full node trace or heap storage is retained.
    pub fn opening(self: *const TreeHasher, leaves: []const Leaf, address: u32) !Opening {
        if (address >= indexLimit(self.kind)) return error.StateIndexOutOfRange;
        try validateLeaves(leaves, self.kind);
        var result: Opening = .{ .address = address, .value = 0, .root = undefined, .siblings = undefined };
        for (&result.siblings, 0..) |*sibling, height| sibling.* = self.defaults[DEPTH - height];
        for (leaves) |entry| if (entry.index == address) {
            result.value = @intCast(entry.value);
            break;
        };
        var iterator = Iterator{ .values = leaves, .current = if (leaves.len == 0) null else leaves[0] };
        result.root = topology.observed(&iterator, 0, 0, ADDRESS_LIMIT, self, &result);
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

pub const Opening = struct {
    address: u32,
    value: u32,
    root: Digest,
    siblings: [DEPTH]Digest,
    pub fn node(self: *Opening, depth: u32, start: u32, width: u32, left: Digest, right: Digest) void {
        if (self.address < start or @as(u64, self.address) >= @as(u64, start) + width) return;
        self.siblings[DEPTH - depth - 1] = if (self.address - start < width / 2) right else left;
    }
    pub fn computedRoot(self: *const Opening, hasher: *const TreeHasher) Digest {
        var current = hasher.leaf(self.value);
        for (self.siblings, 0..) |sibling, height| current = if ((self.address >> @intCast(height)) & 1 == 0) hasher.pair(current, sibling) else hasher.pair(sibling, current);
        return current;
    }
};
fn validateLeaves(leaves: []const Leaf, kind: Kind) !void {
    for (leaves, 0..) |entry, i| {
        if (entry.index >= indexLimit(kind)) return error.StateIndexOutOfRange;
        if (kind == .program) {
            if (entry.value >= @import("stwo_core").fields.m31.Modulus) return error.NonCanonicalProgramField;
        }
        if (i != 0 and leaves[i - 1].index >= entry.index) return error.UnsortedOrDuplicateByte;
    }
}

pub fn indexLimit(kind: Kind) u32 {
    return if (kind == .program) ADDRESS_LIMIT else MEMORY_WORD_LIMIT;
}
pub fn memoryIndex(byte_address: u32) !u32 {
    if (byte_address >= ADDRESS_LIMIT or byte_address & 3 != 0) return error.InvalidMemoryWordAddress;
    return byte_address / 4;
}

/// A subtree wholly outside the admitted address space is a fixed empty digest.
pub fn outsideIndexRange(kind: Kind, level: u32, index: u32) bool {
    return (@as(u64, index) << @as(u6, @intCast(level))) >= indexLimit(kind);
}
