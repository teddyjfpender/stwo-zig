const std = @import("std");
const builtin = @import("builtin");
const channel_blake2s = @import("../channel/blake2s.zig");
const m31 = @import("../fields/m31.zig");
const blake2_hash = @import("../vcs/blake2_hash.zig");

const M31 = m31.M31;

pub const LEAF_PREFIX = makePrefix("leaf");
pub const NODE_PREFIX = makePrefix("node");
pub const DOMAIN_PREFIX_BYTES: u32 = 64;

pub const HashProtocol = enum(u32) {
    plain = 0,
    domain_prefixed = DOMAIN_PREFIX_BYTES,
};

/// Compatibility aliases for pinned raw Stwo `a8fcf4bd`.
pub const Blake2sMerkleHasher = Blake2sMerkleHasherGeneric(false);
pub const Blake2sM31MerkleHasher = Blake2sMerkleHasherGeneric(true);
pub const Blake2sPrefixedMerkleHasher = Blake2sMerkleHasher;
pub const Blake2sPrefixedM31MerkleHasher = Blake2sM31MerkleHasher;

/// Explicit plain-hash protocol used by the newer pinned Stwo-Cairo oracle.
pub const Blake2sPlainMerkleHasher = Blake2sPlainMerkleHasherGeneric(false);
pub const Blake2sPlainM31MerkleHasher = Blake2sPlainMerkleHasherGeneric(true);

pub fn Blake2sMerkleHasherGeneric(comptime is_m31_output: bool) type {
    return Blake2sMerkleHasherProtocolGeneric(is_m31_output, .domain_prefixed);
}

pub fn Blake2sPrefixedMerkleHasherGeneric(comptime is_m31_output: bool) type {
    return Blake2sMerkleHasherGeneric(is_m31_output);
}

pub fn Blake2sPlainMerkleHasherGeneric(comptime is_m31_output: bool) type {
    return Blake2sMerkleHasherProtocolGeneric(is_m31_output, .plain);
}

fn Blake2sMerkleHasherProtocolGeneric(
    comptime is_m31_output: bool,
    comptime hash_protocol: HashProtocol,
) type {
    const InnerHasher = blake2_hash.Blake2sHasherGeneric(is_m31_output);
    const pack_chunk_elems = 32;
    return struct {
        inner: InnerHasher,
        pub const Hash = blake2_hash.Blake2sHash;
        pub const NodeSeed = InnerHasher.Fixed64Seed;
        pub const Children = struct { left: Hash, right: Hash };
        pub const protocol = hash_protocol;

        const Self = @This();

        pub fn init() Self {
            return initWithMode(defaultMode());
        }

        pub fn initWithMode(mode: blake2_hash.BackendMode) Self {
            return .{ .inner = InnerHasher.initWithMode(mode) };
        }

        pub fn defaultWithInitialState() Self {
            return defaultWithInitialStateWithMode(defaultMode());
        }

        pub fn defaultWithInitialStateWithMode(mode: blake2_hash.BackendMode) Self {
            var hasher = Self.initWithMode(mode);
            if (comptime hash_protocol == .domain_prefixed) hasher.inner.update(LEAF_PREFIX[0..]);
            return hasher;
        }

        pub fn hashChildren(children: Children) Hash {
            return hashChildrenWithMode(defaultMode(), children);
        }

        pub fn hashChildrenWithMode(
            mode: blake2_hash.BackendMode,
            children: Children,
        ) Hash {
            if (comptime hash_protocol == .domain_prefixed) {
                var payload: [64]u8 = undefined;
                @memcpy(payload[0..32], children.left[0..]);
                @memcpy(payload[32..64], children.right[0..]);
                return InnerHasher.hashFinal64FromSeedWithMode(mode, nodeSeedWithMode(mode), &payload);
            }
            return InnerHasher.concatAndHashWithMode(mode, children.left, children.right);
        }

        pub fn domainPrefixBytes() u32 {
            return @intFromEnum(hash_protocol);
        }

        /// Pre-hashed node-domain separator state used to avoid reprocessing
        /// `NODE_PREFIX` for every parent hash on one Merkle layer.
        pub fn nodeSeed() NodeSeed {
            return nodeSeedWithMode(defaultMode());
        }

        pub fn nodeSeedWithMode(mode: blake2_hash.BackendMode) NodeSeed {
            return InnerHasher.seedAfterFixed64WithMode(mode, &NODE_PREFIX);
        }

        pub fn leafSeed() NodeSeed {
            return leafSeedWithMode(defaultMode());
        }

        pub fn leafSeedWithMode(mode: blake2_hash.BackendMode) NodeSeed {
            return InnerHasher.seedAfterFixed64WithMode(mode, &LEAF_PREFIX);
        }

        pub fn hashChildrenWithSeed(seed: NodeSeed, children: Children) Hash {
            return hashChildrenWithSeedWithMode(defaultMode(), seed, children);
        }

        pub fn hashChildrenWithSeedWithMode(
            mode: blake2_hash.BackendMode,
            seed: NodeSeed,
            children: Children,
        ) Hash {
            if (comptime hash_protocol == .domain_prefixed) {
                var payload: [64]u8 = undefined;
                @memcpy(payload[0..32], children.left[0..]);
                @memcpy(payload[32..64], children.right[0..]);
                return InnerHasher.hashFinal64FromSeedWithMode(mode, seed, &payload);
            }
            return InnerHasher.concatAndHashWithMode(mode, children.left, children.right);
        }

        pub fn hashChildrenWithSeed4(seed: NodeSeed, children: *const [8]Hash) [4]Hash {
            return hashChildrenWithSeed4WithMode(defaultMode(), seed, children);
        }

        pub fn hashChildrenWithSeed4WithMode(
            mode: blake2_hash.BackendMode,
            seed: NodeSeed,
            children: *const [8]Hash,
        ) [4]Hash {
            if (comptime hash_protocol == .domain_prefixed) {
                var payloads: [4][64]u8 = undefined;
                for (&payloads, 0..) |*payload, lane| {
                    @memcpy(payload[0..32], children[2 * lane][0..]);
                    @memcpy(payload[32..64], children[2 * lane + 1][0..]);
                }
                return InnerHasher.hashFinal64FromSeed4WithMode(mode, seed, &payloads);
            }
            var payloads: [4][64]u8 = undefined;
            for (&payloads, 0..) |*payload, lane| {
                @memcpy(payload[0..32], children[2 * lane][0..]);
                @memcpy(payload[32..64], children[2 * lane + 1][0..]);
            }
            return InnerHasher.hashFixedSingleBlock4WithMode(64, mode, &payloads);
        }

        pub fn hashPackedLeavesWithSeed4(seed: NodeSeed, messages: *const [4][]const u8) [4]Hash {
            return hashPackedLeavesWithSeed4WithMode(defaultMode(), seed, messages);
        }

        pub fn hashPackedLeavesWithSeed4WithMode(
            mode: blake2_hash.BackendMode,
            seed: NodeSeed,
            messages: *const [4][]const u8,
        ) [4]Hash {
            if (comptime hash_protocol == .domain_prefixed)
                return InnerHasher.hashEqualFromSeed4WithMode(mode, seed, messages);
            return InnerHasher.hashEqual4WithMode(mode, messages);
        }

        pub fn hashDirectM31LeavesWithSeed4(
            seed: NodeSeed,
            columns: anytype,
            position: usize,
        ) [4]Hash {
            const mode = defaultMode();
            if (comptime hash_protocol == .domain_prefixed) {
                return InnerHasher.hashM31ColumnsFromSeed4WithMode(
                    mode,
                    seed,
                    columns,
                    position,
                );
            }
            return InnerHasher.hashM31Columns4WithMode(
                mode,
                columns,
                position,
            );
        }

        pub fn hashDirectLiftedM31LeavesWithSeed4(seed: NodeSeed, columns: anytype, position: usize, max_log_size: u32) [4]Hash {
            return InnerHasher.hashLiftedM31Columns4WithMode(defaultMode(), if (hash_protocol == .domain_prefixed) seed else null, columns, position, max_log_size);
        }

        pub fn updateLeaf(self: *Self, column_values: []const M31) void {
            if (column_values.len == 0) return;

            if (builtin.cpu.arch.endian() == .little) {
                // M31 is represented as canonical u32 words, so little-endian
                // hosts can stream the bytes directly without repacking.
                self.inner.update(std.mem.sliceAsBytes(column_values));
                return;
            } else {
                var at: usize = 0;
                var bytes: [pack_chunk_elems * 4]u8 = undefined;
                while (at < column_values.len) {
                    const chunk = @min(pack_chunk_elems, column_values.len - at);
                    for (0..chunk) |i| {
                        const value_bytes = column_values[at + i].toBytesLe();
                        const start = i * 4;
                        @memcpy(bytes[start .. start + 4], value_bytes[0..]);
                    }
                    self.inner.update(bytes[0 .. chunk * 4]);
                    at += chunk;
                }
            }
        }

        /// Updates a leaf hasher from pre-packed canonical little-endian M31 bytes.
        ///
        /// Preconditions:
        /// - `packed_bytes.len` is a multiple of 4.
        pub fn updateLeafPackedBytes(self: *Self, packed_bytes: []const u8) void {
            std.debug.assert((packed_bytes.len & 3) == 0);
            if (packed_bytes.len == 0) return;
            self.inner.update(packed_bytes);
        }

        pub fn finalize(self: *Self) Hash {
            return self.inner.finalize();
        }

        fn defaultMode() blake2_hash.BackendMode {
            return blake2_hash.getDefaultBackendSelection().requested;
        }
    };
}

pub fn Blake2sMerkleChannelGeneric(comptime is_m31_output: bool) type {
    return struct {
        pub fn mixRoot(
            channel: *channel_blake2s.Blake2sChannelGeneric(is_m31_output),
            root: blake2_hash.Blake2sHash,
        ) void {
            const digest = channel.digestBytes();
            channel.updateDigest(
                blake2_hash.Blake2sHasherGeneric(is_m31_output).concatAndHash(digest, root),
            );
        }
    };
}

pub const Blake2sMerkleChannel = Blake2sMerkleChannelGeneric(false);
pub const Blake2sM31MerkleChannel = Blake2sMerkleChannelGeneric(true);
pub const Blake2sPrefixedMerkleChannel = Blake2sMerkleChannel;
pub const Blake2sPrefixedM31MerkleChannel = Blake2sM31MerkleChannel;
pub const Blake2sPlainMerkleChannel = Blake2sMerkleChannel;
pub const Blake2sPlainM31MerkleChannel = Blake2sM31MerkleChannel;

fn makePrefix(comptime tag: []const u8) [64]u8 {
    var out: [64]u8 = [_]u8{0} ** 64;
    inline for (tag, 0..) |c, i| out[i] = c;
    return out;
}

test "vcs_lifted blake2: hash children deterministic" {
    const left = [_]u8{1} ** 32;
    const right = [_]u8{2} ** 32;
    const h1 = Blake2sMerkleHasher.hashChildren(.{ .left = left, .right = right });
    const h2 = Blake2sMerkleHasher.hashChildren(.{ .left = left, .right = right });
    try std.testing.expect(std.mem.eql(u8, h1[0..], h2[0..]));
}

test "vcs_lifted blake2: direct column-major leaves match packed messages" {
    const Column = struct { values: []const M31 };
    var storage: [19][4]M31 = undefined;
    var columns: [storage.len]Column = undefined;
    for (&storage, &columns, 0..) |*values, *column, column_index| {
        for (values, 0..) |*value, row| {
            value.* = M31.fromCanonical(@intCast(1 + column_index * 17 + row * 101));
        }
        column.* = .{ .values = values };
    }

    var messages: [4][storage.len * @sizeOf(M31)]u8 = undefined;
    for (&messages, 0..) |*message, row| {
        for (storage, 0..) |values, column_index| {
            const encoded = values[row].toBytesLe();
            const at = column_index * @sizeOf(M31);
            @memcpy(message[at .. at + @sizeOf(M31)], &encoded);
        }
    }
    var message_views: [4][]const u8 = undefined;
    for (&message_views, &messages) |*view, *message| view.* = message;

    const seed = Blake2sMerkleHasher.leafSeed();
    const expected = Blake2sMerkleHasher.hashPackedLeavesWithSeed4(seed, &message_views);
    const actual = Blake2sMerkleHasher.hashDirectM31LeavesWithSeed4(seed, &columns, 0);
    try std.testing.expectEqualDeep(expected, actual);

    const plain_seed = Blake2sPlainMerkleHasher.leafSeed();
    const plain_expected = Blake2sPlainMerkleHasher.hashPackedLeavesWithSeed4(
        plain_seed,
        &message_views,
    );
    const plain_actual = Blake2sPlainMerkleHasher.hashDirectM31LeavesWithSeed4(
        plain_seed,
        &columns,
        0,
    );
    try std.testing.expectEqualDeep(plain_expected, plain_actual);
}

test "vcs_lifted blake2: mix root changes channel digest" {
    var channel = channel_blake2s.Blake2sChannel{};
    const before = channel.digestBytes();
    Blake2sMerkleChannel.mixRoot(&channel, [_]u8{3} ** 32);
    try std.testing.expect(!std.mem.eql(u8, before[0..], channel.digestBytes()[0..]));
}

test "vcs_lifted blake2: plain updateLeaf matches explicit byte packing" {
    var prng = std.Random.DefaultPrng.init(0x5ca1_ab1e_1234_5678);
    const rng = prng.random();
    var values: [65]M31 = undefined;
    for (values[0..]) |*value| {
        value.* = M31.fromU64(rng.int(u32));
    }

    var lifted = Blake2sPlainMerkleHasher.defaultWithInitialState();
    lifted.updateLeaf(values[0..]);
    const digest = lifted.finalize();

    var manual = blake2_hash.Blake2sHasher.init();
    for (values[0..]) |value| {
        const encoded = value.toBytesLe();
        manual.update(encoded[0..]);
    }
    const expected = manual.finalize();
    try std.testing.expect(std.mem.eql(u8, digest[0..], expected[0..]));
}

test "vcs_lifted blake2: pinned Cairo Rust oracle uses plain leaf and parent hashes" {
    const values = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(2),
        M31.fromCanonical(3),
    };
    var leaf_hasher = Blake2sPlainMerkleHasher.defaultWithInitialState();
    leaf_hasher.updateLeaf(&values);
    const leaf_hex = std.fmt.bytesToHex(leaf_hasher.finalize(), .lower);
    try std.testing.expectEqualStrings(
        "9549ce18083a73c794b0fe338635a4ab0950333ecb2e3f1945adf7db5f0ef4d0",
        &leaf_hex,
    );

    const parent = Blake2sPlainMerkleHasher.hashChildren(.{
        .left = [_]u8{0x01} ** 32,
        .right = [_]u8{0x02} ** 32,
    });
    const parent_hex = std.fmt.bytesToHex(parent, .lower);
    try std.testing.expectEqualStrings(
        "280569932378c99f448df37e893f062fab951bea53515634b7875ae51e1954e7",
        &parent_hex,
    );
}

test "vcs_lifted blake2: pinned raw Stwo oracle uses domain-prefixed hashes" {
    var empty_leaf = Blake2sPrefixedMerkleHasher.defaultWithInitialState();
    const empty_hex = std.fmt.bytesToHex(empty_leaf.finalize(), .lower);
    try std.testing.expectEqualStrings(
        "2a133e150238721921d1ea772882979c810f85f2849099b9d3415a8619d85fad",
        &empty_hex,
    );

    const parent = Blake2sPrefixedMerkleHasher.hashChildren(.{
        .left = [_]u8{0x01} ** 32,
        .right = [_]u8{0x02} ** 32,
    });
    const parent_hex = std.fmt.bytesToHex(parent, .lower);
    try std.testing.expectEqualStrings(
        "24c36247c66cc7b145aee79ccff9d5e3e596a8e13e86d13942f61464364fa53c",
        &parent_hex,
    );
    try std.testing.expectEqual(DOMAIN_PREFIX_BYTES, Blake2sMerkleHasher.domainPrefixBytes());
    try std.testing.expectEqual(@as(u32, 0), Blake2sPlainMerkleHasher.domainPrefixBytes());
}

test "vcs_lifted blake2: updateLeafPackedBytes matches updateLeaf" {
    var prng = std.Random.DefaultPrng.init(0x1234_5678_9abc_def0);
    const rng = prng.random();
    var values: [96]M31 = undefined;
    for (values[0..]) |*value| {
        value.* = M31.fromU64(rng.int(u32));
    }

    var packed_bytes: [96 * 4]u8 = undefined;
    if (builtin.cpu.arch.endian() == .little) {
        @memcpy(packed_bytes[0..], std.mem.sliceAsBytes(values[0..]));
    } else {
        for (values[0..], 0..) |value, i| {
            const encoded = value.toBytesLe();
            const start = i * 4;
            @memcpy(packed_bytes[start .. start + 4], encoded[0..]);
        }
    }

    var from_values = Blake2sMerkleHasher.defaultWithInitialState();
    from_values.updateLeaf(values[0..]);
    const digest_values = from_values.finalize();

    var from_packed = Blake2sMerkleHasher.defaultWithInitialState();
    from_packed.updateLeafPackedBytes(packed_bytes[0..]);
    const digest_packed = from_packed.finalize();

    try std.testing.expect(std.mem.eql(u8, digest_values[0..], digest_packed[0..]));
}

test "vcs_lifted blake2: hashChildrenWithSeed matches fixed parent hash" {
    const left = [_]u8{7} ** 32;
    const right = [_]u8{11} ** 32;
    const seeded = Blake2sMerkleHasher.hashChildrenWithSeed(
        Blake2sMerkleHasher.nodeSeed(),
        .{ .left = left, .right = right },
    );
    const direct = Blake2sMerkleHasher.hashChildren(.{ .left = left, .right = right });
    try std.testing.expect(std.mem.eql(u8, seeded[0..], direct[0..]));
}

test "BLAKE2s direct mixed-height SIMD leaves match independent scalar messages" {
    const Column = struct { values: []const M31, log_size: u32 };
    var storage: [127][256]M31 = undefined;
    var columns: [127]Column = undefined;
    for (&storage, &columns, 0..) |*values, *column, index| {
        const log_size: u32 = @intCast(1 + index % 8);
        for (values, 0..) |*value, row| value.* = M31.fromCanonical(@intCast((index * 71 + row * 19) % 2147483647));
        column.* = .{ .values = values[0 .. @as(usize, 1) << @intCast(log_size)], .log_size = log_size };
    }
    inline for (.{ Blake2sMerkleHasher, Blake2sPlainMerkleHasher }) |H| {
        for ([_]usize{ 1, 15, 16, 17, 31, 32, 33, 65, 127 }) |count| {
            var position: usize = 0;
            while (position < 256) : (position += 4) {
                const actual = H.hashDirectLiftedM31LeavesWithSeed4(H.leafSeed(), columns[0..count], position, 8);
                for (actual, 0..) |digest, lane| {
                    var scalar = H.defaultWithInitialStateWithMode(.scalar);
                    for (columns[0..count]) |column| {
                        const shift: std.math.Log2Int(usize) = @intCast(8 - column.log_size + 1);
                        const source = (((position + lane) >> shift) << 1) + ((position + lane) & 1);
                        scalar.updateLeaf(column.values[source..][0..1]);
                    }
                    try std.testing.expectEqualSlices(u8, &scalar.finalize(), &digest);
                }
            }
        }
    }
}
