//! Four independent leaf streams. The standard library owns chunk-tree merging
//! and finalization; only full, non-final chunk blocks use SIMD compression.
const std = @import("std");
const core = @import("stwo_core");
const compression = core.crypto.blake3_compression;
const H = core.vcs_lifted.blake3_merkle.MerkleHasher;
const M31 = core.fields.m31.M31;
const V = @Vector(4, u32);
const Ops = struct {
    pub const Word = V;
    pub fn add(_: *Ops, a: V, b: V) !V {
        return a +% b;
    }
    pub fn xorRotate(_: *Ops, a: V, b: V, comptime rotation: u5) !V {
        const v = a ^ b;
        return (v >> @as(@Vector(4, u5), @splat(rotation))) |
            (v << @as(@Vector(4, u5), @splat(@intCast(32 - @as(u6, rotation)))));
    }
};

fn compressWords4(hashers: *const [4]H, comptime root: bool) [8]V {
    var cv: [8]V = undefined;
    var message: [16]V = undefined;
    inline for (0..8) |i| {
        var words: [4]u32 = undefined;
        inline for (0..4) |lane| words[lane] = hashers[lane].inner.state.chunk_state.chaining_value[i];
        cv[i] = words;
    }
    inline for (0..16) |i| {
        var words: [4]u32 = undefined;
        inline for (0..4) |lane| words[lane] = std.mem.readInt(u32, hashers[lane].inner.state.chunk_state.block[i * 4 ..][0..4], .little);
        message[i] = words;
    }
    const chunk = &hashers[0].inner.state.chunk_state;
    var state: [16]V = undefined;
    inline for (0..8) |i| state[i] = cv[i];
    inline for (0..4) |i| state[8 + i] = @splat(compression.IV[i]);
    state[12] = @splat(@truncate(chunk.chunk_counter));
    state[13] = @splat(@truncate(chunk.chunk_counter >> 32));
    state[14] = @splat(if (root) chunk.block_len else 64);
    state[15] = @splat(chunk.flags | @as(u8, if (chunk.blocks_compressed == 0) 1 else 0) | @as(u8, if (root) 2 | 8 else 0));
    var ops = Ops{};
    inline for (0..7) |_| {
        inline for (compression.G_INDICES, 0..) |indices, i| {
            const out = compression.g(Ops, &ops, .{ state[indices[0]], state[indices[1]], state[indices[2]], state[indices[3]], message[2 * i], message[2 * i + 1] }) catch unreachable;
            inline for (indices, 0..) |index, j| state[index] = out[j];
        }
        const old = message;
        inline for (compression.PERMUTATION, 0..) |index, i| message[i] = old[index];
    }
    var out: [8]V = undefined;
    inline for (0..8) |i| out[i] = state[i] ^ state[i + 8];
    return out;
}

fn compress4(hashers: *[4]H) void {
    const output = compressWords4(hashers, false);
    inline for (0..8) |i| {
        const words: [4]u32 = output[i];
        inline for (0..4) |lane| hashers[lane].inner.state.chunk_state.chaining_value[i] = words[lane];
    }
    for (hashers) |*hasher| {
        const c = &hasher.inner.state.chunk_state;
        c.blocks_compressed += 1;
        c.block_len = 0;
        @memset(&c.block, 0);
    }
}

pub fn updatePacked4(hashers: *[4]H, messages: *const [4][]const u8) void {
    const first = &hashers[0].inner.state.chunk_state;
    for (hashers, messages) |*hasher, bytes| {
        const c = &hasher.inner.state.chunk_state;
        if (bytes.len != messages[0].len or c.block_len != first.block_len or
            c.blocks_compressed != first.blocks_compressed or c.chunk_counter != first.chunk_counter or c.flags != first.flags)
        {
            for (hashers, messages) |*h, m| h.inner.update(m);
            return;
        }
    }
    var pos: usize = 0;
    while (pos < messages[0].len) {
        if (first.block_len == 64) {
            if (first.blocks_compressed == 15) {
                // Let std handle CHUNK_END, CV-stack carries, and the next chunk.
                for (hashers, messages) |*h, m| h.inner.update(m[pos .. pos + 1]);
                pos += 1;
                continue;
            }
            compress4(hashers);
        }
        const count = @min(64 - @as(usize, first.block_len), messages[0].len - pos);
        for (hashers, messages) |*h, m| {
            const c = &h.inner.state.chunk_state;
            @memcpy(c.block[c.block_len..][0..count], m[pos..][0..count]);
            c.block_len += @intCast(count);
        }
        pos += count;
    }
}

pub fn updateM31Columns4(hashers: *[4]H, columns: anytype, position: usize) void {
    var bytes: [4][256]u8 = undefined;
    var start: usize = 0;
    while (start < columns.len) {
        const count: usize = @min(64, columns.len - start);
        for (columns[start..][0..count], 0..) |column, i| {
            inline for (0..4) |lane| std.mem.writeInt(u32, bytes[lane][i * 4 ..][0..4], column.values[position + lane].v, .little);
        }
        var views: [4][]const u8 = undefined;
        for (&views, 0..) |*view, lane| view.* = bytes[lane][0 .. count * 4];
        updatePacked4(hashers, &views);
        start += count;
    }
}

pub fn finalize4(hashers: *const [4]H) [4]H.Hash {
    var out: [4]H.Hash = undefined;
    const first = &hashers[0].inner.state.chunk_state;
    for (hashers) |*hasher| {
        const c = &hasher.inner.state.chunk_state;
        if (c.chunk_counter != 0 or c.block_len != first.block_len or
            c.blocks_compressed != first.blocks_compressed or c.flags != first.flags)
        {
            for (&out, hashers) |*digest, *h| digest.* = h.finalize();
            return out;
        }
    }
    const words = compressWords4(hashers, true);
    inline for (0..8) |i| {
        const lanes: [4]u32 = words[i];
        inline for (0..4) |lane| std.mem.writeInt(u32, out[lane][i * 4 ..][0..4], lanes[lane], .little);
    }
    return out;
}
pub fn finalizeTail4(hashers: *const [4]H, tails: *const [4][]const M31) [4]H.Hash {
    var out: [4]H.Hash = undefined;
    for (&out, hashers, tails) |*digest, *hasher, tail| {
        var copy = hasher.*;
        copy.updateLeaf(tail);
        digest.* = copy.finalize();
    }
    return out;
}

test "prover vcs_lifted BLAKE3 SIMD streams match std across block and tree boundaries" {
    var data: [4][8193]u8 = undefined;
    for (&data, 0..) |*bytes, lane| for (bytes, 0..) |*byte, i| {
        byte.* = @truncate(i * 37 + lane * 113);
    };
    for ([_]usize{ 0, 1, 31, 37, 38, 39, 63, 64, 65, 101, 102, 103, 127, 128, 997, 998, 999, 1023, 1024, 1025, 2021, 2022, 2023, 2048, 3046, 3073, 8166, 8193 }) |len| {
        for ([_]usize{ 1, 17, 64, 255, 1024, 8193 }) |step| {
            var actual = [_]H{H.defaultWithInitialState()} ** 4;
            var expected = actual;
            var pos: usize = 0;
            while (pos < len) {
                const end = @min(len, pos + step);
                var views: [4][]const u8 = undefined;
                for (&views, 0..) |*view, lane| {
                    view.* = data[lane][pos..end];
                    expected[lane].inner.update(view.*);
                }
                updatePacked4(&actual, &views);
                pos = end;
            }
            const digests = finalize4(&actual);
            for (digests, &expected) |digest, *reference| try std.testing.expectEqualSlices(u8, &reference.finalize(), &digest);
        }
    }
}

test "prover vcs_lifted BLAKE3 columns tails and divergent streams match std" {
    const Column = struct { values: []const M31 };
    var storage: [513][7]M31 = undefined;
    var columns: [513]Column = undefined;
    for (&storage, &columns, 0..) |*row, *column, i| {
        for (row, 0..) |*v, j| v.* = M31.fromCanonical(@intCast(i * 71 + j * 101));
        column.* = .{ .values = row };
    }
    var actual = [_]H{H.defaultWithInitialState()} ** 4;
    var expected = actual;
    for ([_]usize{ 0, 1, 63, 64, 65, 257, 513 }) |count| {
        updateM31Columns4(&actual, columns[0..count], 2);
        for (0..4) |lane| for (columns[0..count]) |column| {
            expected[lane].updateLeaf(column.values[2 + lane ..][0..1]);
        };
        const hashes = finalize4(&actual);
        for (hashes, &expected) |digest, *h| try std.testing.expectEqualSlices(u8, &h.finalize(), &digest);
    }
    const tails = [4][]const M31{ storage[0][0..0], storage[1][0..1], storage[2][0..4], storage[3][0..7] };
    const hashes = finalizeTail4(&actual, &tails);
    for (hashes, &expected, tails) |digest, *h, tail| {
        h.updateLeaf(tail);
        try std.testing.expectEqualSlices(u8, &h.finalize(), &digest);
    }
    // Independent lengths/states must fall back without losing any lane's bytes.
    actual = expected;
    const bytes = [_]u8{0xa7} ** 2051;
    const views = [4][]const u8{ bytes[0..63], bytes[0..64], bytes[0..1025], &bytes };
    updatePacked4(&actual, &views);
    for (&actual, &expected, views) |*a, *e, view| {
        e.inner.update(view);
        try std.testing.expectEqualSlices(u8, &e.finalize(), &a.finalize());
    }
    const equal_views = [_][]const u8{&bytes} ** 4;
    updatePacked4(&actual, &equal_views);
    for (&actual, &expected) |*a, *e| {
        e.inner.update(&bytes);
        try std.testing.expectEqualSlices(u8, &e.finalize(), &a.finalize());
    }
}

pub fn hashChildren4(children: *const [8]H.Hash) [4]H.Hash {
    const protocol = core.channel.blake3;
    var hashers = [_]H{.{ .inner = protocol.start(.node) }} ** 4;
    var payloads: [4][64]u8 = undefined;
    var views: [4][]const u8 = undefined;
    for (&payloads, &views, 0..) |*payload, *view, lane| {
        @memcpy(payload[0..32], &children[2 * lane]);
        @memcpy(payload[32..64], &children[2 * lane + 1]);
        view.* = payload;
    }
    updatePacked4(&hashers, &views);
    return finalize4(&hashers);
}

pub fn hashLiftedLeaves4(columns: anytype, max_log_size: u32, position: usize) [4]H.Hash {
    var hashers = [_]H{H.defaultWithInitialState()} ** 4;
    var bytes: [4][256]u8 = undefined;
    var start: usize = 0;
    while (start < columns.len) {
        const count: usize = @min(64, columns.len - start);
        for (columns[start..][0..count], 0..) |column, i| {
            const shift: std.math.Log2Int(usize) = @intCast(max_log_size - column.log_size + 1);
            inline for (0..4) |lane| {
                const pos = position + lane;
                const index = ((pos >> shift) << 1) + (pos & 1);
                std.mem.writeInt(u32, bytes[lane][i * 4 ..][0..4], column.values[index].v, .little);
            }
        }
        var views: [4][]const u8 = undefined;
        for (&views, 0..) |*view, lane| view.* = bytes[lane][0 .. count * 4];
        updatePacked4(&hashers, &views);
        start += count;
    }
    return finalize4(&hashers);
}

test "prover vcs_lifted BLAKE3 nodes and heterogeneous lifted leaves match scalar" {
    var children: [8]H.Hash = undefined;
    for (&children, 0..) |*child, i| for (child, 0..) |*b, j| {
        b.* = @truncate(i * 51 + j);
    };
    const nodes = hashChildren4(&children);
    for (nodes, 0..) |node, i| try std.testing.expectEqualSlices(u8, &H.hashChildren(.{ .left = children[2 * i], .right = children[2 * i + 1] }), &node);
    const Column = struct { values: []const M31, log_size: u32 };
    var storage: [275][16]M31 = undefined;
    var columns: [275]Column = undefined;
    for (&storage, &columns, 0..) |*values, *column, i| {
        for (values, 0..) |*value, j| value.* = M31.fromCanonical(@intCast(i * 37 + j * 113));
        column.* = .{ .values = values, .log_size = @intCast(1 + i % 4) };
    }
    for ([_]usize{ 0, 4, 8, 12 }) |pos| for ([_]usize{ 0, 1, 9, 64, 257, 275 }) |count| {
        const hashes = hashLiftedLeaves4(columns[0..count], 4, pos);
        for (hashes, 0..) |digest, lane| {
            var h = H.defaultWithInitialState();
            for (columns[0..count]) |column| {
                const shift: u6 = @intCast(5 - column.log_size);
                const index = (((pos + lane) >> shift) << 1) + ((pos + lane) & 1);
                h.updateLeaf(column.values[index..][0..1]);
            }
            try std.testing.expectEqualSlices(u8, &h.finalize(), &digest);
        }
    };
}
