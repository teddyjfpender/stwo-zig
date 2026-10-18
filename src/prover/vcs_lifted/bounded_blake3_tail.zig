//! Four-message native-height prefix caches for lifted BLAKE3 commitments.
//!
//! Every lifted leaf of one commitment absorbs the same byte count, so four
//! independent leaf streams share block offsets, chunk counters, CV-stack
//! depth and flags. The canonical batch compression therefore drives all
//! four lanes in lockstep through exactly the std hasher's control flow,
//! and a lane carries only the CV-stack depth a bounded leaf can reach
//! instead of the 54-entry standard stack the scalar path copies per row.
const std = @import("std");
const core = @import("stwo_core");
const batch = core.crypto.blake3_compression_batch;
const compression = core.crypto.blake3_compression;
const M31 = core.fields.m31.M31;
const Hasher = core.vcs_lifted.blake3_merkle.MerkleHasher;

const LANES = batch.LANES;
const BLOCK_LEN: u32 = 64;
const CHUNK_LEN: u32 = 1024;
const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const PARENT: u32 = 4;
const ROOT: u32 = 8;
/// Pending subtree chaining values per lane: enough for leaves up to
/// 2^MAX_STACK KiB. Larger leaves keep the established scalar path.
const MAX_STACK: usize = 12;

pub fn supports(comptime H: type) bool {
    return H == Hasher;
}

pub fn cacheBytes(comptime H: type, comptime Column: type) usize {
    if (comptime !supports(H)) return 0;
    return @sizeOf(Cache(Column));
}

const Cvs = [LANES][8]u32;
const Blocks = [LANES][16]u32;

/// Four unkeyed BLAKE3 streams that have absorbed equal byte counts.
const Lanes = struct {
    cvs: Cvs,
    blocks: Blocks,
    block_len: u32,
    blocks_compressed: u32,
    chunk_counter: u64,
    stack_len: u32,
    stack: [MAX_STACK]Cvs,

    fn load(sources: [LANES]*const Hasher) Lanes {
        const first = &sources[0].inner.state;
        var lanes = geometry(.{
            .block_len = first.chunk_state.block_len,
            .blocks_compressed = first.chunk_state.blocks_compressed,
            .chunk_counter = first.chunk_state.chunk_counter,
            .stack_len = first.cv_stack_len,
        });
        for (sources, 0..) |source, lane| {
            const state = &source.inner.state;
            lanes.cvs[lane] = state.chunk_state.chaining_value;
            inline for (0..16) |word| {
                lanes.blocks[lane][word] = std.mem.readInt(u32, state.chunk_state.block[4 * word ..][0..4], .little);
            }
            for (0..lanes.stack_len) |depth| lanes.stack[depth][lane] = state.cv_stack[depth];
        }
        return lanes;
    }

    const Geometry = struct { block_len: u32, blocks_compressed: u32, chunk_counter: u64, stack_len: u32 };

    fn geometry(form: Geometry) Lanes {
        return .{
            .cvs = undefined,
            .blocks = undefined,
            .block_len = form.block_len,
            .blocks_compressed = form.blocks_compressed,
            .chunk_counter = form.chunk_counter,
            .stack_len = form.stack_len,
            .stack = undefined,
        };
    }

    fn shape(self: *const Lanes) Geometry {
        return .{
            .block_len = self.block_len,
            .blocks_compressed = self.blocks_compressed,
            .chunk_counter = self.chunk_counter,
            .stack_len = self.stack_len,
        };
    }

    fn copyLane(self: *Lanes, lane: usize, source: *const Lanes, source_lane: usize) void {
        self.cvs[lane] = source.cvs[source_lane];
        self.blocks[lane] = source.blocks[source_lane];
        for (0..self.stack_len) |depth| self.stack[depth][lane] = source.stack[depth][source_lane];
    }

    fn startFlag(self: *const Lanes) u32 {
        return if (self.blocks_compressed == 0) CHUNK_START else 0;
    }

    fn chaining(words: [LANES][16]u32) Cvs {
        var cvs: Cvs = undefined;
        inline for (0..LANES) |lane| cvs[lane] = words[lane][0..8].*;
        return cvs;
    }

    fn parentCvs(left: Cvs, right: Cvs) Cvs {
        var blocks: Blocks = undefined;
        inline for (0..LANES) |lane| blocks[lane] = left[lane] ++ right[lane];
        return chaining(batch.compress4(@splat(compression.IV), blocks, @splat(0), @splat(BLOCK_LEN), @splat(PARENT)) catch unreachable);
    }

    /// Mirrors `std.crypto.hash.Blake3.update` for one little-endian word on
    /// every lane: a full chunk or block is compressed only once more input
    /// arrives, so `finalize` sees the same pending state as the std hasher.
    fn absorbWord(self: *Lanes, words: [LANES]u32) void {
        if (self.blocks_compressed * BLOCK_LEN + self.block_len == CHUNK_LEN) {
            const flags = self.startFlag() | CHUNK_END;
            var value = chaining(batch.compress4(self.cvs, self.blocks, @splat(self.chunk_counter), @splat(self.block_len), @splat(flags)) catch unreachable);
            var total = self.chunk_counter + 1;
            while (total & 1 == 0) : (total >>= 1) {
                self.stack_len -= 1;
                value = parentCvs(self.stack[self.stack_len], value);
            }
            self.stack[self.stack_len] = value;
            self.stack_len += 1;
            self.cvs = @splat(compression.IV);
            self.blocks = @splat(@splat(0));
            self.block_len = 0;
            self.blocks_compressed = 0;
            self.chunk_counter += 1;
        }
        if (self.block_len == BLOCK_LEN) {
            self.cvs = chaining(batch.compress4(self.cvs, self.blocks, @splat(self.chunk_counter), @splat(BLOCK_LEN), @splat(self.startFlag())) catch unreachable);
            self.blocks_compressed += 1;
            self.blocks = @splat(@splat(0));
            self.block_len = 0;
        }
        const word = self.block_len / 4;
        inline for (0..LANES) |lane| self.blocks[lane][word] = words[lane];
        self.block_len += 4;
    }

    fn updateM31Columns(self: *Lanes, columns: anytype, rows: [LANES]usize) void {
        for (columns) |column| {
            var words: [LANES]u32 = undefined;
            inline for (0..LANES) |lane| words[lane] = column.values[rows[lane]].toU32();
            self.absorbWord(words);
        }
    }

    /// Mirrors `std.crypto.hash.Blake3.final` for a 32-byte digest.
    fn finalize(self: *const Lanes) [LANES][32]u8 {
        var cvs = self.cvs;
        var blocks = self.blocks;
        var length = self.block_len;
        var counter = self.chunk_counter;
        var flags = self.startFlag() | CHUNK_END;
        var remaining = self.stack_len;
        while (remaining > 0) {
            remaining -= 1;
            const value = chaining(batch.compress4(cvs, blocks, @splat(counter), @splat(length), @splat(flags)) catch unreachable);
            cvs = @splat(compression.IV);
            inline for (0..LANES) |lane| blocks[lane] = self.stack[remaining][lane] ++ value[lane];
            length = BLOCK_LEN;
            counter = 0;
            flags = PARENT;
        }
        const root = batch.compress4(cvs, blocks, @splat(0), @splat(length), @splat(flags | ROOT)) catch unreachable;
        var digests: [LANES][32]u8 = undefined;
        inline for (0..LANES) |lane| inline for (0..8) |word| {
            std.mem.writeInt(u32, digests[lane][4 * word ..][0..4], root[lane][word], .little);
        };
        return digests;
    }
};

/// Every base state must be an unkeyed stream with word-aligned pending
/// bytes and the same geometry, and the finished leaf must stay within the
/// lane stack. Anything else keeps the scalar path before outputs change.
fn admits(base: []const Hasher, tail_column_count: usize) bool {
    if (base.len == 0) return false;
    const first = &base[0].inner.state;
    if (first.flags != 0 or !std.mem.eql(u32, &first.key, &compression.IV)) return false;
    const chunk = first.chunk_state;
    if (chunk.block_len % 4 != 0 or chunk.block_len > BLOCK_LEN) return false;
    if (chunk.blocks_compressed * BLOCK_LEN + @as(u32, chunk.block_len) > CHUNK_LEN) return false;
    if (first.cv_stack_len > MAX_STACK) return false;
    const absorbed = std.math.add(
        u64,
        std.math.mul(u64, chunk.chunk_counter, CHUNK_LEN) catch return false,
        @as(u64, chunk.blocks_compressed) * BLOCK_LEN + chunk.block_len,
    ) catch return false;
    const tail_bytes = std.math.mul(u64, tail_column_count, @sizeOf(M31)) catch return false;
    const total = std.math.add(u64, absorbed, tail_bytes) catch return false;
    const chunks = @max(1, total / CHUNK_LEN + @intFromBool(total % CHUNK_LEN != 0));
    if (std.math.log2_int(u64, chunks) + 1 > MAX_STACK) return false;
    for (base[1..]) |hasher| {
        const state = &hasher.inner.state;
        if (state.flags != 0 or state.cv_stack_len != first.cv_stack_len) return false;
        if (state.chunk_state.block_len != chunk.block_len or
            state.chunk_state.blocks_compressed != chunk.blocks_compressed or
            state.chunk_state.chunk_counter != chunk.chunk_counter) return false;
    }
    return true;
}

fn Cache(comptime Column: type) type {
    return struct {
        const Self = @This();
        const Group = struct { columns: []const Column, log: u32 };
        const Block = struct { lanes: Lanes, index: usize };
        groups: [@bitSizeOf(usize)]Group = undefined,
        blocks: [@bitSizeOf(usize)]Block = undefined,
        count: usize = 0,
        base: []const Hasher,
        base_log: u32,
        absorptions: usize = 0,

        /// Native rows `index & ~3 ..+4` of group `ordinal`, absorbed.
        fn ensure(self: *Self, ordinal: usize, index: usize) *const Lanes {
            const block_start = index & ~@as(usize, 3);
            const block = &self.blocks[ordinal];
            if (block.index == block_start) return &block.lanes;
            const group = self.groups[ordinal];
            const previous_log = if (ordinal == 0) self.base_log else self.groups[ordinal - 1].log;
            const shift: std.math.Log2Int(usize) = @intCast(group.log - previous_log + 1);
            var rows: [LANES]usize = undefined;
            var parents: [LANES]usize = undefined;
            for (&rows, &parents, 0..) |*row, *parent, lane| {
                row.* = block_start + lane;
                parent.* = ((row.* >> shift) << 1) + (row.* & 1);
            }
            if (ordinal == 0) {
                var sources: [LANES]*const Hasher = undefined;
                for (parents, &sources) |parent, *source| source.* = &self.base[parent];
                block.lanes = Lanes.load(sources);
            } else {
                self.gather(ordinal - 1, parents, &block.lanes);
            }
            block.lanes.updateM31Columns(group.columns, rows);
            self.absorptions += LANES * group.columns.len;
            block.index = block_start;
            return &block.lanes;
        }

        /// Four native rows of group `ordinal` may span two cached blocks;
        /// each lane is copied before the next lookup can replace its block.
        fn gather(self: *Self, ordinal: usize, rows: [LANES]usize, out: *Lanes) void {
            for (rows, 0..) |row, lane| {
                const source = self.ensure(ordinal, row);
                if (lane == 0) out.* = Lanes.geometry(source.shape());
                out.copyLane(lane, source, row & 3);
            }
        }

        fn leafLanes(self: *Self, final_log: u32, rows: [LANES]usize, out: *Lanes) void {
            const previous_log = if (self.count == 0) self.base_log else self.groups[self.count - 1].log;
            const shift: std.math.Log2Int(usize) = @intCast(final_log - previous_log + 1);
            var parents: [LANES]usize = undefined;
            for (rows, &parents) |row, *parent| parent.* = ((row >> shift) << 1) + (row & 1);
            if (self.count == 0) {
                var sources: [LANES]*const Hasher = undefined;
                for (parents, &sources) |parent, *source| source.* = &self.base[parent];
                out.* = Lanes.load(sources);
                return;
            }
            self.gather(self.count - 1, parents, out);
        }
    };
}

/// Returns null before touching outputs if the native domain cannot form a
/// complete four-row block or a base state is not an admitted lockstep lane.
/// The established scalar cache handles those cases.
pub fn finalize(comptime H: type, range: anytype) ?usize {
    if (comptime !supports(H)) return null;
    const Column = std.meta.Child(@TypeOf(range.tail_columns));
    var cache: Cache(Column) = .{ .base = range.base_hashers, .base_log = range.base_log_size };
    var begin: usize = 0;
    while (begin < range.tail_columns.len) {
        const log = range.tail_columns[begin].log_size;
        if (log == range.final_log_size) break;
        if (log < 2) return null;
        var end = begin + 1;
        while (end < range.tail_columns.len and range.tail_columns[end].log_size == log) : (end += 1) {}
        cache.groups[cache.count] = .{ .columns = range.tail_columns[begin..end], .log = log };
        cache.blocks[cache.count].index = std.math.maxInt(usize);
        cache.count += 1;
        begin = end;
    }
    if (!admits(range.base_hashers, range.tail_columns.len)) return null;
    const final_columns = range.tail_columns[begin..];
    var lanes: Lanes = undefined;
    var position = range.start;
    while (position < range.end) : (position += LANES) {
        const count = @min(@as(usize, LANES), range.end - position);
        // A short final block recomputes its last valid row in the spare
        // lanes; only `count` digests are stored.
        var rows: [LANES]usize = undefined;
        for (&rows, 0..) |*row, lane| row.* = @min(position + lane, range.end - 1);
        cache.leafLanes(range.final_log_size, rows, &lanes);
        lanes.updateM31Columns(final_columns, rows);
        const hashes = lanes.finalize();
        @memcpy(range.leaves[position..][0..count], hashes[0..count]);
        cache.absorptions += count * final_columns.len;
    }
    return cache.absorptions;
}

test "prover vcs_lifted BLAKE3 lockstep lanes match std streaming at every word boundary" {
    // 1100 words cross every block edge, four chunk ends and two parent merges.
    var scalar = [_]Hasher{Hasher.defaultWithInitialState()} ** LANES;
    var lanes = Lanes.load(.{ &scalar[0], &scalar[1], &scalar[2], &scalar[3] });
    for (0..1100) |i| {
        const digests = lanes.finalize();
        for (scalar, digests) |hasher, digest| try std.testing.expectEqualSlices(u8, &hasher.finalize(), &digest);
        if (i % 97 == 0) {
            // Reloading from the scalar states exercises pending blocks and stacks.
            lanes = Lanes.load(.{ &scalar[0], &scalar[1], &scalar[2], &scalar[3] });
        }
        var words: [LANES]u32 = undefined;
        for (&words, &scalar, 0..) |*word, *hasher, lane| {
            const value = M31.fromCanonical(@intCast((i * 7919 + lane * 104729 + 1) % core.fields.m31.Modulus));
            word.* = value.toU32();
            hasher.updateLeaf(&.{value});
        }
        lanes.absorbWord(words);
    }
    const digests = lanes.finalize();
    for (scalar, digests) |hasher, digest| try std.testing.expectEqualSlices(u8, &hasher.finalize(), &digest);
}
