//! Chunked LDE -> Merkle streaming plan for resident MAIN/INTER/FIXED commits.
//!
//! The lifted Merkle leaf of row r absorbs every column, in stable ascending
//! height order, into ONE Blake2s message. Blake2s is a sequential sponge over
//! 16-word blocks with a distinct final-block flag, so the message can be split
//! at ANY column boundary: an unfinalized per-row state (hash + pending block,
//! `ProgressiveState`, 24 words) carries everything the remaining columns need.
//! This is exactly the mechanism the established tree kernel already uses
//! between distinct heights (`native_height_leaves` in trace.cu); streaming only
//! adds more boundaries inside one height. Hence the root is a function of the
//! column values and their order alone, never of the chunk schedule.
//!
//! The plan therefore never materialises the full LDE. Peak scratch is
//!   aux (twiddles + log sizes) + one chunk of evaluations + two state banks,
//! and the Merkle tree (only its root is consumed at commit time) is built in
//! the bank that is dead after the final absorption. Everything here is pure
//! and host-only so the same function predicts the peak for any geometry.
const std = @import("std");

/// Unfinalized Blake2s state per row: 8 hash words + 16 pending words.
pub const state_words: usize = 24;
/// Mixed-leaf launch descriptors carry at most this many segments.
pub const max_segments: usize = 96;
/// Bank/chunk offsets are rounded to 256 bytes (Hash needs 32-byte alignment).
pub const align_words: usize = 64;
/// Default evaluation chunk: 2^27 words = 512 MiB.
pub const default_chunk_words: usize = 1 << 27;

pub const Call = struct {
    /// Sorted column range [first, end) absorbed by this call.
    first: u32,
    end: u32,
    /// Output rows: the LDE rows of the chunk's tallest column (the last one).
    size: u32,
    /// Columns absorbed before this call (Blake2s pending-block alignment).
    absorbed: u32,
    /// Bank holding this call's seed state (null for the first call).
    seed_bank: ?u1,
    /// Rows of the seed state (0 for the first call).
    seed_size: u32,
    /// Bank receiving the unfinalized state, or holding the leaf hashes and the
    /// complete Merkle tree when `final`.
    out_bank: u1,
    final: bool,
    /// Evaluation words this chunk occupies (sum of its columns' LDE rows).
    chunk_words: usize,
};

pub const Plan = struct {
    calls: []Call,
    /// Largest chunk of evaluations ever live at once.
    chunk_words: usize,
    /// Words of each ping-pong bank (max of states written and the tree).
    bank_words: [2]usize,
    /// Leaf rows (LDE rows of the tallest column) and full tree words.
    leaves: u32,
    tree_words: usize,
    pub fn deinit(self: *Plan, a: std.mem.Allocator) void {
        a.free(self.calls);
        self.* = undefined;
    }
    /// Device scratch beyond the retained coefficients and the aux plane.
    pub fn scratchWords(self: Plan) usize {
        return alignUp(self.chunk_words) + alignUp(self.bank_words[0]) + alignUp(self.bank_words[1]);
    }
    pub fn chunkOffset(_: Plan) usize {
        return 0;
    }
    pub fn bankOffset(self: Plan, bank: u1) usize {
        return alignUp(self.chunk_words) + if (bank == 1) alignUp(self.bank_words[0]) else 0;
    }
};

pub fn alignUp(words: usize) usize {
    return std.mem.alignForward(usize, words, align_words);
}

pub fn treeWords(leaves: u32) usize {
    return ((@as(usize, 2) * leaves) - 1) * 8;
}

/// `rows` are the LDE rows of every column in the stable ascending commit
/// order (power-of-two, nondecreasing). `budget_words` bounds one chunk of
/// evaluations, except that one column taller than the budget forms its own
/// chunk (a single column is the indivisible LDE unit).
pub fn plan(a: std.mem.Allocator, rows: []const u32, budget_words: usize) !Plan {
    if (rows.len == 0 or rows.len > 65535 or budget_words == 0) return error.InvalidTraceStreamPlan;
    var previous: u32 = 0;
    for (rows) |r| {
        if (r < 2 or !std.math.isPowerOfTwo(r) or r < previous) return error.InvalidTraceStreamPlan;
        previous = r;
    }
    var calls: std.ArrayList(Call) = .empty;
    errdefer calls.deinit(a);
    var first: usize = 0;
    var absorbed: u32 = 0;
    var result = Plan{ .calls = &.{}, .chunk_words = 0, .bank_words = .{ 0, 0 }, .leaves = rows[rows.len - 1], .tree_words = treeWords(rows[rows.len - 1]) };
    while (first < rows.len) {
        var end = first;
        var words: usize = 0;
        var segments: usize = 0;
        while (end < rows.len) : (end += 1) {
            const next = words + rows[end];
            const new_segment = end == first or rows[end] != rows[end - 1];
            if (end > first and (next > budget_words or (new_segment and segments == max_segments))) break;
            words = next;
            if (new_segment) segments += 1;
        }
        const index = calls.items.len;
        const out: u1 = @intCast(index & 1);
        const seed: ?u1 = if (index == 0) null else @as(u1, @intCast((index - 1) & 1));
        const seed_size: u32 = if (index == 0) 0 else calls.items[index - 1].size;
        const final = end == rows.len;
        const size = rows[end - 1];
        try calls.append(a, .{ .first = @intCast(first), .end = @intCast(end), .size = size, .absorbed = absorbed, .seed_bank = seed, .seed_size = seed_size, .out_bank = out, .final = final, .chunk_words = words });
        result.chunk_words = @max(result.chunk_words, words);
        const written = if (final) result.tree_words else @as(usize, size) * state_words;
        result.bank_words[out] = @max(result.bank_words[out], written);
        absorbed += @intCast(end - first);
        first = end;
    }
    result.calls = try calls.toOwnedSlice(a);
    return result;
}

/// Established (unstreamed) scratch for the same commit, in words: the arena
/// holding every LDE evaluation, twiddles and descriptors, plus the full tree
/// with its two prefix banks at the largest nonfinal heights. Used only to
/// report before/after peaks; `aux_words` is the twiddle/descriptor share.
pub fn legacyScratchWords(rows: []const u32, aux_words: usize) usize {
    var evaluations: usize = 0;
    for (rows) |r| evaluations += r;
    var banks = [2]usize{ 0, 0 };
    var next: u1 = 0;
    var last: u32 = 0;
    for (rows[0 .. rows.len - 1], 0..) |r, i| {
        if (r != rows[i + 1] and r != last) {
            banks[next] = r;
            next ^= 1;
            last = r;
        }
    }
    return evaluations + aux_words + treeWords(rows[rows.len - 1]) + (banks[0] + banks[1]) * state_words;
}

/// Reference model of the absorption the device performs, for host tests: an
/// incremental Blake2s over each row's lifted words must equal one-shot
/// hashing regardless of the chunk schedule. The device additionally prepends
/// a 64-byte domain prefix (leaf tag), which is schedule-independent too.
fn liftedRow(row: u32, leaves: u32, source: u32) u32 {
    if (source == leaves) return row;
    const ratio = std.math.log2_int(u32, leaves / source);
    return ((row >> @intCast(ratio + 1)) << 1) | (row & 1);
}

test "plan covers every column once, chains seeds and fits the tree" {
    const a = std.testing.allocator;
    const rows = [_]u32{ 4, 4, 8, 16, 16, 16, 16, 16, 32, 32, 32 };
    for ([_]usize{ 1, 7, 16, 33, 64, 1000 }) |budget| {
        var p = try plan(a, &rows, budget);
        defer p.deinit(a);
        var next: u32 = 0;
        for (p.calls, 0..) |c, i| {
            try std.testing.expectEqual(next, c.first);
            try std.testing.expectEqual(next, c.absorbed);
            try std.testing.expect(c.end > c.first);
            try std.testing.expectEqual(rows[c.end - 1], c.size);
            if (i == 0) {
                try std.testing.expect(c.seed_bank == null);
            } else {
                try std.testing.expectEqual(p.calls[i - 1].out_bank, c.seed_bank.?);
                try std.testing.expectEqual(p.calls[i - 1].size, c.seed_size);
                try std.testing.expect(c.seed_bank.? != c.out_bank);
                try std.testing.expect(c.seed_size <= c.size);
            }
            try std.testing.expect(c.chunk_words <= @max(budget, c.size));
            try std.testing.expectEqual(i + 1 == p.calls.len, c.final);
            next = c.end;
        }
        try std.testing.expectEqual(@as(u32, rows.len), next);
        const last = p.calls[p.calls.len - 1];
        try std.testing.expect(p.bank_words[last.out_bank] >= p.tree_words);
        try std.testing.expectEqual(@as(u32, 32), p.leaves);
    }
}

test "streaming peak is bounded independently of total evaluation width" {
    const a = std.testing.allocator;
    // 600 columns at 2^25 LDE rows: the established arena needs every one.
    const rows = try a.alloc(u32, 600);
    defer a.free(rows);
    @memset(rows, 1 << 25);
    var p = try plan(a, rows, default_chunk_words);
    defer p.deinit(a);
    try std.testing.expectEqual(@as(usize, 150), p.calls.len);
    try std.testing.expectEqual(default_chunk_words, p.chunk_words);
    try std.testing.expectEqual(@as(usize, 24 << 25), p.bank_words[0]);
    try std.testing.expect(p.scratchWords() * 10 < legacyScratchWords(rows, 0));
}

test "invalid geometry is rejected" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.InvalidTraceStreamPlan, plan(a, &.{ 8, 4 }, 16));
    try std.testing.expectError(error.InvalidTraceStreamPlan, plan(a, &.{ 3 }, 16));
    try std.testing.expectError(error.InvalidTraceStreamPlan, plan(a, &.{}, 16));
}

test "chunked progressive Blake2s equals one-shot absorption for every schedule" {
    // Host model of the device contract: per row, words are absorbed in column
    // order; the lifted word of a shorter column is read at its lifted row.
    const a = std.testing.allocator;
    const rows = [_]u32{ 2, 4, 4, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8 };
    const leaves: u32 = 8;
    var values: [rows.len][8]u32 = undefined;
    var prng = std.Random.DefaultPrng.init(7);
    for (&values) |*column| for (column) |*v| {
        v.* = prng.random().int(u32) & 0x7fffffff;
    };
    var expected: [leaves][32]u8 = undefined;
    for (0..leaves) |row| {
        var h = std.crypto.hash.blake2.Blake2s256.init(.{});
        for (rows, 0..) |r, c| h.update(std.mem.asBytes(&values[c][liftedRow(@intCast(row), leaves, r)]));
        h.final(&expected[row]);
    }
    for ([_]usize{ 1, 2, 5, 8, 9, 17, 100 }) |budget| {
        var p = try plan(a, &rows, budget);
        defer p.deinit(a);
        var states: [leaves]std.crypto.hash.blake2.Blake2s256 = undefined;
        for (&states) |*s| s.* = std.crypto.hash.blake2.Blake2s256.init(.{});
        for (p.calls) |c| for (0..leaves) |row| for (c.first..c.end) |col| {
            states[row].update(std.mem.asBytes(&values[col][liftedRow(@intCast(row), leaves, rows[col])]));
        };
        for (0..leaves) |row| {
            var got: [32]u8 = undefined;
            states[row].final(&got);
            try std.testing.expectEqualSlices(u8, &expected[row], &got);
        }
    }
}
