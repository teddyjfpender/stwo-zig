//! M5 verification-key tables (stream canon-vk; design/riscv-proving-stack/
//! rv64-m5-binding.md §1-§4, plan §4.3): the recursion-VK table `T_rec` and
//! the native-VK table `T_nat`, each a fixed-depth Blake2s Merkle tree whose
//! root a fold or leaf circuit takes as a PUBLIC input. A child (or native)
//! VK is admitted by in-circuit membership against that root, so no circuit
//! ever hashes its own VK (the PCD self-VK break of plan §4.3), and the
//! receiver compares the root it derived from source with the root's public
//! statement once.
//!
//! Hash rule (canon-native's frozen `rv64-m5` v1 rule, /workspace/m3/
//! M5-INTERFACES.md canon-native §0, reference scripts/rv64_m5_canon_native_ref.py):
//!   H(tag, words) = Blake2s-256( Blake2s-256(ASCII tag) || LE32(words) )
//! Every message is a fixed-length list of u32 words for a fixed class.
//!
//! T_nat (canon-native §3, consumed unchanged):
//!   leaf_i  = H("rv64-m5-tnat-leaf/v1", [i, f, r, vkhash(8)])
//!   empty_i = H("rv64-m5-tnat-empty/v1", [i]),  i in [n, 2^D)
//!   node    = H("rv64-m5-merkle-node/v1", [left(8), right(8)])
//!   D       = max(1, ceil(log2 n));  header = H("rv64-m5-tnat-header/v1", [1, D, n, image, profile, rung_table_id, root])
//! T_rec (canon-vk, `rv64-m5-trec/v1`, same node rule):
//!   leaf_i  = H("rv64-m5-trec-leaf/v1", [i, kind, family, rung, arity, outer_profile, identity(8), fixed_root(8)])
//!   empty_i = H("rv64-m5-trec-empty/v1", [i]);  header = H("rv64-m5-trec-header/v1", [1, D, n, root(8)])
//!
//! Soundness notes (binding note checklist):
//! - leaf, empty and node tags are distinct, so a node is never a leaf and an
//!   empty slot is never a member (12, Z08); the T_rec and T_nat leaf tags
//!   differ, so a VK of one table is never admitted by the other;
//! - the leaf commits to its own index i, and the circuit computes the index
//!   word from exactly D Boolean-constrained path bits (b*b = b in QM31, a
//!   field), so the index is range-checked to the table by construction (5);
//! - entries are in strictly increasing canonical key order and duplicates
//!   are refused, so derivation is deterministic (6);
//! - every hash input is fixed-length per table (3).
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const core = @import("stwo_core");
const B = circuit.builder;
const Q = core.fields.qm31.QM31;
const Var = B.Var;
const Context = B.Context(Q);
pub const Word = B.wrappers.U32Wrapper(Var);
pub const Hash = B.blake.HashValue(Var);
const Blake2s = std.crypto.hash.blake2.Blake2s256;

pub const TAG_NAT_LEAF = "rv64-m5-tnat-leaf/v1";
pub const TAG_NAT_EMPTY = "rv64-m5-tnat-empty/v1";
pub const TAG_NAT_HEADER = "rv64-m5-tnat-header/v1";
pub const TAG_REC_LEAF = "rv64-m5-trec-leaf/v1";
pub const TAG_REC_EMPTY = "rv64-m5-trec-empty/v1";
pub const TAG_REC_HEADER = "rv64-m5-trec-header/v1";
pub const TAG_NODE = "rv64-m5-merkle-node/v1";
/// Largest admitted depth (2^16 slots): the circuit index word is a single
/// u16 limb, so its packed u32 form is the plain base-field sum of bits.
pub const MAX_DEPTH: u32 = 16;

pub fn tagDigest(comptime name: []const u8) [32]u8 {
    return comptime blk: {
        @setEvalBranchQuota(10_000_000);
        var out: [32]u8 = undefined;
        Blake2s.hash(name, &out, .{});
        break :blk out;
    };
}
fn tagWords(comptime name: []const u8) [8]u32 {
    return comptime blk: {
        const d = tagDigest(name);
        var out: [8]u32 = undefined;
        for (&out, 0..) |*w, i| w.* = std.mem.readInt(u32, d[4 * i ..][0..4], .little);
        break :blk out;
    };
}
pub fn digestWords(digest: [32]u8) [8]u32 {
    var out: [8]u32 = undefined;
    for (&out, 0..) |*w, i| w.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    return out;
}
/// Host `H(tag, words)`.
pub fn tagged(comptime name: []const u8, words: []const u32) [32]u8 {
    var h = Blake2s.init(.{});
    h.update(&tagDigest(name));
    var bytes: [4]u8 = undefined;
    for (words) |w| {
        std.mem.writeInt(u32, &bytes, w, .little);
        h.update(&bytes);
    }
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}
pub fn node(left: [32]u8, right: [32]u8) [32]u8 {
    var words: [16]u32 = undefined;
    words[0..8].* = digestWords(left);
    words[8..16].* = digestWords(right);
    return tagged(TAG_NODE, &words);
}
pub fn depthFor(n: usize) u32 {
    var d: u32 = 1;
    while ((@as(usize, 1) << @intCast(d)) < n) d += 1;
    return d;
}

/// Recursion circuit kinds. A leaf is per (family, rung); a fold is per arity.
pub const Kind = enum(u32) { leaf = 1, fold = 2, compress1 = 3, compress2 = 4 };

/// One `T_rec` entry: `leafhash_rec(kind, f, r, k, V_x)` of the binding note,
/// with `V_x` = (outer authority identity, outer FIXED root).
pub const RecEntry = struct {
    kind: Kind,
    /// Leaf family id (canon-native §1); 0 for non-leaves.
    family: u32 = 0,
    /// Leaf rung index (canon-native §1, 0..R-1); 0 for non-leaves.
    rung: u32 = 0,
    /// Fold arity k in 2..4; 0 for non-folds.
    arity: u32 = 0,
    /// Outer PCS profile, `@intFromEnum(om31.protocol.Profile) + 1`.
    profile: u32,
    identity: [32]u8,
    fixed_root: [32]u8,
    /// Payload words after the index word.
    pub const N_PAYLOAD = 21;
    pub fn payload(self: RecEntry) [N_PAYLOAD]u32 {
        var out: [N_PAYLOAD]u32 = undefined;
        out[0] = @intFromEnum(self.kind);
        out[1] = self.family;
        out[2] = self.rung;
        out[3] = self.arity;
        out[4] = self.profile;
        out[5..13].* = digestWords(self.identity);
        out[13..21].* = digestWords(self.fixed_root);
        return out;
    }
    fn key(self: RecEntry) [5]u32 {
        return .{ @intFromEnum(self.kind), self.family, self.rung, self.arity, self.profile };
    }
    pub fn validate(self: RecEntry) !void {
        if (self.profile == 0) return error.InvalidVkTableEntry;
        switch (self.kind) {
            .leaf => if (self.arity != 0 or self.rung >= 16) return error.InvalidVkTableEntry,
            .fold => if (self.family != 0 or self.rung != 0 or self.arity < 2 or self.arity > 4) return error.InvalidVkTableEntry,
            .compress1, .compress2 => if (self.family != 0 or self.rung != 0 or self.arity != 0) return error.InvalidVkTableEntry,
        }
    }
};

/// One `T_nat` entry (canon-native §3). `vk_hash` = H(native-vk, ...) is
/// computed by canon-native from (suite, FIXED identity/root, profile, structure).
pub const NatEntry = struct {
    family: u32,
    rung: u32,
    vk_hash: [32]u8,
    pub const N_PAYLOAD = 10;
    pub fn payload(self: NatEntry) [N_PAYLOAD]u32 {
        var out: [N_PAYLOAD]u32 = undefined;
        out[0] = self.family;
        out[1] = self.rung;
        out[2..10].* = digestWords(self.vk_hash);
        return out;
    }
    fn key(self: NatEntry) [2]u32 {
        return .{ self.family, self.rung };
    }
};

pub const Which = enum {
    nat,
    rec,
    fn leafTag(comptime self: Which) []const u8 {
        return switch (self) {
            .nat => TAG_NAT_LEAF,
            .rec => TAG_REC_LEAF,
        };
    }
    fn emptyTag(comptime self: Which) []const u8 {
        return switch (self) {
            .nat => TAG_NAT_EMPTY,
            .rec => TAG_REC_EMPTY,
        };
    }
};
pub fn leafHash(comptime which: Which, index: u32, payload: []const u32) [32]u8 {
    var words: [1 + RecEntry.N_PAYLOAD]u32 = undefined;
    std.debug.assert(payload.len <= RecEntry.N_PAYLOAD);
    words[0] = index;
    @memcpy(words[1..][0..payload.len], payload);
    return tagged(which.leafTag(), words[0 .. 1 + payload.len]);
}
pub fn emptyHash(comptime which: Which, index: u32) [32]u8 {
    return tagged(which.emptyTag(), &.{index});
}

/// A complete fixed-depth table (host side: derive-vk-tables, producers).
pub const Table = struct {
    /// levels[0] = 2^depth leaf hashes, levels[depth] = [root].
    levels: [MAX_DEPTH + 1][]const [32]u8 = [_][]const [32]u8{&.{}} ** (MAX_DEPTH + 1),
    depth: u32,
    count: usize,
    allocator: std.mem.Allocator,
    pub fn root(self: *const Table) [32]u8 {
        return self.levels[self.depth][0];
    }
    pub fn deinit(self: *Table) void {
        for (self.levels[0 .. self.depth + 1]) |level| self.allocator.free(level);
        self.* = undefined;
    }
    /// Sibling hashes bottom-up (the order `verifyMembership` reads).
    pub fn path(self: *const Table, a: std.mem.Allocator, index: usize) ![][32]u8 {
        if (index >= self.count) return error.VkTableIndexOutOfRange;
        const out = try a.alloc([32]u8, self.depth);
        var at = index;
        for (out, self.levels[0..self.depth]) |*sibling, level| {
            sibling.* = level[at ^ 1];
            at >>= 1;
        }
        return out;
    }
    fn fromLeaves(comptime which: Which, a: std.mem.Allocator, leaves: []const [32]u8) !Table {
        if (leaves.len == 0) return error.EmptyVkTable;
        const depth = depthFor(leaves.len);
        if (depth > MAX_DEPTH) return error.VkTableFull;
        var self: Table = .{ .depth = depth, .count = leaves.len, .allocator = a };
        var built: usize = 0;
        errdefer for (self.levels[0..built]) |level| a.free(level);
        const bottom = try a.alloc([32]u8, @as(usize, 1) << @intCast(depth));
        for (bottom, 0..) |*slot, i| slot.* = if (i < leaves.len) leaves[i] else emptyHash(which, @intCast(i));
        self.levels[0] = bottom;
        built = 1;
        for (1..depth + 1) |d| {
            const below = self.levels[d - 1];
            const level = try a.alloc([32]u8, below.len / 2);
            for (level, 0..) |*n, i| n.* = node(below[2 * i], below[2 * i + 1]);
            self.levels[d] = level;
            built += 1;
        }
        return self;
    }
};

fn lessKey(comptime N: usize, a: [N]u32, b: [N]u32) bool {
    for (a, b) |x, y| if (x != y) return x < y;
    return false;
}
/// `T_rec`: entries valid and in strictly increasing (kind, family, rung, arity, profile).
pub fn buildRec(a: std.mem.Allocator, entries: []const RecEntry) !Table {
    const leaves = try a.alloc([32]u8, entries.len);
    defer a.free(leaves);
    for (entries, 0..) |entry, i| {
        try entry.validate();
        if (i > 0 and !lessKey(5, entries[i - 1].key(), entry.key())) return error.VkTableOrder;
        leaves[i] = leafHash(.rec, @intCast(i), &entry.payload());
    }
    return Table.fromLeaves(.rec, a, leaves);
}
/// `T_nat`: entries in strictly increasing (family, rung) — canon-native §3.
pub fn buildNat(a: std.mem.Allocator, entries: []const NatEntry) !Table {
    const leaves = try a.alloc([32]u8, entries.len);
    defer a.free(leaves);
    for (entries, 0..) |entry, i| {
        if (i > 0 and !lessKey(2, entries[i - 1].key(), entry.key())) return error.VkTableOrder;
        leaves[i] = leafHash(.nat, @intCast(i), &entry.payload());
    }
    return Table.fromLeaves(.nat, a, leaves);
}
pub fn recHeader(table: *const Table) [32]u8 {
    var words: [11]u32 = undefined;
    words[0] = 1;
    words[1] = table.depth;
    words[2] = @intCast(table.count);
    words[3..11].* = digestWords(table.root());
    return tagged(TAG_REC_HEADER, &words);
}
pub fn natHeader(table: *const Table, image: [32]u8, profile_identity: [32]u8, rung_table_id: [32]u8) [32]u8 {
    var words: [35]u32 = undefined;
    words[0] = 1;
    words[1] = table.depth;
    words[2] = @intCast(table.count);
    words[3..11].* = digestWords(image);
    words[11..19].* = digestWords(profile_identity);
    words[19..27].* = digestWords(rung_table_id);
    words[27..35].* = digestWords(table.root());
    return tagged(TAG_NAT_HEADER, &words);
}

// ---------------------------------------------------------------------------
// In-circuit side.
// ---------------------------------------------------------------------------

pub fn constWord(ctx: *Context, value: u32) !Word {
    return B.wrappers.constU32(Q, ctx, value);
}
pub fn guessWord(ctx: *Context, value: u32) !Word {
    return B.wrappers.guessU32(Q, ctx, B.wrappers.u32Value(Q, value));
}
/// A guessed digest: eight range-checked u32 words (u16 limb pairs).
pub fn guessHash(ctx: *Context, digest: [32]u8) !Hash {
    var out: Hash = undefined;
    for (&out.words, digestWords(digest)) |*w, value| w.* = try guessWord(ctx, value);
    return out;
}
pub fn constHash(ctx: *Context, digest: [32]u8) !Hash {
    var out: Hash = undefined;
    for (&out.words, digestWords(digest)) |*w, value| w.* = try constWord(ctx, value);
    return out;
}
/// A guessed Boolean: b * b = b. QM31 is a field, so b in {0, 1}.
pub fn guessBit(ctx: *Context, value: bool) !Var {
    const bit = try ctx.guess(Q.fromU32Unchecked(@intFromBool(value), 0, 0, 0));
    try ctx.eq(try ctx.mul(bit, bit), bit);
    return bit;
}
/// In-circuit `H(tag, words)`: the tag digest is eight constant words.
pub fn taggedCircuit(ctx: *Context, comptime name: []const u8, words: []const Word) !Hash {
    const all = try ctx.scratch().alloc(Word, 8 + words.len);
    for (all[0..8], tagWords(name)) |*w, value| w.* = try constWord(ctx, value);
    @memcpy(all[8..], words);
    return B.blake.blake2sU32s(Q, ctx, all, 4 * all.len);
}
pub fn nodeCircuit(ctx: *Context, left: Hash, right: Hash) !Hash {
    var words: [16]Word = undefined;
    @memcpy(words[0..8], &left.words);
    @memcpy(words[8..], &right.words);
    return taggedCircuit(ctx, TAG_NODE, &words);
}

/// Membership witness for one leaf: path bits (LSB first) and siblings.
pub const Witness = struct {
    bits: []const Var,
    siblings: []const Hash,
    /// Producer side: guessed index bits and siblings of `index`.
    pub fn guess(ctx: *Context, table: *const Table, index: usize) !Witness {
        return init(ctx, table, index, false);
    }
    /// A constant index (`T_nat` at a leaf of fixed (f, r)): constant bits.
    pub fn guessAtConstantIndex(ctx: *Context, table: *const Table, index: usize) !Witness {
        return init(ctx, table, index, true);
    }
    fn init(ctx: *Context, table: *const Table, index: usize, constant: bool) !Witness {
        const path = try table.path(ctx.scratch(), index);
        const bits = try ctx.scratch().alloc(Var, table.depth);
        const siblings = try ctx.scratch().alloc(Hash, table.depth);
        for (bits, 0..) |*bit, d| {
            const set = (index >> @intCast(d)) & 1 == 1;
            bit.* = if (constant) (if (set) ctx.one() else ctx.zero()) else try guessBit(ctx, set);
        }
        for (siblings, path) |*sibling, value| sibling.* = try guessHash(ctx, value);
        return .{ .bits = bits, .siblings = siblings };
    }
};

/// Asserts `H(leaf_tag, [index, payload])` is leaf `index` of the tree whose
/// root is the `root` wire, with the index word derived from the path bits.
/// `depth` is a circuit constant (`witness.bits.len`).
pub fn verifyMembership(ctx: *Context, comptime which: Which, depth: u32, payload: []const Word, witness: Witness, root: Hash) !void {
    if (depth == 0 or depth > MAX_DEPTH or witness.bits.len != depth or witness.siblings.len != depth) return error.InvalidVkTableWitness;
    // index = sum_d bit_d * 2^d < 2^16: the low u16 limb of the packed word.
    var index = ctx.zero();
    for (witness.bits, 0..) |bit, d| {
        const weight = try ctx.constant(Q.fromU32Unchecked(@as(u32, 1) << @intCast(d), 0, 0, 0));
        index = try ctx.add(index, try ctx.mul(bit, weight));
    }
    const words = try ctx.scratch().alloc(Word, 1 + payload.len);
    words[0] = .newUnsafe(index);
    @memcpy(words[1..], payload);
    var current = try taggedCircuit(ctx, which.leafTag(), words);
    for (witness.bits, witness.siblings) |bit, sibling| {
        var left: Hash = undefined;
        var right: Hash = undefined;
        for (current.words, sibling.words, &left.words, &right.words) |c, s, *l, *r| {
            const flipped = try B.ops.condFlipU32(Q, ctx, bit, c, s);
            l.* = flipped[0];
            r.* = flipped[1];
        }
        current = try nodeCircuit(ctx, left, right);
    }
    for (current.words, root.words) |got, want| try ctx.eq(got.get(), want.get());
}

/// Guessed, range-checked payload wires of a `RecEntry`; callers pin the
/// fields that are class constants with `ctx.eq`.
pub fn guessRecPayload(ctx: *Context, entry: RecEntry) ![RecEntry.N_PAYLOAD]Word {
    var out: [RecEntry.N_PAYLOAD]Word = undefined;
    for (&out, entry.payload()) |*w, value| w.* = try guessWord(ctx, value);
    return out;
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

fn hex(comptime text: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;
    return out;
}

test "vk table: T_nat reproduces canon-native v1 golden vectors" {
    // vectors/rv64-m5/canon-native-v1-vectors.json @ codex/rv64-m5-canon-native e3fdff934.
    const a = std.testing.allocator;
    try std.testing.expectEqualSlices(u8, &hex("5ad650a926f613d1334906d6e45baf25826d807baa4831f47364209dbc5f5cf0"), &tagDigest(TAG_NAT_LEAF));
    try std.testing.expectEqualSlices(u8, &hex("941148b446eb12cf769df8785dbfebf280bbb7c1c05d01ab9e9fbcb7fef3140b"), &tagDigest(TAG_NODE));
    const order = [_][2]u32{ .{ 1, 0 }, .{ 1, 1 }, .{ 1, 2 }, .{ 16, 0 }, .{ 16, 1 }, .{ 16, 2 } };
    const vks = [_][32]u8{
        hex("72301064f28a874dbdaf2aa9e732a288f6c92b1c6e80ea7f9bcdb82a6c84e592"),
        hex("55705cac57a1242d2db14727ced88efebff415bcee729c5b7e0f8a226c8c4c55"),
        hex("0fc1d048640bd974e3f1fad6bd968044e28ded94fd1eaa0b16102f9a03687cf7"),
        hex("8869520e74be58d6c3ecd3346256c6c0a5913262ada0d9c8b8f92649b828c72b"),
        hex("a50142784bb12edf5150ad6e071efbef87ad6ada2fb18088ba9ac843a5814428"),
        hex("4f98ce42e4de618f07e2081309bcb8967bb05de0b82689f1c834217ac5b93741"),
    };
    const leaves = [_][32]u8{
        hex("795fcf6f1d3f6d7e30df0255901c56b5d333f144e17ca8f084cce532bd12698d"),
        hex("38706699a1e0f5c2bda2827f5f7c50b5878aaef27753346a732af0524d064d57"),
        hex("229b214388087efc696ccd16be10b9c015394539917d12061de9bfedf2c0c53f"),
        hex("15b35f744f3f765856ab20751d788bacd3da5ceceb017ca53f641bc790dc79a3"),
        hex("62630dcc9f45543b01b4909684cc3da385d371245f162b77d92e6b20d3e667f9"),
        hex("bbcb4737dca63ebbcb41ed2b9c6fc2db0e5b402ff3c25653e5a4668f5dac2d0f"),
    };
    var entries: [6]NatEntry = undefined;
    for (&entries, order, vks, leaves, 0..) |*e, fr, vk, leaf, i| {
        e.* = .{ .family = fr[0], .rung = fr[1], .vk_hash = vk };
        try std.testing.expectEqualSlices(u8, &leaf, &leafHash(.nat, @intCast(i), &e.payload()));
    }
    var table = try buildNat(a, &entries);
    defer table.deinit();
    try std.testing.expectEqual(@as(u32, 3), table.depth);
    try std.testing.expectEqualSlices(u8, &hex("ccd12023ad6daf17448c44a733a5c026436ad009a0c389588b1306125f4cea2f"), &table.root());
    const path = try table.path(a, 4);
    defer a.free(path);
    const want_path = [_][32]u8{
        hex("bbcb4737dca63ebbcb41ed2b9c6fc2db0e5b402ff3c25653e5a4668f5dac2d0f"),
        hex("e2217b76b6b2b2584d937e722ef8c93f69f2206051c6d6a03e16907d94a9d245"),
        hex("55bfebbf5f890488c3f1c5ab2f35064d3fdb0a85fc37c89c1207cdbdb26ac72f"),
    };
    for (path, want_path) |got, want| try std.testing.expectEqualSlices(u8, &want, &got);
    var seq: [3][32]u8 = undefined;
    for (seq[0..2], [_]u8{ 33, 1 }) |*s, start| for (s, 0..) |*b, i| {
        b.* = @truncate(start + i);
    };
    seq[2] = hex("914e734dc16dae1788447b8942fae77738efbd86a7f8863756d2b3f6d52feb45");
    try std.testing.expectEqualSlices(u8, &hex("20fdcc48035495dfc0a0e01df763e6b685819ca40734da415dc06b1f79705b91"), &natHeader(&table, seq[0], seq[1], seq[2]));
}

fn sampleRec() [5]RecEntry {
    var out: [5]RecEntry = undefined;
    const kinds = [_]struct { Kind, u32, u32, u32 }{ .{ .leaf, 1, 0, 0 }, .{ .leaf, 1, 2, 0 }, .{ .leaf, 16, 0, 0 }, .{ .fold, 0, 0, 2 }, .{ .fold, 0, 0, 4 } };
    for (&out, kinds, 0..) |*e, k, i| {
        var id: [32]u8 = @splat(@intCast(i + 1));
        var root: [32]u8 = @splat(@intCast(0x80 + i));
        id[0] = 0xff;
        root[31] = 0xfe;
        e.* = .{ .kind = k[0], .family = k[1], .rung = k[2], .arity = k[3], .profile = 1, .identity = id, .fixed_root = root };
    }
    return out;
}

test "vk table: T_rec canonical order, duplicates and validation are refused" {
    const a = std.testing.allocator;
    var entries = sampleRec();
    var table = try buildRec(a, &entries);
    defer table.deinit();
    var again = try buildRec(a, &entries);
    defer again.deinit();
    try std.testing.expectEqualSlices(u8, &table.root(), &again.root());
    try std.testing.expectEqualSlices(u8, &recHeader(&table), &recHeader(&again));
    std.mem.swap(RecEntry, &entries[0], &entries[1]);
    try std.testing.expectError(error.VkTableOrder, buildRec(a, &entries));
    entries = sampleRec();
    entries[1] = entries[0];
    try std.testing.expectError(error.VkTableOrder, buildRec(a, &entries));
    entries = sampleRec();
    entries[4].arity = 5;
    try std.testing.expectError(error.InvalidVkTableEntry, buildRec(a, &entries));
    entries = sampleRec();
    entries[0].profile = 0;
    try std.testing.expectError(error.InvalidVkTableEntry, buildRec(a, &entries));
    entries = sampleRec();
    entries[4].identity[31] ^= 1;
    var changed = try buildRec(a, &entries);
    defer changed.deinit();
    try std.testing.expect(!std.mem.eql(u8, &table.root(), &changed.root()));
    try std.testing.expectError(error.EmptyVkTable, buildRec(a, &.{}));
}

test "vk table: host path recomputes the root; leaf, empty and node tags are separated" {
    const a = std.testing.allocator;
    const entries = sampleRec();
    var table = try buildRec(a, &entries);
    defer table.deinit();
    try std.testing.expectEqual(@as(u32, 3), table.depth);
    for (entries, 0..) |entry, index| {
        var current = leafHash(.rec, @intCast(index), &entry.payload());
        const path = try table.path(a, index);
        defer a.free(path);
        for (path, 0..) |sibling, d| current = if ((index >> @intCast(d)) & 1 == 1) node(sibling, current) else node(current, sibling);
        try std.testing.expectEqualSlices(u8, &table.root(), &current);
    }
    try std.testing.expectError(error.VkTableIndexOutOfRange, table.path(a, entries.len));
    // Z08: a level-1 node preimage hashed under the leaf tag differs from the node.
    var pair: [16]u32 = undefined;
    pair[0..8].* = digestWords(table.levels[0][0]);
    pair[8..16].* = digestWords(table.levels[0][1]);
    try std.testing.expect(!std.mem.eql(u8, &tagged(TAG_REC_LEAF, &pair), &table.levels[1][0]));
    // The same payload under the native leaf tag is a different leaf.
    try std.testing.expect(!std.mem.eql(u8, &leafHash(.nat, 0, &entries[0].payload()), &leafHash(.rec, 0, &entries[0].payload())));
}

fn membershipCircuit(payload: [RecEntry.N_PAYLOAD]u32, table: *const Table, index: usize, root: [32]u8, flip_bit: ?usize) !bool {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    var words: [RecEntry.N_PAYLOAD]Word = undefined;
    for (&words, payload) |*w, value| w.* = try guessWord(&ctx, value);
    var witness = try Witness.guess(&ctx, table, index);
    if (flip_bit) |d| {
        const bits = try ctx.scratch().dupe(Var, witness.bits);
        bits[d] = try guessBit(&ctx, (index >> @intCast(d)) & 1 == 0);
        witness.bits = bits;
    }
    const root_wire = try guessHash(&ctx, root);
    try verifyMembership(&ctx, .rec, table.depth, &words, witness, root_wire);
    return ctx.isCircuitValid();
}

test "vk table: in-circuit membership agrees with the host and rejects forgeries" {
    const a = std.testing.allocator;
    const entries = sampleRec();
    var table = try buildRec(a, &entries);
    defer table.deinit();
    // Accept: every member at its own index (the circuit leaf hash equals the host's).
    for (entries, 0..) |entry, index| try std.testing.expect(try membershipCircuit(entry.payload(), &table, index, table.root(), null));
    // G03: a VK not in the table (identity word changed).
    var forged = entries[3];
    forged.identity[0] ^= 0x40;
    try std.testing.expect(!try membershipCircuit(forged.payload(), &table, 3, table.root(), null));
    // G05: arity relabel (the F_2 entry presented as F_4 at the F_2 index).
    var relabel = entries[3];
    relabel.arity = 4;
    try std.testing.expect(!try membershipCircuit(relabel.payload(), &table, 3, table.root(), null));
    // A member presented at another index (one path bit flipped).
    try std.testing.expect(!try membershipCircuit(entries[1].payload(), &table, 1, table.root(), 0));
    // G02: a different table root.
    var other = entries;
    other[0].fixed_root[5] ^= 1;
    var other_table = try buildRec(a, &other);
    defer other_table.deinit();
    try std.testing.expect(!try membershipCircuit(entries[1].payload(), &table, 1, other_table.root(), null));
}

test "vk table: a non-Boolean index bit is unsatisfiable" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    _ = try guessBit(&ctx, true);
    const bit = try ctx.guess(Q.fromU32Unchecked(2, 0, 0, 0));
    try ctx.eq(try ctx.mul(bit, bit), bit);
    try std.testing.expect(!try ctx.isCircuitValid());
}

test "vk table: T_nat membership at a constant index" {
    const a = std.testing.allocator;
    var entries: [3]NatEntry = undefined;
    for (&entries, 0..) |*e, i| e.* = .{ .family = 1, .rung = @intCast(i), .vk_hash = @splat(@intCast(9 + i)) };
    var table = try buildNat(a, &entries);
    defer table.deinit();
    for (entries, 0..) |entry, index| {
        var ctx = try Context.init(a, 0);
        defer ctx.deinit();
        var words: [NatEntry.N_PAYLOAD]Word = undefined;
        for (&words, entry.payload()) |*w, value| w.* = try guessWord(&ctx, value);
        const witness = try Witness.guessAtConstantIndex(&ctx, &table, index);
        try verifyMembership(&ctx, .nat, table.depth, &words, witness, try guessHash(&ctx, table.root()));
        try std.testing.expect(try ctx.isCircuitValid());
    }
    // G01 (rung): the rung-0 VK at the constant index of rung 1 is refused.
    var ctx = try Context.init(a, 0);
    defer ctx.deinit();
    var words: [NatEntry.N_PAYLOAD]Word = undefined;
    for (&words, entries[0].payload()) |*w, value| w.* = try guessWord(&ctx, value);
    const witness = try Witness.guessAtConstantIndex(&ctx, &table, 1);
    try verifyMembership(&ctx, .nat, table.depth, &words, witness, try guessHash(&ctx, table.root()));
    try std.testing.expect(!try ctx.isCircuitValid());
}
