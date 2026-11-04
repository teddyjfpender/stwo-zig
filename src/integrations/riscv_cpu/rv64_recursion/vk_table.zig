//! M5 verification-key tables (stream canon-vk; design/riscv-proving-stack/
//! rv64-m5-binding.md §1-§4, plan §4.3): the recursion-VK table `T_rec` and
//! the native-VK table `T_nat`, each a fixed-depth Blake2s Merkle tree whose
//! root a fold or leaf circuit takes as a PUBLIC input. A child (or native)
//! VK is admitted by in-circuit membership against that root, so no circuit
//! ever hashes its own VK (the PCD self-VK break of plan §4.3), and the
//! receiver compares the root it derived from source with the root's public
//! statement once.
//!
//! Encoding (frozen as `rv64-m5-vk-table/v1` in /workspace/m3/M5-INTERFACES.md):
//! - Every leaf is a FIXED-LENGTH sequence of u32 words that begins with a
//!   table tag word and the schema version. Its hash is the native Merkle
//!   leaf hash `Blake2s(LEAF_PREFIX || LE32(words))`; internal nodes are
//!   `Blake2s(NODE_PREFIX || left || right)` (`core/vcs_lifted/blake2_merkle`
//!   domain-prefixed protocol). LEAF_PREFIX != NODE_PREFIX, so a node can
//!   never be presented as a leaf or vice versa (binding note checklist 12,
//!   corpus Z08), and the tag word separates `T_rec`, `T_nat` and the null
//!   padding leaves from each other and from every native PCS tree.
//! - Depth is a constant (`DEPTH`); unused slots hold the null leaf
//!   `[TAG_NULL, VERSION, slot]`. The circuit fixes word 0 of the admitted
//!   leaf to the table's own tag as a CONSTANT, so a null slot is never
//!   admitted (except with a Blake2s collision).
//! - Entries are in strictly increasing canonical key order; the table
//!   refuses duplicates, so derivation is deterministic and reproducible.
//! - The membership index is a guessed bit vector of exactly `DEPTH`
//!   Boolean-constrained bits (b*b = b over QM31, a field, forces b in {0,1}),
//!   so it is range-checked to the table size by construction (checklist 5).
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const core = @import("stwo_core");
const B = circuit.builder;
const Merkle = circuit.native_verifier.merkle;
const Q = core.fields.qm31.QM31;
const Var = B.Var;
const Context = B.Context(Q);
pub const Word = B.wrappers.U32Wrapper(Var);
pub const Hash = B.blake.HashValue(Var);
const blake2_merkle = core.vcs_lifted.blake2_merkle;

pub const VERSION: u32 = 1;
/// Fixed tree depth of both tables: 64 slots. Recursion classes are
/// families x rungs leaves + 3 fold arities + 2 compress layers; the M4.0
/// census gives <= 46 native classes with 4 rungs (M40-FINDINGS.md).
pub const DEPTH: usize = 6;
pub const SLOTS: usize = 1 << DEPTH;
/// "r5vk": recursion-VK leaf; "r5nv": native-VK leaf; "r5nl": null slot.
pub const TAG_REC: u32 = 0x6b763572;
pub const TAG_NAT: u32 = 0x766e3572;
pub const TAG_NULL: u32 = 0x6c6e3572;

/// Recursion circuit kinds. A leaf is per (family, rung); a fold is per arity.
pub const Kind = enum(u32) { leaf = 1, fold = 2, compress1 = 3, compress2 = 4 };

/// One `T_rec` entry: `leafhash_rec(kind, f, r, k, V_x)` of the binding note,
/// with `V_x` = (authority identity, FIXED root) and the outer profile id.
pub const RecEntry = struct {
    kind: Kind,
    /// Leaf family id (canon-native's class-key schema); 0 for non-leaves.
    family: u32 = 0,
    /// Leaf rung (log2 of the canonical native height); 0 for non-leaves.
    rung: u32 = 0,
    /// Fold arity k in 2..4; 0 for non-folds.
    arity: u32 = 0,
    /// Outer PCS profile, `@intFromEnum(om31.protocol.Profile) + 1`.
    profile: u32,
    identity: [32]u8,
    fixed_root: [32]u8,
    pub const N_WORDS = 23;
    pub fn words(self: RecEntry) [N_WORDS]u32 {
        var out: [N_WORDS]u32 = undefined;
        out[0] = TAG_REC;
        out[1] = VERSION;
        out[2] = @intFromEnum(self.kind);
        out[3] = self.family;
        out[4] = self.rung;
        out[5] = self.arity;
        out[6] = self.profile;
        digestWords(out[7..15], self.identity);
        digestWords(out[15..23], self.fixed_root);
        return out;
    }
    /// Canonical order key: (kind, family, rung, arity, profile).
    fn key(self: RecEntry) [5]u32 {
        return .{ @intFromEnum(self.kind), self.family, self.rung, self.arity, self.profile };
    }
    pub fn validate(self: RecEntry) !void {
        if (self.profile == 0) return error.InvalidVkTableEntry;
        switch (self.kind) {
            .leaf => if (self.arity != 0 or self.rung == 0 or self.rung > 31) return error.InvalidVkTableEntry,
            .fold => if (self.family != 0 or self.rung != 0 or self.arity < 2 or self.arity > 4) return error.InvalidVkTableEntry,
            .compress1, .compress2 => if (self.family != 0 or self.rung != 0 or self.arity != 0) return error.InvalidVkTableEntry,
        }
    }
};

/// One `T_nat` entry: `leafhash_nat(f, r, V^nat_{f,r})`. The native VK words
/// (FIXED root, preprocessed roots, authority identity, profile) are owned by
/// canon-native; this table commits to their digest `vk_hash`.
pub const NatEntry = struct {
    family: u32,
    rung: u32,
    /// Native PCS profile id (canon-native's numbering, nonzero).
    profile: u32,
    vk_hash: [32]u8,
    pub const N_WORDS = 13;
    pub fn words(self: NatEntry) [N_WORDS]u32 {
        var out: [N_WORDS]u32 = undefined;
        out[0] = TAG_NAT;
        out[1] = VERSION;
        out[2] = self.family;
        out[3] = self.rung;
        out[4] = self.profile;
        digestWords(out[5..13], self.vk_hash);
        return out;
    }
    fn key(self: NatEntry) [3]u32 {
        return .{ self.family, self.rung, self.profile };
    }
    pub fn validate(self: NatEntry) !void {
        if (self.profile == 0 or self.rung == 0 or self.rung > 31) return error.InvalidVkTableEntry;
    }
};

fn digestWords(out: []u32, digest: [32]u8) void {
    for (out, 0..) |*w, i| w.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
}

pub fn leafHash(words: []const u32) [32]u8 {
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    h.update(&blake2_merkle.LEAF_PREFIX);
    var bytes: [4]u8 = undefined;
    for (words) |w| {
        std.mem.writeInt(u32, &bytes, w, .little);
        h.update(&bytes);
    }
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}
pub fn nodeHash(left: [32]u8, right: [32]u8) [32]u8 {
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    h.update(&blake2_merkle.NODE_PREFIX);
    h.update(&left);
    h.update(&right);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}
pub fn nullLeaf(slot: usize) [32]u8 {
    return leafHash(&.{ TAG_NULL, VERSION, @intCast(slot) });
}

/// A complete fixed-depth table (host side: derive-vk-tables, producers).
pub const Table = struct {
    /// levels[0] = leaf hashes (SLOTS), levels[DEPTH] = [root].
    levels: [DEPTH + 1][]const [32]u8,
    count: usize,
    allocator: std.mem.Allocator,
    pub fn root(self: *const Table) [32]u8 {
        return self.levels[DEPTH][0];
    }
    pub fn deinit(self: *Table) void {
        for (self.levels) |level| self.allocator.free(level);
        self.* = undefined;
    }
    /// Sibling hashes from the leaf level up (the order `verifyPath` reads).
    pub fn path(self: *const Table, index: usize) ![DEPTH][32]u8 {
        if (index >= self.count) return error.VkTableIndexOutOfRange;
        var out: [DEPTH][32]u8 = undefined;
        var at = index;
        for (&out, self.levels[0..DEPTH]) |*sibling, level| {
            sibling.* = level[at ^ 1];
            at >>= 1;
        }
        return out;
    }
    fn fromLeaves(a: std.mem.Allocator, leaves: []const [32]u8) !Table {
        if (leaves.len > SLOTS) return error.VkTableFull;
        var self: Table = .{ .levels = undefined, .count = leaves.len, .allocator = a };
        var built: usize = 0;
        errdefer for (self.levels[0..built]) |level| a.free(level);
        const bottom = try a.alloc([32]u8, SLOTS);
        for (bottom, 0..) |*slot, i| slot.* = if (i < leaves.len) leaves[i] else nullLeaf(i);
        self.levels[0] = bottom;
        built = 1;
        for (1..DEPTH + 1) |d| {
            const below = self.levels[d - 1];
            const level = try a.alloc([32]u8, below.len / 2);
            for (level, 0..) |*node, i| node.* = nodeHash(below[2 * i], below[2 * i + 1]);
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
/// `T_rec`: entries must be valid and in strictly increasing canonical order.
pub fn buildRec(a: std.mem.Allocator, entries: []const RecEntry) !Table {
    const leaves = try a.alloc([32]u8, entries.len);
    defer a.free(leaves);
    for (entries, 0..) |entry, i| {
        try entry.validate();
        if (i > 0 and !lessKey(5, entries[i - 1].key(), entry.key())) return error.VkTableOrder;
        leaves[i] = leafHash(&entry.words());
    }
    return Table.fromLeaves(a, leaves);
}
/// `T_nat`: entries must be valid and in strictly increasing (f, r, profile).
pub fn buildNat(a: std.mem.Allocator, entries: []const NatEntry) !Table {
    const leaves = try a.alloc([32]u8, entries.len);
    defer a.free(leaves);
    for (entries, 0..) |entry, i| {
        try entry.validate();
        if (i > 0 and !lessKey(3, entries[i - 1].key(), entry.key())) return error.VkTableOrder;
        leaves[i] = leafHash(&entry.words());
    }
    return Table.fromLeaves(a, leaves);
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
    for (&out.words, 0..) |*w, i| w.* = try guessWord(ctx, std.mem.readInt(u32, digest[4 * i ..][0..4], .little));
    return out;
}
pub fn constHash(ctx: *Context, digest: [32]u8) !Hash {
    var out: Hash = undefined;
    for (&out.words, 0..) |*w, i| w.* = try constWord(ctx, std.mem.readInt(u32, digest[4 * i ..][0..4], .little));
    return out;
}
/// A guessed Boolean: b * b = b. QM31 is a field, so b in {0, 1}.
pub fn guessBit(ctx: *Context, value: bool) !Var {
    const bit = try ctx.guess(Q.fromU32Unchecked(@intFromBool(value), 0, 0, 0));
    try ctx.eq(try ctx.mul(bit, bit), bit);
    return bit;
}

/// Membership witness for one leaf: guessed index bits and sibling hashes.
pub const Witness = struct {
    bits: [DEPTH]Var,
    siblings: [DEPTH]Hash,
    /// Producer side: guesses the path of `index` in `table`.
    pub fn guess(ctx: *Context, table: *const Table, index: usize) !Witness {
        const path = try table.path(index);
        var out: Witness = undefined;
        for (&out.bits, 0..) |*bit, d| bit.* = try guessBit(ctx, (index >> @intCast(d)) & 1 == 1);
        for (&out.siblings, path) |*sibling, value| sibling.* = try guessHash(ctx, value);
        return out;
    }
    /// A constant index (T_nat at a leaf of fixed (f, r)): constant bits,
    /// guessed siblings.
    pub fn guessAtConstantIndex(ctx: *Context, table: *const Table, index: usize) !Witness {
        const path = try table.path(index);
        var out: Witness = undefined;
        for (&out.bits, 0..) |*bit, d| bit.* = if ((index >> @intCast(d)) & 1 == 1) ctx.one() else ctx.zero();
        for (&out.siblings, path) |*sibling, value| sibling.* = try guessHash(ctx, value);
        return out;
    }
};

/// Asserts `Blake2s(LEAF_PREFIX || words)` is a leaf of the tree whose root
/// is the `root` wire. `words[0]` must be the table tag and `words[1]` the
/// version: both are checked against constants here, so a null slot, a
/// leaf of the other table or another protocol's leaf is never admitted.
pub fn verifyMembership(ctx: *Context, tag: u32, words: []const Word, witness: Witness, root: Hash) !void {
    if (words.len < 2) return error.InvalidVkTableEntry;
    try ctx.eq(words[0].get(), (try constWord(ctx, tag)).get());
    try ctx.eq(words[1].get(), (try constWord(ctx, VERSION)).get());
    const leaf = try Merkle.hashLeafWords(Q, ctx, words);
    try Merkle.verifyPath(Q, ctx, leaf, &witness.bits, &witness.siblings, root);
}

/// Guessed wires of a `RecEntry` (every field guessed and range-checked);
/// callers constrain fields that are class constants with `ctx.eq`.
pub fn guessRecWords(ctx: *Context, entry: RecEntry) ![RecEntry.N_WORDS]Word {
    var out: [RecEntry.N_WORDS]Word = undefined;
    for (&out, entry.words()) |*w, value| w.* = try guessWord(ctx, value);
    return out;
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

fn sampleRec() [5]RecEntry {
    var id: [32]u8 = undefined;
    var root: [32]u8 = undefined;
    var out: [5]RecEntry = undefined;
    const kinds = [_]struct { Kind, u32, u32, u32 }{ .{ .leaf, 1, 20, 0 }, .{ .leaf, 1, 22, 0 }, .{ .leaf, 2, 20, 0 }, .{ .fold, 0, 0, 2 }, .{ .fold, 0, 0, 4 } };
    for (&out, kinds, 0..) |*e, k, i| {
        @memset(&id, @intCast(i + 1));
        @memset(&root, @intCast(0x80 + i));
        e.* = .{ .kind = k[0], .family = k[1], .rung = k[2], .arity = k[3], .profile = 1, .identity = id, .fixed_root = root };
    }
    return out;
}

test "vk table: canonical order, duplicates and validation are refused" {
    const a = std.testing.allocator;
    var entries = sampleRec();
    var table = try buildRec(a, &entries);
    defer table.deinit();
    var again = try buildRec(a, &entries);
    defer again.deinit();
    try std.testing.expectEqualSlices(u8, &table.root(), &again.root());
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
    // Every field changes the root.
    entries = sampleRec();
    entries[4].identity[31] ^= 1;
    var changed = try buildRec(a, &entries);
    defer changed.deinit();
    try std.testing.expect(!std.mem.eql(u8, &table.root(), &changed.root()));
}

test "vk table: host path recomputes the root; leaf and node hashes are separated" {
    const a = std.testing.allocator;
    const entries = sampleRec();
    var table = try buildRec(a, &entries);
    defer table.deinit();
    for (entries, 0..) |entry, index| {
        var node = leafHash(&entry.words());
        const path = try table.path(index);
        for (path, 0..) |sibling, d| node = if ((index >> @intCast(d)) & 1 == 1) nodeHash(sibling, node) else nodeHash(node, sibling);
        try std.testing.expectEqualSlices(u8, &table.root(), &node);
    }
    try std.testing.expectError(error.VkTableIndexOutOfRange, table.path(entries.len));
    // Z08: a level-1 node's preimage hashed as a leaf is a different value.
    var pair: [16]u32 = undefined;
    digestWords(pair[0..8], table.levels[0][0]);
    digestWords(pair[8..16], table.levels[0][1]);
    try std.testing.expect(!std.mem.eql(u8, &leafHash(&pair), &table.levels[1][0]));
}

fn membershipCircuit(entry_words: [RecEntry.N_WORDS]u32, table: *const Table, index: usize, root: [32]u8, flip_bit: ?usize) !bool {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    var words: [RecEntry.N_WORDS]Word = undefined;
    for (&words, entry_words) |*w, value| w.* = try guessWord(&ctx, value);
    var witness = try Witness.guess(&ctx, table, index);
    if (flip_bit) |d| witness.bits[d] = try guessBit(&ctx, (index >> @intCast(d)) & 1 == 0);
    const root_wire = try guessHash(&ctx, root);
    try verifyMembership(&ctx, TAG_REC, &words, witness, root_wire);
    return ctx.isCircuitValid();
}

test "vk table: in-circuit membership accepts members and rejects forgeries" {
    const a = std.testing.allocator;
    const entries = sampleRec();
    var table = try buildRec(a, &entries);
    defer table.deinit();
    // G03 accept path: every member at its own index.
    for (entries, 0..) |entry, index| try std.testing.expect(try membershipCircuit(entry.words(), &table, index, table.root(), null));
    // G03: a VK not in the table (identity word changed).
    var forged = entries[3];
    forged.identity[0] ^= 0x40;
    try std.testing.expect(!try membershipCircuit(forged.words(), &table, 3, table.root(), null));
    // G05: arity relabel (an F_2 entry presented as F_4 at the F_2 index).
    var relabel = entries[3];
    relabel.arity = 4;
    try std.testing.expect(!try membershipCircuit(relabel.words(), &table, 3, table.root(), null));
    // A member at another index (wrong path bit).
    try std.testing.expect(!try membershipCircuit(entries[1].words(), &table, 1, table.root(), 0));
    // G02: a different table root.
    var other = entries;
    other[0].fixed_root[5] ^= 1;
    var other_table = try buildRec(a, &other);
    defer other_table.deinit();
    try std.testing.expect(!try membershipCircuit(entries[1].words(), &table, 1, other_table.root(), null));
    // Null slot: its preimage starts with TAG_NULL, refused by the tag check.
    var null_words: [RecEntry.N_WORDS]u32 = @splat(0);
    null_words[0] = TAG_NULL;
    null_words[1] = VERSION;
    null_words[2] = @intCast(entries.len);
    try std.testing.expect(!try membershipCircuit(null_words, &table, 0, table.root(), null));
}

test "vk table: a non-Boolean index bit is unsatisfiable" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    const bit = try ctx.guess(Q.fromU32Unchecked(2, 0, 0, 0));
    try ctx.eq(try ctx.mul(bit, bit), bit);
    try std.testing.expect(!try ctx.isCircuitValid());
}

test "vk table: native table order and tags" {
    const a = std.testing.allocator;
    var vk: [32]u8 = @splat(7);
    const entries = [_]NatEntry{ .{ .family = 1, .rung = 20, .profile = 1, .vk_hash = vk }, .{ .family = 1, .rung = 22, .profile = 1, .vk_hash = vk } };
    var table = try buildNat(a, &entries);
    defer table.deinit();
    vk[0] = 8;
    const swapped = [_]NatEntry{ entries[1], entries[0] };
    try std.testing.expectError(error.VkTableOrder, buildNat(a, &swapped));
    try std.testing.expect(TAG_NAT != TAG_REC and TAG_NULL != TAG_REC and TAG_NULL != TAG_NAT);
}
