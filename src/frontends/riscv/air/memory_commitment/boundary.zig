//! Ordinary non-public RW-memory boundary rows and relation claims.
//!
//! The caller supplies every aligned RW word from the loaded/final memory
//! union. Public input and output classification follows pinned Stark-V's
//! segment policy; this module then builds the initial/final memory rows and
//! their byte-addressed sparse Merkle trees.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const relation_challenges = @import("../relation_challenges.zig");
const sparse_merkle = @import("sparse_merkle.zig");
const memory_state = @import("../../runner/memory_state.zig");
const poseidon_work = @import("../../prover/poseidon_witness_work.zig");

pub const Error = sparse_merkle.Error || error{
    DuplicateWord,
    InvalidBoundary,
    MisalignedWord,
    ZeroDenominator,
};

pub const WordRole = memory_state.WordRole;
pub const WordState = memory_state.WordState;

/// One exact row of Stark-V's `memory` table.
pub const Row = struct {
    addr: u32,
    clock: u32,
    value: [4]u8,
    multiplicity: M31,
    root: u32,

    pub fn memoryTuple(self: Row) [7]M31 {
        return .{
            M31.one(),
            base(self.addr),
            base(self.clock),
            base(self.value[0]),
            base(self.value[1]),
            base(self.value[2]),
            base(self.value[3]),
        };
    }

    pub fn leaf(self: Row, limb: u2) sparse_merkle.Leaf {
        return .{
            .index = self.addr + @as(u32, limb),
            .value = self.value[limb],
        };
    }
};

pub const Claims = struct {
    rows: []Row,
    initial_tree: ?sparse_merkle.Tree,
    final_tree: ?sparse_merkle.Tree,

    pub fn deinit(self: *Claims, allocator: std.mem.Allocator) void {
        allocator.free(self.rows);
        if (self.initial_tree) |*tree| tree.deinit(allocator);
        if (self.final_tree) |*tree| tree.deinit(allocator);
        self.* = undefined;
    }

    /// Validates the committed rows, their tree leaves, all node hashes, and
    /// root linkage without trusting the builder's original word inputs.
    pub fn validate(self: Claims, allocator: std.mem.Allocator) Error!void {
        if (self.initial_tree) |tree| try tree.validate(allocator);
        if (self.final_tree) |tree| try tree.validate(allocator);
        try self.validateRows(allocator);
    }

    /// Exact validation route. Tree rebuild receipts remain local until both
    /// hashes and every boundary row/leaf linkage have been accepted.
    pub fn validateWithWorkReceipt(
        self: Claims,
        allocator: std.mem.Allocator,
        authority: *const poseidon_work.Authority,
    ) !poseidon_work.Shard {
        var completed = poseidon_work.Shard{};
        if (self.initial_tree) |tree| {
            const receipt = try tree.validateWithWorkReceipt(allocator, authority);
            try completed.observe(authority, receipt);
        }
        if (self.final_tree) |tree| {
            const receipt = try tree.validateWithWorkReceipt(allocator, authority);
            try completed.observe(authority, receipt);
        }
        try self.validateRows(allocator);
        return completed;
    }

    fn validateRows(self: Claims, allocator: std.mem.Allocator) Error!void {
        var initial_leaves: std.ArrayList(sparse_merkle.Leaf) = .{};
        defer initial_leaves.deinit(allocator);
        var final_leaves: std.ArrayList(sparse_merkle.Leaf) = .{};
        defer final_leaves.deinit(allocator);

        var previous_addr: ?u32 = null;
        var previous_was_initial = false;
        for (self.rows) |row| {
            if ((row.addr & 3) != 0 or row.addr > sparse_merkle.LEAF_COUNT - 4)
                return error.InvalidBoundary;
            const is_initial = row.multiplicity.eql(M31.one());
            const is_final = row.multiplicity.eql(M31.one().neg());
            if (!is_initial and !is_final) return error.InvalidBoundary;
            if (is_initial and row.clock != 0) return error.InvalidBoundary;
            if (previous_addr) |addr| {
                if (row.addr < addr or (row.addr == addr and (!previous_was_initial or is_initial)))
                    return error.InvalidBoundary;
            }
            previous_addr = row.addr;
            previous_was_initial = is_initial;

            const maybe_tree = if (is_initial) self.initial_tree else self.final_tree;
            const tree = maybe_tree orelse return error.InvalidBoundary;
            if (row.root != tree.root) return error.InvalidBoundary;
            for (0..4) |limb| {
                const leaf = row.leaf(@intCast(limb));
                if (is_initial) {
                    try initial_leaves.append(allocator, leaf);
                } else {
                    try final_leaves.append(allocator, leaf);
                }
            }
        }
        try matchLeaves(self.initial_tree, initial_leaves.items);
        try matchLeaves(self.final_tree, final_leaves.items);
    }

    /// The memory-access contribution emitted by boundary rows. Opcode access
    /// chains and public I/O terms must cancel this independently of Merkle.
    pub fn memoryLogupSum(
        self: Claims,
        relation: *const relation_challenges.RelationElements(7),
    ) Error!QM31 {
        var sum = QM31.zero();
        for (self.rows) |row| {
            try addFraction(&sum, relation.combineBase(row.memoryTuple()), row.multiplicity);
        }
        return sum;
    }

    /// Exact Merkle-bus balance: public root emission, memory leaf
    /// consumption, node child emission, and node parent consumption.
    pub fn verifyMerkleCancellation(
        self: Claims,
        relation: *const relation_challenges.RelationElements(4),
    ) Error!void {
        var sum = QM31.zero();
        inline for (.{ self.initial_tree, self.final_tree }) |maybe_tree| {
            if (maybe_tree) |tree| {
                try addTuple(&sum, relation, tree.rootTuple(), M31.one());
                for (tree.nodes) |node| {
                    try addTuple(&sum, relation, node.leftTuple(tree.root), base(node.left.multiplicity));
                    try addTuple(&sum, relation, node.rightTuple(tree.root), base(node.right.multiplicity));
                    try addTuple(&sum, relation, node.parentTuple(tree.root), base(node.current.multiplicity).neg());
                }
            }
        }
        for (self.rows) |row| {
            for (0..4) |limb| {
                const leaf = row.leaf(@intCast(limb));
                try addTuple(&sum, relation, leaf.relationTuple(row.root), M31.one().neg());
            }
        }
        if (!sum.isZero()) return error.InvalidBoundary;
    }
};

pub fn build(allocator: std.mem.Allocator, input: []const WordState) Error!Claims {
    return buildInternal(false, allocator, input, null);
}

pub const BuiltWithWorkReceipt = struct {
    claims: Claims,
    work: poseidon_work.Shard,
};

pub fn buildWithWorkReceipt(
    allocator: std.mem.Allocator,
    input: []const WordState,
    authority: *const poseidon_work.Authority,
) !BuiltWithWorkReceipt {
    return buildInternal(true, allocator, input, authority);
}

fn BuildResult(comptime capture_work: bool) type {
    return if (capture_work) BuiltWithWorkReceipt else Claims;
}

fn buildInternal(
    comptime capture_work: bool,
    allocator: std.mem.Allocator,
    input: []const WordState,
    authority: ?*const poseidon_work.Authority,
) !BuildResult(capture_work) {
    var completed = poseidon_work.Shard{};
    const words = try allocator.dupe(WordState, input);
    defer allocator.free(words);
    std.mem.sort(WordState, words, {}, lessWord);
    for (words, 0..) |word, index| {
        if ((word.addr & 3) != 0) return error.MisalignedWord;
        if (word.addr > sparse_merkle.LEAF_COUNT - 4) return error.IndexOutOfRange;
        if (index != 0 and words[index - 1].addr == word.addr) return error.DuplicateWord;
    }

    var initial_leaves: std.ArrayList(sparse_merkle.Leaf) = .{};
    defer initial_leaves.deinit(allocator);
    var final_leaves: std.ArrayList(sparse_merkle.Leaf) = .{};
    defer final_leaves.deinit(allocator);
    for (words) |word| {
        if (word.includeInitial()) try appendWordLeaves(&initial_leaves, allocator, word.addr, word.initial_word);
        if (word.includeFinal()) try appendWordLeaves(&final_leaves, allocator, word.addr, word.final_word);
    }

    var initial_tree: ?sparse_merkle.Tree = if (initial_leaves.items.len == 0)
        null
    else if (capture_work) blk: {
        var built = try sparse_merkle.buildWithWorkReceipt(
            allocator,
            initial_leaves.items,
            authority.?,
        );
        errdefer built.tree.deinit(allocator);
        try completed.observe(authority.?, built.receipt);
        break :blk built.tree;
    } else try sparse_merkle.build(allocator, initial_leaves.items);
    errdefer if (initial_tree) |*tree| tree.deinit(allocator);
    var final_tree: ?sparse_merkle.Tree = if (final_leaves.items.len == 0)
        null
    else if (capture_work) blk: {
        var built = try sparse_merkle.buildWithWorkReceipt(
            allocator,
            final_leaves.items,
            authority.?,
        );
        errdefer built.tree.deinit(allocator);
        try completed.observe(authority.?, built.receipt);
        break :blk built.tree;
    } else try sparse_merkle.build(allocator, final_leaves.items);
    errdefer if (final_tree) |*tree| tree.deinit(allocator);

    var rows: std.ArrayList(Row) = .{};
    errdefer rows.deinit(allocator);
    for (words) |word| {
        if (initial_tree) |tree| {
            if (word.includeInitial()) try rows.append(allocator, .{
                .addr = word.addr,
                .clock = 0,
                .value = wordBytes(word.initial_word),
                .multiplicity = M31.one(),
                .root = tree.root,
            });
        }
        if (final_tree) |tree| {
            if (word.includeFinal()) try rows.append(allocator, .{
                .addr = word.addr,
                .clock = word.final_clock,
                .value = wordBytes(word.final_word),
                .multiplicity = M31.one().neg(),
                .root = tree.root,
            });
        }
    }
    const claims = Claims{
        .rows = try rows.toOwnedSlice(allocator),
        .initial_tree = initial_tree,
        .final_tree = final_tree,
    };
    initial_tree = null;
    final_tree = null;
    return if (capture_work)
        .{ .claims = claims, .work = completed }
    else
        claims;
}

fn appendWordLeaves(
    leaves: *std.ArrayList(sparse_merkle.Leaf),
    allocator: std.mem.Allocator,
    addr: u32,
    word: u32,
) !void {
    const bytes = wordBytes(word);
    for (bytes, 0..) |value, limb| {
        try leaves.append(allocator, .{ .index = addr + @as(u32, @intCast(limb)), .value = value });
    }
}

fn matchLeaves(maybe_tree: ?sparse_merkle.Tree, actual: []const sparse_merkle.Leaf) Error!void {
    const tree = maybe_tree orelse {
        if (actual.len != 0) return error.InvalidBoundary;
        return;
    };
    if (tree.leaves.len != actual.len) return error.InvalidBoundary;
    for (tree.leaves, actual) |expected, leaf| {
        if (!std.meta.eql(expected, leaf)) return error.InvalidBoundary;
    }
}

fn addTuple(
    sum: *QM31,
    relation: *const relation_challenges.RelationElements(4),
    tuple: [4]u32,
    multiplicity: M31,
) Error!void {
    if (multiplicity.isZero()) return;
    try addFraction(sum, relation.combineBase(.{
        base(tuple[0]), base(tuple[1]), base(tuple[2]), base(tuple[3]),
    }), multiplicity);
}

fn addFraction(sum: *QM31, denominator: QM31, multiplicity: M31) Error!void {
    if (multiplicity.isZero()) return;
    const inverse = denominator.inv() catch return error.ZeroDenominator;
    sum.* = sum.add(inverse.mulM31(multiplicity));
}

fn base(value: anytype) M31 {
    return M31.fromU64(@as(u64, value));
}

fn wordBytes(word: u32) [4]u8 {
    return .{
        @truncate(word),
        @truncate(word >> 8),
        @truncate(word >> 16),
        @truncate(word >> 24),
    };
}

fn lessWord(_: void, lhs: WordState, rhs: WordState) bool {
    return lhs.addr < rhs.addr;
}

test "memory boundary: ordinary words produce initial then final rows" {
    var claims = try build(std.testing.allocator, &.{
        .{ .addr = 0x1004, .initial_word = 3, .final_word = 4, .final_clock = 9 },
        .{ .addr = 0x1000, .initial_word = 1, .final_word = 2, .final_clock = 8 },
    });
    defer claims.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 4), claims.rows.len);
    try std.testing.expectEqual(@as(u32, 0x1000), claims.rows[0].addr);
    try std.testing.expect(claims.rows[0].multiplicity.eql(M31.one()));
    try std.testing.expectEqual(@as(u32, 0), claims.rows[0].clock);
    try std.testing.expect(claims.rows[1].multiplicity.eql(M31.one().neg()));
    try std.testing.expectEqual(@as(u32, 8), claims.rows[1].clock);
    try std.testing.expectEqual(@as(u32, 0x1004), claims.rows[2].addr);
    try claims.verifyMerkleCancellation(&relation_challenges.Relations.dummy().merkle);
}

test "memory boundary: public input and output follow oracle inclusion policy" {
    var claims = try build(std.testing.allocator, &.{
        .{
            .addr = 0x2000,
            .initial_word = 11,
            .final_word = 12,
            .final_clock = 4,
            .role = .{ .is_public_input = true },
        },
        .{
            .addr = 0x2004,
            .initial_word = 21,
            .final_word = 22,
            .final_clock = 5,
            .role = .{ .is_public_output = true },
        },
        .{
            .addr = 0x2008,
            .initial_word = 31,
            .final_word = 31,
            .final_clock = 0,
            .role = .{ .is_public_input = true },
        },
    });
    defer claims.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), claims.rows.len);
    try std.testing.expectEqual(@as(u32, 0x2000), claims.rows[0].addr);
    try std.testing.expect(claims.rows[0].multiplicity.eql(M31.one().neg()));
    try std.testing.expectEqual(@as(u32, 0x2004), claims.rows[1].addr);
    try std.testing.expect(claims.rows[1].multiplicity.eql(M31.one()));
    try claims.verifyMerkleCancellation(&relation_challenges.Relations.dummy().merkle);
}

test "memory boundary: row, root, and node mutations fail validation" {
    var claims = try build(std.testing.allocator, &.{
        .{ .addr = 0x3000, .initial_word = 1, .final_word = 2, .final_clock = 3 },
    });
    defer claims.deinit(std.testing.allocator);

    claims.rows[0].value[0] ^= 1;
    try std.testing.expectError(error.InvalidBoundary, claims.validate(std.testing.allocator));
    claims.rows[0].value[0] ^= 1;
    claims.rows[0].root ^= 1;
    try std.testing.expectError(error.InvalidBoundary, claims.validate(std.testing.allocator));
    claims.rows[0].root ^= 1;
    claims.initial_tree.?.nodes[0].current.value ^= 1;
    try std.testing.expectError(error.InvalidTree, claims.validate(std.testing.allocator));
}

test "memory boundary: invalid addresses and duplicate words fail closed" {
    try std.testing.expectError(error.MisalignedWord, build(std.testing.allocator, &.{
        .{ .addr = 1, .initial_word = 0, .final_word = 0, .final_clock = 0 },
    }));
    try std.testing.expectError(error.DuplicateWord, build(std.testing.allocator, &.{
        .{ .addr = 4, .initial_word = 0, .final_word = 0, .final_clock = 0 },
        .{ .addr = 4, .initial_word = 0, .final_word = 0, .final_clock = 0 },
    }));
}
