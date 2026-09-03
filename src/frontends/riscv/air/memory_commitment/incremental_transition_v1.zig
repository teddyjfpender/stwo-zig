//! Incremental sparse-memory transition witness over existing production AIRs.
//!
//! The transition commits only touched RW words plus a shared multiproof
//! frontier.  Ordinary memory-boundary rows bind the old/final values and
//! clocks to the existing `memory_access` bus.  Ordinary Merkle-node rows and
//! the existing Poseidon provider prove both roots.  `incremental_frontier_v1`
//! forces every omitted subtree to be identical in both computations.
//!
//! This module is append-only and profile-distinct.  It is not selected by any
//! production statement yet; the full-snapshot path remains the oracle.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const boundary = @import("boundary.zig");
const frontier = @import("incremental_frontier_v1.zig");
const frontier_component = @import("incremental_frontier_component_v1.zig");
const memory_interaction = @import("interaction.zig");
const merkle_node = @import("merkle_node.zig");
const poseidon2 = @import("poseidon2.zig");
const poseidon2_air = @import("poseidon2_air.zig");
const relations_mod = @import("../relation_challenges.zig");
const sparse_merkle = @import("sparse_merkle.zig");

pub const PRODUCTION_ACTIVE = false;
pub const PROFILE = "riscv-incremental-memory-transition-v1";

pub const TouchedWord = struct {
    address: u32,
    old_word: u32,
    new_word: u32,
    final_clock: u32,
};

/// Canonical input omits pinned default siblings.  The builder expands those
/// defaults into committed shared-frontier rows before proving.
pub const FrontierNode = struct {
    depth: u8,
    index: u32,
    value: u32,
};

pub const HashWork = struct {
    entry_calls: u64,
    exit_calls: u64,
    total_calls: u64,
    provider_log_size: u8,
};

pub const Witness = struct {
    allocator: std.mem.Allocator,
    entry_root: u32,
    exit_root: u32,
    boundary_rows: []boundary.Row,
    merkle_rows: []merkle_node.NodeRow,
    frontier_rows: []frontier.Row,
    poseidon_calls: []poseidon2_air.Call,
    work: HashWork,

    pub fn deinit(self: *Witness) void {
        self.allocator.free(self.boundary_rows);
        self.allocator.free(self.merkle_rows);
        self.allocator.free(self.frontier_rows);
        self.allocator.free(self.poseidon_calls);
        self.* = undefined;
    }

    pub fn prepareFrontierAir(
        self: *const Witness,
        allocator: std.mem.Allocator,
        placement: frontier_component.Placement,
        relations: *const relations_mod.Relations,
    ) !PreparedFrontierAir {
        const log_size = componentLog(self.frontier_rows.len);
        var main = try frontier.generateMain(
            allocator,
            self.frontier_rows,
            log_size,
        );
        errdefer main.deinit(allocator);
        var interaction = try frontier.generateInteraction(
            allocator,
            self.frontier_rows,
            log_size,
            self.entry_root,
            self.exit_root,
            relations,
        );
        errdefer interaction.deinit(allocator);
        const component = try frontier_component.IncrementalFrontierComponentV1.init(
            log_size,
            @intCast(self.frontier_rows.len),
            self.entry_root,
            self.exit_root,
            placement,
            relations,
            interaction.claims.sum,
        );
        return .{
            .allocator = allocator,
            .main = main,
            .interaction = interaction,
            .component = component,
        };
    }

    /// Native relation-sum check used by the differential oracle.  A STARK
    /// component executes the same generic row evaluators independently.
    pub fn verifyMerkleAndPoseidonCancellation(
        self: *const Witness,
        relations: *const relations_mod.Relations,
    ) !void {
        const log_size = componentLog(self.merkle_rows.len);
        var nodes = try merkle_node.generateInteraction(
            self.allocator,
            self.merkle_rows,
            log_size,
            relations,
        );
        defer nodes.deinit(self.allocator);
        var hashes = try poseidon2_air.generateInteraction(
            self.allocator,
            self.poseidon_calls,
            log_size,
            relations,
        );
        defer hashes.deinit(self.allocator);
        const boundary_claim = try memory_interaction.diagnosticSum(
            self.boundary_rows,
            .merkle,
            relations,
        );
        const frontier_claim = try frontier.diagnosticClaim(
            self.frontier_rows,
            self.entry_root,
            self.exit_root,
            relations,
        );
        const entry_emit = try rootEmit(self.entry_root, relations);
        const exit_emit = try rootEmit(self.exit_root, relations);
        const roots = entry_emit.add(exit_emit);
        const total = nodes.claims.total().add(hashes.claims.total())
            .add(boundary_claim).add(frontier_claim).add(roots);
        if (!total.isZero()) return error.IncrementalRelationNotClosed;
    }
};

pub const PreparedFrontierAir = struct {
    allocator: std.mem.Allocator,
    main: frontier.Columns,
    interaction: frontier.Interaction,
    component: frontier_component.IncrementalFrontierComponentV1,

    pub fn deinit(self: *PreparedFrontierAir) void {
        self.main.deinit(self.allocator);
        self.interaction.deinit(self.allocator);
        self.* = undefined;
    }
};

const PathValue = struct {
    index: u32,
    old_value: u32,
    new_value: u32,
};

const FrontierCursor = struct {
    source: []const FrontierNode,
    at: usize = 0,

    fn missingValue(
        self: *FrontierCursor,
        depth: u8,
        index: u32,
    ) u32 {
        if (self.at < self.source.len) {
            const candidate = self.source[self.at];
            if (candidate.depth == depth and candidate.index == index) {
                self.at += 1;
                return candidate.value;
            }
        }
        return poseidon2.DEFAULT_HASHES[depth];
    }
};

pub fn build(
    allocator: std.mem.Allocator,
    touched_words: []const TouchedWord,
    canonical_frontier: []const FrontierNode,
) !Witness {
    try validateTouched(touched_words);
    try validateFrontier(canonical_frontier);
    if (touched_words.len == 0) return error.EmptyIncrementalTransition;

    const leaf_count = std.math.mul(usize, touched_words.len, 4) catch
        return error.IncrementalTransitionSizeOverflow;
    var current = try allocator.alloc(PathValue, leaf_count);
    defer allocator.free(current);
    var leaf_at: usize = 0;
    for (touched_words) |word| {
        for (0..4) |limb| {
            const shift: u5 = @intCast(limb * 8);
            current[leaf_at] = .{
                .index = word.address + @as(u32, @intCast(limb)),
                .old_value = @as(u8, @truncate(word.old_word >> shift)),
                .new_value = @as(u8, @truncate(word.new_word >> shift)),
            };
            leaf_at += 1;
        }
    }

    var old_rows: std.ArrayList(merkle_node.NodeRow) = .empty;
    defer old_rows.deinit(allocator);
    var new_rows: std.ArrayList(merkle_node.NodeRow) = .empty;
    defer new_rows.deinit(allocator);
    var frontier_rows: std.ArrayList(frontier.Row) = .empty;
    errdefer frontier_rows.deinit(allocator);
    var cursor = FrontierCursor{ .source = canonical_frontier };

    var depth: u8 = @intCast(sparse_merkle.LEAF_DEPTH);
    while (depth > 0) : (depth -= 1) {
        var next: std.ArrayList(PathValue) = .empty;
        errdefer next.deinit(allocator);
        try next.ensureTotalCapacity(allocator, (current.len + 1) / 2);
        var at: usize = 0;
        while (at < current.len) {
            const parent_index = current[at].index / 2;
            const left_index = parent_index * 2;
            const right_index = left_index + 1;
            const left = if (current[at].index == left_index) blk: {
                const value = current[at];
                at += 1;
                break :blk value;
            } else try appendFrontier(
                &frontier_rows,
                allocator,
                &cursor,
                depth,
                left_index,
            );
            const right = if (at < current.len and
                current[at].index == right_index)
            blk: {
                const value = current[at];
                at += 1;
                break :blk value;
            } else try appendFrontier(
                &frontier_rows,
                allocator,
                &cursor,
                depth,
                right_index,
            );
            const old_parent = poseidon2.hashPair(
                left.old_value,
                right.old_value,
            );
            const new_parent = poseidon2.hashPair(
                left.new_value,
                right.new_value,
            );
            try old_rows.append(allocator, .{
                .index = left_index,
                .depth = depth,
                .lhs = left.old_value,
                .rhs = right.old_value,
                .cur = old_parent,
                .lhs_mult = 1,
                .rhs_mult = 1,
                .cur_mult = 1,
                .root = 0,
            });
            try new_rows.append(allocator, .{
                .index = left_index,
                .depth = depth,
                .lhs = left.new_value,
                .rhs = right.new_value,
                .cur = new_parent,
                .lhs_mult = 1,
                .rhs_mult = 1,
                .cur_mult = 1,
                .root = 0,
            });
            next.appendAssumeCapacity(.{
                .index = parent_index,
                .old_value = old_parent,
                .new_value = new_parent,
            });
        }
        allocator.free(current);
        current = try next.toOwnedSlice(allocator);
    }
    if (cursor.at != canonical_frontier.len)
        return error.NonCanonicalIncrementalFrontier;
    if (current.len != 1 or current[0].index != 0)
        return error.InvalidIncrementalTopology;
    const entry_root = current[0].old_value;
    const exit_root = current[0].new_value;

    for (old_rows.items) |*row| row.root = entry_root;
    for (new_rows.items) |*row| row.root = exit_root;
    const node_count = try std.math.add(
        usize,
        old_rows.items.len,
        new_rows.items.len,
    );
    const merkle_rows = try allocator.alloc(merkle_node.NodeRow, node_count);
    errdefer allocator.free(merkle_rows);
    @memcpy(merkle_rows[0..old_rows.items.len], old_rows.items);
    @memcpy(merkle_rows[old_rows.items.len..], new_rows.items);

    const boundary_rows = try allocator.alloc(
        boundary.Row,
        try std.math.mul(usize, touched_words.len, 2),
    );
    errdefer allocator.free(boundary_rows);
    for (touched_words, 0..) |word, index| {
        boundary_rows[index * 2] = .{
            .addr = word.address,
            .clock = 0,
            .value = wordBytes(word.old_word),
            .multiplicity = M31.one(),
            .root = entry_root,
        };
        boundary_rows[index * 2 + 1] = .{
            .addr = word.address,
            .clock = word.final_clock,
            .value = wordBytes(word.new_word),
            .multiplicity = M31.one().neg(),
            .root = exit_root,
        };
    }
    const calls = try merkle_node.calls(allocator, merkle_rows);
    errdefer allocator.free(calls);
    const total_calls: u64 = @intCast(calls.len);
    const entry_calls: u64 = @intCast(old_rows.items.len);
    const exit_calls: u64 = @intCast(new_rows.items.len);
    return .{
        .allocator = allocator,
        .entry_root = entry_root,
        .exit_root = exit_root,
        .boundary_rows = boundary_rows,
        .merkle_rows = merkle_rows,
        .frontier_rows = try frontier_rows.toOwnedSlice(allocator),
        .poseidon_calls = calls,
        .work = .{
            .entry_calls = entry_calls,
            .exit_calls = exit_calls,
            .total_calls = total_calls,
            .provider_log_size = @intCast(componentLog(calls.len)),
        },
    };
}

/// Derives the minimal non-default frontier for `touched_words` from a fully
/// reconstructed entry tree.  This is a compatibility/oracle helper: the hot
/// session path keeps the same keyed nodes alive and emits the frontier while
/// instructions retire, avoiding a second full-tree scan.
pub fn canonicalFrontierFromEntryTree(
    allocator: std.mem.Allocator,
    entry_tree: sparse_merkle.Tree,
    touched_words: []const TouchedWord,
) ![]FrontierNode {
    try validateTouched(touched_words);
    if (touched_words.len == 0) return allocator.alloc(FrontierNode, 0);
    var values = std.AutoHashMap(u64, u32).init(allocator);
    defer values.deinit();
    try values.ensureTotalCapacity(@intCast(
        try std.math.add(usize, entry_tree.leaves.len, entry_tree.nodes.len),
    ));
    for (entry_tree.leaves) |leaf| {
        try values.put(treeKey(@intCast(sparse_merkle.LEAF_DEPTH), leaf.index), leaf.value);
    }
    for (entry_tree.nodes) |node| {
        try values.put(treeKey(
            @intCast(node.depth - 1),
            node.index / 2,
        ), node.current.value);
    }

    const leaf_count = try std.math.mul(usize, touched_words.len, 4);
    var current = try allocator.alloc(u32, leaf_count);
    defer allocator.free(current);
    var at: usize = 0;
    for (touched_words) |word| {
        const bytes = wordBytes(word.old_word);
        for (bytes, 0..) |value, limb| {
            const index = word.address + @as(u32, @intCast(limb));
            if ((values.get(treeKey(
                @intCast(sparse_merkle.LEAF_DEPTH),
                index,
            )) orelse poseidon2.DEFAULT_HASHES[sparse_merkle.LEAF_DEPTH]) != value) {
                return error.TouchedEntryValueMismatch;
            }
            current[at] = index;
            at += 1;
        }
    }
    var current_len = current.len;
    var result: std.ArrayList(FrontierNode) = .empty;
    errdefer result.deinit(allocator);
    var depth: u8 = @intCast(sparse_merkle.LEAF_DEPTH);
    while (depth > 0) : (depth -= 1) {
        for (current[0..current_len]) |index| {
            const sibling = index ^ 1;
            if (std.sort.binarySearch(u32, current[0..current_len], sibling, struct {
                fn compare(key: u32, value: u32) std.math.Order {
                    return std.math.order(key, value);
                }
            }.compare) != null) {
                continue;
            }
            const value = values.get(treeKey(depth, sibling)) orelse
                poseidon2.DEFAULT_HASHES[depth];
            if (value != poseidon2.DEFAULT_HASHES[depth]) {
                try result.append(allocator, .{
                    .depth = depth,
                    .index = sibling,
                    .value = value,
                });
            }
        }
        for (current[0..current_len]) |*index| index.* /= 2;
        current_len = uniqueInPlace(current[0..current_len]);
    }
    return result.toOwnedSlice(allocator);
}

fn appendFrontier(
    rows: *std.ArrayList(frontier.Row),
    allocator: std.mem.Allocator,
    cursor: *FrontierCursor,
    depth: u8,
    index: u32,
) !PathValue {
    const value = cursor.missingValue(depth, index);
    try rows.append(allocator, .{
        .depth = depth,
        .index = index,
        .value = value,
    });
    return .{ .index = index, .old_value = value, .new_value = value };
}

fn validateTouched(words: []const TouchedWord) !void {
    var previous: ?u32 = null;
    for (words) |word| {
        if ((word.address & 3) != 0 or
            word.address > sparse_merkle.LEAF_COUNT - 4)
        {
            return error.InvalidTouchedWordAddress;
        }
        if (previous) |address| {
            if (word.address <= address) return error.NonCanonicalTouchedWords;
        }
        previous = word.address;
    }
}

fn validateFrontier(nodes: []const FrontierNode) !void {
    var previous_depth: ?u8 = null;
    var previous_index: u32 = 0;
    for (nodes) |node| {
        if (node.depth == 0 or node.depth > sparse_merkle.LEAF_DEPTH)
            return error.NonCanonicalIncrementalFrontier;
        const bound = @as(u32, 1) << @intCast(node.depth);
        if (node.index >= bound or
            node.value >= @import("stwo_core").fields.m31.Modulus or
            node.value == poseidon2.DEFAULT_HASHES[node.depth])
        {
            return error.NonCanonicalIncrementalFrontier;
        }
        if (previous_depth) |depth| {
            if (node.depth > depth or
                (node.depth == depth and node.index <= previous_index))
            {
                return error.NonCanonicalIncrementalFrontier;
            }
        }
        previous_depth = node.depth;
        previous_index = node.index;
    }
}

fn rootEmit(
    root_value: u32,
    relations: *const relations_mod.Relations,
) !QM31 {
    const root = M31.fromU64(root_value);
    return relations.merkle.combineBase(.{
        M31.zero(),
        M31.zero(),
        root,
        root,
    }).inv();
}

fn componentLog(row_count: usize) u32 {
    if (row_count <= 1) return 4;
    return @max(@as(u32, 4), std.math.log2_int_ceil(usize, row_count));
}

fn wordBytes(value: u32) [4]u8 {
    return .{
        @truncate(value),
        @truncate(value >> 8),
        @truncate(value >> 16),
        @truncate(value >> 24),
    };
}

fn treeKey(depth: u8, index: u32) u64 {
    return (@as(u64, depth) << 32) | index;
}

fn uniqueInPlace(values: []u32) usize {
    if (values.len == 0) return 0;
    var write: usize = 1;
    for (values[1..]) |value| {
        if (value == values[write - 1]) continue;
        values[write] = value;
        write += 1;
    }
    return write;
}

fn fullTreeForWords(
    allocator: std.mem.Allocator,
    words: []const TouchedWord,
    use_new: bool,
) !sparse_merkle.Tree {
    const leaves = try allocator.alloc(sparse_merkle.Leaf, words.len * 4);
    defer allocator.free(leaves);
    for (words, 0..) |word, word_index| {
        const bytes = wordBytes(if (use_new) word.new_word else word.old_word);
        for (bytes, 0..) |value, limb| {
            leaves[word_index * 4 + limb] = .{
                .index = word.address + @as(u32, @intCast(limb)),
                .value = value,
            };
        }
    }
    return sparse_merkle.build(allocator, leaves);
}

test "incremental transition matches full roots and closes existing buses" {
    const words = [_]TouchedWord{
        .{
            .address = 0x1000,
            .old_word = 0x11223344,
            .new_word = 0x55667788,
            .final_clock = 19,
        },
        .{
            .address = 0x1010,
            .old_word = 0xaabbccdd,
            .new_word = 0xaabbccdd,
            .final_clock = 31,
        },
    };
    var witness = try build(std.testing.allocator, &words, &.{});
    defer witness.deinit();
    var old_tree = try fullTreeForWords(std.testing.allocator, &words, false);
    defer old_tree.deinit(std.testing.allocator);
    var new_tree = try fullTreeForWords(std.testing.allocator, &words, true);
    defer new_tree.deinit(std.testing.allocator);
    try std.testing.expectEqual(old_tree.root, witness.entry_root);
    try std.testing.expectEqual(new_tree.root, witness.exit_root);
    try std.testing.expectEqual(
        witness.work.entry_calls + witness.work.exit_calls,
        witness.work.total_calls,
    );
    try std.testing.expectEqual(witness.merkle_rows.len, witness.poseidon_calls.len);
    const relations = relations_mod.Relations.dummy();
    try witness.verifyMerkleAndPoseidonCancellation(&relations);
    var prepared = try witness.prepareFrontierAir(
        std.testing.allocator,
        .{
            .is_first_col_idx = 0,
            .is_active_col_idx = 1,
            .main_col_offset = 0,
            .interaction_col_offset = 0,
        },
        &relations,
    );
    defer prepared.deinit();
    try std.testing.expectEqual(
        witness.frontier_rows.len,
        prepared.component.n_rows,
    );
    _ = prepared.component.asProverComponent();
    _ = prepared.component.asVerifierComponent();
}

test "incremental transition mutations fail relation closure" {
    const words = [_]TouchedWord{.{
        .address = 0x2000,
        .old_word = 0x01020304,
        .new_word = 0x01020305,
        .final_clock = 7,
    }};
    var witness = try build(std.testing.allocator, &words, &.{});
    defer witness.deinit();
    const relations = relations_mod.Relations.dummy();
    try witness.verifyMerkleAndPoseidonCancellation(&relations);

    witness.boundary_rows[0].value[0] ^= 1;
    try std.testing.expectError(
        error.IncrementalRelationNotClosed,
        witness.verifyMerkleAndPoseidonCancellation(&relations),
    );
    witness.boundary_rows[0].value[0] ^= 1;

    witness.frontier_rows[0].value +%= 1;
    try std.testing.expectError(
        error.IncrementalRelationNotClosed,
        witness.verifyMerkleAndPoseidonCancellation(&relations),
    );
}

test "non-default untouched subtrees are shared across both roots" {
    const touched = [_]TouchedWord{.{
        .address = 0x1000,
        .old_word = 0x11223344,
        .new_word = 0x55667788,
        .final_clock = 11,
    }};
    const untouched = TouchedWord{
        .address = 0x9000,
        .old_word = 0xaabbccdd,
        .new_word = 0xaabbccdd,
        .final_clock = 0,
    };
    const entry_words = [_]TouchedWord{ touched[0], untouched };
    var entry = try fullTreeForWords(
        std.testing.allocator,
        &entry_words,
        false,
    );
    defer entry.deinit(std.testing.allocator);
    const canonical_frontier = try canonicalFrontierFromEntryTree(
        std.testing.allocator,
        entry,
        &touched,
    );
    defer std.testing.allocator.free(canonical_frontier);
    try std.testing.expect(canonical_frontier.len != 0);

    var witness = try build(
        std.testing.allocator,
        &touched,
        canonical_frontier,
    );
    defer witness.deinit();
    var expected_exit = try fullTreeForWords(
        std.testing.allocator,
        &.{ touched[0], untouched },
        true,
    );
    defer expected_exit.deinit(std.testing.allocator);
    try std.testing.expectEqual(entry.root, witness.entry_root);
    try std.testing.expectEqual(expected_exit.root, witness.exit_root);
    const relations = relations_mod.Relations.dummy();
    try witness.verifyMerkleAndPoseidonCancellation(&relations);
}
