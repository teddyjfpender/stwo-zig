//! Diagnostic authority for an incremental Ethereum RW-memory transition.
//!
//! This module is intentionally not proof admission. It keeps one authenticated
//! sparse tree alive for a session, derives a canonical multiproof frontier for
//! each sorted touched-word set, and applies only the changed bytes to obtain
//! the next root. The authority is transport-safe profiling/planning material:
//! a future AIR must independently bind the touched inventory to memory-access
//! rows and prove the old-root/new-root transition before recursion may admit
//! it.

const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("stwo_riscv_frontend");

const m31 = @import("stwo_core").fields.m31;
const memory_poseidon2 = frontend.air.memory_commitment.poseidon2;
const sparse_merkle = frontend.air.memory_commitment.sparse_merkle;

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const SCHEMA = "stwo.ethereum.incremental-boundary-authority.v1";
pub const RECURSIVE_ADMISSIBLE = false;
pub const LEAF_DEPTH: u8 = @intCast(sparse_merkle.LEAF_DEPTH);
pub const MAX_ADDRESS_EXCLUSIVE: u32 = sparse_merkle.LEAF_COUNT;

const AUTHORITY_DOMAIN = "stwo.ethereum.incremental-boundary-authority.v1\x00";
const GENESIS_DOMAIN = "stwo.ethereum.incremental-boundary-session-genesis.v1\x00";

var validation_call_count = std.atomic.Value(u64).init(0);

pub const SparseWordV1 = struct {
    address: u32,
    value: u32,
};

/// Exact word boundary consumed by the future memory-transition component.
/// `final_clock` is transport custody for the memory-access-chain boundary;
/// it does not affect the Merkle root calculation.
pub const TouchedWordV1 = struct {
    address: u32,
    old_word: u32,
    new_word: u32,
    final_clock: u32,
};

/// One non-default untouched subtree needed by the canonical multiproof.
/// Default siblings are omitted and reconstructed from the pinned table.
pub const FrontierNodeV1 = struct {
    depth: u8,
    index: u32,
    value: u32,
};

pub const HashWorkV1 = struct {
    /// Old-root membership hashes for every induced internal path node.
    entry_hash_calls: u64,
    /// New-root hashes only for induced nodes containing a changed byte.
    exit_hash_calls: u64,
    total_hash_calls: u64,
    /// Zero means no provider. Otherwise this is the existing AIR floor of
    /// four or ceil(log2(total_hash_calls)), whichever is larger.
    max_shard_log: u8,
};

pub const IncrementalBoundaryAuthorityV1 = struct {
    allocator: std.mem.Allocator,
    segment_index: u32,
    entry_root: u32,
    exit_root: u32,
    touched_words: []TouchedWordV1,
    frontier_nodes: []FrontierNodeV1,
    changed_word_count: u32,
    work: HashWorkV1,
    prior_authority_id: [32]u8,
    authority_id: [32]u8,

    pub fn deinit(self: *IncrementalBoundaryAuthorityV1) void {
        self.allocator.free(self.touched_words);
        self.allocator.free(self.frontier_nodes);
        self.* = undefined;
    }

    /// Full mutation-sensitive validation. This reconstructs both roots from
    /// only touched values plus the canonical non-default frontier.
    pub fn validate(self: *const IncrementalBoundaryAuthorityV1) !void {
        if (builtin.is_test) _ = validation_call_count.fetchAdd(1, .monotonic);
        if (self.entry_root >= m31.Modulus or self.exit_root >= m31.Modulus)
            return error.NonCanonicalRoot;
        try validateTouchedWords(self.touched_words);
        try validateFrontierShape(self.frontier_nodes);

        if (self.touched_words.len == 0) {
            if (self.frontier_nodes.len != 0 or
                self.entry_root != self.exit_root or
                self.changed_word_count != 0 or
                !std.meta.eql(self.work, HashWorkV1{
                    .entry_hash_calls = 0,
                    .exit_hash_calls = 0,
                    .total_hash_calls = 0,
                    .max_shard_log = 0,
                }))
            {
                return error.InvalidEmptyTransition;
            }
            const empty_id = self.recomputeIdentity();
            if (!std.mem.eql(u8, &empty_id, &self.authority_id))
                return error.AuthorityIdentityMismatch;
            return;
        }

        var frontier = RetainedFrontier{
            .nodes = self.frontier_nodes,
        };
        var scratch = try deriveTransition(
            self.allocator,
            self.touched_words,
            &frontier,
        );
        defer scratch.deinit(self.allocator);
        if (frontier.at != self.frontier_nodes.len)
            return error.NonCanonicalFrontier;
        if (scratch.entry_root != self.entry_root)
            return error.EntryRootMismatch;
        if (scratch.exit_root != self.exit_root)
            return error.ExitRootMismatch;
        if (scratch.changed_word_count != self.changed_word_count)
            return error.ChangedWordCountMismatch;
        if (!std.meta.eql(scratch.work, self.work))
            return error.HashWorkMismatch;
        const expected_id = self.recomputeIdentity();
        if (!std.mem.eql(u8, &expected_id, &self.authority_id))
            return error.AuthorityIdentityMismatch;
    }

    /// External-plan comparison prevents a fully resealed authority from
    /// selecting different roots, order, or predecessor authority.
    pub fn validateAgainst(
        self: *const IncrementalBoundaryAuthorityV1,
        segment_index: u32,
        entry_root: u32,
        exit_root: u32,
        prior_authority_id: [32]u8,
    ) !void {
        try self.validate();
        if (self.segment_index != segment_index)
            return error.SegmentIndexMismatch;
        if (self.entry_root != entry_root)
            return error.EntryRootMismatch;
        if (self.exit_root != exit_root)
            return error.ExitRootMismatch;
        if (!std.mem.eql(u8, &self.prior_authority_id, &prior_authority_id))
            return error.PriorAuthorityMismatch;
    }

    /// Canonical transport identity. SHA-256 is a sidecar seal only; it must
    /// never replace the field-level transition constraints in recursion.
    pub fn recomputeIdentity(self: *const IncrementalBoundaryAuthorityV1) [32]u8 {
        var hash = Sha256.init(.{});
        hash.update(AUTHORITY_DOMAIN);
        hash.update(SCHEMA);
        putU32(&hash, self.segment_index);
        putU32(&hash, self.entry_root);
        putU32(&hash, self.exit_root);
        putU32(&hash, @intCast(self.touched_words.len));
        putU32(&hash, @intCast(self.frontier_nodes.len));
        putU32(&hash, self.changed_word_count);
        putU64(&hash, self.work.entry_hash_calls);
        putU64(&hash, self.work.exit_hash_calls);
        putU64(&hash, self.work.total_hash_calls);
        hash.update(&.{self.work.max_shard_log});
        hash.update(&self.prior_authority_id);
        for (self.touched_words) |word| {
            putU32(&hash, word.address);
            putU32(&hash, word.old_word);
            putU32(&hash, word.new_word);
            putU32(&hash, word.final_clock);
        }
        for (self.frontier_nodes) |node| {
            hash.update(&.{node.depth});
            putU32(&hash, node.index);
            putU32(&hash, node.value);
        }
        var result: [32]u8 = undefined;
        hash.final(&result);
        return result;
    }
};

/// Process-local proof that a complete V1 transition authority has passed its
/// mutation-sensitive sparse-root reconstruction. It is never serialized and
/// owns no allocations; callers must keep the underlying authority slices
/// alive while using the token.
pub const ValidatedIncrementalBoundaryAuthorityV1 = struct {
    value: IncrementalBoundaryAuthorityV1,

    pub fn init(
        value: *const IncrementalBoundaryAuthorityV1,
    ) !ValidatedIncrementalBoundaryAuthorityV1 {
        try value.validate();
        return .{ .value = value.* };
    }

    pub fn authority(
        self: *const ValidatedIncrementalBoundaryAuthorityV1,
    ) *const IncrementalBoundaryAuthorityV1 {
        return &self.value;
    }
};

/// Persistent, process-local tree owner. The full state is admitted once;
/// every later transition reads only touched paths and updates only changed
/// path nodes. It is not serializable proof authority.
pub const SessionTree = struct {
    allocator: std.mem.Allocator,
    nodes: std.AutoHashMap(u64, u32),
    root: u32,
    next_segment_index: u32,
    previous_authority_id: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        session_identity: [32]u8,
        first_segment_index: u32,
        initial_words: []const SparseWordV1,
        expected_root: u32,
    ) !SessionTree {
        if (expected_root >= m31.Modulus) return error.NonCanonicalRoot;
        try validateSparseWords(initial_words);

        var leaves: std.ArrayList(sparse_merkle.Leaf) = .empty;
        defer leaves.deinit(allocator);
        try leaves.ensureTotalCapacity(
            allocator,
            std.math.mul(usize, initial_words.len, 4) catch
                return error.AuthoritySizeOverflow,
        );
        for (initial_words) |word| appendNonzeroBytes(&leaves, word.address, word.value);

        var built = try sparse_merkle.build(allocator, leaves.items);
        defer built.deinit(allocator);
        if (built.root != expected_root) return error.EntryRootMismatch;

        var nodes = std.AutoHashMap(u64, u32).init(allocator);
        errdefer nodes.deinit();
        const capacity = std.math.add(
            usize,
            built.leaves.len,
            built.nodes.len,
        ) catch return error.AuthoritySizeOverflow;
        try nodes.ensureTotalCapacity(@intCast(capacity));
        for (built.leaves) |leaf| {
            nodes.putAssumeCapacity(nodeKey(LEAF_DEPTH, leaf.index), leaf.value);
        }
        for (built.nodes) |node| {
            const parent_depth: u8 = @intCast(node.depth - 1);
            nodes.putAssumeCapacity(
                nodeKey(parent_depth, node.index / 2),
                node.current.value,
            );
        }

        return .{
            .allocator = allocator,
            .nodes = nodes,
            .root = expected_root,
            .next_segment_index = first_segment_index,
            .previous_authority_id = genesisIdentity(
                session_identity,
                first_segment_index,
                expected_root,
                @intCast(initial_words.len),
            ),
        };
    }

    pub fn deinit(self: *SessionTree) void {
        self.nodes.deinit();
        self.* = undefined;
    }

    pub fn currentRoot(self: *const SessionTree) u32 {
        return self.root;
    }

    pub fn nextSegmentIndex(self: *const SessionTree) u32 {
        return self.next_segment_index;
    }

    pub fn priorAuthorityId(self: *const SessionTree) [32]u8 {
        return self.previous_authority_id;
    }

    /// Derive, validate, and apply one transition. All allocation and
    /// reconstruction checks finish before the persistent map is mutated.
    pub fn apply(
        self: *SessionTree,
        segment_index: u32,
        touched_words: []const TouchedWordV1,
    ) !IncrementalBoundaryAuthorityV1 {
        if (segment_index != self.next_segment_index)
            return error.SegmentIndexMismatch;
        const next_segment_index = std.math.add(u32, segment_index, 1) catch
            return error.SegmentIndexOverflow;
        try validateTouchedWords(touched_words);
        for (touched_words) |word| {
            if (self.wordValue(word.address) != word.old_word)
                return error.OldWordMismatch;
        }

        if (touched_words.len == 0) {
            const retained_touched = try self.allocator.alloc(TouchedWordV1, 0);
            errdefer self.allocator.free(retained_touched);
            const retained_frontier = try self.allocator.alloc(FrontierNodeV1, 0);
            errdefer self.allocator.free(retained_frontier);
            var authority = IncrementalBoundaryAuthorityV1{
                .allocator = self.allocator,
                .segment_index = segment_index,
                .entry_root = self.root,
                .exit_root = self.root,
                .touched_words = retained_touched,
                .frontier_nodes = retained_frontier,
                .changed_word_count = 0,
                .work = .{
                    .entry_hash_calls = 0,
                    .exit_hash_calls = 0,
                    .total_hash_calls = 0,
                    .max_shard_log = 0,
                },
                .prior_authority_id = self.previous_authority_id,
                .authority_id = undefined,
            };
            authority.authority_id = authority.recomputeIdentity();
            try authority.validateAgainst(
                segment_index,
                self.root,
                self.root,
                self.previous_authority_id,
            );
            self.next_segment_index = next_segment_index;
            self.previous_authority_id = authority.authority_id;
            return authority;
        }

        var frontier_nodes: std.ArrayList(FrontierNodeV1) = .empty;
        defer frontier_nodes.deinit(self.allocator);
        var provider = SessionFrontier{
            .tree = self,
            .frontier = &frontier_nodes,
        };
        var scratch = try deriveTransition(
            self.allocator,
            touched_words,
            &provider,
        );
        defer scratch.deinit(self.allocator);
        if (scratch.entry_root != self.root)
            return error.EntryRootMismatch;

        const retained_touched = try self.allocator.dupe(TouchedWordV1, touched_words);
        errdefer self.allocator.free(retained_touched);
        const retained_frontier = try frontier_nodes.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(retained_frontier);
        var authority = IncrementalBoundaryAuthorityV1{
            .allocator = self.allocator,
            .segment_index = segment_index,
            .entry_root = scratch.entry_root,
            .exit_root = scratch.exit_root,
            .touched_words = retained_touched,
            .frontier_nodes = retained_frontier,
            .changed_word_count = scratch.changed_word_count,
            .work = scratch.work,
            .prior_authority_id = self.previous_authority_id,
            .authority_id = undefined,
        };
        authority.authority_id = authority.recomputeIdentity();
        try authority.validateAgainst(
            segment_index,
            self.root,
            scratch.exit_root,
            self.previous_authority_id,
        );

        // Capacity is the final fallible operation. From this point through
        // publication every map operation is allocation-free.
        try self.nodes.ensureUnusedCapacity(@intCast(scratch.updates.items.len));
        for (scratch.updates.items) |update| {
            const key = nodeKey(update.depth, update.index);
            if (update.value == memory_poseidon2.DEFAULT_HASHES[update.depth]) {
                _ = self.nodes.remove(key);
            } else {
                self.nodes.putAssumeCapacity(key, update.value);
            }
        }
        self.root = scratch.exit_root;
        self.next_segment_index = next_segment_index;
        self.previous_authority_id = authority.authority_id;
        return authority;
    }

    fn nodeValue(self: *const SessionTree, depth: u8, index: u32) u32 {
        return self.nodes.get(nodeKey(depth, index)) orelse
            memory_poseidon2.DEFAULT_HASHES[depth];
    }

    fn wordValue(self: *const SessionTree, address: u32) u32 {
        var result: u32 = 0;
        for (0..4) |limb| {
            const shift: u5 = @intCast(limb * 8);
            result |= self.nodeValue(
                LEAF_DEPTH,
                address + @as(u32, @intCast(limb)),
            ) << shift;
        }
        return result;
    }
};

const PathValue = struct {
    index: u32,
    old_value: u32,
    new_value: u32,
    changed: bool,
};

const NodeUpdate = struct {
    depth: u8,
    index: u32,
    value: u32,
};

const TransitionScratch = struct {
    entry_root: u32,
    exit_root: u32,
    changed_word_count: u32,
    work: HashWorkV1,
    updates: std.ArrayList(NodeUpdate),

    fn deinit(self: *TransitionScratch, allocator: std.mem.Allocator) void {
        self.updates.deinit(allocator);
        self.* = undefined;
    }
};

const SessionFrontier = struct {
    tree: *const SessionTree,
    frontier: *std.ArrayList(FrontierNodeV1),

    fn get(self: *SessionFrontier, depth: u8, index: u32) !u32 {
        const value = self.tree.nodeValue(depth, index);
        if (value != memory_poseidon2.DEFAULT_HASHES[depth]) {
            try self.frontier.append(self.tree.allocator, .{
                .depth = depth,
                .index = index,
                .value = value,
            });
        }
        return value;
    }
};

const RetainedFrontier = struct {
    nodes: []const FrontierNodeV1,
    at: usize = 0,

    fn get(self: *RetainedFrontier, depth: u8, index: u32) !u32 {
        if (self.at < self.nodes.len) {
            const candidate = self.nodes[self.at];
            if (candidate.depth == depth and candidate.index == index) {
                self.at += 1;
                return candidate.value;
            }
        }
        return memory_poseidon2.DEFAULT_HASHES[depth];
    }
};

fn deriveTransition(
    allocator: std.mem.Allocator,
    touched_words: []const TouchedWordV1,
    frontier: anytype,
) !TransitionScratch {
    if (touched_words.len == 0) return error.EmptyTouchedTransition;
    const leaf_count = std.math.mul(usize, touched_words.len, 4) catch
        return error.AuthoritySizeOverflow;
    var current: std.ArrayList(PathValue) = .empty;
    defer current.deinit(allocator);
    try current.ensureTotalCapacity(allocator, leaf_count);
    var updates: std.ArrayList(NodeUpdate) = .empty;
    errdefer updates.deinit(allocator);

    var changed_word_count: u32 = 0;
    for (touched_words) |word| {
        if (word.old_word != word.new_word) {
            changed_word_count = std.math.add(
                u32,
                changed_word_count,
                1,
            ) catch return error.AuthoritySizeOverflow;
        }
        for (0..4) |limb| {
            const shift: u5 = @intCast(limb * 8);
            const old_value: u8 = @truncate(word.old_word >> shift);
            const new_value: u8 = @truncate(word.new_word >> shift);
            const changed = old_value != new_value;
            current.appendAssumeCapacity(.{
                .index = word.address + @as(u32, @intCast(limb)),
                .old_value = old_value,
                .new_value = new_value,
                .changed = changed,
            });
            if (changed) try updates.append(allocator, .{
                .depth = LEAF_DEPTH,
                .index = word.address + @as(u32, @intCast(limb)),
                .value = new_value,
            });
        }
    }

    var entry_hash_calls: u64 = 0;
    var exit_hash_calls: u64 = 0;
    var depth: u8 = LEAF_DEPTH;
    while (depth > 0) : (depth -= 1) {
        var next: std.ArrayList(PathValue) = .empty;
        errdefer next.deinit(allocator);
        // Sparse nodes need not be siblings. In the worst case every current
        // node has a frontier sibling and therefore produces its own parent.
        // Reserving ceil(n / 2) before appendAssumeCapacity corrupts the next
        // level whenever allocator growth leaves capacity below n.
        try next.ensureTotalCapacity(allocator, current.items.len);
        var at: usize = 0;
        while (at < current.items.len) {
            const parent_index = current.items[at].index / 2;
            const left_index = parent_index * 2;
            const right_index = left_index + 1;
            var left: PathValue = undefined;
            if (current.items[at].index == left_index) {
                left = current.items[at];
                at += 1;
            } else {
                const value = try frontier.get(depth, left_index);
                left = .{
                    .index = left_index,
                    .old_value = value,
                    .new_value = value,
                    .changed = false,
                };
            }
            var right: PathValue = undefined;
            if (at < current.items.len and current.items[at].index == right_index) {
                right = current.items[at];
                at += 1;
            } else {
                const value = try frontier.get(depth, right_index);
                right = .{
                    .index = right_index,
                    .old_value = value,
                    .new_value = value,
                    .changed = false,
                };
            }
            const changed = left.changed or right.changed;
            const old_parent = memory_poseidon2.hashPair(
                left.old_value,
                right.old_value,
            );
            const new_parent = if (changed)
                memory_poseidon2.hashPair(left.new_value, right.new_value)
            else
                old_parent;
            entry_hash_calls = std.math.add(u64, entry_hash_calls, 1) catch
                return error.AuthoritySizeOverflow;
            if (changed) {
                exit_hash_calls = std.math.add(u64, exit_hash_calls, 1) catch
                    return error.AuthoritySizeOverflow;
                try updates.append(allocator, .{
                    .depth = depth - 1,
                    .index = parent_index,
                    .value = new_parent,
                });
            }
            next.appendAssumeCapacity(.{
                .index = parent_index,
                .old_value = old_parent,
                .new_value = new_parent,
                .changed = changed,
            });
        }
        current.deinit(allocator);
        current = next;
    }
    if (current.items.len != 1 or current.items[0].index != 0)
        return error.InvalidTransitionTopology;
    const total_hash_calls = std.math.add(
        u64,
        entry_hash_calls,
        exit_hash_calls,
    ) catch return error.AuthoritySizeOverflow;
    return .{
        .entry_root = current.items[0].old_value,
        .exit_root = current.items[0].new_value,
        .changed_word_count = changed_word_count,
        .work = .{
            .entry_hash_calls = entry_hash_calls,
            .exit_hash_calls = exit_hash_calls,
            .total_hash_calls = total_hash_calls,
            .max_shard_log = providerLogSize(total_hash_calls),
        },
        .updates = updates,
    };
}

fn validateSparseWords(words: []const SparseWordV1) !void {
    var previous: ?u32 = null;
    for (words) |word| {
        try validateWordAddress(word.address);
        if (word.value == 0) return error.NonCanonicalSparseZero;
        if (previous) |address| {
            if (word.address <= address) return error.NonCanonicalWordOrder;
        }
        previous = word.address;
    }
}

fn validateTouchedWords(words: []const TouchedWordV1) !void {
    var previous: ?u32 = null;
    for (words) |word| {
        try validateWordAddress(word.address);
        if (previous) |address| {
            if (word.address <= address) return error.NonCanonicalWordOrder;
        }
        previous = word.address;
    }
}

fn validateFrontierShape(nodes: []const FrontierNodeV1) !void {
    var previous_depth: ?u8 = null;
    var previous_index: u32 = 0;
    for (nodes) |node| {
        if (node.depth == 0 or node.depth > LEAF_DEPTH)
            return error.NonCanonicalFrontier;
        const bound = @as(u32, 1) << @intCast(node.depth);
        if (node.index >= bound or node.value >= m31.Modulus or
            node.value == memory_poseidon2.DEFAULT_HASHES[node.depth])
        {
            return error.NonCanonicalFrontier;
        }
        if (previous_depth) |depth| {
            if (node.depth > depth or
                (node.depth == depth and node.index <= previous_index))
            {
                return error.NonCanonicalFrontier;
            }
        }
        previous_depth = node.depth;
        previous_index = node.index;
    }
}

fn validateWordAddress(address: u32) !void {
    if ((address & 3) != 0 or address > MAX_ADDRESS_EXCLUSIVE - 4)
        return error.InvalidWordAddress;
}

fn appendNonzeroBytes(
    leaves: *std.ArrayList(sparse_merkle.Leaf),
    address: u32,
    word: u32,
) void {
    for (0..4) |limb| {
        const shift: u5 = @intCast(limb * 8);
        const value: u8 = @truncate(word >> shift);
        if (value == 0) continue;
        leaves.appendAssumeCapacity(.{
            .index = address + @as(u32, @intCast(limb)),
            .value = value,
        });
    }
}

fn providerLogSize(total_hash_calls: u64) u8 {
    if (total_hash_calls == 0) return 0;
    const required: u8 = @intCast(std.math.log2_int_ceil(u64, total_hash_calls));
    return @max(@as(u8, 4), required);
}

fn nodeKey(depth: u8, index: u32) u64 {
    return (@as(u64, depth) << 32) | index;
}

fn genesisIdentity(
    session_identity: [32]u8,
    first_segment_index: u32,
    initial_root: u32,
    sparse_word_count: u32,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(GENESIS_DOMAIN);
    hash.update(&session_identity);
    putU32(&hash, first_segment_index);
    putU32(&hash, initial_root);
    putU32(&hash, sparse_word_count);
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn putU32(hash: *Sha256, value: u32) void {
    var encoded: [4]u8 = undefined;
    std.mem.writeInt(u32, &encoded, value, .little);
    hash.update(&encoded);
}

fn putU64(hash: *Sha256, value: u64) void {
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, value, .little);
    hash.update(&encoded);
}

pub const testing = struct {
    pub fn resetValidationCallCount() void {
        validation_call_count.store(0, .monotonic);
    }

    pub fn validationCallCount() u64 {
        return validation_call_count.load(.monotonic);
    }
};

fn fullRoot(allocator: std.mem.Allocator, words: []const SparseWordV1) !u32 {
    var leaves: std.ArrayList(sparse_merkle.Leaf) = .empty;
    defer leaves.deinit(allocator);
    try leaves.ensureTotalCapacity(
        allocator,
        std.math.mul(usize, words.len, 4) catch
            return error.AuthoritySizeOverflow,
    );
    for (words) |word| appendNonzeroBytes(&leaves, word.address, word.value);
    var tree = try sparse_merkle.build(allocator, leaves.items);
    defer tree.deinit(allocator);
    return tree.root;
}

fn expectRejected(result: anytype) !void {
    _ = result catch return;
    return error.ExpectedMutationRejection;
}

test "incremental boundary authority matches full rebuild and chains session roots" {
    const allocator = std.testing.allocator;
    var state = [_]SparseWordV1{
        .{ .address = 0x1000, .value = 0x1122_3344 },
        .{ .address = 0x2000, .value = 0x5566_7788 },
        .{ .address = 0x3000, .value = 0x00aa_00bb },
    };
    const entry_root = try fullRoot(allocator, &state);
    var session = try SessionTree.init(
        allocator,
        [_]u8{0x5a} ** 32,
        7,
        &state,
        entry_root,
    );
    defer session.deinit();
    const prior = session.priorAuthorityId();

    const touched = [_]TouchedWordV1{
        .{
            .address = 0x1000,
            .old_word = state[0].value,
            .new_word = 0x99aa_bbcc,
            .final_clock = 17,
        },
        .{
            .address = 0x3000,
            .old_word = state[2].value,
            .new_word = state[2].value,
            .final_clock = 21,
        },
    };
    var authority = try session.apply(7, &touched);
    defer authority.deinit();
    state[0].value = touched[0].new_word;
    const expected_exit = try fullRoot(allocator, &state);
    try std.testing.expectEqual(expected_exit, authority.exit_root);
    try std.testing.expectEqual(expected_exit, session.currentRoot());
    try std.testing.expect(authority.frontier_nodes.len != 0);
    try std.testing.expectEqual(@as(u32, 1), authority.changed_word_count);
    try std.testing.expect(authority.work.entry_hash_calls != 0);
    try std.testing.expect(authority.work.exit_hash_calls != 0);
    try std.testing.expectEqual(
        authority.work.entry_hash_calls + authority.work.exit_hash_calls,
        authority.work.total_hash_calls,
    );
    try authority.validateAgainst(7, entry_root, expected_exit, prior);

    const second_prior = session.priorAuthorityId();
    var read_only = try session.apply(8, &.{.{
        .address = 0x2000,
        .old_word = state[1].value,
        .new_word = state[1].value,
        .final_clock = 5,
    }});
    defer read_only.deinit();
    try std.testing.expectEqual(expected_exit, read_only.exit_root);
    try std.testing.expectEqual(@as(u64, 0), read_only.work.exit_hash_calls);
    try read_only.validateAgainst(8, expected_exit, expected_exit, second_prior);
}

test "resealed touched, old/new, and frontier mutations cannot change planned roots" {
    const allocator = std.testing.allocator;
    const state = [_]SparseWordV1{
        .{ .address = 0x1000, .value = 0x0102_0304 },
        .{ .address = 0x2000, .value = 0xa1a2_a3a4 },
    };
    const entry_root = try fullRoot(allocator, &state);
    var session = try SessionTree.init(
        allocator,
        [_]u8{0x33} ** 32,
        0,
        &state,
        entry_root,
    );
    defer session.deinit();
    const prior = session.priorAuthorityId();
    var authority = try session.apply(0, &.{.{
        .address = 0x1000,
        .old_word = state[0].value,
        .new_word = 0x1112_1314,
        .final_clock = 9,
    }});
    defer authority.deinit();
    const exit_root = authority.exit_root;
    try std.testing.expect(authority.frontier_nodes.len != 0);

    authority.touched_words[0].address = 0x1004;
    authority.authority_id = authority.recomputeIdentity();
    try expectRejected(authority.validateAgainst(0, entry_root, exit_root, prior));
    authority.touched_words[0].address = 0x1000;

    authority.touched_words[0].old_word ^= 1;
    authority.authority_id = authority.recomputeIdentity();
    try expectRejected(authority.validateAgainst(0, entry_root, exit_root, prior));
    authority.touched_words[0].old_word ^= 1;

    authority.touched_words[0].new_word ^= 1;
    authority.authority_id = authority.recomputeIdentity();
    try expectRejected(authority.validateAgainst(0, entry_root, exit_root, prior));
    authority.touched_words[0].new_word ^= 1;

    authority.frontier_nodes[0].value = if (authority.frontier_nodes[0].value + 1 < m31.Modulus)
        authority.frontier_nodes[0].value + 1
    else
        authority.frontier_nodes[0].value - 1;
    authority.authority_id = authority.recomputeIdentity();
    try expectRejected(authority.validateAgainst(0, entry_root, exit_root, prior));
}
