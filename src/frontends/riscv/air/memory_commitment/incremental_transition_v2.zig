//! Changed-only sparse-memory transition witness.
//!
//! V1 authenticates every touched entry byte and rehashes the same induced
//! topology for the exit root.  V2 keeps the entry authentication unchanged,
//! but hashes only paths containing changed bytes on exit.  Simple bridge
//! rows prove unchanged final leaves and reuse entry-authenticated subtrees.
//! This realizes the exact `entry_hash_calls + exit_hash_calls` cost reported
//! by `incremental_memory_cost_tool.zig`.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const bridge = @import("incremental_bridge_v2.zig");
const bridge_component = @import("incremental_bridge_component_v2.zig");
const memory_interaction = @import("interaction.zig");
const merkle_node = @import("merkle_node.zig");
const poseidon2 = @import("poseidon2.zig");
const poseidon2_air = @import("poseidon2_air.zig");
const relations_mod = @import("../relation_challenges.zig");
const v1 = @import("incremental_transition_v1.zig");

pub const PRODUCTION_ACTIVE = false;
pub const PROFILE = "riscv-incremental-memory-transition-v2-changed-only";

pub const HashWork = struct {
    entry_calls: u64,
    exit_calls: u64,
    total_calls: u64,
    provider_log_size: u8,
    bridge_rows: u64,
};

pub const Witness = struct {
    allocator: std.mem.Allocator,
    entry_root: u32,
    exit_root: u32,
    boundary_rows: []@import("boundary.zig").Row,
    merkle_rows: []merkle_node.NodeRow,
    bridge_rows: []bridge.Row,
    poseidon_calls: []poseidon2_air.Call,
    work: HashWork,

    pub fn deinit(self: *Witness) void {
        self.allocator.free(self.boundary_rows);
        self.allocator.free(self.merkle_rows);
        self.allocator.free(self.bridge_rows);
        self.allocator.free(self.poseidon_calls);
        self.* = undefined;
    }

    pub fn prepareBridgeAir(
        self: *const Witness,
        allocator: std.mem.Allocator,
        placement: bridge_component.Placement,
        relations: *const relations_mod.Relations,
    ) !PreparedBridgeAir {
        const log_size = componentLog(self.bridge_rows.len);
        var main = try bridge.generateMain(
            allocator,
            self.bridge_rows,
            log_size,
        );
        errdefer main.deinit(allocator);
        var interaction = try bridge.generateInteraction(
            allocator,
            self.bridge_rows,
            log_size,
            self.entry_root,
            self.exit_root,
            relations,
        );
        errdefer interaction.deinit(allocator);
        const component = try bridge_component.IncrementalBridgeComponentV2.init(
            log_size,
            @intCast(self.bridge_rows.len),
            self.entry_root,
            self.exit_root,
            placement,
            relations,
            interaction.claim,
        );
        return .{
            .allocator = allocator,
            .main = main,
            .interaction = interaction,
            .component = component,
        };
    }

    pub fn verifyMerkleAndPoseidonCancellation(
        self: *const Witness,
        relations: *const relations_mod.Relations,
    ) !void {
        try self.verifyMerkleMultiset();
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
        const bridge_claim = try bridge.diagnosticClaim(
            self.bridge_rows,
            self.entry_root,
            self.exit_root,
            relations,
        );
        const roots = (try rootEmit(self.entry_root, relations))
            .add(try rootEmit(self.exit_root, relations));
        const total = nodes.claims.total().add(hashes.claims.total())
            .add(boundary_claim).add(bridge_claim).add(roots);
        if (!total.isZero()) return error.IncrementalRelationNotClosed;
    }

    fn verifyMerkleMultiset(self: *const Witness) !void {
        var counts = std.AutoHashMap(MerkleKey, i64).init(self.allocator);
        defer counts.deinit();
        for (self.boundary_rows) |row| {
            for (row.value, 0..) |value, limb| try addCount(&counts, .{
                .root = row.root,
                .index = row.addr + @as(u32, @intCast(limb)),
                .depth = 30,
                .value = value,
            }, -1);
        }
        for (self.merkle_rows) |row| {
            try addCount(&counts, .{
                .root = row.root,
                .index = row.index,
                .depth = row.depth,
                .value = row.lhs,
            }, row.lhs_mult);
            try addCount(&counts, .{
                .root = row.root,
                .index = row.index + 1,
                .depth = row.depth,
                .value = row.rhs,
            }, row.rhs_mult);
            try addCount(&counts, .{
                .root = row.root,
                .index = row.index / 2,
                .depth = row.depth - 1,
                .value = row.cur,
            }, -@as(i64, row.cur_mult));
        }
        for (self.bridge_rows) |row| {
            const coefficients: [2]i64 = switch (row.mode) {
                .external_entry => .{ -1, 0 },
                .external_both => .{ -1, -1 },
                .unchanged_leaf => .{ -1, 1 },
                .reused_subtree => .{ 1, -1 },
            };
            try addCount(&counts, .{
                .root = self.entry_root,
                .index = row.index,
                .depth = row.depth,
                .value = row.value,
            }, coefficients[0]);
            try addCount(&counts, .{
                .root = self.exit_root,
                .index = row.index,
                .depth = row.depth,
                .value = row.value,
            }, coefficients[1]);
        }
        try addCount(&counts, .{
            .root = self.entry_root,
            .index = 0,
            .depth = 0,
            .value = self.entry_root,
        }, 1);
        try addCount(&counts, .{
            .root = self.exit_root,
            .index = 0,
            .depth = 0,
            .value = self.exit_root,
        }, 1);
        var iterator = counts.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.* == 0) continue;
            return error.IncrementalMerkleMultisetNotClosed;
        }
    }
};

pub const PreparedBridgeAir = struct {
    allocator: std.mem.Allocator,
    main: bridge.Columns,
    interaction: bridge.Interaction,
    component: bridge_component.IncrementalBridgeComponentV2,

    pub fn deinit(self: *PreparedBridgeAir) void {
        self.main.deinit(self.allocator);
        self.interaction.deinit(self.allocator);
        self.* = undefined;
    }
};

const MerkleKey = struct {
    root: u32,
    index: u32,
    depth: u32,
    value: u32,
};

const ExitValue = struct {
    index: u32,
    value: u32,
};

const LeafLocation = struct {
    row: usize,
    right: bool,
};

const SourceKind = union(enum) {
    external: usize,
    leaf: LeafLocation,
    internal: usize,
};

const Source = struct {
    value: u32,
    kind: SourceKind,
    used: bool = false,
};

pub fn build(
    allocator: std.mem.Allocator,
    touched_words: []const v1.TouchedWord,
    canonical_frontier: []const v1.FrontierNode,
) !Witness {
    var full = try v1.build(allocator, touched_words, canonical_frontier);
    defer full.deinit();
    const entry_count: usize = @intCast(full.work.entry_calls);
    if (entry_count * 2 != full.merkle_rows.len)
        return error.InvalidIncrementalTopology;

    var old_rows = try allocator.dupe(
        merkle_node.NodeRow,
        full.merkle_rows[0..entry_count],
    );
    defer allocator.free(old_rows);
    var bridge_rows: std.ArrayList(bridge.Row) = .empty;
    errdefer bridge_rows.deinit(allocator);
    try bridge_rows.ensureTotalCapacity(allocator, full.frontier_rows.len);
    for (full.frontier_rows) |row| bridge_rows.appendAssumeCapacity(.{
        .index = row.index,
        .depth = row.depth,
        .value = row.value,
        .mode = .external_entry,
    });

    var sources = std.AutoHashMap(u64, Source).init(allocator);
    defer sources.deinit();
    try sources.ensureTotalCapacity(@intCast(
        full.frontier_rows.len + entry_count + touched_words.len * 4,
    ));
    for (full.frontier_rows, 0..) |row, index| {
        try putSource(&sources, treeKey(@intCast(row.depth), row.index), .{
            .value = row.value,
            .kind = .{ .external = index },
        });
    }
    for (old_rows, 0..) |row, index| {
        try putSource(&sources, treeKey(
            @intCast(row.depth - 1),
            row.index / 2,
        ), .{
            .value = row.cur,
            .kind = .{ .internal = index },
        });
        if (row.depth != 30) continue;
        const left_key = treeKey(30, row.index);
        if (!sources.contains(left_key)) try putSource(&sources, left_key, .{
            .value = row.lhs,
            .kind = .{ .leaf = .{ .row = index, .right = false } },
        });
        const right_key = treeKey(30, row.index + 1);
        if (!sources.contains(right_key)) try putSource(&sources, right_key, .{
            .value = row.rhs,
            .kind = .{ .leaf = .{ .row = index, .right = true } },
        });
    }

    const changed_capacity = try std.math.mul(usize, touched_words.len, 4);
    var current = try allocator.alloc(ExitValue, changed_capacity);
    defer allocator.free(current);
    var current_len: usize = 0;
    for (touched_words) |word| {
        for (0..4) |limb| {
            const shift: u5 = @intCast(limb * 8);
            const old_value: u8 = @truncate(word.old_word >> shift);
            const new_value: u8 = @truncate(word.new_word >> shift);
            if (old_value == new_value) continue;
            current[current_len] = .{
                .index = word.address + @as(u32, @intCast(limb)),
                .value = new_value,
            };
            current_len += 1;
        }
    }

    var exit_rows: std.ArrayList(merkle_node.NodeRow) = .empty;
    defer exit_rows.deinit(allocator);
    var depth: u8 = 30;
    while (depth > 0 and current_len > 0) : (depth -= 1) {
        var next: std.ArrayList(ExitValue) = .empty;
        errdefer next.deinit(allocator);
        try next.ensureTotalCapacity(allocator, (current_len + 1) / 2);
        var at: usize = 0;
        while (at < current_len) {
            const parent_index = current[at].index / 2;
            const left_index = parent_index * 2;
            const right_index = left_index + 1;
            const left = if (current[at].index == left_index) blk: {
                const value = current[at];
                at += 1;
                break :blk value;
            } else ExitValue{
                .index = left_index,
                .value = try useSource(
                    allocator,
                    &sources,
                    old_rows,
                    &bridge_rows,
                    depth,
                    left_index,
                ),
            };
            const right = if (at < current_len and
                current[at].index == right_index)
            blk: {
                const value = current[at];
                at += 1;
                break :blk value;
            } else ExitValue{
                .index = right_index,
                .value = try useSource(
                    allocator,
                    &sources,
                    old_rows,
                    &bridge_rows,
                    depth,
                    right_index,
                ),
            };
            const parent = poseidon2.hashPair(left.value, right.value);
            try exit_rows.append(allocator, .{
                .index = left_index,
                .depth = depth,
                .lhs = left.value,
                .rhs = right.value,
                .cur = parent,
                .lhs_mult = 1,
                .rhs_mult = 1,
                .cur_mult = 1,
                .root = 0,
            });
            next.appendAssumeCapacity(.{
                .index = parent_index,
                .value = parent,
            });
        }
        @memcpy(current[0..next.items.len], next.items);
        current_len = next.items.len;
        next.deinit(allocator);
    }

    const exit_root = if (current_len == 0) blk: {
        const root = sources.getPtr(treeKey(0, 0)) orelse
            return error.MissingIncrementalSource;
        if (root.value != full.entry_root or root.used)
            return error.InvalidIncrementalTopology;
        root.used = true;
        const row_index = switch (root.kind) {
            .internal => |index| index,
            else => return error.InvalidIncrementalTopology,
        };
        try incrementMultiplicity(&old_rows[row_index].cur_mult);
        try bridge_rows.append(allocator, .{
            .index = 0,
            .depth = 0,
            .value = root.value,
            .mode = .reused_subtree,
        });
        break :blk full.entry_root;
    } else blk: {
        if (current_len != 1 or current[0].index != 0)
            return error.InvalidIncrementalTopology;
        break :blk current[0].value;
    };
    if (exit_root != full.exit_root) return error.ExitRootMismatch;
    for (exit_rows.items) |*row| row.root = exit_root;

    // Every unchanged final byte still appears in the ordinary memory
    // boundary table.  One leaf bridge proves it equals the authenticated
    // entry byte without forcing an exit Poseidon path.
    for (touched_words) |word| {
        for (0..4) |limb| {
            const shift: u5 = @intCast(limb * 8);
            const old_value: u8 = @truncate(word.old_word >> shift);
            const new_value: u8 = @truncate(word.new_word >> shift);
            if (old_value != new_value) continue;
            const index = word.address + @as(u32, @intCast(limb));
            var source = sources.getPtr(treeKey(30, index)) orelse
                return error.MissingIncrementalSource;
            switch (source.kind) {
                .leaf => |location| {
                    if (!source.used) {
                        try exposeLeaf(old_rows, location);
                        source.used = true;
                        try bridge_rows.append(allocator, .{
                            .index = index,
                            .depth = 30,
                            .value = old_value,
                            .mode = .unchanged_leaf,
                        });
                    }
                },
                else => return error.InvalidIncrementalTopology,
            }
        }
    }

    const node_count = try std.math.add(
        usize,
        old_rows.len,
        exit_rows.items.len,
    );
    const merkle_rows = try allocator.alloc(merkle_node.NodeRow, node_count);
    errdefer allocator.free(merkle_rows);
    @memcpy(merkle_rows[0..old_rows.len], old_rows);
    @memcpy(merkle_rows[old_rows.len..], exit_rows.items);
    const calls = try merkle_node.calls(allocator, merkle_rows);
    errdefer allocator.free(calls);
    const boundary_rows = try allocator.dupe(
        @import("boundary.zig").Row,
        full.boundary_rows,
    );
    errdefer allocator.free(boundary_rows);
    const total_calls: u64 = @intCast(calls.len);
    const bridge_count: u64 = @intCast(bridge_rows.items.len);
    const owned_bridge_rows = try bridge_rows.toOwnedSlice(allocator);
    return .{
        .allocator = allocator,
        .entry_root = full.entry_root,
        .exit_root = exit_root,
        .boundary_rows = boundary_rows,
        .merkle_rows = merkle_rows,
        .bridge_rows = owned_bridge_rows,
        .poseidon_calls = calls,
        .work = .{
            .entry_calls = @intCast(old_rows.len),
            .exit_calls = @intCast(exit_rows.items.len),
            .total_calls = total_calls,
            .provider_log_size = @intCast(componentLog(calls.len)),
            .bridge_rows = bridge_count,
        },
    };
}

fn useSource(
    allocator: std.mem.Allocator,
    sources: *std.AutoHashMap(u64, Source),
    old_rows: []merkle_node.NodeRow,
    bridge_rows: *std.ArrayList(bridge.Row),
    depth: u8,
    index: u32,
) !u32 {
    var source = sources.getPtr(treeKey(depth, index)) orelse
        return error.MissingIncrementalSource;
    if (source.used) return error.DuplicateIncrementalSource;
    source.used = true;
    switch (source.kind) {
        .external => |row_index| {
            if (bridge_rows.items[row_index].mode != .external_entry)
                return error.DuplicateIncrementalSource;
            bridge_rows.items[row_index].mode = .external_both;
        },
        // A leaf used directly by an exit row is authenticated by the final
        // ordinary boundary tuple, so it needs no cross-root bridge.
        .leaf => {},
        .internal => |row_index| {
            try incrementMultiplicity(&old_rows[row_index].cur_mult);
            try bridge_rows.append(allocator, .{
                .index = index,
                .depth = depth,
                .value = source.value,
                .mode = .reused_subtree,
            });
        },
    }
    return source.value;
}

fn exposeLeaf(
    old_rows: []merkle_node.NodeRow,
    location: LeafLocation,
) !void {
    const multiplicity = if (location.right)
        &old_rows[location.row].rhs_mult
    else
        &old_rows[location.row].lhs_mult;
    try incrementMultiplicity(multiplicity);
}

fn incrementMultiplicity(value: *u8) !void {
    if (value.* != 1) return error.InvalidIncrementalMultiplicity;
    value.* = 2;
}

fn putSource(
    sources: *std.AutoHashMap(u64, Source),
    key: u64,
    source: Source,
) !void {
    const entry = try sources.getOrPut(key);
    if (entry.found_existing) return error.DuplicateIncrementalSource;
    entry.value_ptr.* = source;
}

fn addCount(
    counts: *std.AutoHashMap(MerkleKey, i64),
    key: MerkleKey,
    delta: i64,
) !void {
    const entry = try counts.getOrPut(key);
    if (!entry.found_existing) entry.value_ptr.* = 0;
    entry.value_ptr.* += delta;
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

fn treeKey(depth: u8, index: u32) u64 {
    return (@as(u64, depth) << 32) | index;
}

test "changed-only transition hashes only changed exit paths" {
    const words = [_]v1.TouchedWord{
        .{
            .address = 0,
            .old_word = 0x01020304,
            .new_word = 0x01020305,
            .final_clock = 9,
        },
        .{
            .address = 8,
            .old_word = 0x11121314,
            .new_word = 0x11121314,
            .final_clock = 13,
        },
    };
    var witness = try build(std.testing.allocator, &words, &.{});
    defer witness.deinit();
    try std.testing.expectEqual(@as(u64, 35), witness.work.entry_calls);
    try std.testing.expectEqual(@as(u64, 30), witness.work.exit_calls);
    try std.testing.expectEqual(@as(u64, 65), witness.work.total_calls);
    try std.testing.expectEqual(@as(u64, 36), witness.work.bridge_rows);
    try std.testing.expect(witness.work.total_calls < witness.work.entry_calls * 2);
    const relations = relations_mod.Relations.dummy();
    try witness.verifyMerkleAndPoseidonCancellation(&relations);
    var prepared = try witness.prepareBridgeAir(
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
        @as(u32, @intCast(witness.bridge_rows.len)),
        prepared.component.n_rows,
    );

    witness.bridge_rows[witness.bridge_rows.len - 1].value ^= 1;
    try std.testing.expectError(
        error.IncrementalMerkleMultisetNotClosed,
        witness.verifyMerkleAndPoseidonCancellation(&relations),
    );
}

test "read-only touched words reuse the authenticated root" {
    const words = [_]v1.TouchedWord{.{
        .address = 4,
        .old_word = 0x11223344,
        .new_word = 0x11223344,
        .final_clock = 7,
    }};
    var witness = try build(std.testing.allocator, &words, &.{});
    defer witness.deinit();
    try std.testing.expectEqual(witness.entry_root, witness.exit_root);
    try std.testing.expectEqual(@as(u64, 31), witness.work.entry_calls);
    try std.testing.expectEqual(@as(u64, 0), witness.work.exit_calls);
    try std.testing.expectEqual(@as(u64, 33), witness.work.bridge_rows);
    const relations = relations_mod.Relations.dummy();
    try witness.verifyMerkleAndPoseidonCancellation(&relations);
}
