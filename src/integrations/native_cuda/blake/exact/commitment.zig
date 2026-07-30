//! Exact mixed-height Blake commitment over packed resident LDE groups.

const std = @import("std");
const field = @import("stwo_cuda_backend").abi.field;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const runtime_error = @import("stwo_cuda_backend").runtime.runtime_error;
const telemetry = @import("stwo_cuda_backend").runtime.telemetry;
const commit_tree = @import("../../common/commit_tree.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle
    .Blake2sPrefixedMerkleHasher;
const MerkleProver = @import("stwo_prover_engine").vcs_lifted.prover
    .MerkleProverLifted(Hasher);
const arena_plan = @import("arena_plan.zig");
const geometry_mod = @import("geometry.zig");
const views_mod = @import("views.zig");

pub const max_group_count = geometry_mod.component_count;
pub const Error = commit_tree.Error || runtime_error.Error || error{
    GeometryOverflow,
    InvalidMixedHeightCommitment,
};

pub const Entry = struct {
    original_group_index: usize,
    column_offset: usize,
    column_count: usize,
    source_log: u32,
    source_size: usize,
    arena_offset_words: usize,
    column_stride_words: usize,

    pub fn wordCount(self: Entry) !usize {
        return std.math.mul(
            usize,
            self.column_count,
            self.column_stride_words,
        ) catch error.GeometryOverflow;
    }

    pub fn sourceRow(
        self: Entry,
        lifted_row: usize,
        commitment_log: u32,
    ) !usize {
        if (self.source_log > commitment_log or
            commitment_log >= @bitSizeOf(usize) or
            lifted_row >= (@as(usize, 1) << @intCast(commitment_log)))
        {
            return error.InvalidMixedHeightCommitment;
        }
        const log_ratio = commitment_log - self.source_log;
        if (log_ratio == 0) return lifted_row;
        return ((lifted_row >> @intCast(log_ratio + 1)) << 1) |
            (lifted_row & 1);
    }
};

pub const Schedule = struct {
    entries: [max_group_count]Entry = undefined,
    len: usize = 0,
    commitment_log: u32,
    log_blowup: u32,
    lde_words: usize,
    column_count: usize,

    pub fn init(
        geometry: geometry_mod.Geometry,
        tree_views: views_mod.TreeViews,
        tree: geometry_mod.Tree,
    ) !Schedule {
        var result = Schedule{
            .commitment_log = geometry.treeCommitmentLog(tree),
            .log_blowup = geometry.protocol.fri_config.log_blowup_factor,
            .lde_words = try scaledWords(
                geometry.treeWords(tree),
                geometry.protocol.fri_config.log_blowup_factor,
            ),
            .column_count = geometry.treeColumnCount(tree),
        };
        switch (tree) {
            .preprocessed => for (
                tree_views.preprocessed,
                0..,
            ) |view, index| try result.append(
                index,
                view.column_offset,
                view.column_count,
                view.log_rows,
                view.arena_offset_words,
            ),
            .main => for (tree_views.main, 0..) |view, index| {
                try result.append(
                    index,
                    view.column_offset,
                    view.column_count,
                    view.log_rows,
                    view.arena_offset_words,
                );
            },
            .interaction => for (
                tree_views.interaction,
                0..,
            ) |view, index| try result.append(
                index,
                view.column_offset,
                view.column_count,
                view.log_rows,
                view.arena_offset_words,
            ),
            .composition => try result.append(
                0,
                0,
                tree_views.composition.column_count,
                tree_views.composition.log_rows,
                0,
            ),
        }
        result.sort();
        try result.validate();
        return result;
    }

    pub fn slice(self: *const Schedule) []const Entry {
        return self.entries[0..self.len];
    }

    pub fn bind(self: Schedule, lde: common.Words) !Bound {
        if (lde.len != self.lde_words)
            return error.InvalidMixedHeightCommitment;
        var result = Bound{};
        for (self.slice()) |entry| {
            result.segments[result.len] = .{
                .columns = .{
                    .storage = try lde.sub(
                        entry.arena_offset_words,
                        try entry.wordCount(),
                    ),
                    .column_stride_words = entry.column_stride_words,
                },
                .source_size = std.math.cast(
                    u32,
                    entry.source_size,
                ) orelse return error.GeometryOverflow,
            };
            result.len += 1;
        }
        return result;
    }

    fn append(
        self: *Schedule,
        original_group_index: usize,
        column_offset: usize,
        column_count: usize,
        log_rows: u32,
        arena_offset_words: usize,
    ) !void {
        if (self.len == self.entries.len)
            return error.InvalidMixedHeightCommitment;
        const source_log = std.math.add(
            u32,
            log_rows,
            self.log_blowup,
        ) catch return error.GeometryOverflow;
        if (source_log >= @bitSizeOf(usize))
            return error.GeometryOverflow;
        self.entries[self.len] = .{
            .original_group_index = original_group_index,
            .column_offset = column_offset,
            .column_count = column_count,
            .source_log = source_log,
            .source_size = @as(usize, 1) << @intCast(source_log),
            .arena_offset_words = try scaledWords(
                arena_offset_words,
                self.log_blowup,
            ),
            .column_stride_words = @as(usize, 1) <<
                @intCast(source_log),
        };
        self.len += 1;
    }

    fn sort(self: *Schedule) void {
        std.sort.heap(
            Entry,
            self.entries[0..self.len],
            {},
            lessThan,
        );
    }

    fn validate(self: Schedule) !void {
        if (self.len == 0) return error.InvalidMixedHeightCommitment;
        var columns: usize = 0;
        var words: usize = 0;
        var previous_log: u32 = 0;
        var previous_column: usize = 0;
        for (self.slice(), 0..) |entry, index| {
            const entry_words = try entry.wordCount();
            const entry_end = std.math.add(
                usize,
                entry.arena_offset_words,
                entry_words,
            ) catch return error.GeometryOverflow;
            if (entry.source_log > self.commitment_log or
                entry.source_size != entry.column_stride_words or
                entry_end > self.lde_words or
                (index > 0 and
                    (entry.source_log < previous_log or
                        (entry.source_log == previous_log and
                            entry.column_offset < previous_column))))
            {
                return error.InvalidMixedHeightCommitment;
            }
            for (self.slice()[index + 1 ..]) |other| {
                const other_end = std.math.add(
                    usize,
                    other.arena_offset_words,
                    try other.wordCount(),
                ) catch return error.GeometryOverflow;
                if (entry.arena_offset_words < other_end and
                    other.arena_offset_words < entry_end)
                {
                    return error.InvalidMixedHeightCommitment;
                }
            }
            columns = std.math.add(
                usize,
                columns,
                entry.column_count,
            ) catch return error.GeometryOverflow;
            words = std.math.add(
                usize,
                words,
                entry_words,
            ) catch return error.GeometryOverflow;
            previous_log = entry.source_log;
            previous_column = entry.column_offset;
        }
        if (columns != self.column_count or words != self.lde_words)
            return error.InvalidMixedHeightCommitment;
    }
};

pub const Bound = struct {
    segments: [max_group_count]commit_tree.LiftedSegment = undefined,
    len: usize = 0,

    pub fn slice(self: *const Bound) []const commit_tree.LiftedSegment {
        return self.segments[0..self.len];
    }
};

pub fn CommitterFor(comptime Ops: type) type {
    return struct {
        pub fn commit(
            session: anytype,
            tree: geometry_mod.Tree,
            prepared: *const arena_plan.Prepared,
            lde: common.Words,
            states: common.ProgressiveStates,
            hashes: common.Hashes,
            layers: []const field.MerkleLayerDescriptor,
        ) Error!common.Hashes {
            const schedule = try Schedule.init(
                prepared.geometry,
                prepared.views,
                tree,
            );
            const bound = try schedule.bind(lde);
            if (schedule.commitment_log >= @bitSizeOf(usize))
                return error.GeometryOverflow;
            const size = std.math.cast(
                u32,
                @as(usize, 1) << @intCast(schedule.commitment_log),
            ) orelse return error.SizeOverflow;
            const Builder = commit_tree.BuilderFor(Ops);
            if (bound.len == 1) {
                if (bound.segments[0].source_size != size)
                    return error.InvalidMixedHeightCommitment;
                return Builder.baseField(
                    session,
                    commitStage(tree),
                    size,
                    bound.segments[0].columns,
                    hashes,
                    layers,
                );
            }
            return Builder.baseFieldLiftedSegmented(
                session,
                commitStage(tree),
                size,
                bound.slice(),
                states,
                hashes,
                layers,
            );
        }
    };
}

fn lessThan(_: void, left: Entry, right: Entry) bool {
    if (left.source_log != right.source_log)
        return left.source_log < right.source_log;
    return left.column_offset < right.column_offset;
}

fn scaledWords(words: usize, log_scale: u32) !usize {
    if (log_scale >= @bitSizeOf(usize)) return error.GeometryOverflow;
    return std.math.mul(
        usize,
        words,
        @as(usize, 1) << @intCast(log_scale),
    ) catch error.GeometryOverflow;
}

fn commitStage(tree: geometry_mod.Tree) telemetry.Stage {
    return switch (tree) {
        .preprocessed, .main => .trace_commit,
        .interaction, .composition => .constraint_evaluation,
    };
}

test "exact Blake commitment schedules packed groups in canonical leaf order" {
    const geometry = try geometry_mod.admit(.{
        .statement = .{ .log_n_rows = 4 },
        .protocol = @import("stwo_core").pcs.PcsConfig.default(),
    });
    const tree_views = try views_mod.TreeViews.init(geometry);

    const preprocessed = try Schedule.init(
        geometry,
        tree_views,
        .preprocessed,
    );
    try std.testing.expectEqual(@as(usize, 5), preprocessed.len);
    try std.testing.expectEqualSlices(
        usize,
        &.{ 4, 3, 2, 1, 0 },
        &.{
            preprocessed.entries[0].original_group_index,
            preprocessed.entries[1].original_group_index,
            preprocessed.entries[2].original_group_index,
            preprocessed.entries[3].original_group_index,
            preprocessed.entries[4].original_group_index,
        },
    );

    const main = try Schedule.init(geometry, tree_views, .main);
    try std.testing.expectEqualSlices(
        usize,
        &.{ 0, 2, 1, 7, 6, 5, 4, 3 },
        &.{
            main.entries[0].original_group_index,
            main.entries[1].original_group_index,
            main.entries[2].original_group_index,
            main.entries[3].original_group_index,
            main.entries[4].original_group_index,
            main.entries[5].original_group_index,
            main.entries[6].original_group_index,
            main.entries[7].original_group_index,
        },
    );
    try std.testing.expectEqual(@as(u32, 5), main.entries[0].source_log);
    try std.testing.expectEqual(@as(u32, 17), main.commitment_log);
    for (main.slice()) |entry| {
        const original = tree_views.main[entry.original_group_index];
        try std.testing.expectEqual(
            original.arena_offset_words * 2,
            entry.arena_offset_words,
        );
        try std.testing.expectEqual(
            original.column_stride_words * 2,
            entry.column_stride_words,
        );
        try std.testing.expectEqual(
            original.column_count * original.column_stride_words * 2,
            try entry.wordCount(),
        );
    }

    const lde = common.Words{
        .address = 0x1000,
        .len = main.lde_words,
        .owner = 9,
    };
    const bound = try main.bind(lde);
    try std.testing.expectEqual(main.len, bound.len);
    try std.testing.expectEqual(
        lde.address +
            main.entries[0].arena_offset_words * @sizeOf(u32),
        bound.segments[0].columns.storage.address,
    );
    try std.testing.expectEqual(
        try main.entries[0].wordCount(),
        bound.segments[0].columns.storage.len,
    );
}

test "equal-height exact groups retain original PCS column order" {
    const geometry = try geometry_mod.admit(.{
        .statement = .{ .log_n_rows = 8 },
        .protocol = @import("stwo_core").pcs.PcsConfig.default(),
    });
    const tree_views = try views_mod.TreeViews.init(geometry);
    const main = try Schedule.init(geometry, tree_views, .main);
    var scheduler_at: ?usize = null;
    var xor4_at: ?usize = null;
    for (main.slice(), 0..) |entry, index| {
        if (entry.original_group_index == 0) scheduler_at = index;
        if (entry.original_group_index == 7) xor4_at = index;
    }
    try std.testing.expect(scheduler_at != null and xor4_at != null);
    try std.testing.expectEqual(
        main.entries[scheduler_at.?].source_log,
        main.entries[xor4_at.?].source_log,
    );
    try std.testing.expect(scheduler_at.? < xor4_at.?);
}

test "exact Blake lifted row mapping preserves the circle parity bit" {
    const entry = Entry{
        .original_group_index = 0,
        .column_offset = 0,
        .column_count = 1,
        .source_log = 3,
        .source_size = 8,
        .arena_offset_words = 0,
        .column_stride_words = 8,
    };
    const expected = [_]usize{ 0, 1, 0, 1, 2, 3, 2, 3, 4, 5, 4, 5, 6, 7, 6, 7 };
    for (expected, 0..) |source_row, lifted_row| {
        try std.testing.expectEqual(
            source_row,
            try entry.sourceRow(lifted_row, 4),
        );
    }
}

test "mixed-height schedules match an independent CPU root oracle" {
    const allocator = std.testing.allocator;
    const geometry = try geometry_mod.admit(.{
        .statement = .{ .log_n_rows = 4 },
        .protocol = @import("stwo_core").pcs.PcsConfig.default(),
    });
    const tree_views = try views_mod.TreeViews.init(geometry);
    for ([_]geometry_mod.Tree{
        .preprocessed,
        .main,
        .interaction,
        .composition,
    }) |tree| {
        const schedule = try Schedule.init(geometry, tree_views, tree);
        const scheduled = try structuralRoot(
            allocator,
            schedule,
            @intFromEnum(tree),
        );
        const oracle = try cpuOracleRoot(
            allocator,
            schedule,
            @intFromEnum(tree),
        );
        try std.testing.expectEqualSlices(u8, &oracle, &scheduled);
    }
}

fn structuralRoot(
    allocator: std.mem.Allocator,
    schedule: Schedule,
    tree_tag: u8,
) !Hasher.Hash {
    var minimum_log = schedule.entries[0].source_log;
    for (schedule.slice()[1..]) |entry|
        minimum_log = @min(minimum_log, entry.source_log);
    const normalized_commitment_log =
        schedule.commitment_log - minimum_log + 1;
    const leaf_count = @as(usize, 1) <<
        @intCast(normalized_commitment_log);
    const leaves = try allocator.alloc(Hasher.Hash, leaf_count);
    defer allocator.free(leaves);
    const values = try allocator.alloc(M31, schedule.column_count);
    defer allocator.free(values);

    for (leaves, 0..) |*leaf, lifted_row| {
        var at: usize = 0;
        for (schedule.slice()) |entry| {
            const source_log = entry.source_log - minimum_log + 1;
            const source_row = liftedIndex(
                lifted_row,
                normalized_commitment_log,
                source_log,
            );
            for (0..entry.column_count) |local| {
                values[at] = syntheticValue(
                    tree_tag,
                    entry.column_offset + local,
                    source_row,
                );
                at += 1;
            }
        }
        var hasher = Hasher.defaultWithInitialState();
        hasher.updateLeaf(values);
        leaf.* = hasher.finalize();
    }

    var count = leaves.len;
    while (count > 1) {
        for (0..count / 2) |index| {
            leaves[index] = Hasher.hashChildren(.{
                .left = leaves[index * 2],
                .right = leaves[index * 2 + 1],
            });
        }
        count /= 2;
    }
    return leaves[0];
}

fn cpuOracleRoot(
    allocator: std.mem.Allocator,
    schedule: Schedule,
    tree_tag: u8,
) !Hasher.Hash {
    var minimum_log = schedule.entries[0].source_log;
    for (schedule.slice()[1..]) |entry|
        minimum_log = @min(minimum_log, entry.source_log);

    const source_logs = try allocator.alloc(u32, schedule.column_count);
    defer allocator.free(source_logs);
    for (schedule.slice()) |entry| {
        @memset(
            source_logs[entry.column_offset .. entry.column_offset + entry.column_count],
            entry.source_log - minimum_log + 1,
        );
    }

    const columns = try allocator.alloc([]M31, schedule.column_count);
    var initialized: usize = 0;
    defer {
        for (columns[0..initialized]) |column| allocator.free(column);
        allocator.free(columns);
    }
    for (columns, source_logs, 0..) |*column, source_log, index| {
        const source_size = @as(usize, 1) << @intCast(source_log);
        column.* = try allocator.alloc(M31, source_size);
        initialized += 1;
        for (column.*, 0..) |*value, source_row| {
            value.* = syntheticValue(tree_tag, index, source_row);
        }
    }

    const references = try allocator.alloc(
        []const M31,
        schedule.column_count,
    );
    defer allocator.free(references);
    for (columns, references) |column, *reference|
        reference.* = column;

    var prover = try MerkleProver.commit(allocator, references);
    defer prover.deinit(allocator);
    return prover.root();
}

fn liftedIndex(
    lifted_row: usize,
    commitment_log: u32,
    source_log: u32,
) usize {
    const log_ratio = commitment_log - source_log;
    if (log_ratio == 0) return lifted_row;
    return ((lifted_row >> @intCast(log_ratio + 1)) << 1) |
        (lifted_row & 1);
}

fn syntheticValue(
    tree_tag: u8,
    original_column: usize,
    source_row: usize,
) M31 {
    const modulus: u64 = 0x7fff_ffff;
    const raw = (@as(u64, tree_tag) + 1) * 0x1f12_3bb5 +
        @as(u64, original_column) * 0x45d9_f3b +
        @as(u64, source_row) * 0x119d_e1f3;
    return M31.fromCanonical(@intCast(raw % modulus));
}
