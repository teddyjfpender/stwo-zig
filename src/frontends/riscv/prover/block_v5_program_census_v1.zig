//! Exact block-wide ROM fetch census assembled from one replayed native plan
//! at a time. This is prechallenge planning, not a proof receipt: the v5 ROM
//! table and every native program-request proof must subsequently verify and
//! close under the common source-seal-derived relation challenge.
const std = @import("std");
const core = @import("stwo_core");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const native = @import("blake3_commitment_plan.zig");
const table = @import("block_v5_program_table_v1.zig");

/// One replayed precompile-caller fetch. These are a partition of the native
/// plan's already counted fetches, never an additional table contribution.
pub const Fetch = struct { address: u32, multiplicity: u64 = 1 };

pub const Census = struct {
    allocator: std.mem.Allocator,
    program_root: tree.Digest,
    leaves: []tree.Leaf,
    counts: []u64,
    total_fetches: u64 = 0,
    segments: u32 = 0,

    pub fn init(a: std.mem.Allocator, root: tree.Digest, leaves: []const tree.Leaf) !Census {
        if (leaves.len == 0 or leaves.len % 4 != 0) return error.InvalidV5ProgramCensus;
        try @import("../air/program/blake3_root_cache.zig").validate(leaves, root);
        const owned_leaves = try a.dupe(tree.Leaf, leaves);
        errdefer a.free(owned_leaves);
        const counts = try a.alloc(u64, leaves.len / 4);
        @memset(counts, 0);
        return .{ .allocator = a, .program_root = root, .leaves = owned_leaves, .counts = counts };
    }

    pub fn deinit(self: *Census) void {
        self.allocator.free(self.counts);
        self.allocator.free(self.leaves);
        self.* = undefined;
    }

    /// Plans may have full or sparse-active program schedules. In both cases
    /// `Plan.validate` authenticates the complete ROM against the same root;
    /// the accumulator maps each exact address to its one decoded-ROM row.
    pub fn add(self: *Census, plan: *const native.Plan) !void {
        try plan.validate();
        if (!std.meta.eql(plan.roots[0], self.program_root) or
            !sameLeaves(plan.program_leaves, self.leaves))
            return error.ChangedV5ProgramImage;
        return self.addCanonical(plan.programs);
    }

    /// Plan-free v3 census over canonical replayed fetch multiplicities. The
    /// complete image/root is authenticated once by init; fresh same-root
    /// native/caller request proofs subsequently authenticate these counts.
    pub fn addFetches(self: *Census, fetches: []const Fetch) !void {
        return self.addCanonical(fetches);
    }

    fn addCanonical(self: *Census, fetches: anytype) !void {
        if (self.segments == std.math.maxInt(u32)) return error.V5ProgramSegmentOverflow;
        var local_total: u64 = 0;
        const maximum = @as(u64, core.fields.m31.Modulus) - 1;
        var previous: ?u32 = null;
        for (fetches) |item| {
            if (previous != null and item.address <= previous.?) return error.NonCanonicalV5ProgramFetches;
            previous = item.address;
            const at = self.find(item.address) orelse return error.MissingV5ProgramAddress;
            if (item.multiplicity > maximum or
                self.counts[at] > maximum - item.multiplicity)
                return error.V5ProgramFetchCensusOverflow;
            local_total = try std.math.add(u64, local_total, item.multiplicity);
        }
        if (local_total > maximum - self.total_fetches)
            return error.V5ProgramFetchCensusOverflow;
        for (fetches) |item| self.counts[self.find(item.address).?] += item.multiplicity;
        self.total_fetches += local_total;
        self.segments += 1;
    }

    /// Verify the caller partition against this exact segment plan before
    /// committing the global ROM table. The eventual same-root PCS request
    /// proof, not this host check, authenticates the caller tuples.
    pub fn validateSubset(self: *const Census, plan: *const native.Plan, fetches: []const Fetch) !u64 {
        if (!std.meta.eql(plan.roots[0], self.program_root) or
            !sameLeaves(plan.program_leaves, self.leaves))
            return error.ChangedV5ProgramImage;
        return self.validateCanonicalSubset(plan.programs, fetches);
    }

    /// Validate a sparse caller partition against a canonical v3 replayed
    /// fetch census without constructing any per-leaf commitment schedule.
    pub fn validateFetchSubset(self: *const Census, complete: []const Fetch, subset: []const Fetch) !u64 {
        return self.validateCanonicalSubset(complete, subset);
    }
    fn validateCanonicalSubset(self: *const Census, complete: anytype, subset: []const Fetch) !u64 {
        var previous: ?u32 = null;
        for (complete) |fetch| {
            if (previous != null and fetch.address <= previous.?) return error.NonCanonicalV5ProgramFetches;
            previous = fetch.address;
            if (self.find(fetch.address) == null) return error.MissingV5ProgramAddress;
        }
        var counts: std.AutoHashMapUnmanaged(u32, u64) = .empty;
        defer counts.deinit(self.allocator);
        var total: u64 = 0;
        for (subset) |fetch| {
            if (fetch.multiplicity == 0) return error.InvalidV5ProgramExtensionFetch;
            var low: usize = 0;
            var high = complete.len;
            while (low < high) {
                const mid = low + (high - low) / 2;
                if (complete[mid].address < fetch.address) low = mid + 1 else high = mid;
            }
            if (low >= complete.len or complete[low].address != fetch.address) return error.MissingV5ProgramAddress;
            const gop = try counts.getOrPut(self.allocator, fetch.address);
            if (!gop.found_existing) gop.value_ptr.* = 0;
            gop.value_ptr.* = try std.math.add(u64, gop.value_ptr.*, fetch.multiplicity);
            if (gop.value_ptr.* > complete[low].multiplicity) return error.V5ProgramExtensionFetchOverflow;
            total = try std.math.add(u64, total, fetch.multiplicity);
        }
        return total;
    }

    /// Borrowed plan; keep the census alive through table proving/verification.
    pub fn tablePlan(self: *const Census, expected_segments: u32, expected_fetches: u64, log_size: u32) !table.Plan {
        if (self.segments == 0 or self.segments != expected_segments or
            self.total_fetches != expected_fetches)
            return error.IncompleteV5ProgramCensus;
        const result = table.Plan{
            .program_root = self.program_root,
            .leaves = self.leaves,
            .multiplicities = self.counts,
            .expected_fetches = expected_fetches,
            .log_size = log_size,
        };
        try result.validate();
        return result;
    }

    /// Program-table AIR size is independent of execution and memory sizes.
    /// Use the smallest supported power of two that contains the complete ROM.
    pub fn smallestTablePlan(self: *const Census, expected_segments: u32, expected_fetches: u64) !table.Plan {
        const rows = @max(@as(usize, 1) << 7, self.counts.len);
        const capacity = try std.math.ceilPowerOfTwo(usize, rows);
        if (capacity > (@as(usize, 1) << 24)) return error.InvalidProgramTableGeometry;
        return self.tablePlan(expected_segments, expected_fetches, std.math.log2_int(usize, capacity));
    }

    fn find(self: *const Census, address: u32) ?usize {
        var low: usize = 0;
        var high: usize = self.counts.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            if (self.leaves[4 * mid].index < address) low = mid + 1 else high = mid;
        }
        if (low >= self.counts.len or self.leaves[4 * low].index != address) return null;
        return low;
    }
};

fn sameLeaves(left: []const tree.Leaf, right: []const tree.Leaf) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| {
        if (a.index != b.index or a.value != b.value) return false;
    }
    return true;
}

test "block-v5 census merges full and sparse native program schedules exactly" {
    const a = std.testing.allocator;
    const leaves = [_]tree.Leaf{
        .{ .index = 0, .value = 1 }, .{ .index = 1, .value = 2 },
        .{ .index = 2, .value = 3 }, .{ .index = 3, .value = 4 },
        .{ .index = 4, .value = 5 }, .{ .index = 5, .value = 6 },
        .{ .index = 6, .value = 7 }, .{ .index = 7, .value = 8 },
    };
    const root = try tree.TreeHasher.init(.program).root(&leaves);
    const roots = [3]tree.Digest{ root, root, root };
    const Word = @import("../recursion/air/blake3_program_word.zig").Statement;
    const full_rows = [_]Word{
        .{ .namespace = 100, .address = 0, .multiplicity = 2, .root = root },
        .{ .namespace = 100 + @import("../recursion/air/blake3_program_word.zig").CIRCUIT_COUNT, .address = 4, .multiplicity = 1, .root = root },
    };
    const sparse_rows = [_]Word{.{ .namespace = 100, .address = 4, .multiplicity = 3, .root = root }};
    var full = try native.Plan.init(a, roots, &.{}, &full_rows, &leaves);
    defer full.deinit();
    var sparse = try native.Plan.initSparse(a, roots, &.{}, &sparse_rows, &leaves);
    defer sparse.deinit();
    var census = try Census.init(a, root, &leaves);
    defer census.deinit();
    try census.add(&full);
    try census.add(&sparse);
    const combined = try census.tablePlan(2, 6, 7);
    try std.testing.expectEqualSlices(u64, &.{ 2, 4 }, combined.multiplicities);
    try std.testing.expectEqual(@as(u32, 7), (try census.smallestTablePlan(2, 6)).log_size);
    try std.testing.expectError(error.IncompleteV5ProgramCensus, census.tablePlan(3, 6, 7));
    try std.testing.expectError(error.IncompleteV5ProgramCensus, census.tablePlan(2, 5, 7));
    var changed_leaves = leaves;
    changed_leaves[4].value ^= 1;
    const changed_root = try tree.TreeHasher.init(.program).root(&changed_leaves);
    const changed_roots = [3]tree.Digest{ changed_root, changed_root, changed_root };
    const changed_rows = [_]Word{.{ .namespace = 100, .address = 4, .multiplicity = 1, .root = changed_root }};
    var changed_plan = try native.Plan.initSparse(a, changed_roots, &.{}, &changed_rows, &changed_leaves);
    defer changed_plan.deinit();
    try std.testing.expectError(error.ChangedV5ProgramImage, census.add(&changed_plan));
    try std.testing.expectEqual(@as(u32, 2), census.segments);
    try std.testing.expectEqual(@as(u64, 6), census.total_fetches);
    var lightweight = try Census.init(a, root, &leaves);
    defer lightweight.deinit();
    const fetches = [_]Fetch{ .{ .address = 0, .multiplicity = 2 }, .{ .address = 4, .multiplicity = 4 } };
    try lightweight.addFetches(&fetches);
    try std.testing.expectEqualSlices(u64, census.counts, lightweight.counts);
    try std.testing.expectEqual(@as(u64, 3), try lightweight.validateFetchSubset(&fetches, &.{ .{ .address = 4 }, .{ .address = 4, .multiplicity = 2 } }));
    try std.testing.expectError(error.V5ProgramExtensionFetchOverflow, lightweight.validateFetchSubset(&fetches, &.{ .{ .address = 4, .multiplicity = 3 }, .{ .address = 4, .multiplicity = 2 } }));
    try std.testing.expectError(error.NonCanonicalV5ProgramFetches, lightweight.addFetches(&.{ .{ .address = 0 }, .{ .address = 0 } }));
    try std.testing.expectEqual(@as(u32, 1), lightweight.segments);
    try std.testing.expectEqual(@as(u64, 6), lightweight.total_fetches);
    census.leaves[0].value ^= 1;
    try std.testing.expectError(error.ProgramRootMismatch, census.tablePlan(2, 6, 7));
}
