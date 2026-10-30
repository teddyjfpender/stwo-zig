//! Bounded actual PAGE artifacts -> original verifier rows. Each child is
//! freshly verified; only rows and canonical claims survive. No wrapper proof
//! is produced. The complete mixed-root owner must include every returned page.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Admissions = @import("block_v6_source_recursive_admissions_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Codec = @import("block_v5_memory_source_unified_page_codec_v1.zig");
const Capture = @import("block_v5_memory_source_page_recursive_capture_v1.zig");
const Job = @import("block_v5_memory_source_page_job_v1.zig");
const Prep = @import("../recursion/block_v6_auxiliary_direct_prepare_v1.zig");
const Types = @import("../recursion/block_v6_mixed_claim_types_v1.zig");
pub const Limits = struct {
    artifact: Codec.Limits = .{},
    max_total_artifact_bytes: usize = 512 << 20,
    max_heap_bytes: usize = 8 << 30,
    preparation_capacity: u32 = 2,
};
pub const Owner = struct {
    budget: *Budget,
    pieces: []Prep.Prepared,
    records: []Types.Record,
    pub fn deinit(self: *Owner) void {
        const budget = self.budget;
        const a = budget.allocator();
        for (self.pieces) |*piece| piece.deinit();
        a.free(self.pieces);
        a.free(self.records);
        self.* = undefined;
        budget.destroy();
    }
};
pub fn collect(backing: std.mem.Allocator, dir: std.fs.Dir, admitted: *const Admissions.Owner, limits: Limits) !Owner {
    if (limits.max_heap_bytes == 0 or limits.max_total_artifact_bytes == 0 or limits.preparation_capacity == 0)
        return error.SourceRecursiveCollectionResourceLimit;
    const budget = try Budget.createRetainingParent(backing, limits.max_heap_bytes);
    errdefer budget.destroy();
    const a = budget.allocator();
    const count = admitted.expected.len;
    const pieces = try a.alloc(Prep.Prepared, count);
    var initialized: usize = 0;
    errdefer {
        for (pieces[0..initialized]) |*piece| piece.deinit();
        a.free(pieces);
    }
    const records = try a.alloc(Types.Record, count);
    errdefer a.free(records);
    const qualify_fixed = try @import("block_v6_fixed_parity_v1.zig").enabled(a);
    var bytes_read: usize = 0;
    inline for (.{ Semantic.Kind.raw, Semantic.Kind.fold }) |kind| {
        const policies = if (kind == .raw) admitted.raw else admitted.fold;
        for (policies, 0..) |*policy, index| {
            const ordinal = if (kind == .raw) index else admitted.raw.len + index;
            var path: [96]u8 = undefined;
            const name = try Job.name(&path, kind, @intCast(index), true);
            const remaining = limits.max_total_artifact_bytes - bytes_read;
            const bytes = try dir.readFileAlloc(a, name, @min(remaining, limits.artifact.max_artifact_bytes));
            defer a.free(bytes);
            bytes_read = try std.math.add(usize, bytes_read, bytes.len);
            var proof = try Codec.ForKind(kind).decode(a, bytes, &admitted.context, policy.pin, policy.fold_rows, policy.limits.page, limits.artifact);
            defer proof.deinit(a);
            var captured = Capture.ForKind(kind).verifyBorrowed(a, &proof, policy) catch |err| {
                reportFailure(budget, kind, index, "capture", err);
                return err;
            };
            defer captured.deinit();
            const family = if (kind == .raw) "source_raw" else "source_fold";
            records[ordinal] = .{ .index = @intCast(index), .claim = @unionInit(Types.Claim, family, .{
                .semantic = captured.original.frame.semantic,
                .components = captured.original.frame.claims,
            }) };
            const input = @unionInit(Prep.Input, family, .{ .admitted = policy, .capture = &captured });
            const expected = admitted.expected[ordinal].auxiliary;
            pieces[ordinal] = Prep.prepare(a, &.{input}, &.{expected}, limits.preparation_capacity) catch |err| {
                reportFailure(budget, kind, index, "prepare", err);
                return err;
            };
            initialized += 1;
            if (qualify_fixed) {
                var cold = try @import("../recursion/block_v6_page_auxiliary_fixed_v1.zig").ForKind(kind).Owned.derive(a, policy, policy.template_id, captured.original.frame.semantic.claims, limits.preparation_capacity, try @import("block_v6_fixed_parity_v1.zig").profile(policy.config), .{});
                defer cold.deinit();
                try cold.validateLive(&pieces[ordinal]);
                std.debug.print("FIXED_PARITY family=source_{s} index={d} matched=true\n", .{ @tagName(kind), index });
            }
        }
    }
    return .{ .budget = budget, .pieces = pieces, .records = records };
}

fn reportFailure(budget: *Budget, kind: Semantic.Kind, index: usize, phase: []const u8, failure: anyerror) void {
    const snapshot = budget.snapshot();
    std.debug.print("SOURCE_RECURSIVE_FAILURE family={s} index={d} phase={s} error={s} live_bytes={d} peak_bytes={d} limit_bytes={d} budget_exceeded={}\n", .{ @tagName(kind), index, phase, @errorName(failure), snapshot.live_bytes, snapshot.peak_live_bytes, snapshot.limit, snapshot.exceeded });
}
