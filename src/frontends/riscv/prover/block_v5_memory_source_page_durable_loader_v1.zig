//! Detached original PAGE/RAM/range proposal loader. No Job or transported
//! VerifiedPage scalars are retained. Independent original Metadata Globals and
//! out-of-band PAGE policy pins reconstruct all expected admissions.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Policy = @import("block_v5_memory_source_page_policy_file_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Page = @import("block_v5_memory_source_unified_page_proof_v1.zig");
const Codec = @import("block_v5_memory_source_unified_page_codec_v1.zig");
const Join = @import("block_v5_memory_source_page_join_owner_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Inventory = @import("block_v5_memory_source_fold_inventory_owner_v1.zig");
const Global = @import("block_v5_capacity_global_receiver_v1.zig");
const Bundle = @import("block_v5_cpu_bundle_store_v1.zig").ForCapacity(true);
const BundlePolicy = @import("block_v5_cpu_bundle_policy_v1.zig").ForCapacity(true);
const Lane = @import("block_v5_ram_lanes_proof_v1.zig");
const Range = @import("block_v5_range16_proof_v1.zig");
pub const Limits = struct { policy: Policy.Limits = .{}, store: Bundle.Limits, max_owned_bytes: usize = 1 << 30 };
pub fn name(buffer: []u8, kind: Semantic.Kind, index: u32, artifact: bool) ![]const u8 {
    return std.fmt.bufPrint(buffer, "source-page-{s}-{d}.{s}", .{ @tagName(kind), index, if (artifact) "b5pg" else "operands" });
}
pub const Loader = struct {
    budget: *Budget,
    dir: std.fs.Dir,
    policy: *Policy.Owned,
    reader: Bundle.Store,
    bundle_policy: BundlePolicy.Owned,
    raw_taken: []bool,
    fold_taken: []bool,
    pending: ?Inventory.Owner = null,
    pending_index: ?u32 = null,
    failed: bool = false,
    /// Original independently owned Globals and directory must outlive Loader;
    /// Bundle's pointer-bearing native/caller policy borrows that admission.
    pub fn init(a: std.mem.Allocator, dir: std.fs.Dir, expected: Policy.Pin, globals: Global.Pins, bundle_manifest_sha256: [32]u8, limits: Limits) !*Loader {
        try limits.policy.validate();
        try limits.store.validate();
        if (limits.max_owned_bytes == 0) return error.SourcePageLoaderResourceLimit;
        const budget = try Budget.createRetainingParent(a, limits.max_owned_bytes);
        errdefer budget.destroy();
        const bounded = budget.allocator();
        const policy = try Policy.read(bounded, dir, expected, globals, limits.policy);
        errdefer policy.deinit();
        var independent = try BundlePolicy.collect(bounded, globals, limits.store);
        errdefer independent.deinit();
        var manifest = try Bundle.readPins(bounded, dir, bundle_manifest_sha256, limits.store);
        defer manifest.deinit();
        var reader = try Bundle.Store.initReader(bounded, dir, independent.policies, manifest.files, globals.tables.seal.config, limits.store);
        errdefer reader.deinit();
        const raw_taken = try bounded.alloc(bool, policy.context.raw.len);
        errdefer bounded.free(raw_taken);
        const fold_taken = try bounded.alloc(bool, policy.context.fold.len);
        errdefer bounded.free(fold_taken);
        @memset(raw_taken, false);
        @memset(fold_taken, false);
        const self = try bounded.create(Loader);
        self.* = .{ .budget = budget, .dir = dir, .policy = policy, .reader = reader, .bundle_policy = independent, .raw_taken = raw_taken, .fold_taken = fold_taken };
        return self;
    }
    pub fn deinit(self: *Loader) void {
        const budget = self.budget;
        if (self.pending) |*pending| pending.deinit();
        self.reader.deinit();
        self.bundle_policy.deinit();
        budget.allocator().free(self.fold_taken);
        budget.allocator().free(self.raw_taken);
        self.policy.deinit();
        budget.allocator().destroy(self);
        budget.destroy();
    }
    /// The original owner copies normative rosters; it never borrows loader
    /// metadata as an accepted receipt. Its cold immutable setups stay bounded.
    pub fn createJoin(self: *Loader, a: std.mem.Allocator, globals: Global.Pins, limits: Join.Limits) !*Join.Owner {
        if (self.failed or !std.meta.eql(limits.pages, self.policy.limits.pages)) return error.UntrustedSourcePageLoaderPolicy;
        const sorted = switch (globals.memory.memory) {
            .lanes => |value| value,
            .word => return error.NoncanonicalSourcePageTransitionMemory,
        };
        const sealed = try globals.validate();
        if (!std.meta.eql(sealed, self.policy.context.base) or !std.meta.eql(sorted.source, self.policy.context.admitted.source.pins)) return error.UntrustedSourcePageLoaderPolicy;
        return Join.Owner.create(a, &self.policy.context, sorted, limits);
    }
    pub fn pageLoader(self: *Loader) Join.Loader {
        return .{ .context = self, .raw = raw, .fold = fold, .fold_rows = rows, .release_fold_rows = releaseRows, .memory = memory, .range = range };
    }
    /// Keep the returned adapter at a stable address throughout callbacks.
    pub fn withProofAllocator(self: *Loader, a: std.mem.Allocator) Bundle.ProofReader {
        return self.reader.withProofAllocator(a);
    }
    pub fn requireConsumed(self: *Loader) !void {
        if (self.failed or self.pending != null or self.pending_index != null) return error.IncompleteSourcePageLoader;
        for (self.raw_taken) |taken| if (!taken) return error.IncompleteSourcePageLoader;
        for (self.fold_taken) |taken| if (!taken) return error.IncompleteSourcePageLoader;
        try self.reader.requireConsumed();
    }
    fn cast(context: *anyopaque) *Loader {
        return @ptrCast(@alignCast(context));
    }
    fn readArtifact(self: *Loader, a: std.mem.Allocator, comptime kind: Semantic.Kind, index: u32) ![]u8 {
        if (self.failed) return error.IncompleteSourcePageLoader;
        const records = if (kind == .raw) self.policy.parsed.value.raw else self.policy.parsed.value.fold;
        if (index >= records.len) return error.UnadmittedSourcePageLoaderIndex;
        const taken = if (kind == .raw) self.raw_taken else self.fold_taken;
        if (taken[index]) return error.SourcePageLoaderAlreadyTaken;
        // Take is consuming on failures too; a partial session cannot retry.
        taken[index] = true;
        errdefer self.failed = true;
        var path: [96]u8 = undefined;
        return Files.readPinned(a, self.dir, try name(&path, kind, index, true), records[index].artifact.byte_len, records[index].artifact.sha256, self.policy.limits.codec.max_artifact_bytes);
    }
    fn raw(context: *anyopaque, a: std.mem.Allocator, index: u32) !Page.ForKind(.raw).Proof {
        const self = cast(context);
        errdefer self.failed = true;
        const bytes = try self.readArtifact(a, .raw, index);
        defer a.free(bytes);
        return Codec.ForKind(.raw).decodeProposal(a, bytes, &self.policy.context, self.policy.context.raw[index], &.{}, self.policy.limits.pages, self.policy.limits.codec);
    }
    fn fold(context: *anyopaque, a: std.mem.Allocator, index: u32) !Page.ForKind(.fold).Proof {
        const self = cast(context);
        errdefer self.failed = true;
        if (self.pending == null or self.pending_index == null or self.pending_index.? != index) return error.UntrustedSourcePageLoaderInventory;
        const bytes = try self.readArtifact(a, .fold, index);
        defer a.free(bytes);
        return Codec.ForKind(.fold).decodeProposal(a, bytes, &self.policy.context, self.policy.context.fold[index], self.pending.?.rows, self.policy.limits.pages, self.policy.limits.codec);
    }
    fn rows(context: *anyopaque, a: std.mem.Allocator, index: u32, maximum: u32) ![]Semantic.FoldRow {
        const self = cast(context);
        errdefer self.failed = true;
        if (self.failed or self.pending != null or self.pending_index != null or index >= self.policy.context.fold.len or self.fold_taken[index]) return error.UntrustedSourcePageLoaderInventory;
        const record = self.policy.parsed.value.fold[index];
        if (maximum != record.pin.page.count) return error.UntrustedSourcePageLoaderInventory;
        var path: [96]u8 = undefined;
        const inventory = try Inventory.load(a, self.dir, try name(&path, .fold, index, false), record.pin, record.operands, self.policy.limits.pages.fold);
        self.pending = inventory;
        self.pending_index = index;
        return inventory.rows;
    }
    fn releaseRows(context: *anyopaque, a: std.mem.Allocator, values: []const Semantic.FoldRow) void {
        const self = cast(context);
        if (self.pending) |*pending| {
            pending.requireRelease(a, values);
            pending.deinit();
        } else @panic("source PAGE descriptor release without owner");
        self.pending = null;
        self.pending_index = null;
    }
    fn memory(context: *anyopaque, a: std.mem.Allocator, index: u32) !Lane.Proof {
        const self = cast(context);
        if (self.failed) return error.IncompleteSourcePageLoader;
        errdefer self.failed = true;
        return self.reader.takeWithAllocator(a, .ram_lanes, index);
    }
    fn range(context: *anyopaque, a: std.mem.Allocator, index: u32) !Range.Proof {
        const self = cast(context);
        if (self.failed) return error.IncompleteSourcePageLoader;
        errdefer self.failed = true;
        return self.reader.takeWithAllocator(a, .range16, index);
    }
};
