//! Real original draft files/decoder with transactional production wiring guards.
//! No PCS, STARK, FRI, guest, proof receipt or device invocation.
const std = @import("std");
const Collection = @import("block_v5_memory_source_fold_draft_collection_v1.zig").Collection;
const Draft = @import("block_v5_memory_source_fold_draft_pages_v1.zig");
const Store = @import("block_v5_memory_source_fold_operand_store_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Batch = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Initial = @import("block_v5_initial_sources_v1.zig");
const Tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const Sparse = @import("block_v5_sparse_state_stream_v1.zig");
const Fixture = struct {
    bytes: [64 * 8]u8 = undefined,
    leaves: [64]Tree.Leaf = undefined,
    admitted: Batch.Admission = undefined,
    count: usize = 64,
    fail_read: bool = false,
    fn init(self: *@This(), count: usize) !void {
        self.count = count;
        for (&self.leaves, 0..) |*leaf, i| {
            const address: u32 = @intCast(1024 + 4 * i);
            const value: u32 = @intCast(i + 1);
            std.mem.writeInt(u32, self.bytes[8 * i ..][0..4], address, .little);
            std.mem.writeInt(u32, self.bytes[8 * i + 4 ..][0..4], value, .little);
            leaf.* = .{ .index = address / 4, .value = value };
        }
        var image = Image{ .leaves = self.leaves[0..count] };
        const root = (try Sparse.root(&image, count)).bytes;
        const empty = Initial.sha256("");
        const original = try Source.make(.{ .initial = .{
            .layout = .{ .program_base = 0, .program_end = 16, .data_base = 32, .data_end = 4096, .stack_bottom = 128, .stack_top = 8192, .io_base = 256, .io_end = 10240, .input_base = 32, .input_end = 64, .output_len_addr = 64, .output_data_addr = 68, .output_base = 64, .output_end = 256 },
            .initial_rw_root = root,
            .initial_registers = @splat(0),
            .public_input_sha256 = empty,
            .public_input_len = 0,
            .input_words = .{ .records = 0, .sha256 = empty },
            .rw_words = .{ .records = count, .sha256 = Initial.sha256(self.bytes[0 .. count * 8]) },
            .first_touches = .{ .records = 0, .sha256 = empty },
        }, .memory_plan_digest = @splat(7), .expected_final_rw_root = root, .endpoints = .{ .records = 0, .sha256 = empty } }, @splat(8), .{});
        self.admitted = try Batch.Admission.init(original, .{});
    }
    const Image = struct {
        leaves: []const Tree.Leaf,
        index: usize = 0,
        pub fn next(self: *@This()) !?Tree.Leaf {
            if (self.index == self.leaves.len) return null;
            defer self.index += 1;
            return self.leaves[self.index];
        }
    };
    fn read(context: *anyopaque, stream: Source.Stream, offset: u64, out: []u8) !void {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (self.fail_read) return error.InjectedSourceReadFailure;
        if (stream != .rw_words) {
            if (out.len != 0) return error.InvalidFoldSpoolFixtureOffset;
            return;
        }
        const end = try std.math.add(u64, offset, out.len);
        if (end > self.count * 8) return error.InvalidFoldSpoolFixtureOffset;
        @memcpy(out, self.bytes[@intCast(offset)..@intCast(end)]);
    }
    fn reader(self: *@This()) Fold.Reader {
        return .{ .context = self, .read = read };
    }
};
const config = @import("stwo_core").pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{ .log_blowup_factor = 1, .n_queries = 1, .log_last_layer_degree_bound = 0, .fold_step = 1 },
};
fn planFor(fixture: *const Fixture, owner: *const Draft.Owner) !Protocol.FoldPlan {
    return Protocol.FoldPlan.init(&fixture.admitted, owner.census, config, .{ .page_row_log = 1 });
}
fn drain(collection: *Collection) !void {
    while (try collection.next() != null) {}
    try collection.requireFinished();
}
fn pageIdentity(index: u32) [32]u8 {
    // Explicit unverified transport proposals; no constructed proof receipt.
    var bytes: [32]u8 = @splat(3);
    std.mem.writeInt(u32, bytes[0..4], index, .little);
    return bytes;
}
test "source fold draft collection: later failure rolls back successful final prefix while collision and original inputs survive" {
    var fixture = Fixture{};
    try fixture.init(1);
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const owner = try Draft.collect(std.testing.allocator, temporary.dir, &fixture.admitted, fixture.reader(), .{ .row_log = 1 });
    defer owner.deinit() catch unreachable;
    const plan = try planFor(&fixture, owner);
    try std.testing.expect(plan.pages > 1);
    const original = try temporary.dir.createFile("original-source.records", .{ .exclusive = true });
    try original.writeAll("original input");
    original.close();
    const prior = try temporary.dir.createFile("source-page-fold-1.operands", .{ .exclusive = true });
    try prior.writeAll("preexisting final");
    prior.close();
    {
        var collection = try Collection.init(owner, &fixture.admitted, plan, .{ .page_row_log = 1 }, 0);
        defer collection.deinit();
        try drain(&collection);
        _ = try collection.promote(0, pageIdentity(0));
        try std.testing.expectEqual(@as(u32, 1), collection.created);
        try std.testing.expectError(error.ExistingV5BundleArtifact, collection.promote(1, pageIdentity(1)));
        try std.testing.expectEqual(@as(u32, 1), collection.created);
    }
    try std.testing.expectError(error.FileNotFound, temporary.dir.access("source-page-fold-0.operands", .{}));
    const retained = try temporary.dir.readFileAlloc(std.testing.allocator, "source-page-fold-1.operands", 128);
    defer std.testing.allocator.free(retained);
    try std.testing.expectEqualStrings("preexisting final", retained);
    try temporary.dir.access("original-source.records", .{});
    try std.testing.expect(owner.failed);
    try std.testing.expect(!owner.active_reader);
}
test "source fold draft collection: commit transfers only complete original transport and rejects reused owners" {
    var fixture = Fixture{};
    try fixture.init(1);
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const owner = try Draft.collect(std.testing.allocator, temporary.dir, &fixture.admitted, fixture.reader(), .{ .row_log = 1 });
    defer owner.deinit() catch unreachable;
    const plan = try planFor(&fixture, owner);
    {
        var collection = try Collection.init(owner, &fixture.admitted, plan, .{ .page_row_log = 1 }, 0);
        defer collection.deinit();
        try std.testing.expectError(error.IncompleteSourceFoldDraft, collection.commit());
        try drain(&collection);
        try std.testing.expectError(error.IncompleteSourceFoldDraftPublication, collection.commit());
        for (0..plan.pages) |index| {
            const identity = pageIdentity(@intCast(index));
            const stored = try collection.promote(@intCast(index), identity);
            var buffer: [128]u8 = undefined;
            var loaded = try Store.load(std.testing.allocator, temporary.dir, try Draft.path(&buffer, @intCast(index), true), try plan.page(@intCast(index)), plan.identity, identity, stored, .{});
            defer loaded.deinit();
            try std.testing.expectEqual((try plan.page(@intCast(index))).count, @as(u32, @intCast(loaded.operations.len)));
        }
        try collection.commit();
        try std.testing.expectError(error.ClosedSourceFoldDraftCollection, collection.next());
        try std.testing.expectError(error.ClosedSourceFoldDraftCollection, collection.promote(0, pageIdentity(0)));
    }
    try std.testing.expect(!owner.failed);
    try std.testing.expect(!owner.active_reader);
    try std.testing.expectError(error.ReusedSourceFoldDraftPublication, Collection.init(owner, &fixture.admitted, plan, .{ .page_row_log = 1 }, 0));
    for (0..plan.pages) |index| {
        var buffer: [128]u8 = undefined;
        try temporary.dir.access(try Draft.path(&buffer, @intCast(index), true), .{});
    }
}
fn afterPublicationFailure(collection: *Collection) !void {
    try drain(collection);
    _ = try collection.promote(0, pageIdentity(0));
    return error.InjectedAfterPublicationFailure;
}
test "source fold draft collection: arbitrary late callback failure cleans files without allocating cleanup state" {
    var fixture = Fixture{};
    try fixture.init(0);
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const owner = try Draft.collect(std.testing.allocator, temporary.dir, &fixture.admitted, fixture.reader(), .{ .row_log = 1 });
    defer owner.deinit() catch unreachable;
    const plan = try planFor(&fixture, owner);
    {
        var collection = try Collection.init(owner, &fixture.admitted, plan, .{ .page_row_log = 1 }, 0);
        defer collection.deinit();
        try std.testing.expectError(error.InjectedAfterPublicationFailure, afterPublicationFailure(&collection));
        try std.testing.expectEqual(@as(u32, 1), collection.created);
    }
    try std.testing.expectError(error.FileNotFound, temporary.dir.access("source-page-fold-0.operands", .{}));
    try std.testing.expect(owner.failed);
}
test "source fold draft collection: raw success inventory and fold prefix roll back together preserving later collisions" {
    var fixture = Fixture{};
    try fixture.init(0);
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const owner = try Draft.collect(std.testing.allocator, temporary.dir, &fixture.admitted, fixture.reader(), .{ .row_log = 1 });
    defer owner.deinit() catch unreachable;
    const plan = try planFor(&fixture, owner);
    const Files = @import("block_v5_artifact_files_v1.zig");
    try Files.publish(temporary.dir, "source-page-raw-1.operands", "preexisting raw");
    {
        var collection = try Collection.init(owner, &fixture.admitted, plan, .{ .page_row_log = 1 }, 2);
        defer collection.deinit();
        // Metadata transport only; original Job body performs real RawOwner
        // custody/persistence before advancing this same success inventory.
        try Files.publish(temporary.dir, "source-page-raw-0.operands", "new raw transport");
        collection.recordRaw(0);
        try drain(&collection);
        _ = try collection.promote(0, pageIdentity(0));
        try std.testing.expectError(error.IncompleteSourceFoldDraftPublication, collection.commit());
        try std.testing.expectError(error.ExistingV5BundleArtifact, Files.publish(temporary.dir, "source-page-raw-1.operands", "replacement"));
    }
    try std.testing.expectError(error.FileNotFound, temporary.dir.access("source-page-raw-0.operands", .{}));
    try std.testing.expectError(error.FileNotFound, temporary.dir.access("source-page-fold-0.operands", .{}));
    const bytes = try temporary.dir.readFileAlloc(std.testing.allocator, "source-page-raw-1.operands", 128);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("preexisting raw", bytes);
}
fn allocationFault(a: std.mem.Allocator) !void {
    var fixture = Fixture{};
    try fixture.init(1);
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const owner = try Draft.collect(a, temporary.dir, &fixture.admitted, fixture.reader(), .{ .row_log = 1 });
    defer owner.deinit() catch unreachable;
    const plan = try planFor(&fixture, owner);
    var collection = try Collection.init(owner, &fixture.admitted, plan, .{ .page_row_log = 1 }, 0);
    defer collection.deinit();
    try drain(&collection);
    for (0..plan.pages) |index| {
        const identity = pageIdentity(@intCast(index));
        const stored = try collection.promote(@intCast(index), identity);
        var buffer: [128]u8 = undefined;
        var loaded = try Store.load(a, temporary.dir, try Draft.path(&buffer, @intCast(index), true), try plan.page(@intCast(index)), plan.identity, identity, stored, .{});
        defer loaded.deinit();
        try std.testing.expect(loaded.operations.len != 0);
    }
    try collection.commit();
}
test "source fold draft collection: allocation faults after promotion release transaction before source owner" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFault, .{});
}
