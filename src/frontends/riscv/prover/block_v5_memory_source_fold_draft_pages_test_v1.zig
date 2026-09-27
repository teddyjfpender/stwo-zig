//! Canonical draft transport only: no PCS, STARK, FRI, guest or receipt.
const std = @import("std");
const Draft = @import("block_v5_memory_source_fold_draft_pages_v1.zig");
const Store = @import("block_v5_memory_source_fold_operand_store_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Batch = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Initial = @import("block_v5_initial_sources_v1.zig");
const Tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const Sparse = @import("block_v5_sparse_state_stream_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
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
    return Protocol.FoldPlan.init(&fixture.admitted, owner.census, config, .{ .page_row_log = owner.limits.row_log });
}
fn checkOracle(reader: *Draft.Reader, fixture: *Fixture) !void {
    var oracle = try Fold.Cursor.init(fixture.admitted.source, fixture.reader(), fixture.admitted.limits);
    while (try oracle.next()) |expected| {
        const actual = try reader.next() orelse return error.TestExpectedOperation;
        try std.testing.expect(std.meta.eql(expected, actual));
    }
    try std.testing.expect(try reader.next() == null);
    try reader.requireFinished();
    try std.testing.expect(std.meta.eql(oracle.census, reader.owner.census));
}
fn drain(reader: *Draft.Reader) !void {
    while (try reader.next() != null) {}
    try reader.requireFinished();
}
fn absent(dir: std.fs.Dir, name: []const u8) !void {
    try std.testing.expectError(error.FileNotFound, dir.access(name, .{}));
}
fn countDrafts(dir: std.fs.Dir) !usize {
    var scan = try dir.openDir(".", .{ .iterate = true });
    defer scan.close();
    var iterator = scan.iterate();
    var count: usize = 0;
    while (try iterator.next()) |entry| {
        if (std.mem.endsWith(u8, entry.name, ".draft")) count += 1;
    }
    return count;
}
fn pageIdentity(index: u32) [32]u8 {
    // Unverified transport metadata proposals, never premix/proof receipts.
    var value: [32]u8 = @splat(7);
    std.mem.writeInt(u32, value[0..4], index, .little);
    return value;
}
test "source fold draft pages: dense original cursor two-pass replay and same-inode original Store interoperability" {
    var fixture = Fixture{};
    try fixture.init(64);
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var original = std.testing.tmpDir(.{});
    defer original.cleanup();
    const owner = try Draft.collect(std.testing.allocator, temporary.dir, &fixture.admitted, fixture.reader(), .{ .row_log = 7 });
    defer owner.deinit() catch unreachable;
    const plan = try planFor(&fixture, owner);
    try std.testing.expect(plan.pages > 1);
    try std.testing.expect(try owner.census.operations() > 2 * Store.BUFFER_RECORDS);
    try std.testing.expectEqual(@as(u64, 96 * plan.pages) + 250 * try owner.census.operations(), owner.total_bytes);
    try absent(temporary.dir, "source-fold-census.operands");
    var reader = try Draft.Reader.open(owner, &fixture.admitted, plan, .{ .page_row_log = 7 });
    defer reader.deinit();
    try checkOracle(&reader, &fixture);
    try reader.rewind();
    try checkOracle(&reader, &fixture);
    // Original PAGE-sized oracle owners only, never a full stream matrix.
    var oracle = try Fold.Cursor.init(fixture.admitted.source, fixture.reader(), fixture.admitted.limits);
    for (owner.pins, 0..) |pin, index| {
        var buffer: [128]u8 = undefined;
        var private_buffer: [128]u8 = undefined;
        const name = try Draft.path(&buffer, @intCast(index), true);
        const draft_name = try Draft.path(&private_buffer, @intCast(index), false);
        const before = try temporary.dir.statFile(draft_name);
        const operations = try std.testing.allocator.alloc(Fold.Operation, pin.page.count);
        defer std.testing.allocator.free(operations);
        for (operations) |*operation| operation.* = try oracle.next() orelse return error.TestExpectedOperation;
        const identity = pageIdentity(@intCast(index));
        const stored = try owner.promote(&fixture.admitted, plan, @intCast(index), identity, .{ .page_row_log = 7 });
        const expected = try Store.publish(std.testing.allocator, original.dir, name, pin.page, plan.identity, identity, operations, .{});
        try std.testing.expect(std.meta.eql(expected, stored));
        const after = try temporary.dir.statFile(name);
        try std.testing.expectEqual(before.inode, after.inode);
        try absent(temporary.dir, draft_name);
        var loaded = try Store.load(std.testing.allocator, temporary.dir, name, pin.page, plan.identity, identity, stored, .{});
        defer loaded.deinit();
        try std.testing.expectEqualDeep(operations, loaded.operations);
        const actual_bytes = try temporary.dir.readFileAlloc(std.testing.allocator, name, 2 << 20);
        defer std.testing.allocator.free(actual_bytes);
        const expected_bytes = try original.dir.readFileAlloc(std.testing.allocator, name, 2 << 20);
        defer std.testing.allocator.free(expected_bytes);
        try std.testing.expectEqualSlices(u8, expected_bytes, actual_bytes);
    }
    try std.testing.expect(try oracle.next() == null);
    try std.testing.expectEqual(@as(usize, 0), try countDrafts(temporary.dir));
    try reader.rewind();
    try checkOracle(&reader, &fixture); // Canonical published bytes, same guard.
}
test "source fold draft pages: empty image exact capacity boundaries and teardown preserve promoted originals" {
    for ([_]usize{ 0, 1 }) |count| {
        var fixture = Fixture{};
        try fixture.init(count);
        var temporary = std.testing.tmpDir(.{});
        defer temporary.cleanup();
        const owner = try Draft.collect(std.testing.allocator, temporary.dir, &fixture.admitted, fixture.reader(), .{ .row_log = 1 });
        var owner_live = true;
        defer if (owner_live) owner.deinit() catch unreachable;
        const plan = try planFor(&fixture, owner);
        var reader = try Draft.Reader.open(owner, &fixture.admitted, plan, .{ .page_row_log = 1 });
        var reader_live = true;
        defer if (reader_live) reader.deinit();
        try checkOracle(&reader, &fixture);
        reader.deinit();
        reader_live = false;
        const pin = owner.pins[0];
        try std.testing.expectEqual(@as(u32, 2), pin.page.count);
        _ = try owner.promote(&fixture.admitted, plan, 0, pageIdentity(0), .{ .page_row_log = 1 });
        try owner.deinit();
        owner_live = false;
        try temporary.dir.access("source-page-fold-0.operands", .{});
        try std.testing.expectEqual(@as(usize, 0), try countDrafts(temporary.dir));
    }
}
test "source fold draft pages: fail-closed limits source failure and exclusive collisions roll back only new drafts" {
    var fixture = Fixture{};
    try fixture.init(64);
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var deny = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.SourceFoldDraftResourceLimit, Draft.collect(deny.allocator(), undefined, undefined, undefined, .{ .row_log = 0 }));
    try std.testing.expectEqual(@as(usize, 0), deny.alloc_index);
    for ([_]Draft.Limits{
        .{ .max_operations = 1 },
        .{ .row_log = 1, .max_pages = 1 },
        .{ .max_total_bytes = Store.HEADER_BYTES },
        .{ .max_metadata_bytes = @sizeOf(Draft.Owner) },
        .{ .stored = .{ .max_file_bytes = Store.HEADER_BYTES } },
    }) |limits| {
        try std.testing.expectError(error.SourceFoldDraftResourceLimit, Draft.collect(std.testing.allocator, temporary.dir, &fixture.admitted, fixture.reader(), limits));
        try std.testing.expectEqual(@as(usize, 0), try countDrafts(temporary.dir));
    }
    fixture.fail_read = true;
    try std.testing.expectError(error.InjectedSourceReadFailure, Draft.collect(std.testing.allocator, temporary.dir, &fixture.admitted, fixture.reader(), .{}));
    fixture.fail_read = false;
    try std.testing.expectEqual(@as(usize, 0), try countDrafts(temporary.dir));
    const prior = try temporary.dir.createFile("source-page-fold-1.operands.draft", .{ .exclusive = true });
    try prior.writeAll("preexisting draft");
    prior.close();
    try std.testing.expectError(error.PathAlreadyExists, Draft.collect(std.testing.allocator, temporary.dir, &fixture.admitted, fixture.reader(), .{ .row_log = 1 }));
    try absent(temporary.dir, "source-page-fold-0.operands.draft");
    const bytes = try temporary.dir.readFileAlloc(std.testing.allocator, "source-page-fold-1.operands.draft", 128);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("preexisting draft", bytes);
    try temporary.dir.deleteFile("source-page-fold-1.operands.draft");
    const final = try temporary.dir.createFile("source-page-fold-0.operands", .{ .exclusive = true });
    try final.writeAll("preexisting final");
    final.close();
    try std.testing.expectError(error.ExistingV5BundleArtifact, Draft.collect(std.testing.allocator, temporary.dir, &fixture.admitted, fixture.reader(), .{}));
    try std.testing.expectEqual(@as(usize, 0), try countDrafts(temporary.dir));
}
test "source fold draft pages: exact plan and pin order single-reader lifetime and no promotion before replay" {
    var fixture = Fixture{};
    try fixture.init(1);
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const owner = try Draft.collect(std.testing.allocator, temporary.dir, &fixture.admitted, fixture.reader(), .{ .row_log = 1 });
    defer owner.deinit() catch unreachable;
    const limits = Protocol.Limits{ .page_row_log = 1 };
    const plan = try planFor(&fixture, owner);
    try std.testing.expectError(error.InvalidSourceFoldDraftOrder, owner.promote(&fixture.admitted, plan, 0, pageIdentity(0), limits));
    var changed = plan;
    changed.identity[0] ^= 1;
    try std.testing.expectError(error.UntrustedSourceUnifiedFoldPlan, owner.require(&fixture.admitted, changed, limits));
    const source_id = owner.source_id;
    owner.source_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedSourceFoldDraft, owner.require(&fixture.admitted, plan, limits));
    owner.source_id = source_id;
    var reader = try Draft.Reader.open(owner, &fixture.admitted, plan, limits);
    defer reader.deinit();
    try std.testing.expectError(error.ActiveSourceFoldDraftReader, Draft.Reader.open(owner, &fixture.admitted, plan, limits));
    try std.testing.expectError(error.ActiveSourceFoldDraftReader, owner.deinit());
    try std.testing.expectError(error.IncompleteSourceFoldDraft, reader.requireFinished());
    try drain(&reader);
    try std.testing.expectError(error.InvalidSourceFoldDraftOrder, owner.promote(&fixture.admitted, plan, 1, pageIdentity(1), limits));
    try std.testing.expectError(error.InvalidSourceFoldDraftOrder, owner.promote(&fixture.admitted, plan, 0, @splat(0), limits));
    _ = try owner.promote(&fixture.admitted, plan, 0, pageIdentity(0), limits);
    try std.testing.expectError(error.InvalidSourceFoldDraftOrder, owner.promote(&fixture.admitted, plan, 0, pageIdentity(0), limits));
}
test "source fold draft pages: independently admitted census row capacity and every per-page tuple stay exact" {
    for (0..5) |mutation| {
        var fixture = Fixture{};
        try fixture.init(1);
        var temporary = std.testing.tmpDir(.{});
        defer temporary.cleanup();
        const owner = try Draft.collect(std.testing.allocator, temporary.dir, &fixture.admitted, fixture.reader(), .{ .row_log = 1 });
        defer owner.deinit() catch unreachable;
        const plan = try planFor(&fixture, owner);
        if (mutation == 0) {
            owner.census.compressions += 1;
            try std.testing.expectError(error.UntrustedSourceFoldDraft, owner.require(&fixture.admitted, plan, .{ .page_row_log = 1 }));
        } else if (mutation == 1) {
            owner.limits.row_log = 2;
            try std.testing.expectError(error.UntrustedSourceFoldDraft, owner.require(&fixture.admitted, plan, .{ .page_row_log = 1 }));
        } else {
            var reader = try Draft.Reader.open(owner, &fixture.admitted, plan, .{ .page_row_log = 1 });
            defer reader.deinit();
            switch (mutation) {
                2 => owner.pins[0].page.first += 1,
                3 => owner.pins[0].page.count += 1,
                4 => owner.pins[0].byte_len += 1,
                else => unreachable,
            }
            try std.testing.expectError(error.UntrustedSourceFoldDraft, reader.next());
            try std.testing.expect(owner.failed);
        }
    }
}
test "source fold draft pages: header enum image bool ordinal payload length and pin tampering poison replay" {
    const Mutation = struct { offset: u64, value: u8, failure: anyerror };
    const cases = [_]Mutation{
        .{ .offset = 0, .value = 'X', .failure = error.InvalidSourceFoldDraftHeader },
        .{ .offset = 8, .value = 0, .failure = error.InvalidSourceFoldDraftHeader },
        .{ .offset = Store.HEADER_BYTES, .value = 1, .failure = error.InvalidSourceFoldOperandOrder },
        .{ .offset = Store.HEADER_BYTES + 8, .value = 255, .failure = error.InvalidSourceFoldOperandKind },
        .{ .offset = Store.HEADER_BYTES + 104, .value = 255, .failure = error.InvalidSourceFoldOperandImage },
        .{ .offset = Store.HEADER_BYTES + 105, .value = 2, .failure = error.InvalidSourceFoldOperandBoolean },
        .{ .offset = Store.HEADER_BYTES + 20, .value = 255, .failure = error.TamperedV5BundleFileHash },
    };
    for (cases) |mutation| {
        var fixture = Fixture{};
        try fixture.init(0);
        var temporary = std.testing.tmpDir(.{});
        defer temporary.cleanup();
        const owner = try Draft.collect(std.testing.allocator, temporary.dir, &fixture.admitted, fixture.reader(), .{ .row_log = 1 });
        defer owner.deinit() catch unreachable;
        const plan = try planFor(&fixture, owner);
        var reader = try Draft.Reader.open(owner, &fixture.admitted, plan, .{ .page_row_log = 1 });
        defer reader.deinit();
        // Rewind must inspect changed bytes, even after a successful first pass.
        try drain(&reader);
        try reader.rewind();
        const file = try temporary.dir.openFile("source-page-fold-0.operands.draft", .{ .mode = .read_write });
        defer file.close();
        var before: [1]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 1), try file.preadAll(&before, mutation.offset));
        // Header identity and payload mutations must actually differ.
        const value = if (mutation.offset == 8 or mutation.offset == Store.HEADER_BYTES + 20) before[0] ^ 1 else mutation.value;
        try file.pwriteAll(&.{value}, mutation.offset);
        try std.testing.expectError(mutation.failure, drain(&reader));
        try std.testing.expect(owner.failed);
        try std.testing.expectError(error.UntrustedSourceFoldDraft, reader.rewind());
        try std.testing.expectError(error.IncompleteSourceFoldDraft, reader.requireFinished());
        try absent(temporary.dir, "source-page-fold-0.operands");
    }
    for ([_]bool{ false, true }) |truncate| {
        var fixture = Fixture{};
        try fixture.init(0);
        var temporary = std.testing.tmpDir(.{});
        defer temporary.cleanup();
        const owner = try Draft.collect(std.testing.allocator, temporary.dir, &fixture.admitted, fixture.reader(), .{ .row_log = 1 });
        defer owner.deinit() catch unreachable;
        const plan = try planFor(&fixture, owner);
        var reader = try Draft.Reader.open(owner, &fixture.admitted, plan, .{ .page_row_log = 1 });
        defer reader.deinit();
        if (truncate) {
            const file = try temporary.dir.openFile("source-page-fold-0.operands.draft", .{ .mode = .read_write });
            defer file.close();
            try file.setEndPos(owner.pins[0].byte_len - 1);
            try std.testing.expectError(error.TamperedV5BundleFileLength, drain(&reader));
        } else {
            owner.pins[0].payload_sha256[0] ^= 1;
            try std.testing.expectError(error.TamperedV5BundleFileHash, drain(&reader));
        }
    }
}
test "source fold draft pages: promotion rechecks payload and preserves destination collisions" {
    for ([_]bool{ false, true }) |corrupt| {
        var fixture = Fixture{};
        try fixture.init(0);
        var temporary = std.testing.tmpDir(.{});
        defer temporary.cleanup();
        const owner = try Draft.collect(std.testing.allocator, temporary.dir, &fixture.admitted, fixture.reader(), .{ .row_log = 1 });
        var live = true;
        defer if (live) owner.deinit() catch unreachable;
        const plan = try planFor(&fixture, owner);
        {
            var reader = try Draft.Reader.open(owner, &fixture.admitted, plan, .{ .page_row_log = 1 });
            defer reader.deinit();
            try drain(&reader);
        }
        if (corrupt) {
            const file = try temporary.dir.openFile("source-page-fold-0.operands.draft", .{ .mode = .read_write });
            defer file.close();
            var before: [1]u8 = undefined;
            _ = try file.preadAll(&before, Store.HEADER_BYTES + 20);
            try file.pwriteAll(&.{before[0] ^ 1}, Store.HEADER_BYTES + 20);
            try std.testing.expectError(error.TamperedV5BundleFileHash, owner.promote(&fixture.admitted, plan, 0, pageIdentity(0), .{ .page_row_log = 1 }));
            try absent(temporary.dir, "source-page-fold-0.operands");
        } else {
            const prior = try temporary.dir.createFile("source-page-fold-0.operands", .{ .exclusive = true });
            try prior.writeAll("preexisting final");
            prior.close();
            try std.testing.expectError(error.ExistingV5BundleArtifact, owner.promote(&fixture.admitted, plan, 0, pageIdentity(0), .{ .page_row_log = 1 }));
            const bytes = try temporary.dir.readFileAlloc(std.testing.allocator, "source-page-fold-0.operands", 128);
            defer std.testing.allocator.free(bytes);
            try std.testing.expectEqualStrings("preexisting final", bytes);
        }
        try std.testing.expect(owner.failed);
        try owner.deinit();
        live = false;
        try std.testing.expectEqual(@as(usize, 0), try countDrafts(temporary.dir));
    }
}
fn allocationFault(a: std.mem.Allocator) !void {
    var fixture = Fixture{};
    try fixture.init(1);
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const owner = Draft.collect(a, temporary.dir, &fixture.admitted, fixture.reader(), .{ .row_log = 1 }) catch |failure| {
        try std.testing.expectEqual(@as(usize, 0), try countDrafts(temporary.dir));
        return failure;
    };
    defer owner.deinit() catch unreachable;
    const plan = try planFor(&fixture, owner);
    var reader = try Draft.Reader.open(owner, &fixture.admitted, plan, .{ .page_row_log = 1 });
    defer reader.deinit();
    try drain(&reader);
    for (owner.pins, 0..) |pin, index| {
        const identity = pageIdentity(@intCast(index));
        const stored = try owner.promote(&fixture.admitted, plan, @intCast(index), identity, .{ .page_row_log = 1 });
        var buffer: [128]u8 = undefined;
        var loaded = try Store.load(a, temporary.dir, try Draft.path(&buffer, @intCast(index), true), pin.page, plan.identity, identity, stored, .{});
        defer loaded.deinit();
        try std.testing.expectEqual(@as(usize, pin.page.count), loaded.operations.len);
    }
}
test "source fold draft pages: every owner metadata and original load allocation failure releases files and owners" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFault, .{});
}
test "source fold draft pages: retained aggregate budget outlives coordinator and replay reuses its charged PAGE buffer" {
    var fixture = Fixture{};
    try fixture.init(0);
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const budget = try Budget.create(std.testing.allocator, 1 << 20);
    var coordinator_live = true;
    defer if (coordinator_live) budget.destroy();
    const owner = try Draft.collect(budget.allocator(), temporary.dir, &fixture.admitted, fixture.reader(), .{ .row_log = 1 });
    defer owner.deinit() catch unreachable;
    const plan = try planFor(&fixture, owner);
    budget.destroy();
    coordinator_live = false;
    const live_bytes = budget.snapshot().live_bytes;
    try std.testing.expect(live_bytes >= @sizeOf(Draft.Owner));
    var reader = try Draft.Reader.open(owner, &fixture.admitted, plan, .{ .page_row_log = 1 });
    defer reader.deinit();
    try std.testing.expectEqual(live_bytes + 2 * Store.RECORD_BYTES, budget.snapshot().live_bytes);
    const replay_live = budget.snapshot().live_bytes;
    try checkOracle(&reader, &fixture);
    _ = try owner.promote(&fixture.admitted, plan, 0, pageIdentity(0), .{ .page_row_log = 1 });
    try std.testing.expectEqual(replay_live, budget.snapshot().live_bytes);
}
