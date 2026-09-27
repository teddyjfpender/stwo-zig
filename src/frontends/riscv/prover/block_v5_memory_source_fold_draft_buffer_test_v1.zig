//! Original-byte guarded buffered replay; no PCS/proof/guest/device invocation.
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
fn identity(index: u32) [32]u8 {
    // Original transport proposals, never cryptographic verification receipts.
    var bytes: [32]u8 = @splat(3);
    std.mem.writeInt(u32, bytes[0..4], index, .little);
    return bytes;
}
fn drain(reader: *Draft.Reader) !void {
    while (try reader.next() != null) {}
    try reader.requireFinished();
}
test "source fold draft buffer: exact original Cursor and final bytes with one-record 64-record and PAGE buffers" {
    for ([_]u32{ 1, 64, 4096 }) |records| {
        var fixture = Fixture{};
        try fixture.init(64);
        var temporary = std.testing.tmpDir(.{});
        defer temporary.cleanup();
        const owner = try Draft.collect(std.testing.allocator, temporary.dir, &fixture.admitted, fixture.reader(), .{ .row_log = 7, .max_buffer_records = records });
        defer owner.deinit() catch unreachable;
        const plan = try planFor(&fixture, owner);
        var reader = try Draft.Reader.open(owner, &fixture.admitted, plan, .{ .page_row_log = 7 });
        defer reader.deinit();
        try std.testing.expectEqual(@as(usize, @min(records, 128)) * Store.RECORD_BYTES, reader.buffer.len);
        const address = reader.buffer.ptr;
        var oracle = try Fold.Cursor.init(fixture.admitted.source, fixture.reader(), fixture.admitted.limits);
        for (owner.pins, 0..) |pin, index| {
            const operations = try std.testing.allocator.alloc(Fold.Operation, pin.page.count);
            defer std.testing.allocator.free(operations);
            for (operations) |*operation| {
                operation.* = try oracle.next() orelse return error.TestExpectedOperation;
                try std.testing.expect(std.meta.eql(operation.*, try reader.next() orelse return error.TestExpectedOperation));
            }
            try std.testing.expect(owner.pins[index].checked_inventory != null);
            try std.testing.expect(!owner.buffer_borrowed);
            const stored = try owner.promote(&fixture.admitted, plan, @intCast(index), identity(@intCast(index)), .{ .page_row_log = 7 });
            var buffer: [128]u8 = undefined;
            var loaded = try Store.load(std.testing.allocator, temporary.dir, try Draft.path(&buffer, @intCast(index), true), pin.page, plan.identity, identity(@intCast(index)), stored, .{});
            defer loaded.deinit();
            try std.testing.expectEqualDeep(operations, loaded.operations);
        }
        try std.testing.expect(try oracle.next() == null);
        try std.testing.expect(try reader.next() == null);
        try reader.requireFinished();
        const operations = try owner.census.operations();
        var requests: u64 = 0;
        for (owner.pins) |pin| requests += (pin.page.count + @min(records, 128) - 1) / @min(records, 128);
        try std.testing.expectEqual(requests, owner.work.replay_payload_requests);
        try std.testing.expectEqual(requests, owner.work.promotion_payload_requests);
        try std.testing.expectEqual(operations * Store.RECORD_BYTES, owner.work.replay_payload_sha_bytes);
        try std.testing.expectEqual(operations * Store.RECORD_BYTES * 2, owner.work.promotion_payload_sha_bytes);
        try std.testing.expectEqual(@as(u64, 0), owner.work.promotion_decode_attempts);
        try reader.rewind();
        try std.testing.expectEqual(address, reader.buffer.ptr);
        try drain(&reader); // Published envelope SHA is still checked.
        try std.testing.expectEqual(operations * Store.RECORD_BYTES * 3, owner.work.replay_payload_sha_bytes);
    }
}
test "source fold draft buffer: earlier promotion preserves unread later-PAGE bytes and exact order" {
    var fixture = Fixture{};
    try fixture.init(64);
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const owner = try Draft.collect(std.testing.allocator, temporary.dir, &fixture.admitted, fixture.reader(), .{ .row_log = 7 });
    defer owner.deinit() catch unreachable;
    const plan = try planFor(&fixture, owner);
    var reader = try Draft.Reader.open(owner, &fixture.admitted, plan, .{ .page_row_log = 7 });
    defer reader.deinit();
    var oracle = try Fold.Cursor.init(fixture.admitted.source, fixture.reader(), fixture.admitted.limits);
    for (0..owner.pins[0].page.count + 1) |_| {
        try std.testing.expect(std.meta.eql(try oracle.next() orelse return error.TestExpectedOperation, try reader.next() orelse return error.TestExpectedOperation));
    }
    try std.testing.expect(owner.buffer_borrowed);
    _ = try owner.promote(&fixture.admitted, plan, 0, identity(0), .{ .page_row_log = 7 });
    try std.testing.expect(owner.buffer_borrowed);
    while (try oracle.next()) |operation| {
        try std.testing.expect(std.meta.eql(operation, try reader.next() orelse return error.TestExpectedOperation));
    }
    try std.testing.expect(try reader.next() == null);
    try reader.requireFinished();
}
test "source fold draft buffer: cached inventory never accepts changed current bytes or forged payload grammar" {
    for ([_]bool{ false, true }) |rewrite_pin| {
        var fixture = Fixture{};
        try fixture.init(0);
        var temporary = std.testing.tmpDir(.{});
        defer temporary.cleanup();
        const owner = try Draft.collect(std.testing.allocator, temporary.dir, &fixture.admitted, fixture.reader(), .{ .row_log = 1 });
        defer owner.deinit() catch unreachable;
        const plan = try planFor(&fixture, owner);
        var reader = try Draft.Reader.open(owner, &fixture.admitted, plan, .{ .page_row_log = 1 });
        defer reader.deinit();
        try drain(&reader);
        try std.testing.expect(owner.pins[0].checked_inventory != null);
        const file = try temporary.dir.openFile("source-page-fold-0.operands.draft", .{ .mode = .read_write });
        defer file.close();
        try file.pwriteAll(&.{255}, Store.HEADER_BYTES + 8); // Invalid kind.
        if (rewrite_pin) {
            var payload: [2 * Store.RECORD_BYTES]u8 = undefined;
            try std.testing.expectEqual(payload.len, try file.preadAll(&payload, Store.HEADER_BYTES));
            std.crypto.hash.sha2.Sha256.hash(&payload, &owner.pins[0].payload_sha256, .{});
            // Changing the pin invalidates cached exact inventory. The
            // ORIGINAL decoder then rejects even a newly matching hash.
            try std.testing.expectError(error.InvalidSourceFoldOperandKind, owner.promote(&fixture.admitted, plan, 0, identity(0), .{ .page_row_log = 1 }));
        } else {
            // Cache matches original pin, but EVERY current byte is rehashed.
            try std.testing.expectError(error.TamperedV5BundleFileHash, owner.promote(&fixture.admitted, plan, 0, identity(0), .{ .page_row_log = 1 }));
        }
        try std.testing.expect(owner.failed);
        try std.testing.expectError(error.FileNotFound, temporary.dir.access("source-page-fold-0.operands", .{}));
    }
}
test "source fold draft buffer: cache mutation only selects original fallback and published full SHA stays mandatory" {
    var fixture = Fixture{};
    try fixture.init(0);
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const owner = try Draft.collect(std.testing.allocator, temporary.dir, &fixture.admitted, fixture.reader(), .{ .row_log = 1 });
    defer owner.deinit() catch unreachable;
    const plan = try planFor(&fixture, owner);
    var reader = try Draft.Reader.open(owner, &fixture.admitted, plan, .{ .page_row_log = 1 });
    defer reader.deinit();
    try drain(&reader);
    owner.pins[0].checked_inventory.?[0] ^= 1;
    _ = try owner.promote(&fixture.admitted, plan, 0, identity(0), .{ .page_row_log = 1 });
    try std.testing.expectEqual(@as(u64, 2), owner.work.promotion_decode_attempts);
    try reader.rewind();
    owner.pins[0].published.?.sha256[0] ^= 1;
    try std.testing.expectError(error.TamperedV5BundleFileHash, drain(&reader));
}
test "source fold draft buffer: allocation refusal leaves reader lease free and capacity denied before source" {
    var fixture = Fixture{};
    try fixture.init(0);
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var deny = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.SourceFoldDraftResourceLimit, Draft.collect(deny.allocator(), undefined, undefined, undefined, .{ .max_buffer_records = 0 }));
    try std.testing.expectError(error.SourceFoldDraftResourceLimit, Draft.collect(deny.allocator(), undefined, undefined, undefined, .{ .max_buffer_records = 4097 }));
    try std.testing.expectEqual(@as(usize, 0), deny.alloc_index);
    // An actual owner keeps its own charged allocation context; temporarily
    // replace only that allocator to exercise buffer OOM before taking lease.
    const owner = try Draft.collect(std.testing.allocator, temporary.dir, &fixture.admitted, fixture.reader(), .{ .row_log = 1 });
    defer owner.deinit() catch unreachable;
    const plan = try planFor(&fixture, owner);
    const original = owner.a;
    owner.a = deny.allocator();
    defer owner.a = original;
    try std.testing.expectError(error.OutOfMemory, Draft.Reader.open(owner, &fixture.admitted, plan, .{ .page_row_log = 1 }));
    owner.a = original;
    try std.testing.expect(!owner.active_reader);
    try std.testing.expectEqual(@as(usize, 0), owner.buffer.len);
    var reader = try Draft.Reader.open(owner, &fixture.admitted, plan, .{ .page_row_log = 1 });
    defer reader.deinit();
    try drain(&reader);
}
