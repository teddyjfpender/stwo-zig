//! Actual full4096-record original source PAGE transport; no PCS/STARK/FRI.
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
    bytes: [2048 * 8]u8 = undefined,
    leaves: [2048]Tree.Leaf = undefined,
    admitted: Batch.Admission = undefined,
    count: usize = 2048,
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
            .layout = .{ .program_base = 0, .program_end = 16, .data_base = 32, .data_end = 65536, .stack_bottom = 131072, .stack_top = 196608, .io_base = 196608, .io_end = 262144, .input_base = 32, .input_end = 64, .output_len_addr = 64, .output_data_addr = 68, .output_base = 64, .output_end = 256 },
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
test "source fold full PAGE transport: original 4096-record PAGE observes 64 versus one request with identical bytes and corruption rejection" {
    var fixture = Fixture{};
    try fixture.init(2048);
    var golden = std.testing.tmpDir(.{});
    defer golden.cleanup();
    var golden_pin: ?Store.Pin = null;
    // Same original source/schema and page identity across both executions.
    // Identity is an unverified transport proposal, never a proof receipt.
    const page_identity: [32]u8 = @splat(9);
    for ([_]u32{ 64, 4096 }) |records| {
        var temporary = std.testing.tmpDir(.{});
        defer temporary.cleanup();
        const owner = try Draft.collect(std.testing.allocator, temporary.dir, &fixture.admitted, fixture.reader(), .{ .row_log = 12, .max_buffer_records = records });
        defer owner.deinit() catch unreachable;
        const plan = try planFor(&fixture, owner);
        const page = try plan.page(0);
        try std.testing.expectEqual(@as(u32, 4096), page.count);
        try std.testing.expect(plan.pages > 1); // Original full tree includes tail.
        try std.testing.expectEqual(@as(u64, 2048), owner.census.rw);
        try std.testing.expectEqual(@as(u64, 2048), owner.census.leaves);
        try std.testing.expectEqual(@as(u64, 0), owner.census.touches);
        var reader = try Draft.Reader.open(owner, &fixture.admitted, plan, .{ .page_row_log = 12 });
        defer reader.deinit();
        var oracle = try Fold.Cursor.init(fixture.admitted.source, fixture.reader(), fixture.admitted.limits);
        // A single PAGE oracle owner, never a whole-stream operation matrix.
        const operations = try std.testing.allocator.alloc(Fold.Operation, page.count);
        defer std.testing.allocator.free(operations);
        for (operations) |*operation| {
            operation.* = try oracle.next() orelse return error.TestExpectedOperation;
            try std.testing.expect(std.meta.eql(operation.*, try reader.next() orelse return error.TestExpectedOperation));
        }
        try std.testing.expectEqual(@as(u32, 1), reader.index);
        try std.testing.expect(!owner.buffer_borrowed);
        try std.testing.expectEqual(@as(usize, records) * Store.RECORD_BYTES, owner.buffer.len);
        const expected_requests: u64 = if (records == 64) 64 else 1;
        try std.testing.expectEqual(expected_requests, owner.work.replay_payload_requests);
        try std.testing.expectEqual(@as(u64, 4096 * Store.RECORD_BYTES), owner.work.replay_payload_sha_bytes);
        const stored = try owner.promote(&fixture.admitted, plan, 0, page_identity, .{ .page_row_log = 12 });
        try std.testing.expectEqual(expected_requests, owner.work.promotion_payload_requests);
        try std.testing.expectEqual(@as(u64, 2 * 4096 * Store.RECORD_BYTES), owner.work.promotion_payload_sha_bytes);
        try std.testing.expectEqual(@as(u64, 0), owner.work.promotion_decode_attempts);
        const name = "source-page-fold-0.operands";
        if (golden_pin == null) {
            golden_pin = try Store.publish(std.testing.allocator, golden.dir, name, page, plan.identity, page_identity, operations, .{});
        }
        try std.testing.expect(std.meta.eql(golden_pin.?, stored));
        var loaded = try Store.load(std.testing.allocator, temporary.dir, name, page, plan.identity, page_identity, stored, .{});
        defer loaded.deinit();
        try std.testing.expectEqualDeep(operations, loaded.operations);
        const actual_bytes = try temporary.dir.readFileAlloc(std.testing.allocator, name, 2 << 20);
        defer std.testing.allocator.free(actual_bytes);
        const golden_bytes = try golden.dir.readFileAlloc(std.testing.allocator, name, 2 << 20);
        defer std.testing.allocator.free(golden_bytes);
        try std.testing.expectEqualSlices(u8, golden_bytes, actual_bytes);
        // Valid scalar framing but changed digest bytes must fail both original
        // Store load and published Reader at its complete-PAGE hash boundary.
        const file = try temporary.dir.openFile(name, .{ .mode = .read_write });
        defer file.close();
        var byte: [1]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 1), try file.preadAll(&byte, Store.HEADER_BYTES + 20));
        try file.pwriteAll(&.{byte[0] ^ 1}, Store.HEADER_BYTES + 20);
        try std.testing.expectError(error.TamperedV5BundleFileHash, Store.load(std.testing.allocator, temporary.dir, name, page, plan.identity, page_identity, stored, .{}));
        try reader.rewind();
        for (0..page.count - 1) |_| _ = try reader.next() orelse return error.TestExpectedOperation;
        try std.testing.expectError(error.TamperedV5BundleFileHash, reader.next());
        try std.testing.expect(owner.failed);
    }
}
