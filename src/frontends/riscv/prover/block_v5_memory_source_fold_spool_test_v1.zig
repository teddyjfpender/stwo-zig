//! Original tree/cursor vs durable buffered replay; no PAGE/PCS/proof invoked.
const std = @import("std");
const Spool = @import("block_v5_memory_source_fold_spool_v1.zig");
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
    fn init(self: *@This()) !void {
        for (&self.leaves, 0..) |*leaf, i| {
            const address: u32 = @intCast(1024 + 4 * i);
            const value: u32 = @intCast(i + 1);
            std.mem.writeInt(u32, self.bytes[8 * i ..][0..4], address, .little);
            std.mem.writeInt(u32, self.bytes[8 * i + 4 ..][0..4], value, .little);
            leaf.* = .{ .index = address / 4, .value = value };
        }
        var image = Image{ .leaves = &self.leaves };
        const root = (try Sparse.root(&image, self.leaves.len)).bytes;
        const empty = Initial.sha256("");
        const original = try Source.make(.{ .initial = .{
            .layout = .{ .program_base = 0, .program_end = 16, .data_base = 32, .data_end = 4096, .stack_bottom = 128, .stack_top = 8192, .io_base = 256, .io_end = 10240, .input_base = 32, .input_end = 64, .output_len_addr = 64, .output_data_addr = 68, .output_base = 64, .output_end = 256 },
            .initial_rw_root = root,
            .initial_registers = @splat(0),
            .public_input_sha256 = empty,
            .public_input_len = 0,
            .input_words = .{ .records = 0, .sha256 = empty },
            .rw_words = .{ .records = self.leaves.len, .sha256 = Initial.sha256(&self.bytes) },
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
        if (stream != .rw_words) {
            if (out.len != 0) return error.InvalidFoldSpoolFixtureOffset;
            return;
        }
        const end = try std.math.add(u64, offset, out.len);
        if (end > self.bytes.len) return error.InvalidFoldSpoolFixtureOffset;
        @memcpy(out, self.bytes[@intCast(offset)..@intCast(end)]);
    }
    fn reader(self: *@This()) Fold.Reader {
        return .{ .context = self, .read = read };
    }
};
test "source fold spool: original dense full tree crosses buffers with exact canonical operation parity" {
    var fixture = Fixture{};
    try fixture.init();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const pin = try Spool.collect(temporary.dir, "fold.spool", &fixture.admitted, fixture.reader(), .{});
    try std.testing.expect(try pin.census.operations() > 2 * Spool.BUFFER_RECORDS);
    var reader = try Spool.Reader.open(temporary.dir, "fold.spool", pin, &fixture.admitted, .{});
    defer reader.deinit();
    var oracle = try Fold.Cursor.init(fixture.admitted.source, fixture.reader(), fixture.admitted.limits);
    while (try oracle.next()) |expected| {
        const actual = try reader.next() orelse return error.TestExpectedOperation;
        try std.testing.expect(std.meta.eql(expected, actual));
    }
    try std.testing.expect(try reader.next() == null);
    try reader.requireFinished();
    try std.testing.expect(std.meta.eql(oracle.census, pin.census));
    try std.testing.expectError(error.ExistingSourceFoldSpool, Spool.collect(temporary.dir, "fold.spool", &fixture.admitted, fixture.reader(), .{}));
}
test "source fold spool: caps identity order footer hash and truncation are distinct fail-closed guards" {
    var fixture = Fixture{};
    try fixture.init();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try std.testing.expectError(error.InvalidSourceFoldSpoolLimits, Spool.collect(temporary.dir, "invalid", &fixture.admitted, undefined, .{ .max_operations = 0 }));
    try std.testing.expectError(error.SourceFoldSpoolResourceLimit, Spool.collect(temporary.dir, "small", &fixture.admitted, fixture.reader(), .{ .max_operations = 1 }));
    const pin = try Spool.collect(temporary.dir, "fold.spool", &fixture.admitted, fixture.reader(), .{});
    var changed = pin;
    changed.admission_id[0] ^= 1;
    try std.testing.expectError(error.InvalidSourceFoldSpoolPin, Spool.Reader.open(temporary.dir, "fold.spool", changed, &fixture.admitted, .{}));
    changed = pin;
    changed.sha256[0] ^= 1;
    var bad_hash = try Spool.Reader.open(temporary.dir, "fold.spool", changed, &fixture.admitted, .{});
    defer bad_hash.deinit();
    const count = try pin.census.operations();
    for (0..@as(usize, @intCast(count))) |_| _ = try bad_hash.next() orelse return error.TestExpectedOperation;
    try std.testing.expectError(error.TamperedSourceFoldSpool, bad_hash.next());
    changed = pin;
    changed.census.compressions += 1;
    var bad_footer = try Spool.Reader.open(temporary.dir, "fold.spool", changed, &fixture.admitted, .{});
    defer bad_footer.deinit();
    for (0..@as(usize, @intCast(count))) |_| _ = try bad_footer.next() orelse return error.TestExpectedOperation;
    try std.testing.expectError(error.InvalidSourceFoldSpoolFooter, bad_footer.next());
    var reader = try Spool.Reader.open(temporary.dir, "fold.spool", pin, &fixture.admitted, .{});
    defer reader.deinit();
    try std.testing.expectError(error.IncompleteSourceFoldSpool, reader.requireFinished());
    const file = try temporary.dir.openFile("fold.spool", .{ .mode = .read_write });
    defer file.close();
    try file.pwriteAll(&.{1}, Spool.HEADER_BYTES);
    try std.testing.expectError(error.InvalidSourceFoldSpoolOrder, reader.next());
    try file.pwriteAll(&.{0}, Spool.HEADER_BYTES);
    try file.setEndPos(pin.byte_len - 1);
    try std.testing.expectError(error.TruncatedSourceFoldSpool, Spool.Reader.open(temporary.dir, "fold.spool", pin, &fixture.admitted, .{}));
}
const DenyOperations = struct {
    fn next(_: *anyopaque) !?Fold.Operation {
        return error.UnexpectedOperationRead;
    }
    fn finished(_: *anyopaque) !void {
        return error.UnexpectedOperationFinish;
    }
};
test "source fold spool: Job rejects stale census admission and file cap before ownership or stream access" {
    const JobModule = @import("block_v5_memory_source_page_job_v1.zig");
    const Job = JobModule.ForBackend(@import("stwo_cpu_backend").CpuBackend).Job;
    var deny = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var admitted: Batch.Admission = undefined;
    admitted.identity = @splat(3);
    var plan: @import("block_v5_memory_source_unified_page_protocol_v1.zig").FoldPlan = undefined;
    plan.census = .{ .roots = 1, .empty = 1 };
    const operations = JobModule.OperationSource{ .context = undefined, .admission_id = @splat(4), .census = plan.census, .next = DenyOperations.next, .require_finished = DenyOperations.finished };
    try std.testing.expectError(error.InvalidSourcePageJobCollection, Job.collectWithOperations(deny.allocator(), undefined, admitted, undefined, plan, undefined, operations, undefined, .{}));
    try std.testing.expectEqual(@as(usize, 0), deny.alloc_index);
    try std.testing.expectError(error.InvalidSourcePageJobLimits, Job.collectWithOperations(deny.allocator(), undefined, undefined, undefined, undefined, undefined, undefined, undefined, .{ .max_job_heap_bytes = 0 }));
    var fixture = Fixture{};
    try fixture.init();
    var cursor = try Fold.Cursor.init(fixture.admitted.source, fixture.reader(), fixture.admitted.limits);
    while (try cursor.next() != null) {}
    plan.census = cursor.census;
    var oversized = operations;
    oversized.admission_id = fixture.admitted.identity;
    oversized.census = cursor.census;
    oversized.stored_bytes = (JobModule.Limits{}).max_operand_bytes + 1;
    try std.testing.expectError(error.SourcePageJobFileResourceLimit, Job.collectWithOperations(deny.allocator(), undefined, fixture.admitted, undefined, plan, undefined, oversized, undefined, .{}));
    try std.testing.expectEqual(@as(usize, 0), deny.alloc_index);
}
