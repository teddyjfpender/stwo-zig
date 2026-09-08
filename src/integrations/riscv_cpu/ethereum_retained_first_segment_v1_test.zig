//! Real retained regression: execute only the first admitted segment, then
//! require the same global/local source validation as V4 raw capture.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const retained_mod = @import("ethereum_incremental_capture_retained_authority_v4.zig");
const global = frontend.recursion.segment_leaf_local_authority_v3;

const Observer = struct {
    retained: *const retained_mod.RetainedAuthorityV4,
    checked: bool = false,
    require_legacy_heap_failure: bool = false,

    pub fn observe(self: *Observer, comptime profile: anytype, configured: anytype, record: [32]u8) !void {
        if (comptime profile != .rv32im_zkvm_ethereum_v1) return error.ExecutionProfileMismatch;
        const segment = &configured.base;
        try std.testing.expectEqual(@as(u32, 0), segment.segment_index);
        const source = &self.retained.sources[0].value;
        try std.testing.expectEqualSlices(u8, &source.journal_record_sha256, &record);
        var word_at: usize = 0;
        for (segment.exit_access_clocks.memory_clocks) |clock| {
            while (word_at < segment.rw_memory.words.len and segment.rw_memory.words[word_at].addr < clock.addr)
                word_at += 1;
            const word = if (word_at < segment.rw_memory.words.len and segment.rw_memory.words[word_at].addr == clock.addr)
                segment.rw_memory.words[word_at]
            else
                null;
            if (word == null or word.?.final_clock != clock.clock) {
                if (self.require_legacy_heap_failure) {
                    try std.testing.expectEqual(@as(u32, 0x0200e630), clock.addr);
                    try std.testing.expectEqual(@as(u32, 49491), clock.clock);
                    try std.testing.expect(word == null);
                    try std.testing.expect(!segment.rw_memory.layout.isRwAddr(clock.addr));
                }
                var program_word: ?u32 = null;
                for (segment.rw_memory.program_words) |entry| {
                    if (entry.addr == clock.addr) {
                        program_word = entry.final_word;
                        break;
                    }
                }
                std.debug.print("RETAINED_MEMORY_CLOCK_MISMATCH segment={} address=0x{x} clock={} rw_present={} rw_value={?} rw_clock={?} program_value={?} is_rw={} is_program={} rw_count={} clock_count={} layout={any}\n", .{
                    segment.segment_index,                              clock.addr,                            clock.clock,                                  word != null,
                    if (word) |w| w.final_word else null,               if (word) |w| w.final_clock else null, program_word,                                 segment.rw_memory.layout.isRwAddr(clock.addr),
                    segment.rw_memory.layout.isProgramAddr(clock.addr), segment.rw_memory.words.len,           segment.exit_access_clocks.memory_clocks.len, segment.rw_memory.layout,
                });
                var access_seen = false;
                for (segment.execution_trace.rows.items) |row| {
                    if ((row.is_load or row.is_store) and (row.mem_addr & ~@as(u32, 3)) == clock.addr and
                        frontend.access_clock.encode(row.clk, .third) == clock.clock)
                    {
                        access_seen = true;
                        if (self.require_legacy_heap_failure) {
                            try std.testing.expectEqual(@as(u32, 6960), row.pc);
                            try std.testing.expectEqual(@as(u32, 0), row.mem_prev_word);
                            try std.testing.expectEqual(@as(u32, 1), row.mem_next_word);
                            try std.testing.expect(row.is_store);
                        }
                        std.debug.print("RETAINED_MEMORY_CLOCK_ACCESS {any}\n", .{row});
                    }
                }
                try std.testing.expect(access_seen);
                break;
            }
        }
        const statement = try frontend.recursion.span_statement.SpanStatement.fromCanonicalWords(&source.metadata.base_statement_words);
        _ = try global.SourceV3.fromSegmentResultAgainstMetadata(statement, segment, &source.metadata);
        self.checked = true;
        return error.FirstRetainedSegmentChecked;
    }
};

test "real retained Ethereum first segment authenticates memory clock projection" {
    const path = try std.process.getEnvVarOwned(std.testing.allocator, "STWO_ETHEREUM_RETAINED_MATERIALIZATION");
    defer std.testing.allocator.free(path);
    try checkFirst(path, false);
}

test "legacy Ethereum guest heap omission is rejected by memory clock admission" {
    const path = try std.process.getEnvVarOwned(std.testing.allocator, "STWO_ETHEREUM_RETAINED_LEGACY_MATERIALIZATION");
    defer std.testing.allocator.free(path);
    try std.testing.expectError(error.MemoryClockMissing, checkFirst(path, true));
}

fn checkFirst(path: []const u8, legacy_failure: bool) !void {
    const allocator = std.testing.allocator;
    var retained = try retained_mod.RetainedAuthorityV4.openWithCampaignGeometryV1(allocator, path, .authenticated_v1);
    defer retained.deinit();
    if (legacy_failure) {
        var expected: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, "f3657d077b88da313369ff002aafbe8b6bf4912e8fd1ef1d1b76a6dc0f1d40a7");
        try std.testing.expectEqualSlices(u8, &expected, &retained.elf_identity.sha256);
    }
    var observer = Observer{ .retained = &retained, .require_legacy_heap_failure = legacy_failure };
    var journal = std.Io.Writer.Allocating.init(allocator);
    defer journal.deinit();
    frontend.diagnostics.segment_manifest.streamObserved(
        allocator,
        retained.elf_bytes,
        retained.input_bytes,
        (try retained.executionAuthority()).segment_step_budget,
        true,
        .leaf_local,
        &journal.writer,
        &observer,
    ) catch |err| {
        if (err != error.FirstRetainedSegmentChecked) return err;
    };
    try std.testing.expect(observer.checked);
}
