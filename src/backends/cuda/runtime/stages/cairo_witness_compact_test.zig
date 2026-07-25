//! Exact resident contracts for Cairo multiset compaction.

const std = @import("std");
const witness = @import("cairo_witness.zig");
const support = @import("contract_test_support.zig");

const CaptureApi = struct {
    var calls: usize = 0;

    pub fn stwo_witness_input_compact_sort_temp_bytes(
        rows: u32,
        out_bytes: *usize,
    ) c_int {
        if (rows != 32) return 1;
        out_bytes.* = 256;
        return 0;
    }

    pub fn stwo_witness_input_compact_scan_temp_bytes(
        rows: u32,
        out_bytes: *usize,
    ) c_int {
        if (rows != 32) return 1;
        out_bytes.* = 128;
        return 0;
    }

    pub fn stwo_witness_input_compact_v2_on(
        producers: [*]const u64,
        descriptors: [*]const u32,
        edge_count: u32,
        tuple_words: u32,
        key_words: u32,
        total_rows: u32,
        sort_rows: u32,
        consumer_rows: u32,
        input_count: u32,
        consumers: [*]const u64,
        enabler_slot: u32,
        iota_slot: u32,
        multiplicity_slot: u32,
        tuples: [*]u32,
        keys_a: [*]u32,
        keys_b: [*]u32,
        indices_a: [*]u32,
        indices_b: [*]u32,
        heads: [*]u32,
        positions: [*]u32,
        unique_count: *u32,
        sort_temp: *anyopaque,
        sort_temp_bytes: usize,
        scan_temp: *anyopaque,
        scan_temp_bytes: usize,
        _: *anyopaque,
    ) c_int {
        if (@intFromPtr(producers) != 0x1000 or
            @intFromPtr(descriptors) != 0x2000 or
            @intFromPtr(consumers) != 0x3000 or
            edge_count != 2 or tuple_words != 3 or key_words != 2 or
            total_rows != 20 or sort_rows != 32 or consumer_rows != 16 or
            input_count != 6 or enabler_slot != 3 or iota_slot != 4 or
            multiplicity_slot != 5 or @intFromPtr(tuples) != 0x10000 or
            @intFromPtr(keys_a) != 0x11000 or
            @intFromPtr(keys_b) != 0x12000 or
            @intFromPtr(indices_a) != 0x13000 or
            @intFromPtr(indices_b) != 0x14000 or
            @intFromPtr(heads) != 0x15000 or
            @intFromPtr(positions) != 0x16000 or
            @intFromPtr(unique_count) != 0x17000 or
            @intFromPtr(sort_temp) != 0x18000 or sort_temp_bytes != 256 or
            @intFromPtr(scan_temp) != 0x19000 or scan_temp_bytes != 128)
        {
            return 1;
        }
        calls += 1;
        return 0;
    }
};

fn binding() witness.Compact {
    return .{
        .producer_pointer_table = support.viewAt(u32, 0x1000, 4),
        .edge_descriptors = support.viewAt(u32, 0x2000, 12),
        .edge_count = 2,
        .tuple_words = 3,
        .key_words = 2,
        .total_rows = 20,
        .sort_rows = 32,
        .consumer_rows = 16,
        .input_count = 6,
        .consumer_pointer_table = support.viewAt(u32, 0x3000, 12),
        .enabler_slot = 3,
        .iota_slot = 4,
        .multiplicity_slot = 5,
        .tuples = support.viewAt(u32, 0x10000, 96),
        .keys_a = support.viewAt(u32, 0x11000, 32),
        .keys_b = support.viewAt(u32, 0x12000, 32),
        .indices_a = support.viewAt(u32, 0x13000, 32),
        .indices_b = support.viewAt(u32, 0x14000, 32),
        .heads = support.viewAt(u32, 0x15000, 32),
        .positions = support.viewAt(u32, 0x16000, 32),
        .unique_count = support.viewAt(u32, 0x17000, 1),
        .sort_temp = support.viewAt(u32, 0x18000, 64),
        .sort_temp_bytes = 256,
        .scan_temp = support.viewAt(u32, 0x19000, 32),
        .scan_temp_bytes = 128,
    };
}

test "compact temp query and launch preserve the exact native ABI" {
    const Ops = witness.OpsFor(CaptureApi);
    const temp = try Ops.compactTempBytes(32);
    try std.testing.expectEqual(@as(usize, 256), temp.sort);
    try std.testing.expectEqual(@as(usize, 128), temp.scan);
    try std.testing.expectEqual(@as(usize, 64), try temp.sortWords());
    try std.testing.expectEqual(@as(usize, 32), try temp.scanWords());

    CaptureApi.calls = 0;
    var session = support.FakeSession.init(.trace_generation);
    try Ops.compact(&session, binding());
    try std.testing.expectEqual(@as(usize, 1), CaptureApi.calls);
    try std.testing.expectEqual(@as(usize, 1), session.launches);
}

test "compact launch rejects malformed slots, workspace, and aliasing" {
    const Ops = witness.OpsFor(CaptureApi);
    var session = support.FakeSession.init(.trace_generation);

    var malformed = binding();
    malformed.multiplicity_slot = 4;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        Ops.compact(&session, malformed),
    );

    var short = binding();
    short.sort_temp.len -= 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        Ops.compact(&session, short),
    );

    var aliased = binding();
    aliased.scan_temp.address = aliased.sort_temp.address;
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        Ops.compact(&session, aliased),
    );

    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        Ops.compactTempBytes(24),
    );
}
