//! Canonical identities and ingress metadata for recorded Cairo CUDA writers.

const std = @import("std");
const product_aot = @import("../../backends/cuda/aot/product_registry.zig");
const common = @import("../../backends/cuda/runtime/stages/common.zig");

const pointer_words = @sizeOf(usize) / @sizeOf(u32);
const execution_table_count = 37;
const execution_big_limb_count = 28;

comptime {
    std.debug.assert(pointer_words == 2);
}

pub const ComponentGeometry = struct {
    canonical_ordinal: u32,
    instance: u32,
    trace_log_size: u32,

    pub fn validateRows(self: ComponentGeometry, row_count: u32) !void {
        if (self.trace_log_size >= 32 or
            row_count != @as(u32, 1) << @intCast(self.trace_log_size))
        {
            return error.InvalidKernelDescriptor;
        }
    }
};

pub fn catalogIdentity(
    component: ComponentGeometry,
    label: []const u8,
    admitted: product_aot.RecordedWitness,
    native_consumer: bool,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/base-recorded/v1\x00");
    hashInt(&hash, u8, @intFromBool(native_consumer));
    hashInt(&hash, u32, component.canonical_ordinal);
    hashBytes(&hash, label);
    hashInt(&hash, u32, component.instance);
    hashInt(&hash, u32, component.trace_log_size);
    hashInt(&hash, u64, admitted.cache_key);
    hashInt(&hash, u64, admitted.semantic_hash);
    hash.update(&admitted.program_identity);
    hash.update(&admitted.source_identity);
    hashInt(&hash, u32, @intFromEnum(admitted.module_globals));
    hashBytes(&hash, admitted.kernel_name);
    return hash.finalResult();
}

pub fn bindingIdentity(
    catalog_identity: [32]u8,
    buffers: anytype,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/recorded-resident-binding/v1\x00");
    hash.update(&catalog_identity);
    hashSlice(&hash, buffers.input_pointer_table);
    hashSlices(&hash, buffers.input_columns);
    hashSlice(&hash, buffers.execution_pointer_table);
    hashSlices(&hash, buffers.execution_tables);
    hashSlice(&hash, buffers.execution_strides);
    hashSlice(&hash, buffers.output_pointer_table);
    hashSlices(&hash, buffers.output_columns);
    hashSlice(&hash, buffers.multiplicity_pointer_table);
    hashSlices(&hash, buffers.multiplicity_tables);
    hashSlice(&hash, buffers.lookup_words_word_major);
    hashSlice(&hash, buffers.sub_words_word_major);
    if (buffers.pedersen_w18) |table| {
        hashInt(&hash, u8, 1);
        hash.update(&table.identity);
        hashSlices(&hash, &table.columns);
    } else {
        hashInt(&hash, u8, 0);
    }
    return hash.finalResult();
}

pub fn uploadCanonical(
    allocator: std.mem.Allocator,
    uploader: anytype,
    buffers: anytype,
) !void {
    if (buffers.execution_tables.len != execution_table_count)
        return error.InvalidKernelDescriptor;
    const total_pointers = try checkedAdd(
        try checkedAdd(
            @max(buffers.input_columns.len, 1),
            @max(buffers.execution_tables.len, 1),
        ),
        try checkedAdd(
            @max(buffers.output_columns.len, 1),
            @max(buffers.multiplicity_tables.len, 1),
        ),
    );
    const storage = try allocator.alloc(
        u32,
        try checkedMul(total_pointers, pointer_words),
    );
    defer allocator.free(storage);

    var cursor: usize = 0;
    const input = try takePointers(storage, &cursor, buffers.input_columns.len);
    const execution = try takePointers(
        storage,
        &cursor,
        buffers.execution_tables.len,
    );
    const output = try takePointers(storage, &cursor, buffers.output_columns.len);
    const multiplicity = try takePointers(
        storage,
        &cursor,
        buffers.multiplicity_tables.len,
    );
    try encodePointerTable(input, buffers.input_columns);
    try encodePointerTable(execution, buffers.execution_tables);
    try encodePointerTable(output, buffers.output_columns);
    try encodePointerTable(multiplicity, buffers.multiplicity_tables);
    const strides = try executionStrides(buffers.execution_tables);

    try uploader.uploadSlice(u32, buffers.input_pointer_table, input);
    try uploader.uploadSlice(u32, buffers.execution_pointer_table, execution);
    try uploader.uploadSlice(u32, buffers.execution_strides, &strides);
    try uploader.uploadSlice(u32, buffers.output_pointer_table, output);
    try uploader.uploadSlice(
        u32,
        buffers.multiplicity_pointer_table,
        multiplicity,
    );
}

pub fn encodePointerTable(destination: []u32, slices: anytype) !void {
    if (destination.len != try checkedMul(@max(slices.len, 1), pointer_words))
        return error.InvalidKernelDescriptor;
    @memset(destination, 0);
    for (slices, 0..) |slice, index| {
        if (slice.address == 0) return error.InvalidKernelDescriptor;
        const first = index * pointer_words;
        destination[first] = @truncate(slice.address);
        destination[first + 1] = @truncate(slice.address >> 32);
    }
}

fn executionStrides(tables: anytype) ![3]u32 {
    if (tables.len != execution_table_count)
        return error.InvalidKernelDescriptor;
    const strides = [3]u32{
        std.math.cast(u32, tables[0].len) orelse
            return error.InvalidKernelDescriptor,
        std.math.cast(u32, tables[1].len) orelse
            return error.InvalidKernelDescriptor,
        std.math.cast(u32, tables[1 + execution_big_limb_count].len) orelse
            return error.InvalidKernelDescriptor,
    };
    if (strides[0] == 0 or strides[1] == 0 or strides[2] == 0)
        return error.InvalidKernelDescriptor;
    for (tables[1 .. 1 + execution_big_limb_count]) |table| {
        if (table.len != strides[1]) return error.InvalidKernelDescriptor;
    }
    for (tables[1 + execution_big_limb_count ..]) |table| {
        if (table.len != strides[2]) return error.InvalidKernelDescriptor;
    }
    return strides;
}

fn takePointers(
    storage: []u32,
    cursor: *usize,
    count: usize,
) ![]u32 {
    const words = try checkedMul(@max(count, 1), pointer_words);
    const end = try checkedAdd(cursor.*, words);
    if (end > storage.len) return error.InvalidKernelDescriptor;
    defer cursor.* = end;
    return storage[cursor.*..end];
}

fn hashSlices(hash: *std.crypto.hash.sha2.Sha256, slices: anytype) void {
    hashInt(hash, u64, slices.len);
    for (slices) |slice| hashSlice(hash, slice);
}

pub fn hashSlice(
    hash: *std.crypto.hash.sha2.Sha256,
    slice: common.Words,
) void {
    hashInt(hash, u64, slice.address);
    hashInt(hash, u64, slice.len);
    hashInt(hash, u64, slice.owner);
    hashInt(hash, u64, slice.generation);
}

pub fn hashBytes(
    hash: *std.crypto.hash.sha2.Sha256,
    bytes: []const u8,
) void {
    hashInt(hash, u64, bytes.len);
    hash.update(bytes);
}

pub fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: anytype,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

fn checkedAdd(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch
        error.InvalidKernelDescriptor;
}

fn checkedMul(left: usize, right: usize) !usize {
    return std.math.mul(usize, left, right) catch
        error.InvalidKernelDescriptor;
}

test "pointer tables are encoded only from supplied resident slices" {
    const slices = [_]common.Words{
        .{ .address = 0x1234_5678_9abc_def0, .len = 8, .owner = 1 },
        .{ .address = 0xfedc_ba98_7654_3210, .len = 8, .owner = 1 },
    };
    var words: [4]u32 = undefined;
    try encodePointerTable(&words, &slices);
    try std.testing.expectEqualSlices(u32, &.{
        0x9abc_def0,
        0x1234_5678,
        0x7654_3210,
        0xfedc_ba98,
    }, &words);

    var changed = slices;
    changed[1].address += 4;
    var changed_words: [4]u32 = undefined;
    try encodePointerTable(&changed_words, &changed);
    try std.testing.expect(!std.mem.eql(
        u8,
        std.mem.sliceAsBytes(&words),
        std.mem.sliceAsBytes(&changed_words),
    ));
}

test "recorded ingress overwrites every pointer table and execution stride" {
    const inputs = [_]common.Words{
        testSlice(0x1000, 16),
        testSlice(0x2000, 16),
    };
    var execution: [execution_table_count]common.Words = undefined;
    execution[0] = testSlice(0x3000, 113);
    for (execution[1 .. 1 + execution_big_limb_count], 0..) |
        *table,
        index,
    | {
        table.* = testSlice(0x4000 + index * 0x100, 80);
    }
    for (execution[1 + execution_big_limb_count ..], 0..) |
        *table,
        index,
    | {
        table.* = testSlice(0x8000 + index * 0x100, 16);
    }
    const outputs = [_]common.Words{testSlice(0x9000, 16)};
    const multiplicities = [_]common.Words{};
    const buffers = .{
        .input_pointer_table = testSlice(0xa000, 4),
        .input_columns = inputs[0..],
        .execution_pointer_table = testSlice(0xb000, 74),
        .execution_tables = execution[0..],
        .execution_strides = testSlice(0xc000, 3),
        .output_pointer_table = testSlice(0xd000, 2),
        .output_columns = outputs[0..],
        .multiplicity_pointer_table = testSlice(0xe000, 2),
        .multiplicity_tables = multiplicities[0..],
    };
    var uploader = CaptureUploader{};
    try uploadCanonical(
        std.testing.allocator,
        &uploader,
        buffers,
    );
    try std.testing.expectEqual(@as(usize, 5), uploader.count);
    try std.testing.expectEqualSlices(
        u32,
        &.{ 0x1000, 0, 0x2000, 0 },
        uploader.values[0][0..uploader.lengths[0]],
    );
    try std.testing.expectEqualSlices(
        u32,
        &.{ 113, 80, 16 },
        uploader.values[2][0..uploader.lengths[2]],
    );
    try std.testing.expectEqualSlices(
        u32,
        &.{ 0x9000, 0 },
        uploader.values[3][0..uploader.lengths[3]],
    );
    try std.testing.expectEqualSlices(
        u32,
        &.{ 0, 0 },
        uploader.values[4][0..uploader.lengths[4]],
    );
}

const CaptureUploader = struct {
    values: [5][74]u32 = [_][74]u32{[_]u32{0} ** 74} ** 5,
    lengths: [5]usize = [_]usize{0} ** 5,
    count: usize = 0,

    pub fn uploadSlice(
        self: *CaptureUploader,
        comptime F: type,
        _: anytype,
        source: []const F,
    ) !void {
        if (F != u32 or self.count >= self.values.len or
            source.len > self.values[0].len)
        {
            return error.InvalidKernelDescriptor;
        }
        @memcpy(self.values[self.count][0..source.len], source);
        self.lengths[self.count] = source.len;
        self.count += 1;
    }
};

fn testSlice(address: usize, len: usize) common.Words {
    return .{
        .address = address,
        .len = len,
        .owner = 7,
        .generation = 11,
    };
}
