//! Compact and retained resident circle-transform contracts.

const std = @import("std");
const column = @import("../column.zig");
const telemetry = @import("../telemetry.zig");
const transform_module = @import("transform.zig");
const transform = transform_module.Native;

const owner: usize = 41;

const FakeContext = struct {
    stream_storage: u8 = 0,
    stream: *anyopaque = undefined,
    active_stage: ?telemetry.Stage = null,

    fn init(stage: telemetry.Stage) FakeContext {
        var result = FakeContext{ .active_stage = stage };
        result.stream = &result.stream_storage;
        return result;
    }

    pub fn deviceSlicePointer(
        self: *@This(),
        comptime F: type,
        slice: anytype,
        minimum: usize,
    ) ![*]F {
        _ = self;
        if (slice.owner != owner or slice.len < minimum or
            slice.address == 0 or slice.address % @alignOf(F) != 0)
        {
            return error.InvalidDeviceAddress;
        }
        return @ptrFromInt(slice.address);
    }

    pub fn requireStage(self: *@This(), expected: telemetry.Stage) !void {
        if (self.active_stage != expected) return error.StageOrderViolation;
    }
};

const FakeSession = struct {
    context: FakeContext,
    launches: usize = 0,

    fn init(stage: telemetry.Stage) FakeSession {
        return .{ .context = FakeContext.init(stage) };
    }

    pub fn recordOrdinaryKernels(
        self: *@This(),
        stage: telemetry.Stage,
        status: c_int,
        count: u64,
    ) !void {
        if (status != 0) return error.CudaFailure;
        try self.context.requireStage(stage);
        self.launches += @intCast(count);
    }
};

fn wordMatrix(
    address: usize,
    column_count: usize,
    stride_words: usize,
) transform_module.WordMatrix {
    return .{
        .storage = .{
            .address = address,
            .len = column_count * stride_words,
            .owner = owner,
        },
        .column_stride_words = stride_words,
    };
}

fn wordsAt(address: usize, len: usize) column.DeviceSlice(u32) {
    return .{ .address = address, .len = len, .owner = owner };
}

const CaptureApi = struct {
    var compact_calls: u32 = 0;
    var retained_calls: u32 = 0;
    var compact_output_stride: usize = 0;
    var retained_output_stride: usize = 0;

    fn reset() void {
        compact_calls = 0;
        retained_calls = 0;
        compact_output_stride = 0;
        retained_output_stride = 0;
    }

    fn validate(
        log_n: u32,
        columns: u32,
        twiddle_words: u32,
        domain_size: u32,
    ) c_int {
        return if (log_n == 8 and columns == 4 and
            twiddle_words == 256 and domain_size == 128)
            0
        else
            1;
    }

    pub fn stwo_ntt_b2n_columns_compact_on(
        _: [*]const u32,
        _: usize,
        _: [*]u32,
        output_stride: usize,
        log_n: u32,
        columns: u32,
        _: [*]const u32,
        twiddle_words: u32,
        domain_size: u32,
        _: *anyopaque,
        launches_out: *u32,
    ) c_int {
        const status = validate(log_n, columns, twiddle_words, domain_size);
        if (status != 0) return status;
        compact_calls += 1;
        compact_output_stride = output_stride;
        launches_out.* = 1;
        return 0;
    }

    pub fn stwo_ntt_b2n_columns_to_retained_on(
        _: [*]const u32,
        _: usize,
        _: [*]u32,
        output_stride: usize,
        log_n: u32,
        columns: u32,
        _: [*]const u32,
        twiddle_words: u32,
        domain_size: u32,
        _: *anyopaque,
        launches_out: *u32,
    ) c_int {
        const status = validate(log_n, columns, twiddle_words, domain_size);
        if (status != 0) return status;
        retained_calls += 1;
        retained_output_stride = output_stride;
        launches_out.* = 1;
        return 0;
    }
};

test "compact B2N accepts exactly N words per column" {
    var session = FakeSession.init(.trace_commit);
    try transform.inverseCompact(
        &session,
        .trace_commit,
        wordMatrix(0x24000, 4, 256),
        wordMatrix(0x24000, 4, 256),
        8,
        wordsAt(0x1000, 256),
    );
    try transform.inverseCompact(
        &session,
        .trace_commit,
        wordMatrix(0x30000, 4, 256),
        wordMatrix(0x40000, 4, 256),
        8,
        wordsAt(0x1000, 256),
    );
    try std.testing.expectEqual(@as(usize, 16), session.launches);
}

test "compact B2N rejects unsafe or inconsistent resident ranges" {
    var session = FakeSession.init(.trace_commit);
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        transform.inverseCompact(
            &session,
            .trace_commit,
            wordMatrix(0x40000, 1, 256),
            wordMatrix(0x40004, 1, 256),
            8,
            wordsAt(0x1000, 256),
        ),
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        transform.inverseCompact(
            &session,
            .trace_commit,
            wordMatrix(0x50000, 2, 256),
            wordMatrix(0x60000, 1, 256),
            8,
            wordsAt(0x1000, 256),
        ),
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        transform.inverseCompact(
            &session,
            .trace_commit,
            wordMatrix(0x70000, 1, 256),
            wordMatrix(0x80000, 1, 255),
            8,
            wordsAt(0x1000, 256),
        ),
    );
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        transform.inverseCompact(
            &session,
            .trace_commit,
            wordMatrix(0x90000, 1, 256),
            wordMatrix(0xa0000, 1, 256),
            8,
            // The first 128 words end at the output. The selected tail aliases
            // it, so validation must cover the complete passed twiddle slab.
            wordsAt(0x9fe00, 384),
        ),
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        transform.inverseCompact(
            &session,
            .trace_commit,
            wordMatrix(0xb0000, 1, 256),
            wordMatrix(0xc0000, 1, 256),
            8,
            wordsAt(0x1000, 127),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), session.launches);
}

test "compact and retained B2N select distinct compatibility ABIs" {
    CaptureApi.reset();
    var session = FakeSession.init(.trace_commit);
    const captured = transform_module.OpsFor(CaptureApi);
    try captured.inverseCompact(
        &session,
        .trace_commit,
        wordMatrix(0x24000, 4, 256),
        wordMatrix(0x30000, 4, 256),
        8,
        wordsAt(0x1000, 256),
    );
    try captured.inverseToRetained(
        &session,
        .trace_commit,
        wordMatrix(0x40000, 4, 256),
        wordMatrix(0x50000, 4, 512),
        8,
        wordsAt(0x1000, 256),
    );
    try std.testing.expectEqual(@as(u32, 1), CaptureApi.compact_calls);
    try std.testing.expectEqual(@as(u32, 1), CaptureApi.retained_calls);
    try std.testing.expectEqual(
        @as(usize, 256),
        CaptureApi.compact_output_stride,
    );
    try std.testing.expectEqual(
        @as(usize, 512),
        CaptureApi.retained_output_stride,
    );
    try std.testing.expectEqual(@as(usize, 2), session.launches);
}

const CaptureAddressedApi = struct {
    var calls: u32 = 0;
    var tile_offset: usize = 0;
    var include_circle: u32 = 0;

    pub fn stwo_lde_n2b_addressed_on(
        arena: [*]u32,
        arena_words: usize,
        descriptors: [*]const transform_module.AddressedLdeDescriptor,
        descriptor_count: u32,
        evaluation_tile_offset_words: usize,
        log_n: u32,
        twiddles: [*]const u32,
        twiddle_words: u32,
        domain_size: u32,
        _: *anyopaque,
        include: u32,
        launches_out: *u32,
    ) c_int {
        if (@intFromPtr(arena) != 0x100000 or
            arena_words != 4096 or
            @intFromPtr(descriptors) != 0x100100 or
            descriptor_count != 2 or
            evaluation_tile_offset_words != 2048 or
            log_n != 8 or
            @intFromPtr(twiddles) != 0x100400 or
            twiddle_words != 128 or
            domain_size != 128)
        {
            return 1;
        }
        calls += 1;
        tile_offset = evaluation_tile_offset_words;
        include_circle = include;
        launches_out.* = 4;
        return 0;
    }
};

fn descriptorSlice(
    address: usize,
    len: usize,
) transform_module.AddressedLdeDescriptors {
    return .{ .address = address, .len = len, .owner = owner };
}

test "addressed LDE validates the sealed plan before ingress" {
    const Descriptor = transform_module.AddressedLdeDescriptor;
    const descriptors = [_]Descriptor{
        Descriptor.init(0, 2048, 6),
        Descriptor.init(64, 2304, 6),
    };
    try transform_module.validateAddressedPlan(
        &descriptors,
        4096,
        2048,
        8,
    );

    var wrong_destination = descriptors;
    wrong_destination[1].evaluation_offset_words += 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        transform_module.validateAddressedPlan(
            &wrong_destination,
            4096,
            2048,
            8,
        ),
    );

    var aliases_tile = descriptors;
    aliases_tile[0].coefficient_offset_words = 2304;
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        transform_module.validateAddressedPlan(
            &aliases_tile,
            4096,
            2048,
            8,
        ),
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        transform_module.validateAddressedPlan(&.{}, 4096, 2048, 8),
    );
}

test "addressed LDE dispatch remains inside one resident arena" {
    CaptureAddressedApi.calls = 0;
    var session = FakeSession.init(.constraint_evaluation);
    const captured = transform_module.OpsFor(CaptureAddressedApi);
    try captured.extendAddressed(
        &session,
        .constraint_evaluation,
        wordsAt(0x100000, 4096),
        descriptorSlice(0x100100, 2),
        2048,
        8,
        wordsAt(0x100400, 128),
        false,
    );
    try std.testing.expectEqual(@as(u32, 1), CaptureAddressedApi.calls);
    try std.testing.expectEqual(@as(usize, 2048), CaptureAddressedApi.tile_offset);
    try std.testing.expectEqual(@as(u32, 1), CaptureAddressedApi.include_circle);
    try std.testing.expectEqual(@as(usize, 4), session.launches);

    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        captured.extendAddressed(
            &session,
            .constraint_evaluation,
            wordsAt(0x100000, 4096),
            descriptorSlice(0x200000, 2),
            2048,
            8,
            wordsAt(0x100400, 128),
            false,
        ),
    );
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        captured.extendAddressed(
            &session,
            .constraint_evaluation,
            wordsAt(0x100000, 4096),
            descriptorSlice(0x100100, 2),
            2048,
            8,
            wordsAt(0x102000, 128),
            false,
        ),
    );
}
