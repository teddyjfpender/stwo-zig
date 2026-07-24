//! Validated description and receipt for one strict-AOT CUDA launch.

const std = @import("std");
const schema = @import("../abi/schema.zig");
const types = @import("../abi/types.zig");
const runtime_error = @import("error.zig");
const telemetry = @import("telemetry.zig");

pub const receipt_abi_version: u32 = 1;

pub const Kernel = struct {
    stage: telemetry.Stage,
    abi_schema: schema.KernelSchema,
    cache_key: u64,
    name: [:0]const u8,
    grid: [3]u32,
    block: [3]u32,
    dynamic_shared_bytes: u32 = 0,
    argument_count: u32,

    pub fn validate(self: Kernel) runtime_error.Error!void {
        if (self.cache_key == 0 or self.name.len == 0 or self.argument_count == 0)
            return error.InvalidKernelDescriptor;
        for (self.grid) |extent| {
            if (extent == 0) return error.InvalidKernelDescriptor;
        }
        for (self.block) |extent| {
            if (extent == 0) return error.InvalidKernelDescriptor;
        }
        _ = std.math.mul(
            u64,
            std.math.mul(u64, self.block[0], self.block[1]) catch
                return error.InvalidKernelDescriptor,
            self.block[2],
        ) catch return error.InvalidKernelDescriptor;
    }

    pub fn validateReceipt(
        self: Kernel,
        receipt: types.NativeAotFunctionReceipt,
        device: types.DeviceSnapshot,
        stream: *anyopaque,
    ) runtime_error.Error!void {
        try self.validate();
        if (receipt.abi_version != receipt_abi_version or
            receipt.abi_schema != @intFromEnum(self.abi_schema) or
            receipt.device_ordinal != device.current or
            receipt.sm_major != device.sm_major or
            receipt.sm_minor != device.sm_minor or
            receipt.argument_count != self.argument_count or
            !std.mem.eql(u32, &receipt.grid, &self.grid) or
            !std.mem.eql(u32, &receipt.block, &self.block) or
            receipt.dynamic_shared_bytes != self.dynamic_shared_bytes or
            receipt.cache_key != self.cache_key or
            receipt.context_token == 0 or
            receipt.module_token == 0 or
            receipt.function_token == 0 or
            receipt.stream_token != @intFromPtr(stream))
        {
            return error.AotReceiptMismatch;
        }
    }
};

test "kernel receipt binds launch to the admitted device and stream" {
    var stream_word: u8 = 0;
    const kernel = Kernel{
        .stage = .quotient,
        .abi_schema = .ordinary_constraint_v1,
        .cache_key = 0x1234,
        .name = "quotient_kernel",
        .grid = .{ 32, 1, 1 },
        .block = .{ 256, 1, 1 },
        .argument_count = 3,
    };
    const device = types.DeviceSnapshot{
        .count = 1,
        .current = 0,
        .sm_major = 9,
        .sm_minor = 0,
    };
    const receipt = types.NativeAotFunctionReceipt{
        .abi_version = receipt_abi_version,
        .abi_schema = @intFromEnum(schema.KernelSchema.ordinary_constraint_v1),
        .device_ordinal = 0,
        .sm_major = 9,
        .sm_minor = 0,
        .argument_count = 3,
        .grid = .{ 32, 1, 1 },
        .block = .{ 256, 1, 1 },
        .registers_per_thread = 48,
        .max_threads_per_block = 1024,
        .binary_version = 90,
        .cache_key = 0x1234,
        .context_token = 1,
        .module_token = 2,
        .function_token = 3,
        .stream_token = @intFromPtr(&stream_word),
    };
    try kernel.validateReceipt(receipt, device, &stream_word);

    var wrong = receipt;
    wrong.stream_token += 1;
    try std.testing.expectError(
        error.AotReceiptMismatch,
        kernel.validateReceipt(wrong, device, &stream_word),
    );
    wrong = receipt;
    wrong.abi_schema = @intFromEnum(schema.KernelSchema.composition_wave_v2);
    try std.testing.expectError(
        error.AotReceiptMismatch,
        kernel.validateReceipt(wrong, device, &stream_word),
    );
}

test "empty and degenerate kernel descriptions are rejected" {
    const invalid = Kernel{
        .stage = .fri_commit,
        .abi_schema = .ordinary_constraint_v1,
        .cache_key = 0,
        .name = "",
        .grid = .{ 0, 1, 1 },
        .block = .{ 256, 1, 1 },
        .argument_count = 0,
    };
    try std.testing.expectError(error.InvalidKernelDescriptor, invalid.validate());
}
