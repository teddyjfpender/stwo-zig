//! ownership contract cases for context.
//! Proof-owned CUDA stream, pool, opaque buffers, and transfer accounting.

const std = @import("std");
const telemetry = @import("telemetry.zig");

const Owner = @import("context.zig");
const ContextFor = Owner.ContextFor;

test "context owns buffers and accounts only explicit transfers" {
    const Fake = struct {
        var handle_word: u8 = 0;
        var stream_word: u8 = 0;
        var device_words: [16]u32 = [_]u32{0} ** 16;
        var sync_calls: usize = 0;

        pub fn stwo_exec_context_create(out: *?*anyopaque) c_int {
            out.* = &handle_word;
            return 0;
        }
        pub fn stwo_exec_context_destroy(_: *anyopaque) c_int {
            return 0;
        }
        pub fn stwo_exec_context_stream(_: *anyopaque, out: *?*anyopaque) c_int {
            out.* = &stream_word;
            return 0;
        }
        pub fn stwo_exec_context_device(_: *anyopaque, out: *c_int) c_int {
            out.* = 0;
            return 0;
        }
        pub fn stwo_exec_context_lane_count(_: *anyopaque, out: *u32) c_int {
            // Legacy create() uses the one-lane default in ContextOptions.
            out.* = 1;
            return 0;
        }
        pub fn stwo_exec_context_alloc_u32(_: *anyopaque, _: usize, out: *?[*]u32) c_int {
            out.* = &device_words;
            return 0;
        }
        pub fn stwo_exec_context_free_u32(_: *anyopaque, _: [*]u32) c_int {
            return 0;
        }
        pub fn stwo_exec_context_memcpy_h2d_async(
            _: *anyopaque,
            _: *anyopaque,
            _: *const anyopaque,
            _: usize,
        ) c_int {
            return 0;
        }
        pub fn stwo_exec_context_memcpy_d2d_async(
            _: *anyopaque,
            _: *anyopaque,
            _: *const anyopaque,
            _: usize,
        ) c_int {
            return 0;
        }
        pub fn stwo_exec_context_memcpy_d2h_async(
            _: *anyopaque,
            _: *anyopaque,
            _: *const anyopaque,
            _: usize,
        ) c_int {
            return 0;
        }
        pub fn stwo_exec_context_fill_u32_async(
            _: *anyopaque,
            _: [*]u32,
            _: u32,
            _: usize,
        ) c_int {
            return 0;
        }
        pub fn stwo_exec_context_join_all_lanes(_: *anyopaque) c_int {
            return 0;
        }
        pub fn stwo_exec_context_sync(_: *anyopaque) c_int {
            sync_calls += 1;
            return 0;
        }
        pub fn stwo_exec_context_pool_current(
            _: *anyopaque,
            used: *usize,
            reserved: *usize,
        ) c_int {
            used.* = 0;
            reserved.* = 4096;
            return 0;
        }
    };

    const Context = ContextFor(Fake);
    var context = try Context.open();
    try context.beginStage(.ingress);
    var buffer = try context.allocate(16);
    try context.upload(buffer, &.{ 1, 2, 3, 4 });
    try context.fill(buffer, 7);
    const owned_slice = .{
        .address = @intFromPtr(buffer.pointer),
        .len = buffer.words,
        .owner = buffer.owner,
        .generation = buffer.generation,
    };
    try std.testing.expectEqual(
        @intFromPtr(buffer.pointer),
        @intFromPtr(try context.deviceSlicePointer(u32, owned_slice, 16)),
    );
    try context.uploadSlice(u32, owned_slice, &.{ 5, 6, 7, 8 });
    const source_slice = .{
        .address = owned_slice.address,
        .len = 4,
        .owner = owned_slice.owner,
        .generation = owned_slice.generation,
    };
    const destination_slice = .{
        .address = owned_slice.address + 8 * @sizeOf(u32),
        .len = 4,
        .owner = owned_slice.owner,
        .generation = owned_slice.generation,
    };
    try context.copyDeviceSlice(u32, destination_slice, source_slice);
    const overlapping_slice = .{
        .address = owned_slice.address + 2 * @sizeOf(u32),
        .len = 4,
        .owner = owned_slice.owner,
        .generation = owned_slice.generation,
    };
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        context.copyDeviceSlice(u32, overlapping_slice, source_slice),
    );
    var oversized_slice = owned_slice;
    oversized_slice.len = 17;
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        context.deviceSlicePointer(u32, oversized_slice, 17),
    );
    var foreign_slice = owned_slice;
    foreign_slice.owner += 1;
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        context.deviceSlicePointer(u32, foreign_slice, 1),
    );
    try context.endStage(.ingress);
    try context.beginStage(.trace_generation);
    try context.recordKernels(1);
    try context.endStage(.trace_generation);
    try context.beginStage(.trace_commit);
    try context.recordKernels(3);
    try context.endStage(.trace_commit);
    try std.testing.expectError(
        error.StageOrderViolation,
        context.beginStage(.proof_assembly),
    );
    inline for (.{
        telemetry.Stage.constraint_evaluation,
        telemetry.Stage.oods,
        telemetry.Stage.quotient,
        telemetry.Stage.fri_commit,
        telemetry.Stage.pow,
        telemetry.Stage.decommit,
    }) |stage| {
        try context.beginStage(stage);
        try context.recordKernels(1);
        try context.endStage(stage);
    }
    try context.beginStage(.proof_assembly);
    var proof_words: [4]u32 = undefined;
    var proof_slice = owned_slice;
    proof_slice.len = proof_words.len;
    try context.readProofSlice(u32, &proof_words, proof_slice);
    try context.free(&buffer);
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        context.deviceSlicePointer(u32, owned_slice, 1),
    );
    try context.endStage(.proof_assembly);
    try context.close();
    try std.testing.expectEqual(@as(u64, 64), context.counters.peak_live_bytes);
    try std.testing.expectEqual(@as(u64, 32), context.counters.h2d_bytes);
    try std.testing.expectEqual(@as(u64, 16), context.counters.d2d_bytes);
    try std.testing.expectEqual(@as(u64, 16), context.counters.d2h_proof_bytes);
    try std.testing.expectEqual(@as(u64, 1), context.counters.d2h_proof_operations);
    try std.testing.expectEqual(@as(usize, 1), Fake.sync_calls);
    try std.testing.expectEqual(@as(u64, 1), context.counters.sync_calls);
    try std.testing.expect(context.counters.isResident());
    try std.testing.expect(context.counters.stagesCompleteExactlyOnce());
}
