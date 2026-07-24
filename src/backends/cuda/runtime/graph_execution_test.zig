const std = @import("std");
const arena_module = @import("arena.zig");
const context_module = @import("context.zig");
const cache_module = @import("execution_cache.zig");
const telemetry = @import("telemetry.zig");

test "graph cache is plan keyed, fixed address, replayed, and fail closed" {
    const Fake = struct {
        var storage: [256]u32 = [_]u32{0} ** 256;
        var graph_word: u8 = 0;
        var allocations: usize = 0;
        var frees: usize = 0;
        var captures: usize = 0;
        var capture_aborts: usize = 0;
        var launches: usize = 0;
        var destroys: usize = 0;
        var kernel_nodes: u64 = 2;
        var fail_launch = false;
        var destroy_before_free = false;

        pub fn stwo_exec_context_alloc_u32(
            _: *anyopaque,
            words: usize,
            out: *?[*]u32,
        ) c_int {
            if (words > storage.len) return 1;
            allocations += 1;
            out.* = &storage;
            return 0;
        }

        pub fn stwo_exec_context_free_u32(
            _: *anyopaque,
            _: [*]u32,
        ) c_int {
            frees += 1;
            destroy_before_free = destroys != 0;
            return 0;
        }

        pub fn stwo_exec_context_sync(_: *anyopaque) c_int {
            return 0;
        }

        pub fn stwo_exec_context_memory_info(
            _: *anyopaque,
            available: *usize,
            total: *usize,
        ) c_int {
            available.* = 1024 * 1024 * 1024;
            total.* = 2 * 1024 * 1024 * 1024;
            return 0;
        }

        pub fn stwo_graph_capture_begin(_: *anyopaque) c_int {
            captures += 1;
            return 0;
        }

        pub fn stwo_graph_capture_end(
            _: *anyopaque,
            out: *?*anyopaque,
            out_kernel_nodes: *u64,
        ) c_int {
            out.* = &graph_word;
            out_kernel_nodes.* = kernel_nodes;
            return 0;
        }

        pub fn stwo_graph_capture_abort(_: *anyopaque) c_int {
            capture_aborts += 1;
            return 0;
        }

        pub fn stwo_graph_launch(
            _: *anyopaque,
            _: *anyopaque,
        ) c_int {
            if (fail_launch) {
                fail_launch = false;
                return 1;
            }
            launches += 1;
            return 0;
        }

        pub fn stwo_graph_destroy(_: *anyopaque) c_int {
            destroys += 1;
            return 0;
        }
    };

    const Context = context_module.ContextFor(Fake);
    const Cache = cache_module.CacheFor(Fake, Context);
    var handle_word: u8 = 0;
    var stream_word: u8 = 0;
    var context = Context{
        .handle = &handle_word,
        .stream = &stream_word,
        .device = 0,
        .lane_count = 1,
    };
    var cache = Cache{};
    const allocator = std.testing.allocator;
    const requirements = [_]arena_module.Requirement{.{
        .id = 1,
        .words = 64,
        .live_from = .ingress,
        .live_through = .proof_assembly,
    }};
    const key_a = [_]u8{0xa1} ** 32;
    const key_b = [_]u8{0xb2} ** 32;

    var first_plan = try arena_module.Plan.init(allocator, &requirements);
    try cache.prepare(&context, allocator, key_a, first_plan);
    first_plan = undefined;
    try std.testing.expectEqual(@as(usize, 1), Fake.allocations);
    try std.testing.expectEqual(@as(usize, 1), context.persistent_buffers);

    try context.beginProof();
    try context.beginStage(.ingress);
    try context.endStage(.ingress);
    try context.beginStage(.trace_generation);
    try cache.beginCapture(&context, key_a, .trace_generation);
    try context.recordKernels(2);
    try cache.finishCaptureAndLaunch(
        &context,
        key_a,
        .trace_generation,
    );
    try context.endStage(.trace_generation);
    try std.testing.expectEqual(@as(u64, 1), cache.misses);
    try std.testing.expectEqual(@as(u64, 1), context.counters.graph_launches);
    try std.testing.expectEqual(@as(u64, 1), context.counters.graph_cache_misses);
    try context.abortProof();

    var same_plan = try arena_module.Plan.init(allocator, &requirements);
    try cache.prepare(&context, allocator, key_a, same_plan);
    same_plan = undefined;
    try std.testing.expectEqual(@as(usize, 1), Fake.allocations);
    try std.testing.expectEqual(@as(usize, 0), Fake.destroys);

    try context.beginProof();
    try context.beginStage(.ingress);
    try context.endStage(.ingress);
    try context.beginStage(.trace_generation);
    try cache.launch(&context, key_a, .trace_generation);
    try context.endStage(.trace_generation);
    try std.testing.expectEqual(@as(u64, 1), cache.hits);
    try std.testing.expectEqual(@as(u64, 2), context.counters.kernel_launches);
    try std.testing.expectEqual(@as(u64, 1), context.counters.graph_cache_hits);
    try context.abortProof();

    var replacement = try arena_module.Plan.init(allocator, &requirements);
    try cache.prepare(&context, allocator, key_b, replacement);
    replacement = undefined;
    try std.testing.expect(Fake.destroy_before_free);
    try std.testing.expectEqual(@as(usize, 2), Fake.allocations);
    try std.testing.expectEqual(@as(usize, 1), Fake.frees);

    Fake.kernel_nodes = 1;
    try context.beginProof();
    try context.beginStage(.ingress);
    try context.endStage(.ingress);
    try context.beginStage(.trace_generation);
    try cache.beginCapture(&context, key_b, .trace_generation);
    try context.recordKernels(2);
    try std.testing.expectError(
        error.InvalidState,
        cache.finishCaptureAndLaunch(
            &context,
            key_b,
            .trace_generation,
        ),
    );
    try std.testing.expect(!(try cache.hasGraph(
        key_b,
        .trace_generation,
    )));
    try context.abortProof();

    Fake.kernel_nodes = 2;
    Fake.fail_launch = true;
    try context.beginProof();
    try context.beginStage(.ingress);
    try context.endStage(.ingress);
    try context.beginStage(.trace_generation);
    try cache.beginCapture(&context, key_b, .trace_generation);
    try context.recordKernels(2);
    try std.testing.expectError(
        error.CudaFailure,
        cache.finishCaptureAndLaunch(
            &context,
            key_b,
            .trace_generation,
        ),
    );
    try std.testing.expect(!(try cache.hasGraph(
        key_b,
        .trace_generation,
    )));
    try context.abortProof();

    try context.beginProof();
    try context.beginStage(.ingress);
    try context.endStage(.ingress);
    try context.beginStage(.trace_generation);
    try cache.beginCapture(&context, key_b, .trace_generation);
    try cache.abortCapture(&context);
    try std.testing.expect(!context.capture_active);
    try std.testing.expectEqual(@as(usize, 1), Fake.capture_aborts);
    try context.abortProof();
    try cache.deinit(&context);
    try std.testing.expectEqual(@as(usize, 2), Fake.frees);
    try std.testing.expectEqual(@as(usize, 3), Fake.destroys);
}
