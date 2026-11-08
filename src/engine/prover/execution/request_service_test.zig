const std = @import("std");
const service_module = @import("request_service.zig");

const FakeClock = struct {
    var value: u64 = 0;

    pub fn now(_: *@This()) u64 {
        return value;
    }

    fn set(next: u64) void {
        value = next;
    }

    fn advance(amount: u64) void {
        value += amount;
    }
};

const FakeRuntime = struct {
    const max_shapes = 2;

    cached: [max_shapes]?service_module.ShapeKey =
        [_]?service_module.ShapeKey{null} ** max_shapes,
    next_cache: usize = 0,
    ready: bool = true,
    closed: bool = false,
    aborted: bool = false,
    executions: u64 = 0,
    lanes: u32 = 1,

    pub fn close(self: *@This()) !void {
        if (!self.ready or self.closed or self.aborted)
            return error.BadRuntimeState;
        self.closed = true;
        self.ready = false;
    }

    pub fn abort(self: *@This()) !void {
        if (self.closed or self.aborted) return error.BadRuntimeState;
        self.aborted = true;
        self.ready = false;
    }

    fn contains(self: *const @This(), key: service_module.ShapeKey) bool {
        for (self.cached) |entry| {
            if (entry) |candidate| {
                if (std.mem.eql(u8, &candidate, &key)) return true;
            }
        }
        return false;
    }

    fn retain(self: *@This(), key: service_module.ShapeKey) void {
        if (self.contains(key)) return;
        self.cached[self.next_cache] = key;
        self.next_cache = (self.next_cache + 1) % max_shapes;
    }
};

const Failure = enum {
    none,
    recoverable,
    fatal,
    clock_regression,
};

const TestRequest = struct {
    marker: u32,
    shape: service_module.ShapeKey,
    elapsed_ns: u64,
    failure: Failure = .none,
};

const TestProof = struct {
    marker: u32,
    runtime_index: u64,
};

const Workload = struct {
    pub const Request = TestRequest;
    pub const Proof = TestProof;

    var requests_destroyed: u64 = 0;
    var proofs_destroyed: u64 = 0;
    var block_execute = std.atomic.Value(bool).init(false);
    var execute_entered = std.atomic.Value(bool).init(false);
    var release_execute = std.atomic.Value(bool).init(false);

    pub fn execute(
        _: std.mem.Allocator,
        runtime: *FakeRuntime,
        request: *Request,
    ) !Proof {
        if (block_execute.load(.acquire)) {
            execute_entered.store(true, .release);
            while (!release_execute.load(.acquire))
                std.atomic.spinLoopHint();
        }
        FakeClock.advance(request.elapsed_ns);
        switch (request.failure) {
            .recoverable => return error.BadRequest,
            .fatal => {
                runtime.ready = false;
                return error.DeviceLost;
            },
            .clock_regression => FakeClock.set(0),
            .none => {},
        }
        runtime.executions += 1;
        runtime.retain(request.shape);
        return .{
            .marker = request.marker,
            .runtime_index = runtime.executions,
        };
    }

    pub fn deinitRequest(_: std.mem.Allocator, _: *Request) void {
        requests_destroyed += 1;
    }

    pub fn deinitProof(_: std.mem.Allocator, _: *Proof) void {
        proofs_destroyed += 1;
    }

    pub fn shapeCached(
        runtime: *FakeRuntime,
        key: service_module.ShapeKey,
    ) bool {
        return runtime.contains(key);
    }

    pub fn runtimeReady(runtime: *FakeRuntime) bool {
        return runtime.ready and !runtime.closed and !runtime.aborted;
    }

    pub fn executionLaneCount(runtime: *const FakeRuntime) u32 {
        return runtime.lanes;
    }

    pub fn failureDisposition(
        _: *FakeRuntime,
        cause: anyerror,
    ) service_module.FailureDisposition {
        return if (cause == error.BadRequest)
            .request_only
        else
            .poison_runtime;
    }
};

const Service = service_module.ServiceFor(
    FakeRuntime,
    Workload,
    FakeClock,
);

fn shape(byte: u8) service_module.ShapeKey {
    return [_]u8{byte} ** 32;
}

fn metadata(
    shape_key: service_module.ShapeKey,
    device_bytes: u64,
    input_bytes: u64,
) service_module.RequestMetadata {
    return .{
        .shape_key = shape_key,
        .predicted_device_bytes = device_bytes,
        .retained_input_bytes = input_bytes,
    };
}

fn resetCounters() void {
    Workload.requests_destroyed = 0;
    Workload.proofs_destroyed = 0;
    Workload.block_execute.store(false, .release);
    Workload.execute_entered.store(false, .release);
    Workload.release_execute.store(false, .release);
    FakeClock.set(0);
}

test "mixed-shape FIFO records cold, miss, and retained shape hit boundaries" {
    resetCounters();
    var service = try Service.init(
        std.testing.allocator,
        FakeRuntime{},
        FakeClock{},
        .{
            .max_pending = 4,
            .max_request_device_bytes = 1_000,
            .max_queued_input_bytes = 100,
        },
        19,
    );
    defer service.deinit();

    const a = shape(0xa1);
    const b = shape(0xb2);
    try std.testing.expectEqual(
        @as(service_module.Ticket, 1),
        (try service.submit(
            .{ .marker = 11, .shape = a, .elapsed_ns = 7 },
            metadata(a, 700, 10),
        )).accepted,
    );
    FakeClock.advance(2);
    try std.testing.expectEqual(
        @as(service_module.Ticket, 2),
        (try service.submit(
            .{ .marker = 22, .shape = b, .elapsed_ns = 11 },
            metadata(b, 800, 20),
        )).accepted,
    );
    FakeClock.advance(3);
    try std.testing.expectEqual(
        @as(service_module.Ticket, 3),
        (try service.submit(
            .{ .marker = 33, .shape = a, .elapsed_ns = 13 },
            metadata(a, 700, 30),
        )).accepted,
    );

    try std.testing.expectEqual(
        service_module.PumpOutcome{ .completed = 1 },
        try service.pumpOne(),
    );
    try std.testing.expectEqual(
        service_module.PumpOutcome{ .completed = 2 },
        try service.pumpOne(),
    );
    try std.testing.expectEqual(
        service_module.PumpOutcome{ .completed = 3 },
        try service.pumpOne(),
    );
    try std.testing.expectEqual(
        service_module.PumpOutcome.idle,
        try service.pumpOne(),
    );

    var first = (try service.publishNext()).proof;
    defer Workload.deinitProof(std.testing.allocator, &first.proof);
    var second = (try service.publishNext()).proof;
    defer Workload.deinitProof(std.testing.allocator, &second.proof);
    var third = (try service.publishNext()).proof;
    defer Workload.deinitProof(std.testing.allocator, &third.proof);
    try std.testing.expectEqual(@as(u32, 11), first.proof.marker);
    try std.testing.expectEqual(@as(u32, 22), second.proof.marker);
    try std.testing.expectEqual(@as(u32, 33), third.proof.marker);
    try std.testing.expect(first.receipt.service_cold);
    try std.testing.expectEqual(@as(u64, 19), first.receipt.runtime_init_ns);
    try std.testing.expect(!first.receipt.shape_cache_hit);
    try std.testing.expect(first.receipt.shape_retained_after);
    try std.testing.expect(!second.receipt.service_cold);
    try std.testing.expect(!second.receipt.shape_cache_hit);
    try std.testing.expect(third.receipt.shape_cache_hit);
    try std.testing.expectEqual(@as(u64, 7), first.receipt.service_ns);
    try std.testing.expectEqual(@as(u64, 11), second.receipt.service_ns);
    try std.testing.expectEqual(@as(u64, 13), third.receipt.service_ns);
    try std.testing.expect(
        second.receipt.queue_wait_ns > first.receipt.queue_wait_ns,
    );
    try std.testing.expect(
        third.receipt.queue_wait_ns > second.receipt.queue_wait_ns,
    );

    const snapshot = service.snapshot();
    try std.testing.expectEqual(@as(u64, 19), snapshot.runtime_init_ns);
    try std.testing.expectEqual(@as(u32, 1), snapshot.execution_lane_count);
    try std.testing.expectEqual(@as(usize, 3), snapshot.queue_high_water);
    try std.testing.expectEqual(@as(u64, 60), snapshot.queued_input_high_water);
    try std.testing.expectEqual(@as(u64, 2), snapshot.shape_misses);
    try std.testing.expectEqual(@as(u64, 1), snapshot.shape_hits);
    try std.testing.expectEqual(@as(u64, 3), snapshot.requests_completed);
    try std.testing.expectEqual(@as(u64, 3), snapshot.publications);
    try std.testing.expectEqual(@as(u64, 3), Workload.requests_destroyed);
    try service.close();
}

test "admission exposes queue, device, input, and busy boundaries" {
    resetCounters();
    var service = try Service.init(
        std.testing.allocator,
        FakeRuntime{},
        FakeClock{},
        .{
            .max_pending = 1,
            .max_request_device_bytes = 100,
            .max_queued_input_bytes = 20,
        },
        0,
    );
    defer service.deinit();
    const a = shape(1);
    try std.testing.expectEqual(
        service_module.Admission.request_device_capacity,
        try service.submit(
            .{ .marker = 1, .shape = a, .elapsed_ns = 1 },
            metadata(a, 101, 1),
        ),
    );
    try std.testing.expectEqual(
        service_module.Admission.queued_input_capacity,
        try service.submit(
            .{ .marker = 1, .shape = a, .elapsed_ns = 1 },
            metadata(a, 100, 21),
        ),
    );
    _ = try service.submit(
        .{ .marker = 1, .shape = a, .elapsed_ns = 1 },
        metadata(a, 100, 20),
    );
    try std.testing.expectEqual(
        service_module.Admission.queue_capacity,
        try service.submit(
            .{ .marker = 2, .shape = a, .elapsed_ns = 1 },
            metadata(a, 100, 1),
        ),
    );
    try std.testing.expectEqual(.canceled, try service.abortQueued(1));
    _ = try service.publishNext();

    try std.testing.expectEqual(@as(u64, 1), Workload.requests_destroyed);
    try service.close();
}

test "producer may enqueue behind one running proof without GPU overlap" {
    resetCounters();
    var service = try Service.init(
        std.testing.allocator,
        FakeRuntime{},
        FakeClock{},
        .{
            .max_pending = 3,
            .max_request_device_bytes = 100,
            .max_queued_input_bytes = 100,
        },
        0,
    );
    defer service.deinit();
    const a = shape(1);
    const b = shape(2);
    _ = try service.submit(
        .{ .marker = 1, .shape = a, .elapsed_ns = 3 },
        metadata(a, 10, 1),
    );
    Workload.block_execute.store(true, .release);
    var producer_admission: ?service_module.Admission = null;
    const producer = try std.Thread.spawn(.{}, struct {
        fn run(
            target: *Service,
            result: *?service_module.Admission,
            shape_key: service_module.ShapeKey,
        ) void {
            while (!Workload.execute_entered.load(.acquire))
                std.atomic.spinLoopHint();
            result.* = target.submit(
                .{ .marker = 2, .shape = shape_key, .elapsed_ns = 5 },
                metadata(shape_key, 10, 1),
            ) catch unreachable;
            Workload.release_execute.store(true, .release);
        }
    }.run, .{ &service, &producer_admission, b });
    try std.testing.expectEqual(
        service_module.PumpOutcome{ .completed = 1 },
        try service.pumpOne(),
    );
    producer.join();
    try std.testing.expectEqual(
        @as(service_module.Ticket, 2),
        producer_admission.?.accepted,
    );
    Workload.block_execute.store(false, .release);
    try std.testing.expectEqual(
        service_module.PumpOutcome{ .completed = 2 },
        try service.pumpOne(),
    );
    var first = (try service.publishNext()).proof;
    defer Workload.deinitProof(std.testing.allocator, &first.proof);
    var second = (try service.publishNext()).proof;
    defer Workload.deinitProof(std.testing.allocator, &second.proof);
    try std.testing.expectEqual(@as(u32, 1), first.proof.marker);
    try std.testing.expectEqual(@as(u32, 2), second.proof.marker);
    try std.testing.expectEqual(@as(u64, 2), service.runtime.executions);
    try service.close();
}

test "single-lane admission reports busy when running enqueue is disabled" {
    resetCounters();
    var service = try Service.init(
        std.testing.allocator,
        FakeRuntime{},
        FakeClock{},
        .{
            .max_pending = 2,
            .max_request_device_bytes = 100,
            .max_queued_input_bytes = 100,
            .enqueue_while_running = false,
        },
        0,
    );
    defer service.deinit();
    const a = shape(1);
    _ = try service.submit(
        .{ .marker = 1, .shape = a, .elapsed_ns = 3 },
        metadata(a, 10, 1),
    );
    Workload.block_execute.store(true, .release);
    var producer_admission: ?service_module.Admission = null;
    const producer = try std.Thread.spawn(.{}, struct {
        fn run(
            target: *Service,
            result: *?service_module.Admission,
            shape_key: service_module.ShapeKey,
        ) void {
            while (!Workload.execute_entered.load(.acquire))
                std.atomic.spinLoopHint();
            result.* = target.submit(
                .{ .marker = 2, .shape = shape_key, .elapsed_ns = 5 },
                metadata(shape_key, 10, 1),
            ) catch unreachable;
            Workload.release_execute.store(true, .release);
        }
    }.run, .{ &service, &producer_admission, shape(2) });
    _ = try service.pumpOne();
    producer.join();
    try std.testing.expectEqual(
        service_module.Admission.busy,
        producer_admission.?,
    );
    var proof = (try service.publishNext()).proof;
    defer Workload.deinitProof(std.testing.allocator, &proof.proof);
    try std.testing.expectEqual(@as(u64, 1), service.snapshot().busy_rejections);
    try service.close();
}

test "recoverable request failure preserves runtime and publication order" {
    resetCounters();
    var service = try Service.init(
        std.testing.allocator,
        FakeRuntime{},
        FakeClock{},
        .{
            .max_pending = 3,
            .max_request_device_bytes = 100,
            .max_queued_input_bytes = 100,
        },
        0,
    );
    defer service.deinit();
    const a = shape(1);
    _ = try service.submit(
        .{
            .marker = 1,
            .shape = a,
            .elapsed_ns = 3,
            .failure = .recoverable,
        },
        metadata(a, 10, 1),
    );
    _ = try service.submit(
        .{ .marker = 2, .shape = a, .elapsed_ns = 5 },
        metadata(a, 10, 1),
    );
    try std.testing.expectEqual(
        service_module.PumpOutcome{ .failed = 1 },
        try service.pumpOne(),
    );
    try std.testing.expectEqual(
        service_module.PumpOutcome{ .completed = 2 },
        try service.pumpOne(),
    );
    const failed = (try service.publishNext()).failure;
    try std.testing.expectEqual(error.BadRequest, failed.cause);
    var proof = (try service.publishNext()).proof;
    defer Workload.deinitProof(std.testing.allocator, &proof.proof);
    try std.testing.expectEqual(@as(u32, 2), proof.proof.marker);
    try std.testing.expectEqual(@as(u64, 0), service.snapshot().runtime_poisons);
    try service.close();
}

test "fatal failure poisons owner, cancels queue, and resets safely" {
    resetCounters();
    var service = try Service.init(
        std.testing.allocator,
        FakeRuntime{},
        FakeClock{},
        .{
            .max_pending = 3,
            .max_request_device_bytes = 100,
            .max_queued_input_bytes = 100,
        },
        4,
    );
    defer service.deinit();
    const a = shape(1);
    _ = try service.submit(
        .{
            .marker = 1,
            .shape = a,
            .elapsed_ns = 3,
            .failure = .fatal,
        },
        metadata(a, 10, 1),
    );
    _ = try service.submit(
        .{ .marker = 2, .shape = a, .elapsed_ns = 5 },
        metadata(a, 10, 1),
    );
    try std.testing.expectEqual(
        service_module.PumpOutcome{ .poisoned = 1 },
        try service.pumpOne(),
    );
    try std.testing.expectEqual(error.DeviceLost, service.runtimePoison().?);
    try std.testing.expectEqual(
        service_module.Admission.poisoned,
        try service.submit(
            .{ .marker = 3, .shape = a, .elapsed_ns = 1 },
            metadata(a, 10, 1),
        ),
    );
    const failed = (try service.publishNext()).failure;
    try std.testing.expect(failed.receipt.poisoned_runtime);
    try std.testing.expectEqual(error.DeviceLost, failed.cause);
    _ = (try service.publishNext()).canceled;
    try std.testing.expectEqual(@as(u64, 2), Workload.requests_destroyed);
    try std.testing.expectEqual(@as(u64, 1), service.snapshot().runtime_poisons);

    try service.reset(FakeRuntime{}, 9);
    _ = try service.submit(
        .{ .marker = 4, .shape = a, .elapsed_ns = 7 },
        metadata(a, 10, 1),
    );
    _ = try service.pumpOne();
    var proof = (try service.publishNext()).proof;
    defer Workload.deinitProof(std.testing.allocator, &proof.proof);
    try std.testing.expect(proof.receipt.service_cold);
    try std.testing.expectEqual(@as(u64, 2), proof.receipt.runtime_generation);
    try std.testing.expectEqual(@as(u64, 9), service.snapshot().runtime_init_ns);
    try std.testing.expectEqual(
        @as(u64, 13),
        service.snapshot().total_runtime_init_ns,
    );
    try service.close();
}

test "timing failure releases request and proof ownership before poison" {
    resetCounters();
    FakeClock.set(100);
    var service = try Service.init(
        std.testing.allocator,
        FakeRuntime{},
        FakeClock{},
        .{
            .max_pending = 1,
            .max_request_device_bytes = 100,
            .max_queued_input_bytes = 100,
        },
        4,
    );
    defer service.deinit();
    const a = shape(1);
    _ = try service.submit(
        .{
            .marker = 1,
            .shape = a,
            .elapsed_ns = 3,
            .failure = .clock_regression,
        },
        metadata(a, 10, 7),
    );
    try std.testing.expectEqual(
        service_module.PumpOutcome{ .poisoned = 1 },
        try service.pumpOne(),
    );
    const failure = (try service.publishNext()).failure;
    try std.testing.expectEqual(error.TimeWentBackwards, failure.cause);
    try std.testing.expectEqual(@as(u64, 1), Workload.requests_destroyed);
    try std.testing.expectEqual(@as(u64, 1), Workload.proofs_destroyed);
    try std.testing.expectEqual(
        @as(u64, 0),
        service.snapshot().queued_input_bytes,
    );
}

test "service rejects unmeasured physical execution lanes" {
    resetCounters();
    try std.testing.expectError(
        error.UnsupportedExecutionLaneCount,
        Service.init(
            std.testing.allocator,
            FakeRuntime{ .lanes = 2 },
            FakeClock{},
            .{
                .max_pending = 1,
                .max_request_device_bytes = 1,
                .max_queued_input_bytes = 1,
            },
            0,
        ),
    );
}
