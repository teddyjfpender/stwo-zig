//! Backend-neutral, bounded FIFO service for process-owned proof runtimes.
//!
//! The service deliberately executes one request at a time. A backend may add
//! physical lanes only after replacing this policy with measured scheduling
//! evidence. Requests may still queue while a proof is running, and every
//! result remains unpublished until all earlier tickets have been consumed.

const std = @import("std");
const types = @import("request_service_types.zig");

pub const ShapeKey = types.ShapeKey;
pub const Ticket = types.Ticket;
pub const Error = types.Error;
pub const Limits = types.Limits;
pub const RequestMetadata = types.RequestMetadata;
pub const Admission = types.Admission;
pub const FailureDisposition = types.FailureDisposition;
pub const Receipt = types.Receipt;
pub const Telemetry = types.Telemetry;
pub const PumpOutcome = types.PumpOutcome;
pub const AbortOutcome = types.AbortOutcome;
pub const SystemClock = types.SystemClock;

/// `Workload` is the only policy-bearing layer. It must declare:
///
/// - `Request` and `Proof` types;
/// - `execute(allocator, runtime, request) !Proof`;
/// - request/proof destructors;
/// - `shapeCached`, `runtimeReady`, and `executionLaneCount` observations;
/// - `failureDisposition`, based on the runtime state after worker cleanup.
///
/// `Clock.now` must be safe for concurrent admission. Only `submit` may run
/// away from the service owner thread; proof execution and every lifecycle or
/// publication operation remain owner-thread-only.
///
/// `Runtime.close` and `Runtime.abort` transfer runtime ownership out of the
/// service even when they return an error.
pub fn ServiceFor(
    comptime Runtime: type,
    comptime Workload: type,
    comptime Clock: type,
) type {
    assertWorkload(Runtime, Workload);
    const Request = Workload.Request;
    const Proof = Workload.Proof;

    const SlotState = enum {
        vacant,
        queued,
        running,
        completed,
        failed,
        canceled,
    };

    const Slot = struct {
        state: SlotState = .vacant,
        request: ?Request = null,
        proof: ?Proof = null,
        failure: ?anyerror = null,
        metadata: RequestMetadata = undefined,
        receipt: Receipt = undefined,
    };

    return struct {
        const Self = @This();

        pub const PublishedProof = struct {
            receipt: Receipt,
            proof: Proof,
        };
        pub const PublishedFailure = struct {
            receipt: Receipt,
            cause: anyerror,
        };
        pub const PublishedCancellation = struct {
            receipt: Receipt,
        };
        pub const Publication = union(enum) {
            proof: PublishedProof,
            failure: PublishedFailure,
            canceled: PublishedCancellation,
            pending,
            empty,
        };
        const ActiveRequest = struct {
            index: usize,
            ticket: Ticket,
        };
        const StartOutcome = union(enum) {
            active: ActiveRequest,
            outcome: PumpOutcome,
        };

        allocator: std.mem.Allocator,
        runtime: Runtime,
        clock: Clock,
        limits: Limits,
        slots: []Slot,
        queue_mutex: std.Thread.Mutex = .{},
        owner_thread_id: std.Thread.Id,
        head: usize = 0,
        tail: usize = 0,
        count: usize = 0,
        active_ticket: ?Ticket = null,
        next_ticket: Ticket = 1,
        state: enum { ready, poisoned, stopped } = .ready,
        runtime_owned: bool = true,
        generation_requests_started: u64 = 0,
        poison_cause: ?anyerror = null,
        poison_cleanup_error: ?anyerror = null,
        telemetry: Telemetry,

        pub fn init(
            allocator: std.mem.Allocator,
            runtime: Runtime,
            clock: Clock,
            limits: Limits,
            runtime_init_ns: u64,
        ) (std.mem.Allocator.Error || Error)!Self {
            var owned_runtime = runtime;
            errdefer owned_runtime.abort() catch {};
            try limits.validate();
            const lane_count = Workload.executionLaneCount(&owned_runtime);
            if (lane_count != 1)
                return error.UnsupportedExecutionLaneCount;
            const slots = try allocator.alloc(Slot, limits.max_pending);
            @memset(slots, .{});
            return .{
                .allocator = allocator,
                .runtime = owned_runtime,
                .clock = clock,
                .limits = limits,
                .slots = slots,
                .owner_thread_id = std.Thread.getCurrentId(),
                .telemetry = .{
                    .runtime_init_ns = runtime_init_ns,
                    .total_runtime_init_ns = runtime_init_ns,
                    .execution_lane_count = lane_count,
                },
            };
        }

        pub fn submit(
            self: *Self,
            request: Request,
            metadata: RequestMetadata,
        ) Error!Admission {
            self.queue_mutex.lock();
            defer self.queue_mutex.unlock();
            switch (self.state) {
                .poisoned => {
                    self.telemetry.poisoned_rejections += 1;
                    return .poisoned;
                },
                .stopped => {
                    self.telemetry.stopped_rejections += 1;
                    return .stopped;
                },
                .ready => {},
            }
            if (self.active_ticket != null and
                !self.limits.enqueue_while_running)
            {
                self.telemetry.busy_rejections += 1;
                return .busy;
            }
            if (self.count == self.slots.len) {
                self.telemetry.queue_capacity_rejections += 1;
                return .queue_capacity;
            }
            if (metadata.predicted_device_bytes >
                self.limits.max_request_device_bytes)
            {
                self.telemetry.request_device_capacity_rejections += 1;
                return .request_device_capacity;
            }
            const queued_bytes = std.math.add(
                u64,
                self.telemetry.queued_input_bytes,
                metadata.retained_input_bytes,
            ) catch {
                self.telemetry.queued_input_capacity_rejections += 1;
                return .queued_input_capacity;
            };
            if (queued_bytes > self.limits.max_queued_input_bytes) {
                self.telemetry.queued_input_capacity_rejections += 1;
                return .queued_input_capacity;
            }

            const ticket = self.next_ticket;
            self.next_ticket = std.math.add(Ticket, ticket, 1) catch
                return error.TicketOverflow;
            const admitted_ns = self.clock.now();
            const queue_depth = self.telemetry.queue_depth + 1;
            self.slots[self.tail] = .{
                .state = .queued,
                .request = request,
                .metadata = metadata,
                .receipt = .{
                    .ticket = ticket,
                    .runtime_generation = self.telemetry.runtime_generation,
                    .shape_key = metadata.shape_key,
                    .predicted_device_bytes = metadata.predicted_device_bytes,
                    .retained_input_bytes = metadata.retained_input_bytes,
                    .runtime_init_ns = self.telemetry.runtime_init_ns,
                    .queue_depth_at_admission = queue_depth,
                    .admitted_ns = admitted_ns,
                    .started_ns = 0,
                    .finished_ns = 0,
                    .queue_wait_ns = 0,
                    .service_ns = 0,
                    .service_cold = false,
                    .shape_cache_hit = false,
                    .shape_retained_after = false,
                    .poisoned_runtime = false,
                },
            };
            self.tail = (self.tail + 1) % self.slots.len;
            self.count += 1;
            self.telemetry.admissions += 1;
            self.telemetry.queue_depth = queue_depth;
            self.telemetry.queue_high_water = @max(
                self.telemetry.queue_high_water,
                queue_depth,
            );
            self.telemetry.queued_input_bytes = queued_bytes;
            self.telemetry.queued_input_high_water = @max(
                self.telemetry.queued_input_high_water,
                queued_bytes,
            );
            return .{ .accepted = ticket };
        }

        /// Executes the oldest queued request completely before returning.
        /// No second proof can overlap this call.
        pub fn pumpOne(self: *Self) Error!PumpOutcome {
            try self.requireOwner();
            const start = try self.startNext();
            const active = switch (start) {
                .active => |value| value,
                .outcome => |value| return value,
            };
            const request = &self.slots[active.index].request.?;
            const proof = Workload.execute(
                self.allocator,
                &self.runtime,
                request,
            ) catch |cause| return self.finishFailed(active, cause);
            return self.finishCompleted(active, proof);
        }

        fn startNext(self: *Self) Error!StartOutcome {
            self.queue_mutex.lock();
            switch (self.state) {
                .stopped => {
                    self.queue_mutex.unlock();
                    return .{ .outcome = .stopped };
                },
                .poisoned => {
                    self.queue_mutex.unlock();
                    return .{ .outcome = .unavailable_poisoned };
                },
                .ready => {},
            }
            if (self.active_ticket != null) {
                self.queue_mutex.unlock();
                return .{ .outcome = .busy };
            }
            const index = self.nextQueuedIndex() orelse {
                self.queue_mutex.unlock();
                return .{ .outcome = .idle };
            };
            var slot = &self.slots[index];
            const ticket = slot.receipt.ticket;
            const started_ns = self.clock.now();
            slot.receipt.started_ns = started_ns;
            slot.receipt.queue_wait_ns = elapsed(
                slot.receipt.admitted_ns,
                started_ns,
            ) catch |cause| {
                self.queue_mutex.unlock();
                return cause;
            };
            slot.receipt.service_cold =
                self.generation_requests_started == 0;
            slot.receipt.shape_cache_hit = Workload.shapeCached(
                &self.runtime,
                slot.metadata.shape_key,
            );
            if (slot.receipt.shape_cache_hit)
                self.telemetry.shape_hits += 1
            else
                self.telemetry.shape_misses += 1;
            slot.state = .running;
            self.active_ticket = ticket;
            self.telemetry.queue_depth -= 1;
            self.telemetry.requests_started += 1;
            self.generation_requests_started += 1;
            self.queue_mutex.unlock();
            return .{ .active = .{ .index = index, .ticket = ticket } };
        }

        fn finishFailed(
            self: *Self,
            active: ActiveRequest,
            cause: anyerror,
        ) PumpOutcome {
            self.queue_mutex.lock();
            defer self.queue_mutex.unlock();
            var slot = &self.slots[active.index];
            const request = &slot.request.?;
            const finished_ns = self.clock.now();
            self.finishRequestAccounting(slot, finished_ns) catch |err| {
                self.releaseInputAfterAccountingFailure(slot);
                Workload.deinitRequest(self.allocator, request);
                slot.request = null;
                self.active_ticket = null;
                self.telemetry.requests_failed += 1;
                slot.failure = err;
                slot.state = .failed;
                self.poisonSlotAndRuntime(slot, err, finished_ns);
                return .{ .poisoned = active.ticket };
            };
            Workload.deinitRequest(self.allocator, request);
            slot.request = null;
            self.active_ticket = null;
            self.telemetry.requests_failed += 1;
            slot.failure = cause;
            slot.state = .failed;
            const disposition = Workload.failureDisposition(
                &self.runtime,
                cause,
            );
            if (disposition == .request_only and
                Workload.runtimeReady(&self.runtime))
            {
                return .{ .failed = active.ticket };
            }
            self.poisonSlotAndRuntime(slot, cause, finished_ns);
            return .{ .poisoned = active.ticket };
        }

        fn finishCompleted(
            self: *Self,
            active: ActiveRequest,
            proof: Proof,
        ) PumpOutcome {
            self.queue_mutex.lock();
            defer self.queue_mutex.unlock();
            var slot = &self.slots[active.index];
            const request = &slot.request.?;
            const finished_ns = self.clock.now();
            self.finishRequestAccounting(slot, finished_ns) catch |cause| {
                self.releaseInputAfterAccountingFailure(slot);
                var owned_proof = proof;
                Workload.deinitProof(self.allocator, &owned_proof);
                Workload.deinitRequest(self.allocator, request);
                slot.request = null;
                self.active_ticket = null;
                self.telemetry.requests_failed += 1;
                slot.failure = cause;
                slot.state = .failed;
                self.poisonSlotAndRuntime(slot, cause, finished_ns);
                return .{ .poisoned = active.ticket };
            };
            Workload.deinitRequest(self.allocator, request);
            slot.request = null;
            self.active_ticket = null;
            if (!Workload.runtimeReady(&self.runtime)) {
                var owned_proof = proof;
                Workload.deinitProof(self.allocator, &owned_proof);
                self.telemetry.requests_failed += 1;
                slot.failure = error.RuntimeNotReady;
                slot.state = .failed;
                self.poisonSlotAndRuntime(
                    slot,
                    error.RuntimeNotReady,
                    finished_ns,
                );
                return .{ .poisoned = active.ticket };
            }
            slot.receipt.shape_retained_after = Workload.shapeCached(
                &self.runtime,
                slot.metadata.shape_key,
            );
            slot.proof = proof;
            slot.state = .completed;
            self.telemetry.requests_completed += 1;
            return .{ .completed = active.ticket };
        }

        /// Moves only the oldest completed ticket out of the service.
        pub fn publishNext(self: *Self) Error!Publication {
            try self.requireOwner();
            self.queue_mutex.lock();
            defer self.queue_mutex.unlock();
            if (self.count == 0) return .empty;
            var slot = &self.slots[self.head];
            const publication: Publication = switch (slot.state) {
                .completed => .{ .proof = .{
                    .receipt = slot.receipt,
                    .proof = slot.proof.?,
                } },
                .failed => .{ .failure = .{
                    .receipt = slot.receipt,
                    .cause = slot.failure.?,
                } },
                .canceled => .{ .canceled = .{
                    .receipt = slot.receipt,
                } },
                .queued, .running => return .pending,
                .vacant => return error.InvalidState,
            };
            slot.proof = null;
            slot.failure = null;
            slot.* = .{};
            self.head = (self.head + 1) % self.slots.len;
            self.count -= 1;
            self.telemetry.publications += 1;
            return publication;
        }

        /// Cancels a request that has not started. Its ticket remains in FIFO
        /// order and publishes as `canceled`.
        pub fn abortQueued(
            self: *Self,
            ticket: Ticket,
        ) Error!AbortOutcome {
            try self.requireOwner();
            self.queue_mutex.lock();
            defer self.queue_mutex.unlock();
            if (self.state == .stopped) return .stopped;
            for (self.slots) |*slot| {
                if (slot.state == .vacant or
                    slot.receipt.ticket != ticket)
                {
                    continue;
                }
                return switch (slot.state) {
                    .queued => result: {
                        try self.cancelSlot(slot, self.clock.now());
                        break :result .canceled;
                    },
                    .running => .busy,
                    .completed, .failed, .canceled => .too_late,
                    .vacant => unreachable,
                };
            }
            return .unknown;
        }

        /// Graceful shutdown requires every accepted ticket to be published.
        pub fn close(self: *Self) anyerror!void {
            try self.requireOwner();
            self.queue_mutex.lock();
            defer self.queue_mutex.unlock();
            if (self.state != .ready or
                self.active_ticket != null or
                self.count != 0)
            {
                return error.InvalidState;
            }
            self.runtime.close() catch |cause| {
                self.abortRuntime(cause);
                return cause;
            };
            self.runtime_owned = false;
            self.state = .stopped;
        }

        /// Destructive shutdown releases all queued requests and unpublished
        /// proofs, then relinquishes process-runtime ownership.
        pub fn abortAll(self: *Self) anyerror!void {
            try self.requireOwner();
            self.queue_mutex.lock();
            defer self.queue_mutex.unlock();
            if (self.active_ticket != null) return error.ServiceBusy;
            self.destroySlots();
            if (self.runtime_owned) {
                const result = self.runtime.abort();
                self.runtime_owned = false;
                self.state = .stopped;
                return result;
            }
            self.state = .stopped;
        }

        /// Installs a newly opened runtime only after the poisoned generation's
        /// ordered failure/cancellation publications have been consumed.
        pub fn reset(
            self: *Self,
            runtime: Runtime,
            runtime_init_ns: u64,
        ) Error!void {
            try self.requireOwner();
            self.queue_mutex.lock();
            defer self.queue_mutex.unlock();
            if (self.state != .poisoned or
                self.runtime_owned or
                self.active_ticket != null or
                self.count != 0)
            {
                return error.InvalidState;
            }
            var owned_runtime = runtime;
            const lanes = Workload.executionLaneCount(&owned_runtime);
            if (lanes != 1) {
                owned_runtime.abort() catch {};
                return error.UnsupportedExecutionLaneCount;
            }
            const next_generation = std.math.add(
                u64,
                self.telemetry.runtime_generation,
                1,
            ) catch {
                owned_runtime.abort() catch {};
                return error.CounterOverflow;
            };
            const total_runtime_init_ns = addTime(
                self.telemetry.total_runtime_init_ns,
                runtime_init_ns,
            ) catch {
                owned_runtime.abort() catch {};
                return error.CounterOverflow;
            };
            self.runtime = owned_runtime;
            self.runtime_owned = true;
            self.state = .ready;
            self.poison_cause = null;
            self.poison_cleanup_error = null;
            self.generation_requests_started = 0;
            self.telemetry.runtime_generation = next_generation;
            self.telemetry.total_runtime_init_ns = total_runtime_init_ns;
            self.telemetry.runtime_init_ns = runtime_init_ns;
            self.telemetry.execution_lane_count = lanes;
        }

        pub fn snapshot(self: *Self) Telemetry {
            self.queue_mutex.lock();
            defer self.queue_mutex.unlock();
            return self.telemetry;
        }

        pub fn runtimePoison(self: *Self) ?anyerror {
            self.queue_mutex.lock();
            defer self.queue_mutex.unlock();
            return self.poison_cause;
        }

        pub fn runtimePoisonCleanupError(self: *Self) ?anyerror {
            self.queue_mutex.lock();
            defer self.queue_mutex.unlock();
            return self.poison_cleanup_error;
        }

        pub fn deinit(self: *Self) void {
            std.debug.assert(
                self.owner_thread_id == std.Thread.getCurrentId(),
            );
            if (self.runtime_owned) {
                self.runtime.abort() catch {};
                self.runtime_owned = false;
            }
            self.destroySlots();
            self.allocator.free(self.slots);
            self.* = undefined;
        }

        fn finishRequestAccounting(
            self: *Self,
            slot: *Slot,
            finished_ns: u64,
        ) Error!void {
            const service_ns = try elapsed(
                slot.receipt.started_ns,
                finished_ns,
            );
            const total_queue_wait_ns = try addTime(
                self.telemetry.total_queue_wait_ns,
                slot.receipt.queue_wait_ns,
            );
            const total_service_ns = try addTime(
                self.telemetry.total_service_ns,
                service_ns,
            );
            const cold_service_ns = if (slot.receipt.service_cold)
                try addTime(
                    self.telemetry.cold_service_ns,
                    service_ns,
                )
            else
                self.telemetry.cold_service_ns;
            if (slot.metadata.retained_input_bytes >
                self.telemetry.queued_input_bytes)
            {
                return error.InvalidState;
            }
            slot.receipt.finished_ns = finished_ns;
            slot.receipt.service_ns = service_ns;
            self.telemetry.total_queue_wait_ns = total_queue_wait_ns;
            self.telemetry.total_service_ns = total_service_ns;
            self.telemetry.cold_service_ns = cold_service_ns;
            self.telemetry.queued_input_bytes -=
                slot.metadata.retained_input_bytes;
        }

        fn poisonSlotAndRuntime(
            self: *Self,
            slot: *Slot,
            cause: anyerror,
            now_ns: u64,
        ) void {
            slot.receipt.poisoned_runtime = true;
            self.abortRuntime(cause);
            self.cancelQueuedAfterPoison(now_ns);
        }

        fn releaseInputAfterAccountingFailure(
            self: *Self,
            slot: *const Slot,
        ) void {
            const retained = slot.metadata.retained_input_bytes;
            if (retained <= self.telemetry.queued_input_bytes)
                self.telemetry.queued_input_bytes -= retained
            else
                self.telemetry.queued_input_bytes = 0;
        }

        fn abortRuntime(self: *Self, cause: anyerror) void {
            if (self.state == .poisoned) return;
            self.poison_cause = cause;
            self.telemetry.runtime_poisons += 1;
            self.state = .poisoned;
            if (self.runtime_owned) {
                self.runtime.abort() catch |cleanup_error| {
                    self.poison_cleanup_error = cleanup_error;
                };
                self.runtime_owned = false;
            }
        }

        fn cancelQueuedAfterPoison(self: *Self, now_ns: u64) void {
            for (self.slots) |*slot| {
                if (slot.state == .queued) {
                    self.cancelSlot(slot, now_ns) catch |cause| {
                        if (self.poison_cleanup_error == null)
                            self.poison_cleanup_error = cause;
                    };
                }
            }
        }

        fn cancelSlot(
            self: *Self,
            slot: *Slot,
            now_ns: u64,
        ) Error!void {
            const queue_wait_ns = elapsed(
                slot.receipt.admitted_ns,
                now_ns,
            ) catch |cause| {
                self.cancelSlotWithWait(slot, now_ns, 0);
                return cause;
            };
            self.cancelSlotWithWait(slot, now_ns, queue_wait_ns);
        }

        fn cancelSlotWithWait(
            self: *Self,
            slot: *Slot,
            now_ns: u64,
            queue_wait_ns: u64,
        ) void {
            Workload.deinitRequest(self.allocator, &slot.request.?);
            slot.request = null;
            slot.state = .canceled;
            slot.failure = error.ServicePoisoned;
            slot.receipt.started_ns = now_ns;
            slot.receipt.finished_ns = now_ns;
            slot.receipt.queue_wait_ns = queue_wait_ns;
            slot.receipt.service_ns = 0;
            std.debug.assert(
                slot.metadata.retained_input_bytes <=
                    self.telemetry.queued_input_bytes,
            );
            self.telemetry.queued_input_bytes -=
                slot.metadata.retained_input_bytes;
            self.telemetry.queue_depth -= 1;
            self.telemetry.requests_canceled += 1;
        }

        fn nextQueuedIndex(self: *const Self) ?usize {
            var offset: usize = 0;
            while (offset < self.count) : (offset += 1) {
                const index = (self.head + offset) % self.slots.len;
                if (self.slots[index].state == .queued) return index;
            }
            return null;
        }

        fn destroySlots(self: *Self) void {
            for (self.slots) |*slot| {
                if (slot.request) |*request|
                    Workload.deinitRequest(self.allocator, request);
                if (slot.proof) |*proof|
                    Workload.deinitProof(self.allocator, proof);
                slot.* = .{};
            }
            self.head = 0;
            self.tail = 0;
            self.count = 0;
            self.active_ticket = null;
            self.telemetry.queue_depth = 0;
            self.telemetry.queued_input_bytes = 0;
        }

        fn requireOwner(self: *const Self) Error!void {
            if (self.owner_thread_id != std.Thread.getCurrentId())
                return error.ThreadOwnershipViolation;
        }
    };
}

fn elapsed(start: u64, end: u64) Error!u64 {
    if (end < start) return error.TimeWentBackwards;
    return end - start;
}

fn addTime(left: u64, right: u64) Error!u64 {
    return std.math.add(u64, left, right) catch error.CounterOverflow;
}

fn assertWorkload(comptime Runtime: type, comptime Workload: type) void {
    inline for (&.{
        "Request",
        "Proof",
        "execute",
        "deinitRequest",
        "deinitProof",
        "shapeCached",
        "runtimeReady",
        "executionLaneCount",
        "failureDisposition",
    }) |name| {
        if (!@hasDecl(Workload, name))
            @compileError("proof service workload is missing " ++ name);
    }
    inline for (&.{ "close", "abort" }) |name| {
        if (!@hasDecl(Runtime, name))
            @compileError("proof service runtime is missing " ++ name);
    }
}
