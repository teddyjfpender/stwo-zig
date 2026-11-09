//! Same-process native verification on a side thread, overlapped with
//! recursion and joined before any acceptance artifact is published.
//!
//! Scheduling only: the verifier, its inputs (image, keys, bundle, FIXED
//! authority) and its accept/reject decision are unchanged. All inputs are
//! read-only for the whole request (`*const` everywhere; recursion lanes
//! already read the same setups and bundle concurrently). The combined
//! request publishes `report.json` and `combined-report.json` only after a
//! successful join, so acceptance still implies a complete native verify.
//! Recursive proof files written meanwhile are not acceptance artifacts; on a
//! verifier rejection the request fails and no report is written.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Receiver = @import("gkr_receiver.zig");
const ReceiverBudget = @import("receiver_budget.zig");

pub const DEFAULT_WORKERS: usize = 8;
const THREAD_STACK_BYTES: usize = 16 << 20;

pub fn enabled() bool {
    return true;
}

pub fn workers(_: std.mem.Allocator, native_workers: usize) usize {
    return @max(1, @min(native_workers, DEFAULT_WORKERS));
}

pub fn Job(comptime Image: type, comptime Keys: type, comptime Bundle: type, comptime Fixed: type, comptime Config: type) type {
    return struct {
        const Self = @This();
        a: std.mem.Allocator,
        image: *const Image,
        keys: *const Keys,
        bundle: *const Bundle,
        max_steps: u64,
        batch_steps: u32,
        completed: bool,
        config: Config,
        fixed: ?*const Fixed,
        worker_count: usize,
        result: anyerror!?[43]u8 = error.NativeVerifyNotJoined,
        ns: u64 = 0,
        thread: ?std.Thread = null,
        /// Helper stacks + side-thread stack, charged to the shared budget
        /// when one owns the allocator (ready lanes), as the native pool is.
        stacks: engine.host_budget_allocator.SharedHostBudget.ExternalReservation = .empty(),

        pub fn start(self: *Self) !void {
            if (engine.host_budget_allocator.SharedHostBudget.fromAllocator(self.a) orelse recyclerBudget(self.a)) |owner| {
                const helpers = try std.math.mul(usize, self.worker_count - 1, ReceiverBudget.WORKER_STACK_BYTES);
                self.stacks = try owner.reserveExternal(try std.math.add(usize, helpers, THREAD_STACK_BYTES));
            }
            errdefer self.stacks.deinit();
            self.thread = try std.Thread.spawn(.{ .stack_size = THREAD_STACK_BYTES }, run, .{self});
        }

        /// Always joins; returns the verifier's own result.
        pub fn join(self: *Self) !?[43]u8 {
            if (self.thread) |thread| thread.join();
            self.thread = null;
            self.stacks.deinit();
            return self.result;
        }

        fn run(self: *Self) void {
            var timer = std.time.Timer.start() catch {
                self.result = error.NativeVerifyTimerUnavailable;
                return;
            };
            self.result = self.body();
            self.ns = timer.read();
        }

        fn body(self: *Self) !?[43]u8 {
            var pool: engine.work_pool.WorkPool = .{};
            try pool.initInPlaceWithOptions(.{ .worker_count = self.worker_count, .stack_size = ReceiverBudget.WORKER_STACK_BYTES, .backing_allocator = self.a });
            defer pool.deinit();
            var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
            defer binding.deinit();
            return Receiver.verifyWithAuthority(self.a, self.image, self.keys, self.bundle, self.max_steps, self.batch_steps, self.completed, self.config, self.fixed);
        }

        fn recyclerBudget(a: std.mem.Allocator) ?*engine.host_budget_allocator.SharedHostBudget {
            return @import("../../rv64_recursion_budget.zig").require(engine.host_budget_allocator.SharedHostBudget, a) catch null;
        }
    };
}
