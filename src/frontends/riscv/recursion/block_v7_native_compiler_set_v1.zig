//! One bounded original-roster window of immutable native compiler programs.
//! Slots retain full native indices; only selected window entries are compiled.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Pool = @import("stwo_prover_engine").work_pool;
const Inputs = @import("block_v7_mixed_inputs_v1.zig");
const Bus = @import("block_v7_mixed_public_v1.zig");
const Capsule = @import("block_v7_native_compiler_capsule_v1.zig").Capsule;
const Profile = @import("block_v7_native_fixed_profile_v1.zig");
pub const Options = struct { max_bytes: usize = 2 << 30, parallel_families: usize = 1 };
const Job = struct {
    a: std.mem.Allocator,
    profile: *const Profile.Owned,
    max_bytes: usize,
    result: ?*Capsule = null,
    failure: ?anyerror = null,
    fn run(self: *Job) void {
        self.result = Capsule.derive(self.a, self.profile, .{ .max_bytes = self.max_bytes }) catch |err| {
            self.failure = err;
            return;
        };
    }
    fn deinit(self: *Job) void {
        if (self.result) |item| item.deinit();
    }
};
pub const Owned = struct {
    budget: *Budget,
    slots: []?*const Capsule,
    pub fn initWindow(a: std.mem.Allocator, input: Inputs.Input, first: usize, count: usize, max_entries: usize, options: Options) !Owned {
        if (options.max_bytes == 0 or options.parallel_families == 0 or options.parallel_families > Pool.MAX_WORKERS or count == 0 or count > Bus.MAX_CHILDREN) return error.NativeCompilerResourceLimit;
        const budget = try Budget.createRetainingParent(a, options.max_bytes);
        errdefer budget.destroy();
        const temp = budget.allocator();
        var canonical = try Inputs.Owned.initWhole(temp, input, max_entries);
        defer canonical.deinit();
        _ = try canonical.window(first, count);
        const slots = try temp.alloc(?*const Capsule, input.natives.len);
        @memset(slots, null);
        var result: Owned = .{ .budget = budget, .slots = slots };
        errdefer {
            result.clear();
            temp.free(slots);
        }
        var indices: [Bus.MAX_CHILDREN]usize = undefined;
        var n: usize = 0;
        for (canonical.expected[first..][0..count]) |entry| if (entry.kind == .native) {
            indices[n] = entry.index;
            n += 1;
        };
        var lease: ?Pool.WorkLease = null;
        if (options.parallel_families > 1 and n > 1) if (Pool.currentScopedPool()) |pool| {
            const workers = @min(@min(options.parallel_families, n), pool.workerCount());
            if (workers > 1) lease = pool.acquire(try Pool.WorkerBudget.init(workers)) catch |err| switch (err) {
                error.WorkerBudgetUnavailable => null,
                else => return err,
            };
        };
        defer if (lease) |*held| held.deinit();
        const width = if (lease) |*held| held.workerCount() else 1;
        const jobs = try temp.alloc(Job, width);
        defer temp.free(jobs);
        var start: usize = 0;
        while (start < n) {
            const end = @min(n, start + width);
            const cohort = jobs[0 .. end - start];
            var initialized: usize = 0;
            defer for (cohort[0..initialized]) |*job| job.deinit();
            var wait = std.Thread.WaitGroup{};
            {
                defer {
                    wait.wait();
                    if (lease) |*held| held.completeWave();
                }
                for (cohort, indices[start..end], 0..) |*job, index, j| {
                    job.* = .{ .a = temp, .profile = input.natives[index].profile, .max_bytes = options.max_bytes };
                    initialized += 1;
                    if (j + 1 < cohort.len) try lease.?.spawnWg(&wait, Job.run, .{job}) else job.run();
                }
            }
            for (cohort) |job| if (job.failure) |err| return err;
            for (cohort, indices[start..end]) |*job, index| {
                slots[index] = job.result.?;
                job.result = null;
            }
            start = end;
        }
        return result;
    }
    pub fn clear(self: *Owned) void {
        for (self.slots) |*slot| {
            if (slot.*) |capsule| @constCast(capsule).deinit();
            slot.* = null;
        }
    }
    pub fn deinit(self: *Owned) void {
        self.clear();
        self.budget.allocator().free(self.slots);
        self.budget.destroy();
        self.* = undefined;
    }
};
