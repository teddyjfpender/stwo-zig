//! Optional device generation from original topology + explicit input origins.
//! The CPU builder still constructs/checks its reference assignments. This
//! removes their upload; it does not yet make graph construction GPU-resident.
const std = @import("std");
const Circuit = @import("stwo_circuit_frontend");
const Q = @import("stwo_core").fields.qm31.QM31;
const Schedule = Circuit.builder.witness_plan;
const SC = @import("session_context.zig");
const N = @import("pcs_native_abi.zig");
pub const Task = extern struct { kind: u32, out: u32, args: [6]u32 = @splat(0) };
pub const Seed = extern struct { out: u32, value: [4]u32 };
pub const Job = extern struct { values: [*]u32, records: [*]const u32, indices: ?[*]const u32, status: *u32, value_count: u32, record_count: u32, index_count: u32, first: u32, count: u32, reserved: u32 = 0 };
pub const Launch = *const fn (*anyopaque, u32, *const Job) callconv(.c) c_int;
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    reference: [*]const Q,
    count: usize,
    plan: Schedule.Plan,
    tasks: []Task,
    indices: []u32,
    seeds: []Seed,
    identity: [32]u8,
    check_reference: bool = false,
    seed: Launch,
    level: Launch,
    pub fn init(a: std.mem.Allocator, ctx: *const Circuit.builder.Context(Q), library: *std.DynLib) !Prepared {
        const seed = library.lookup(Launch, "stwo_circuit_assignment_seed_on") orelse return error.MissingCircuitAssignmentKernel;
        const level = library.lookup(Launch, "stwo_circuit_assignment_level_on") orelse return error.MissingCircuitAssignmentKernel;
        var plan = try Schedule.build(a, ctx);
        errdefer plan.deinit();
        const tasks = try a.alloc(Task, plan.tasks.len);
        errdefer a.free(tasks);
        var indices: std.ArrayList(u32) = .empty;
        defer indices.deinit(a);
        for (plan.tasks, tasks) |task, *out| {
            var ibuf: [6]u32 = undefined;
            var obuf: [4]u32 = undefined;
            const in = Schedule.inputs(ctx, task, &ibuf);
            const outputs = Schedule.outputs(ctx, task, &obuf);
            out.* = .{ .kind = @intFromEnum(task.kind), .out = outputs[0] };
            if (task.kind == .permutation) {
                out.args[0] = std.math.cast(u32, indices.items.len) orelse return error.WitnessPlanTooLarge;
                out.args[1] = std.math.cast(u32, in.len) orelse return error.WitnessPlanTooLarge;
                try indices.appendSlice(a, in);
                try indices.appendSlice(a, outputs);
            } else {
                @memcpy(out.args[0..in.len], in);
                if (task.kind == .hint) out.kind = switch (ctx.witness_metadata.?.origins.items[task.index].kind) {
                    .seed => return error.InvalidWitnessOrigin,
                    .inverse => 8,
                    .divide => 9,
                    .pointwise_inverse_or_zero => 10,
                    .pointwise_lsb => 11,
                };
            }
        }
        const seeds = try a.alloc(Seed, plan.seeds.len);
        errdefer a.free(seeds);
        for (plan.seeds, seeds) |input, *out| out.* = .{ .out = input.variable, .value = Circuit.builder.ivalue.limbs(input.value) };
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("circuit/original-witness-schedule/v1\x00");
        hash.update(std.mem.sliceAsBytes(tasks));
        hash.update(std.mem.sliceAsBytes(indices.items));
        hash.update(std.mem.sliceAsBytes(plan.level_ends));
        return .{ .allocator = a, .reference = ctx.values().ptr, .count = ctx.values().len, .plan = plan, .tasks = tasks, .indices = try indices.toOwnedSlice(a), .seeds = seeds, .identity = hash.finalResult(), .seed = seed, .level = level };
    }
    pub fn deinit(self: *Prepared) void {
        self.plan.deinit();
        self.allocator.free(self.tasks);
        self.allocator.free(self.indices);
        self.allocator.free(self.seeds);
        self.* = undefined;
    }
    fn key(self: *const Prepared, fixed: [32]u8, kind: u32) [8]u32 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(&fixed);
        hash.update(&self.identity);
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, kind, .little);
        hash.update(&bytes);
        const digest = hash.finalResult();
        var words: [8]u32 = undefined;
        for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
        return words;
    }
    pub fn generate(self: *const Prepared, owner: anytype, ctx: *SC.Context) !N.Lease {
        const service = owner.backend.service;
        var values = try ctx.allocate(self.count * 4, 0);
        errdefer ctx.release(&values) catch {};
        var status = try ctx.allocate(1, 0);
        defer ctx.release(&status) catch {};
        var seed_lease = try ctx.allocate(self.seeds.len * 5, 0);
        defer ctx.release(&seed_lease) catch {};
        try ctx.upload(try ctx.borrow(seed_lease), @as([*]const u32, @ptrCast(self.seeds.ptr))[0 .. self.seeds.len * 5]);
        try ctx.upload(try ctx.borrow(status), &.{0});
        var job: Job = .{ .values = values.words.?, .records = seed_lease.words.?, .indices = null, .status = @ptrCast(status.words.?), .value_count = @intCast(self.count), .record_count = @intCast(self.seeds.len), .index_count = 0, .first = 0, .count = @intCast(self.seeds.len) };
        try ctx.join();
        if (self.seed(ctx.native_context, 1, &job) != 0) return error.CudaCircuitAssignmentFailed;
        const task_words = @as([*]const u32, @ptrCast(self.tasks.ptr))[0 .. self.tasks.len * 8];
        const tasks = try service.immutableWords(ctx.native_context, ctx.scope, self.key(owner.initial_scope.fixed, 0), task_words);
        const indices: ?N.Lease = if (self.indices.len == 0) null else try service.immutableWords(ctx.native_context, ctx.scope, self.key(owner.initial_scope.fixed, 1), self.indices);
        job.records = tasks.words.?;
        job.record_count = @intCast(self.tasks.len);
        if (indices) |lease| {
            job.indices = lease.words.?;
            job.index_count = @intCast(self.indices.len);
        }
        try ctx.join();
        var begin: usize = 0;
        for (self.plan.level_ends) |end| {
            if (end != begin) {
                job.first = @intCast(begin);
                job.count = @intCast(end - begin);
                if (self.level(ctx.native_context, 1, &job) != 0) return error.CudaCircuitAssignmentFailed;
            }
            begin = end;
        }
        var flag: [1]u32 = undefined;
        try ctx.download(try ctx.borrow(status), &flag);
        try ctx.join();
        if (flag[0] != 0) return error.InvalidCircuitDeviceAssignment;
        if (self.check_reference) {
            const observed = try self.allocator.alloc(u32, self.count * 4);
            defer self.allocator.free(observed);
            try ctx.download(try ctx.borrow(values), observed);
            try ctx.join();
            const expected = @as([*]const u32, @ptrCast(self.reference))[0 .. self.count * 4];
            if (!std.mem.eql(u32, observed, expected)) return error.CircuitDeviceAssignmentMismatch;
        }
        std.debug.print("GPU_OUTER_ASSIGNMENT variables={} seed_words={} static_words={} levels={} full_assignment_upload_words=0\n", .{ self.count, self.seeds.len * 5, task_words.len + self.indices.len, self.plan.level_ends.len });
        return values;
    }
};
