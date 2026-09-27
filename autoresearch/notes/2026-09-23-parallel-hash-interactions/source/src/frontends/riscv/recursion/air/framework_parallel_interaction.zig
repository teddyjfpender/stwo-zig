//! Bounded scheduling for the canonical typed interaction writer. All helpers
//! finish before output ownership transfers or allocation cleanup begins.
const std = @import("std");
const pool_mod = @import("stwo_prover_engine").work_pool;
const universal = @import("universal_challenges.zig");
const Q = @import("stwo_core").fields.qm31.QM31;

const Scheduler = struct {
    lease: *pool_mod.WorkLease,
    pub fn run(self: @This(), contexts: anytype) void {
        const Context = @TypeOf(contexts[0]);
        var group: std.Thread.WaitGroup = .{};
        defer {
            group.wait();
            self.lease.completeWave();
        }
        for (contexts[1..]) |*context| {
            // A submission that was not accepted can safely execute inline.
            self.lease.spawnWg(&group, Context.run, .{context}) catch context.run();
        }
        contexts[0].run();
    }
};

pub fn generate(comptime Runtime: type, a: std.mem.Allocator, workspace: *Runtime.Workspace, plan: *const Runtime.Plan, source: Runtime.ColumnRows, log: u32, relations: *const universal.UniversalRelations, padding: ?Runtime.Row) !Runtime.OwnedColumns {
    const pool = pool_mod.getGlobalPool() orelse return Runtime.generatePreparedOwnedColumnsTiledWithWorkspace(a, workspace, plan, source, log, relations, padding);
    if (log > 24) return error.InvalidTraceShape;
    const tile_log = @min(log, workspace.capacity_log_size);
    const scratch_bytes = try std.math.mul(usize, try Runtime.requiredScratchElementCount(tile_log), @sizeOf(Q));
    const workers = @min(pool.workerCount(), 8, @as(usize, 1) << @intCast(log - tile_log), @max(1, (128 * 1024 * 1024) / scratch_bytes));
    if (workers < 2 or std.process.hasEnvVarConstant("STWO_RISCV_SERIAL_HASH_INTERACTIONS")) return Runtime.generatePreparedOwnedColumnsTiledWithWorkspace(a, workspace, plan, source, log, relations, padding);
    var lease = pool.acquire(try pool_mod.WorkerBudget.init(workers)) catch return Runtime.generatePreparedOwnedColumnsTiledWithWorkspace(a, workspace, plan, source, log, relations, padding);
    defer lease.deinit();
    var owned: [7]Runtime.Workspace = undefined;
    var pointers: [8]*Runtime.Workspace = undefined;
    pointers[0] = workspace;
    var initialized: usize = 0;
    defer for (owned[0..initialized]) |*item| item.deinit();
    for (1..workers) |i| {
        owned[i - 1] = try Runtime.Workspace.init(a, tile_log);
        initialized += 1;
        pointers[i] = &owned[i - 1];
    }
    return Runtime.generatePreparedOwnedColumnsScheduled(a, pointers[0..workers], plan, source, log, relations, padding, Scheduler{ .lease = &lease });
}

test "R-012 framework parallel tiles match serial and drain failures" {
    const a = std.testing.allocator;
    const framework = @import("framework_interaction.zig");
    const control = @import("control.zig");
    const relation = @import("control_relation.zig");
    const witness = @import("control_witness.zig");
    const F = framework.Runtime(relation.Runtime);
    var definition = try control.build(a);
    defer definition.deinit();
    const plan = try relation.authenticate(&definition);
    const rows = [_]relation.Row{
        witness.logicalRow(.{ .segment_mask = 1, .binary_mask = 0, .verifier_id = 0, .sequence = 0, .tag = 7, .args = .{ 11, 13, 17, 19 }, .terminal_mask = 1 }, .segment_leaf),
    };
    var relations = universal.UniversalRelations.dummy();
    const view = F.ColumnRows{ .columns = @splat(&.{}), .count = rows.len, .main_count = 0, .metadata = &rows };
    var scratch = try F.Workspace.init(a, 4);
    defer scratch.deinit();
    var oracle = try F.generatePreparedOwnedColumnsTiledWithWorkspace(a, &scratch, &plan, view, 7, &relations, null);
    defer oracle.deinit(a);
    var pool: pool_mod.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4 });
    defer pool.deinit();
    var binding = try pool_mod.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var actual = try generate(F, a, &scratch, &plan, view, 7, &relations, null);
    defer actual.deinit(a);
    try std.testing.expect(oracle.claimed_sum.eql(actual.claimed_sum));
    for (oracle.columns, actual.columns) |left, right| try std.testing.expectEqualSlices(@import("stwo_core").fields.m31.M31, left, right);
    {
        var held = try pool.acquire(try pool_mod.WorkerBudget.init(4));
        defer held.deinit();
        var fallback = try generate(F, a, &scratch, &plan, view, 7, &relations, null);
        defer fallback.deinit(a);
        for (oracle.columns, fallback.columns) |left, right| try std.testing.expectEqualSlices(@import("stwo_core").fields.m31.M31, left, right);
    }
    const pairs = try plan.preparedRowPairs(rows[0], &relations);
    const domain = @intFromEnum(plan.events[plan.batches[0].first].domain);
    relations.elements[domain].z = relations.elements[domain].z.add(pairs[0].d1);
    try std.testing.expectError(error.ZeroDenominator, generate(F, a, &scratch, &plan, view, 7, &relations, null));
    var drained = try pool.acquire(try pool_mod.WorkerBudget.init(4));
    defer drained.deinit();
}
