//! Focused ownership and failure tests for production Tree-1 destinations.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const statement_mod = @import("../air/statement.zig");
const arena = @import("main_trace_plan_execution_production_arena.zig");
const plan_mod = @import("main_trace_plan.zig");

const COLUMN_COUNT: usize = 6;
const MAIN_CELLS: usize = 24;
const RETAINED_CELLS: usize = 7;

const Fixture = struct {
    statement: statement_mod.RiscVStatement,
    plan: plan_mod.Plan,

    fn init() Fixture {
        var statement: statement_mod.RiscVStatement = undefined;
        statement.n_components = 2;
        statement.component_descs[0] = .{
            .family = .base_alu_imm,
            .log_size = 2,
            .n_rows = 4,
            .n_columns = 2,
        };
        statement.component_descs[1] = .{
            .family = .base_alu_reg,
            .log_size = 3,
            .n_rows = 8,
            .n_columns = 1,
        };
        statement.n_infra = 2;
        statement.infra_descs[0] = .{
            .kind = .program,
            .log_size = 2,
            .n_rows = 4,
            .n_columns = 1,
        };
        statement.infra_descs[1] = .{
            .kind = .clock_update,
            .log_size = 1,
            .n_rows = 2,
            .n_columns = 2,
        };

        var plan: plan_mod.Plan = undefined;
        plan.total_columns = COLUMN_COUNT;
        plan.resources.main_output_payload_bytes = MAIN_CELLS * @sizeOf(M31);
        plan.resources.retained_opcode_payload_bytes = 4 * @sizeOf(M31);
        plan.resources.retained_clock_payload_bytes = 3 * @sizeOf(M31);
        return .{ .statement = statement, .plan = plan };
    }
};

test "production arena policy: backend adoption selects exactly one ownership shape" {
    const NonAdopter = struct {};
    const ExplicitNonAdopter = struct {
        pub const adopts_source_trace_arena = false;
    };
    const Adopter = struct {
        pub const adopts_source_trace_arena = true;
        pub const resident_column_arena_alignment =
            std.mem.Alignment.fromByteUnits(16 * 1024);
    };
    const CpuLikeEngine = struct {
        pub const Backend = NonAdopter;
    };
    const MetalLikeEngine = struct {
        pub const Backend = Adopter;
    };

    try std.testing.expectEqual(
        arena.DestinationPolicy.independent_columns,
        arena.DestinationPolicy.forBackend(NonAdopter),
    );
    try std.testing.expectEqual(
        arena.DestinationPolicy.independent_columns,
        arena.DestinationPolicy.forBackend(ExplicitNonAdopter),
    );
    try std.testing.expectEqual(
        arena.DestinationPolicy.grouped_backing,
        arena.DestinationPolicy.forBackend(Adopter),
    );
    try std.testing.expectEqual(
        arena.DestinationPolicy.independent_columns,
        arena.DestinationPolicy.forEngine(CpuLikeEngine),
    );
    try std.testing.expectEqual(
        arena.DestinationPolicy.grouped_backing,
        arena.DestinationPolicy.forEngine(MetalLikeEngine),
    );
}

test "production arena ownership: independent columns transfer once without backing" {
    try exerciseOwnership(.independent_columns);
}

test "production arena ownership: grouped aligned backing transfers once" {
    try exerciseOwnership(.grouped_backing);
}

test "production arena failure: both destination policies clean every partial allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocateAndReleaseIndependent,
        .{},
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocateAndReleaseGrouped,
        .{},
    );
}

test "production arena transfer: seal and take allocate nothing" {
    const fixture = Fixture.init();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = failing.allocator();
    const artifacts = try arena.Artifacts.initWithPolicy(
        allocator,
        &fixture.statement,
        &fixture.plan,
        .independent_columns,
    );
    defer artifacts.deinit();

    const allocation_count = failing.alloc_index;
    const resize_count = failing.resize_index;
    failing.fail_index = allocation_count;
    failing.resize_fail_index = resize_count;
    try artifacts.completeRange(.{ .start = 0, .len = COLUMN_COUNT });
    var commitment = try artifacts.takeCommitment();
    defer commitment.deinit(allocator);

    try std.testing.expectEqual(allocation_count, failing.alloc_index);
    try std.testing.expectEqual(resize_count, failing.resize_index);
    try std.testing.expect(!failing.has_induced_failure);
}

test "production arena policy: malformed resource and adoption states reject" {
    const fixture = Fixture.init();
    var bad_plan = fixture.plan;
    bad_plan.resources.main_output_payload_bytes += @sizeOf(M31);
    try std.testing.expectError(
        error.InvalidProductionDestinationShape,
        arena.Artifacts.initWithPolicy(
            std.testing.allocator,
            &fixture.statement,
            &bad_plan,
            .independent_columns,
        ),
    );

    const artifacts = try arena.Artifacts.initWithPolicy(
        std.testing.allocator,
        &fixture.statement,
        &fixture.plan,
        .grouped_backing,
    );
    defer artifacts.deinit();
    try artifacts.completeRange(.{ .start = 0, .len = COLUMN_COUNT });
    artifacts.destination_policy = .independent_columns;
    try std.testing.expectError(
        error.InvalidProductionDestinationPolicy,
        artifacts.takeCommitment(),
    );
    artifacts.destination_policy = .grouped_backing;
}

fn exerciseOwnership(policy: arena.DestinationPolicy) !void {
    const fixture = Fixture.init();
    const artifacts = try arena.Artifacts.initWithPolicy(
        std.testing.allocator,
        &fixture.statement,
        &fixture.plan,
        policy,
    );
    defer artifacts.deinit();

    try std.testing.expectEqual(policy, artifacts.destination_policy);
    try std.testing.expectEqual(COLUMN_COUNT, artifacts.columns.len);
    try std.testing.expectEqual(RETAINED_CELLS, artifacts.retained_payload.len);
    try expectColumnShapeAndZeros(artifacts.columns);
    for (artifacts.retained_payload) |value| {
        try std.testing.expect(value.eql(M31.zero()));
    }
    try std.testing.expectError(
        error.IncompleteProductionOwner,
        artifacts.takeCommitment(),
    );
    try artifacts.completeRange(.{ .start = 0, .len = 3 });
    try std.testing.expectError(
        error.IncompleteProductionOwner,
        artifacts.takeCommitment(),
    );
    try std.testing.expectError(
        error.DuplicateProductionDestinationOwner,
        artifacts.completeRange(.{ .start = 1, .len = 2 }),
    );
    try artifacts.completeRange(.{ .start = 3, .len = 3 });

    var commitment = try artifacts.takeCommitment();
    defer commitment.deinit(std.testing.allocator);
    try commitment.validatePolicy();
    try std.testing.expectEqual(policy.hasSharedBacking(), commitment.hasSharedBacking());
    switch (policy) {
        .independent_columns => {
            try std.testing.expect(commitment.backing == null);
            try std.testing.expect(commitment.backingBuffers() == null);
            for (commitment.columns, 0..) |column, index| {
                for (commitment.columns[0..index]) |previous| {
                    try std.testing.expect(column.values.ptr != previous.values.ptr);
                }
            }
        },
        .grouped_backing => {
            const payload = commitment.backing.?.payload;
            const buffers = commitment.backingBuffers().?;
            try std.testing.expectEqual(@as(usize, 1), buffers.len);
            try std.testing.expectEqual(payload.ptr, buffers[0].ptr);
            try std.testing.expectEqual(payload.len, buffers[0].len);
            try std.testing.expectEqual(
                @as(usize, 0),
                @intFromPtr(payload.ptr) % arena.GROUPED_ARENA_ALIGNMENT.toByteUnits(),
            );
            // Equal-log-size columns are one run even though descriptor order
            // interleaves other groups.
            try std.testing.expectEqual(
                commitment.columns[0].values.ptr + commitment.columns[0].values.len,
                commitment.columns[1].values.ptr,
            );
            try std.testing.expectEqual(
                commitment.columns[1].values.ptr + commitment.columns[1].values.len,
                commitment.columns[3].values.ptr,
            );
            try std.testing.expectEqual(
                commitment.columns[4].values.ptr + commitment.columns[4].values.len,
                commitment.columns[5].values.ptr,
            );
        },
    }
    try std.testing.expectEqual(@as(usize, 0), artifacts.columns.len);
    try std.testing.expectEqual(RETAINED_CELLS, artifacts.retained_payload.len);
    try std.testing.expectError(
        error.Tree1ProductionOutputAlreadyTransferred,
        artifacts.takeCommitment(),
    );
}

fn expectColumnShapeAndZeros(
    columns: []const @import("stwo_prover_engine").pcs.ColumnEvaluation,
) !void {
    const expected_logs = [_]u32{ 2, 2, 3, 2, 1, 1 };
    for (columns, expected_logs) |column, log_size| {
        try std.testing.expectEqual(log_size, column.log_size);
        try std.testing.expectEqual(
            @as(usize, 1) << @intCast(log_size),
            column.values.len,
        );
        for (column.values) |value| {
            try std.testing.expect(value.eql(M31.zero()));
        }
    }
}

fn allocateAndReleaseIndependent(allocator: std.mem.Allocator) !void {
    return allocateAndRelease(allocator, .independent_columns);
}

fn allocateAndReleaseGrouped(allocator: std.mem.Allocator) !void {
    return allocateAndRelease(allocator, .grouped_backing);
}

fn allocateAndRelease(
    allocator: std.mem.Allocator,
    policy: arena.DestinationPolicy,
) !void {
    const fixture = Fixture.init();
    const artifacts = try arena.Artifacts.initWithPolicy(
        allocator,
        &fixture.statement,
        &fixture.plan,
        policy,
    );
    defer artifacts.deinit();
    try artifacts.completeRange(.{ .start = 0, .len = COLUMN_COUNT });
    var commitment = try artifacts.takeCommitment();
    commitment.deinit(allocator);
}
