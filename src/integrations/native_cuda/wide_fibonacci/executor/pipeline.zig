//! One-shot orchestration for a complete resident Native CUDA proof.

const std = @import("std");
const arena = @import("../../../../backends/cuda/runtime/arena.zig");
const canonical_ingress = @import("../canonical_ingress.zig");
const plan_mod = @import("../plan.zig");
const program_mod = @import("../program.zig");
const request = @import("../request.zig");
const bindings = @import("../resident_bindings/mod.zig");
const composition = @import("composition.zig");
const fri = @import("fri.zig");
const ingress_stage = @import("ingress.zig");
const oods_stage = @import("oods.zig");
const pow_decommit = @import("pow_decommit.zig");
const quotient_stage = @import("quotient.zig");
const trace_commit = @import("trace_commit.zig");

pub const PreparedPlan = struct {
    structural: plan_mod.PreparedPlan,
    canonical: canonical_ingress.Pack,

    pub fn init(
        allocator: std.mem.Allocator,
        geometry: request.Geometry,
        target: @import(
            "../../../../backends/cuda/runtime/execution_plan.zig",
        ).CompileOptions,
    ) !PreparedPlan {
        var structural = try plan_mod.PreparedPlan.initForTarget(
            allocator,
            geometry,
            target,
        );
        errdefer structural.deinit(allocator);
        return .{
            .structural = structural,
            .canonical = try canonical_ingress.Pack.init(
                allocator,
                geometry,
            ),
        };
    }

    pub fn deinit(
        self: *PreparedPlan,
        allocator: std.mem.Allocator,
    ) void {
        self.canonical.deinit(allocator);
        self.structural.deinit(allocator);
        self.* = undefined;
    }

    pub fn requirements(
        self: *const PreparedPlan,
    ) []const arena.Requirement {
        return self.structural.requirements();
    }

    pub fn proofSlot(self: *const PreparedPlan) arena.SlotId {
        return self.structural.proofSlot();
    }

    pub fn instantiateArenaPlan(
        self: *const PreparedPlan,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!arena.Plan {
        return self.structural.instantiateArenaPlan(allocator);
    }

    pub fn schedule(
        self: *const PreparedPlan,
    ) []const @import(
        "../../../../backends/cuda/runtime/execution_plan.zig",
    ).ScheduledNode {
        return self.structural.schedule();
    }
};

pub fn prepare(
    allocator: std.mem.Allocator,
    geometry: request.Geometry,
    target: @import(
        "../../../../backends/cuda/runtime/execution_plan.zig",
    ).CompileOptions,
) !PreparedPlan {
    return PreparedPlan.init(allocator, geometry, target);
}

pub fn planTarget(session: anytype) !@import(
    "../../../../backends/cuda/runtime/execution_plan.zig",
).CompileOptions {
    return program_mod.targetFor(session);
}

pub fn validatePrepared(
    prepared: *const PreparedPlan,
    geometry: request.Geometry,
) !void {
    try requireGeometry(prepared, geometry);
}

pub fn ingressStage(
    transaction: anytype,
    prepared: *PreparedPlan,
    geometry: request.Geometry,
) !void {
    try requireGeometry(prepared, geometry);
    const views = try bind(transaction, prepared);
    try ingress_stage.run(
        transaction,
        &prepared.structural,
        &prepared.canonical,
        &views,
    );
}

pub const ingress = ingressStage;

pub fn traceGeneration(
    transaction: anytype,
    prepared: *PreparedPlan,
    geometry: request.Geometry,
) !void {
    try requireGeometry(prepared, geometry);
    const views = try bind(transaction, prepared);
    try trace_commit.generate(
        transaction,
        &prepared.structural,
        &views,
    );
}

pub fn traceCommit(
    transaction: anytype,
    prepared: *PreparedPlan,
    geometry: request.Geometry,
) !void {
    try requireGeometry(prepared, geometry);
    const views = try bind(transaction, prepared);
    try trace_commit.commit(
        transaction,
        &prepared.structural,
        &views,
    );
}

pub fn constraintEvaluation(
    transaction: anytype,
    prepared: *PreparedPlan,
    geometry: request.Geometry,
) !void {
    try requireGeometry(prepared, geometry);
    const views = try bind(transaction, prepared);
    try composition.run(
        transaction,
        &prepared.structural,
        &views,
    );
}

pub fn oodsStage(
    transaction: anytype,
    prepared: *PreparedPlan,
    geometry: request.Geometry,
) !void {
    try requireGeometry(prepared, geometry);
    const views = try bind(transaction, prepared);
    try oods_stage.run(
        transaction,
        &prepared.structural,
        &prepared.canonical,
        &views,
    );
}

pub const oods = oodsStage;

pub fn quotientStage(
    transaction: anytype,
    prepared: *PreparedPlan,
    geometry: request.Geometry,
) !void {
    try requireGeometry(prepared, geometry);
    const views = try bind(transaction, prepared);
    try quotient_stage.run(
        transaction,
        &prepared.structural,
        &prepared.canonical,
        &views,
    );
}

pub const quotient = quotientStage;

pub fn friCommit(
    transaction: anytype,
    prepared: *PreparedPlan,
    geometry: request.Geometry,
) !void {
    try requireGeometry(prepared, geometry);
    const views = try bind(transaction, prepared);
    try fri.run(
        transaction,
        &prepared.structural,
        &prepared.canonical,
        &views,
    );
}

pub fn pow(
    transaction: anytype,
    prepared: *PreparedPlan,
    geometry: request.Geometry,
) !void {
    try requireGeometry(prepared, geometry);
    const views = try bind(transaction, prepared);
    try pow_decommit.executePow(
        transaction,
        &prepared.structural,
        &views,
    );
}

pub fn decommit(
    transaction: anytype,
    prepared: *PreparedPlan,
    geometry: request.Geometry,
) !void {
    try requireGeometry(prepared, geometry);
    const views = try bind(transaction, prepared);
    try pow_decommit.executeDecommit(
        transaction,
        &prepared.structural,
        &views,
    );
}

pub fn executeNode(
    transaction: anytype,
    prepared: *PreparedPlan,
    geometry: request.Geometry,
    scheduled: @import(
        "../../../../backends/cuda/runtime/execution_plan.zig",
    ).ScheduledNode,
) !void {
    const proof_ir = @import("stwo_backend_contracts").proof_program;
    switch (scheduled.kind) {
        .trace_generation => try traceGeneration(
            transaction,
            prepared,
            geometry,
        ),
        .commitment => try traceCommit(transaction, prepared, geometry),
        .constraint_evaluation => try constraintEvaluation(
            transaction,
            prepared,
            geometry,
        ),
        .oods => try oods(transaction, prepared, geometry),
        .quotient => try quotient(transaction, prepared, geometry),
        .fri_commit => try friCommit(transaction, prepared, geometry),
        .pow => try pow(transaction, prepared, geometry),
        .decommit => try decommit(transaction, prepared, geometry),
    }
    const expected_stage: proof_ir.Stage =
        prepared.structural.proof_program.nodes[scheduled.node_id].stage;
    if (@intFromEnum(expected_stage) != @intFromEnum(scheduled.stage))
        return error.InvalidKernelDescriptor;
}

fn bind(
    transaction: anytype,
    prepared: *const PreparedPlan,
) !bindings.Views {
    return bindings.bind(transaction, &prepared.structural);
}

fn requireGeometry(
    prepared: *const PreparedPlan,
    geometry: request.Geometry,
) !void {
    if (!std.meta.eql(prepared.structural.logical.geometry, geometry))
        return error.InvalidKernelDescriptor;
}

test "prepared executor owns canonical inputs and transfers its plan once" {
    const allocator = std.testing.allocator;
    const geometry = try request.admit(.{
        .statement = .{ .log_n_rows = 3, .sequence_len = 3 },
        .protocol = .{
            .pow_bits = 10,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
            .fold_step = 1,
            .lifting_log_size = null,
        },
    });
    const proof_ir = @import("stwo_backend_contracts").proof_program;
    var prepared = try prepare(allocator, geometry, .{
        .sm = 89,
        .runtime_build_identity = proof_ir.identityDigest("test-runtime"),
        .toolchain_identity = proof_ir.identityDigest("test-toolchain"),
        .kernel_pack_identity = proof_ir.identityDigest("test-pack"),
        .lane_streams = 0,
        .enable_graphs = false,
    });
    defer prepared.deinit(allocator);
    try std.testing.expectEqual(
        prepared.structural.requirements().len,
        prepared.requirements().len,
    );
    try std.testing.expectEqual(
        prepared.structural.proofSlot(),
        prepared.proofSlot(),
    );
    try std.testing.expectEqual(
        geometry.trace_rows,
        prepared.canonical.forwardTwiddleWords().len,
    );

    var owned_plan = try prepared.instantiateArenaPlan(allocator);
    defer owned_plan.deinit(allocator);
    try std.testing.expectEqual(
        prepared.structural.cuda_plan.arena_plan.total_words,
        owned_plan.total_words,
    );
}
