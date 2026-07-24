//! One-shot orchestration for a complete resident Native CUDA proof.

const std = @import("std");
const arena = @import("../../../../backends/cuda/runtime/arena.zig");
const canonical_ingress = @import("../canonical_ingress.zig");
const plan_mod = @import("../plan.zig");
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
    ) !PreparedPlan {
        var structural = try plan_mod.PreparedPlan.init(
            allocator,
            geometry,
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

    pub fn takeArenaPlan(self: *PreparedPlan) arena.Plan {
        return self.structural.takeArenaPlan();
    }
};

pub fn prepare(
    allocator: std.mem.Allocator,
    geometry: request.Geometry,
) !PreparedPlan {
    return PreparedPlan.init(allocator, geometry);
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
    var prepared = try prepare(allocator, geometry);
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

    var owned_plan = prepared.takeArenaPlan();
    defer owned_plan.deinit(allocator);
    try std.testing.expect(!prepared.structural.arena_plan_live);
}
