//! Wide-Fibonacci hooks for the shared resident CUDA pipeline.

const std = @import("std");
const stark_bundle = @import("stwo_cuda_backend").runtime.proof_assembly.stark_bundle;
const common_pipeline = @import("../../common/pipeline.zig");
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

const Hooks = struct {
    pub const BundleDescriptor = stark_bundle.WideDescriptor;
    pub const admit = request.admit;
    pub const planTarget = program_mod.targetFor;

    pub fn initCanonical(
        allocator: std.mem.Allocator,
        geometry: request.Geometry,
    ) !canonical_ingress.Pack {
        return canonical_ingress.Pack.init(allocator, geometry);
    }

    pub fn deinitCanonical(
        canonical: *canonical_ingress.Pack,
        allocator: std.mem.Allocator,
    ) void {
        canonical.deinit(allocator);
    }

    pub fn ingress(
        transaction: anytype,
        structural: *plan_mod.PreparedPlan,
        canonical: *canonical_ingress.Pack,
    ) !void {
        const views = try bind(transaction, structural);
        try ingress_stage.run(
            transaction,
            structural,
            canonical,
            &views,
        );
    }

    pub fn traceGeneration(
        transaction: anytype,
        structural: *plan_mod.PreparedPlan,
        _: *canonical_ingress.Pack,
    ) !void {
        const views = try bind(transaction, structural);
        try trace_commit.generate(transaction, structural, &views);
    }

    pub fn traceCommit(
        transaction: anytype,
        structural: *plan_mod.PreparedPlan,
        _: *canonical_ingress.Pack,
    ) !void {
        const views = try bind(transaction, structural);
        try trace_commit.commit(transaction, structural, &views);
    }

    pub fn constraintEvaluation(
        transaction: anytype,
        structural: *plan_mod.PreparedPlan,
        _: *canonical_ingress.Pack,
    ) !void {
        const views = try bind(transaction, structural);
        try composition.run(transaction, structural, &views);
    }

    pub fn oods(
        transaction: anytype,
        structural: *plan_mod.PreparedPlan,
        canonical: *canonical_ingress.Pack,
    ) !void {
        const views = try bind(transaction, structural);
        try oods_stage.run(
            transaction,
            structural,
            canonical,
            &views,
        );
    }

    pub fn quotient(
        transaction: anytype,
        structural: *plan_mod.PreparedPlan,
        canonical: *canonical_ingress.Pack,
    ) !void {
        const views = try bind(transaction, structural);
        try quotient_stage.run(
            transaction,
            structural,
            canonical,
            &views,
        );
    }

    pub fn friCommit(
        transaction: anytype,
        structural: *plan_mod.PreparedPlan,
        canonical: *canonical_ingress.Pack,
    ) !void {
        const views = try bind(transaction, structural);
        try fri.run(transaction, structural, canonical, &views);
    }

    pub fn pow(
        transaction: anytype,
        structural: *plan_mod.PreparedPlan,
        _: *canonical_ingress.Pack,
    ) !void {
        const views = try bind(transaction, structural);
        try pow_decommit.executePow(transaction, structural, &views);
    }

    pub fn decommit(
        transaction: anytype,
        structural: *plan_mod.PreparedPlan,
        _: *canonical_ingress.Pack,
    ) !void {
        const views = try bind(transaction, structural);
        try pow_decommit.executeDecommit(transaction, structural, &views);
    }

    fn bind(
        transaction: anytype,
        structural: *const plan_mod.PreparedPlan,
    ) !bindings.Views {
        return bindings.bind(transaction, structural);
    }
};

const Pipeline = common_pipeline.PipelineFor(
    request.Request,
    request.Geometry,
    plan_mod.PreparedPlan,
    canonical_ingress.Pack,
    Hooks,
);

pub const Request = Pipeline.Request;
pub const Geometry = Pipeline.Geometry;
pub const BundleDescriptor = Pipeline.BundleDescriptor;
pub const PreparedPlan = Pipeline.PreparedPlan;
pub const admit = Pipeline.admit;
pub const prepare = Pipeline.prepare;
pub const planTarget = Pipeline.planTarget;
pub const validatePrepared = Pipeline.validatePrepared;
pub const ingress = Pipeline.ingress;
pub const executeNode = Pipeline.executeNode;

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
        .device_uuid = [_]u8{0x42} ** 16,
        .driver_version = 12080,
        .runtime_version = 12080,
        .toolkit_version = 12080,
        .runtime_build_identity = proof_ir.identityDigest("test-runtime"),
        .host_toolchain_identity = proof_ir.identityDigest("test-toolchain"),
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
