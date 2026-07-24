//! Native state-machine binding of the AIR-neutral resident CUDA pipeline.

const std = @import("std");
const common_pipeline = @import("../../common/pipeline.zig");
const canonical = @import("../canonical_ingress.zig");
const frontend_hooks = @import("frontend_hooks.zig");
const geometry_mod = @import("../geometry.zig");
const plan_mod = @import("../plan.zig");

const Pipeline = common_pipeline.PipelineFor(
    geometry_mod.Request,
    geometry_mod.Geometry,
    plan_mod.PreparedPlan,
    canonical.Pack,
    frontend_hooks.Hooks,
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

test "state-machine pipeline owns canonical inputs and one compiled arena plan" {
    const allocator = std.testing.allocator;
    const geometry = try admit(.{
        .statement = .{
            .log_n_rows = 8,
            .initial_state = .{
                @import("stwo_core").fields.m31.M31.fromU64(9),
                @import("stwo_core").fields.m31.M31.fromU64(3),
            },
        },
        .protocol = @import("stwo_core").pcs.PcsConfig.default(),
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
