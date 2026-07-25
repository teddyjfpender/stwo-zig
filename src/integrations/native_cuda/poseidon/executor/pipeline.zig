//! Native Poseidon binding of the AIR-neutral resident CUDA pipeline.

const canonical = @import("../canonical_ingress.zig");
const common_pipeline = @import("../../common/pipeline.zig");
const frontend_hooks = @import("frontend_hooks.zig");
const geometry_mod = @import("../geometry.zig");
const plan_mod = @import("../plan.zig");
const std = @import("std");
const terminal_output = @import("../terminal_output.zig");

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

pub fn OutputFor(comptime Transaction: type) type {
    return terminal_output.OutputFor(Transaction);
}

pub fn finish(
    transaction: anytype,
    allocator: std.mem.Allocator,
    prepared: anytype,
) !OutputFor(@TypeOf(transaction.*)) {
    const raw = try transaction.assembleStarkBundleAndStatementFinishWith(
        BundleDescriptor,
        allocator,
        prepared.proofSlot(),
        geometry_mod.terminal_statement_words,
    );
    return terminal_output.fromRaw(
        @TypeOf(transaction.*),
        allocator,
        prepared.structural.logical.geometry.statement,
        raw,
    );
}

test "Poseidon pipeline prepares one exact resident proof plan" {
    const allocator = std.testing.allocator;
    const geometry = try admit(.{
        .statement = .{ .log_n_instances = 13 },
        .protocol = @import("stwo_core").pcs.PcsConfig.default(),
    });
    const proof_ir =
        @import("stwo_backend_contracts").proof_program;
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
        geometry.trace_rows,
        prepared.canonical.forwardTwiddleWords().len,
    );
}
