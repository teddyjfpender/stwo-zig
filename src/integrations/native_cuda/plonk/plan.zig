//! Descriptor-driven prepared plan for one resident Native Plonk proof.

const std = @import("std");
const arena = @import("stwo_cuda_backend").runtime.arena;
const execution_plan = @import("stwo_cuda_backend").runtime.execution_plan;
const geometry_mod = @import("geometry.zig");
const layout = @import("layout.zig");
const program = @import("program.zig");
const proof_bundle = @import("proof_bundle.zig");
const requirements = @import("requirements.zig");
const shared = @import("../common/prepared_plan.zig");
const slots = @import("slots.zig");
const topology = @import("topology.zig");
const transcript = @import("transcript_schedule.zig");

const Policy = struct {
    pub fn buildRequirements(
        allocator: std.mem.Allocator,
        geometry: geometry_mod.Geometry,
        quotient: topology.Quotient,
        fri: topology.Fri,
        decommit: topology.Decommit,
        proof: proof_bundle.Bundle,
    ) ![]arena.Requirement {
        return requirements.build(
            allocator,
            geometry,
            quotient,
            fri,
            decommit,
            proof,
        );
    }

    pub fn emitProgram(
        allocator: std.mem.Allocator,
        geometry: geometry_mod.Geometry,
        logical: layout.Layout,
        quotient: topology.Quotient,
        fri: topology.Fri,
        arena_requirements: []const arena.Requirement,
    ) !@import("stwo_backend_contracts").proof_program.ProofProgram {
        return program.emitPlan(
            allocator,
            geometry,
            logical,
            quotient,
            fri,
            arena_requirements,
        );
    }

    pub fn proofSlot() arena.SlotId {
        return slots.proof_bundle;
    }

    pub fn maxTotalWords() usize {
        return requirements.max_total_words;
    }

    pub fn defaultTarget() execution_plan.CompileOptions {
        const identity =
            @import("stwo_backend_contracts").proof_program
                .identityDigest("native-plonk-cuda-test-target");
        return .{
            .sm = 89,
            .device_uuid = [_]u8{0x42} ** 16,
            .driver_version = 12080,
            .runtime_version = 12080,
            .toolkit_version = 12080,
            .runtime_build_identity = identity,
            .host_toolchain_identity = identity,
            .kernel_pack_identity = program.kernel_pack_identity,
            .lane_streams = 0,
            .enable_graphs = false,
        };
    }
};

pub const PreparedPlan = shared.PreparedPlanFor(
    geometry_mod.Geometry,
    layout.Layout,
    topology,
    proof_bundle.Bundle,
    transcript.Schedule,
    Policy,
);

test "Plonk prepared plan seals all three proof trees" {
    const geometry = try geometry_mod.admit(
        .{ .log_n_rows = 8 },
        @import("stwo_core").pcs.PcsConfig.default(),
    );
    var prepared = try PreparedPlan.init(
        std.testing.allocator,
        geometry,
    );
    defer prepared.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        @as(usize, 3),
        prepared.logical.trace_trees.len,
    );
    try std.testing.expectEqual(
        @as(usize, 3),
        prepared.decommit.trace_trees.len,
    );
    try std.testing.expectEqual(
        slots.proof_bundle,
        prepared.proofSlot(),
    );
    try std.testing.expect(
        prepared.totalWords() <= requirements.max_total_words,
    );
}
