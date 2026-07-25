//! Prepared ingress plan for the resident Native Poseidon executor.
//!
//! This module seals memory and structural topology. Runtime execution and
//! external proof-oracle gates remain owned by their narrower modules.

const std = @import("std");
const arena = @import("../../../backends/cuda/runtime/arena.zig");
const cuda_plan_mod = @import(
    "../../../backends/cuda/runtime/execution_plan.zig",
);
const telemetry = @import("../../../backends/cuda/runtime/telemetry.zig");
const canonical_ingress = @import("canonical_ingress.zig");
const layout_mod = @import("layout.zig");
const program_mod = @import("program.zig");
const proof_bundle = @import("proof_bundle.zig");
const geometry_mod = @import("geometry.zig");
const requirements_mod = @import("requirements.zig");
const shared = @import("../common/prepared_plan.zig");
const slots = @import("slots.zig");
const topology = @import("topology.zig");
const transcript_schedule = @import("transcript_schedule.zig");

/// Reusable host authority for values uploaded during ingress. It is separate
/// from `PreparedPlan` so structural planning never rebuilds canonical
/// twiddles and a persistent proof session can retain one pack across requests.
pub const CanonicalIngress = canonical_ingress.Pack;

const Policy = struct {
    pub fn buildRequirements(
        allocator: std.mem.Allocator,
        geometry: geometry_mod.Geometry,
        quotient: topology.Quotient,
        fri: topology.Fri,
        decommit: topology.Decommit,
        proof: proof_bundle.Bundle,
    ) ![]arena.Requirement {
        return requirements_mod.build(
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
        logical: layout_mod.Layout,
        quotient: topology.Quotient,
        fri: topology.Fri,
        requirements: []const arena.Requirement,
    ) !@import("stwo_backend_contracts").proof_program.ProofProgram {
        return program_mod.emit(
            allocator,
            geometry,
            logical,
            quotient,
            fri,
            requirements,
        );
    }

    pub fn proofSlot() arena.SlotId {
        return slots.proof_bundle;
    }

    pub fn maxTotalWords() usize {
        return requirements_mod.max_total_words;
    }

    pub fn defaultTarget() cuda_plan_mod.CompileOptions {
        return testTarget();
    }
};

pub const PreparedPlan = shared.PreparedPlanFor(
    geometry_mod.Geometry,
    layout_mod.Layout,
    topology,
    proof_bundle.Bundle,
    transcript_schedule.Schedule,
    Policy,
);

test "prepared plans seal small standard and large admitted geometry" {
    const allocator = std.testing.allocator;
    var previous_words: usize = 0;
    for ([_]u32{ 3, 10, 18 }) |log_n_rows| {
        const geometry = try geometry_mod.admitRequest(testRequest(log_n_rows));
        var prepared = try PreparedPlan.initForTarget(
            allocator,
            geometry,
            testTarget(),
        );
        defer prepared.deinit(allocator);
        try std.testing.expectEqual(
            @as(usize, log_n_rows),
            prepared.fri.layers.len,
        );
        try std.testing.expectEqual(
            geometry.decommit_tree_count,
            prepared.decommit.fri_trees.len + 2,
        );
        try std.testing.expect(prepared.totalWords() > 0);
        try std.testing.expect(prepared.totalWords() > previous_words);
        previous_words = prepared.totalWords();
        try std.testing.expect(
            prepared.totalWords() <= requirements_mod.max_total_words,
        );
        try std.testing.expectEqual(
            88 + 3 * @as(usize, log_n_rows),
            prepared.requirements().len,
        );
        const inverse_twiddles = try prepared.cuda_plan.arena_plan.placement(
            slots.twiddles_inverse,
        );
        try std.testing.expectEqual(
            geometry.commitment_rows,
            inverse_twiddles.requirement.words,
        );
        try std.testing.expectEqual(
            telemetry.Stage.ingress,
            inverse_twiddles.requirement.live_from,
        );
        try std.testing.expectEqual(
            telemetry.Stage.fri_commit,
            inverse_twiddles.requirement.live_through,
        );
        const last_evaluation = try prepared.cuda_plan.arena_plan.placement(
            slots.fri_last_evaluation,
        );
        try std.testing.expectEqual(
            @as(usize, 8),
            last_evaluation.requirement.words,
        );
        try std.testing.expectEqual(
            telemetry.Stage.fri_commit,
            last_evaluation.requirement.live_from,
        );
        try std.testing.expectEqual(
            telemetry.Stage.fri_commit,
            last_evaluation.requirement.live_through,
        );
        const last_coefficients = try prepared.cuda_plan.arena_plan.placement(
            slots.fri_last_coefficients,
        );
        try std.testing.expect(
            try last_evaluation.endWords() <= last_coefficients.offset_words or
                try last_coefficients.endWords() <= last_evaluation.offset_words,
        );
        const input_snapshot = try prepared.cuda_plan.arena_plan.placement(
            slots.transcript_input_snapshot,
        );
        const boundary_snapshot = try prepared.cuda_plan.arena_plan.placement(
            slots.transcript_boundary_snapshot,
        );
        try std.testing.expectEqual(
            telemetry.Stage.ingress,
            input_snapshot.requirement.live_from,
        );
        try std.testing.expectEqual(
            telemetry.Stage.ingress,
            boundary_snapshot.requirement.live_from,
        );
        const quotient_challenge = try prepared.cuda_plan.arena_plan.placement(
            slots.quotient_challenge,
        );
        try std.testing.expectEqual(
            telemetry.Stage.oods,
            quotient_challenge.requirement.live_from,
        );
        try std.testing.expectEqual(
            telemetry.Stage.quotient,
            quotient_challenge.requirement.live_through,
        );
        const coefficient_log_sizes = try prepared.cuda_plan.arena_plan.placement(
            slots.coefficient_log_sizes,
        );
        try std.testing.expectEqual(
            telemetry.Stage.constraint_evaluation,
            coefficient_log_sizes.requirement.live_through,
        );
        const main_coefficients = try prepared.cuda_plan.arena_plan.placement(
            slots.main_coefficients,
        );
        try std.testing.expectEqual(
            geometry.main_columns * try geometry.traceRowCount(),
            main_coefficients.requirement.words,
        );
        try std.testing.expectEqual(
            telemetry.Stage.trace_generation,
            main_coefficients.requirement.live_from,
        );
        const relation_sources =
            try prepared.cuda_plan.arena_plan.placement(
                slots.relation_source_values,
            );
        try std.testing.expectEqual(
            @as(usize, 256) * geometry.trace_rows,
            relation_sources.requirement.words,
        );
        const constraint_sources =
            try prepared.cuda_plan.arena_plan.placement(
                slots.constraint_source_evaluations,
            );
        try std.testing.expectEqual(
            @as(usize, 1296) * geometry.composition_rows,
            constraint_sources.requirement.words,
        );
        const interaction_coefficients =
            try prepared.cuda_plan.arena_plan.placement(
                slots.interaction_coefficients,
            );
        try std.testing.expectEqual(
            @as(usize, geometry_mod.interaction_columns) *
                try geometry.traceRowCount(),
            interaction_coefficients.requirement.words,
        );
        const composition_coefficients =
            try prepared.cuda_plan.arena_plan.placement(
                slots.composition_coefficients,
            );
        try std.testing.expectEqual(
            @as(usize, geometry_mod.composition_columns) *
                try geometry.traceRowCount(),
            composition_coefficients.requirement.words,
        );
        try std.testing.expectError(
            error.ArenaSlotMissing,
            prepared.cuda_plan.arena_plan.placement(0x0200),
        );
        for ([_]arena.SlotId{
            0x0102,
            0x0111,
            0x0207,
            0x0210,
            0x0211,
            0x0504,
        }) |retired_slot| {
            try std.testing.expectError(
                error.ArenaSlotMissing,
                prepared.cuda_plan.arena_plan.placement(retired_slot),
            );
        }
        try std.testing.expectEqual(
            prepared.proof.total_words +
                geometry_mod.terminal_statement_words,
            (try prepared.cuda_plan.arena_plan.placement(slots.proof_bundle))
                .requirement.words,
        );
        try prepared.proof.validate(prepared.decommit.assembly_words);
    }
}

test "concurrent arena lifetimes never overlap" {
    const allocator = std.testing.allocator;
    const geometry = try geometry_mod.admitRequest(testRequest(14));
    var prepared = try PreparedPlan.initForTarget(
        allocator,
        geometry,
        testTarget(),
    );
    defer prepared.deinit(allocator);

    const placements = prepared.cuda_plan.arena_plan.placements;
    for (placements, 0..) |left, index| {
        for (placements[index + 1 ..]) |right| {
            if (!lifetimesOverlap(left.requirement, right.requirement)) continue;
            try std.testing.expect(
                try left.endWords() <= right.offset_words or
                    try right.endWords() <= left.offset_words,
            );
        }
    }
}

test "topology slots contain no device pointer table allocations" {
    const allocator = std.testing.allocator;
    const geometry = try geometry_mod.admitRequest(testRequest(14));
    var prepared = try PreparedPlan.initForTarget(
        allocator,
        geometry,
        testTarget(),
    );
    defer prepared.deinit(allocator);

    try std.testing.expectError(
        error.ArenaSlotMissing,
        prepared.cuda_plan.arena_plan.placement(0x0900),
    );
}

fn lifetimesOverlap(left: arena.Requirement, right: arena.Requirement) bool {
    return left.live_from.index() <= right.live_through.index() and
        right.live_from.index() <= left.live_through.index();
}

fn testRequest(log_n_rows: u32) geometry_mod.Request {
    const pcs = @import("stwo_core").pcs;
    return .{
        .statement = .{ .log_n_instances = log_n_rows + 3 },
        .protocol = pcs.PcsConfig.default(),
    };
}

fn testTarget() cuda_plan_mod.CompileOptions {
    const proof_ir = @import("stwo_backend_contracts").proof_program;
    return .{
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
    };
}
