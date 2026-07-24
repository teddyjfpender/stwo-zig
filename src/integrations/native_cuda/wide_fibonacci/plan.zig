//! Prepared ingress plan for a future resident wide-Fibonacci executor.
//!
//! This module seals memory and structural topology only. It deliberately does
//! not claim kernel execution, proof parity, or oracle acceptance.

const std = @import("std");
const arena = @import("../../../backends/cuda/runtime/arena.zig");
const telemetry = @import("../../../backends/cuda/runtime/telemetry.zig");
const canonical_ingress = @import("canonical_ingress.zig");
const layout_mod = @import("layout.zig");
const proof_bundle = @import("proof_bundle.zig");
const request = @import("request.zig");
const requirements_mod = @import("requirements.zig");
const slots = @import("slots.zig");
const topology = @import("topology.zig");
const transcript_schedule = @import("transcript_schedule.zig");

pub const BindingId = enum {
    composition_split,
    canonical_proof_sections,
};

/// Reusable host authority for values uploaded during ingress. It is separate
/// from `PreparedPlan` so structural planning never rebuilds canonical
/// twiddles and a future proof session can retain one pack across requests.
pub const CanonicalIngress = canonical_ingress.Pack;

pub const DynamicBinding = struct {
    id: BindingId,
    stage: telemetry.Stage,
    requirement: []const u8,
};

/// These are the only values that admitted geometry cannot seal. Each entry is
/// protocol data derived by core Stwo or final proof assembly work.
pub const remaining_dynamic_bindings = [_]DynamicBinding{
    .{
        .id = .composition_split,
        .stage = .constraint_evaluation,
        .requirement = "bind the exact four-coordinate to eight-base-column split and coefficient transform",
    },
    .{
        .id = .canonical_proof_sections,
        .stage = .proof_assembly,
        .requirement = "assemble roots, sampled values, last FRI polynomial, nonce, and compact openings into canonical proof bytes",
    },
};

pub const PreparedPlan = struct {
    logical: layout_mod.Layout,
    quotient: topology.Quotient,
    fri: topology.Fri,
    decommit: topology.Decommit,
    proof: proof_bundle.Bundle,
    transcript: transcript_schedule.Schedule,
    requirement_storage: []arena.Requirement,
    arena_plan: arena.Plan,
    arena_plan_live: bool = true,

    pub fn init(
        allocator: std.mem.Allocator,
        geometry: request.Geometry,
    ) !PreparedPlan {
        var logical = try layout_mod.Layout.init(allocator, geometry);
        errdefer logical.deinit(allocator);
        try logical.validate();
        var quotient = try topology.Quotient.init(allocator, logical);
        errdefer quotient.deinit(allocator);
        var fri = try topology.Fri.init(allocator, logical);
        errdefer fri.deinit(allocator);
        var decommit = try topology.Decommit.init(allocator, logical);
        errdefer decommit.deinit(allocator);
        var proof = try proof_bundle.Bundle.init(allocator, logical, decommit);
        errdefer proof.deinit(allocator);
        try proof.validate(decommit.assembly_words);
        const requirement_storage = try requirements_mod.build(
            allocator,
            geometry,
            quotient,
            fri,
            decommit,
            proof,
        );
        errdefer allocator.free(requirement_storage);
        var planned = try arena.Plan.init(allocator, requirement_storage);
        errdefer planned.deinit(allocator);
        if (planned.total_words > requirements_mod.max_total_words)
            return error.SizeOverflow;
        return .{
            .logical = logical,
            .quotient = quotient,
            .fri = fri,
            .decommit = decommit,
            .proof = proof,
            .transcript = try transcript_schedule.Schedule.init(geometry),
            .requirement_storage = requirement_storage,
            .arena_plan = planned,
        };
    }

    pub fn deinit(self: *PreparedPlan, allocator: std.mem.Allocator) void {
        if (self.arena_plan_live) self.arena_plan.deinit(allocator);
        allocator.free(self.requirement_storage);
        self.proof.deinit(allocator);
        self.decommit.deinit(allocator);
        self.fri.deinit(allocator);
        self.quotient.deinit(allocator);
        self.logical.deinit(allocator);
        self.* = undefined;
    }

    pub fn requirements(self: *const PreparedPlan) []const arena.Requirement {
        return self.requirement_storage;
    }

    pub fn proofSlot(_: *const PreparedPlan) arena.SlotId {
        return slots.proof_bundle;
    }

    pub fn totalWords(self: *const PreparedPlan) usize {
        return self.arena_plan.total_words;
    }

    pub fn takeArenaPlan(self: *PreparedPlan) arena.Plan {
        std.debug.assert(self.arena_plan_live);
        self.arena_plan_live = false;
        return self.arena_plan;
    }
};

test "prepared plans seal small standard and extreme admitted geometry" {
    const allocator = std.testing.allocator;
    var previous_words: usize = 0;
    for ([_]u32{ 3, 14, 22 }) |log_n_rows| {
        const geometry = try request.admit(testRequest(log_n_rows));
        var prepared = try PreparedPlan.init(allocator, geometry);
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
            66 + 3 * @as(usize, log_n_rows),
            prepared.requirements().len,
        );
        const inverse_twiddles = try prepared.arena_plan.placement(
            slots.twiddles_inverse,
        );
        try std.testing.expectEqual(
            geometry.trace_rows,
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
        const last_evaluation = try prepared.arena_plan.placement(
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
        const last_coefficients = try prepared.arena_plan.placement(
            slots.fri_last_coefficients,
        );
        try std.testing.expect(
            try last_evaluation.endWords() <= last_coefficients.offset_words or
                try last_coefficients.endWords() <= last_evaluation.offset_words,
        );
        const input_snapshot = try prepared.arena_plan.placement(
            slots.transcript_input_snapshot,
        );
        const boundary_snapshot = try prepared.arena_plan.placement(
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
        const coefficient_slab = try prepared.arena_plan.placement(
            slots.coefficient_slab,
        );
        try std.testing.expectEqual(
            geometry.main_columns * (2 * geometry.trace_rows) +
                request.composition_column_count * geometry.trace_rows,
            coefficient_slab.requirement.words,
        );
        try std.testing.expectEqual(
            telemetry.Stage.trace_generation,
            coefficient_slab.requirement.live_from,
        );
        try std.testing.expectError(
            error.ArenaSlotMissing,
            prepared.arena_plan.placement(0x0200),
        );
        for ([_]arena.SlotId{ 0x0102, 0x0111, 0x0504 }) |retired_slot| {
            try std.testing.expectError(
                error.ArenaSlotMissing,
                prepared.arena_plan.placement(retired_slot),
            );
        }
        try std.testing.expectEqual(
            prepared.proof.total_words,
            (try prepared.arena_plan.placement(slots.proof_bundle))
                .requirement.words,
        );
        try prepared.proof.validate(prepared.decommit.assembly_words);
    }
}

test "concurrent lifetimes never overlap and stage-local commitment scratch aliases" {
    const allocator = std.testing.allocator;
    const geometry = try request.admit(testRequest(14));
    var prepared = try PreparedPlan.init(allocator, geometry);
    defer prepared.deinit(allocator);

    const placements = prepared.arena_plan.placements;
    for (placements, 0..) |left, index| {
        for (placements[index + 1 ..]) |right| {
            if (!lifetimesOverlap(left.requirement, right.requirement)) continue;
            try std.testing.expect(
                try left.endWords() <= right.offset_words or
                    try right.endWords() <= left.offset_words,
            );
        }
    }
    const main = try prepared.arena_plan.placement(slots.main_commit_states);
    const composition = try prepared.arena_plan.placement(
        slots.composition_commit_states,
    );
    try std.testing.expectEqual(main.requirement.words, composition.requirement.words);
    try std.testing.expectEqual(main.offset_words, composition.offset_words);
}

test "topology slots contain no device pointer table allocations" {
    const allocator = std.testing.allocator;
    const geometry = try request.admit(testRequest(14));
    var prepared = try PreparedPlan.init(allocator, geometry);
    defer prepared.deinit(allocator);

    try std.testing.expectError(
        error.ArenaSlotMissing,
        prepared.arena_plan.placement(0x0900),
    );
    try std.testing.expectEqual(@as(usize, 2), remaining_dynamic_bindings.len);
    for (remaining_dynamic_bindings, 0..) |binding, index| {
        for (remaining_dynamic_bindings[0..index]) |previous| {
            try std.testing.expect(binding.id != previous.id);
        }
    }
}

fn lifetimesOverlap(left: arena.Requirement, right: arena.Requirement) bool {
    return left.live_from.index() <= right.live_through.index() and
        right.live_from.index() <= left.live_through.index();
}

fn testRequest(log_n_rows: u32) request.Request {
    return .{
        .statement = .{ .log_n_rows = log_n_rows, .sequence_len = 100 },
        .protocol = .{
            .pow_bits = 10,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
            .fold_step = 1,
            .lifting_log_size = null,
        },
    };
}
