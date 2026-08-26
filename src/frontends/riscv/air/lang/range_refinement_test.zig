const std = @import("std");
const digest = @import("digest.zig");
const effects = @import("effects.zig");
const ir = @import("ir.zig");
const manifest = @import("manifest.zig");
const range_refinement = @import("range_refinement.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const validate = @import("validate.zig");
const range_test_support = @import("range_refinement_test_support.zig");

const Fixture = range_test_support.Fixture;

test "range refinement closes direct fields derived 884 and aligned control target" {
    var fixture = try buildFixture(std.testing.allocator);
    defer fixture.deinit();
    try validate.validate(&fixture.arena);
    try std.testing.expectEqual(@as(usize, 4), fixture.arena.effectsView().len);
    try std.testing.expectEqual(@as(usize, 2), fixture.arena.range_refinements.items.len);
    try std.testing.expectEqual(@as(usize, 4), fixture.arena.fixed_table_requests.items.len);
    try std.testing.expectEqual(types.Type.pc, fixture.arena.node(fixture.pc).?.key.ty);
}

test "range refinement rejects wrong request gate expression bound order omission and coordination" {
    {
        var fixture = try buildFixture(std.testing.allocator);
        defer fixture.deinit();
        fixture.arena.fixed_table_requests.items[0].liveness = fixture.high;
        try std.testing.expectError(error.InvalidRangeRefinement, validate.validate(&fixture.arena));
    }
    {
        var fixture = try buildFixture(std.testing.allocator);
        defer fixture.deinit();
        std.mem.swap(
            @TypeOf(fixture.arena.fixed_table_requests.items[0]),
            &fixture.arena.fixed_table_requests.items[0],
            &fixture.arena.fixed_table_requests.items[1],
        );
        try std.testing.expectError(error.InvalidRangeRefinement, validate.validate(&fixture.arena));
    }
    {
        var fixture = try buildFixture(std.testing.allocator);
        defer fixture.deinit();
        _ = fixture.arena.range_refinements.pop();
        try std.testing.expectError(error.InvalidNodeShape, validate.validate(&fixture.arena));
    }
    {
        var fixture = try buildFixture(std.testing.allocator);
        defer fixture.deinit();
        const proof = &fixture.arena.range_refinements.items[1].premise.aligned_control_target;
        proof.low_effect = fixture.high_request.effect;
        try std.testing.expectError(error.InvalidRangeRefinement, validate.validate(&fixture.arena));
    }
    {
        var fixture = try buildFixture(std.testing.allocator);
        defer fixture.deinit();
        const item = &fixture.arena.range_refinements.items[0];
        item.source = fixture.low;
        item.premise.fixed_table_field.field_index = 0;
        try std.testing.expectError(error.InvalidRangeRefinement, validate.validate(&fixture.arena));
    }
}

test "range refinement construction rolls back every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

test "outer-refined 884 request binds exact field types and proof order" {
    var fixture = try buildOuter884Fixture(std.testing.allocator);
    defer fixture.arena.deinit();
    try validate.validate(&fixture.arena);

    try std.testing.expectEqual(@as(usize, 1), fixture.arena.effectsView().len);
    try std.testing.expectEqual(@as(usize, 1), fixture.arena.fixed_table_requests.items.len);
    try std.testing.expectEqual(@as(usize, 2), fixture.arena.range_refinements.items.len);
    const fields = fixture.request.fields();
    try std.testing.expectEqual(@as(usize, 3), fields.len);
    try std.testing.expectEqual(types.Type.byte, fixture.arena.node(fields[0]).?.key.ty);
    try std.testing.expectEqual(types.Type.byte, fixture.arena.node(fields[1]).?.key.ty);
    try std.testing.expectEqual(
        try types.Type.boundedField(4),
        fixture.arena.node(fields[2]).?.key.ty,
    );
    try std.testing.expectEqual(fixture.middle, fields[1]);
    try std.testing.expectEqual(fixture.first, fixture.arena.range_refinements.items[0].source);
    try std.testing.expectEqual(fields[0], fixture.arena.range_refinements.items[0].target);
    try std.testing.expectEqual(
        @as(u8, 0),
        fixture.arena.range_refinements.items[0].premise.fixed_table_field.field_index,
    );
    try std.testing.expectEqual(fixture.third, fixture.arena.range_refinements.items[1].source);
    try std.testing.expectEqual(fields[2], fixture.arena.range_refinements.items[1].target);
    try std.testing.expectEqual(
        @as(u8, 2),
        fixture.arena.range_refinements.items[1].premise.fixed_table_field.field_index,
    );
}

test "outer-refined 884 request rejects invalid source types and liveness" {
    const span = source.SourceSpan.generated();
    {
        var arena = ir.Arena.init(std.testing.allocator);
        defer arena.deinit();
        const active = try arena.input("active", .selector, span);
        const first = try arena.input("first", .word32, span);
        const middle = try arena.input("middle", .byte, span);
        const third = try arena.input("third", .felt, span);
        try std.testing.expectError(
            error.InvalidRefinementSource,
            range_refinement.rangeCheck884OuterRefined(
                &arena,
                first,
                middle,
                third,
                active,
                span,
            ),
        );
    }
    {
        var arena = ir.Arena.init(std.testing.allocator);
        defer arena.deinit();
        const active = try arena.input("active", .selector, span);
        const first = try arena.input("first", .felt, span);
        const middle = try arena.input("middle", .felt, span);
        const third = try arena.input("third", .felt, span);
        try std.testing.expectError(
            error.InvalidRefinementSource,
            range_refinement.rangeCheck884OuterRefined(
                &arena,
                first,
                middle,
                third,
                active,
                span,
            ),
        );
    }
    {
        var arena = ir.Arena.init(std.testing.allocator);
        defer arena.deinit();
        const inactive = try arena.input("inactive", .felt, span);
        const first = try arena.input("first", .felt, span);
        const middle = try arena.input("middle", .byte, span);
        const third = try arena.input("third", .felt, span);
        try std.testing.expectError(
            error.InvalidLiveness,
            range_refinement.rangeCheck884OuterRefined(
                &arena,
                first,
                middle,
                third,
                inactive,
                span,
            ),
        );
    }
}

test "outer-refined 884 proof forgeries reject" {
    {
        var fixture = try buildOuter884Fixture(std.testing.allocator);
        defer fixture.arena.deinit();
        fixture.arena.range_refinements.items[0].premise.fixed_table_field.field_index = 2;
        try std.testing.expectError(error.InvalidRangeRefinement, validate.validate(&fixture.arena));
    }
    {
        var fixture = try buildOuter884Fixture(std.testing.allocator);
        defer fixture.arena.deinit();
        fixture.arena.range_refinements.items[1].premise.fixed_table_field.field_index = 1;
        try std.testing.expectError(error.InvalidRangeRefinement, validate.validate(&fixture.arena));
    }
    {
        var fixture = try buildOuter884Fixture(std.testing.allocator);
        defer fixture.arena.deinit();
        fixture.arena.range_refinements.items[1].premise.fixed_table_field.liveness = fixture.middle;
        try std.testing.expectError(error.InvalidRangeRefinement, validate.validate(&fixture.arena));
    }
    {
        var fixture = try buildOuter884Fixture(std.testing.allocator);
        defer fixture.arena.deinit();
        _ = fixture.arena.fixed_table_requests.pop();
        try std.testing.expectError(error.InvalidRangeRefinement, validate.validate(&fixture.arena));
    }
    {
        var fixture = try buildOuter884Fixture(std.testing.allocator);
        defer fixture.arena.deinit();
        std.mem.swap(
            @TypeOf(fixture.arena.range_refinements.items[0]),
            &fixture.arena.range_refinements.items[0],
            &fixture.arena.range_refinements.items[1],
        );
        try std.testing.expectError(error.InvalidRangeRefinement, validate.validate(&fixture.arena));
    }
}

test "outer-refined 884 construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        outer884AllocationFailureCase,
        .{},
    );
}

test "range refinement advances canonical manifest and semantic identity domains" {
    var fixture = try buildFixture(std.testing.allocator);
    defer fixture.deinit();
    const identity = try digest.computeIdentity(&fixture.arena);
    try std.testing.expectEqual(digest.range_refinement_format_version, identity.format_version);
    try std.testing.expectError(error.InvalidEffect, digest.computeV6(&fixture.arena));
    try std.testing.expectError(
        error.RangeRefinementRequiresManifestV9,
        manifest.serializeAllocV8(std.testing.allocator, &fixture.arena),
    );
    const v9 = try manifest.serializeAllocV9(std.testing.allocator, &fixture.arena);
    defer std.testing.allocator.free(v9);
    const current = try manifest.serializeAllocCurrent(std.testing.allocator, &fixture.arena);
    defer std.testing.allocator.free(current);
    try std.testing.expectEqualSlices(u8, v9, current);
}

test "aligned control target is admitted only as the proof-matched retirement pc" {
    {
        var fixture = try buildFixture(std.testing.allocator);
        defer fixture.deinit();
        const span = source.SourceSpan.generated();
        const current_pc = try fixture.arena.input("current_pc", .pc, span);
        const current_clock = try fixture.arena.input("current_clock", .clock, span);
        const next_clock = try fixture.arena.instructionNextClock(current_clock, span);
        _ = try effects.retire(
            &fixture.arena,
            .{ .pc = current_pc, .clock = current_clock },
            .{ .pc = fixture.pc, .clock = next_clock },
            fixture.active,
            span,
        );
        try validate.validate(&fixture.arena);

        fixture.arena.range_refinements.items[1].premise.aligned_control_target.liveness =
            try fixture.arena.input("other_active", .selector, span);
        try std.testing.expectError(error.InvalidEffect, validate.validate(&fixture.arena));
    }
    {
        var fixture = try buildFixture(std.testing.allocator);
        defer fixture.deinit();
        const span = source.SourceSpan.generated();
        const current_pc = try fixture.arena.input("current_pc", .pc, span);
        const current_clock = try fixture.arena.input("current_clock", .clock, span);
        const other_active = try fixture.arena.input("other_active", .selector, span);
        _ = try effects.retire(
            &fixture.arena,
            .{ .pc = current_pc, .clock = current_clock },
            .{ .pc = fixture.pc, .clock = current_clock },
            other_active,
            span,
        );
        try std.testing.expectError(error.InvalidEffect, validate.validate(&fixture.arena));
    }
    {
        var fixture = try buildFixture(std.testing.allocator);
        defer fixture.deinit();
        const span = source.SourceSpan.generated();
        _ = try fixture.arena.select(
            fixture.active,
            fixture.pc,
            try fixture.arena.input("other_pc", .pc, span),
            span,
        );
        try std.testing.expectError(error.InvalidEffect, validate.validate(&fixture.arena));
    }
}

test "program control target adds only closed logical evidence" {
    var fixture = try buildJumpControlFixture(std.testing.allocator);
    defer fixture.deinit();
    try validate.validate(&fixture.arena);

    try std.testing.expectEqual(@as(usize, 0), fixture.direct_constraints_before);
    try std.testing.expectEqual(@as(usize, 0), fixture.arena.constraintsView().len);
    try std.testing.expectEqual(@as(usize, 1), fixture.effects_before);
    try std.testing.expectEqual(@as(usize, 3), fixture.arena.effectsView().len);
    try std.testing.expectEqual(@as(usize, 1), fixture.arena.range_refinements.items.len);
    try std.testing.expectEqual(@as(usize, 0), fixture.arena.fixed_table_requests.items.len);
    try std.testing.expectEqual(types.Type.pc, fixture.arena.node(fixture.target).?.key.ty);
}

test "program control target admits exact jump and conditional branch polynomials" {
    {
        var fixture = try buildJumpControlFixture(std.testing.allocator);
        defer fixture.deinit();
        try validate.validate(&fixture.arena);
        const proof = fixture.arena.range_refinements.items[0]
            .premise.program_control_target;
        try std.testing.expectEqual(fixture.program_effect, proof.program_effect);
        try std.testing.expectEqual(fixture.current_pc, proof.current_pc);
        try std.testing.expectEqual(fixture.offset, proof.offset);
        try std.testing.expectEqual(fixture.active, proof.liveness);
        switch (proof.kind) {
            .jump => {},
            else => return error.ExpectedProgramJumpTarget,
        }
    }
    {
        var fixture = try buildBranchControlFixture(std.testing.allocator);
        defer fixture.deinit();
        try validate.validate(&fixture.arena);
        const proof = fixture.arena.range_refinements.items[0]
            .premise.program_control_target;
        switch (proof.kind) {
            .branch => |branch| {
                try std.testing.expectEqual(fixture.condition, branch.condition);
                try std.testing.expectEqual(
                    fixture.condition_constraint,
                    branch.condition_constraint,
                );
            },
            else => return error.ExpectedProgramBranchTarget,
        }
    }
}

test "program control target rejects forged tuple proof polynomial and retirement edges" {
    {
        var fixture = try buildJumpControlFixture(std.testing.allocator);
        defer fixture.deinit();
        const other_offset = try fixture.arena.input(
            "other_offset",
            .felt,
            source.SourceSpan.generated(),
        );
        fixture.arena.range_refinements.items[0]
            .premise.program_control_target.offset = other_offset;
        try std.testing.expectError(
            error.InvalidNodeShape,
            validate.validate(&fixture.arena),
        );
    }
    {
        var fixture = try buildJumpControlFixture(std.testing.allocator);
        defer fixture.deinit();
        const other_active = try fixture.arena.input(
            "other_active",
            .selector,
            source.SourceSpan.generated(),
        );
        fixture.arena.range_refinements.items[0]
            .premise.program_control_target.liveness = other_active;
        try std.testing.expectError(error.InvalidEffect, validate.validate(&fixture.arena));
    }
    {
        var fixture = try buildJumpControlFixture(std.testing.allocator);
        defer fixture.deinit();
        fixture.arena.range_refinements.items[0].source = fixture.offset;
        try std.testing.expectError(
            error.InvalidNodeShape,
            validate.validate(&fixture.arena),
        );
    }
    {
        var fixture = try buildBranchControlFixture(std.testing.allocator);
        defer fixture.deinit();
        const span = source.SourceSpan.generated();
        const other = try fixture.arena.input("other_condition", .bit, span);
        const one = try fixture.arena.constantField(1, span);
        const other_constraint = try fixture.arena.assertZero(
            "test.other_condition.boolean",
            try fixture.arena.mul(other, try fixture.arena.sub(one, other, span), span),
            null,
            .semantic,
            span,
        );
        fixture.arena.range_refinements.items[0]
            .premise.program_control_target.kind.branch.condition_constraint =
            other_constraint;
        try std.testing.expectError(
            error.InvalidRangeRefinement,
            validate.validate(&fixture.arena),
        );
    }
    {
        var fixture = try buildJumpControlFixture(std.testing.allocator);
        defer fixture.deinit();
        const later = try effects.programFetch(
            &fixture.arena,
            .{
                .pc = fixture.current_pc,
                .opcode_id = fixture.opcode,
                .rd = fixture.rd,
                .rs1 = fixture.offset,
                .operand = fixture.zero,
            },
            fixture.active,
            source.SourceSpan.generated(),
        );
        fixture.arena.range_refinements.items[0]
            .premise.program_control_target.program_effect = later;
        try std.testing.expectError(error.InvalidEffect, validate.validate(&fixture.arena));
    }
    {
        var fixture = try buildJumpControlFixture(std.testing.allocator);
        defer fixture.deinit();
        _ = try fixture.arena.select(
            fixture.active,
            fixture.target,
            fixture.current_pc,
            source.SourceSpan.generated(),
        );
        try std.testing.expectError(error.InvalidEffect, validate.validate(&fixture.arena));
    }
    {
        var fixture = try buildJumpControlFixture(std.testing.allocator);
        defer fixture.deinit();
        _ = fixture.arena.range_refinements.pop();
        try std.testing.expectError(error.InvalidNodeShape, validate.validate(&fixture.arena));
    }
}

test "program control target advances identity v9 and manifest v11 only" {
    var fixture = try buildJumpControlFixture(std.testing.allocator);
    defer fixture.deinit();
    const identity = try digest.computeIdentity(&fixture.arena);
    try std.testing.expectEqual(
        digest.program_control_target_format_version,
        identity.format_version,
    );
    try std.testing.expectEqual(
        try digest.computeV9(&fixture.arena),
        identity.bytes,
    );
    try std.testing.expectError(error.InvalidEffect, digest.computeV7(&fixture.arena));
    try std.testing.expectError(
        error.ProgramControlTargetRequiresManifestV11,
        manifest.serializeAllocV9(std.testing.allocator, &fixture.arena),
    );
    try std.testing.expectError(
        error.ProgramControlTargetRequiresManifestV11,
        manifest.serializeAllocV10(std.testing.allocator, &fixture.arena),
    );
    const v11 = try manifest.serializeAllocV11(std.testing.allocator, &fixture.arena);
    defer std.testing.allocator.free(v11);
    const current = try manifest.serializeAllocCurrent(std.testing.allocator, &fixture.arena);
    defer std.testing.allocator.free(current);
    try std.testing.expectEqualSlices(u8, v11, current);
}

test "program control target construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        programControlAllocationFailureCase,
        .{},
    );
}

test "committed program control target adds proof metadata only" {
    var fixture = try buildCommittedControlFixture(std.testing.allocator);
    defer fixture.deinit();
    try validate.validate(&fixture.arena);

    try std.testing.expectEqual(
        fixture.nodes_before,
        fixture.nodes_after_authority,
    );
    try std.testing.expectEqual(
        fixture.nodes_before + 1,
        fixture.arena.nodesView().len,
    );
    try std.testing.expectEqual(
        fixture.constraints_before,
        fixture.arena.constraintsView().len,
    );
    try std.testing.expectEqual(
        fixture.effects_before + 2,
        fixture.arena.effectsView().len,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        fixture.arena.committed_program_control_targets.items.len,
    );
    try std.testing.expectEqual(fixture.target, fixture.authorized_target);
}

test "committed program control target rejects tuple shadow root and use forgeries" {
    {
        var fixture = try buildCommittedControlFixture(std.testing.allocator);
        defer fixture.deinit();
        fixture.arena.committed_program_control_targets.items[0].offset =
            fixture.condition;
        try std.testing.expectError(
            error.InvalidEffect,
            validate.validate(&fixture.arena),
        );
    }
    {
        var fixture = try buildCommittedControlFixture(std.testing.allocator);
        defer fixture.deinit();
        fixture.arena.committed_program_control_targets.items[0]
            .current_pc_polynomial = fixture.target_polynomial;
        try std.testing.expectError(
            error.InvalidEffect,
            validate.validate(&fixture.arena),
        );
    }
    {
        var fixture = try buildCommittedControlFixture(std.testing.allocator);
        defer fixture.deinit();
        fixture.arena.committed_program_control_targets.items[0]
            .condition_constraint = fixture.target_constraint;
        try std.testing.expectError(
            error.InvalidEffect,
            validate.validate(&fixture.arena),
        );
    }
    {
        var fixture = try buildCommittedControlFixture(std.testing.allocator);
        defer fixture.deinit();
        fixture.arena.committed_program_control_targets.items[0]
            .target_constraint = fixture.condition_constraint;
        try std.testing.expectError(
            error.InvalidEffect,
            validate.validate(&fixture.arena),
        );
    }
    {
        var fixture = try buildCommittedControlFixture(std.testing.allocator);
        defer fixture.deinit();
        fixture.arena.committed_program_control_targets.items[0]
            .committed_target_polynomial = fixture.current_pc_polynomial;
        try std.testing.expectError(
            error.InvalidEffect,
            validate.validate(&fixture.arena),
        );
    }
    {
        var fixture = try buildCommittedControlFixture(std.testing.allocator);
        defer fixture.deinit();
        _ = fixture.arena.committed_program_control_targets.pop();
        try std.testing.expectError(
            error.InvalidEffect,
            validate.validate(&fixture.arena),
        );
    }
    {
        var fixture = try buildCommittedControlFixture(std.testing.allocator);
        defer fixture.deinit();
        _ = try fixture.arena.add(
            fixture.target_polynomial,
            fixture.offset,
            source.SourceSpan.generated(),
        );
        try std.testing.expectError(
            error.InvalidEffect,
            validate.validate(&fixture.arena),
        );
    }
    {
        var fixture = try buildCommittedControlFixture(std.testing.allocator);
        defer fixture.deinit();
        // Copy before appending to the same list: passing `items[0]` directly
        // would let a capacity-growing append invalidate its own argument.
        const duplicate = fixture.arena.committed_program_control_targets.items[0];
        try fixture.arena.committed_program_control_targets.append(
            fixture.arena.allocator,
            duplicate,
        );
        try std.testing.expectError(
            // Duplicate ownership makes the closed target non-singular, so
            // machine-use validation rejects it before terminal refinement
            // metadata validation runs.
            error.InvalidEffect,
            validate.validate(&fixture.arena),
        );
    }
}

test "committed program control target advances identity v10 and manifest v12 only" {
    var fixture = try buildCommittedControlFixture(std.testing.allocator);
    defer fixture.deinit();
    const identity = try digest.computeIdentity(&fixture.arena);
    try std.testing.expectEqual(
        digest.committed_program_control_target_format_version,
        identity.format_version,
    );
    try std.testing.expectEqual(
        try digest.computeV10(&fixture.arena),
        identity.bytes,
    );
    try std.testing.expectError(error.InvalidEffect, digest.computeV9(&fixture.arena));
    try std.testing.expectError(
        error.CommittedProgramControlTargetRequiresManifestV12,
        manifest.serializeAllocV11(std.testing.allocator, &fixture.arena),
    );
    const v12 = try manifest.serializeAllocV12(std.testing.allocator, &fixture.arena);
    defer std.testing.allocator.free(v12);
    const current = try manifest.serializeAllocCurrent(std.testing.allocator, &fixture.arena);
    defer std.testing.allocator.free(current);
    try std.testing.expectEqualSlices(u8, v12, current);
}

test "committed program control target construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        committedControlAllocationFailureCase,
        .{},
    );
}

const allocationFailureCase = range_test_support.allocationFailureCase;
const outer884AllocationFailureCase = range_test_support.outer884AllocationFailureCase;
const programControlAllocationFailureCase = range_test_support.programControlAllocationFailureCase;
const committedControlAllocationFailureCase = range_test_support.committedControlAllocationFailureCase;
const CommittedControlFixture = range_test_support.CommittedControlFixture;
const buildCommittedControlFixture = range_test_support.buildCommittedControlFixture;
const JumpControlFixture = range_test_support.JumpControlFixture;
const buildJumpControlFixture = range_test_support.buildJumpControlFixture;
const BranchControlFixture = range_test_support.BranchControlFixture;
const buildBranchControlFixture = range_test_support.buildBranchControlFixture;
const Outer884Fixture = range_test_support.Outer884Fixture;
const buildOuter884Fixture = range_test_support.buildOuter884Fixture;
const buildFixture = range_test_support.buildFixture;
