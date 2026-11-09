//! Shared fixtures for range-refinement adversarial suites.

const std = @import("std");
const digest = @import("digest.zig");
const effects = @import("effects.zig");
const ir = @import("ir.zig");
const manifest = @import("manifest.zig");
const range_refinement = @import("range_refinement.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const validate = @import("validate.zig");

pub const Fixture = struct {
    arena: ir.Arena,
    active: types.ValueId,
    low: types.ValueId,
    high: types.ValueId,
    low_request: range_refinement.Request,
    high_request: range_refinement.Request,
    nibble_request: range_refinement.Request,
    byte_request: range_refinement.Request,
    pc: types.ValueId,

    pub fn deinit(self: *Fixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var fixture = try buildFixture(allocator);
    defer fixture.deinit();
    try validate.validate(&fixture.arena);
}

pub fn outer884AllocationFailureCase(allocator: std.mem.Allocator) !void {
    var fixture = try buildOuter884Fixture(allocator);
    defer fixture.arena.deinit();
    try validate.validate(&fixture.arena);
}

pub fn programControlAllocationFailureCase(allocator: std.mem.Allocator) !void {
    var fixture = try buildJumpControlFixture(allocator);
    defer fixture.deinit();
    try validate.validate(&fixture.arena);
}

pub fn committedControlAllocationFailureCase(allocator: std.mem.Allocator) !void {
    var fixture = try buildCommittedControlFixture(allocator);
    defer fixture.deinit();
    try validate.validate(&fixture.arena);
}

pub const CommittedControlFixture = struct {
    arena: ir.Arena,
    active_source: types.ValueId,
    active: types.ValueId,
    current_pc: types.ValueId,
    current_pc_polynomial: types.ValueId,
    offset: types.ValueId,
    condition: types.ValueId,
    condition_constraint: types.ConstraintId,
    target: types.ValueId,
    target_polynomial: types.ValueId,
    target_constraint: types.ConstraintId,
    authorized_target: types.ValueId,
    nodes_before: usize,
    nodes_after_authority: usize,
    constraints_before: usize,
    effects_before: usize,

    pub fn deinit(self: *CommittedControlFixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub fn buildCommittedControlFixture(
    allocator: std.mem.Allocator,
) !CommittedControlFixture {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = source.SourceSpan.generated();
    const active_source = try arena.input("committed_active", .felt, span);
    const current_pc = try arena.input("committed_current_pc", .pc, span);
    const current_pc_polynomial = try arena.input(
        "committed_current_pc_polynomial",
        .felt,
        span,
    );
    const clock = try arena.input("committed_clock", .clock, span);
    const offset = try arena.input("committed_offset", .felt, span);
    const condition = try arena.input("committed_condition", .bit, span);
    const target = try arena.input("committed_target", .pc, span);
    const target_polynomial = try arena.input(
        "committed_target_polynomial",
        .felt,
        span,
    );
    const rs1 = try arena.input("committed_rs1", .register_index, span);
    const rs2 = try arena.input("committed_rs2", .register_index, span);
    const one = try arena.constantField(1, span);
    const four = try arena.constantField(4, span);
    const active_constraint = try arena.assertZero(
        "test.committed.active.boolean",
        try arena.mul(
            active_source,
            try arena.sub(one, active_source, span),
            span,
        ),
        null,
        .semantic,
        span,
    );
    const active = try range_refinement.booleanFromConstraint(
        &arena,
        active_source,
        active_constraint,
        span,
    );
    const condition_constraint = try arena.assertZero(
        "test.committed.condition.boolean",
        try arena.mul(condition, try arena.sub(one, condition, span), span),
        null,
        .semantic,
        span,
    );
    const taken = try arena.mul(offset, condition, span);
    var selected = try arena.add(current_pc_polynomial, taken, span);
    selected = try arena.add(
        selected,
        try arena.mul(four, try arena.sub(one, condition, span), span),
        span,
    );
    const target_constraint = try arena.assertZero(
        "test.committed.target",
        try arena.mul(
            active_source,
            try arena.sub(target_polynomial, selected, span),
            span,
        ),
        null,
        .semantic,
        span,
    );
    const program_effect = try effects.programFetch(&arena, .{
        .pc = current_pc,
        .opcode_id = try arena.constantField(27, span),
        .rd = rs1,
        .rs1 = rs2,
        .operand = offset,
    }, active, span);
    const nodes_before = arena.nodesView().len;
    const constraints_before = arena.constraintsView().len;
    const effects_before = arena.effectsView().len;
    const authorized_target = try range_refinement.committedProgramControlTarget(
        &arena,
        program_effect,
        current_pc,
        current_pc_polynomial,
        offset,
        condition,
        condition_constraint,
        target,
        target_polynomial,
        target_constraint,
        active,
        span,
    );
    const nodes_after_authority = arena.nodesView().len;
    _ = try effects.retire(
        &arena,
        .{ .pc = current_pc, .clock = clock },
        .{
            .pc = authorized_target,
            .clock = try arena.instructionNextClock(clock, span),
        },
        active,
        span,
    );
    return .{
        .arena = arena,
        .active_source = active_source,
        .active = active,
        .current_pc = current_pc,
        .current_pc_polynomial = current_pc_polynomial,
        .offset = offset,
        .condition = condition,
        .condition_constraint = condition_constraint,
        .target = target,
        .target_polynomial = target_polynomial,
        .target_constraint = target_constraint,
        .authorized_target = authorized_target,
        .nodes_before = nodes_before,
        .nodes_after_authority = nodes_after_authority,
        .constraints_before = constraints_before,
        .effects_before = effects_before,
    };
}

pub const JumpControlFixture = struct {
    arena: ir.Arena,
    active: types.ValueId,
    current_pc: types.ValueId,
    offset: types.ValueId,
    opcode: types.ValueId,
    rd: types.ValueId,
    zero: types.ValueId,
    program_effect: types.EffectId,
    target: types.ValueId,
    direct_constraints_before: usize,
    effects_before: usize,

    pub fn deinit(self: *JumpControlFixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub fn buildJumpControlFixture(allocator: std.mem.Allocator) !JumpControlFixture {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = source.SourceSpan.generated();
    const active = try arena.input("active", .selector, span);
    const current_pc = try arena.input("current_pc", .pc, span);
    const clock = try arena.input("clock", .clock, span);
    const offset = try arena.input("offset", .felt, span);
    const rd = try arena.input("rd", .register_index, span);
    const opcode = try arena.constantField(33, span);
    const zero = try arena.constantField(0, span);
    const program_effect = try effects.programFetch(&arena, .{
        .pc = current_pc,
        .opcode_id = opcode,
        .rd = rd,
        .rs1 = offset,
        .operand = zero,
    }, active, span);
    const direct_constraints_before = arena.constraintsView().len;
    const effects_before = arena.effectsView().len;
    const target = try range_refinement.programControlTarget(
        &arena,
        program_effect,
        current_pc,
        offset,
        .jump,
        active,
        span,
    );
    const next_clock = try arena.instructionNextClock(clock, span);
    _ = try effects.retire(
        &arena,
        .{ .pc = current_pc, .clock = clock },
        .{ .pc = target, .clock = next_clock },
        active,
        span,
    );
    return .{
        .arena = arena,
        .active = active,
        .current_pc = current_pc,
        .offset = offset,
        .opcode = opcode,
        .rd = rd,
        .zero = zero,
        .program_effect = program_effect,
        .target = target,
        .direct_constraints_before = direct_constraints_before,
        .effects_before = effects_before,
    };
}

pub const BranchControlFixture = struct {
    arena: ir.Arena,
    condition: types.ValueId,
    condition_constraint: types.ConstraintId,

    pub fn deinit(self: *BranchControlFixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub fn buildBranchControlFixture(allocator: std.mem.Allocator) !BranchControlFixture {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = source.SourceSpan.generated();
    const active = try arena.input("active", .selector, span);
    const current_pc = try arena.input("current_pc", .pc, span);
    const clock = try arena.input("clock", .clock, span);
    const offset = try arena.input("offset", .felt, span);
    const condition = try arena.input("condition", .bit, span);
    const rs1 = try arena.input("rs1", .register_index, span);
    const rs2 = try arena.input("rs2", .register_index, span);
    const one = try arena.constantField(1, span);
    const condition_constraint = try arena.assertZero(
        "test.condition.boolean",
        try arena.mul(condition, try arena.sub(one, condition, span), span),
        null,
        .semantic,
        span,
    );
    const program_effect = try effects.programFetch(&arena, .{
        .pc = current_pc,
        .opcode_id = try arena.constantField(27, span),
        .rd = rs1,
        .rs1 = rs2,
        .operand = offset,
    }, active, span);
    const target = try range_refinement.programControlTarget(
        &arena,
        program_effect,
        current_pc,
        offset,
        .{ .branch = .{
            .condition = condition,
            .condition_constraint = condition_constraint,
        } },
        active,
        span,
    );
    _ = try effects.retire(
        &arena,
        .{ .pc = current_pc, .clock = clock },
        .{ .pc = target, .clock = try arena.instructionNextClock(clock, span) },
        active,
        span,
    );
    return .{
        .arena = arena,
        .condition = condition,
        .condition_constraint = condition_constraint,
    };
}

pub const Outer884Fixture = struct {
    arena: ir.Arena,
    active: types.ValueId,
    first: types.ValueId,
    middle: types.ValueId,
    third: types.ValueId,
    request: range_refinement.Request,
};

pub fn buildOuter884Fixture(allocator: std.mem.Allocator) !Outer884Fixture {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = source.SourceSpan.generated();
    const active = try arena.input("active", .selector, span);
    const signed_msb = try arena.input("signed_msb", .felt, span);
    const signed = try arena.input("signed", .bit, span);
    const middle = try arena.input("middle", .byte, span);
    const high3 = try arena.input("high3", try types.Type.boundedField(3), span);
    const first = try arena.add(
        signed_msb,
        try arena.mul(signed, try arena.constantField(128, span), span),
        span,
    );
    const third = try arena.mul(high3, try arena.constantField(2, span), span);
    const request = try range_refinement.rangeCheck884OuterRefined(
        &arena,
        first,
        middle,
        third,
        active,
        span,
    );
    return .{
        .arena = arena,
        .active = active,
        .first = first,
        .middle = middle,
        .third = third,
        .request = request,
    };
}

pub fn buildFixture(allocator: std.mem.Allocator) !Fixture {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = source.SourceSpan.generated();
    const active = try arena.input("active", .selector, span);
    const low = try arena.input("target_low20", .uint20, span);
    const high = try arena.input("target_high8", .byte, span);
    const high7 = try arena.input("target_high7", try types.Type.boundedField(7), span);
    const first = try arena.input("imm_first", .byte, span);
    const second = try arena.input("imm_second", .byte, span);
    const sign = try arena.input("imm_sign", .bit, span);
    const eight = try arena.constantField(8, span);
    const two = try arena.constantField(2, span);
    const raw_nibble = try arena.mul(
        try arena.sub(first, try arena.mul(sign, eight, span), span),
        two,
        span,
    );
    const low_request = try range_refinement.rangeCheck20Typed(&arena, low, active, span);
    const high_request = try range_refinement.rangeCheckM31Typed(
        &arena,
        high,
        high7,
        active,
        span,
    );
    const nibble_request = try range_refinement.rangeCheck884Refined(
        &arena,
        first,
        second,
        raw_nibble,
        active,
        span,
    );
    const byte_request = try range_refinement.rangeCheck88Typed(
        &arena,
        first,
        second,
        active,
        span,
    );
    const pc = try range_refinement.alignedControlTarget(
        &arena,
        low,
        high,
        low_request.effect,
        high_request.effect,
        active,
        span,
    );
    return .{
        .arena = arena,
        .active = active,
        .low = low,
        .high = high,
        .low_request = low_request,
        .high_request = high_request,
        .nibble_request = nibble_request,
        .byte_request = byte_request,
        .pc = pc,
    };
}
