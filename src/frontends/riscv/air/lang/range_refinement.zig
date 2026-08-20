//! Closed, proof-carrying range refinements for derived AIR polynomials.
//!
//! A refinement is never a cast. The target clones the source operation, so
//! both IDs lower to the same polynomial, while an arena-owned record names
//! the constraint or fixed-table request that proves the stronger type.

const std = @import("std");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const MAX_REFINED_FIELDS: usize = 3;

pub const Error = ir.Error || relation.Error || error{
    CircularRefinement,
    DuplicateRefinementTarget,
    InvalidBooleanPremise,
    InvalidFieldIndex,
    InvalidFixedTablePremise,
    InvalidLiveness,
    InvalidProgramControlPremise,
    InvalidRefinementOrder,
    InvalidRefinementSource,
    InvalidRefinementTarget,
    MissingRefinementEvidence,
    UnsupportedRefinementType,
};

pub const Request = struct {
    effect: types.EffectId,
    values: [MAX_REFINED_FIELDS]types.ValueId,
    arity: u8,

    pub fn fields(self: *const Request) []const types.ValueId {
        return self.values[0..self.arity];
    }
};

const FieldInput = union(enum) {
    typed: types.ValueId,
    refine: types.ValueId,
};

const runtime = @import("range_refinement_runtime.zig").Runtime(.{
    .MAX_REFINED_FIELDS = MAX_REFINED_FIELDS,
    .Error = Error,
    .Request = Request,
    .FieldInput = FieldInput,
    .isBoundedLiveness = isBoundedLiveness,
    .isTarget = isTarget,
    .effectHasFixedPremise = effectHasFixedPremise,
});
const binaryOperands = runtime.binaryOperands;
const booleanRefinementSource = runtime.booleanRefinementSource;
const committedControlExpression = runtime.committedControlExpression;
const exactBinary = runtime.exactBinary;
const exactBranchTarget = runtime.exactBranchTarget;
const fixedRequest = runtime.fixedRequest;
const isBooleanConstraint = runtime.isBooleanConstraint;
const isTakenPc = runtime.isTakenPc;
const requestOwns = runtime.requestOwns;
const requireFreshTarget = runtime.requireFreshTarget;
const requireType = runtime.requireType;
const validateCommittedProgramControlTarget = runtime.validateCommittedProgramControlTarget;
const validateControlTarget = runtime.validateControlTarget;
const validateFixedPremise = runtime.validateFixedPremise;
const validateIdentity = runtime.validateIdentity;
const validateProgramControlEffect = runtime.validateProgramControlEffect;
const validateProgramControlTarget = runtime.validateProgramControlTarget;
const validateRequestProof = runtime.validateRequestProof;

pub const ProgramControlTargetKind = program.ProgramControlTargetKind;

/// Refine a scalar to a selector using an existing, ungated canonical
/// `x * (1 - x) = 0` (or sign-equivalent) constraint as the named premise.
pub fn booleanFromConstraint(
    arena: *ir.Arena,
    value: types.ValueId,
    constraint: types.ConstraintId,
    span: source.SourceSpan,
) Error!types.ValueId {
    try arena.validateSpan(span);
    const source_node = try booleanRefinementSource(arena, value);
    if (!isBooleanConstraint(arena, value, constraint))
        return error.InvalidBooleanPremise;
    const key = expr.Key{ .ty = .selector, .op = source_node.key.op };
    try requireFreshTarget(arena, key);
    try arena.ensureUnusedNodeCapacity(1);
    try arena.range_refinements.ensureUnusedCapacity(arena.allocator, 1);
    const node_checkpoint = arena.nodeCheckpoint();
    const refinement_checkpoint = arena.range_refinements.items.len;
    errdefer {
        arena.range_refinements.shrinkRetainingCapacity(refinement_checkpoint);
        arena.rollbackToNodeCheckpoint(node_checkpoint);
    }
    const target = try arena.internTypedNode(key, span);
    arena.range_refinements.appendAssumeCapacity(.{
        .source = value,
        .target = target,
        .premise = .{ .constraint_boolean = .{ .constraint = constraint } },
        .source_span = span,
    });
    return target;
}

pub fn rangeCheck20(
    arena: *ir.Arena,
    value: types.ValueId,
    liveness: types.ValueId,
    span: source.SourceSpan,
) Error!Request {
    return fixedRequest(arena, .range_check_20, &.{.{ .refine = value }}, liveness, span);
}

pub fn rangeCheck20Typed(
    arena: *ir.Arena,
    value: types.ValueId,
    liveness: types.ValueId,
    span: source.SourceSpan,
) Error!Request {
    return fixedRequest(arena, .range_check_20, &.{.{ .typed = value }}, liveness, span);
}

pub fn rangeCheck811(
    arena: *ir.Arena,
    low_byte: types.ValueId,
    high: types.ValueId,
    liveness: types.ValueId,
    span: source.SourceSpan,
) Error!Request {
    return fixedRequest(arena, .range_check_8_11, &.{
        .{ .typed = low_byte }, .{ .refine = high },
    }, liveness, span);
}

pub fn rangeCheckM31(
    arena: *ir.Arena,
    low_byte: types.ValueId,
    high: types.ValueId,
    liveness: types.ValueId,
    span: source.SourceSpan,
) Error!Request {
    return fixedRequest(arena, .range_check_m31, &.{
        .{ .typed = low_byte }, .{ .refine = high },
    }, liveness, span);
}

pub fn rangeCheckM31Typed(
    arena: *ir.Arena,
    low_byte: types.ValueId,
    high: types.ValueId,
    liveness: types.ValueId,
    span: source.SourceSpan,
) Error!Request {
    return fixedRequest(arena, .range_check_m31, &.{
        .{ .typed = low_byte }, .{ .typed = high },
    }, liveness, span);
}

pub fn rangeCheck88Refined(
    arena: *ir.Arena,
    first: types.ValueId,
    second: types.ValueId,
    liveness: types.ValueId,
    span: source.SourceSpan,
) Error!Request {
    return fixedRequest(arena, .range_check_8_8, &.{
        .{ .refine = first }, .{ .refine = second },
    }, liveness, span);
}

pub fn rangeCheck88Typed(
    arena: *ir.Arena,
    first: types.ValueId,
    second: types.ValueId,
    liveness: types.ValueId,
    span: source.SourceSpan,
) Error!Request {
    return fixedRequest(arena, .range_check_8_8, &.{
        .{ .typed = first }, .{ .typed = second },
    }, liveness, span);
}

pub fn rangeCheck884Refined(
    arena: *ir.Arena,
    first_byte: types.ValueId,
    second_byte: types.ValueId,
    low_nibble: types.ValueId,
    liveness: types.ValueId,
    span: source.SourceSpan,
) Error!Request {
    return fixedRequest(arena, .range_check_8_8_4, &.{
        .{ .typed = first_byte }, .{ .typed = second_byte }, .{ .refine = low_nibble },
    }, liveness, span);
}

/// Request `range_check_8_8_4@1` when both outer coordinates are derived
/// polynomials. The fixed table proves the first coordinate is a byte and the
/// third is a canonical nibble; the middle coordinate must already be a typed
/// byte. This deliberately narrow surface covers signed-comparison witnesses
/// without exposing the general fixed-request constructor.
pub fn rangeCheck884OuterRefined(
    arena: *ir.Arena,
    first_byte: types.ValueId,
    second_byte: types.ValueId,
    low_nibble: types.ValueId,
    liveness: types.ValueId,
    span: source.SourceSpan,
) Error!Request {
    return fixedRequest(arena, .range_check_8_8_4, &.{
        .{ .refine = first_byte },
        .{ .typed = second_byte },
        .{ .refine = low_nibble },
    }, liveness, span);
}

/// Construct the exact aligned RV32 control target
/// `4 * (low20 + 2^20 * high8)` and refine it to `.pc`. Both committed limbs
/// must be owned by named fixed-table requests with identical liveness.
pub fn alignedControlTarget(
    arena: *ir.Arena,
    low: types.ValueId,
    high: types.ValueId,
    low_effect: types.EffectId,
    high_effect: types.EffectId,
    liveness: types.ValueId,
    span: source.SourceSpan,
) Error!types.ValueId {
    try arena.validateSpan(span);
    try requireType(arena, low, .uint20);
    try requireType(arena, high, .byte);
    if (!requestOwns(arena, low_effect, low, liveness) or
        !requestOwns(arena, high_effect, high, liveness))
    {
        return error.InvalidFixedTablePremise;
    }
    const checkpoint = arena.nodeCheckpoint();
    const refinement_checkpoint = arena.range_refinements.items.len;
    errdefer {
        arena.range_refinements.shrinkRetainingCapacity(refinement_checkpoint);
        arena.rollbackToNodeCheckpoint(checkpoint);
    }
    try arena.ensureUnusedNodeCapacity(5);
    try arena.range_refinements.ensureUnusedCapacity(arena.allocator, 1);
    const scale = try arena.constantUnsigned(try types.Type.boundedField(21), 1 << 20, span);
    const four = try arena.constantUnsigned(try types.Type.boundedField(3), 4, span);
    const high_shifted = try arena.boundedMul(high, scale, span);
    const word = try arena.boundedAdd(low, high_shifted, span);
    const polynomial = try arena.boundedMul(word, four, span);
    const polynomial_node = arena.node(polynomial) orelse return error.UnknownValue;
    const key = expr.Key{ .ty = .pc, .op = polynomial_node.key.op };
    try requireFreshTarget(arena, key);
    const target = try arena.internTypedNode(key, span);
    arena.range_refinements.appendAssumeCapacity(.{
        .source = polynomial,
        .target = target,
        .premise = .{ .aligned_control_target = .{
            .low = low,
            .high = high,
            .low_effect = low_effect,
            .high_effect = high_effect,
            .liveness = liveness,
        } },
        .source_span = span,
    });
    return target;
}

/// Refine one of the two reviewed program-authenticated control polynomials to
/// `.pc` without adding a column, constraint, lookup, or witness operation.
///
/// `jump` is exactly `current_pc + offset`, with `offset` bound to field three
/// of the named JAL program tuple and field four fixed to zero. `branch` is
/// exactly `current_pc + offset * condition + 4 * (1 - condition)`, with the
/// offset bound to field four of the named branch tuple and a named direct
/// boolean constraint proving `condition`. Whole-program machine validation
/// additionally restricts the result to the matching adjacent retirement.
pub fn programControlTarget(
    arena: *ir.Arena,
    program_effect: types.EffectId,
    current_pc: types.ValueId,
    offset: types.ValueId,
    kind: ProgramControlTargetKind,
    liveness: types.ValueId,
    span: source.SourceSpan,
) Error!types.ValueId {
    try arena.validateSpan(span);
    try validateProgramControlEffect(
        arena,
        program_effect,
        current_pc,
        offset,
        kind,
        liveness,
    );

    // The conditional form creates at most six scalar nodes plus the typed
    // alias. Reserve once so the complete operation is allocation-atomic.
    try arena.ensureUnusedNodeCapacity(7);
    try arena.range_refinements.ensureUnusedCapacity(arena.allocator, 1);
    const checkpoint = arena.nodeCheckpoint();
    const refinement_checkpoint = arena.range_refinements.items.len;
    errdefer {
        arena.range_refinements.shrinkRetainingCapacity(refinement_checkpoint);
        arena.rollbackToNodeCheckpoint(checkpoint);
    }

    const polynomial = switch (kind) {
        .jump => try addPcPolynomial(arena, current_pc, offset, span),
        .branch => |branch| blk: {
            const one = try arena.constantField(1, span);
            const four = try arena.constantField(4, span);
            const taken = try arena.mul(offset, branch.condition, span);
            const taken_pc = try addPcPolynomial(arena, current_pc, taken, span);
            const not_taken = try arena.sub(one, branch.condition, span);
            const fallthrough = try arena.mul(four, not_taken, span);
            break :blk try arena.add(taken_pc, fallthrough, span);
        },
    };
    const polynomial_node = arena.node(polynomial) orelse
        return error.UnknownValue;
    const key = expr.Key{ .ty = .pc, .op = polynomial_node.key.op };
    try requireFreshTarget(arena, key);
    const target = try arena.internTypedNode(key, span);
    arena.range_refinements.appendAssumeCapacity(.{
        .source = polynomial,
        .target = target,
        .premise = .{ .program_control_target = .{
            .program_effect = program_effect,
            .current_pc = current_pc,
            .offset = offset,
            .kind = kind,
            .liveness = liveness,
        } },
        .source_span = span,
    });
    return target;
}

/// Authenticate an exact branch target that already occupies a committed
/// physical `.pc` column. This appends proof metadata only: no node,
/// constraint, lookup, column, or witness operation is created.
///
/// Compatibility direct programs carry scalar views of physical PC columns so
/// their shipped polynomial DAG can remain byte-exact. The proof binds both
/// views, the program tuple, the named decision-bit constraint, and the named
/// gated target equality. Machine validation separately confines the physical
/// target to the adjacent state-produce field.
pub fn committedProgramControlTarget(
    arena: *ir.Arena,
    program_effect: types.EffectId,
    current_pc: types.ValueId,
    current_pc_polynomial: types.ValueId,
    offset: types.ValueId,
    condition: types.ValueId,
    condition_constraint: types.ConstraintId,
    committed_target: types.ValueId,
    committed_target_polynomial: types.ValueId,
    target_constraint: types.ConstraintId,
    liveness: types.ValueId,
    span: source.SourceSpan,
) Error!types.ValueId {
    try arena.validateSpan(span);
    const proof = program.CommittedProgramControlTargetProof{
        .program_effect = program_effect,
        .current_pc = current_pc,
        .current_pc_polynomial = current_pc_polynomial,
        .offset = offset,
        .condition = condition,
        .condition_constraint = condition_constraint,
        .committed_target = committed_target,
        .committed_target_polynomial = committed_target_polynomial,
        .target_constraint = target_constraint,
        .liveness = liveness,
        .source_span = span,
    };
    try validateCommittedProgramControlTarget(arena, proof);
    for (arena.committed_program_control_targets.items) |existing| {
        if (existing.committed_target == committed_target)
            return error.DuplicateRefinementTarget;
    }
    try arena.committed_program_control_targets.ensureUnusedCapacity(
        arena.allocator,
        1,
    );
    arena.committed_program_control_targets.appendAssumeCapacity(proof);
    return committed_target;
}

/// Narrow scalar view for a PC addition. General field arithmetic continues
/// to reject `.pc`; this node is well-formed only while owned by the terminal
/// `program_control_target` proof appended by the caller above.
fn addPcPolynomial(
    arena: *ir.Arena,
    current_pc: types.ValueId,
    scalar: types.ValueId,
    span: source.SourceSpan,
) Error!types.ValueId {
    try requireType(arena, current_pc, .pc);
    const scalar_node = arena.node(scalar) orelse return error.UnknownValue;
    if (!scalar_node.key.ty.isFieldScalar())
        return error.InvalidProgramControlPremise;
    var operands = expr.Binary{ .lhs = current_pc, .rhs = scalar };
    if (types.idIndex(operands.rhs) < types.idIndex(operands.lhs))
        std.mem.swap(types.ValueId, &operands.lhs, &operands.rhs);
    return arena.internTypedNode(.{
        .ty = .felt,
        .op = .{ .add = operands },
    }, span);
}

/// True only for selectors/bits or an exact difference of two unit-bounded
/// values. The latter is a signed unit multiplicity, not a selector claim.
pub fn isBoundedLiveness(arena: *const ir.Arena, value: types.ValueId) bool {
    const node = arena.node(value) orelse return false;
    if (node.key.ty.isSelector()) return true;
    if (!std.meta.eql(node.key.ty, types.Type.felt)) return false;
    const operands = switch (node.key.op) {
        .sub => |binary| binary,
        else => return false,
    };
    const lhs = arena.node(operands.lhs) orelse return false;
    const rhs = arena.node(operands.rhs) orelse return false;
    return lhs.key.ty.isSelector() and rhs.key.ty.isSelector();
}

pub fn isTarget(arena: *const ir.Arena, value: types.ValueId) bool {
    for (arena.range_refinements.items) |item| if (item.target == value) return true;
    return false;
}

pub fn sourceForTarget(arena: *const ir.Arena, target: types.ValueId) ?types.ValueId {
    for (arena.range_refinements.items) |item| if (item.target == target)
        return item.source;
    return null;
}

/// Structural capability probe for validators that run before the complete
/// refinement evidence graph is checked. A true result is not proof validity;
/// `validateProgram` remains the authority for that decision.
pub fn hasAlignedControlTargetPremise(
    arena: *const ir.Arena,
    value: types.ValueId,
    liveness: types.ValueId,
) bool {
    const premise_liveness = alignedControlTargetPremiseLiveness(arena, value) orelse
        return false;
    return premise_liveness == liveness;
}

pub fn alignedControlTargetPremiseLiveness(
    arena: *const ir.Arena,
    value: types.ValueId,
) ?types.ValueId {
    for (arena.range_refinements.items) |item| {
        if (item.target != value) continue;
        return switch (item.premise) {
            .aligned_control_target => |proof| proof.liveness,
            .program_control_target => null,
            else => null,
        };
    }
    return null;
}

pub fn programControlTargetPremise(
    arena: *const ir.Arena,
    value: types.ValueId,
    liveness: types.ValueId,
) ?@FieldType(program.RangeRefinementPremise, "program_control_target") {
    for (arena.range_refinements.items) |item| {
        if (item.target != value) continue;
        return switch (item.premise) {
            .program_control_target => |proof| if (proof.liveness == liveness)
                proof
            else
                null,
            else => null,
        };
    }
    return null;
}

pub fn programControlTargetPremiseLiveness(
    arena: *const ir.Arena,
    value: types.ValueId,
) ?types.ValueId {
    for (arena.range_refinements.items) |item| {
        if (item.target != value) continue;
        return switch (item.premise) {
            .program_control_target => |proof| proof.liveness,
            else => null,
        };
    }
    return null;
}

pub fn committedProgramControlTargetPremise(
    arena: *const ir.Arena,
    value: types.ValueId,
    liveness: types.ValueId,
) ?program.CommittedProgramControlTargetProof {
    for (arena.committed_program_control_targets.items) |proof| {
        if (proof.committed_target != value or proof.liveness != liveness)
            continue;
        validateCommittedProgramControlTarget(arena, proof) catch return null;
        return proof;
    }
    return null;
}

pub fn committedProgramControlTargetPremiseLiveness(
    arena: *const ir.Arena,
    value: types.ValueId,
) ?types.ValueId {
    for (arena.committed_program_control_targets.items) |proof| {
        if (proof.committed_target != value) continue;
        validateCommittedProgramControlTarget(arena, proof) catch return null;
        return proof.liveness;
    }
    return null;
}

pub const CommittedControlExpressionRole = enum {
    target_polynomial,
    difference,
    root,
};

/// A closed-role probe for the exact proof-owned expression chain. A true
/// result already implies that the complete proof record is structurally
/// valid; callers may then admit only the two canonical parent/child edges.
pub fn committedControlExpressionRole(
    arena: *const ir.Arena,
    value: types.ValueId,
) ?CommittedControlExpressionRole {
    for (arena.committed_program_control_targets.items) |proof| {
        validateCommittedProgramControlTarget(arena, proof) catch continue;
        const expression = committedControlExpression(arena, proof) orelse continue;
        if (value == proof.committed_target_polynomial)
            return .target_polynomial;
        if (value == expression.difference) return .difference;
        if (value == expression.root) return .root;
    }
    return null;
}

pub fn isCommittedControlExpressionEdge(
    arena: *const ir.Arena,
    parent: types.ValueId,
    child: types.ValueId,
) bool {
    for (arena.committed_program_control_targets.items) |proof| {
        validateCommittedProgramControlTarget(arena, proof) catch continue;
        const expression = committedControlExpression(arena, proof) orelse continue;
        if (child == proof.committed_target_polynomial and
            parent == expression.difference) return true;
        if (child == expression.difference and parent == expression.root)
            return true;
    }
    return false;
}

pub fn isCommittedControlConstraint(
    arena: *const ir.Arena,
    constraint_id: types.ConstraintId,
) bool {
    for (arena.committed_program_control_targets.items) |proof| {
        if (proof.target_constraint != constraint_id) continue;
        validateCommittedProgramControlTarget(arena, proof) catch return false;
        return true;
    }
    return false;
}

/// Structural probe used only by the arena's early node-shape pass. It admits
/// the one otherwise-forbidden `.pc + field` node owned by a complete
/// program-control proof. Terminal range-refinement and machine-use passes
/// independently validate the proof and its retirement edge.
pub fn isProgramControlPcAdd(
    arena: *const ir.Arena,
    value: types.ValueId,
) bool {
    for (arena.range_refinements.items) |item| switch (item.premise) {
        .program_control_target => |proof| switch (proof.kind) {
            .jump => if ((item.source == value or item.target == value) and exactBinary(
                arena,
                value,
                .add,
                proof.current_pc,
                proof.offset,
            )) return true,
            .branch => |branch| {
                if (!exactBranchTarget(
                    arena,
                    item.source,
                    proof.current_pc,
                    proof.offset,
                    branch.condition,
                )) continue;
                const top = binaryOperands(arena, item.source, .add) orelse continue;
                if ((top.lhs == value or top.rhs == value) and isTakenPc(
                    arena,
                    value,
                    proof.current_pc,
                    proof.offset,
                    branch.condition,
                )) return true;
            },
        },
        else => {},
    };
    return false;
}

pub fn effectHasFixedPremise(
    arena: *const ir.Arena,
    effect: types.EffectId,
) bool {
    for (arena.fixed_table_requests.items) |item| if (item.effect == effect) return true;
    return false;
}

/// Allocation-free defensive validation of the complete evidence graph.
pub fn validateProgram(arena: *const ir.Arena) Error!void {
    var previous_request: ?types.EffectId = null;
    for (arena.fixed_table_requests.items) |request| {
        try arena.validateSpan(request.source_span);
        if (previous_request) |prior| if (types.idIndex(prior) >= types.idIndex(request.effect))
            return error.InvalidRefinementOrder;
        previous_request = request.effect;
        try validateRequestProof(arena, request);
    }
    var previous_target: ?types.ValueId = null;
    var previous_fixed: ?struct { effect: types.EffectId, field: u8 } = null;
    for (arena.range_refinements.items) |item| {
        try arena.validateSpan(item.source_span);
        if (previous_target) |prior| if (types.idIndex(prior) >= types.idIndex(item.target))
            return error.InvalidRefinementOrder;
        previous_target = item.target;
        try validateIdentity(arena, item);
        for (arena.range_refinements.items) |other| {
            if (other.target == item.source) return error.CircularRefinement;
        }
        switch (item.premise) {
            .constraint_boolean => |proof| {
                if (previous_fixed != null) return error.InvalidRefinementOrder;
                const target = arena.node(item.target) orelse
                    return error.InvalidRefinementTarget;
                if (!std.meta.eql(target.key.ty, types.Type.selector) or
                    !isBooleanConstraint(arena, item.source, proof.constraint))
                {
                    return error.InvalidBooleanPremise;
                }
            },
            .fixed_table_field => |proof| {
                if (previous_fixed) |prior| {
                    const prior_effect = types.idIndex(prior.effect);
                    const effect_index = types.idIndex(proof.effect);
                    if (prior_effect > effect_index or
                        (prior_effect == effect_index and prior.field >= proof.field_index))
                    {
                        return error.InvalidRefinementOrder;
                    }
                }
                previous_fixed = .{ .effect = proof.effect, .field = proof.field_index };
                try validateFixedPremise(arena, item, proof);
            },
            .aligned_control_target => |proof| {
                previous_fixed = null;
                try validateControlTarget(arena, item, proof);
            },
            .program_control_target => {
                previous_fixed = null;
                try validateProgramControlTarget(arena, item, item.premise.program_control_target);
            },
        }
    }
    var previous_committed_target: ?types.ValueId = null;
    for (arena.committed_program_control_targets.items) |proof| {
        try arena.validateSpan(proof.source_span);
        if (previous_committed_target) |prior| {
            if (types.idIndex(prior) >= types.idIndex(proof.committed_target))
                return error.InvalidRefinementOrder;
        }
        previous_committed_target = proof.committed_target;
        try validateCommittedProgramControlTarget(arena, proof);
    }
}
