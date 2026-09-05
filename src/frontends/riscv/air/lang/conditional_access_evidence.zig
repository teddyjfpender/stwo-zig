//! Proof-premise validation for a conditional load/store access plan. This
//! half owns selector, address, range, and zero-column alias evidence; the
//! schedule half owns ordered relation effects and alias-use confinement.

const std = @import("std");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const types = @import("types.zig");

pub const Error = ir.Error || relation.Error || error{
    InvalidConditionalAccessAlias,
    InvalidConditionalAccessEffect,
    InvalidConditionalAccessProof,
};

pub fn validate(
    arena: *const ir.Arena,
    proof: program.ConditionalAccessPlanProof,
) Error!void {
    try validateSelectors(arena, proof);
    try validateAliases(arena, proof);
    try validateAddressConstraints(arena, proof);
    try validateRanges(arena, proof);
}

pub fn isStrictGap(
    arena: *const ir.Arena,
    gap: types.ValueId,
    current: types.ValueId,
    previous: types.ValueId,
) bool {
    const outer = binary(arena, gap, .sub) orelse return false;
    const inner = binary(arena, outer.lhs, .sub) orelse return false;
    return inner.lhs == current and inner.rhs == previous and
        isConstant(arena, outer.rhs, 1);
}

pub fn isZero(arena: *const ir.Arena, value: types.ValueId) bool {
    return isConstant(arena, value, 0);
}

fn validateSelectors(
    arena: *const ir.Arena,
    proof: program.ConditionalAccessPlanProof,
) Error!void {
    try requireType(arena, proof.active_source, .felt);
    try requireType(arena, proof.active, .selector);
    try requireType(arena, proof.store_source, .felt);
    try requireType(arena, proof.store_selector, .selector);
    try requireType(arena, proof.is_load, .felt);
    try requireType(arena, proof.instruction_clock, .clock);
    try requireType(arena, proof.second_clock, .felt);
    try requireType(arena, proof.register_index, .register_index);
    if (!sameOperation(arena, proof.active_source, proof.active) or
        !sameOperation(arena, proof.store_source, proof.store_selector) or
        !isSub(arena, proof.is_load, proof.active_source, proof.store_source) or
        !isAccessClockPolynomial(arena, proof.second_clock, proof.instruction_clock, 2))
    {
        return error.InvalidConditionalAccessProof;
    }

    var active_leaves: [8]types.ValueId = undefined;
    var active_len: usize = 0;
    try collectBitLeaves(arena, proof.active_source, &active_leaves, &active_len);
    var store_leaves: [8]types.ValueId = undefined;
    var store_len: usize = 0;
    try collectBitLeaves(arena, proof.store_source, &store_leaves, &store_len);
    if (active_len != 8 or store_len != 3)
        return error.InvalidConditionalAccessProof;
    for (active_leaves[0..active_len]) |leaf| if (!hasBooleanConstraint(arena, leaf))
        return error.InvalidConditionalAccessProof;
    for (store_leaves[0..store_len]) |leaf| {
        var found = false;
        for (active_leaves[0..active_len]) |candidate| found = found or candidate == leaf;
        if (!found) return error.InvalidConditionalAccessProof;
    }
    if (!hasBooleanRefinement(arena, proof.active_source, proof.active))
        return error.InvalidConditionalAccessProof;
}

fn validateAliases(
    arena: *const ir.Arena,
    proof: program.ConditionalAccessPlanProof,
) Error!void {
    const expected = [_]types.Type{
        .address, .clock, .uint20, .address, .clock, .uint20,
    };
    const items = [_]program.SemanticAlias{
        proof.source_address,
        proof.source_clock,
        proof.source_gap,
        proof.destination_address,
        proof.destination_clock,
        proof.destination_gap,
    };
    for (items, expected, 0..) |item, target_type, index| {
        const source_node = arena.node(item.source) orelse
            return error.InvalidConditionalAccessAlias;
        const target_node = arena.node(item.target) orelse
            return error.InvalidConditionalAccessAlias;
        if (types.idIndex(item.source) >= types.idIndex(item.target) or
            !std.meta.eql(source_node.key.ty, types.Type.felt) or
            !std.meta.eql(target_node.key.ty, target_type) or
            !std.meta.eql(source_node.key.op, target_node.key.op))
        {
            return error.InvalidConditionalAccessAlias;
        }
        for (items[0..index]) |prior| if (prior.target == item.target)
            return error.InvalidConditionalAccessAlias;
    }
    try requireInputAlias(arena, proof.source_address);
    try requireInputAlias(arena, proof.destination_address);
    if (!isAdd(arena, proof.source_clock.source, proof.second_clock, proof.is_load) or
        !isAdd(arena, proof.destination_clock.source, proof.second_clock, proof.store_source))
    {
        return error.InvalidConditionalAccessAlias;
    }
}

fn validateAddressConstraints(
    arena: *const ir.Arena,
    proof: program.ConditionalAccessPlanProof,
) Error!void {
    try requireType(arena, proof.memory_address, .felt);
    try requireType(arena, proof.shift_amount, .felt);
    try requireAddressConstraint(
        arena,
        proof.source_address_constraint,
        proof.source_address.source,
        proof.is_load,
        proof.store_source,
        proof.memory_address,
        proof.shift_amount,
        proof.register_index,
    );
    try requireAddressConstraint(
        arena,
        proof.destination_address_constraint,
        proof.destination_address.source,
        proof.store_source,
        proof.is_load,
        proof.memory_address,
        proof.shift_amount,
        proof.register_index,
    );
    if (!isWordIndexPolynomial(
        arena,
        proof.word_source,
        proof.source_address.source,
        proof.destination_address.source,
        proof.register_index,
    )) return error.InvalidConditionalAccessProof;
}

fn validateRanges(
    arena: *const ir.Arena,
    proof: program.ConditionalAccessPlanProof,
) Error!void {
    try requireType(arena, proof.word_index, try types.Type.boundedField(28));
    try requireType(arena, proof.base_low, .byte);
    try requireType(arena, proof.base_high, try types.Type.boundedField(7));
    const aligned_values = arena.effectValues(proof.aligned_range) orelse
        return error.InvalidConditionalAccessEffect;
    if (aligned_values.len != 1) return error.InvalidConditionalAccessEffect;
    const aligned_low20 = aligned_values[0];
    try requireType(arena, aligned_low20, .uint20);
    try requireFixedRange(
        arena,
        proof.aligned_range,
        .range_check_20,
        &.{aligned_low20},
        proof.active,
    );
    try requireFixedRange(
        arena,
        proof.base_range,
        .range_check_m31,
        &.{ proof.base_low, proof.base_high },
        proof.active,
    );
    if (!hasWideWordBinding(arena, proof, aligned_low20) or
        !hasBoundedBaseBinding(arena, proof))
    {
        return error.InvalidConditionalAccessProof;
    }
}

/// Authenticate the 28-bit committed word index without trusting its semantic
/// type. One direct root binds it to the selector-derived address polynomial;
/// the named low20 request plus one unique `(high8, 0)` request prove the exact
/// decomposition `word = low20 + 2^20 * high8`.
fn hasWideWordBinding(
    arena: *const ir.Arena,
    proof: program.ConditionalAccessPlanProof,
    low20: types.ValueId,
) bool {
    if (!isInput(arena, proof.word_index) or !isInput(arena, low20)) return false;

    var equality_count: usize = 0;
    for (arena.constraintsView()) |constraint| {
        if (constraint.gate != null or constraint.category != .semantic) continue;
        const product = binary(arena, constraint.root, .mul) orelse continue;
        const difference = if (product.lhs == proof.active_source)
            binary(arena, product.rhs, .sub)
        else if (product.rhs == proof.active_source)
            binary(arena, product.lhs, .sub)
        else
            null;
        const exact = difference orelse continue;
        if (exact.lhs == proof.word_index and exact.rhs == proof.word_source)
            equality_count += 1;
    }
    if (equality_count != 1) return false;

    var high_count: usize = 0;
    for (arena.range_refinements.items) |item| switch (item.premise) {
        .fixed_table_field => |fixed| {
            if (fixed.field_index != 0 or fixed.liveness != proof.active or
                !isWideHighSource(arena, item.source, proof.word_index, low20))
            {
                continue;
            }
            const effect = arena.effect(fixed.effect) orelse return false;
            const values = arena.effectValues(fixed.effect) orelse return false;
            if (effect.kind != .range_request or effect.liveness != proof.active or
                effect.access_ordinal != null or
                !bindingIs(effect.binding, .range_check_8_8, .request) or
                values.len != 2 or values[0] != item.target or
                !isTypedZero(arena, values[1], .byte) or
                !fixedProofOwns(arena, fixed.effect, proof.active))
            {
                return false;
            }
            high_count += 1;
        },
        else => {},
    };
    return high_count == 1;
}

fn hasBoundedBaseBinding(
    arena: *const ir.Arena,
    proof: program.ConditionalAccessPlanProof,
) bool {
    const first_values = arena.effectValues(proof.first_effect) orelse return false;
    if (first_values.len != 7 or proof.base_low != first_values[3]) return false;
    const base_top = first_values[6];
    var count: usize = 0;
    for (arena.range_refinements.items) |item| {
        if (item.target != proof.base_high) continue;
        const fixed = switch (item.premise) {
            .fixed_table_field => |value| value,
            else => return false,
        };
        if (fixed.effect != proof.base_range or fixed.field_index != 1 or
            fixed.liveness != proof.active or
            !isScaledBy(arena, item.source, base_top, 2))
        {
            return false;
        }
        count += 1;
    }
    return count == 1;
}

fn isWideHighSource(
    arena: *const ir.Arena,
    value: types.ValueId,
    word: types.ValueId,
    low20: types.ValueId,
) bool {
    const product = binary(arena, value, .mul) orelse return false;
    const difference_value = if (isConstant(arena, product.lhs, 1 << 11))
        product.rhs
    else if (isConstant(arena, product.rhs, 1 << 11))
        product.lhs
    else
        return false;
    const difference = binary(arena, difference_value, .sub) orelse return false;
    return difference.lhs == word and difference.rhs == low20;
}

fn isScaledBy(
    arena: *const ir.Arena,
    value: types.ValueId,
    source_value: types.ValueId,
    scale: u32,
) bool {
    const product = binary(arena, value, .mul) orelse return false;
    return (product.lhs == source_value and isConstant(arena, product.rhs, scale)) or
        (product.rhs == source_value and isConstant(arena, product.lhs, scale));
}

fn isInput(arena: *const ir.Arena, value: types.ValueId) bool {
    const node = arena.node(value) orelse return false;
    return switch (node.key.op) {
        .input => true,
        else => false,
    };
}

fn isTypedZero(
    arena: *const ir.Arena,
    value: types.ValueId,
    wanted_type: types.Type,
) bool {
    const node = arena.node(value) orelse return false;
    return std.meta.eql(node.key.ty, wanted_type) and isConstant(arena, value, 0);
}

fn requireAddressConstraint(
    arena: *const ir.Arena,
    constraint_id: types.ConstraintId,
    address: types.ValueId,
    memory_selector: types.ValueId,
    register_selector: types.ValueId,
    memory_address: types.ValueId,
    shift_amount: types.ValueId,
    register_index: types.ValueId,
) Error!void {
    const constraint = arena.constraint(constraint_id) orelse
        return error.InvalidConditionalAccessProof;
    if (constraint.gate != null or constraint.category != .semantic)
        return error.InvalidConditionalAccessProof;
    const root = arena.node(constraint.root) orelse
        return error.InvalidConditionalAccessProof;
    const difference = switch (root.key.op) {
        .sub => |operation| operation,
        else => return error.InvalidConditionalAccessProof,
    };
    if (difference.lhs != address)
        return error.InvalidConditionalAccessProof;
    const sum = binary(arena, difference.rhs, .add) orelse
        return error.InvalidConditionalAccessProof;
    const valid = (isMemoryTerm(
        arena,
        sum.lhs,
        memory_selector,
        memory_address,
        shift_amount,
    ) and isProduct(arena, sum.rhs, register_selector, register_index)) or
        (isMemoryTerm(
            arena,
            sum.rhs,
            memory_selector,
            memory_address,
            shift_amount,
        ) and isProduct(arena, sum.lhs, register_selector, register_index));
    if (!valid) return error.InvalidConditionalAccessProof;
}

fn isMemoryTerm(
    arena: *const ir.Arena,
    value: types.ValueId,
    selector: types.ValueId,
    address: types.ValueId,
    shift: types.ValueId,
) bool {
    const product = binary(arena, value, .mul) orelse return false;
    const difference = if (product.lhs == selector)
        product.rhs
    else if (product.rhs == selector)
        product.lhs
    else
        return false;
    return isSub(arena, difference, address, shift);
}

fn isWordIndexPolynomial(
    arena: *const ir.Arena,
    value: types.ValueId,
    source_address: types.ValueId,
    destination_address: types.ValueId,
    register_index: types.ValueId,
) bool {
    const product = binary(arena, value, .mul) orelse return false;
    const body = if (isConstant(arena, product.lhs, 1 << 29))
        product.rhs
    else if (isConstant(arena, product.rhs, 1 << 29))
        product.lhs
    else
        return false;
    const difference = binary(arena, body, .sub) orelse return false;
    const sum = binary(arena, difference.lhs, .add) orelse return false;
    return difference.rhs == register_index and
        ((sum.lhs == source_address and sum.rhs == destination_address) or
            (sum.rhs == source_address and sum.lhs == destination_address));
}

fn isAccessClockPolynomial(
    arena: *const ir.Arena,
    value: types.ValueId,
    clock: types.ValueId,
    phase: u32,
) bool {
    const sum = binary(arena, value, .add) orelse return false;
    const scaled = if (isConstant(arena, sum.lhs, phase))
        sum.rhs
    else if (isConstant(arena, sum.rhs, phase))
        sum.lhs
    else
        return false;
    const product = binary(arena, scaled, .mul) orelse return false;
    const shifted = if (isConstant(arena, product.lhs, 4))
        product.rhs
    else if (isConstant(arena, product.rhs, 4))
        product.lhs
    else
        return false;
    const difference = binary(arena, shifted, .sub) orelse return false;
    return difference.lhs == clock and isConstant(arena, difference.rhs, 1);
}

fn hasBooleanRefinement(
    arena: *const ir.Arena,
    source_value: types.ValueId,
    target: types.ValueId,
) bool {
    for (arena.range_refinements.items) |item| {
        if (item.source != source_value or item.target != target) continue;
        return switch (item.premise) {
            .constraint_boolean => true,
            else => false,
        };
    }
    return false;
}

fn hasFixedRefinement(
    arena: *const ir.Arena,
    source_value: types.ValueId,
    target: types.ValueId,
    effect: types.EffectId,
    field: u8,
    active: types.ValueId,
) bool {
    for (arena.range_refinements.items) |item| {
        if (item.source != source_value or item.target != target) continue;
        return switch (item.premise) {
            .fixed_table_field => |proof| proof.effect == effect and
                proof.field_index == field and proof.liveness == active,
            else => false,
        };
    }
    return false;
}

fn hasFixedRefinementTarget(
    arena: *const ir.Arena,
    target: types.ValueId,
    effect: types.EffectId,
    field: u8,
    active: types.ValueId,
) bool {
    for (arena.range_refinements.items) |item| if (item.target == target)
        return switch (item.premise) {
            .fixed_table_field => |proof| proof.effect == effect and
                proof.field_index == field and proof.liveness == active,
            else => false,
        };
    return false;
}

fn requireFixedRange(
    arena: *const ir.Arena,
    effect_id: types.EffectId,
    domain: relation.Domain,
    expected_values: []const types.ValueId,
    active: types.ValueId,
) Error!void {
    const effect = arena.effect(effect_id) orelse
        return error.InvalidConditionalAccessEffect;
    if (effect.kind != .range_request or effect.liveness != active or
        effect.access_ordinal != null or !bindingIs(effect.binding, domain, .request))
    {
        return error.InvalidConditionalAccessEffect;
    }
    const values = arena.effectValues(effect_id) orelse
        return error.InvalidConditionalAccessEffect;
    if (!std.mem.eql(types.ValueId, values, expected_values) or
        !fixedProofOwns(arena, effect_id, active))
    {
        return error.InvalidConditionalAccessEffect;
    }
    try validateRelation(arena, effect.binding.?, values, null);
}

fn fixedProofOwns(
    arena: *const ir.Arena,
    effect: types.EffectId,
    active: types.ValueId,
) bool {
    for (arena.fixed_table_requests.items) |proof|
        if (proof.effect == effect) return proof.liveness == active;
    return false;
}

fn validateRelation(
    arena: *const ir.Arena,
    binding_value: program.RelationBinding,
    values: []const types.ValueId,
    ordinal: ?u8,
) Error!void {
    const schema = relation.getById(binding_value.schema) orelse
        return error.UnknownSchema;
    if (schema.version != binding_value.schema_version)
        return error.InvalidConditionalAccessEffect;
    var field_types: [7]types.Type = undefined;
    if (values.len > field_types.len) return error.InvalidConditionalAccessEffect;
    for (values, field_types[0..values.len]) |value, *ty|
        ty.* = (arena.node(value) orelse return error.UnknownValue).key.ty;
    try relation.validateEvent(
        binding_value.schema,
        binding_value.role,
        field_types[0..values.len],
        ordinal,
    );
}

fn bindingIs(
    actual: ?program.RelationBinding,
    domain: relation.Domain,
    role: relation.Role,
) bool {
    const present = actual orelse return false;
    const schema = relation.get(domain);
    return present.schema == schema.id and present.schema_version == schema.version and
        present.role == role;
}

fn requireInputAlias(arena: *const ir.Arena, item: program.SemanticAlias) Error!void {
    const source_node = arena.node(item.source) orelse
        return error.InvalidConditionalAccessAlias;
    const target_node = arena.node(item.target) orelse
        return error.InvalidConditionalAccessAlias;
    switch (source_node.key.op) {
        .input => {},
        else => return error.InvalidConditionalAccessAlias,
    }
    switch (target_node.key.op) {
        .input => {},
        else => return error.InvalidConditionalAccessAlias,
    }
}

fn requireType(arena: *const ir.Arena, value: types.ValueId, wanted: types.Type) Error!void {
    const node = arena.node(value) orelse return error.UnknownValue;
    if (!std.meta.eql(node.key.ty, wanted)) return error.InvalidConditionalAccessProof;
}

fn sameOperation(arena: *const ir.Arena, lhs: types.ValueId, rhs: types.ValueId) bool {
    const lhs_node = arena.node(lhs) orelse return false;
    const rhs_node = arena.node(rhs) orelse return false;
    return std.meta.eql(lhs_node.key.op, rhs_node.key.op);
}

fn binary(
    arena: *const ir.Arena,
    value: types.ValueId,
    comptime operation: enum { add, sub, mul },
) ?expr.Binary {
    const node = arena.node(value) orelse return null;
    return switch (operation) {
        .add => switch (node.key.op) {
            .add => |item| item,
            else => null,
        },
        .sub => switch (node.key.op) {
            .sub => |item| item,
            else => null,
        },
        .mul => switch (node.key.op) {
            .mul => |item| item,
            else => null,
        },
    };
}

fn isAdd(arena: *const ir.Arena, value: types.ValueId, lhs: types.ValueId, rhs: types.ValueId) bool {
    const item = binary(arena, value, .add) orelse return false;
    return (item.lhs == lhs and item.rhs == rhs) or (item.lhs == rhs and item.rhs == lhs);
}

fn isSub(arena: *const ir.Arena, value: types.ValueId, lhs: types.ValueId, rhs: types.ValueId) bool {
    const item = binary(arena, value, .sub) orelse return false;
    return item.lhs == lhs and item.rhs == rhs;
}

fn isProduct(arena: *const ir.Arena, value: types.ValueId, lhs: types.ValueId, rhs: types.ValueId) bool {
    const item = binary(arena, value, .mul) orelse return false;
    return (item.lhs == lhs and item.rhs == rhs) or (item.lhs == rhs and item.rhs == lhs);
}

fn isConstant(arena: *const ir.Arena, value: types.ValueId, wanted: u32) bool {
    const node = arena.node(value) orelse return false;
    return switch (node.key.op) {
        .constant => |constant| switch (constant) {
            .field, .unsigned => |number| number == wanted,
        },
        else => false,
    };
}

fn collectBitLeaves(
    arena: *const ir.Arena,
    value: types.ValueId,
    out: *[8]types.ValueId,
    len: *usize,
) Error!void {
    const node = arena.node(value) orelse return error.InvalidConditionalAccessProof;
    if (std.meta.eql(node.key.ty, types.Type.bit)) {
        if (len.* == out.len) return error.InvalidConditionalAccessProof;
        for (out[0..len.*]) |prior| if (prior == value)
            return error.InvalidConditionalAccessProof;
        out[len.*] = value;
        len.* += 1;
        return;
    }
    const item = switch (node.key.op) {
        .add => |binary_value| binary_value,
        else => return error.InvalidConditionalAccessProof,
    };
    try collectBitLeaves(arena, item.lhs, out, len);
    try collectBitLeaves(arena, item.rhs, out, len);
}

fn hasBooleanConstraint(arena: *const ir.Arena, value: types.ValueId) bool {
    for (arena.constraintsView()) |constraint| {
        if (constraint.gate != null) continue;
        const product = binary(arena, constraint.root, .mul) orelse continue;
        const other = if (product.lhs == value)
            product.rhs
        else if (product.rhs == value)
            product.lhs
        else
            continue;
        const difference = binary(arena, other, .sub) orelse continue;
        if ((difference.lhs == value and isConstant(arena, difference.rhs, 1)) or
            (difference.rhs == value and isConstant(arena, difference.lhs, 1)))
        {
            return true;
        }
    }
    return false;
}
