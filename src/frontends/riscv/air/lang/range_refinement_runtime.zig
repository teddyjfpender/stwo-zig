//! Internal construction and fail-closed validation kernels for range refinement.

const std = @import("std");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const source = @import("source.zig");
const types = @import("types.zig");

/// Bind the runtime to the facade-owned public types and capability probes.
pub fn Runtime(comptime contract: anytype) type {
    return struct {
        const MAX_REFINED_FIELDS: usize = contract.MAX_REFINED_FIELDS;
        const Error = contract.Error;
        const Request = contract.Request;
        const FieldInput = contract.FieldInput;
        const ProgramControlTargetKind = program.ProgramControlTargetKind;
        const isBoundedLiveness = contract.isBoundedLiveness;
        const isTarget = contract.isTarget;
        const effectHasFixedPremise = contract.effectHasFixedPremise;

        pub fn fixedRequest(
            arena: *ir.Arena,
            domain: relation.Domain,
            inputs: []const FieldInput,
            liveness: types.ValueId,
            span: source.SourceSpan,
        ) Error!Request {
            if (inputs.len == 0 or inputs.len > MAX_REFINED_FIELDS)
                return error.InvalidFieldIndex;
            try arena.validateSpan(span);
            if (!isBoundedLiveness(arena, liveness)) return error.InvalidLiveness;
            const schema = relation.get(domain);
            if (!isPrimitiveRangeDomain(domain) or schema.fields.len != inputs.len)
                return error.InvalidFixedTablePremise;

            var expected: [MAX_REFINED_FIELDS]types.Type = undefined;
            var keys: [MAX_REFINED_FIELDS]?expr.Key = .{null} ** MAX_REFINED_FIELDS;
            var refined_count: u32 = 0;
            for (inputs, schema.fields, 0..) |input, spec, index| {
                expected[index] = switch (spec) {
                    .exact => |ty| ty,
                    .field_scalar => return error.UnsupportedRefinementType,
                };
                switch (input) {
                    .typed => |value| {
                        const node = arena.node(value) orelse return error.UnknownValue;
                        if (!std.meta.eql(node.key.ty, expected[index]))
                            return error.InvalidRefinementSource;
                    },
                    .refine => |value| {
                        const node = try fixedRefinementSource(arena, value);
                        keys[index] = .{ .ty = expected[index], .op = node.key.op };
                        try requireFreshTarget(arena, keys[index].?);
                        refined_count += 1;
                    },
                }
            }
            try relation.validateEvent(schema.id, .request, expected[0..inputs.len], null);
            try arena.ensureUnusedNodeCapacity(refined_count);
            try arena.ensureUnusedEffectCapacity(1, inputs.len);
            try arena.range_refinements.ensureUnusedCapacity(arena.allocator, refined_count);
            try arena.fixed_table_requests.ensureUnusedCapacity(arena.allocator, 1);
            const node_checkpoint = arena.nodeCheckpoint();
            const effect_checkpoint = arena.effectCheckpoint();
            const refinement_checkpoint = arena.range_refinements.items.len;
            const request_checkpoint = arena.fixed_table_requests.items.len;
            errdefer {
                arena.fixed_table_requests.shrinkRetainingCapacity(request_checkpoint);
                arena.range_refinements.shrinkRetainingCapacity(refinement_checkpoint);
                arena.rollbackToEffectCheckpoint(effect_checkpoint);
                arena.rollbackToNodeCheckpoint(node_checkpoint);
            }

            var values: [MAX_REFINED_FIELDS]types.ValueId = undefined;
            for (inputs, 0..) |input, index| values[index] = switch (input) {
                .typed => |value| value,
                .refine => try arena.internTypedNode(keys[index].?, span),
            };
            const binding = program.RelationBinding{
                .schema = schema.id,
                .schema_version = schema.version,
                .role = .request,
            };
            const effect = try arena.addBoundEffectUnchecked(
                .range_request,
                binding,
                values[0..inputs.len],
                liveness,
                null,
                span,
            );
            arena.fixed_table_requests.appendAssumeCapacity(.{
                .effect = effect,
                .liveness = liveness,
                .source_span = span,
            });
            for (inputs, 0..) |input, field_index| switch (input) {
                .typed => {},
                .refine => |value| arena.range_refinements.appendAssumeCapacity(.{
                    .source = value,
                    .target = values[field_index],
                    .premise = .{ .fixed_table_field = .{
                        .effect = effect,
                        .field_index = @intCast(field_index),
                        .liveness = liveness,
                    } },
                    .source_span = span,
                }),
            };
            return .{ .effect = effect, .values = values, .arity = @intCast(inputs.len) };
        }

        pub fn validateIdentity(arena: *const ir.Arena, item: program.RangeRefinement) Error!void {
            const source_node = arena.node(item.source) orelse return error.InvalidRefinementSource;
            const target_node = arena.node(item.target) orelse return error.InvalidRefinementTarget;
            if (types.idIndex(item.source) >= types.idIndex(item.target) or
                std.meta.eql(target_node.key.ty, types.Type.felt) or
                !std.meta.eql(source_node.key.op, target_node.key.op) or
                !isCloneable(source_node.key.op))
            {
                return error.InvalidRefinementTarget;
            }
            switch (item.premise) {
                .constraint_boolean => if (!std.meta.eql(source_node.key.ty, types.Type.felt))
                    return error.InvalidRefinementSource,
                .fixed_table_field => if (!source_node.key.ty.isFieldScalar())
                    return error.InvalidRefinementSource,
                .aligned_control_target => if (!source_node.key.ty.isFieldScalar())
                    return error.InvalidRefinementSource,
                .program_control_target => if (!source_node.key.ty.isFieldScalar())
                    return error.InvalidRefinementSource,
            }
        }

        pub fn validateFixedPremise(
            arena: *const ir.Arena,
            item: program.RangeRefinement,
            proof: @FieldType(program.RangeRefinementPremise, "fixed_table_field"),
        ) Error!void {
            const effect = arena.effect(proof.effect) orelse return error.InvalidFixedTablePremise;
            const binding = effect.binding orelse return error.InvalidFixedTablePremise;
            const schema = relation.getById(binding.schema) orelse return error.InvalidFixedTablePremise;
            const values = arena.effectValues(proof.effect) orelse return error.InvalidFixedTablePremise;
            const field_index: usize = proof.field_index;
            if (!effectHasFixedPremise(arena, proof.effect) or
                effect.kind != .range_request or binding.role != .request or
                binding.schema_version != schema.version or !isPrimitiveRangeDomain(schema.domain) or
                effect.access_ordinal != null or effect.liveness != proof.liveness or
                !isBoundedLiveness(arena, proof.liveness) or field_index >= values.len or
                field_index >= schema.fields.len or values[field_index] != item.target or
                item.target == proof.liveness or item.source == proof.liveness)
            {
                return error.InvalidFixedTablePremise;
            }
            const expected = switch (schema.fields[field_index]) {
                .exact => |ty| ty,
                .field_scalar => return error.UnsupportedRefinementType,
            };
            const target = arena.node(item.target) orelse return error.InvalidRefinementTarget;
            if (!std.meta.eql(target.key.ty, expected)) return error.InvalidFixedTablePremise;
            var occurrences: usize = 0;
            for (values) |value| if (value == item.target) {
                occurrences += 1;
            };
            if (occurrences != 1) return error.CircularRefinement;
            for (arena.effectsView()[0..types.idIndex(proof.effect)], 0..) |_, index| {
                const id = types.idFromIndex(types.EffectId, index) catch
                    return error.InvalidFixedTablePremise;
                for (arena.effectValues(id) orelse return error.InvalidFixedTablePremise) |value|
                    if (value == item.target) return error.CircularRefinement;
            }
        }

        pub fn validateRequestProof(
            arena: *const ir.Arena,
            proof: program.FixedTableRequestProof,
        ) Error!void {
            const effect = arena.effect(proof.effect) orelse return error.InvalidFixedTablePremise;
            const binding = effect.binding orelse return error.InvalidFixedTablePremise;
            const schema = relation.getById(binding.schema) orelse return error.InvalidFixedTablePremise;
            const values = arena.effectValues(proof.effect) orelse return error.InvalidFixedTablePremise;
            if (effect.kind != .range_request or binding.role != .request or
                binding.schema_version != schema.version or !isPrimitiveRangeDomain(schema.domain) or
                schema.coefficient_bound != .preprocessed_table_geometry or
                effect.access_ordinal != null or effect.liveness != proof.liveness or
                !isBoundedLiveness(arena, proof.liveness))
            {
                return error.InvalidFixedTablePremise;
            }
            var field_types: [MAX_REFINED_FIELDS]types.Type = undefined;
            if (values.len > field_types.len) return error.InvalidFixedTablePremise;
            for (values, field_types[0..values.len]) |value, *ty| {
                ty.* = (arena.node(value) orelse return error.InvalidFixedTablePremise).key.ty;
            }
            try relation.validateEvent(binding.schema, .request, field_types[0..values.len], null);
        }

        pub fn validateControlTarget(
            arena: *const ir.Arena,
            item: program.RangeRefinement,
            proof: @FieldType(program.RangeRefinementPremise, "aligned_control_target"),
        ) Error!void {
            const source_node = arena.node(item.source) orelse return error.InvalidRefinementSource;
            const target_node = arena.node(item.target) orelse return error.InvalidRefinementTarget;
            const bounded = switch (source_node.key.ty) {
                .bounded_uint => |value| value,
                else => return error.InvalidRefinementSource,
            };
            if (bounded.bits != 30 or bounded.representation != .canonical_field or
                !std.meta.eql(target_node.key.ty, types.Type.pc) or
                !(arena.node(proof.liveness) orelse return error.InvalidLiveness).key.ty.isSelector() or
                !requestOwns(arena, proof.low_effect, proof.low, proof.liveness) or
                !requestOwns(arena, proof.high_effect, proof.high, proof.liveness))
            {
                return error.InvalidFixedTablePremise;
            }
            try requireType(arena, proof.low, .uint20);
            try requireType(arena, proof.high, .byte);
            const word = mulOther(arena, item.source, 4) orelse
                return error.InvalidRefinementSource;
            const addition = switch ((arena.node(word) orelse return error.InvalidRefinementSource).key.op) {
                .add => |binary| binary,
                else => return error.InvalidRefinementSource,
            };
            const shifted = if (addition.lhs == proof.low)
                addition.rhs
            else if (addition.rhs == proof.low)
                addition.lhs
            else
                return error.InvalidRefinementSource;
            if (mulOther(arena, shifted, 1 << 20) != proof.high)
                return error.InvalidRefinementSource;
        }

        pub fn validateProgramControlTarget(
            arena: *const ir.Arena,
            item: program.RangeRefinement,
            proof: @FieldType(program.RangeRefinementPremise, "program_control_target"),
        ) Error!void {
            const source_node = arena.node(item.source) orelse
                return error.InvalidRefinementSource;
            const target_node = arena.node(item.target) orelse
                return error.InvalidRefinementTarget;
            if (!std.meta.eql(source_node.key.ty, types.Type.felt) or
                !std.meta.eql(target_node.key.ty, types.Type.pc))
            {
                return error.InvalidProgramControlPremise;
            }
            try validateProgramControlEffect(
                arena,
                proof.program_effect,
                proof.current_pc,
                proof.offset,
                proof.kind,
                proof.liveness,
            );
            const exact = switch (proof.kind) {
                .jump => exactBinary(
                    arena,
                    item.source,
                    .add,
                    proof.current_pc,
                    proof.offset,
                ),
                .branch => |branch| exactBranchTarget(
                    arena,
                    item.source,
                    proof.current_pc,
                    proof.offset,
                    branch.condition,
                ),
            };
            if (!exact) return error.InvalidProgramControlPremise;
        }

        pub fn validateCommittedProgramControlTarget(
            arena: *const ir.Arena,
            proof: program.CommittedProgramControlTargetProof,
        ) Error!void {
            const current_pc = arena.node(proof.current_pc) orelse
                return error.InvalidProgramControlPremise;
            const current_pc_polynomial = arena.node(proof.current_pc_polynomial) orelse
                return error.InvalidProgramControlPremise;
            const target = arena.node(proof.committed_target) orelse
                return error.InvalidProgramControlPremise;
            const target_polynomial = arena.node(proof.committed_target_polynomial) orelse
                return error.InvalidProgramControlPremise;
            if (!std.meta.eql(current_pc.key.ty, types.Type.pc) or
                !std.meta.eql(target.key.ty, types.Type.pc) or
                !std.meta.eql(current_pc_polynomial.key.ty, types.Type.felt) or
                !std.meta.eql(target_polynomial.key.ty, types.Type.felt) or
                proof.current_pc == proof.committed_target or
                proof.current_pc_polynomial == proof.committed_target_polynomial or
                proof.condition_constraint == proof.target_constraint)
            {
                return error.InvalidProgramControlPremise;
            }
            switch (current_pc.key.op) {
                .input => {},
                else => return error.InvalidProgramControlPremise,
            }
            switch (target.key.op) {
                .input => {},
                else => return error.InvalidProgramControlPremise,
            }
            switch (current_pc_polynomial.key.op) {
                .input => {},
                else => return error.InvalidProgramControlPremise,
            }
            switch (target_polynomial.key.op) {
                .input => {},
                else => return error.InvalidProgramControlPremise,
            }
            try validateProgramControlEffect(
                arena,
                proof.program_effect,
                proof.current_pc,
                proof.offset,
                .{ .branch = .{
                    .condition = proof.condition,
                    .condition_constraint = proof.condition_constraint,
                } },
                proof.liveness,
            );
            if (types.idIndex(proof.condition_constraint) >=
                types.idIndex(proof.target_constraint) or
                committedControlExpression(arena, proof) == null)
            {
                return error.InvalidProgramControlPremise;
            }
        }

        pub const CommittedControlExpression = struct {
            difference: types.ValueId,
            root: types.ValueId,
        };

        pub fn committedControlExpression(
            arena: *const ir.Arena,
            proof: program.CommittedProgramControlTargetProof,
        ) ?CommittedControlExpression {
            const constraint = arena.constraint(proof.target_constraint) orelse return null;
            if (constraint.gate != null or constraint.category != .semantic) return null;
            const gate = livenessPolynomial(arena, proof.liveness) orelse return null;
            const root_product = binaryOperands(arena, constraint.root, .mul) orelse return null;
            const difference = if (root_product.lhs == gate)
                root_product.rhs
            else if (root_product.rhs == gate)
                root_product.lhs
            else
                return null;
            const subtraction = binaryOperands(arena, difference, .sub) orelse return null;
            if (subtraction.lhs != proof.committed_target_polynomial or
                !exactBranchTarget(
                    arena,
                    subtraction.rhs,
                    proof.current_pc_polynomial,
                    proof.offset,
                    proof.condition,
                ))
            {
                return null;
            }
            return .{ .difference = difference, .root = constraint.root };
        }

        pub fn livenessPolynomial(
            arena: *const ir.Arena,
            liveness: types.ValueId,
        ) ?types.ValueId {
            const node = arena.node(liveness) orelse return null;
            if (!node.key.ty.isSelector()) return null;
            for (arena.range_refinements.items) |item| {
                if (item.target != liveness) continue;
                return switch (item.premise) {
                    .constraint_boolean => item.source,
                    else => null,
                };
            }
            return liveness;
        }

        pub fn validateProgramControlEffect(
            arena: *const ir.Arena,
            program_effect: types.EffectId,
            current_pc: types.ValueId,
            offset: types.ValueId,
            kind: ProgramControlTargetKind,
            liveness: types.ValueId,
        ) Error!void {
            const effect = arena.effect(program_effect) orelse
                return error.InvalidProgramControlPremise;
            const binding = effect.binding orelse
                return error.InvalidProgramControlPremise;
            const values = arena.effectValues(program_effect) orelse
                return error.InvalidProgramControlPremise;
            const schema = relation.get(.program_access);
            const pc_node = arena.node(current_pc) orelse
                return error.InvalidProgramControlPremise;
            const offset_node = arena.node(offset) orelse
                return error.InvalidProgramControlPremise;
            const liveness_node = arena.node(liveness) orelse
                return error.InvalidProgramControlPremise;
            if (effect.kind != .program_fetch or binding.schema != schema.id or
                binding.schema_version != schema.version or binding.role != .request or
                effect.access_ordinal != null or effect.liveness != liveness or
                values.len != schema.fields.len or values[0] != current_pc or
                !std.meta.eql(pc_node.key.ty, types.Type.pc) or
                !offset_node.key.ty.isFieldScalar() or !liveness_node.key.ty.isSelector())
            {
                return error.InvalidProgramControlPremise;
            }
            switch (kind) {
                .jump => {
                    if (values[3] != offset or !isConstant(arena, values[4], 0))
                        return error.InvalidProgramControlPremise;
                },
                .branch => |branch| {
                    const condition = arena.node(branch.condition) orelse
                        return error.InvalidProgramControlPremise;
                    if (values[4] != offset or !condition.key.ty.isSelector() or
                        !isBooleanConstraint(
                            arena,
                            branch.condition,
                            branch.condition_constraint,
                        ))
                    {
                        return error.InvalidProgramControlPremise;
                    }
                },
            }
        }

        pub const BinaryOperation = enum { add, sub, mul };

        pub fn exactBranchTarget(
            arena: *const ir.Arena,
            source_value: types.ValueId,
            current_pc: types.ValueId,
            offset: types.ValueId,
            condition: types.ValueId,
        ) bool {
            const sum = binaryOperands(arena, source_value, .add) orelse return false;
            return (isTakenPc(arena, sum.lhs, current_pc, offset, condition) and
                isFallthrough(arena, sum.rhs, condition)) or
                (isTakenPc(arena, sum.rhs, current_pc, offset, condition) and
                    isFallthrough(arena, sum.lhs, condition));
        }

        pub fn isTakenPc(
            arena: *const ir.Arena,
            value: types.ValueId,
            current_pc: types.ValueId,
            offset: types.ValueId,
            condition: types.ValueId,
        ) bool {
            const sum = binaryOperands(arena, value, .add) orelse return false;
            const taken = if (sum.lhs == current_pc)
                sum.rhs
            else if (sum.rhs == current_pc)
                sum.lhs
            else
                return false;
            return exactBinary(arena, taken, .mul, offset, condition);
        }

        pub fn isFallthrough(
            arena: *const ir.Arena,
            value: types.ValueId,
            condition: types.ValueId,
        ) bool {
            const product = binaryOperands(arena, value, .mul) orelse return false;
            const not_taken = if (isConstant(arena, product.lhs, 4))
                product.rhs
            else if (isConstant(arena, product.rhs, 4))
                product.lhs
            else
                return false;
            const difference = binaryOperands(arena, not_taken, .sub) orelse return false;
            return isConstant(arena, difference.lhs, 1) and
                difference.rhs == condition;
        }

        pub fn exactBinary(
            arena: *const ir.Arena,
            value: types.ValueId,
            operation: BinaryOperation,
            first: types.ValueId,
            second: types.ValueId,
        ) bool {
            const operands = binaryOperands(arena, value, operation) orelse return false;
            return (operands.lhs == first and operands.rhs == second) or
                (operation != .sub and operands.lhs == second and operands.rhs == first);
        }

        pub fn binaryOperands(
            arena: *const ir.Arena,
            value: types.ValueId,
            operation: BinaryOperation,
        ) ?expr.Binary {
            const node = arena.node(value) orelse return null;
            return switch (operation) {
                .add => switch (node.key.op) {
                    .add => |operands| operands,
                    else => null,
                },
                .sub => switch (node.key.op) {
                    .sub => |operands| operands,
                    else => null,
                },
                .mul => switch (node.key.op) {
                    .mul => |operands| operands,
                    else => null,
                },
            };
        }

        pub fn requestOwns(
            arena: *const ir.Arena,
            effect_id: types.EffectId,
            value: types.ValueId,
            liveness: types.ValueId,
        ) bool {
            var named = false;
            for (arena.fixed_table_requests.items) |proof| if (proof.effect == effect_id) {
                if (proof.liveness != liveness) return false;
                named = true;
                break;
            };
            if (!named) return false;
            const effect = arena.effect(effect_id) orelse return false;
            if (effect.liveness != liveness) return false;
            for (arena.effectValues(effect_id) orelse return false) |field|
                if (field == value) return true;
            return false;
        }

        pub fn mulOther(arena: *const ir.Arena, product: types.ValueId, constant: u32) ?types.ValueId {
            const binary = switch ((arena.node(product) orelse return null).key.op) {
                .mul => |value| value,
                else => return null,
            };
            if (isConstant(arena, binary.lhs, constant)) return binary.rhs;
            if (isConstant(arena, binary.rhs, constant)) return binary.lhs;
            return null;
        }

        pub fn requireType(arena: *const ir.Arena, value: types.ValueId, ty: types.Type) Error!void {
            const node = arena.node(value) orelse return error.UnknownValue;
            if (!std.meta.eql(node.key.ty, ty)) return error.InvalidRefinementSource;
        }

        pub fn isConstant(arena: *const ir.Arena, value: types.ValueId, expected: u32) bool {
            return switch ((arena.node(value) orelse return false).key.op) {
                .constant => |constant| switch (constant) {
                    .field, .unsigned => |number| number == expected,
                },
                else => false,
            };
        }

        pub fn booleanRefinementSource(arena: *const ir.Arena, value: types.ValueId) Error!expr.Node {
            const node = arena.node(value) orelse return error.UnknownValue;
            if (!std.meta.eql(node.key.ty, types.Type.felt) or !isCloneable(node.key.op) or
                isTarget(arena, value)) return error.InvalidRefinementSource;
            return node;
        }

        pub fn fixedRefinementSource(arena: *const ir.Arena, value: types.ValueId) Error!expr.Node {
            const node = arena.node(value) orelse return error.UnknownValue;
            if (!node.key.ty.isFieldScalar() or !isCloneable(node.key.op) or isTarget(arena, value))
                return error.InvalidRefinementSource;
            return node;
        }

        pub fn requireFreshTarget(arena: *const ir.Arena, key: expr.Key) Error!void {
            if (arena.interned_nodes.get(key) != null) return error.DuplicateRefinementTarget;
        }

        pub fn isCloneable(op: expr.Op) bool {
            return switch (op) {
                .input, .add, .sub, .mul => true,
                else => false,
            };
        }

        pub fn isPrimitiveRangeDomain(domain: relation.Domain) bool {
            return switch (domain) {
                .range_check_20,
                .range_check_8_11,
                .range_check_8_8_4,
                .range_check_8_8,
                .range_check_m31,
                => true,
                else => false,
            };
        }

        pub fn isBooleanConstraint(
            arena: *const ir.Arena,
            value: types.ValueId,
            constraint_id: types.ConstraintId,
        ) bool {
            const constraint = arena.constraint(constraint_id) orelse return false;
            if (constraint.gate != null or
                (constraint.category != .semantic and constraint.category != .type_range))
            {
                return false;
            }
            const product = switch ((arena.node(constraint.root) orelse return false).key.op) {
                .mul => |binary| binary,
                else => return false,
            };
            const other = if (product.lhs == value)
                product.rhs
            else if (product.rhs == value)
                product.lhs
            else
                return false;
            const difference = switch ((arena.node(other) orelse return false).key.op) {
                .sub => |binary| binary,
                else => return false,
            };
            return (difference.rhs == value and isOne(arena, difference.lhs)) or
                (difference.lhs == value and isOne(arena, difference.rhs));
        }

        pub fn isOne(arena: *const ir.Arena, value: types.ValueId) bool {
            const node = arena.node(value) orelse return false;
            return switch (node.key.op) {
                .constant => |constant| switch (constant) {
                    .field, .unsigned => |number| number == 1,
                },
                else => false,
            };
        }
    };
}
