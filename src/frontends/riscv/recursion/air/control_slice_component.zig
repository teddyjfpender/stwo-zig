//! Typed-AIR factory shared only by the two source-identical control slices.
//!
//! Public-LogUp control (row 17) and AIR-composition control (row 19) have the
//! same polynomial and relation shape but distinct preprocessing namespaces
//! and semantic seals. The factory removes transcription drift without merging
//! their verifier-owned schedule validators.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const Config = struct {
    stable_name: []const u8,
    preprocessed_names: [9][]const u8,
    parameter_names: [2][]const u8,
    constraint_name: []const u8,
    semantic_digest_hex: []const u8,
};

pub fn Component(comptime config: Config) type {
    return struct {
        const Self = @This();

        pub const STABLE_NAME = config.stable_name;
        pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 0;
        pub const PREPROCESSED_COLUMN_COUNT: usize = 9;
        pub const PROOF_KIND_PARAMETER_COUNT: usize = 2;
        pub const LOGICAL_INPUT_COUNT: usize = 11;
        pub const DIRECT_CONSTRAINT_COUNT: usize = 1;
        pub const RELATION_EVENT_COUNT: usize = 1;
        pub const LOOKUP_BATCH_SIZE: u8 = 1;
        pub const INTERACTION_BATCH_COUNT: usize = 1;
        pub const INTERACTION_COLUMN_COUNT: usize = 4;
        pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 0;
        pub const SEMANTIC_DIGEST_HEX = config.semantic_digest_hex;
        pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
            config.semantic_digest_hex,
            "invalid recursion control-slice semantic digest",
        );
        pub const PREPROCESSED_COLUMN_NAMES = config.preprocessed_names;
        pub const PARAMETER_NAMES = config.parameter_names;

        pub const PreprocessedColumns = struct {
            row_mask: types.ValueId,
            segment_mask: types.ValueId,
            verifier_id: types.ValueId,
            sequence: types.ValueId,
            tag: types.ValueId,
            args: [4]types.ValueId,

            pub fn physical(self: PreprocessedColumns) [9]types.ValueId {
                return .{
                    self.row_mask,
                    self.segment_mask,
                    self.verifier_id,
                    self.sequence,
                    self.tag,
                } ++ self.args;
            }

            pub fn stepTuple(self: PreprocessedColumns) [7]types.ValueId {
                return .{ self.verifier_id, self.sequence, self.tag } ++ self.args;
            }
        };

        pub const Parameters = struct {
            segment_active: types.ValueId,
            binary_active: types.ValueId,

            pub fn physical(self: Parameters) [2]types.ValueId {
                return .{ self.segment_active, self.binary_active };
            }
        };

        pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
            InvalidControlSliceDefinition,
        };

        pub const Definition = struct {
            arena: ir.Arena,
            preprocessed: PreprocessedColumns,
            parameters: Parameters,
            generated_enabler_root: types.ValueId,
            generated_enabler_constraint: types.ConstraintId,
            active: types.ValueId,
            event: types.EffectId,

            pub fn deinit(self: *Definition) void {
                self.arena.deinit();
                self.* = undefined;
            }

            pub fn validate(self: *const Definition) ValidationError!void {
                try validate_mod.validate(&self.arena);
                const identity = try digest.computeIdentity(&self.arena);
                if (identity.format_version != digest.typed_effect_format_version or
                    !std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or
                    self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
                    self.arena.effectsView().len != RELATION_EVENT_COUNT or
                    self.arena.hints.items.len != 0 or self.arena.functions.items.len != 0 or
                    self.arena.calls.items.len != 0 or self.arena.range_refinements.items.len != 0 or
                    self.arena.fixed_table_requests.items.len != 0)
                {
                    return error.InvalidControlSliceDefinition;
                }
                try validateInputBlock(
                    &self.arena,
                    &self.preprocessed.physical(),
                    &PREPROCESSED_COLUMN_NAMES,
                    0,
                    &.{ 0, 1 },
                );
                try validateInputBlock(
                    &self.arena,
                    &self.parameters.physical(),
                    &PARAMETER_NAMES,
                    PREPROCESSED_COLUMN_COUNT,
                    &.{ 0, 1 },
                );
                const constraint = self.arena.constraint(
                    self.generated_enabler_constraint,
                ) orelse return error.InvalidControlSliceDefinition;
                const constraint_name = self.arena.name(constraint.name) orelse
                    return error.InvalidControlSliceDefinition;
                if (types.idIndex(self.generated_enabler_constraint) != 0 or
                    constraint.root != self.generated_enabler_root or
                    constraint.gate != null or constraint.category != .semantic or
                    !std.mem.eql(u8, constraint_name, config.constraint_name))
                {
                    return error.InvalidControlSliceDefinition;
                }

                const schema = relation.get(.recursion_step);
                const effect = self.arena.effect(self.event) orelse
                    return error.InvalidControlSliceDefinition;
                const binding = effect.binding orelse
                    return error.InvalidControlSliceDefinition;
                const values = self.arena.effectValues(self.event) orelse
                    return error.InvalidControlSliceDefinition;
                const tuple = self.preprocessed.stepTuple();
                if (types.idIndex(self.event) != 0 or effect.kind != .component_call or
                    binding.schema != schema.id or binding.schema_version != schema.version or
                    binding.role != .consume or effect.liveness != self.active or
                    effect.access_ordinal != null or
                    !std.mem.eql(types.ValueId, values, &tuple))
                {
                    return error.InvalidControlSliceDefinition;
                }
            }
        };

        pub fn build(allocator: std.mem.Allocator) !Definition {
            var result = try buildDefinition(allocator);
            errdefer result.deinit();
            try result.validate();
            return result;
        }

        fn buildDefinition(allocator: std.mem.Allocator) !Definition {
            var arena = ir.Arena.init(allocator);
            errdefer arena.deinit();
            const span = source.SourceSpan.generated();
            var preprocessing: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
            for (&preprocessing, PREPROCESSED_COLUMN_NAMES, 0..) |
                *value,
                name,
                index,
            | {
                value.* = try arena.input(
                    name,
                    if (index == 0 or index == 1) .selector else .felt,
                    span,
                );
            }
            const preprocessed = PreprocessedColumns{
                .row_mask = preprocessing[0],
                .segment_mask = preprocessing[1],
                .verifier_id = preprocessing[2],
                .sequence = preprocessing[3],
                .tag = preprocessing[4],
                .args = preprocessing[5..9].*,
            };
            var parameter_values: [2]types.ValueId = undefined;
            for (&parameter_values, PARAMETER_NAMES) |*value, name|
                value.* = try arena.input(name, .selector, span);
            const parameters = Parameters{
                .segment_active = parameter_values[0],
                .binary_active = parameter_values[1],
            };

            const one = try arena.constantField(1, span);
            const generated_enabler_root = try arena.mul(
                one,
                try arena.sub(one, one, span),
                span,
            );
            const generated_enabler_constraint = try arena.assertZero(
                config.constraint_name,
                generated_enabler_root,
                null,
                .semantic,
                span,
            );
            const binary_mask = try arena.sub(one, preprocessed.segment_mask, span);
            const selected_lane = try arena.add(
                try arena.mul(preprocessed.segment_mask, parameters.segment_active, span),
                try arena.mul(binary_mask, parameters.binary_active, span),
                span,
            );
            const active = try arena.mul(preprocessed.row_mask, selected_lane, span);
            const tuple = preprocessed.stepTuple();
            const event = try relation_effect.append(&arena, .{
                .domain = .recursion_step,
                .role = .consume,
                .values = &tuple,
                .weight = active,
            }, span);
            return .{
                .arena = arena,
                .preprocessed = preprocessed,
                .parameters = parameters,
                .generated_enabler_root = generated_enabler_root,
                .generated_enabler_constraint = generated_enabler_constraint,
                .active = active,
                .event = event,
            };
        }

        fn validateInputBlock(
            arena: *const ir.Arena,
            values: []const types.ValueId,
            names: []const []const u8,
            offset: usize,
            selector_indices: []const usize,
        ) error{InvalidControlSliceDefinition}!void {
            if (values.len != names.len)
                return error.InvalidControlSliceDefinition;
            for (values, names, 0..) |value, name, local_index| {
                if (types.idIndex(value) != offset + local_index)
                    return error.InvalidControlSliceDefinition;
                const node = arena.node(value) orelse
                    return error.InvalidControlSliceDefinition;
                var selector = false;
                for (selector_indices) |index|
                    selector = selector or index == local_index;
                if (!std.meta.eql(
                    node.key.ty,
                    if (selector) types.Type.selector else .felt,
                )) return error.InvalidControlSliceDefinition;
                const name_id = switch (node.key.op) {
                    .input => |input_name| input_name,
                    else => return error.InvalidControlSliceDefinition,
                };
                const actual_name = arena.name(name_id) orelse
                    return error.InvalidControlSliceDefinition;
                if (!std.mem.eql(u8, actual_name, name))
                    return error.InvalidControlSliceDefinition;
            }
        }
    };
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
