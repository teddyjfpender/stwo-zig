//! V2 row-17 authority for the exact VM public-LogUp verifier slice.
//!
//! This component consumes the verifier-owned schedule events for the seventy
//! canonical public-LogUp terms and the following global-zero assertion.  The
//! assertion row additionally consumes the one-word control relay produced by
//! the public-spine publication row.  It never re-emits that wire: doing so
//! would self-cancel the relay obligation instead of closing it.

const std = @import("std");

const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const direct_program = @import("direct_constraint_program.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.vm_public_logup_control.v2";
pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;

pub const CONTROL_RELAY_CIRCUIT_ID: u32 = 43;
pub const CONTROL_RELAY_NODE_ID: u32 = 0;

pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 1;
pub const PREPROCESSED_COLUMN_COUNT: usize = 9;
pub const PARAMETER_COUNT: usize = 0;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 4;
pub const RELATION_EVENT_COUNT: usize = 2;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 1;
pub const INTERACTION_COLUMN_COUNT: usize = 4;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

// Regenerated from this file's typed IR and pinned by the focused profile
// test. `computeSemanticDigest` deliberately builds the raw arena so an
// intentional semantic edit has one auditable regeneration path.
pub const SEMANTIC_DIGEST_HEX =
    "d9dc9d62860f1759b03a6af615fa9ffe2f7e5da3623b8d5c968b04314585593f";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid VM public-LogUp V2 control semantic digest",
);

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.vm_public_logup_control.v2.control_value",
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_vm_public_logup_control_v2_row_mask",
    "recursion_vm_public_logup_control_v2_control_mask",
    "recursion_vm_public_logup_control_v2_verifier_id",
    "recursion_vm_public_logup_control_v2_sequence",
    "recursion_vm_public_logup_control_v2_tag",
    "recursion_vm_public_logup_control_v2_arg_0",
    "recursion_vm_public_logup_control_v2_arg_1",
    "recursion_vm_public_logup_control_v2_arg_2",
    "recursion_vm_public_logup_control_v2_arg_3",
};

pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
    "recursion.vm_public_logup_control.v2.row_mask_boolean",
    "recursion.vm_public_logup_control.v2.control_mask_boolean",
    "recursion.vm_public_logup_control.v2.control_requires_row",
    "recursion.vm_public_logup_control.v2.non_control_value_zero",
};

pub const MainColumns = struct {
    control_value: types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{self.control_value};
    }
};

pub const PreprocessedColumns = struct {
    row_mask: types.ValueId,
    control_mask: types.ValueId,
    verifier_id: types.ValueId,
    sequence: types.ValueId,
    tag: types.ValueId,
    args: [4]types.ValueId,

    pub fn physical(
        self: PreprocessedColumns,
    ) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.control_mask,
            self.verifier_id,
            self.sequence,
            self.tag,
        } ++ self.args;
    }

    pub fn stepTuple(self: PreprocessedColumns) [7]types.ValueId {
        return .{ self.verifier_id, self.sequence, self.tag } ++ self.args;
    }
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    one: types.ValueId,
    zero: types.ValueId,
    control_circuit: types.ValueId,
    roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    events: [RELATION_EVENT_COUNT]types.EffectId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) !void {
        try validate_mod.validate(&self.arena);
        const identity = try digest.computeIdentity(&self.arena);
        if (identity.format_version != digest.typed_effect_format_version or
            !std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            self.arena.hints.items.len != 0 or
            self.arena.functions.items.len != 0 or
            self.arena.calls.items.len != 0 or
            self.arena.range_refinements.items.len != 0 or
            self.arena.fixed_table_requests.items.len != 0)
        {
            return error.InvalidPublicLogUpControlV2Definition;
        }

        try validateInputs(
            &self.arena,
            &self.main.physical(),
            &MAIN_COLUMN_NAMES,
            0,
            null,
        );
        try validateInputs(
            &self.arena,
            &self.preprocessed.physical(),
            &PREPROCESSED_COLUMN_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT,
            &.{ 0, 1 },
        );
        try validateConstant(&self.arena, self.one, 1);
        try validateConstant(&self.arena, self.zero, 0);
        try validateConstant(
            &self.arena,
            self.control_circuit,
            CONTROL_RELAY_CIRCUIT_ID,
        );

        for (self.constraints, self.roots, CONSTRAINT_NAMES, 0..) |
            constraint_id,
            root,
            expected_name,
            index,
        | {
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidPublicLogUpControlV2Definition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidPublicLogUpControlV2Definition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidPublicLogUpControlV2Definition;
            }
        }

        const step_tuple = self.preprocessed.stepTuple();
        try validateEffect(
            &self.arena,
            self.events[0],
            0,
            .recursion_step,
            .consume,
            self.preprocessed.row_mask,
            &step_tuple,
        );
        const control_tuple = [_]types.ValueId{
            self.control_circuit,
            self.zero,
            self.main.control_value,
            self.zero,
            self.zero,
            self.zero,
        };
        try validateEffect(
            &self.arena,
            self.events[1],
            1,
            .recursion_wire,
            .consume,
            self.preprocessed.control_mask,
            &control_tuple,
        );
    }
};

pub const StaticProfile = struct {
    arena_nodes: u16,
    compiled_nodes: u16,
    direct_constraints: u16,
    relation_events: u16,
    interaction_batches: u16,
    interaction_columns: u16,
    maximum_constraint_degree: u32,
};

pub const EXPECTED_STATIC_PROFILE = StaticProfile{
    .arena_nodes = 21,
    .compiled_nodes = 11,
    .direct_constraints = 4,
    .relation_events = 2,
    .interaction_batches = 1,
    .interaction_columns = 4,
    .maximum_constraint_degree = 2,
};

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try buildRaw(allocator);
    errdefer result.deinit();
    try result.validate();
    return result;
}

pub fn computeSemanticDigest(allocator: std.mem.Allocator) !digest.Digest {
    var definition = try buildRaw(allocator);
    defer definition.deinit();
    return (try digest.computeIdentity(&definition.arena)).bytes;
}

pub fn staticProfile(definition: *const Definition) !StaticProfile {
    try definition.validate();
    const program = try direct_program.authenticate(
        &definition.arena,
        SEMANTIC_DIGEST,
        LOGICAL_INPUT_COUNT,
    );
    return .{
        .arena_nodes = program.node_count,
        .compiled_nodes = program.compiled_node_count,
        .direct_constraints = program.constraint_count,
        .relation_events = RELATION_EVENT_COUNT,
        .interaction_batches = INTERACTION_BATCH_COUNT,
        .interaction_columns = INTERACTION_COLUMN_COUNT,
        .maximum_constraint_degree = MAXIMUM_CONSTRAINT_DEGREE,
    };
}

fn buildRaw(allocator: std.mem.Allocator) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = source.SourceSpan.generated();
    const main = MainColumns{
        .control_value = try arena.input(MAIN_COLUMN_NAMES[0], .felt, span),
    };
    var preprocessing: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&preprocessing, PREPROCESSED_COLUMN_NAMES, 0..) |
        *value,
        name,
        index,
    | {
        value.* = try arena.input(
            name,
            if (index < 2) .selector else .felt,
            span,
        );
    }
    const preprocessed = PreprocessedColumns{
        .row_mask = preprocessing[0],
        .control_mask = preprocessing[1],
        .verifier_id = preprocessing[2],
        .sequence = preprocessing[3],
        .tag = preprocessing[4],
        .args = preprocessing[5..9].*,
    };

    const one = try arena.constantField(1, span);
    const zero = try arena.constantField(0, span);
    const control_circuit = try arena.constantField(
        CONTROL_RELAY_CIRCUIT_ID,
        span,
    );
    const roots = [DIRECT_CONSTRAINT_COUNT]types.ValueId{
        try arena.mul(
            preprocessed.row_mask,
            try arena.sub(preprocessed.row_mask, one, span),
            span,
        ),
        try arena.mul(
            preprocessed.control_mask,
            try arena.sub(preprocessed.control_mask, one, span),
            span,
        ),
        try arena.mul(
            preprocessed.control_mask,
            try arena.sub(one, preprocessed.row_mask, span),
            span,
        ),
        try arena.mul(
            try arena.sub(one, preprocessed.control_mask, span),
            main.control_value,
            span,
        ),
    };
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name|
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);

    const step_tuple = preprocessed.stepTuple();
    const control_tuple = [_]types.ValueId{
        control_circuit,
        zero,
        main.control_value,
        zero,
        zero,
        zero,
    };
    const events = try relation_effect.appendGroup(
        RELATION_EVENT_COUNT,
        &arena,
        .{
            .{
                .domain = .recursion_step,
                .role = .consume,
                .values = &step_tuple,
                .weight = preprocessed.row_mask,
            },
            .{
                .domain = .recursion_wire,
                .role = .consume,
                .values = &control_tuple,
                .weight = preprocessed.control_mask,
            },
        },
        span,
    );
    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .one = one,
        .zero = zero,
        .control_circuit = control_circuit,
        .roots = roots,
        .constraints = constraints,
        .events = events,
    };
}

fn validateInputs(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    selector_indices: ?[]const usize,
) !void {
    if (values.len != names.len)
        return error.InvalidPublicLogUpControlV2Definition;
    for (values, names, 0..) |value, expected_name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidPublicLogUpControlV2Definition;
        const node = arena.node(value) orelse
            return error.InvalidPublicLogUpControlV2Definition;
        var selector = false;
        if (selector_indices) |indices| {
            for (indices) |index|
                selector = selector or index == local_index;
        }
        if (!std.meta.eql(
            node.key.ty,
            if (selector) types.Type.selector else .felt,
        )) return error.InvalidPublicLogUpControlV2Definition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidPublicLogUpControlV2Definition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidPublicLogUpControlV2Definition;
        if (!std.mem.eql(u8, actual_name, expected_name))
            return error.InvalidPublicLogUpControlV2Definition;
    }
}

fn validateConstant(
    arena: *const ir.Arena,
    value: types.ValueId,
    expected: u32,
) !void {
    const node = arena.node(value) orelse
        return error.InvalidPublicLogUpControlV2Definition;
    const actual = switch (node.key.op) {
        .constant => |constant| switch (constant) {
            .field, .unsigned => |word| word,
        },
        else => return error.InvalidPublicLogUpControlV2Definition,
    };
    if (actual != expected)
        return error.InvalidPublicLogUpControlV2Definition;
}

fn validateEffect(
    arena: *const ir.Arena,
    effect_id: types.EffectId,
    expected_index: usize,
    expected_domain: relation.Domain,
    expected_role: relation.Role,
    expected_weight: types.ValueId,
    expected_tuple: []const types.ValueId,
) !void {
    if (types.idIndex(effect_id) != expected_index)
        return error.InvalidPublicLogUpControlV2Definition;
    const item = arena.effect(effect_id) orelse
        return error.InvalidPublicLogUpControlV2Definition;
    const binding = item.binding orelse
        return error.InvalidPublicLogUpControlV2Definition;
    const schema = relation.get(expected_domain);
    const values = arena.effectValues(effect_id) orelse
        return error.InvalidPublicLogUpControlV2Definition;
    if (item.kind != .component_call or item.liveness != expected_weight or
        item.access_ordinal != null or binding.schema != schema.id or
        binding.schema_version != schema.version or
        binding.role != expected_role or
        !std.mem.eql(types.ValueId, values, expected_tuple))
    {
        return error.InvalidPublicLogUpControlV2Definition;
    }
}

fn hexDigest(
    comptime value: []const u8,
    comptime message: []const u8,
) digest.Digest {
    if (value.len != 2 * @sizeOf(digest.Digest)) @compileError(message);
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}

comptime {
    if (INTERACTION_BATCH_COUNT != 1 or INTERACTION_COLUMN_COUNT != 4 or
        RELATION_EVENT_COUNT != 2 or LOOKUP_BATCH_SIZE != 2)
    {
        @compileError("VM public-LogUp V2 relation batching drifted");
    }
}
