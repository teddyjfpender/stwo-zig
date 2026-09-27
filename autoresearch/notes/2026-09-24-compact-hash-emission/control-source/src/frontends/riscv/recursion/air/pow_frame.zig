//! Exact typed logical AIR for Stark-V universal PoW binding row 7.
//!
//! This row is the narrow bridge between the verifier-owned transcript
//! schedule and the arithmetic PoW predicate.  It consumes the exact 14-word
//! transcript frame and emits the five-word predicate tuple.  The source's
//! affine tag map (`kind * 14 - 8`) gives tags 6 and 20, matching the two
//! verifier control instructions, while the cubic root admits only kinds 1
//! and 2 on enabled rows.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const check = @import("pow_check.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.pow_frame.v1";
pub const WORD_COUNT: usize = 8;
pub const FRAME_RELATION_COORDINATE_COUNT: usize = 14;
pub const CHECK_RELATION_COORDINATE_COUNT: usize = 5;
pub const DECLARED_COMMITTED_COLUMN_COUNT: usize =
    FRAME_RELATION_COORDINATE_COUNT;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize =
    1 + DECLARED_COMMITTED_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT: usize = 0;
pub const PARAMETER_COUNT: usize = 0;
pub const LOGICAL_INPUT_COUNT: usize = PHYSICAL_MAIN_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 2;
pub const FRAMEWORK_CONSTRAINT_COUNT: usize = DIRECT_CONSTRAINT_COUNT + 1;
pub const RELATION_EVENT_COUNT: usize = 2;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 1;
pub const INTERACTION_COLUMN_COUNT: usize = 4;
pub const SOURCE_DECLARED_MAXIMUM_DEGREE: u32 = 3;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const INTERACTION_CONTROL_TAG: u32 = 6;
pub const PCS_CONTROL_TAG: u32 = 20;

pub const PowKind = check.PowKind;
pub const SourceAuthority = check.SourceAuthority;
pub const SOURCE_AUTHORITY_DIGEST = check.SOURCE_AUTHORITY_DIGEST;
pub const SOURCE_AUTHORITY_DIGEST_HEX = check.SOURCE_AUTHORITY_DIGEST_HEX;

pub const SEMANTIC_DIGEST_HEX =
    "24c5e8b25dba5075a08032342824d67092fb78cb8b8e55d833a519f8feaf681e";
pub const SEMANTIC_DIGEST = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion PoW-frame semantic digest",
);

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.pow_frame.enabler",
    "recursion.pow_frame.verifier_id",
    "recursion.pow_frame.sequence",
    "recursion.pow_frame.pow_kind",
    "recursion.pow_frame.hash_id",
    "recursion.pow_frame.call_id",
    "recursion.pow_frame.bits",
    "recursion.pow_frame.word_0",
    "recursion.pow_frame.word_1",
    "recursion.pow_frame.word_2",
    "recursion.pow_frame.word_3",
    "recursion.pow_frame.word_4",
    "recursion.pow_frame.word_5",
    "recursion.pow_frame.word_6",
    "recursion.pow_frame.word_7",
};

pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
    "recursion.pow_frame.enabler_boolean",
    "recursion.pow_frame.kind",
};

pub const MainColumns = struct {
    enabler: types.ValueId,
    verifier_id: types.ValueId,
    sequence: types.ValueId,
    pow_kind: types.ValueId,
    hash_id: types.ValueId,
    call_id: types.ValueId,
    bits: types.ValueId,
    words: [WORD_COUNT]types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{
            self.enabler,
            self.verifier_id,
            self.sequence,
            self.pow_kind,
            self.hash_id,
            self.call_id,
            self.bits,
        } ++ self.words;
    }

    pub fn frameTuple(
        self: MainColumns,
        pow_tag: types.ValueId,
    ) [FRAME_RELATION_COORDINATE_COUNT]types.ValueId {
        return .{
            self.verifier_id,
            self.sequence,
            pow_tag,
            self.hash_id,
            self.call_id,
            self.bits,
        } ++ self.words;
    }

    pub fn checkTuple(self: MainColumns) [CHECK_RELATION_COORDINATE_COUNT]types.ValueId {
        return .{
            self.verifier_id,
            self.pow_kind,
            self.call_id,
            self.bits,
            self.words[0],
        };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidPowFrameDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    pow_tag: types.ValueId,
    roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    events: [RELATION_EVENT_COUNT]types.EffectId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) ValidationError!void {
        try validate_mod.validate(&self.arena);
        const actual = try digest.computeIdentity(&self.arena);
        if (actual.format_version != digest.typed_effect_format_version or
            !std.mem.eql(u8, &actual.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            self.arena.hints.items.len != 0 or
            self.arena.functions.items.len != 0 or
            self.arena.calls.items.len != 0 or
            self.arena.range_refinements.items.len != 0 or
            self.arena.fixed_table_requests.items.len != 0)
        {
            return error.InvalidPowFrameDefinition;
        }
        const physical = self.main.physical();
        for (physical, MAIN_COLUMN_NAMES, 0..) |value, expected_name, index| {
            if (types.idIndex(value) != index)
                return error.InvalidPowFrameDefinition;
            const node = self.arena.node(value) orelse
                return error.InvalidPowFrameDefinition;
            const expected_type: types.Type = if (index == 0) .selector else .felt;
            if (!std.meta.eql(node.key.ty, expected_type))
                return error.InvalidPowFrameDefinition;
            const name_id = switch (node.key.op) {
                .input => |name| name,
                else => return error.InvalidPowFrameDefinition,
            };
            const actual_name = self.arena.name(name_id) orelse
                return error.InvalidPowFrameDefinition;
            if (!std.mem.eql(u8, actual_name, expected_name))
                return error.InvalidPowFrameDefinition;
        }
        for (self.constraints, self.roots, CONSTRAINT_NAMES, 0..) |
            constraint_id,
            root,
            expected_name,
            index,
        | {
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidPowFrameDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidPowFrameDefinition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidPowFrameDefinition;
            }
        }
        const frame_tuple = self.main.frameTuple(self.pow_tag);
        const check_tuple = self.main.checkTuple();
        try validateEvent(
            self,
            0,
            .recursion_transcript_pow_frame,
            .consume,
            &frame_tuple,
        );
        try validateEvent(self, 1, .recursion_pow_check, .emit, &check_tuple);
    }
};

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try buildDefinition(allocator);
    errdefer result.deinit();
    try result.validate();
    return result;
}

pub fn identity(allocator: std.mem.Allocator) !digest.Identity {
    var result = try buildDefinition(allocator);
    defer result.deinit();
    return digest.computeIdentity(&result.arena);
}

fn buildDefinition(allocator: std.mem.Allocator) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = source.SourceSpan.generated();
    var inputs: [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId = undefined;
    for (&inputs, MAIN_COLUMN_NAMES, 0..) |*value, name, index|
        value.* = try arena.input(name, if (index == 0) .selector else .felt, span);
    const main = MainColumns{
        .enabler = inputs[0],
        .verifier_id = inputs[1],
        .sequence = inputs[2],
        .pow_kind = inputs[3],
        .hash_id = inputs[4],
        .call_id = inputs[5],
        .bits = inputs[6],
        .words = inputs[7..][0..WORD_COUNT].*,
    };
    const one = try arena.constantField(1, span);
    const two = try arena.constantField(2, span);
    const fourteen = try arena.constantField(14, span);
    const eight = try arena.constantField(8, span);
    const pow_tag = try arena.sub(
        try arena.mul(main.pow_kind, fourteen, span),
        eight,
        span,
    );
    const roots = [DIRECT_CONSTRAINT_COUNT]types.ValueId{
        try arena.mul(main.enabler, try arena.sub(one, main.enabler, span), span),
        try arena.mul(
            try arena.mul(
                main.enabler,
                try arena.sub(main.pow_kind, one, span),
                span,
            ),
            try arena.sub(main.pow_kind, two, span),
            span,
        ),
    };
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name|
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);

    const frame_tuple = main.frameTuple(pow_tag);
    const check_tuple = main.checkTuple();
    const events = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{
            .domain = .recursion_transcript_pow_frame,
            .role = .consume,
            .values = &frame_tuple,
            .weight = main.enabler,
        },
        .{
            .domain = .recursion_pow_check,
            .role = .emit,
            .values = &check_tuple,
            .weight = main.enabler,
        },
    }, span);
    return .{
        .arena = arena,
        .main = main,
        .pow_tag = pow_tag,
        .roots = roots,
        .constraints = constraints,
        .events = events,
    };
}

fn validateEvent(
    definition: *const Definition,
    index: usize,
    domain: relation.Domain,
    role: relation.Role,
    expected_values: []const types.ValueId,
) error{InvalidPowFrameDefinition}!void {
    const event_id = definition.events[index];
    if (types.idIndex(event_id) != index)
        return error.InvalidPowFrameDefinition;
    const item = definition.arena.effect(event_id) orelse
        return error.InvalidPowFrameDefinition;
    const binding = item.binding orelse return error.InvalidPowFrameDefinition;
    const schema = relation.get(domain);
    const values = definition.arena.effectValues(event_id) orelse
        return error.InvalidPowFrameDefinition;
    if (item.kind != .component_call or
        item.liveness != definition.main.enabler or
        item.access_ordinal != null or
        binding.schema != schema.id or
        binding.schema_version != schema.version or binding.role != role or
        !std.mem.eql(types.ValueId, values, expected_values))
    {
        return error.InvalidPowFrameDefinition;
    }
}

pub fn controlTag(kind: PowKind) u32 {
    return @intFromEnum(kind) * 14 - 8;
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}

comptime {
    if (PHYSICAL_MAIN_COLUMN_COUNT != 15 or
        DIRECT_CONSTRAINT_COUNT != 2 or
        FRAMEWORK_CONSTRAINT_COUNT != 3 or
        RELATION_EVENT_COUNT != 2 or
        INTERACTION_BATCH_COUNT != 1 or
        INTERACTION_COLUMN_COUNT != 4 or
        MAXIMUM_CONSTRAINT_DEGREE != 3 or
        controlTag(.interaction) != INTERACTION_CONTROL_TAG or
        controlTag(.pcs) != PCS_CONTROL_TAG)
    {
        @compileError("universal PoW-frame geometry drifted");
    }
}
