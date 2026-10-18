//! Exact typed logical AIR for Stark-V authority-spine row 12.
//!
//! Verifier-owned preprocessing fixes every VM public-claim word coordinate,
//! value class, constant, and public-I/O projection. Segment leaves publish the
//! same value into three independently scoped consumers and export the unique
//! byte decomposition of each u16 word. The two native sparse-memory roots
//! additionally enter the row-18 statement-word relation at scope 6, directly
//! from their authenticated public-claim coordinates. Inactive proof modes
//! carry only zero.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.vm_public_claim_input.v1";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 4;
pub const PREPROCESSED_COLUMN_COUNT: usize = 12;
pub const PARAMETER_COUNT: usize = 8;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT + PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 7;
pub const RELATION_EVENT_COUNT: usize = 9;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 5;
pub const INTERACTION_COLUMN_COUNT: usize = 20;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
// The local conservative analyzer counts verifier parameters as degree-one
// inputs. STWO substitutes `segment_active` as a public constant.
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 4;

pub const VM_CLAIM_SEMANTICS_SCOPE: u32 = 0;
pub const VM_CLAIM_HASH_SCOPE: u32 = 1;
pub const VM_PUBLIC_LOGUP_SCOPE: u32 = 2;
pub const VM_PUBLIC_INPUT_KIND: u32 = 0;
pub const VM_PUBLIC_OUTPUT_KIND: u32 = 1;
pub const LOW_BYTE_INDEX: u32 = 0;
pub const HIGH_BYTE_INDEX: u32 = 1;

pub const SEMANTIC_DIGEST_HEX =
    "b1ab8e1035056bf4ac0889c0f93a97feaf71dd9cfea83c90b6720f7c3b731df4";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion VM public-claim input semantic digest",
);
pub const STATIC_PROFILE_DIGEST_HEX =
    "ea8942630bd8075f719c869f93b10b40978b0f0344f44bd910575d3556dd176c";

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.vm_public_claim_input.enabler",
    "recursion.vm_public_claim_input.value",
    "recursion.vm_public_claim_input.low_byte",
    "recursion.vm_public_claim_input.high_byte",
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_vm_public_claim_input_row_mask",
    "recursion_vm_public_claim_input_word_index",
    "recursion_vm_public_claim_input_constant_mask",
    "recursion_vm_public_claim_input_boolean_mask",
    "recursion_vm_public_claim_input_u16_mask",
    "recursion_vm_public_claim_input_constant",
    "recursion_vm_public_claim_input_input_io_mask",
    "recursion_vm_public_claim_input_input_io_index",
    "recursion_vm_public_claim_input_output_io_mask",
    "recursion_vm_public_claim_input_output_io_index",
    "recursion_vm_public_claim_input_native_root_mask",
    "recursion_vm_public_claim_input_native_root_side",
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.vm_public_claim_input.param.segment_active",
    "recursion.vm_public_claim_input.param.semantics_scope",
    "recursion.vm_public_claim_input.param.hash_scope",
    "recursion.vm_public_claim_input.param.public_logup_scope",
    "recursion.vm_public_claim_input.param.input_kind",
    "recursion.vm_public_claim_input.param.output_kind",
    "recursion.vm_public_claim_input.param.low_byte_index",
    "recursion.vm_public_claim_input.param.high_byte_index",
};

pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
    "recursion.vm_public_claim_input.enabler",
    "recursion.vm_public_claim_input.inactive_value_zero",
    "recursion.vm_public_claim_input.constant",
    "recursion.vm_public_claim_input.boolean",
    "recursion.vm_public_claim_input.u16_decomposition",
    "recursion.vm_public_claim_input.inactive_low_byte_zero",
    "recursion.vm_public_claim_input.inactive_high_byte_zero",
};

pub const MainColumns = struct {
    enabler: types.ValueId,
    value: types.ValueId,
    low_byte: types.ValueId,
    high_byte: types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{ self.enabler, self.value, self.low_byte, self.high_byte };
    }
};

pub const PreprocessedColumns = struct {
    row_mask: types.ValueId,
    word_index: types.ValueId,
    constant_mask: types.ValueId,
    boolean_mask: types.ValueId,
    u16_mask: types.ValueId,
    constant_value: types.ValueId,
    input_io_mask: types.ValueId,
    input_io_index: types.ValueId,
    output_io_mask: types.ValueId,
    output_io_index: types.ValueId,
    native_root_mask: types.ValueId,
    native_root_side: types.ValueId,

    pub fn physical(
        self: PreprocessedColumns,
    ) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.word_index,
            self.constant_mask,
            self.boolean_mask,
            self.u16_mask,
            self.constant_value,
            self.input_io_mask,
            self.input_io_index,
            self.output_io_mask,
            self.output_io_index,
            self.native_root_mask,
            self.native_root_side,
        };
    }
};

pub const Parameters = struct {
    segment_active: types.ValueId,
    semantics_scope: types.ValueId,
    hash_scope: types.ValueId,
    public_logup_scope: types.ValueId,
    input_kind: types.ValueId,
    output_kind: types.ValueId,
    low_byte_index: types.ValueId,
    high_byte_index: types.ValueId,

    pub fn physical(self: Parameters) [PARAMETER_COUNT]types.ValueId {
        return .{
            self.segment_active,
            self.semantics_scope,
            self.hash_scope,
            self.public_logup_scope,
            self.input_kind,
            self.output_kind,
            self.low_byte_index,
            self.high_byte_index,
        };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidVmPublicClaimInputDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    parameters: Parameters,
    native_root_scope: types.ValueId,
    active: types.ValueId,
    active_boolean: types.ValueId,
    active_u16: types.ValueId,
    roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    weights: [RELATION_EVENT_COUNT]types.ValueId,
    events: [RELATION_EVENT_COUNT]types.EffectId,

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
            return error.InvalidVmPublicClaimInputDefinition;
        }
        try validateInputs(
            &self.arena,
            &self.main.physical(),
            &MAIN_COLUMN_NAMES,
            0,
            &.{0},
            &.{ 2, 3 },
        );
        try validateInputs(
            &self.arena,
            &self.preprocessed.physical(),
            &PREPROCESSED_COLUMN_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT,
            &.{ 0, 2, 3, 4, 6, 8, 10 },
            &.{},
        );
        try validateInputs(
            &self.arena,
            &self.parameters.physical(),
            &PARAMETER_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT,
            &.{0},
            &.{},
        );
        for (self.constraints, self.roots, CONSTRAINT_NAMES, 0..) |
            constraint_id,
            root,
            expected_name,
            index,
        | {
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidVmPublicClaimInputDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidVmPublicClaimInputDefinition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidVmPublicClaimInputDefinition;
            }
        }

        const tuples = [_][]const types.ValueId{
            &.{ self.parameters.semantics_scope, self.preprocessed.word_index, self.main.value },
            &.{ self.parameters.hash_scope, self.preprocessed.word_index, self.main.value },
            &.{ self.parameters.public_logup_scope, self.preprocessed.word_index, self.main.value },
            &.{ self.parameters.input_kind, self.preprocessed.input_io_index, self.main.value },
            &.{ self.parameters.output_kind, self.preprocessed.output_io_index, self.main.value },
            &.{ self.main.low_byte, self.main.high_byte },
            &.{ self.preprocessed.word_index, self.parameters.low_byte_index, self.main.low_byte },
            &.{ self.preprocessed.word_index, self.parameters.high_byte_index, self.main.high_byte },
            &.{ self.native_root_scope, self.preprocessed.native_root_side, self.main.value },
        };
        const domains = [_]relation.Domain{
            .recursion_vm_public_claim_word,
            .recursion_vm_public_claim_word,
            .recursion_vm_public_claim_word,
            .recursion_vm_public_io_word,
            .recursion_vm_public_io_word,
            .range_check_8_8,
            .recursion_vm_public_claim_byte,
            .recursion_vm_public_claim_byte,
            .recursion_statement_word,
        };
        const roles = [_]relation.Role{
            .emit,
            .emit,
            .emit,
            .emit,
            .emit,
            .request,
            .emit,
            .emit,
            .emit,
        };
        for (self.events, self.weights, domains, roles, tuples, 0..) |
            effect_id,
            weight,
            domain,
            role,
            tuple,
            index,
        | {
            if (types.idIndex(effect_id) != index)
                return error.InvalidVmPublicClaimInputDefinition;
            const item = self.arena.effect(effect_id) orelse
                return error.InvalidVmPublicClaimInputDefinition;
            const binding = item.binding orelse
                return error.InvalidVmPublicClaimInputDefinition;
            const schema = relation.get(domain);
            const values = self.arena.effectValues(effect_id) orelse
                return error.InvalidVmPublicClaimInputDefinition;
            if (item.kind != .component_call or item.liveness != weight or
                item.access_ordinal != null or binding.schema != schema.id or
                binding.schema_version != schema.version or binding.role != role or
                !std.mem.eql(types.ValueId, values, tuple))
            {
                return error.InvalidVmPublicClaimInputDefinition;
            }
        }
    }
};

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try buildDefinition(allocator, true);
    errdefer result.deinit();
    try result.validate();
    return result;
}

pub fn semanticIdentity(allocator: std.mem.Allocator) !digest.Identity {
    var result = try buildDefinition(allocator, true);
    defer result.deinit();
    return digest.computeIdentity(&result.arena);
}

/// Ethereum uses the same canonical claim and range constraints, but its
/// public-sum circuit consumes the SpanStatement and committed role-I/O stream.
/// The legacy VM-claim digest is not a native Ethereum transcript input, so
/// this arena emits no claim-hash fanout. Exact role uses replace the legacy
/// LogUp fanouts; semantic and IO projections retain their original weights.
/// The default builder remains sealed to the original CSP relation schedule.
pub fn buildEthereumRoutingArena(allocator: std.mem.Allocator) !ir.Arena {
    const definition = try buildDefinition(allocator, false);
    return definition.arena;
}

fn buildDefinition(allocator: std.mem.Allocator, comptime legacy_logup_exports: bool) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = source.SourceSpan.generated();
    const main = MainColumns{
        .enabler = try arena.input(MAIN_COLUMN_NAMES[0], .selector, span),
        .value = try arena.input(MAIN_COLUMN_NAMES[1], .felt, span),
        .low_byte = try arena.input(MAIN_COLUMN_NAMES[2], .byte, span),
        .high_byte = try arena.input(MAIN_COLUMN_NAMES[3], .byte, span),
    };
    var preprocessed_values: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&preprocessed_values, PREPROCESSED_COLUMN_NAMES, 0..) |
        *value,
        name,
        index,
    | value.* = try arena.input(
        name,
        switch (index) {
            0, 2, 3, 4, 6, 8, 10 => .selector,
            else => .felt,
        },
        span,
    );
    const preprocessed = PreprocessedColumns{
        .row_mask = preprocessed_values[0],
        .word_index = preprocessed_values[1],
        .constant_mask = preprocessed_values[2],
        .boolean_mask = preprocessed_values[3],
        .u16_mask = preprocessed_values[4],
        .constant_value = preprocessed_values[5],
        .input_io_mask = preprocessed_values[6],
        .input_io_index = preprocessed_values[7],
        .output_io_mask = preprocessed_values[8],
        .output_io_index = preprocessed_values[9],
        .native_root_mask = preprocessed_values[10],
        .native_root_side = preprocessed_values[11],
    };
    var routed_uses: [3]?types.ValueId = .{ null, null, null };
    if (!legacy_logup_exports) {
        for (&routed_uses, [_][]const u8{ "preprocessed.role_word_uses", "preprocessed.role_low_byte_uses", "preprocessed.role_high_byte_uses" }) |*uses, name|
            uses.* = try arena.input(name, .felt, span);
    }
    var parameter_values: [PARAMETER_COUNT]types.ValueId = undefined;
    for (&parameter_values, PARAMETER_NAMES, 0..) |*value, name, index|
        value.* = try arena.input(name, if (index == 0) .selector else .felt, span);
    const parameters = Parameters{
        .segment_active = parameter_values[0],
        .semantics_scope = parameter_values[1],
        .hash_scope = parameter_values[2],
        .public_logup_scope = parameter_values[3],
        .input_kind = parameter_values[4],
        .output_kind = parameter_values[5],
        .low_byte_index = parameter_values[6],
        .high_byte_index = parameter_values[7],
    };

    const one = try arena.constantField(1, span);
    const native_root_scope = try arena.constantField(
        @import("vm_statement_roots.zig").NATIVE_CONTINUATION_SCOPE,
        span,
    );
    const active = try arena.mul(preprocessed.row_mask, parameters.segment_active, span);
    const active_boolean = try arena.mul(
        preprocessed.boolean_mask,
        parameters.segment_active,
        span,
    );
    const active_u16 = try arena.mul(
        preprocessed.u16_mask,
        parameters.segment_active,
        span,
    );
    const byte_radix = try arena.constantField(256, span);
    const roots = [DIRECT_CONSTRAINT_COUNT]types.ValueId{
        try arena.sub(main.enabler, preprocessed.row_mask, span),
        try arena.mul(try arena.sub(one, active, span), main.value, span),
        try arena.mul(
            try arena.mul(active, preprocessed.constant_mask, span),
            try arena.sub(main.value, preprocessed.constant_value, span),
            span,
        ),
        try arena.mul(
            try arena.mul(active_boolean, main.value, span),
            try arena.sub(one, main.value, span),
            span,
        ),
        try arena.mul(
            active_u16,
            try arena.sub(
                try arena.sub(main.value, main.low_byte, span),
                try arena.mul(main.high_byte, byte_radix, span),
                span,
            ),
            span,
        ),
        try arena.mul(try arena.sub(one, active_u16, span), main.low_byte, span),
        try arena.mul(try arena.sub(one, active_u16, span), main.high_byte, span),
    };
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name|
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);

    const input_io_weight = try arena.mul(active, preprocessed.input_io_mask, span);
    const output_io_weight = try arena.mul(active, preprocessed.output_io_mask, span);
    const logup_word_weight = if (legacy_logup_exports) active else try arena.mul(active, routed_uses[0].?, span);
    const logup_low_weight = if (legacy_logup_exports) active_u16 else try arena.mul(active_u16, routed_uses[1].?, span);
    const logup_high_weight = if (legacy_logup_exports) active_u16 else try arena.mul(active_u16, routed_uses[2].?, span);
    const claim_hash_weight = if (legacy_logup_exports) active else try arena.constantField(0, span);
    const native_root_weight = try arena.mul(active, preprocessed.native_root_mask, span);
    const weights = [RELATION_EVENT_COUNT]types.ValueId{
        active,
        claim_hash_weight,
        logup_word_weight,
        input_io_weight,
        output_io_weight,
        active_u16,
        logup_low_weight,
        logup_high_weight,
        native_root_weight,
    };
    const events = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{
            .domain = .recursion_vm_public_claim_word,
            .role = .emit,
            .values = &.{ parameters.semantics_scope, preprocessed.word_index, main.value },
            .weight = active,
        },
        .{
            .domain = .recursion_vm_public_claim_word,
            .role = .emit,
            .values = &.{ parameters.hash_scope, preprocessed.word_index, main.value },
            .weight = claim_hash_weight,
        },
        .{
            .domain = .recursion_vm_public_claim_word,
            .role = .emit,
            .values = &.{ parameters.public_logup_scope, preprocessed.word_index, main.value },
            .weight = logup_word_weight,
        },
        .{
            .domain = .recursion_vm_public_io_word,
            .role = .emit,
            .values = &.{ parameters.input_kind, preprocessed.input_io_index, main.value },
            .weight = input_io_weight,
        },
        .{
            .domain = .recursion_vm_public_io_word,
            .role = .emit,
            .values = &.{ parameters.output_kind, preprocessed.output_io_index, main.value },
            .weight = output_io_weight,
        },
        .{
            .domain = .range_check_8_8,
            .role = .request,
            .values = &.{ main.low_byte, main.high_byte },
            .weight = active_u16,
        },
        .{
            .domain = .recursion_vm_public_claim_byte,
            .role = .emit,
            .values = &.{ preprocessed.word_index, parameters.low_byte_index, main.low_byte },
            .weight = logup_low_weight,
        },
        .{
            .domain = .recursion_vm_public_claim_byte,
            .role = .emit,
            .values = &.{ preprocessed.word_index, parameters.high_byte_index, main.high_byte },
            .weight = logup_high_weight,
        },
        .{
            .domain = .recursion_statement_word,
            .role = .emit,
            .values = &.{ native_root_scope, preprocessed.native_root_side, main.value },
            .weight = native_root_weight,
        },
    }, span);
    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .parameters = parameters,
        .native_root_scope = native_root_scope,
        .active = active,
        .active_boolean = active_boolean,
        .active_u16 = active_u16,
        .roots = roots,
        .constraints = constraints,
        .weights = weights,
        .events = events,
    };
}

fn validateInputs(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    selector_indices: []const usize,
    byte_indices: []const usize,
) error{InvalidVmPublicClaimInputDefinition}!void {
    if (values.len != names.len)
        return error.InvalidVmPublicClaimInputDefinition;
    for (values, names, 0..) |value, expected_name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidVmPublicClaimInputDefinition;
        const node = arena.node(value) orelse
            return error.InvalidVmPublicClaimInputDefinition;
        var ty: types.Type = .felt;
        for (selector_indices) |index| if (index == local_index) {
            ty = .selector;
            break;
        };
        for (byte_indices) |index| if (index == local_index) {
            ty = .byte;
            break;
        };
        if (!std.meta.eql(node.key.ty, ty))
            return error.InvalidVmPublicClaimInputDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidVmPublicClaimInputDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidVmPublicClaimInputDefinition;
        if (!std.mem.eql(u8, actual_name, expected_name))
            return error.InvalidVmPublicClaimInputDefinition;
    }
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
