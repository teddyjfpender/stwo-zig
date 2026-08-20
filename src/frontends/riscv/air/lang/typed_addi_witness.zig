//! Allocation-free shadow witness generation for native typed RV32 ADDI.
//!
//! The immutable binding authenticates the complete physical row recipe, the
//! wrapping-add policy (including the deliberately uncommitted carry chain),
//! the inverse-or-zero hint, and all ordered typed relation effects.  Cold
//! construction validates those identities once.  Accepted hot calls then
//! write directly into caller-owned final column-major storage without an
//! allocator, scratch ownership, indirect dispatch, or intermediate columns.
//!
//! This remains shadow-only.  The production family writer, commitment
//! geometry, transcript, and proof authority are unchanged.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const direct_witness_executor = @import("direct_witness_executor.zig");
const digest = @import("digest.zig");
const hint_recipe = @import("hint_recipe.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const trace_row = @import("../../runner/trace_row.zig");
const production_columns = @import("../trace_columns/base.zig");
const typed_addi = @import("typed_addi.zig");
const types = @import("types.zig");

pub const MAIN_COLUMN_COUNT: usize = typed_addi.MAIN_COLUMN_COUNT;
pub const EVENT_COUNT: usize = typed_addi.RELATION_EVENT_COUNT;
pub const MAX_EVENT_ARITY: usize = 7;
pub const TraceRow = trace_row.TraceRow;

pub const WITNESS_BINDING_FORMAT_VERSION: u16 = 1;
pub const WITNESS_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/addi-witness-binding/v1";
pub const WITNESS_BINDING_DIGEST_HEX =
    "402a9f967e68d9a1f33efd9c646b6bdd51952ce89f9aa477c6de9c470f234595";

pub const WITNESS_BINDING_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, WITNESS_BINDING_DIGEST_HEX) catch
        @compileError("invalid typed ADDI witness-binding digest");
    break :blk result;
};

/// Stable numeric sources for the exact 35 committed columns.
pub const RowSource = enum(u8) {
    trace_clock = 0,
    trace_pc = 1,
    trace_rd_address = 2,
    trace_rd_previous_byte_0 = 3,
    trace_rd_previous_byte_1 = 4,
    trace_rd_previous_byte_2 = 5,
    trace_rd_previous_byte_3 = 6,
    trace_rd_previous_clock = 7,
    trace_rd_next_byte_0 = 8,
    trace_rd_next_byte_1 = 9,
    trace_rd_next_byte_2 = 10,
    trace_rd_next_byte_3 = 11,
    trace_rs1_address = 12,
    trace_rs1_value_previous_byte_0 = 13,
    trace_rs1_value_previous_byte_1 = 14,
    trace_rs1_value_previous_byte_2 = 15,
    trace_rs1_value_previous_byte_3 = 16,
    trace_rs1_previous_clock = 17,
    trace_rs1_value_next_byte_0 = 18,
    trace_rs1_value_next_byte_1 = 19,
    trace_rs1_value_next_byte_2 = 20,
    trace_rs1_value_next_byte_3 = 21,
    trace_signed_immediate_low_byte = 22,
    trace_signed_immediate_high_three_bits = 23,
    trace_signed_immediate_sign = 24,
    constant_addi_active = 25,
    constant_xori_inactive = 26,
    constant_ori_inactive = 27,
    constant_andi_inactive = 28,
    derived_wrapping_sum_byte_0 = 29,
    derived_wrapping_sum_byte_1 = 30,
    derived_wrapping_sum_byte_2 = 31,
    derived_wrapping_sum_byte_3 = 32,
    hint_rd_nonzero = 33,
    hint_rd_inverse_or_zero = 34,
};

pub const CANONICAL_RECIPE = [MAIN_COLUMN_COUNT]RowSource{
    .trace_clock,
    .trace_pc,
    .trace_rd_address,
    .trace_rd_previous_byte_0,
    .trace_rd_previous_byte_1,
    .trace_rd_previous_byte_2,
    .trace_rd_previous_byte_3,
    .trace_rd_previous_clock,
    .trace_rd_next_byte_0,
    .trace_rd_next_byte_1,
    .trace_rd_next_byte_2,
    .trace_rd_next_byte_3,
    .trace_rs1_address,
    .trace_rs1_value_previous_byte_0,
    .trace_rs1_value_previous_byte_1,
    .trace_rs1_value_previous_byte_2,
    .trace_rs1_value_previous_byte_3,
    .trace_rs1_previous_clock,
    .trace_rs1_value_next_byte_0,
    .trace_rs1_value_next_byte_1,
    .trace_rs1_value_next_byte_2,
    .trace_rs1_value_next_byte_3,
    .trace_signed_immediate_low_byte,
    .trace_signed_immediate_high_three_bits,
    .trace_signed_immediate_sign,
    .constant_addi_active,
    .constant_xori_inactive,
    .constant_ori_inactive,
    .constant_andi_inactive,
    .derived_wrapping_sum_byte_0,
    .derived_wrapping_sum_byte_1,
    .derived_wrapping_sum_byte_2,
    .derived_wrapping_sum_byte_3,
    .hint_rd_nonzero,
    .hint_rd_inverse_or_zero,
};

pub const ArithmeticAlgorithm = enum(u8) {
    rv32_wrapping_add_signed_imm12 = 0,
};

pub const ArithmeticSource = enum(u8) {
    trace_rs1_value = 0,
    trace_signed_immediate = 1,
};

pub const CarryPolicy = enum(u8) {
    /// Carries are derived by the AIR and never accepted as witness inputs.
    derived_uncommitted_boolean_chain = 0,
    /// Representable only so deserialized/adversarial plans fail by value at
    /// the authenticated boundary; it is never a supported ADDI policy.
    external_committed_carries = 1,
};

pub const ArithmeticBinding = struct {
    algorithm: ArithmeticAlgorithm,
    lhs: ArithmeticSource,
    rhs: ArithmeticSource,
    first_result_column: u8,
    result_limb_count: u8,
    carry_policy: CarryPolicy,
};

pub const CANONICAL_ARITHMETIC = ArithmeticBinding{
    .algorithm = .rv32_wrapping_add_signed_imm12,
    .lhs = .trace_rs1_value,
    .rhs = .trace_signed_immediate,
    .first_result_column = 29,
    .result_limb_count = 4,
    .carry_policy = .derived_uncommitted_boolean_chain,
};

pub const HintActivation = enum(u8) { active_rows = 0 };

pub const DestinationHintBinding = struct {
    recipe: types.HintRecipeId,
    recipe_version: u16,
    algorithm: hint_recipe.Algorithm,
    exceptional_cases: hint_recipe.ExceptionalCasePolicy,
    input_count: u8,
    output_count: u8,
    input_column: u8,
    inverse_output_column: u8,
    nonzero_output_column: u8,
    activation: HintActivation,
};

const destination_recipe = hint_recipe.get(.field_inverse_or_zero);

pub const CANONICAL_DESTINATION_HINT = DestinationHintBinding{
    .recipe = hint_recipe.id(.field_inverse_or_zero),
    .recipe_version = destination_recipe.version,
    .algorithm = destination_recipe.algorithm,
    .exceptional_cases = destination_recipe.exceptional_cases,
    .input_count = destination_recipe.input_types.len,
    .output_count = destination_recipe.output_types.len,
    .input_column = 2,
    .inverse_output_column = 34,
    .nonzero_output_column = 33,
    .activation = .active_rows,
};

pub const SlotBinding = struct {
    column: u8,
    value: types.ValueId,
    source: RowSource,
};

const no_value: types.ValueId = @enumFromInt(std.math.maxInt(u32));

pub const EventBinding = struct {
    effect: types.EffectId,
    kind: program.EffectKind,
    schema: types.RelationSchemaId,
    schema_version: u16,
    role: relation.Role,
    liveness: types.ValueId,
    arity: u8,
    values: [MAX_EVENT_ARITY]types.ValueId,
    access_ordinal: ?u8,
};

pub const EventSpec = struct {
    kind: program.EffectKind,
    domain: relation.Domain,
    role: relation.Role,
    arity: u8,
    access_ordinal: ?u8 = null,
};

pub const EVENT_SPECS = [EVENT_COUNT]EventSpec{
    .{ .kind = .program_fetch, .domain = .program_access, .role = .request, .arity = 5 },
    .{ .kind = .range_request, .domain = .range_check_8_11, .role = .request, .arity = 2 },
    .{ .kind = .state_consume, .domain = .registers_state, .role = .consume, .arity = 2 },
    .{ .kind = .state_produce, .domain = .registers_state, .role = .emit, .arity = 2 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 1 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 1 },
    .{ .kind = .register_read, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 1 },
    .{ .kind = .bitwise_request, .domain = .bitwise, .role = .request, .arity = 4 },
    .{ .kind = .bitwise_request, .domain = .bitwise, .role = .request, .arity = 4 },
    .{ .kind = .bitwise_request, .domain = .bitwise, .role = .request, .arity = 4 },
    .{ .kind = .bitwise_request, .domain = .bitwise, .role = .request, .arity = 4 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .register_write, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 2 },
    .{ .kind = .register_write, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 2 },
    .{ .kind = .register_write, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 2 },
};

/// Pointer-free executable identity retained after the authored arena dies.
pub const WitnessBinding = struct {
    format_version: u16,
    semantic_format_version: u16,
    opcode_id: u32,
    semantic_digest: digest.Digest,
    slots: [MAIN_COLUMN_COUNT]SlotBinding,
    arithmetic: ArithmeticBinding,
    destination_hint: DestinationHintBinding,
    events: [EVENT_COUNT]EventBinding,

    pub fn canonical(
        definition: *const typed_addi.Definition,
    ) ConstructionError!WitnessBinding {
        try definition.validate();
        try validatePhysicalDefinition(definition);
        return canonicalUnchecked(definition);
    }

    pub fn identityDigest(self: *const WitnessBinding) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(WITNESS_BINDING_DOMAIN_SEPARATOR);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.semantic_format_version);
        hashInt(&hash, u32, self.opcode_id);
        hash.update(&self.semantic_digest);
        hashInt(&hash, u16, MAIN_COLUMN_COUNT);
        for (self.slots) |slot| {
            hashInt(&hash, u8, slot.column);
            hashInt(&hash, u32, @intFromEnum(slot.value));
            hashInt(&hash, u8, @intFromEnum(slot.source));
        }
        hashInt(&hash, u8, @intFromEnum(self.arithmetic.algorithm));
        hashInt(&hash, u8, @intFromEnum(self.arithmetic.lhs));
        hashInt(&hash, u8, @intFromEnum(self.arithmetic.rhs));
        hashInt(&hash, u8, self.arithmetic.first_result_column);
        hashInt(&hash, u8, self.arithmetic.result_limb_count);
        hashInt(&hash, u8, @intFromEnum(self.arithmetic.carry_policy));
        hashInt(&hash, u16, @intFromEnum(self.destination_hint.recipe));
        hashInt(&hash, u16, self.destination_hint.recipe_version);
        hashInt(&hash, u16, @intFromEnum(self.destination_hint.algorithm));
        hashInt(
            &hash,
            u8,
            @intFromEnum(self.destination_hint.exceptional_cases),
        );
        hashInt(&hash, u8, self.destination_hint.input_count);
        hashInt(&hash, u8, self.destination_hint.output_count);
        hashInt(&hash, u8, self.destination_hint.input_column);
        hashInt(&hash, u8, self.destination_hint.inverse_output_column);
        hashInt(&hash, u8, self.destination_hint.nonzero_output_column);
        hashInt(&hash, u8, @intFromEnum(self.destination_hint.activation));
        hashInt(&hash, u16, EVENT_COUNT);
        for (self.events) |event| {
            hashInt(&hash, u32, @intFromEnum(event.effect));
            hashInt(&hash, u8, @intFromEnum(event.kind));
            hashInt(&hash, u16, @intFromEnum(event.schema));
            hashInt(&hash, u16, event.schema_version);
            hashInt(&hash, u8, @intFromEnum(event.role));
            hashInt(&hash, u32, @intFromEnum(event.liveness));
            hashInt(&hash, u8, event.arity);
            for (event.values) |value|
                hashInt(&hash, u32, @intFromEnum(value));
            hashOptionalU8(&hash, event.access_ordinal);
        }
        return hash.finalResult();
    }
};

pub const ConstructionError = typed_addi.ValidationError || error{
    InvalidWitnessBinding,
};

pub const ExecutionError = direct_witness_executor.Error;

pub const RelationEvent = struct {
    kind: program.EffectKind,
    domain: relation.Domain,
    role: relation.Role,
    liveness: M31,
    arity: u8,
    values: [MAX_EVENT_ARITY]M31,
    access_ordinal: ?u8,

    pub fn signedNumerator(self: RelationEvent) M31 {
        return switch (self.role) {
            .emit => self.liveness,
            .request, .consume => M31.zero().sub(self.liveness),
        };
    }
};

pub const RelationRow = struct {
    events: [EVENT_COUNT]RelationEvent,
};

/// Immutable ADDI shadow executor, safe to share between worker threads.
pub const Executor = struct {
    binding: WitnessBinding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const typed_addi.Definition,
        supplied: *const WitnessBinding,
    ) ConstructionError!Executor {
        try definition.validate();
        try validatePhysicalDefinition(definition);
        const expected = try canonicalUnchecked(definition);
        if (!std.meta.eql(expected, supplied.*))
            return error.InvalidWitnessBinding;
        const binding_digest = supplied.identityDigest();
        if (!std.mem.eql(u8, &binding_digest, &WITNESS_BINDING_DIGEST))
            return error.InvalidWitnessBinding;
        return .{ .binding = supplied.*, .binding_digest = binding_digest };
    }

    pub fn identitySnapshot(self: *const Executor) WitnessBinding {
        return self.binding;
    }

    pub fn identityDigest(self: *const Executor) digest.Digest {
        return self.binding_digest;
    }

    /// Fill exact final column-major main storage; padding is exactly zero.
    pub fn generateMainInto(
        self: *const Executor,
        columns: *[MAIN_COLUMN_COUNT][]M31,
        rows: []const TraceRow,
        log_size: u32,
    ) ExecutionError!void {
        return direct_witness_executor.generateMainInto(
            M31,
            TraceRow,
            MAIN_COLUMN_COUNT,
            columns,
            rows,
            log_size,
            M31.zero(),
            self,
            validateRow,
            writeRow,
        );
    }

    /// Generate the exact declaration-order typed relation row without heap
    /// work. This is shadow evidence; production interactions remain unchanged.
    pub fn generateRelationRow(
        _: *const Executor,
        row: TraceRow,
    ) ExecutionError!RelationRow {
        try validateRow(row);
        return buildRelationRow(row);
    }
};

const PhysicalSpec = struct {
    name: []const u8,
    ty: types.Type,
    source: RowSource,
};

const uint3 = types.Type{ .bounded_uint = .{
    .bits = 3,
    .representation = .canonical_field,
} };

const physical_specs = [MAIN_COLUMN_COUNT]PhysicalSpec{
    .{ .name = "clock", .ty = .clock, .source = .trace_clock },
    .{ .name = "pc", .ty = .pc, .source = .trace_pc },
    .{ .name = "rd_addr", .ty = .register_index, .source = .trace_rd_address },
    .{ .name = "rd_prev_0", .ty = .byte, .source = .trace_rd_previous_byte_0 },
    .{ .name = "rd_prev_1", .ty = .byte, .source = .trace_rd_previous_byte_1 },
    .{ .name = "rd_prev_2", .ty = .byte, .source = .trace_rd_previous_byte_2 },
    .{ .name = "rd_prev_3", .ty = .byte, .source = .trace_rd_previous_byte_3 },
    .{ .name = "rd_clock_prev", .ty = .clock, .source = .trace_rd_previous_clock },
    .{ .name = "rd_next_0", .ty = .byte, .source = .trace_rd_next_byte_0 },
    .{ .name = "rd_next_1", .ty = .byte, .source = .trace_rd_next_byte_1 },
    .{ .name = "rd_next_2", .ty = .byte, .source = .trace_rd_next_byte_2 },
    .{ .name = "rd_next_3", .ty = .byte, .source = .trace_rd_next_byte_3 },
    .{ .name = "rs1_addr", .ty = .register_index, .source = .trace_rs1_address },
    .{ .name = "rs1_prev_0", .ty = .byte, .source = .trace_rs1_value_previous_byte_0 },
    .{ .name = "rs1_prev_1", .ty = .byte, .source = .trace_rs1_value_previous_byte_1 },
    .{ .name = "rs1_prev_2", .ty = .byte, .source = .trace_rs1_value_previous_byte_2 },
    .{ .name = "rs1_prev_3", .ty = .byte, .source = .trace_rs1_value_previous_byte_3 },
    .{ .name = "rs1_clock_prev", .ty = .clock, .source = .trace_rs1_previous_clock },
    .{ .name = "rs1_next_0", .ty = .byte, .source = .trace_rs1_value_next_byte_0 },
    .{ .name = "rs1_next_1", .ty = .byte, .source = .trace_rs1_value_next_byte_1 },
    .{ .name = "rs1_next_2", .ty = .byte, .source = .trace_rs1_value_next_byte_2 },
    .{ .name = "rs1_next_3", .ty = .byte, .source = .trace_rs1_value_next_byte_3 },
    .{ .name = "imm_0", .ty = .byte, .source = .trace_signed_immediate_low_byte },
    .{ .name = "imm_1", .ty = uint3, .source = .trace_signed_immediate_high_three_bits },
    .{ .name = "imm_msb", .ty = .bit, .source = .trace_signed_immediate_sign },
    .{ .name = "opcode_add_flag", .ty = .bit, .source = .constant_addi_active },
    .{ .name = "opcode_xor_flag", .ty = .bit, .source = .constant_xori_inactive },
    .{ .name = "opcode_or_flag", .ty = .bit, .source = .constant_ori_inactive },
    .{ .name = "opcode_and_flag", .ty = .bit, .source = .constant_andi_inactive },
    .{ .name = "result_0", .ty = .byte, .source = .derived_wrapping_sum_byte_0 },
    .{ .name = "result_1", .ty = .byte, .source = .derived_wrapping_sum_byte_1 },
    .{ .name = "result_2", .ty = .byte, .source = .derived_wrapping_sum_byte_2 },
    .{ .name = "result_3", .ty = .byte, .source = .derived_wrapping_sum_byte_3 },
    .{ .name = "rd_nonzero", .ty = .bit, .source = .hint_rd_nonzero },
    .{ .name = "rd_inv", .ty = .felt, .source = .hint_rd_inverse_or_zero },
};

fn canonicalUnchecked(
    definition: *const typed_addi.Definition,
) error{InvalidWitnessBinding}!WitnessBinding {
    const physical = definition.columns.physical();
    var slots: [MAIN_COLUMN_COUNT]SlotBinding = undefined;
    for (&slots, physical, CANONICAL_RECIPE, 0..) |*slot, value, source, column| {
        slot.* = .{ .column = @intCast(column), .value = value, .source = source };
    }

    var events: [EVENT_COUNT]EventBinding = undefined;
    for (&events, EVENT_SPECS, 0..) |*destination, spec, index| {
        const effect_id = types.idFromIndex(types.EffectId, index) catch
            return error.InvalidWitnessBinding;
        const effect = definition.arena.effect(effect_id) orelse
            return error.InvalidWitnessBinding;
        const binding = effect.binding orelse return error.InvalidWitnessBinding;
        const liveness = effect.liveness orelse return error.InvalidWitnessBinding;
        const values = definition.arena.effectValues(effect_id) orelse
            return error.InvalidWitnessBinding;
        const schema = relation.get(spec.domain);
        if (values.len != spec.arity or effect.kind != spec.kind or
            binding.schema != schema.id or binding.schema_version != schema.version or
            binding.role != spec.role or effect.access_ordinal != spec.access_ordinal)
        {
            return error.InvalidWitnessBinding;
        }
        var owned_values = [_]types.ValueId{no_value} ** MAX_EVENT_ARITY;
        @memcpy(owned_values[0..values.len], values);
        destination.* = .{
            .effect = effect_id,
            .kind = effect.kind,
            .schema = binding.schema,
            .schema_version = binding.schema_version,
            .role = binding.role,
            .liveness = liveness,
            .arity = @intCast(values.len),
            .values = owned_values,
            .access_ordinal = effect.access_ordinal,
        };
    }
    return .{
        .format_version = WITNESS_BINDING_FORMAT_VERSION,
        .semantic_format_version = digest.typed_lookup_request_format_version,
        .opcode_id = typed_addi.ADDI_OPCODE_ID,
        .semantic_digest = typed_addi.SEMANTIC_DIGEST,
        .slots = slots,
        .arithmetic = CANONICAL_ARITHMETIC,
        .destination_hint = CANONICAL_DESTINATION_HINT,
        .events = events,
    };
}

fn validatePhysicalDefinition(
    definition: *const typed_addi.Definition,
) error{InvalidWitnessBinding}!void {
    const physical = definition.columns.physical();
    inline for (physical_specs, 0..) |spec, index| {
        const value = physical[index];
        if (types.idIndex(value) != index or spec.source != CANONICAL_RECIPE[index])
            return error.InvalidWitnessBinding;
        const node = definition.arena.node(value) orelse
            return error.InvalidWitnessBinding;
        if (!std.meta.eql(node.key.ty, spec.ty))
            return error.InvalidWitnessBinding;
        const name_id = switch (node.key.op) {
            .input => |name| name,
            else => return error.InvalidWitnessBinding,
        };
        const name = definition.arena.name(name_id) orelse
            return error.InvalidWitnessBinding;
        if (!std.mem.eql(u8, name, spec.name))
            return error.InvalidWitnessBinding;
    }
}

const DecodedRow = struct {
    clock: M31,
    pc: M31,
    rd: M31,
    rd_previous: [4]M31,
    rd_previous_clock: M31,
    rd_next: [4]M31,
    rs1: M31,
    rs1_value: [4]M31,
    rs1_previous_clock: M31,
    immediate_bits: u32,
    immediate: [4]M31,
    result: [4]M31,
    destination_nonzero: M31,
    destination_inverse: M31,
};

inline fn decodeRow(row: TraceRow) DecodedRow {
    const immediate_word: u32 = @bitCast(row.imm);
    const immediate_bits = immediate_word & 0xfff;
    const sign = (immediate_bits >> 11) & 1;
    const rd = fromUnsigned(row.rd);
    return .{
        .clock = fromUnsigned(row.clk),
        .pc = fromUnsigned(row.pc),
        .rd = rd,
        .rd_previous = limbs(row.rd_prev_val),
        .rd_previous_clock = fromUnsigned(row.rd_prev_clk),
        .rd_next = limbs(row.rd_val),
        .rs1 = fromUnsigned(row.rs1),
        .rs1_value = limbs(row.rs1_val),
        .rs1_previous_clock = fromUnsigned(row.rs1_prev_clk),
        .immediate_bits = immediate_bits,
        .immediate = .{
            fromUnsigned(immediate_bits & 0xff),
            fromUnsigned(((immediate_bits >> 8) & 0x7) + sign * 248),
            fromUnsigned(sign * 255),
            fromUnsigned(sign * 255),
        },
        .result = limbs(row.rs1_val +% immediate_word),
        .destination_nonzero = if (row.rd == 0) M31.zero() else M31.one(),
        .destination_inverse = if (row.rd == 0)
            M31.zero()
        else
            rd.invUncheckedNonZero(),
    };
}

inline fn writeRow(
    columns: *[MAIN_COLUMN_COUNT][]M31,
    row_index: usize,
    row: TraceRow,
) void {
    const decoded = decodeRow(row);
    columns[0][row_index] = decoded.clock;
    columns[1][row_index] = decoded.pc;
    columns[2][row_index] = decoded.rd;
    inline for (0..4) |limb| columns[3 + limb][row_index] = decoded.rd_previous[limb];
    columns[7][row_index] = decoded.rd_previous_clock;
    inline for (0..4) |limb| columns[8 + limb][row_index] = decoded.rd_next[limb];
    columns[12][row_index] = decoded.rs1;
    inline for (0..4) |limb| columns[13 + limb][row_index] = decoded.rs1_value[limb];
    columns[17][row_index] = decoded.rs1_previous_clock;
    inline for (0..4) |limb| columns[18 + limb][row_index] = decoded.rs1_value[limb];
    columns[22][row_index] = decoded.immediate[0];
    columns[23][row_index] = fromUnsigned((decoded.immediate_bits >> 8) & 0x7);
    columns[24][row_index] = fromUnsigned(decoded.immediate_bits >> 11);
    columns[25][row_index] = M31.one();
    columns[26][row_index] = M31.zero();
    columns[27][row_index] = M31.zero();
    columns[28][row_index] = M31.zero();
    inline for (0..4) |limb| columns[29 + limb][row_index] = decoded.result[limb];
    columns[33][row_index] = decoded.destination_nonzero;
    columns[34][row_index] = decoded.destination_inverse;
}

fn validateRow(row: TraceRow) ExecutionError!void {
    if (row.opcode != .ADDI or row.imm < -2048 or row.imm > 2047 or
        row.clk == 0 or row.next_pc != row.pc +% 4 or row.is_load or
        row.is_store or row.branch_taken)
    {
        return error.InvalidTraceRow;
    }
    const source_clock = accessClock(row.clk, 1) orelse
        return error.InvalidTraceRow;
    const destination_clock = accessClock(row.clk, 2) orelse
        return error.InvalidTraceRow;
    if (!validGap(row.rs1_prev_clk, source_clock) or
        !validGap(row.rd_prev_clk, destination_clock))
    {
        return error.InvalidTraceRow;
    }
    const expected = row.rs1_val +% @as(u32, @bitCast(row.imm));
    if (row.rd_val != (if (row.rd == 0) 0 else expected) or
        (row.rs1 == 0 and row.rs1_val != 0) or
        (row.rd == 0 and row.rd_prev_val != 0))
    {
        return error.InvalidTraceRow;
    }
    if (row.rd == row.rs1 and
        (row.rd_prev_val != row.rs1_val or row.rd_prev_clk != source_clock))
    {
        return error.InvalidTraceRow;
    }
}

fn buildRelationRow(row: TraceRow) RelationRow {
    const d = decodeRow(row);
    const one = M31.one();
    const zero = M31.zero();
    const four = fromUnsigned(4);
    const source_clock = d.clock.sub(one).mul(four).add(one);
    const destination_clock = d.clock.sub(one).mul(four).add(fromUnsigned(2));
    const source_gap = source_clock.sub(d.rs1_previous_clock).sub(one);
    const destination_gap = destination_clock.sub(d.rd_previous_clock).sub(one);
    const high_shifted = fromUnsigned(((d.immediate_bits >> 8) & 0x7) << 8);
    const unsigned_immediate = fromUnsigned(d.immediate_bits);

    var result: RelationRow = undefined;
    result.events[0] = makeEvent(0, one, .{
        d.pc, fromUnsigned(typed_addi.ADDI_OPCODE_ID), d.rd, d.rs1, unsigned_immediate,
    });
    result.events[1] = makeEvent(1, one, .{ d.immediate[0], high_shifted });
    result.events[2] = makeEvent(2, one, .{ d.pc, d.clock });
    result.events[3] = makeEvent(3, one, .{ d.pc.add(four), d.clock.add(one) });
    result.events[4] = makeEvent(4, one, .{
        zero,           d.rs1,          d.rs1_previous_clock,
        d.rs1_value[0], d.rs1_value[1], d.rs1_value[2],
        d.rs1_value[3],
    });
    result.events[5] = makeEvent(5, one, .{
        zero,           d.rs1,          source_clock,
        d.rs1_value[0], d.rs1_value[1], d.rs1_value[2],
        d.rs1_value[3],
    });
    result.events[6] = makeEvent(6, one, .{source_gap});
    inline for (0..4) |limb| result.events[7 + limb] = makeEvent(
        7 + limb,
        zero,
        .{ d.rs1_value[limb], d.immediate[limb], d.result[limb], zero },
    );
    result.events[11] = makeEvent(11, one, .{ d.result[0], d.result[1] });
    result.events[12] = makeEvent(12, one, .{ d.result[2], d.result[3] });
    result.events[13] = makeEvent(13, one, .{
        zero,             d.rd,             d.rd_previous_clock,
        d.rd_previous[0], d.rd_previous[1], d.rd_previous[2],
        d.rd_previous[3],
    });
    result.events[14] = makeEvent(14, one, .{
        zero,         d.rd,         destination_clock,
        d.rd_next[0], d.rd_next[1], d.rd_next[2],
        d.rd_next[3],
    });
    result.events[15] = makeEvent(15, one, .{destination_gap});
    return result;
}

fn makeEvent(
    comptime index: usize,
    liveness: M31,
    values: anytype,
) RelationEvent {
    const spec = EVENT_SPECS[index];
    comptime if (values.len != spec.arity)
        @compileError("typed ADDI relation row arity drift");
    var owned = [_]M31{M31.zero()} ** MAX_EVENT_ARITY;
    inline for (values, 0..) |value, field| owned[field] = value;
    return .{
        .kind = spec.kind,
        .domain = spec.domain,
        .role = spec.role,
        .liveness = liveness,
        .arity = spec.arity,
        .values = owned,
        .access_ordinal = spec.access_ordinal,
    };
}

fn accessClock(clock: u32, phase: u32) ?u32 {
    if (clock == 0 or phase == 0 or phase > 3) return null;
    const encoded = (@as(u64, clock) - 1) * 4 + phase;
    return std.math.cast(u32, encoded);
}

fn validGap(previous: u32, current: u32) bool {
    if (previous >= current) return false;
    return current - previous - 1 < (@as(u32, 1) << 20);
}

inline fn fromUnsigned(value: anytype) M31 {
    return M31.fromU64(@intCast(value));
}

inline fn limbs(value: u32) [4]M31 {
    return .{
        fromUnsigned(value & 0xff),
        fromUnsigned((value >> 8) & 0xff),
        fromUnsigned((value >> 16) & 0xff),
        fromUnsigned(value >> 24),
    };
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

fn hashOptionalU8(hash: anytype, value: ?u8) void {
    if (value) |present| {
        hashInt(hash, u8, 1);
        hashInt(hash, u8, present);
    } else {
        hashInt(hash, u8, 0);
    }
}

comptime {
    if (MAIN_COLUMN_COUNT != production_columns.BaseAluImmColumns.N_COLUMNS)
        @compileError("typed ADDI witness width drifted from production");
    const fields = @typeInfo(production_columns.BaseAluImmColumns).@"struct".fields;
    for (physical_specs, fields, CANONICAL_RECIPE, 0..) |spec, field, source, index| {
        if (!std.mem.eql(u8, spec.name, field.name))
            @compileError("typed ADDI witness name drifted from production");
        if (spec.source != source or @intFromEnum(source) != index)
            @compileError("typed ADDI numeric row recipe is not canonical");
    }
    if (MAX_EVENT_ARITY != relation.get(.memory_access).fields.len)
        @compileError("typed ADDI event storage must match its widest relation");
}
