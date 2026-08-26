//! Allocation-free production witness generation for native typed BEQ/BNE.
//!
//! Cold construction authenticates the semantic definition, exact thirty-slot
//! row recipe, opcode decisions, inverse-marker policy, and event geometry.
//! Accepted hot rows write directly into final SoA storage with no allocator,
//! scratch copy, string dispatch, or runtime recipe walk.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const digest = @import("digest.zig");
const direct_witness_executor = @import("direct_witness_executor.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const trace_row = @import("../../runner/trace_row.zig");
const production_columns = @import("../trace_columns/compare.zig");
const typed = @import("typed_branch_eq.zig");
const types = @import("types.zig");

pub const MAIN_COLUMN_COUNT: usize = typed.MAIN_COLUMN_COUNT;
pub const EVENT_COUNT: usize = typed.LOOKUP_COUNT;
pub const MAX_EVENT_ARITY: usize = 7;
pub const TraceRow = trace_row.TraceRow;

pub const WITNESS_BINDING_FORMAT_VERSION: u16 = 1;
pub const WITNESS_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/branch-eq-witness-binding/v1";
pub const WITNESS_BINDING_DIGEST_HEX =
    "18b4a5dc55e5bcd193c714daaf62f6399023af74080f5653aa58e51d4bea48e6";
pub const WITNESS_BINDING_DIGEST: digest.Digest = hexDigest(
    WITNESS_BINDING_DIGEST_HEX,
    "invalid typed BRANCH_EQ witness-binding digest",
);

pub const RowSource = enum(u8) {
    trace_clock = 0,
    trace_pc = 1,
    trace_rs1_address = 2,
    trace_rs1_previous_byte_0 = 3,
    trace_rs1_previous_byte_1 = 4,
    trace_rs1_previous_byte_2 = 5,
    trace_rs1_previous_byte_3 = 6,
    trace_rs1_previous_clock = 7,
    trace_rs1_next_byte_0 = 8,
    trace_rs1_next_byte_1 = 9,
    trace_rs1_next_byte_2 = 10,
    trace_rs1_next_byte_3 = 11,
    trace_rs2_address = 12,
    trace_rs2_previous_byte_0 = 13,
    trace_rs2_previous_byte_1 = 14,
    trace_rs2_previous_byte_2 = 15,
    trace_rs2_previous_byte_3 = 16,
    trace_rs2_previous_clock = 17,
    trace_rs2_next_byte_0 = 18,
    trace_rs2_next_byte_1 = 19,
    trace_rs2_next_byte_2 = 20,
    trace_rs2_next_byte_3 = 21,
    trace_signed_immediate = 22,
    derived_branch_decision = 23,
    hint_difference_inverse_0 = 24,
    hint_difference_inverse_1 = 25,
    hint_difference_inverse_2 = 26,
    hint_difference_inverse_3 = 27,
    derived_beq_flag = 28,
    derived_bne_flag = 29,
};

pub const CANONICAL_RECIPE = [MAIN_COLUMN_COUNT]RowSource{
    .trace_clock,
    .trace_pc,
    .trace_rs1_address,
    .trace_rs1_previous_byte_0,
    .trace_rs1_previous_byte_1,
    .trace_rs1_previous_byte_2,
    .trace_rs1_previous_byte_3,
    .trace_rs1_previous_clock,
    .trace_rs1_next_byte_0,
    .trace_rs1_next_byte_1,
    .trace_rs1_next_byte_2,
    .trace_rs1_next_byte_3,
    .trace_rs2_address,
    .trace_rs2_previous_byte_0,
    .trace_rs2_previous_byte_1,
    .trace_rs2_previous_byte_2,
    .trace_rs2_previous_byte_3,
    .trace_rs2_previous_clock,
    .trace_rs2_next_byte_0,
    .trace_rs2_next_byte_1,
    .trace_rs2_next_byte_2,
    .trace_rs2_next_byte_3,
    .trace_signed_immediate,
    .derived_branch_decision,
    .hint_difference_inverse_0,
    .hint_difference_inverse_1,
    .hint_difference_inverse_2,
    .hint_difference_inverse_3,
    .derived_beq_flag,
    .derived_bne_flag,
};

pub const ComparisonDecision = enum(u8) {
    equal = 0,
    not_equal = 1,
};

pub const OperationBinding = struct {
    opcode_id: u32,
    flag_column: u8,
    decision: ComparisonDecision,
};

pub const CANONICAL_OPERATIONS = [2]OperationBinding{
    .{ .opcode_id = typed.BEQ_OPCODE_ID, .flag_column = 28, .decision = .equal },
    .{ .opcode_id = typed.BNE_OPCODE_ID, .flag_column = 29, .decision = .not_equal },
};

pub const InverseMarkerAlgorithm = enum(u8) {
    first_nonzero_little_endian_limb = 0,
    last_nonzero_little_endian_limb = 1,
};

pub const CANONICAL_INVERSE_ALGORITHM: InverseMarkerAlgorithm =
    .first_nonzero_little_endian_limb;

pub const EventSpec = struct {
    kind: program.EffectKind,
    domain: relation.Domain,
    role: relation.Role,
    arity: u8,
    access_ordinal: ?u8 = null,
};

pub const EVENT_SPECS = [EVENT_COUNT]EventSpec{
    .{ .kind = .program_fetch, .domain = .program_access, .role = .request, .arity = 5 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 1 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 1 },
    .{ .kind = .register_read, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 1 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 2 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 2 },
    .{ .kind = .register_read, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 2 },
    .{ .kind = .state_consume, .domain = .registers_state, .role = .consume, .arity = 2 },
    .{ .kind = .state_produce, .domain = .registers_state, .role = .emit, .arity = 2 },
};

pub const SlotBinding = struct {
    column: u8,
    value: types.ValueId,
    source: RowSource,
};

pub const WitnessBinding = struct {
    format_version: u16,
    semantic_format_version: u16,
    semantic_digest: digest.Digest,
    slots: [MAIN_COLUMN_COUNT]SlotBinding,
    operations: [CANONICAL_OPERATIONS.len]OperationBinding,
    inverse_algorithm: InverseMarkerAlgorithm,
    events: [EVENT_COUNT]EventSpec,

    pub fn canonical(definition: *const typed.Definition) ConstructionError!WitnessBinding {
        try definition.validate();
        try validatePhysicalDefinition(definition);
        return canonicalUnchecked(definition);
    }

    pub fn identityDigest(self: *const WitnessBinding) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(WITNESS_BINDING_DOMAIN_SEPARATOR);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.semantic_format_version);
        hash.update(&self.semantic_digest);
        hashInt(&hash, u16, MAIN_COLUMN_COUNT);
        for (self.slots) |slot| {
            hashInt(&hash, u8, slot.column);
            hashInt(&hash, u32, @intFromEnum(slot.value));
            hashInt(&hash, u8, @intFromEnum(slot.source));
        }
        hashInt(&hash, u8, CANONICAL_OPERATIONS.len);
        for (self.operations) |operation| {
            hashInt(&hash, u32, operation.opcode_id);
            hashInt(&hash, u8, operation.flag_column);
            hashInt(&hash, u8, @intFromEnum(operation.decision));
        }
        hashInt(&hash, u8, @intFromEnum(self.inverse_algorithm));
        hashInt(&hash, u8, EVENT_COUNT);
        for (self.events) |event| {
            hashInt(&hash, u8, @intFromEnum(event.kind));
            hashInt(&hash, u8, @intFromEnum(event.domain));
            hashInt(&hash, u8, @intFromEnum(event.role));
            hashInt(&hash, u8, event.arity);
            // Zero is the absence code; present ordinals are shifted so even
            // an invalid future ordinal zero cannot alias null in identity.
            hashInt(
                &hash,
                u8,
                if (event.access_ordinal) |ordinal| ordinal + 1 else 0,
            );
        }
        return hash.finalResult();
    }
};

pub const ConstructionError = typed.ValidationError || error{InvalidWitnessBinding};
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
            .request, .consume => self.liveness.neg(),
        };
    }
};

pub const RelationRow = struct { events: [EVENT_COUNT]RelationEvent };

pub const Executor = struct {
    binding: WitnessBinding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const typed.Definition,
        supplied: *const WitnessBinding,
    ) ConstructionError!Executor {
        const expected = try WitnessBinding.canonical(definition);
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
            writeActiveRow,
        );
    }

    pub fn generateRelationRow(_: *const Executor, row: TraceRow) ExecutionError!RelationRow {
        try validateRow(row);
        return buildRelationRow(row);
    }
};

fn canonicalUnchecked(definition: *const typed.Definition) WitnessBinding {
    const physical = definition.columns.physical();
    var slots: [MAIN_COLUMN_COUNT]SlotBinding = undefined;
    for (&slots, physical, CANONICAL_RECIPE, 0..) |*slot, value, row_source, column| {
        slot.* = .{
            .column = @intCast(column),
            .value = value,
            .source = row_source,
        };
    }
    return .{
        .format_version = WITNESS_BINDING_FORMAT_VERSION,
        .semantic_format_version = digest.program_control_target_format_version,
        .semantic_digest = typed.SEMANTIC_DIGEST,
        .slots = slots,
        .operations = CANONICAL_OPERATIONS,
        .inverse_algorithm = CANONICAL_INVERSE_ALGORITHM,
        .events = EVENT_SPECS,
    };
}

const PhysicalSpec = struct {
    name: []const u8,
    ty: types.Type,
    source: RowSource,
};

const physical_specs = [MAIN_COLUMN_COUNT]PhysicalSpec{
    .{ .name = "clock", .ty = .clock, .source = .trace_clock },
    .{ .name = "pc", .ty = .pc, .source = .trace_pc },
    .{ .name = "rs1_addr", .ty = .register_index, .source = .trace_rs1_address },
    .{ .name = "rs1_prev_0", .ty = .byte, .source = .trace_rs1_previous_byte_0 },
    .{ .name = "rs1_prev_1", .ty = .byte, .source = .trace_rs1_previous_byte_1 },
    .{ .name = "rs1_prev_2", .ty = .byte, .source = .trace_rs1_previous_byte_2 },
    .{ .name = "rs1_prev_3", .ty = .byte, .source = .trace_rs1_previous_byte_3 },
    .{ .name = "rs1_clock_prev", .ty = .clock, .source = .trace_rs1_previous_clock },
    .{ .name = "rs1_next_0", .ty = .byte, .source = .trace_rs1_next_byte_0 },
    .{ .name = "rs1_next_1", .ty = .byte, .source = .trace_rs1_next_byte_1 },
    .{ .name = "rs1_next_2", .ty = .byte, .source = .trace_rs1_next_byte_2 },
    .{ .name = "rs1_next_3", .ty = .byte, .source = .trace_rs1_next_byte_3 },
    .{ .name = "rs2_addr", .ty = .register_index, .source = .trace_rs2_address },
    .{ .name = "rs2_prev_0", .ty = .byte, .source = .trace_rs2_previous_byte_0 },
    .{ .name = "rs2_prev_1", .ty = .byte, .source = .trace_rs2_previous_byte_1 },
    .{ .name = "rs2_prev_2", .ty = .byte, .source = .trace_rs2_previous_byte_2 },
    .{ .name = "rs2_prev_3", .ty = .byte, .source = .trace_rs2_previous_byte_3 },
    .{ .name = "rs2_clock_prev", .ty = .clock, .source = .trace_rs2_previous_clock },
    .{ .name = "rs2_next_0", .ty = .byte, .source = .trace_rs2_next_byte_0 },
    .{ .name = "rs2_next_1", .ty = .byte, .source = .trace_rs2_next_byte_1 },
    .{ .name = "rs2_next_2", .ty = .byte, .source = .trace_rs2_next_byte_2 },
    .{ .name = "rs2_next_3", .ty = .byte, .source = .trace_rs2_next_byte_3 },
    .{ .name = "imm_felt", .ty = .felt, .source = .trace_signed_immediate },
    .{ .name = "cmp_result", .ty = .bit, .source = .derived_branch_decision },
    .{ .name = "diff_inv_marker_0", .ty = .felt, .source = .hint_difference_inverse_0 },
    .{ .name = "diff_inv_marker_1", .ty = .felt, .source = .hint_difference_inverse_1 },
    .{ .name = "diff_inv_marker_2", .ty = .felt, .source = .hint_difference_inverse_2 },
    .{ .name = "diff_inv_marker_3", .ty = .felt, .source = .hint_difference_inverse_3 },
    .{ .name = "opcode_beq_flag", .ty = .bit, .source = .derived_beq_flag },
    .{ .name = "opcode_bne_flag", .ty = .bit, .source = .derived_bne_flag },
};

fn validatePhysicalDefinition(
    definition: *const typed.Definition,
) error{InvalidWitnessBinding}!void {
    const physical = definition.columns.physical();
    inline for (physical_specs, physical, CANONICAL_RECIPE, 0..) |
        spec,
        value,
        row_source,
        column,
    | {
        if (types.idIndex(value) != column or spec.source != row_source)
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
    rs1: M31,
    rs1_value: [4]M31,
    rs1_previous_clock: M31,
    rs2: M31,
    rs2_value: [4]M31,
    rs2_previous_clock: M31,
    immediate: M31,
    taken: bool,
    target: M31,
    opcode_id: M31,
    inverse_markers: [4]M31,
    flags: [2]M31,
};

inline fn decodeRow(row: TraceRow) DecodedRow {
    const lhs = limbs(row.rs1_val);
    const rhs = limbs(row.rs2_val);
    const equal = row.rs1_val == row.rs2_val;
    var inverse_markers = [_]M31{M31.zero()} ** 4;
    var wrote_inverse = false;
    inline for (0..4) |limb| {
        const difference = lhs[limb].sub(rhs[limb]);
        if (!wrote_inverse and !difference.isZero()) {
            inverse_markers[limb] = difference.invUncheckedNonZero();
            wrote_inverse = true;
        }
    }
    const is_beq = row.opcode == .BEQ;
    return .{
        .clock = fromUnsigned(row.clk),
        .pc = fromUnsigned(row.pc),
        .rs1 = fromUnsigned(row.rs1),
        .rs1_value = lhs,
        .rs1_previous_clock = fromUnsigned(row.rs1_prev_clk),
        .rs2 = fromUnsigned(row.rs2),
        .rs2_value = rhs,
        .rs2_previous_clock = fromUnsigned(row.rs2_prev_clk),
        .immediate = fromSigned(row.imm),
        .taken = if (is_beq) equal else !equal,
        .target = fromUnsigned(row.next_pc),
        .opcode_id = fromUnsigned(if (is_beq) typed.BEQ_OPCODE_ID else typed.BNE_OPCODE_ID),
        .inverse_markers = inverse_markers,
        .flags = .{ flag(is_beq), flag(!is_beq) },
    };
}

pub inline fn writeActiveRow(columns: anytype, row_index: usize, row: TraceRow) void {
    @setEvalBranchQuota(10_000);
    const decoded = decodeRow(row);
    inline for (CANONICAL_RECIPE, 0..) |row_source, column| {
        columns[column][row_index] = switch (row_source) {
            .trace_clock => decoded.clock,
            .trace_pc => decoded.pc,
            .trace_rs1_address => decoded.rs1,
            .trace_rs1_previous_byte_0 => decoded.rs1_value[0],
            .trace_rs1_previous_byte_1 => decoded.rs1_value[1],
            .trace_rs1_previous_byte_2 => decoded.rs1_value[2],
            .trace_rs1_previous_byte_3 => decoded.rs1_value[3],
            .trace_rs1_previous_clock => decoded.rs1_previous_clock,
            .trace_rs1_next_byte_0 => decoded.rs1_value[0],
            .trace_rs1_next_byte_1 => decoded.rs1_value[1],
            .trace_rs1_next_byte_2 => decoded.rs1_value[2],
            .trace_rs1_next_byte_3 => decoded.rs1_value[3],
            .trace_rs2_address => decoded.rs2,
            .trace_rs2_previous_byte_0 => decoded.rs2_value[0],
            .trace_rs2_previous_byte_1 => decoded.rs2_value[1],
            .trace_rs2_previous_byte_2 => decoded.rs2_value[2],
            .trace_rs2_previous_byte_3 => decoded.rs2_value[3],
            .trace_rs2_previous_clock => decoded.rs2_previous_clock,
            .trace_rs2_next_byte_0 => decoded.rs2_value[0],
            .trace_rs2_next_byte_1 => decoded.rs2_value[1],
            .trace_rs2_next_byte_2 => decoded.rs2_value[2],
            .trace_rs2_next_byte_3 => decoded.rs2_value[3],
            .trace_signed_immediate => decoded.immediate,
            .derived_branch_decision => flag(decoded.taken),
            .hint_difference_inverse_0 => decoded.inverse_markers[0],
            .hint_difference_inverse_1 => decoded.inverse_markers[1],
            .hint_difference_inverse_2 => decoded.inverse_markers[2],
            .hint_difference_inverse_3 => decoded.inverse_markers[3],
            .derived_beq_flag => decoded.flags[0],
            .derived_bne_flag => decoded.flags[1],
        };
    }
}

fn validateRow(row: TraceRow) ExecutionError!void {
    if (!isFamilyOpcode(row) or row.imm < -4096 or row.imm > 4094 or
        (@as(u32, @bitCast(row.imm)) & 1) != 0 or row.clk == 0 or
        row.pc & 3 != 0 or row.pc >= (@as(u32, 1) << 30) or
        row.is_load or row.is_store or
        row.mem_addr != 0 or row.mem_val != 0 or row.mem_prev_word != 0 or
        row.mem_next_word != 0 or row.mem_prev_clk != 0)
    {
        return error.InvalidTraceRow;
    }
    const source_1_clock = accessClock(row.clk, 1) orelse
        return error.InvalidTraceRow;
    const source_2_clock = accessClock(row.clk, 2) orelse
        return error.InvalidTraceRow;
    if (!validGap(row.rs1_prev_clk, source_1_clock) or
        !validGap(row.rs2_prev_clk, source_2_clock) or
        (row.rs1 == 0 and row.rs1_val != 0) or
        (row.rs2 == 0 and row.rs2_val != 0) or
        (row.rs1 == row.rs2 and
            (row.rs1_val != row.rs2_val or row.rs2_prev_clk != source_1_clock)))
    {
        return error.InvalidTraceRow;
    }
    const equal = row.rs1_val == row.rs2_val;
    const taken = if (row.opcode == .BEQ) equal else !equal;
    const target = if (taken)
        row.pc +% @as(u32, @bitCast(row.imm))
    else
        row.pc +% 4;
    if (target & 3 != 0 or target >= (@as(u32, 1) << 30) or
        row.next_pc != target or row.branch_taken != (target != row.pc +% 4))
    {
        return error.InvalidTraceRow;
    }
}

fn buildRelationRow(row: TraceRow) RelationRow {
    const decoded = decodeRow(row);
    const one = M31.one();
    const zero = M31.zero();
    const four = fromUnsigned(4);
    const source_1_clock = decoded.clock.sub(one).mul(four).add(one);
    const source_2_clock = decoded.clock.sub(one).mul(four).add(fromUnsigned(2));
    var result: RelationRow = undefined;
    result.events[0] = makeEvent(0, one, .{
        decoded.pc, decoded.opcode_id, decoded.rs1, decoded.rs2, decoded.immediate,
    });
    result.events[1] = makeEvent(1, one, .{
        zero,                 decoded.rs1,          decoded.rs1_previous_clock,
        decoded.rs1_value[0], decoded.rs1_value[1], decoded.rs1_value[2],
        decoded.rs1_value[3],
    });
    result.events[2] = makeEvent(2, one, .{
        zero,                 decoded.rs1,          source_1_clock,
        decoded.rs1_value[0], decoded.rs1_value[1], decoded.rs1_value[2],
        decoded.rs1_value[3],
    });
    result.events[3] = makeEvent(
        3,
        one,
        .{source_1_clock.sub(decoded.rs1_previous_clock).sub(one)},
    );
    result.events[4] = makeEvent(4, one, .{
        zero,                 decoded.rs2,          decoded.rs2_previous_clock,
        decoded.rs2_value[0], decoded.rs2_value[1], decoded.rs2_value[2],
        decoded.rs2_value[3],
    });
    result.events[5] = makeEvent(5, one, .{
        zero,                 decoded.rs2,          source_2_clock,
        decoded.rs2_value[0], decoded.rs2_value[1], decoded.rs2_value[2],
        decoded.rs2_value[3],
    });
    result.events[6] = makeEvent(
        6,
        one,
        .{source_2_clock.sub(decoded.rs2_previous_clock).sub(one)},
    );
    result.events[7] = makeEvent(7, one, .{ decoded.pc, decoded.clock });
    result.events[8] = makeEvent(8, one, .{ decoded.target, decoded.clock.add(one) });
    return result;
}

fn makeEvent(comptime index: usize, liveness: M31, values: anytype) RelationEvent {
    const spec = EVENT_SPECS[index];
    comptime if (values.len != spec.arity)
        @compileError("typed BRANCH_EQ relation row arity drift");
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

inline fn isFamilyOpcode(row: TraceRow) bool {
    return row.opcode == .BEQ or row.opcode == .BNE;
}

inline fn accessClock(clock: u32, ordinal: u32) ?u32 {
    if (clock == 0) return null;
    const base = @as(u64, clock - 1) * 4 + ordinal;
    if (base > std.math.maxInt(u32)) return null;
    return @intCast(base);
}

inline fn validGap(previous: u32, current: u32) bool {
    return previous < current and current - previous - 1 < (1 << 20);
}

inline fn flag(value: bool) M31 {
    return if (value) M31.one() else M31.zero();
}

inline fn fromUnsigned(value: anytype) M31 {
    return M31.fromU64(@intCast(value));
}

inline fn fromSigned(value: i32) M31 {
    if (value >= 0) return fromUnsigned(value);
    return M31.zero().sub(M31.fromU64(@intCast(-@as(i64, value))));
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

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}

comptime {
    if (MAIN_COLUMN_COUNT != production_columns.BranchEqColumns.N_COLUMNS)
        @compileError("typed BRANCH_EQ witness width drifted from production");
    const production_fields = @typeInfo(production_columns.BranchEqColumns).@"struct".fields;
    for (physical_specs, production_fields, CANONICAL_RECIPE, 0..) |
        spec,
        field,
        row_source,
        index,
    | {
        if (!std.mem.eql(u8, spec.name, field.name))
            @compileError("typed BRANCH_EQ witness name drifted from production");
        if (spec.source != row_source or @intFromEnum(row_source) != index)
            @compileError("typed BRANCH_EQ numeric witness recipe is not canonical");
    }
}
