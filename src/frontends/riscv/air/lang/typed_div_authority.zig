//! Fixed executable authority for RV32 `DIV`.
//!
//! Cold construction authenticates the native typed graph, its exact physical
//! witness projection, all seventy-nine direct roots, and all twenty-five ordered
//! lookup events.  The retained capability is pointer-free.  Its hot paths
//! allocate nothing and perform no arena traversal, textual lookup, callback
//! dispatch, or runtime interpretation of the authored graph.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const entry = @import("../lookups/entry.zig");
const decode = @import("../../runner/decode.zig");
const trace_row = @import("../../runner/trace_row.zig");
const digest = @import("digest.zig");
const direct_witness_executor = @import("direct_witness_executor.zig");
const typed = @import("typed_div.zig");
const evaluator_impl = @import("typed_div_evaluator.zig");
const witness = @import("typed_div_witness.zig");

pub const MAIN_COLUMN_COUNT: usize = typed.MAIN_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = typed.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = typed.LOOKUP_COUNT;
pub const LOOKUP_BATCH_SIZE: usize = typed.LOOKUP_BATCH_SIZE;
pub const OPCODE_IDS: [4]u32 = typed.OPCODE_IDS;

pub const DecodedInst = decode.DecodedInst;
pub const TraceRow = trace_row.TraceRow;

pub const AUTHORITY_BINDING_FORMAT_VERSION: u16 = 1;
pub const AUTHORITY_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/div-fixed-authority/v1";
pub const AUTHORITY_BINDING_DIGEST_HEX =
    "65ea8c40383f799fe8526eaf44cf763953fd61c5e56c19c7b79562ff789b934b";
pub const AUTHORITY_BINDING_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, AUTHORITY_BINDING_DIGEST_HEX) catch
        @compileError("invalid typed DIV authority-binding digest");
    break :blk result;
};

pub const ExecutionRecipe = enum(u8) {
    rv32_divrem_special_cases_and_x0_discard = 0,
    reserved = 255,
};

pub const DirectRecipe = enum(u8) {
    active_bit = 0,
    div_bit = 1,
    divu_bit = 2,
    rem_bit = 3,
    remu_bit = 4,
    zero_divisor_bit = 5,
    remainder_zero_bit = 6,
    dividend_sign_bit = 7,
    divisor_sign_bit = 8,
    quotient_sign_bit = 9,
    sign_xor_bit = 10,
    less_than_marker_0_bit = 11,
    less_than_marker_1_bit = 12,
    less_than_marker_2_bit = 13,
    less_than_marker_3_bit = 14,
    special_case_bit = 15,
    valid_not_zero_divisor_bit = 16,
    valid_not_special_bit = 17,
    zero_divisor_divisor_0 = 18,
    zero_divisor_divisor_1 = 19,
    zero_divisor_divisor_2 = 20,
    zero_divisor_divisor_3 = 21,
    zero_divisor_quotient_0 = 22,
    zero_divisor_quotient_1 = 23,
    zero_divisor_quotient_2 = 24,
    zero_divisor_quotient_3 = 25,
    nonzero_divisor_inverse = 26,
    zero_remainder_0 = 27,
    zero_remainder_1 = 28,
    zero_remainder_2 = 29,
    zero_remainder_3 = 30,
    nonzero_remainder_inverse = 31,
    unsigned_dividend_sign_zero = 32,
    unsigned_divisor_sign_zero = 33,
    sign_xor_relation = 34,
    quotient_sign_nonzero_relation = 35,
    quotient_sign_boolean_relation = 36,
    zero_divisor_quotient_sign = 37,
    remainder_abs_0 = 38,
    remainder_negation_carry_0 = 39,
    remainder_negation_zero_0 = 40,
    remainder_inverse_0 = 41,
    remainder_abs_1 = 42,
    remainder_negation_carry_1 = 43,
    remainder_negation_zero_1 = 44,
    remainder_inverse_1 = 45,
    remainder_abs_2 = 46,
    remainder_negation_carry_2 = 47,
    remainder_negation_zero_2 = 48,
    remainder_inverse_2 = 49,
    remainder_abs_3 = 50,
    remainder_negation_carry_3 = 51,
    remainder_negation_zero_3 = 52,
    remainder_inverse_3 = 53,
    remainder_bound_prefix_3 = 54,
    remainder_bound_difference_3 = 55,
    remainder_bound_prefix_2 = 56,
    remainder_bound_difference_2 = 57,
    remainder_bound_prefix_1 = 58,
    remainder_bound_difference_1 = 59,
    remainder_bound_prefix_0 = 60,
    remainder_bound_difference_0 = 61,
    remainder_bound_marker_exists = 62,
    destination_nonzero_bit = 63,
    destination_zero_address = 64,
    destination_inverse = 65,
    destination_result_0 = 66,
    destination_result_1 = 67,
    destination_result_2 = 68,
    destination_result_3 = 69,
    source_1_read_only_0 = 70,
    source_1_read_only_1 = 71,
    source_1_read_only_2 = 72,
    source_1_read_only_3 = 73,
    source_2_read_only_0 = 74,
    source_2_read_only_1 = 75,
    source_2_read_only_2 = 76,
    source_2_read_only_3 = 77,
    active_placement = 78,
};

pub const CANONICAL_DIRECT_RECIPE: [DIRECT_CONSTRAINT_COUNT]DirectRecipe = blk: {
    var result: [DIRECT_CONSTRAINT_COUNT]DirectRecipe = undefined;
    for (&result, 0..) |*recipe, index| recipe.* = @enumFromInt(index);
    break :blk result;
};

pub const LookupRecipe = enum(u8) {
    program_fetch = 0,
    state_consume = 1,
    state_emit = 2,
    source_1_consume = 3,
    source_1_emit = 4,
    source_1_clock_gap = 5,
    source_2_consume = 6,
    source_2_emit = 7,
    source_2_clock_gap = 8,
    divisor_range_0 = 9,
    divisor_range_1 = 10,
    quotient_remainder_range_0 = 11,
    quotient_remainder_range_1 = 12,
    quotient_remainder_range_2 = 13,
    quotient_remainder_range_3 = 14,
    quotient_remainder_range_4 = 15,
    quotient_remainder_range_5 = 16,
    quotient_remainder_range_6 = 17,
    quotient_remainder_range_7 = 18,
    quotient_sign_range = 19,
    operand_sign_range = 20,
    positive_remainder_difference = 21,
    destination_consume = 22,
    destination_emit = 23,
    destination_clock_gap = 24,
};

pub const LookupDescriptor = struct {
    recipe: LookupRecipe,
    domain: entry.Domain,
    role: entry.EventRole,
    arity: u8,
    access_ordinal: ?u8,
};

pub const CANONICAL_LOOKUP_RECIPE = [LOOKUP_COUNT]LookupDescriptor{
    .{ .recipe = .program_fetch, .domain = .program_access, .role = .request, .arity = 5, .access_ordinal = null },
    .{ .recipe = .state_consume, .domain = .registers_state, .role = .consume, .arity = 2, .access_ordinal = null },
    .{ .recipe = .state_emit, .domain = .registers_state, .role = .emit, .arity = 2, .access_ordinal = null },
    .{ .recipe = .source_1_consume, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 1 },
    .{ .recipe = .source_1_emit, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 1 },
    .{ .recipe = .source_1_clock_gap, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 1 },
    .{ .recipe = .source_2_consume, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 2 },
    .{ .recipe = .source_2_emit, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 2 },
    .{ .recipe = .source_2_clock_gap, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 2 },
    .{ .recipe = .divisor_range_0, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .divisor_range_1, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .quotient_remainder_range_0, .domain = .range_check_8_11, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .quotient_remainder_range_1, .domain = .range_check_8_11, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .quotient_remainder_range_2, .domain = .range_check_8_11, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .quotient_remainder_range_3, .domain = .range_check_8_11, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .quotient_remainder_range_4, .domain = .range_check_8_11, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .quotient_remainder_range_5, .domain = .range_check_8_11, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .quotient_remainder_range_6, .domain = .range_check_8_11, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .quotient_remainder_range_7, .domain = .range_check_8_11, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .quotient_sign_range, .domain = .range_check_m31, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .operand_sign_range, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .positive_remainder_difference, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = null },
    .{ .recipe = .destination_consume, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 3 },
    .{ .recipe = .destination_emit, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 3 },
    .{ .recipe = .destination_clock_gap, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 3 },
};

pub const Binding = struct {
    format_version: u16,
    semantic_format_version: u16,
    opcode_ids: [4]u32,
    semantic_digest: digest.Digest,
    witness_binding_digest: digest.Digest,
    main_column_count: u16,
    execution: ExecutionRecipe,
    direct: [DIRECT_CONSTRAINT_COUNT]DirectRecipe,
    lookups: [LOOKUP_COUNT]LookupDescriptor,
    lookup_batch_size: u8,

    pub fn canonical(definition: *const typed.Definition) witness.ConstructionError!Binding {
        try definition.validate();
        const physical = witness.WitnessBinding.canonical(definition);
        const physical_digest = physical.identityDigest();
        if (!std.mem.eql(u8, &physical_digest, &witness.WITNESS_BINDING_DIGEST))
            return error.InvalidWitnessBinding;
        _ = try witness.Executor.init(definition, &physical);
        return CANONICAL_BINDING;
    }

    pub fn identityDigest(self: *const Binding) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(AUTHORITY_BINDING_DOMAIN_SEPARATOR);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.semantic_format_version);
        for (self.opcode_ids) |opcode_id| hashInt(&hash, u32, opcode_id);
        hash.update(&self.semantic_digest);
        hash.update(&self.witness_binding_digest);
        hashInt(&hash, u16, self.main_column_count);
        hashInt(&hash, u8, @intFromEnum(self.execution));
        hashInt(&hash, u16, self.direct.len);
        for (self.direct) |recipe| hashInt(&hash, u8, @intFromEnum(recipe));
        hashInt(&hash, u16, self.lookups.len);
        for (self.lookups) |lookup| {
            hashInt(&hash, u8, @intFromEnum(lookup.recipe));
            hashInt(&hash, u8, @intFromEnum(lookup.domain));
            hashInt(&hash, u8, @intFromEnum(lookup.role));
            hashInt(&hash, u8, lookup.arity);
            hashInt(&hash, u8, @intFromBool(lookup.access_ordinal != null));
            hashInt(&hash, u8, lookup.access_ordinal orelse 0);
        }
        hashInt(&hash, u8, self.lookup_batch_size);
        return hash.finalResult();
    }
};

pub const CANONICAL_BINDING = Binding{
    .format_version = AUTHORITY_BINDING_FORMAT_VERSION,
    .semantic_format_version = digest.range_refinement_format_version,
    .opcode_ids = OPCODE_IDS,
    .semantic_digest = typed.SEMANTIC_DIGEST,
    .witness_binding_digest = witness.WITNESS_BINDING_DIGEST,
    .main_column_count = MAIN_COLUMN_COUNT,
    .execution = .rv32_divrem_special_cases_and_x0_discard,
    .direct = CANONICAL_DIRECT_RECIPE,
    .lookups = CANONICAL_LOOKUP_RECIPE,
    .lookup_batch_size = LOOKUP_BATCH_SIZE,
};

pub const ConstructionError = witness.ConstructionError || error{InvalidAuthorityBinding};
pub const ExecutionError = error{ WrongDivOpcode, InvalidImmediate };

pub const Retirement = struct {
    rd: u5,
    source_1_value: u32,
    source_2_value: u32,
    write_enabled: bool,
    attempted_value: u32,
    visible_value: u32,
};

pub inline fn resultFor(opcode: decode.Opcode, source_1: u32, source_2: u32) u32 {
    return switch (opcode) {
        .DIV => signedDivision(source_1, source_2),
        .DIVU => if (source_2 == 0) std.math.maxInt(u32) else source_1 / source_2,
        .REM => signedRemainder(source_1, source_2),
        .REMU => if (source_2 == 0) source_1 else source_1 % source_2,
        else => unreachable,
    };
}

inline fn signedDivision(source_1: u32, source_2: u32) u32 {
    if (source_2 == 0) return std.math.maxInt(u32);
    if (source_1 == 0x8000_0000 and source_2 == 0xffff_ffff)
        return 0x8000_0000;
    const lhs: i32 = @bitCast(source_1);
    const rhs: i32 = @bitCast(source_2);
    return @bitCast(@divTrunc(lhs, rhs));
}

inline fn signedRemainder(source_1: u32, source_2: u32) u32 {
    if (source_2 == 0) return source_1;
    if (source_1 == 0x8000_0000 and source_2 == 0xffff_ffff) return 0;
    const lhs: i32 = @bitCast(source_1);
    const rhs: i32 = @bitCast(source_2);
    return @bitCast(@rem(lhs, rhs));
}

inline fn canonicalRetirement(
    instruction: DecodedInst,
    source_1: u32,
    source_2: u32,
) Retirement {
    const attempted = resultFor(instruction.opcode, source_1, source_2);
    return .{
        .rd = instruction.rd,
        .source_1_value = source_1,
        .source_2_value = source_2,
        .write_enabled = instruction.rd != 0,
        .attempted_value = attempted,
        .visible_value = if (instruction.rd == 0) 0 else attempted,
    };
}

pub inline fn acceptsRetirement(
    instruction: DecodedInst,
    source_1: u32,
    source_2: u32,
    visible_value: u32,
) bool {
    if (!isFamilyOpcode(instruction.opcode) or instruction.imm != 0) return false;
    return visible_value == canonicalRetirement(
        instruction,
        source_1,
        source_2,
    ).visible_value;
}

/// Authenticate the complete R-type encoding carried beside a decoded
/// division or remainder instruction.
pub inline fn instructionMatchesWord(
    instruction: DecodedInst,
    inst_word: u32,
) bool {
    if (!isFamilyOpcode(instruction.opcode) or instruction.imm != 0)
        return false;
    const funct3: u32 = switch (instruction.opcode) {
        .DIV => 0b100,
        .DIVU => 0b101,
        .REM => 0b110,
        .REMU => 0b111,
        else => unreachable,
    };
    const reconstructed = (@as(u32, 1) << 25) |
        (@as(u32, instruction.rs2) << 20) |
        (@as(u32, instruction.rs1) << 15) |
        (funct3 << 12) |
        (@as(u32, instruction.rd) << 7) |
        0b0110011;
    return inst_word == reconstructed;
}

pub const Authority = struct {
    binding: Binding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const typed.Definition,
        supplied: *const Binding,
    ) ConstructionError!Authority {
        try definition.validate();
        const canonical = try Binding.canonical(definition);
        if (!std.meta.eql(canonical, supplied.*)) return error.InvalidAuthorityBinding;
        const owned = supplied.*;
        const binding_digest = owned.identityDigest();
        if (!std.mem.eql(u8, &binding_digest, &AUTHORITY_BINDING_DIGEST))
            return error.InvalidAuthorityBinding;
        return .{ .binding = owned, .binding_digest = binding_digest };
    }

    pub inline fn pinned() Authority {
        return .{ .binding = CANONICAL_BINDING, .binding_digest = AUTHORITY_BINDING_DIGEST };
    }

    pub fn identitySnapshot(self: *const Authority) Binding {
        return self.binding;
    }

    pub fn identityDigest(self: *const Authority) digest.Digest {
        return self.binding_digest;
    }

    pub inline fn retire(
        _: *const Authority,
        instruction: DecodedInst,
        source_1: u32,
        source_2: u32,
    ) ExecutionError!Retirement {
        if (!isFamilyOpcode(instruction.opcode)) return error.WrongDivOpcode;
        if (instruction.imm != 0) return error.InvalidImmediate;
        return canonicalRetirement(instruction, source_1, source_2);
    }

    pub fn generateMainInto(
        self: *const Authority,
        columns: *[MAIN_COLUMN_COUNT][]M31,
        rows: []const TraceRow,
        log_size: u32,
    ) direct_witness_executor.Error!void {
        return direct_witness_executor.generateMainInto(
            M31,
            TraceRow,
            MAIN_COLUMN_COUNT,
            columns,
            rows,
            log_size,
            M31.zero(),
            self,
            validateTraceRow,
            writeActiveRowUnchecked,
        );
    }

    pub inline fn writeActiveRow(
        _: *const Authority,
        columns: anytype,
        row_index: usize,
        row: TraceRow,
    ) void {
        std.debug.assert(validTraceRow(row));
        writeActiveRowUnchecked(columns, row_index, row);
    }

    pub fn buildProgram(
        _: *const Authority,
        comptime S: type,
        columns: []const S,
        is_active: S,
    ) !Evaluator(S).ConstraintProgram {
        return Evaluator(S).build(columns, is_active);
    }

    pub inline fn evaluateDirect(
        _: *const Authority,
        comptime S: type,
        columns: []const S,
        is_active: S,
    ) !Evaluator(S).DirectConstraints {
        return Evaluator(S).direct(columns, is_active);
    }

    pub fn buildLookupsInto(
        _: *const Authority,
        comptime S: type,
        columns: []const S,
        result: *entry.Builder(S).List,
    ) !void {
        return Evaluator(S).lookupsInto(columns, result);
    }
};

pub fn Evaluator(comptime S: type) type {
    return evaluator_impl.Evaluator(@This(), S);
}
pub fn validateTraceRow(row: TraceRow) direct_witness_executor.Error!void {
    if (!validTraceRow(row)) return error.InvalidTraceRow;
}

inline fn writeActiveRowUnchecked(columns: anytype, row_index: usize, row: TraceRow) void {
    witness.writeActiveRow(columns, row_index, row);
}

inline fn validTraceRow(row: TraceRow) bool {
    if (!instructionMatchesWord(.{
        .opcode = row.opcode,
        .rd = row.rd,
        .rs1 = row.rs1,
        .rs2 = row.rs2,
        .imm = row.imm,
    }, row.inst_word) or row.clk == 0 or
        row.next_pc != row.pc +% 4 or row.is_load or row.is_store or
        row.branch_taken)
    {
        return false;
    }
    const source_1_clock = accessClock(row.clk, 1) orelse return false;
    const source_2_clock = accessClock(row.clk, 2) orelse return false;
    const destination_clock = accessClock(row.clk, 3) orelse return false;
    if (!validGap(row.rs1_prev_clk, source_1_clock) or
        !validGap(row.rs2_prev_clk, source_2_clock) or
        !validGap(row.rd_prev_clk, destination_clock)) return false;
    if ((row.rs1 == 0 and row.rs1_val != 0) or
        (row.rs2 == 0 and row.rs2_val != 0) or
        (row.rd == 0 and (row.rd_prev_val != 0 or row.rd_val != 0)) or
        (row.rs1 == row.rs2 and
            (row.rs1_val != row.rs2_val or row.rs2_prev_clk != source_1_clock)))
    {
        return false;
    }
    if (row.rd == row.rs2 and
        (row.rd_prev_clk != source_2_clock or row.rd_prev_val != row.rs2_val))
    {
        return false;
    }
    if (row.rd != row.rs2 and row.rd == row.rs1 and
        (row.rd_prev_clk != source_1_clock or row.rd_prev_val != row.rs1_val))
    {
        return false;
    }
    const expected = resultFor(row.opcode, row.rs1_val, row.rs2_val);
    return row.rd_val == (if (row.rd == 0) 0 else expected);
}

inline fn isFamilyOpcode(opcode: decode.Opcode) bool {
    return switch (opcode) {
        .DIV, .DIVU, .REM, .REMU => true,
        else => false,
    };
}

inline fn accessClock(clock: u32, phase: u32) ?u32 {
    if (clock == 0 or phase == 0 or phase > 3) return null;
    return std.math.cast(u32, (@as(u64, clock) - 1) * 4 + phase);
}

inline fn validGap(previous: u32, current: u32) bool {
    return previous < current and current - previous - 1 < (@as(u32, 1) << 20);
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

comptime {
    @setEvalBranchQuota(50_000);
    if (DIRECT_CONSTRAINT_COUNT != 79 or LOOKUP_COUNT != 25 or
        CANONICAL_DIRECT_RECIPE.len != 79)
    {
        @compileError("typed DIV fixed authority geometry drifted");
    }
    for (CANONICAL_DIRECT_RECIPE, 0..) |recipe, index|
        if (@intFromEnum(recipe) != index)
            @compileError("typed DIV direct recipe is not canonical");
    if (!std.mem.eql(
        u8,
        &CANONICAL_BINDING.identityDigest(),
        &AUTHORITY_BINDING_DIGEST,
    )) @compileError("typed DIV canonical authority digest drifted");
}
