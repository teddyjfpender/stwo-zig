//! Fixed executable authority for RV32 byte/half/word loads and stores.
//!
//! The authenticated binding owns architectural memory retirement, physical
//! witness projection, all 63 direct roots, and all 17 ordered lookup events.
//! Its retained evaluator is pointer-free and performs no allocation, string
//! lookup, arena traversal, callback dispatch, or runtime metadata decoding.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const access_clock = @import("../../access_clock.zig");
const entry = @import("../lookups/entry.zig");
const decode = @import("../../runner/decode.zig");
const state_chain = @import("../../runner/state_chain.zig");
const trace_row = @import("../../runner/trace_row.zig");
const digest = @import("digest.zig");
const direct_witness_executor = @import("direct_witness_executor.zig");
const fixed = @import("fixed_load_store.zig");
const typed = @import("typed_load_store.zig");
const witness = @import("typed_load_store_witness.zig");

pub const MAIN_COLUMN_COUNT: usize = typed.MAIN_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = typed.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = typed.LOOKUP_COUNT;
pub const LOOKUP_BATCH_SIZE: usize = typed.LOOKUP_BATCH_SIZE;
pub const OPCODE_IDS = typed.OPCODE_IDS;

pub const DecodedInst = decode.DecodedInst;
pub const TraceRow = trace_row.TraceRow;

pub const AUTHORITY_BINDING_FORMAT_VERSION: u16 = 1;
pub const AUTHORITY_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/load-store-fixed-authority/v1";
pub const AUTHORITY_BINDING_DIGEST_HEX =
    "0ccb85bcc31f45ed31f76bf208e4e046e3e0f47047231fc9171612a8c88bb040";
pub const AUTHORITY_BINDING_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, AUTHORITY_BINDING_DIGEST_HEX) catch
        @compileError("invalid typed LOAD_STORE authority-binding digest");
    break :blk result;
};
const ENFORCE_AUTHORITY_BINDING_DIGEST = true;

pub const ExecutionRecipe = enum(u8) {
    aligned_memory_retirement_x0_discard = 0,
};

pub const DirectRecipe = enum(u8) {
    active_bit = 0,
    lb_bit = 1,
    lh_bit = 2,
    lbu_bit = 3,
    lhu_bit = 4,
    lw_bit = 5,
    sb_bit = 6,
    sh_bit = 7,
    sw_bit = 8,
    source_msb_bit = 9,
    source_msb_canonical = 10,
    marker_bit_0 = 11,
    marker_bit_1 = 12,
    marker_bit_2 = 13,
    marker_bit_3 = 14,
    shift_amount = 15,
    source_address = 16,
    destination_address = 17,
    byte_marker_sum = 18,
    half_marker_sum = 19,
    half_position = 20,
    byte_sign_fill_1 = 21,
    byte_sign_fill_2 = 22,
    byte_sign_fill_3 = 23,
    byte_load_0 = 24,
    byte_store_0 = 25,
    byte_load_1 = 26,
    byte_store_1 = 27,
    byte_load_2 = 28,
    byte_store_2 = 29,
    byte_load_3 = 30,
    byte_store_3 = 31,
    half_sign_fill_2 = 32,
    half_sign_fill_3 = 33,
    half_load_low_0 = 34,
    half_load_low_1 = 35,
    half_load_high_0 = 36,
    half_load_high_1 = 37,
    half_store_low_0 = 38,
    half_store_low_1 = 39,
    half_store_high_0 = 40,
    half_store_high_1 = 41,
    word_result_0 = 42,
    word_result_1 = 43,
    word_result_2 = 44,
    word_result_3 = 45,
    partial_store_preserve_0 = 46,
    partial_store_preserve_1 = 47,
    partial_store_preserve_2 = 48,
    partial_store_preserve_3 = 49,
    destination_nonzero_bit = 50,
    destination_zero_address = 51,
    destination_inverse = 52,
    destination_result_0 = 53,
    destination_result_1 = 54,
    destination_result_2 = 55,
    destination_result_3 = 56,
    store_result_zero_0 = 57,
    store_result_zero_1 = 58,
    store_result_zero_2 = 59,
    store_result_zero_3 = 60,
    aligned_address_word_binding = 61,
    active_placement = 62,
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
    base_register_consume = 3,
    base_register_emit = 4,
    base_register_clock_gap = 5,
    aligned_address_range = 6,
    base_address_range = 7,
    source_consume = 8,
    source_emit = 9,
    source_clock_gap = 10,
    destination_consume = 11,
    destination_emit = 12,
    destination_clock_gap = 13,
    byte_sign_range = 14,
    half_sign_range = 15,
    aligned_address_high_range = 16,
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
    .{ .recipe = .base_register_consume, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 1 },
    .{ .recipe = .base_register_emit, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 1 },
    .{ .recipe = .base_register_clock_gap, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 1 },
    .{ .recipe = .aligned_address_range, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = null },
    .{ .recipe = .base_address_range, .domain = .range_check_m31, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .source_consume, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 2 },
    .{ .recipe = .source_emit, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 2 },
    .{ .recipe = .source_clock_gap, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 2 },
    .{ .recipe = .destination_consume, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 3 },
    .{ .recipe = .destination_emit, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 3 },
    .{ .recipe = .destination_clock_gap, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 3 },
    .{ .recipe = .byte_sign_range, .domain = .range_check_m31, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .half_sign_range, .domain = .range_check_m31, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .aligned_address_high_range, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
};

pub const Binding = struct {
    format_version: u16,
    semantic_format_version: u16,
    opcode_ids: [8]u32,
    semantic_digest: digest.Digest,
    witness_binding_digest: digest.Digest,
    main_column_count: u16,
    execution: ExecutionRecipe,
    direct: [DIRECT_CONSTRAINT_COUNT]DirectRecipe,
    lookups: [LOOKUP_COUNT]LookupDescriptor,
    lookup_batch_size: u8,

    pub fn canonical(definition: *const typed.Definition) ConstructionError!Binding {
        try definition.validate();
        const physical = witness.WitnessBinding.canonical(definition);
        const physical_digest = physical.identityDigest();
        if (ENFORCE_AUTHORITY_BINDING_DIGEST and
            !std.mem.eql(u8, &physical_digest, &witness.WITNESS_BINDING_DIGEST))
            return error.InvalidWitnessBinding;
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
    .semantic_format_version = digest.conditional_access_format_version,
    .opcode_ids = OPCODE_IDS,
    .semantic_digest = typed.SEMANTIC_DIGEST,
    .witness_binding_digest = witness.WITNESS_BINDING_DIGEST,
    .main_column_count = MAIN_COLUMN_COUNT,
    .execution = .aligned_memory_retirement_x0_discard,
    .direct = CANONICAL_DIRECT_RECIPE,
    .lookups = CANONICAL_LOOKUP_RECIPE,
    .lookup_batch_size = LOOKUP_BATCH_SIZE,
};

pub const ConstructionError = typed.ValidationError || witness.ConstructionError ||
    error{InvalidAuthorityBinding};
pub const ExecutionError = error{
    AddressOutOfRange,
    MisalignedMemoryAccess,
    WrongLoadStoreOpcode,
};

pub const Retirement = struct {
    is_load: bool,
    address: u32,
    aligned_address: u32,
    write_register: bool,
    register_value: u32,
    write_memory: bool,
    memory_next_word: u32,
};

pub inline fn isFamilyOpcode(opcode: decode.Opcode) bool {
    return switch (opcode) {
        .LB, .LH, .LBU, .LHU, .LW, .SB, .SH, .SW => true,
        else => false,
    };
}

pub inline fn isLoadOpcode(opcode: decode.Opcode) bool {
    return switch (opcode) {
        .LB, .LH, .LBU, .LHU, .LW => true,
        else => false,
    };
}

/// Authenticate every encoding bit, including the I/S immediate fragments
/// retained in `DecodedInst.rs2`/`DecodedInst.rd` by the canonical decoder.
/// Those fields are not architectural register operands, but accepting them
/// independently would leave trace metadata detached from `inst_word`.
pub inline fn instructionMatchesWord(
    instruction: DecodedInst,
    inst_word: u32,
) bool {
    if (!isFamilyOpcode(instruction.opcode) or
        instruction.imm < -2048 or instruction.imm > 2047)
    {
        return false;
    }
    const immediate_12 = @as(u32, @bitCast(instruction.imm)) & 0xfff;
    const funct3: u32 = switch (instruction.opcode) {
        .LB, .SB => 0,
        .LH, .SH => 1,
        .LW, .SW => 2,
        .LBU => 4,
        .LHU => 5,
        else => unreachable,
    };
    if (isLoadOpcode(instruction.opcode)) {
        const reconstructed = (immediate_12 << 20) |
            (@as(u32, instruction.rs1) << 15) |
            (funct3 << 12) |
            (@as(u32, instruction.rd) << 7) |
            0b0000011;
        return inst_word == reconstructed and
            instruction.rs2 == @as(u5, @truncate(immediate_12));
    }
    const reconstructed = ((immediate_12 & 0xfe0) << 20) |
        (@as(u32, instruction.rs2) << 20) |
        (@as(u32, instruction.rs1) << 15) |
        (funct3 << 12) |
        ((immediate_12 & 0x1f) << 7) |
        0b0100011;
    return inst_word == reconstructed and
        instruction.rd == @as(u5, @truncate(immediate_12));
}

pub fn canonicalRetirement(
    instruction: DecodedInst,
    base_value: u32,
    source_value: u32,
    memory_previous_word: u32,
) ExecutionError!Retirement {
    if (!isFamilyOpcode(instruction.opcode)) return error.WrongLoadStoreOpcode;
    const address = base_value +% @as(u32, @bitCast(instruction.imm));
    const alignment: u32 = switch (instruction.opcode) {
        .LB, .LBU, .SB => 1,
        .LH, .LHU, .SH => 2,
        .LW, .SW => 4,
        else => unreachable,
    };
    if (address & (alignment - 1) != 0) return error.MisalignedMemoryAccess;
    const aligned_address = address & ~@as(u32, 3);
    if (base_value >= (@as(u32, 1) << 30) or
        aligned_address >= (@as(u32, 1) << 30))
    {
        return error.AddressOutOfRange;
    }
    const amount: u5 = @intCast((address & 3) * 8);
    const byte: u8 = @truncate(memory_previous_word >> amount);
    const half: u16 = @truncate(memory_previous_word >> amount);
    const loaded: u32 = switch (instruction.opcode) {
        .LB => @bitCast(@as(i32, @as(i8, @bitCast(byte)))),
        .LH => @bitCast(@as(i32, @as(i16, @bitCast(half)))),
        .LBU => byte,
        .LHU => half,
        .LW => memory_previous_word,
        else => 0,
    };
    const memory_next = switch (instruction.opcode) {
        .SB => (memory_previous_word & ~(@as(u32, 0xff) << amount)) |
            (@as(u32, @as(u8, @truncate(source_value))) << amount),
        .SH => (memory_previous_word & ~(@as(u32, 0xffff) << amount)) |
            (@as(u32, @as(u16, @truncate(source_value))) << amount),
        .SW => source_value,
        else => memory_previous_word,
    };
    const is_load = isLoadOpcode(instruction.opcode);
    return .{
        .is_load = is_load,
        .address = address,
        .aligned_address = aligned_address,
        .write_register = is_load and instruction.rd != 0,
        .register_value = if (is_load and instruction.rd != 0) loaded else 0,
        .write_memory = !is_load,
        .memory_next_word = memory_next,
    };
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
        const physical = witness.WitnessBinding.canonical(definition);
        _ = try witness.Executor.init(definition, &physical);
        const owned = supplied.*;
        const binding_digest = owned.identityDigest();
        if (ENFORCE_AUTHORITY_BINDING_DIGEST and
            !std.mem.eql(u8, &binding_digest, &AUTHORITY_BINDING_DIGEST))
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
        base_value: u32,
        source_value: u32,
        memory_previous_word: u32,
    ) ExecutionError!Retirement {
        return canonicalRetirement(
            instruction,
            base_value,
            source_value,
            memory_previous_word,
        );
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

inline fn writeActiveRowUnchecked(
    columns: anytype,
    row_index: usize,
    row: TraceRow,
) void {
    witness.writeActiveRow(columns, row_index, row);
}

pub fn Evaluator(comptime S: type) type {
    return struct {
        const core = fixed.Evaluator(S);
        const e = entry.Builder(S);

        pub const Row = core.Row;

        pub const DirectConstraints = struct {
            values: [DIRECT_CONSTRAINT_COUNT]S,

            pub fn allZero(self: @This()) bool {
                for (self.values) |value| if (!value.isZero()) return false;
                return true;
            }
        };

        pub const ConstraintProgram = struct {
            active_row: S,
            direct_constraints: DirectConstraints,
            lookup_entries: e.List,
        };

        pub inline fn direct(columns: []const S, is_active: S) !DirectConstraints {
            const row = try core.Row.fromMainColumns(columns);
            var out: [DIRECT_CONSTRAINT_COUNT]S = undefined;
            const semantic = core.evaluate(row);
            @memcpy(out[0..core.CONSTRAINT_COUNT], &semantic.values);
            out[core.CONSTRAINT_COUNT] = core.placementConstraint(row, is_active);
            return .{ .values = out };
        }

        pub fn build(columns: []const S, is_active: S) !ConstraintProgram {
            const row = try core.Row.fromMainColumns(columns);
            const direct_constraints = try direct(columns, is_active);
            const active = row.active();
            var lookups: e.List = undefined;
            try lookupsInto(columns, &lookups);
            return .{
                .active_row = active,
                .direct_constraints = direct_constraints,
                .lookup_entries = lookups,
            };
        }

        pub fn lookupsInto(columns: []const S, lookups: *e.List) !void {
            @setEvalBranchQuota(100_000);
            const row = try core.Row.fromMainColumns(columns);
            const active = row.active();
            const accesses = core.accessLookups(row);
            const signs = core.signRangeLookups(row);
            lookups.* = .{ .batch_size = LOOKUP_BATCH_SIZE };
            e.program(lookups, active.neg(), core.programLookup(row));
            e.stateChain(lookups, core.stateLookup(row), active);
            e.accessChainAt(lookups, accesses.rs1, active, 1);
            e.range20(lookups, active.neg(), core.alignedAddressRangeLookup(row));
            e.rangeM31(lookups, active.neg(), core.baseAddressM31Lookup(row));
            e.accessChainAt(lookups, accesses.src, active, 2);
            e.accessChainAt(lookups, accesses.dst, active, 3);
            e.rangeM31(lookups, row.is_lb.neg(), signs[0]);
            e.rangeM31(lookups, row.is_lh.neg(), signs[1]);
            e.range88(
                lookups,
                active.neg(),
                core.alignedAddressHighRangeLookup(row),
            );
            std.debug.assert(lookups.len == LOOKUP_COUNT);
        }
    };
}

pub fn validateTraceRow(row: TraceRow) direct_witness_executor.Error!void {
    if (!validTraceRow(row)) return error.InvalidTraceRow;
}

inline fn validTraceRow(row: TraceRow) bool {
    if (!isFamilyOpcode(row.opcode) or row.clk == 0 or
        access_clock.maximum(row.clk) >= state_chain.CLOCK_PREV_BOUND or
        row.imm < -2048 or row.imm > 2047 or row.branch_taken or
        row.next_pc != row.pc +% 4)
    {
        return false;
    }
    const is_load = isLoadOpcode(row.opcode);
    if (row.is_load != is_load or row.is_store == is_load) return false;
    if (!instructionMatchesWord(.{
        .opcode = row.opcode,
        .rd = row.rd,
        .rs1 = row.rs1,
        .rs2 = row.rs2,
        .imm = row.imm,
    }, row.inst_word)) return false;
    if (row.rs1 == 0 and row.rs1_val != 0) return false;

    const first = access_clock.encode(row.clk, .first);
    const second = access_clock.encode(row.clk, .second);
    const third = access_clock.encode(row.clk, .third);
    if (!validGap(row.rs1_prev_clk, first) or !validGap(row.mem_prev_clk, third))
        return false;

    const retired = canonicalRetirement(
        .{
            .opcode = row.opcode,
            .rd = row.rd,
            .rs1 = row.rs1,
            .rs2 = row.rs2,
            .imm = row.imm,
        },
        row.rs1_val,
        row.rs2_val,
        row.mem_prev_word,
    ) catch return false;
    if (retired.address != row.mem_addr or
        retired.memory_next_word != row.mem_next_word)
    {
        return false;
    }

    if (is_load) {
        if (row.rs2_val != 0 or row.rs2_prev_clk != 0 or
            row.mem_next_word != row.mem_prev_word)
            return false;
        const raw = rawLoadValue(row.opcode, row.mem_prev_word, row.mem_addr);
        if (row.mem_val != raw or row.rd_val != retired.register_value)
            return false;
        if (row.rd == 0 and row.rd_prev_val != 0) return false;
        if (row.rd == row.rs1) {
            if (row.rd_prev_val != row.rs1_val or row.rd_prev_clk != first)
                return false;
        } else if (!validGap(row.rd_prev_clk, second)) {
            return false;
        }
    } else {
        if (row.rs2 == 0 and row.rs2_val != 0) return false;
        if (row.rs2 == row.rs1) {
            if (row.rs2_val != row.rs1_val or row.rs2_prev_clk != first)
                return false;
        } else if (!validGap(row.rs2_prev_clk, second)) {
            return false;
        }
        if (row.mem_val != row.rs2_val or row.rd_prev_val != 0 or
            row.rd_prev_clk != 0 or row.rd_val != 0)
        {
            return false;
        }
    }
    return true;
}

inline fn validGap(previous: u32, current: u32) bool {
    return previous < current and
        current - previous - 1 < (@as(u32, 1) << 20);
}

inline fn rawLoadValue(opcode: decode.Opcode, word: u32, address: u32) u32 {
    const amount: u5 = @intCast((address & 3) * 8);
    return switch (opcode) {
        .LB, .LBU => @as(u8, @truncate(word >> amount)),
        .LH, .LHU => @as(u16, @truncate(word >> amount)),
        .LW => word,
        else => unreachable,
    };
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

comptime {
    @setEvalBranchQuota(50_000);
    if (DIRECT_CONSTRAINT_COUNT != 63 or CANONICAL_DIRECT_RECIPE.len != 63)
        @compileError("typed LOAD_STORE direct geometry drifted");
    for (CANONICAL_DIRECT_RECIPE, 0..) |recipe, index|
        if (@intFromEnum(recipe) != index)
            @compileError("typed LOAD_STORE direct recipe is not canonical");
    if (ENFORCE_AUTHORITY_BINDING_DIGEST and !std.mem.eql(
        u8,
        &CANONICAL_BINDING.identityDigest(),
        &AUTHORITY_BINDING_DIGEST,
    )) @compileError("typed LOAD_STORE canonical authority digest drifted");
}
