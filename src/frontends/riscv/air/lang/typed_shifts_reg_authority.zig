//! Fixed executable authority for RV32 SLL/SRL/SRA.
//!
//! The authenticated binding owns architectural retirement, physical witness
//! projection, all 70 direct roots, and all 20 ordered lookup events. The two
//! shift families share one fixed 65-root core; the retained register-family
//! capability is pointer-free and performs no allocation, string lookup,
//! arena traversal, callback dispatch, or runtime metadata interpretation.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const entry = @import("../lookups/entry.zig");
const common = @import("../semantics/common.zig");
const decode = @import("../../runner/decode.zig");
const trace_row = @import("../../runner/trace_row.zig");
const digest = @import("digest.zig");
const direct_witness_executor = @import("direct_witness_executor.zig");
const fixed_shift_common = @import("fixed_shift_common.zig");
const typed = @import("typed_shifts_reg.zig");
const witness = @import("typed_shifts_reg_witness.zig");

pub const MAIN_COLUMN_COUNT: usize = typed.MAIN_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = typed.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = typed.RELATION_EVENT_COUNT;
pub const LOOKUP_BATCH_SIZE: usize = typed.RELATION_BATCH_SIZE;
pub const OPCODE_IDS = [3]u32{
    typed.SLL_OPCODE_ID,
    typed.SRL_OPCODE_ID,
    typed.SRA_OPCODE_ID,
};

pub const DecodedInst = decode.DecodedInst;
pub const TraceRow = trace_row.TraceRow;

pub const AUTHORITY_BINDING_FORMAT_VERSION: u16 = 1;
pub const AUTHORITY_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/shifts-reg-fixed-authority/v1";
pub const AUTHORITY_BINDING_DIGEST_HEX =
    "c587bc538b1dd084a260a1b359caeb6e4ca26c4e2625000ffee2ca7ffeb43409";
pub const AUTHORITY_BINDING_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, AUTHORITY_BINDING_DIGEST_HEX) catch
        @compileError("invalid typed SHIFTS_REG authority-binding digest");
    break :blk result;
};

pub const ExecutionRecipe = enum(u8) {
    low_five_shift_write_x0_discard = 0,
};

pub const DirectRecipe = enum(u8) {
    active_bit = 0,
    sll_bit = 1,
    srl_bit = 2,
    sra_bit = 3,
    source_sign_bit = 4,
    logical_zero_fill = 5,
    bit_marker_bit_0 = 6,
    bit_marker_bit_1 = 7,
    bit_marker_bit_2 = 8,
    bit_marker_bit_3 = 9,
    bit_marker_bit_4 = 10,
    bit_marker_bit_5 = 11,
    bit_marker_bit_6 = 12,
    bit_marker_bit_7 = 13,
    limb_marker_bit_0 = 14,
    limb_marker_bit_1 = 15,
    limb_marker_bit_2 = 16,
    limb_marker_bit_3 = 17,
    bit_marker_one_hot = 18,
    limb_marker_one_hot = 19,
    left_multiplier = 20,
    right_multiplier = 21,
    left_0_0 = 22,
    left_0_1 = 23,
    left_0_2 = 24,
    left_0_3 = 25,
    left_1_0 = 26,
    left_1_1 = 27,
    left_1_2 = 28,
    left_1_3 = 29,
    left_2_0 = 30,
    left_2_1 = 31,
    left_2_2 = 32,
    left_2_3 = 33,
    left_3_0 = 34,
    left_3_1 = 35,
    left_3_2 = 36,
    left_3_3 = 37,
    right_0_0 = 38,
    right_0_1 = 39,
    right_0_2 = 40,
    right_0_3 = 41,
    right_1_0 = 42,
    right_1_1 = 43,
    right_1_2 = 44,
    right_1_3 = 45,
    right_2_0 = 46,
    right_2_1 = 47,
    right_2_2 = 48,
    right_2_3 = 49,
    right_3_0 = 50,
    right_3_1 = 51,
    right_3_2 = 52,
    right_3_3 = 53,
    destination_nonzero_bit = 54,
    destination_zero_address = 55,
    destination_inverse = 56,
    destination_result_0 = 57,
    destination_result_1 = 58,
    destination_result_2 = 59,
    destination_result_3 = 60,
    source_1_read_only_0 = 61,
    source_1_read_only_1 = 62,
    source_1_read_only_2 = 63,
    source_1_read_only_3 = 64,
    source_2_read_only_0 = 65,
    source_2_read_only_1 = 66,
    source_2_read_only_2 = 67,
    source_2_read_only_3 = 68,
    active_placement = 69,
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
    shift_amount_range = 9,
    carry_range_0 = 10,
    carry_range_1 = 11,
    carry_range_2 = 12,
    carry_range_3 = 13,
    result_range_0 = 14,
    result_range_1 = 15,
    destination_consume = 16,
    destination_emit = 17,
    destination_clock_gap = 18,
    arithmetic_sign_range = 19,
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
    .{ .recipe = .shift_amount_range, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = null },
    .{ .recipe = .carry_range_0, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .carry_range_1, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .carry_range_2, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .carry_range_3, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .result_range_0, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .result_range_1, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .destination_consume, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 3 },
    .{ .recipe = .destination_emit, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 3 },
    .{ .recipe = .destination_clock_gap, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 3 },
    .{ .recipe = .arithmetic_sign_range, .domain = .range_check_m31, .role = .request, .arity = 2, .access_ordinal = null },
};

pub const Binding = struct {
    format_version: u16,
    semantic_format_version: u16,
    opcode_ids: [3]u32,
    semantic_digest: digest.Digest,
    witness_binding_digest: digest.Digest,
    main_column_count: u16,
    execution: ExecutionRecipe,
    direct: [DIRECT_CONSTRAINT_COUNT]DirectRecipe,
    lookups: [LOOKUP_COUNT]LookupDescriptor,
    lookup_batch_size: u8,

    pub fn canonical(definition: *const typed.Definition) witness.ConstructionError!Binding {
        const physical = try witness.WitnessBinding.canonical(definition);
        const physical_digest = physical.identityDigest();
        if (!std.mem.eql(u8, &physical_digest, &witness.WITNESS_BINDING_DIGEST))
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
    .semantic_format_version = digest.range_refinement_format_version,
    .opcode_ids = OPCODE_IDS,
    .semantic_digest = typed.SEMANTIC_DIGEST,
    .witness_binding_digest = witness.WITNESS_BINDING_DIGEST,
    .main_column_count = MAIN_COLUMN_COUNT,
    .execution = .low_five_shift_write_x0_discard,
    .direct = CANONICAL_DIRECT_RECIPE,
    .lookups = CANONICAL_LOOKUP_RECIPE,
    .lookup_batch_size = LOOKUP_BATCH_SIZE,
};

pub const ConstructionError = witness.ConstructionError || error{InvalidAuthorityBinding};
pub const ExecutionError = error{ WrongShiftsRegOpcode, InvalidImmediate };

pub const Retirement = struct {
    rd: u5,
    source_value: u32,
    shift_source_value: u32,
    shift_amount: u5,
    write_enabled: bool,
    attempted_value: u32,
    visible_value: u32,
};

pub inline fn isFamilyOpcode(opcode: decode.Opcode) bool {
    return switch (opcode) {
        .SLL, .SRL, .SRA => true,
        else => false,
    };
}

pub inline fn resultFor(opcode: decode.Opcode, source: u32, shift_source: u32) u32 {
    const amount: u5 = @truncate(shift_source);
    return switch (opcode) {
        .SLL => source << amount,
        .SRL => source >> amount,
        .SRA => @bitCast(@as(i32, @bitCast(source)) >> amount),
        else => unreachable,
    };
}

inline fn canonicalRetirement(
    instruction: DecodedInst,
    source: u32,
    shift_source: u32,
) Retirement {
    const attempted = resultFor(instruction.opcode, source, shift_source);
    return .{
        .rd = instruction.rd,
        .source_value = source,
        .shift_source_value = shift_source,
        .shift_amount = @truncate(shift_source),
        .write_enabled = instruction.rd != 0,
        .attempted_value = attempted,
        .visible_value = if (instruction.rd == 0) 0 else attempted,
    };
}

pub inline fn acceptsRetirement(
    instruction: DecodedInst,
    source: u32,
    shift_source: u32,
    visible_value: u32,
) bool {
    if (!isFamilyOpcode(instruction.opcode) or instruction.imm != 0) return false;
    return visible_value == canonicalRetirement(instruction, source, shift_source).visible_value;
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
        const physical = try witness.WitnessBinding.canonical(definition);
        _ = try witness.Executor.init(definition, &physical);
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
        source: u32,
        shift_source: u32,
    ) ExecutionError!Retirement {
        if (!isFamilyOpcode(instruction.opcode)) return error.WrongShiftsRegOpcode;
        if (instruction.imm != 0) return error.InvalidImmediate;
        return canonicalRetirement(instruction, source, shift_source);
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
    return struct {
        const ops = common.Ops(S);
        const shift = fixed_shift_common.Evaluator(S);
        const e = entry.Builder(S);

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

        pub const Row = struct {
            clk: S,
            pc: S,
            rs2: ops.Access,
            semantic: shift.Row,

            pub inline fn fromMainColumns(columns: []const S) !Row {
                if (columns.len != MAIN_COLUMN_COUNT)
                    return error.InvalidMainTraceShape;
                return .{
                    .clk = columns[0],
                    .pc = columns[1],
                    .rs2 = ops.accessFromColumns(columns[22..32]),
                    .semantic = .{
                        .rd = ops.accessFromColumns(columns[2..12]),
                        .rs1 = ops.accessFromColumns(columns[12..22]),
                        .rs1_sign = columns[32],
                        .is_sll = columns[33],
                        .is_srl = columns[34],
                        .is_sra = columns[35],
                        .bit_multiplier_left = columns[36],
                        .bit_multiplier_right = columns[37],
                        .bit_markers = columns[38..46].*,
                        .limb_markers = columns[46..50].*,
                        .carries = columns[50..54].*,
                        .result = columns[54..58].*,
                        .destination = ops.destinationFromColumns(columns[58..60]),
                    },
                };
            }

            pub inline fn active(self: Row) S {
                return self.semantic.active();
            }
        };

        pub inline fn direct(columns: []const S, is_active: S) !DirectConstraints {
            return directRow(try Row.fromMainColumns(columns), is_active);
        }

        pub fn build(columns: []const S, is_active: S) !ConstraintProgram {
            const row = try Row.fromMainColumns(columns);
            const direct_constraints = directRow(row, is_active);
            var lookup_entries: e.List = undefined;
            lookupsRowInto(row, &lookup_entries);
            return .{
                .active_row = row.active(),
                .direct_constraints = direct_constraints,
                .lookup_entries = lookup_entries,
            };
        }

        pub inline fn directRow(row: Row, is_active: S) DirectConstraints {
            var out: [DIRECT_CONSTRAINT_COUNT]S = undefined;
            const core = shift.evaluate(row.semantic);
            @memcpy(out[0..fixed_shift_common.CONSTRAINT_COUNT], &core.values);
            var index: usize = fixed_shift_common.CONSTRAINT_COUNT;
            inline for (ops.readOnlyAccessConstraints(row.rs2, row.active())) |root| {
                out[index] = root;
                index += 1;
            }
            out[index] = row.active().sub(is_active);
            index += 1;
            std.debug.assert(index == out.len);
            return .{ .values = out };
        }

        pub fn lookups(columns: []const S) !e.List {
            var result: e.List = undefined;
            try lookupsInto(columns, &result);
            return result;
        }

        pub fn lookupsInto(columns: []const S, result: *e.List) !void {
            lookupsRowInto(try Row.fromMainColumns(columns), result);
        }

        fn lookupsRowInto(row: Row, result: *e.List) void {
            @setEvalBranchQuota(100_000);
            const active = row.active();
            const negative_active = active.neg();
            const zero = S.zero();
            const one = S.one();
            const four = ops.q(4);
            const source_1_clock = row.clk.sub(one).mul(four).add(one);
            const source_2_clock = row.clk.sub(one).mul(four).add(ops.q(2));
            const destination_clock = row.clk.sub(one).mul(four).add(ops.q(3));
            const source_1_gap = source_1_clock.sub(row.semantic.rs1.previous_clock).sub(one);
            const source_2_gap = source_2_clock.sub(row.rs2.previous_clock).sub(one);
            const destination_gap = destination_clock
                .sub(row.semantic.rd.previous_clock).sub(one);
            const opcode = row.semantic.is_sll.mul(ops.q(OPCODE_IDS[0]))
                .add(row.semantic.is_srl.mul(ops.q(OPCODE_IDS[1])))
                .add(row.semantic.is_sra.mul(ops.q(OPCODE_IDS[2])));
            const derived = shift.derive(row.semantic);
            const shift_range = ops.q(7).sub(
                row.rs2.next[0].sub(derived.shift_amount).mul(ops.q(typed.INV_32)),
            );
            const carries = shift.carryRangePairs(row.semantic);
            const result_ranges = shift.resultRangePairs(row.semantic);
            const sign_range = shift.signRange(row.semantic);

            result.* = .{ .batch_size = LOOKUP_BATCH_SIZE };
            appendLookup(result, 0, negative_active, .{
                row.pc,
                opcode,
                row.semantic.rd.addr,
                row.semantic.rs1.addr,
                row.rs2.addr,
            });
            appendLookup(result, 1, negative_active, .{ row.pc, row.clk });
            appendLookup(result, 2, active, .{ row.pc.add(four), row.clk.add(one) });
            appendLookup(result, 3, negative_active, .{
                zero,
                row.semantic.rs1.addr,
                row.semantic.rs1.previous_clock,
                row.semantic.rs1.previous[0],
                row.semantic.rs1.previous[1],
                row.semantic.rs1.previous[2],
                row.semantic.rs1.previous[3],
            });
            appendLookup(result, 4, active, .{
                zero,
                row.semantic.rs1.addr,
                source_1_clock,
                row.semantic.rs1.next[0],
                row.semantic.rs1.next[1],
                row.semantic.rs1.next[2],
                row.semantic.rs1.next[3],
            });
            appendLookup(result, 5, negative_active, .{source_1_gap});
            appendLookup(result, 6, negative_active, .{
                zero,
                row.rs2.addr,
                row.rs2.previous_clock,
                row.rs2.previous[0],
                row.rs2.previous[1],
                row.rs2.previous[2],
                row.rs2.previous[3],
            });
            appendLookup(result, 7, active, .{
                zero,
                row.rs2.addr,
                source_2_clock,
                row.rs2.next[0],
                row.rs2.next[1],
                row.rs2.next[2],
                row.rs2.next[3],
            });
            appendLookup(result, 8, negative_active, .{source_2_gap});
            appendLookup(result, 9, negative_active, .{shift_range});
            inline for (carries, 0..) |pair, index|
                appendLookup(result, 10 + index, negative_active, pair);
            inline for (result_ranges, 0..) |pair, index|
                appendLookup(result, 14 + index, negative_active, pair);
            appendLookup(result, 16, negative_active, .{
                zero,
                row.semantic.rd.addr,
                row.semantic.rd.previous_clock,
                row.semantic.rd.previous[0],
                row.semantic.rd.previous[1],
                row.semantic.rd.previous[2],
                row.semantic.rd.previous[3],
            });
            appendLookup(result, 17, active, .{
                zero,
                row.semantic.rd.addr,
                destination_clock,
                row.semantic.rd.next[0],
                row.semantic.rd.next[1],
                row.semantic.rd.next[2],
                row.semantic.rd.next[3],
            });
            appendLookup(result, 18, negative_active, .{destination_gap});
            appendLookup(result, 19, row.semantic.is_sra.neg(), sign_range);
            std.debug.assert(result.len == LOOKUP_COUNT);
        }

        inline fn appendLookup(
            result: *e.List,
            comptime index: usize,
            numerator: S,
            values: anytype,
        ) void {
            const descriptor = CANONICAL_LOOKUP_RECIPE[index];
            comptime if (@intFromEnum(descriptor.recipe) != index or
                descriptor.arity != values.len)
            {
                @compileError("typed SHIFTS_REG fixed lookup append drifted");
            };
            const target = &result.entries[index];
            target.* = .{
                .domain = descriptor.domain,
                .numerator = numerator,
                .arity = descriptor.arity,
                .role = descriptor.role,
                .access_ordinal = descriptor.access_ordinal,
            };
            inline for (values, 0..) |value, value_index|
                target.values[value_index] = value;
            result.len = index + 1;
        }
    };
}

pub fn validateTraceRow(row: TraceRow) direct_witness_executor.Error!void {
    if (!validTraceRow(row)) return error.InvalidTraceRow;
}

inline fn writeActiveRowUnchecked(columns: anytype, row_index: usize, row: TraceRow) void {
    witness.writeActiveRow(columns, row_index, row);
}

inline fn validTraceRow(row: TraceRow) bool {
    if (!isFamilyOpcode(row.opcode) or row.imm != 0 or row.clk == 0 or
        row.next_pc != row.pc +% 4 or row.is_load or row.is_store or row.branch_taken)
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
        (row.rd == 0 and row.rd_prev_val != 0) or
        (row.rs1 == row.rs2 and
            (row.rs1_val != row.rs2_val or row.rs2_prev_clk != source_1_clock)))
    {
        return false;
    }
    const expected_previous_clock = if (row.rd == row.rs2)
        source_2_clock
    else if (row.rd == row.rs1)
        source_1_clock
    else
        row.rd_prev_clk;
    const expected_previous_value = if (row.rd == row.rs2)
        row.rs2_val
    else if (row.rd == row.rs1)
        row.rs1_val
    else
        row.rd_prev_val;
    if ((row.rd == row.rs1 or row.rd == row.rs2) and
        (row.rd_prev_clk != expected_previous_clock or
            row.rd_prev_val != expected_previous_value))
    {
        return false;
    }
    const expected = resultFor(row.opcode, row.rs1_val, row.rs2_val);
    return row.rd_val == (if (row.rd == 0) 0 else expected);
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
    if (DIRECT_CONSTRAINT_COUNT != 70 or CANONICAL_DIRECT_RECIPE.len != 70)
        @compileError("typed SHIFTS_REG direct geometry drifted");
    for (CANONICAL_DIRECT_RECIPE, 0..) |recipe, index|
        if (@intFromEnum(recipe) != index)
            @compileError("typed SHIFTS_REG direct recipe is not canonical");
    if (!std.mem.eql(
        u8,
        &CANONICAL_BINDING.identityDigest(),
        &AUTHORITY_BINDING_DIGEST,
    )) @compileError("typed SHIFTS_REG canonical authority digest drifted");
}
