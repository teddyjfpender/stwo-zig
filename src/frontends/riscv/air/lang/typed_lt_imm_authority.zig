//! Fixed executable authority for RV32 SLTI/SLTIU.
//!
//! One authenticated, pointer-free binding owns immediate comparison,
//! architectural retirement, physical witness projection, direct roots, and
//! ordered lookup events. Cold construction authenticates the complete typed
//! graph and witness recipe; hot execution retains no arena or allocator and
//! performs no dynamic, textual, or callback dispatch.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const entry = @import("../lookups/entry.zig");
const common = @import("../semantics/common.zig");
const decode = @import("../../runner/decode.zig");
const trace_row = @import("../../runner/trace_row.zig");
const digest = @import("digest.zig");
const direct_witness_executor = @import("direct_witness_executor.zig");
const typed = @import("typed_lt_imm.zig");
const witness = @import("typed_lt_imm_witness.zig");

pub const MAIN_COLUMN_COUNT: usize = typed.MAIN_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = typed.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = typed.LOOKUP_COUNT;
pub const LOOKUP_BATCH_SIZE: usize = 2;
pub const OPCODE_IDS = [2]u32{ typed.SLTI_OPCODE_ID, typed.SLTIU_OPCODE_ID };

pub const DecodedInst = decode.DecodedInst;
pub const TraceRow = trace_row.TraceRow;

pub const AUTHORITY_BINDING_FORMAT_VERSION: u16 = 1;
pub const AUTHORITY_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/lt-imm-fixed-authority/v1";

// Replaced only by the binding-identity admission test. A literal receipt
// makes execution, root order, lookup order, and witness geometry changes an
// explicit protocol review.
pub const AUTHORITY_BINDING_DIGEST_HEX =
    "bfe5a4896da341e2efd83feaf82c2ac289937712a3d2971162f3d783a25b491f";
pub const AUTHORITY_BINDING_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, AUTHORITY_BINDING_DIGEST_HEX) catch
        @compileError("invalid typed LT_IMM authority-binding digest");
    break :blk result;
};

pub const ExecutionRecipe = enum(u8) {
    signed_unsigned_immediate_compare_write_x0_discard = 0,
};

pub const DirectRecipe = enum(u8) {
    active_bit = 0,
    slti_bit = 1,
    sltiu_bit = 2,
    immediate_sign_bit = 3,
    immediate_most_significant_limb = 4,
    source_most_significant_limb_split = 5,
    difference_marker_bit_0 = 6,
    difference_marker_bit_1 = 7,
    difference_marker_bit_2 = 8,
    difference_marker_bit_3 = 9,
    limb_3_first_difference = 10,
    limb_3_positive_difference = 11,
    limb_2_first_difference = 12,
    limb_2_positive_difference = 13,
    limb_1_first_difference = 14,
    limb_1_positive_difference = 15,
    limb_0_first_difference = 16,
    limb_0_positive_difference = 17,
    marker_prefix_bit = 18,
    equal_operands_not_less = 19,
    comparison_bit = 20,
    destination_nonzero_bit = 21,
    destination_zero_address = 22,
    destination_inverse = 23,
    destination_result_0 = 24,
    destination_result_1 = 25,
    destination_result_2 = 26,
    destination_result_3 = 27,
    source_read_only_0 = 28,
    source_read_only_1 = 29,
    source_read_only_2 = 30,
    source_read_only_3 = 31,
    active_placement = 32,
};

pub const CANONICAL_DIRECT_RECIPE = [DIRECT_CONSTRAINT_COUNT]DirectRecipe{
    .active_bit,
    .slti_bit,
    .sltiu_bit,
    .immediate_sign_bit,
    .immediate_most_significant_limb,
    .source_most_significant_limb_split,
    .difference_marker_bit_0,
    .difference_marker_bit_1,
    .difference_marker_bit_2,
    .difference_marker_bit_3,
    .limb_3_first_difference,
    .limb_3_positive_difference,
    .limb_2_first_difference,
    .limb_2_positive_difference,
    .limb_1_first_difference,
    .limb_1_positive_difference,
    .limb_0_first_difference,
    .limb_0_positive_difference,
    .marker_prefix_bit,
    .equal_operands_not_less,
    .comparison_bit,
    .destination_nonzero_bit,
    .destination_zero_address,
    .destination_inverse,
    .destination_result_0,
    .destination_result_1,
    .destination_result_2,
    .destination_result_3,
    .source_read_only_0,
    .source_read_only_1,
    .source_read_only_2,
    .source_read_only_3,
    .active_placement,
};

pub const LookupRecipe = enum(u8) {
    program_fetch = 0,
    immediate_range = 1,
    state_consume = 2,
    state_emit = 3,
    source_consume = 4,
    source_emit = 5,
    source_clock_gap = 6,
    positive_difference = 7,
    destination_consume = 8,
    destination_emit = 9,
    destination_clock_gap = 10,
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
    .{ .recipe = .immediate_range, .domain = .range_check_8_8_4, .role = .request, .arity = 3, .access_ordinal = null },
    .{ .recipe = .state_consume, .domain = .registers_state, .role = .consume, .arity = 2, .access_ordinal = null },
    .{ .recipe = .state_emit, .domain = .registers_state, .role = .emit, .arity = 2, .access_ordinal = null },
    .{ .recipe = .source_consume, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 1 },
    .{ .recipe = .source_emit, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 1 },
    .{ .recipe = .source_clock_gap, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 1 },
    .{ .recipe = .positive_difference, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = null },
    .{ .recipe = .destination_consume, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 2 },
    .{ .recipe = .destination_emit, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 2 },
    .{ .recipe = .destination_clock_gap, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 2 },
};

pub const Binding = struct {
    format_version: u16,
    semantic_format_version: u16,
    opcode_ids: [2]u32,
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
    .execution = .signed_unsigned_immediate_compare_write_x0_discard,
    .direct = CANONICAL_DIRECT_RECIPE,
    .lookups = CANONICAL_LOOKUP_RECIPE,
    .lookup_batch_size = LOOKUP_BATCH_SIZE,
};

pub const ConstructionError = witness.ConstructionError || error{InvalidAuthorityBinding};
pub const ExecutionError = error{ WrongLtImmOpcode, InvalidImmediate };

pub const Retirement = struct {
    rd: u5,
    source_value: u32,
    immediate: i32,
    signed: bool,
    less: bool,
    write_enabled: bool,
    attempted_value: u32,
    visible_value: u32,
};

pub inline fn isFamilyOpcode(opcode: decode.Opcode) bool {
    return switch (opcode) {
        .SLTI, .SLTIU => true,
        else => false,
    };
}

pub inline fn resultFor(opcode: decode.Opcode, source: u32, immediate: i32) u32 {
    const less = switch (opcode) {
        .SLTI => @as(i32, @bitCast(source)) < immediate,
        .SLTIU => source < @as(u32, @bitCast(immediate)),
        else => unreachable,
    };
    return @intFromBool(less);
}

inline fn canonicalRetirement(
    instruction: DecodedInst,
    source: u32,
) Retirement {
    const attempted = resultFor(instruction.opcode, source, instruction.imm);
    return .{
        .rd = instruction.rd,
        .source_value = source,
        .immediate = instruction.imm,
        .signed = instruction.opcode == .SLTI,
        .less = attempted != 0,
        .write_enabled = instruction.rd != 0,
        .attempted_value = attempted,
        .visible_value = if (instruction.rd == 0) 0 else attempted,
    };
}

pub inline fn acceptsRetirement(
    instruction: DecodedInst,
    source: u32,
    visible_value: u32,
) bool {
    if (!isFamilyOpcode(instruction.opcode) or
        instruction.imm < -2048 or instruction.imm > 2047)
    {
        return false;
    }
    return visible_value == canonicalRetirement(instruction, source).visible_value;
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
    ) ExecutionError!Retirement {
        if (!isFamilyOpcode(instruction.opcode)) return error.WrongLtImmOpcode;
        if (instruction.imm < -2048 or instruction.imm > 2047)
            return error.InvalidImmediate;
        return canonicalRetirement(instruction, source);
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
            rd: ops.Access,
            rs1: ops.Access,
            cmp_result: S,
            rs1_msl_felt: S,
            imm_0: S,
            imm_1: S,
            imm_msb: S,
            is_slti: S,
            is_sltiu: S,
            diff_markers: [4]S,
            diff_val: S,
            destination: ops.Destination,
            imm_msl_felt: S,

            pub inline fn fromMainColumns(columns: []const S) !Row {
                if (columns.len != MAIN_COLUMN_COUNT)
                    return error.InvalidMainTraceShape;
                return .{
                    .clk = columns[0],
                    .pc = columns[1],
                    .rd = ops.accessFromColumns(columns[2..12]),
                    .rs1 = ops.accessFromColumns(columns[12..22]),
                    .cmp_result = columns[22],
                    .rs1_msl_felt = columns[23],
                    .imm_0 = columns[24],
                    .imm_1 = columns[25],
                    .imm_msb = columns[26],
                    .is_slti = columns[27],
                    .is_sltiu = columns[28],
                    .diff_markers = columns[29..33].*,
                    .diff_val = columns[33],
                    .destination = ops.destinationFromColumns(columns[34..36]),
                    .imm_msl_felt = columns[36],
                };
            }

            pub inline fn active(self: Row) S {
                return self.is_slti.add(self.is_sltiu);
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
            @setEvalBranchQuota(10_000);
            var out: [DIRECT_CONSTRAINT_COUNT]S = undefined;
            var index: usize = 0;
            const active = row.active();
            out[index] = ops.bit(active);
            index += 1;
            out[index] = ops.bit(row.is_slti);
            index += 1;
            out[index] = ops.bit(row.is_sltiu);
            index += 1;
            out[index] = ops.bit(row.imm_msb);
            index += 1;

            const immediate_sign_extension = row.imm_msb.mul(ops.q(255));
            const expected_imm_msl = row.is_sltiu
                .mul(immediate_sign_extension)
                .sub(row.is_slti.mul(row.imm_msb));
            out[index] = row.imm_msl_felt.sub(expected_imm_msl);
            index += 1;
            const rs1_msl_gap = row.rs1.next[3].sub(row.rs1_msl_felt);
            out[index] = rs1_msl_gap.mul(ops.q(256).sub(rs1_msl_gap));
            index += 1;
            inline for (row.diff_markers) |marker| {
                out[index] = ops.bit(marker);
                index += 1;
            }

            const immediate_high = row.imm_1.add(row.imm_msb.mul(ops.q(248)));
            const lhs = [4]S{
                row.rs1.next[0],
                row.rs1.next[1],
                row.rs1.next[2],
                row.rs1_msl_felt,
            };
            const rhs = [4]S{
                row.imm_0,
                immediate_high,
                immediate_sign_extension,
                row.imm_msl_felt,
            };
            const cmp_sign = row.cmp_result.mul(ops.q(2)).sub(S.one());
            var more_significant = S.zero();
            inline for (0..4) |offset| {
                const limb = 3 - offset;
                const marker = row.diff_markers[limb];
                const oriented = cmp_sign.mul(rhs[limb].sub(lhs[limb]));
                out[index] = S.one().sub(more_significant).sub(marker).mul(oriented);
                index += 1;
                out[index] = marker.mul(row.diff_val.sub(oriented));
                index += 1;
                more_significant = more_significant.add(marker);
            }
            var prefix = S.zero();
            inline for (row.diff_markers) |marker| prefix = prefix.add(marker);
            out[index] = prefix.mul(S.one().sub(prefix));
            index += 1;
            out[index] = S.one().sub(prefix).mul(row.cmp_result);
            index += 1;
            out[index] = ops.bit(row.cmp_result);
            index += 1;
            inline for (ops.destinationConstraints(row.rd.addr, row.destination)) |constraint| {
                out[index] = constraint;
                index += 1;
            }
            inline for (ops.destinationResultConstraints(
                row.rd,
                .{ row.cmp_result, S.zero(), S.zero(), S.zero() },
                row.destination,
            )) |constraint| {
                out[index] = constraint;
                index += 1;
            }
            inline for (ops.readOnlyAccessConstraints(row.rs1, active)) |constraint| {
                out[index] = constraint;
                index += 1;
            }
            out[index] = active.sub(is_active);
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
            const active = row.active();
            const negative_active = active.neg();
            const zero = S.zero();
            const one = S.one();
            const four = ops.q(4);
            const source_clock = row.clk.sub(one).mul(four).add(one);
            const destination_clock = row.clk.sub(one).mul(four).add(ops.q(2));
            const source_gap = source_clock.sub(row.rs1.previous_clock).sub(one);
            const destination_gap = destination_clock.sub(row.rd.previous_clock).sub(one);
            const immediate = row.imm_0
                .add(row.imm_1.mul(ops.q(256)))
                .add(row.imm_msb.mul(ops.q(2048)));
            const opcode = row.is_slti.mul(ops.q(OPCODE_IDS[0]))
                .add(row.is_sltiu.mul(ops.q(OPCODE_IDS[1])));
            var prefix = S.zero();
            inline for (row.diff_markers) |marker| prefix = prefix.add(marker);
            result.* = .{ .batch_size = LOOKUP_BATCH_SIZE };
            appendLookup(result, 0, negative_active, .{
                row.pc, opcode, row.rd.addr, row.rs1.addr, immediate,
            });
            appendLookup(result, 1, negative_active, .{
                row.rs1_msl_felt.add(row.is_slti.mul(ops.q(128))),
                row.imm_0,
                row.imm_1.mul(ops.q(2)),
            });
            appendLookup(result, 2, negative_active, .{ row.pc, row.clk });
            appendLookup(result, 3, active, .{ row.pc.add(four), row.clk.add(one) });
            appendLookup(result, 4, negative_active, .{
                zero,                row.rs1.addr,        row.rs1.previous_clock,
                row.rs1.previous[0], row.rs1.previous[1], row.rs1.previous[2],
                row.rs1.previous[3],
            });
            appendLookup(result, 5, active, .{
                zero,            row.rs1.addr,    source_clock,
                row.rs1.next[0], row.rs1.next[1], row.rs1.next[2],
                row.rs1.next[3],
            });
            appendLookup(result, 6, negative_active, .{source_gap});
            appendLookup(result, 7, prefix.neg(), .{row.diff_val.sub(one)});
            appendLookup(result, 8, negative_active, .{
                zero,               row.rd.addr,        row.rd.previous_clock,
                row.rd.previous[0], row.rd.previous[1], row.rd.previous[2],
                row.rd.previous[3],
            });
            appendLookup(result, 9, active, .{
                zero,           row.rd.addr,    destination_clock,
                row.rd.next[0], row.rd.next[1], row.rd.next[2],
                row.rd.next[3],
            });
            appendLookup(result, 10, negative_active, .{destination_gap});
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
                @compileError("typed LT_IMM fixed lookup append drifted");
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
    if (!isFamilyOpcode(row.opcode) or row.imm < -2048 or row.imm > 2047 or
        row.clk == 0 or row.next_pc != row.pc +% 4 or row.is_load or
        row.is_store or row.branch_taken)
    {
        return false;
    }
    const source_clock = accessClock(row.clk, 1) orelse return false;
    const destination_clock = accessClock(row.clk, 2) orelse return false;
    if (!validGap(row.rs1_prev_clk, source_clock) or
        !validGap(row.rd_prev_clk, destination_clock)) return false;
    const expected = resultFor(row.opcode, row.rs1_val, row.imm);
    return row.rd_val == (if (row.rd == 0) 0 else expected) and
        (row.rs1 != 0 or row.rs1_val == 0) and
        (row.rd != 0 or row.rd_prev_val == 0) and
        (row.rd != row.rs1 or
            (row.rd_prev_val == row.rs1_val and row.rd_prev_clk == source_clock));
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
    @setEvalBranchQuota(20_000);
    if (!std.mem.eql(
        u8,
        &CANONICAL_BINDING.identityDigest(),
        &AUTHORITY_BINDING_DIGEST,
    )) @compileError("typed LT_IMM canonical authority digest drifted");
}
