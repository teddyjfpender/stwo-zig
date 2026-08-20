//! Fixed executable authority for RV32 BLT/BLTU/BGE/BGEU.
//!
//! One authenticated, pointer-free binding owns branch comparison and target
//! selection, physical witness projection, direct roots, and ordered lookup
//! events. Cold construction authenticates the native typed graph and complete
//! witness recipe; hot execution retains neither arenas nor allocators and
//! performs no dynamic, textual, or callback dispatch.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const entry = @import("../lookups/entry.zig");
const common = @import("../semantics/common.zig");
const control = @import("../semantics/control_common.zig");
const decode = @import("../../runner/decode.zig");
const trace_row = @import("../../runner/trace_row.zig");
const digest = @import("digest.zig");
const direct_witness_executor = @import("direct_witness_executor.zig");
const typed = @import("typed_branch_lt.zig");
const witness = @import("typed_branch_lt_witness.zig");

pub const MAIN_COLUMN_COUNT: usize = typed.MAIN_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = typed.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = typed.LOOKUP_COUNT;
pub const LOOKUP_BATCH_SIZE: usize = typed.LOOKUP_BATCH_SIZE;
pub const OPCODE_IDS = [4]u32{
    typed.BLT_OPCODE_ID,
    typed.BLTU_OPCODE_ID,
    typed.BGE_OPCODE_ID,
    typed.BGEU_OPCODE_ID,
};
pub const PC_BOUND: u32 = @as(u32, 1) << 30;

pub const DecodedInst = decode.DecodedInst;
pub const Opcode = decode.Opcode;
pub const TraceRow = trace_row.TraceRow;

pub const AUTHORITY_BINDING_FORMAT_VERSION: u16 = 1;
pub const AUTHORITY_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/branch-lt-fixed-authority/v1";

// Updated only through the binding-identity admission test. Keeping a literal
// receipt makes execution, root, lookup-order, or witness-geometry drift an
// explicit protocol review.
pub const AUTHORITY_BINDING_DIGEST_HEX =
    "77e729cdac93b45bfd71ecfb8f7afa9411a1db09f9caf567c9fd87d460412a95";
pub const AUTHORITY_BINDING_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, AUTHORITY_BINDING_DIGEST_HEX) catch
        @compileError("invalid typed BRANCH_LT authority-binding digest");
    break :blk result;
};

pub const ExecutionRecipe = enum(u8) {
    compare_sources_select_aligned_pc = 0,
};

pub const DirectRecipe = enum(u8) {
    active_bit = 0,
    blt_bit = 1,
    bltu_bit = 2,
    bge_bit = 3,
    bgeu_bit = 4,
    comparison_bit = 5,
    difference_marker_0_bit = 6,
    difference_marker_1_bit = 7,
    difference_marker_2_bit = 8,
    difference_marker_3_bit = 9,
    selected_target = 10,
    source_1_signed_msb = 11,
    source_2_signed_msb = 12,
    difference_3_prefix = 13,
    difference_3_selected = 14,
    difference_2_prefix = 15,
    difference_2_selected = 16,
    difference_1_prefix = 17,
    difference_1_selected = 18,
    difference_0_prefix = 19,
    difference_0_selected = 20,
    difference_prefix_bit = 21,
    equal_not_less = 22,
    branch_decision = 23,
    source_1_read_only_0 = 24,
    source_1_read_only_1 = 25,
    source_1_read_only_2 = 26,
    source_1_read_only_3 = 27,
    source_2_read_only_0 = 28,
    source_2_read_only_1 = 29,
    source_2_read_only_2 = 30,
    source_2_read_only_3 = 31,
    active_placement = 32,
};

pub const CANONICAL_DIRECT_RECIPE = [DIRECT_CONSTRAINT_COUNT]DirectRecipe{
    .active_bit,
    .blt_bit,
    .bltu_bit,
    .bge_bit,
    .bgeu_bit,
    .comparison_bit,
    .difference_marker_0_bit,
    .difference_marker_1_bit,
    .difference_marker_2_bit,
    .difference_marker_3_bit,
    .selected_target,
    .source_1_signed_msb,
    .source_2_signed_msb,
    .difference_3_prefix,
    .difference_3_selected,
    .difference_2_prefix,
    .difference_2_selected,
    .difference_1_prefix,
    .difference_1_selected,
    .difference_0_prefix,
    .difference_0_selected,
    .difference_prefix_bit,
    .equal_not_less,
    .branch_decision,
    .source_1_read_only_0,
    .source_1_read_only_1,
    .source_1_read_only_2,
    .source_1_read_only_3,
    .source_2_read_only_0,
    .source_2_read_only_1,
    .source_2_read_only_2,
    .source_2_read_only_3,
    .active_placement,
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
    shifted_most_significant_bytes = 9,
    positive_difference = 10,
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
    .{ .recipe = .shifted_most_significant_bytes, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .positive_difference, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = null },
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
    .semantic_format_version = digest.committed_program_control_target_format_version,
    .opcode_ids = OPCODE_IDS,
    .semantic_digest = typed.SEMANTIC_DIGEST,
    .witness_binding_digest = witness.WITNESS_BINDING_DIGEST,
    .main_column_count = MAIN_COLUMN_COUNT,
    .execution = .compare_sources_select_aligned_pc,
    .direct = CANONICAL_DIRECT_RECIPE,
    .lookups = CANONICAL_LOOKUP_RECIPE,
    .lookup_batch_size = LOOKUP_BATCH_SIZE,
};

pub const ConstructionError = witness.ConstructionError || error{InvalidAuthorityBinding};
pub const ExecutionError = error{
    WrongBranchLtOpcode,
    InvalidImmediate,
    InvalidProgramCounter,
    InstructionAddressMisaligned,
    TargetOutOfRange,
};

pub const Retirement = struct {
    source_1_value: u32,
    source_2_value: u32,
    less: bool,
    taken: bool,
    next_pc: u32,
    branch_taken: bool,
};

pub inline fn isFamilyOpcode(opcode: decode.Opcode) bool {
    return switch (opcode) {
        .BLT, .BLTU, .BGE, .BGEU => true,
        else => false,
    };
}

pub inline fn branchCondition(
    opcode: decode.Opcode,
    source_1: u32,
    source_2: u32,
) bool {
    return switch (opcode) {
        .BLT => @as(i32, @bitCast(source_1)) <
            @as(i32, @bitCast(source_2)),
        .BLTU => source_1 < source_2,
        .BGE => @as(i32, @bitCast(source_1)) >=
            @as(i32, @bitCast(source_2)),
        .BGEU => source_1 >= source_2,
        else => unreachable,
    };
}

inline fn canonicalRetirement(
    instruction: DecodedInst,
    pc: u32,
    source_1: u32,
    source_2: u32,
) ExecutionError!Retirement {
    if (!isFamilyOpcode(instruction.opcode)) return error.WrongBranchLtOpcode;
    if (instruction.imm < -4096 or instruction.imm > 4094 or
        (@as(u32, @bitCast(instruction.imm)) & 1) != 0)
    {
        return error.InvalidImmediate;
    }
    if (pc >= PC_BOUND) return error.InvalidProgramCounter;
    if (pc & 3 != 0) return error.InstructionAddressMisaligned;
    const less = switch (instruction.opcode) {
        .BLT, .BGE => @as(i32, @bitCast(source_1)) <
            @as(i32, @bitCast(source_2)),
        .BLTU, .BGEU => source_1 < source_2,
        else => unreachable,
    };
    const taken = switch (instruction.opcode) {
        .BLT, .BLTU => less,
        .BGE, .BGEU => !less,
        else => unreachable,
    };
    const next_pc = if (taken)
        pc +% @as(u32, @bitCast(instruction.imm))
    else
        pc +% 4;
    if (next_pc >= PC_BOUND) return error.TargetOutOfRange;
    if (next_pc & 3 != 0) return error.InstructionAddressMisaligned;
    return .{
        .source_1_value = source_1,
        .source_2_value = source_2,
        .less = less,
        .taken = taken,
        .next_pc = next_pc,
        .branch_taken = next_pc != pc +% 4,
    };
}

pub inline fn acceptsRetirement(
    instruction: DecodedInst,
    pc: u32,
    source_1: u32,
    source_2: u32,
    next_pc: u32,
    branch_taken: bool,
) bool {
    const retirement = canonicalRetirement(
        instruction,
        pc,
        source_1,
        source_2,
    ) catch return false;
    return retirement.next_pc == next_pc and
        retirement.branch_taken == branch_taken;
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
        pc: u32,
        source_1: u32,
        source_2: u32,
    ) ExecutionError!Retirement {
        return canonicalRetirement(instruction, pc, source_1, source_2);
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
        pc_polynomial: S,
        branch_target_polynomial: S,
        is_active: S,
    ) !Evaluator(S).ConstraintProgram {
        return Evaluator(S).build(
            columns,
            pc_polynomial,
            branch_target_polynomial,
            is_active,
        );
    }

    pub inline fn evaluateDirect(
        _: *const Authority,
        comptime S: type,
        columns: []const S,
        pc_polynomial: S,
        branch_target_polynomial: S,
        is_active: S,
    ) !Evaluator(S).DirectConstraints {
        return Evaluator(S).direct(
            columns,
            pc_polynomial,
            branch_target_polynomial,
            is_active,
        );
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
        const ctl = control.Ops(S);
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
            clock: S,
            pc: S,
            rs1: ops.Access,
            rs2: ops.Access,
            rs1_msl_felt: S,
            rs2_msl_felt: S,
            imm_felt: S,
            cmp_result: S,
            cmp_lt: S,
            diff_markers: [4]S,
            diff_val: S,
            branch_target: S,
            opcode_blt_flag: S,
            opcode_bltu_flag: S,
            opcode_bge_flag: S,
            opcode_bgeu_flag: S,

            pub inline fn fromMainColumns(columns: []const S) !Row {
                if (columns.len != MAIN_COLUMN_COUNT)
                    return error.InvalidMainTraceShape;
                return .{
                    .clock = columns[0],
                    .pc = columns[1],
                    .rs1 = ctl.accessFromColumns(columns, 2),
                    .rs2 = ctl.accessFromColumns(columns, 12),
                    .rs1_msl_felt = columns[22],
                    .rs2_msl_felt = columns[23],
                    .imm_felt = columns[24],
                    .cmp_result = columns[25],
                    .cmp_lt = columns[26],
                    .diff_markers = columns[27..31].*,
                    .diff_val = columns[31],
                    .branch_target = columns[32],
                    .opcode_blt_flag = columns[33],
                    .opcode_bltu_flag = columns[34],
                    .opcode_bge_flag = columns[35],
                    .opcode_bgeu_flag = columns[36],
                };
            }

            pub inline fn active(self: Row) S {
                return self.opcode_blt_flag
                    .add(self.opcode_bltu_flag)
                    .add(self.opcode_bge_flag)
                    .add(self.opcode_bgeu_flag);
            }
        };

        pub inline fn direct(
            columns: []const S,
            pc_polynomial: S,
            branch_target_polynomial: S,
            is_active: S,
        ) !DirectConstraints {
            return directRow(
                try Row.fromMainColumns(columns),
                pc_polynomial,
                branch_target_polynomial,
                is_active,
            );
        }

        pub fn build(
            columns: []const S,
            pc_polynomial: S,
            branch_target_polynomial: S,
            is_active: S,
        ) !ConstraintProgram {
            const row = try Row.fromMainColumns(columns);
            const direct_constraints = directRow(
                row,
                pc_polynomial,
                branch_target_polynomial,
                is_active,
            );
            var lookup_entries: e.List = undefined;
            lookupsRowInto(row, &lookup_entries);
            return .{
                .active_row = row.active(),
                .direct_constraints = direct_constraints,
                .lookup_entries = lookup_entries,
            };
        }

        pub inline fn directRow(
            row: Row,
            pc_polynomial: S,
            branch_target_polynomial: S,
            is_active: S,
        ) DirectConstraints {
            @setEvalBranchQuota(10_000);
            var out: [DIRECT_CONSTRAINT_COUNT]S = undefined;
            var index: usize = 0;
            const active = row.active();
            out[index] = ops.bit(active);
            index += 1;
            inline for (.{
                row.opcode_blt_flag,
                row.opcode_bltu_flag,
                row.opcode_bge_flag,
                row.opcode_bgeu_flag,
            }) |flag| {
                out[index] = ops.bit(flag);
                index += 1;
            }
            out[index] = ops.bit(row.cmp_result);
            index += 1;
            inline for (row.diff_markers) |marker| {
                out[index] = ops.bit(marker);
                index += 1;
            }

            const not_cmp = S.one().sub(row.cmp_result);
            const selected_target = pc_polynomial
                .add(row.imm_felt.mul(row.cmp_result))
                .add(ops.q(4).mul(not_cmp));
            out[index] = active.mul(
                branch_target_polynomial.sub(selected_target),
            );
            index += 1;

            const rs1_msl_gap = row.rs1.next[3].sub(row.rs1_msl_felt);
            const rs2_msl_gap = row.rs2.next[3].sub(row.rs2_msl_felt);
            out[index] = rs1_msl_gap.mul(ops.q(256).sub(rs1_msl_gap));
            index += 1;
            out[index] = rs2_msl_gap.mul(ops.q(256).sub(rs2_msl_gap));
            index += 1;

            const prefix = row.diff_markers[0]
                .add(row.diff_markers[1])
                .add(row.diff_markers[2])
                .add(row.diff_markers[3]);
            const lt_sign = ops.q(2).mul(row.cmp_lt).sub(S.one());
            const diff3 = lt_sign.mul(
                row.rs2_msl_felt.sub(row.rs1_msl_felt),
            );
            const diff2 = lt_sign.mul(row.rs2.next[2].sub(row.rs1.next[2]));
            const diff1 = lt_sign.mul(row.rs2.next[1].sub(row.rs1.next[1]));
            const diff0 = lt_sign.mul(row.rs2.next[0].sub(row.rs1.next[0]));
            const m0 = row.diff_markers[0];
            const m1 = row.diff_markers[1];
            const m2 = row.diff_markers[2];
            const m3 = row.diff_markers[3];
            out[index] = S.one().sub(m3).mul(diff3);
            index += 1;
            out[index] = m3.mul(row.diff_val.sub(diff3));
            index += 1;
            out[index] = S.one().sub(m3).sub(m2).mul(diff2);
            index += 1;
            out[index] = m2.mul(row.diff_val.sub(diff2));
            index += 1;
            out[index] = S.one().sub(m3).sub(m2).sub(m1).mul(diff1);
            index += 1;
            out[index] = m1.mul(row.diff_val.sub(diff1));
            index += 1;
            out[index] = S.one().sub(prefix).mul(diff0);
            index += 1;
            out[index] = m0.mul(row.diff_val.sub(diff0));
            index += 1;
            out[index] = ops.bit(prefix);
            index += 1;
            out[index] = S.one().sub(prefix).mul(row.cmp_lt);
            index += 1;

            const lt = row.opcode_blt_flag.add(row.opcode_bltu_flag);
            const ge = row.opcode_bge_flag.add(row.opcode_bgeu_flag);
            const expected_cmp_lt = row.cmp_result.mul(lt)
                .add(not_cmp.mul(ge));
            out[index] = row.cmp_lt.sub(expected_cmp_lt);
            index += 1;
            inline for (ops.readOnlyAccessConstraints(row.rs1, active)) |constraint| {
                out[index] = constraint;
                index += 1;
            }
            inline for (ops.readOnlyAccessConstraints(row.rs2, active)) |constraint| {
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
            const opcode_id = row.opcode_blt_flag.mul(ops.q(OPCODE_IDS[0]))
                .add(row.opcode_bltu_flag.mul(ops.q(OPCODE_IDS[1])))
                .add(row.opcode_bge_flag.mul(ops.q(OPCODE_IDS[2])))
                .add(row.opcode_bgeu_flag.mul(ops.q(OPCODE_IDS[3])));
            const program_request = ctl.programRequest(active, .{
                .pc = row.pc,
                .opcode_id = opcode_id,
                .rd = row.rs1.addr,
                .rs1 = row.rs2.addr,
                .operand = row.imm_felt,
            });
            const source_1 = ctl.registerAccessLookups(
                row.rs1,
                row.clock,
                .first,
                active,
            );
            const source_2 = ctl.registerAccessLookups(
                row.rs2,
                row.clock,
                .second,
                active,
            );
            const state = ctl.stateLookups(
                row.pc,
                row.clock,
                row.branch_target,
                active,
            );
            const signed = row.opcode_blt_flag.add(row.opcode_bge_flag);
            const sign_shift = signed.mul(ops.q(128));
            const shifted_msls = ctl.rangePairRequest(
                active,
                row.rs1_msl_felt.add(sign_shift),
                row.rs2_msl_felt.add(sign_shift),
            );
            const prefix = row.diff_markers[0]
                .add(row.diff_markers[1])
                .add(row.diff_markers[2])
                .add(row.diff_markers[3]);
            const positive_difference = ctl.range20Request(
                prefix,
                row.diff_val.sub(S.one()),
            );
            result.* = .{ .batch_size = LOOKUP_BATCH_SIZE };
            appendLookup(result, 0, program_request.numerator, program_request.tuple.values());
            appendLookup(result, 1, state.consume.numerator, state.consume.tuple.values());
            appendLookup(result, 2, state.emit.numerator, state.emit.tuple.values());
            appendLookup(result, 3, source_1.consume.numerator, source_1.consume.tuple.values());
            appendLookup(result, 4, source_1.emit.numerator, source_1.emit.tuple.values());
            appendLookup(result, 5, source_1.clock_gap.numerator, source_1.clock_gap.tuple.values());
            appendLookup(result, 6, source_2.consume.numerator, source_2.consume.tuple.values());
            appendLookup(result, 7, source_2.emit.numerator, source_2.emit.tuple.values());
            appendLookup(result, 8, source_2.clock_gap.numerator, source_2.clock_gap.tuple.values());
            appendLookup(result, 9, shifted_msls.numerator, shifted_msls.tuple.values());
            appendLookup(result, 10, positive_difference.numerator, positive_difference.tuple.values());
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
                @compileError("typed BRANCH_LT fixed lookup append drifted");
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
    if (!isFamilyOpcode(row.opcode) or row.imm < -4096 or row.imm > 4094 or
        (@as(u32, @bitCast(row.imm)) & 1) != 0 or row.clk == 0 or
        row.pc & 3 != 0 or row.pc >= PC_BOUND or row.is_load or row.is_store or
        row.mem_addr != 0 or row.mem_val != 0 or row.mem_prev_word != 0 or
        row.mem_next_word != 0 or row.mem_prev_clk != 0)
    {
        return false;
    }
    const source_1_clock = accessClock(row.clk, 1) orelse return false;
    const source_2_clock = accessClock(row.clk, 2) orelse return false;
    if (!validGap(row.rs1_prev_clk, source_1_clock) or
        !validGap(row.rs2_prev_clk, source_2_clock) or
        (row.rs1 == 0 and row.rs1_val != 0) or
        (row.rs2 == 0 and row.rs2_val != 0) or
        (row.rs1 == row.rs2 and
            (row.rs1_val != row.rs2_val or row.rs2_prev_clk != source_1_clock)))
    {
        return false;
    }
    return acceptsRetirement(
        .{
            .opcode = row.opcode,
            .rd = row.rd,
            .rs1 = row.rs1,
            .rs2 = row.rs2,
            .imm = row.imm,
        },
        row.pc,
        row.rs1_val,
        row.rs2_val,
        row.next_pc,
        row.branch_taken,
    );
}

inline fn accessClock(clock: u32, phase: u32) ?u32 {
    if (clock == 0 or phase == 0 or phase > 2) return null;
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
    @setEvalBranchQuota(100_000);
    if (MAIN_COLUMN_COUNT != 37 or
        DIRECT_CONSTRAINT_COUNT != 33 or
        LOOKUP_COUNT != 11 or
        LOOKUP_BATCH_SIZE != 2)
    {
        @compileError("typed BRANCH_LT fixed authority geometry drifted");
    }
    for (CANONICAL_DIRECT_RECIPE, 0..) |recipe, index| {
        if (@intFromEnum(recipe) != index)
            @compileError("typed BRANCH_LT direct recipe is not canonical");
    }
    for (CANONICAL_LOOKUP_RECIPE, 0..) |lookup, index| {
        if (@intFromEnum(lookup.recipe) != index or
            lookup.arity != entry.expectedArity(lookup.domain))
        {
            @compileError("typed BRANCH_LT lookup recipe is not canonical");
        }
    }
    if (@sizeOf(Authority) > 512)
        @compileError("typed BRANCH_LT fixed authority exceeded its stack budget");
    const calculated_binding_digest = CANONICAL_BINDING.identityDigest();
    if (!std.mem.eql(
        u8,
        &calculated_binding_digest,
        &AUTHORITY_BINDING_DIGEST,
    )) @compileError("typed BRANCH_LT canonical authority digest drifted");
}
