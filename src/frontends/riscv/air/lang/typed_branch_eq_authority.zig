//! Fixed executable authority for RV32 BEQ/BNE.
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
const typed = @import("typed_branch_eq.zig");
const witness = @import("typed_branch_eq_witness.zig");

pub const MAIN_COLUMN_COUNT: usize = typed.MAIN_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = typed.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = typed.LOOKUP_COUNT;
pub const LOOKUP_BATCH_SIZE: usize = typed.LOOKUP_BATCH_SIZE;
pub const OPCODE_IDS = [2]u32{ typed.BEQ_OPCODE_ID, typed.BNE_OPCODE_ID };
pub const PC_BOUND: u32 = @as(u32, 1) << 30;

pub const DecodedInst = decode.DecodedInst;
pub const TraceRow = trace_row.TraceRow;

pub const AUTHORITY_BINDING_FORMAT_VERSION: u16 = 1;
pub const AUTHORITY_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/branch-eq-fixed-authority/v1";

// Updated only through the binding-identity admission test. Keeping a literal
// receipt makes execution, root, lookup-order, or witness-geometry drift an
// explicit protocol review.
pub const AUTHORITY_BINDING_DIGEST_HEX =
    "afa781f9d1a02f5906706554bcc694f39658998470b6da79ee85717e4b0232f4";
pub const AUTHORITY_BINDING_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, AUTHORITY_BINDING_DIGEST_HEX) catch
        @compileError("invalid typed BRANCH_EQ authority-binding digest");
    break :blk result;
};

pub const ExecutionRecipe = enum(u8) {
    compare_sources_select_aligned_pc = 0,
};

pub const DirectRecipe = enum(u8) {
    active_bit = 0,
    beq_bit = 1,
    bne_bit = 2,
    comparison_bit = 3,
    equality_limb_0 = 4,
    equality_limb_1 = 5,
    equality_limb_2 = 6,
    equality_limb_3 = 7,
    inequality_inverse = 8,
    source_1_read_only_0 = 9,
    source_1_read_only_1 = 10,
    source_1_read_only_2 = 11,
    source_1_read_only_3 = 12,
    source_2_read_only_0 = 13,
    source_2_read_only_1 = 14,
    source_2_read_only_2 = 15,
    source_2_read_only_3 = 16,
    active_placement = 17,
};

pub const CANONICAL_DIRECT_RECIPE = [DIRECT_CONSTRAINT_COUNT]DirectRecipe{
    .active_bit,
    .beq_bit,
    .bne_bit,
    .comparison_bit,
    .equality_limb_0,
    .equality_limb_1,
    .equality_limb_2,
    .equality_limb_3,
    .inequality_inverse,
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
    source_1_consume = 1,
    source_1_emit = 2,
    source_1_clock_gap = 3,
    source_2_consume = 4,
    source_2_emit = 5,
    source_2_clock_gap = 6,
    state_consume = 7,
    state_emit = 8,
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
    .{ .recipe = .source_1_consume, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 1 },
    .{ .recipe = .source_1_emit, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 1 },
    .{ .recipe = .source_1_clock_gap, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 1 },
    .{ .recipe = .source_2_consume, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 2 },
    .{ .recipe = .source_2_emit, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 2 },
    .{ .recipe = .source_2_clock_gap, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 2 },
    .{ .recipe = .state_consume, .domain = .registers_state, .role = .consume, .arity = 2, .access_ordinal = null },
    .{ .recipe = .state_emit, .domain = .registers_state, .role = .emit, .arity = 2, .access_ordinal = null },
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
    .semantic_format_version = digest.program_control_target_format_version,
    .opcode_ids = OPCODE_IDS,
    .semantic_digest = typed.SEMANTIC_DIGEST,
    .witness_binding_digest = witness.WITNESS_BINDING_DIGEST,
    .main_column_count = MAIN_COLUMN_COUNT,
    .execution = .compare_sources_select_aligned_pc,
    .direct = CANONICAL_DIRECT_RECIPE,
    .lookups = CANONICAL_LOOKUP_RECIPE,
    .lookup_batch_size = LOOKUP_BATCH_SIZE,
};

comptime {
    @setEvalBranchQuota(20_000);
    if (!std.mem.eql(
        u8,
        &CANONICAL_BINDING.identityDigest(),
        &AUTHORITY_BINDING_DIGEST,
    )) {
        @compileError("typed BRANCH_EQ authority binding receipt drifted");
    }
}

pub const ConstructionError = witness.ConstructionError || error{InvalidAuthorityBinding};
pub const ExecutionError = error{
    WrongBranchEqOpcode,
    InvalidImmediate,
    InvalidProgramCounter,
    InstructionAddressMisaligned,
    TargetOutOfRange,
};

pub const Retirement = struct {
    source_1_value: u32,
    source_2_value: u32,
    equal: bool,
    taken: bool,
    next_pc: u32,
    branch_taken: bool,
};

pub inline fn isFamilyOpcode(opcode: decode.Opcode) bool {
    return opcode == .BEQ or opcode == .BNE;
}

pub inline fn branchCondition(
    opcode: decode.Opcode,
    source_1: u32,
    source_2: u32,
) bool {
    return switch (opcode) {
        .BEQ => source_1 == source_2,
        .BNE => source_1 != source_2,
        else => unreachable,
    };
}

inline fn canonicalRetirement(
    instruction: DecodedInst,
    pc: u32,
    source_1: u32,
    source_2: u32,
) ExecutionError!Retirement {
    if (!isFamilyOpcode(instruction.opcode)) return error.WrongBranchEqOpcode;
    if (instruction.imm < -4096 or instruction.imm > 4094 or
        (@as(u32, @bitCast(instruction.imm)) & 1) != 0)
    {
        return error.InvalidImmediate;
    }
    if (pc >= PC_BOUND) return error.InvalidProgramCounter;
    if (pc & 3 != 0) return error.InstructionAddressMisaligned;
    const equal = source_1 == source_2;
    const taken = if (instruction.opcode == .BEQ) equal else !equal;
    const next_pc = if (taken)
        pc +% @as(u32, @bitCast(instruction.imm))
    else
        pc +% 4;
    if (next_pc >= PC_BOUND) return error.TargetOutOfRange;
    if (next_pc & 3 != 0) return error.InstructionAddressMisaligned;
    return .{
        .source_1_value = source_1,
        .source_2_value = source_2,
        .equal = equal,
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
            imm_felt: S,
            cmp_result: S,
            diff_inv_markers: [4]S,
            opcode_beq_flag: S,
            opcode_bne_flag: S,

            pub inline fn fromMainColumns(columns: []const S) !Row {
                if (columns.len != MAIN_COLUMN_COUNT)
                    return error.InvalidMainTraceShape;
                return .{
                    .clock = columns[0],
                    .pc = columns[1],
                    .rs1 = ctl.accessFromColumns(columns, 2),
                    .rs2 = ctl.accessFromColumns(columns, 12),
                    .imm_felt = columns[22],
                    .cmp_result = columns[23],
                    .diff_inv_markers = columns[24..28].*,
                    .opcode_beq_flag = columns[28],
                    .opcode_bne_flag = columns[29],
                };
            }

            pub inline fn active(self: Row) S {
                return self.opcode_beq_flag.add(self.opcode_bne_flag);
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
            out[index] = ops.bit(row.opcode_beq_flag);
            index += 1;
            out[index] = ops.bit(row.opcode_bne_flag);
            index += 1;
            out[index] = ops.bit(row.cmp_result);
            index += 1;

            const cmp_eq = row.cmp_result.mul(row.opcode_beq_flag)
                .add(S.one().sub(row.cmp_result).mul(row.opcode_bne_flag));
            inline for (0..4) |limb| {
                out[index] = cmp_eq.mul(row.rs1.next[limb].sub(row.rs2.next[limb]));
                index += 1;
            }
            var diff_inv_sum = cmp_eq;
            inline for (0..4) |limb| {
                diff_inv_sum = diff_inv_sum.add(
                    row.rs1.next[limb]
                        .sub(row.rs2.next[limb])
                        .mul(row.diff_inv_markers[limb]),
                );
            }
            out[index] = active.mul(S.one().sub(diff_inv_sum));
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

        pub inline fn lookupsInto(columns: []const S, result: *e.List) !void {
            lookupsRowInto(try Row.fromMainColumns(columns), result);
        }

        inline fn lookupsRowInto(row: Row, result: *e.List) void {
            const active = row.active();
            const opcode_id = row.opcode_beq_flag.mul(ops.q(OPCODE_IDS[0]))
                .add(row.opcode_bne_flag.mul(ops.q(OPCODE_IDS[1])));
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
            const next_pc = row.pc
                .add(row.imm_felt.mul(row.cmp_result))
                .add(ops.q(4).mul(S.one().sub(row.cmp_result)));
            const state = ctl.stateLookups(row.pc, row.clock, next_pc, active);
            result.* = .{ .batch_size = LOOKUP_BATCH_SIZE };
            e.program(result, program_request.numerator, program_request.tuple);
            e.accessAt(result, source_1, 1);
            e.accessAt(result, source_2, 2);
            e.stateRequests(result, state);
            std.debug.assert(result.len == LOOKUP_COUNT);
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
