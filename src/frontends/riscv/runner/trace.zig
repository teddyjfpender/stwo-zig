//! RISC-V execution capture and pinned Stark-V family trace generation.

const std = @import("std");
const decode = @import("decode.zig");
const opcode_manifest = @import("../opcode_manifest.zig");
const composition_manifest = @import("../air/lang/opcode_composition_manifest.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const typed_auipc_authority = @import("../air/lang/typed_auipc_authority.zig");
const typed_base_alu_imm_authority =
    @import("../air/lang/typed_base_alu_imm_authority.zig");
const typed_base_alu_imm_witness =
    @import("../air/lang/typed_base_alu_imm_witness.zig");
const typed_base_alu_reg_authority =
    @import("../air/lang/typed_base_alu_reg_authority.zig");
const typed_auipc_witness = @import("../air/lang/typed_auipc_witness.zig");
const typed_branch_eq_authority =
    @import("../air/lang/typed_branch_eq_authority.zig");
const typed_branch_lt_authority =
    @import("../air/lang/typed_branch_lt_authority.zig");
const typed_lui_witness = @import("../air/lang/typed_lui_witness.zig");
const typed_div_authority = @import("../air/lang/typed_div_authority.zig");
const typed_fence_authority = @import("../air/lang/typed_fence_authority.zig");
const typed_fence_witness = @import("../air/lang/typed_fence_witness.zig");
const typed_jal_authority = @import("../air/lang/typed_jal_authority.zig");
const typed_jalr_authority = @import("../air/lang/typed_jalr_authority.zig");
const typed_lt_imm_authority =
    @import("../air/lang/typed_lt_imm_authority.zig");
const typed_lt_reg_authority = @import("../air/lang/typed_lt_reg_authority.zig");
const typed_lui_authority = @import("../air/lang/typed_lui_authority.zig");
const typed_mul_authority = @import("../air/lang/typed_mul_authority.zig");
const typed_mulh_authority = @import("../air/lang/typed_mulh_authority.zig");
const typed_shifts_imm_authority = @import("../air/lang/typed_shifts_imm_authority.zig");
const typed_shifts_reg_authority = @import("../air/lang/typed_shifts_reg_authority.zig");
const typed_load_store_authority = @import("../air/lang/typed_load_store_authority.zig");
const BASE_ALU_REG_AUTHORITY = typed_base_alu_reg_authority.Authority.pinned();
const BRANCH_EQ_AUTHORITY = typed_branch_eq_authority.Authority.pinned();
const BRANCH_LT_AUTHORITY = typed_branch_lt_authority.Authority.pinned();
const LT_IMM_AUTHORITY = typed_lt_imm_authority.Authority.pinned();
const JAL_AUTHORITY = typed_jal_authority.Authority.pinned();
const JALR_AUTHORITY = typed_jalr_authority.Authority.pinned();
const LT_REG_AUTHORITY = typed_lt_reg_authority.Authority.pinned();
const SHIFTS_IMM_AUTHORITY = typed_shifts_imm_authority.Authority.pinned();
const SHIFTS_REG_AUTHORITY = typed_shifts_reg_authority.Authority.pinned();
const LOAD_STORE_AUTHORITY = typed_load_store_authority.Authority.pinned();
const MUL_AUTHORITY = typed_mul_authority.Authority.pinned();
const MULH_AUTHORITY = typed_mulh_authority.Authority.pinned();
const DIV_AUTHORITY = typed_div_authority.Authority.pinned();

const Opcode = decode.Opcode;

pub const TraceRow = @import("trace_row.zig").TraceRow;

pub const Trace = struct {
    rows: std.ArrayList(TraceRow),
    allocator: std.mem.Allocator,
    initial_pc: u32,
    final_pc: u32,
    step_count: usize,
    /// Global clock immediately before this trace range. One-shot traces start
    /// at zero; extracted continuation segments retain their non-zero origin.
    clock_origin: u32,
    /// Last globally retired instruction represented by either a core row or
    /// a transactionally recorded profile-extension row.
    last_retirement_clock: u32,
    /// Profile-extension retirements deliberately omitted from `rows` and
    /// owned by the corresponding extension trace that proving later binds.
    recorded_external_steps: usize,

    pub fn init(allocator: std.mem.Allocator) Trace {
        return .{
            .rows = .{},
            .allocator = allocator,
            .initial_pc = 0,
            .final_pc = 0,
            .step_count = 0,
            .clock_origin = 0,
            .last_retirement_clock = 0,
            .recorded_external_steps = 0,
        };
    }

    pub fn deinit(self: *Trace) void {
        self.rows.deinit(self.allocator);
        self.* = undefined;
    }

    /// Complete the only fallible work required by one later trace append.
    /// Capacity growth is not logical trace state, so a subsequent prepare
    /// failure can leave it in place without exposing a retired-row prefix.
    pub fn reserveOne(self: *Trace) error{OutOfMemory}!void {
        try self.rows.ensureUnusedCapacity(self.allocator, 1);
    }

    /// Bulk form used by admission and allocation/performance gates.
    pub fn reserveAdditional(
        self: *Trace,
        additional: usize,
    ) error{OutOfMemory}!void {
        try self.rows.ensureUnusedCapacity(self.allocator, additional);
    }

    /// Publish one row after `reserveOne` (or an equivalent bulk reserve).
    /// This operation cannot allocate or fail.
    pub fn appendAssumeCapacity(self: *Trace, row: TraceRow) void {
        std.debug.assert(self.expectsNextCoreRetirement(row.clk));
        self.rows.appendAssumeCapacity(row);
        self.step_count = self.rows.items.len;
        self.last_retirement_clock = row.clk;
    }

    pub fn append(self: *Trace, row: TraceRow) !void {
        if (!self.expectsNextCoreRetirement(row.clk))
            return error.InstructionClockMismatch;
        try self.reserveOne();
        self.appendAssumeCapacity(row);
    }

    /// A CUSTOM-0 retirement publishes outside the core trace. Preparation is
    /// fallible and happens before architectural mutation; `commit` below is
    /// deliberately infallible and validates the execute contract in Debug.
    pub const ExternalRetirementToken = struct {
        instruction_clock: u32,
        segment_external_origin: usize,
        call_count_before: usize,
        row_count_before: usize,
    };

    pub fn recordedExternalSteps(self: *const Trace) usize {
        return self.recorded_external_steps;
    }

    pub fn prepareRecordedExternalRetirement(
        self: *const Trace,
        instruction_clock: u32,
        segment_external_origin: usize,
        call_count: usize,
        row_count: usize,
    ) !ExternalRetirementToken {
        if (!self.expectsNextCoreRetirement(instruction_clock))
            return error.InstructionClockMismatch;
        if (!self.clockAuthorityIsValid())
            return error.ProfileClockAuthorityMismatch;
        if (call_count != row_count) return error.ProfileClockCountMismatch;
        const segment_external_steps = std.math.sub(
            usize,
            self.recorded_external_steps,
            segment_external_origin,
        ) catch return error.ProfileClockCountMismatch;
        if (segment_external_steps != call_count)
            return error.ProfileClockCountMismatch;
        return .{
            .instruction_clock = instruction_clock,
            .segment_external_origin = segment_external_origin,
            .call_count_before = call_count,
            .row_count_before = row_count,
        };
    }

    pub fn externalRetirementCommitIsValid(
        token: ExternalRetirementToken,
        call_count_after: usize,
        row_count_after: usize,
        call_clock: u32,
        row_clock: u32,
    ) bool {
        const expected_calls = std.math.add(
            usize,
            token.call_count_before,
            1,
        ) catch return false;
        const expected_rows = std.math.add(
            usize,
            token.row_count_before,
            1,
        ) catch return false;
        return call_count_after == expected_calls and
            row_count_after == expected_rows and
            call_clock == token.instruction_clock and
            row_clock == token.instruction_clock;
    }

    /// Revalidate a prepared token after every fallible reservation. This is
    /// deliberately allocation-free: a re-entrant allocator may advance the
    /// trace clock while capacity grows, and stale publication must be rejected
    /// before the architectural commit begins.
    pub fn externalRetirementTokenIsCurrent(
        self: *const Trace,
        token: ExternalRetirementToken,
        call_count: usize,
        row_count: usize,
    ) bool {
        if (!self.clockAuthorityIsValid() or
            !self.expectsNextCoreRetirement(token.instruction_clock) or
            call_count != token.call_count_before or
            row_count != token.row_count_before)
        {
            return false;
        }
        const segment_external_steps = std.math.sub(
            usize,
            self.recorded_external_steps,
            token.segment_external_origin,
        ) catch return false;
        return segment_external_steps == token.call_count_before;
    }

    pub fn commitRecordedExternalRetirement(
        self: *Trace,
        token: ExternalRetirementToken,
    ) void {
        std.debug.assert(self.expectsNextCoreRetirement(token.instruction_clock));
        std.debug.assert(self.recorded_external_steps -
            token.segment_external_origin == token.call_count_before);
        self.recorded_external_steps += 1;
        self.last_retirement_clock = token.instruction_clock;
        std.debug.assert(self.clockAuthorityIsValid());
    }

    /// Bind a copied segment range to its global entry clock and the exact
    /// number of extension rows retained beside it.
    pub fn bindExtractedClockRange(
        self: *Trace,
        clock_origin: u32,
        last_retirement_clock: u32,
        recorded_external_steps: usize,
    ) !void {
        if (!clockStateIsValid(
            clock_origin,
            self.rows.items.len,
            recorded_external_steps,
            last_retirement_clock,
        )) return error.ProfileClockAuthorityMismatch;
        self.clock_origin = clock_origin;
        self.last_retirement_clock = last_retirement_clock;
        self.recorded_external_steps = recorded_external_steps;
    }

    /// Central next-clock predicate for both generated and legacy retirement.
    /// The arithmetic identity makes a gap admissible only after an explicitly
    /// recorded extension retirement advanced this execution authority.
    pub fn expectsNextCoreRetirement(
        self: *const Trace,
        instruction_clock: u32,
    ) bool {
        if (self.step_count != self.rows.items.len or
            self.last_retirement_clock == std.math.maxInt(u32))
        {
            return false;
        }
        return instruction_clock == self.last_retirement_clock + 1;
    }

    pub fn validateClockAuthority(self: *const Trace) !void {
        if (self.step_count != self.rows.items.len or !self.clockAuthorityIsValid())
            return error.ProfileClockAuthorityMismatch;
    }

    pub fn validateClockRange(
        self: *const Trace,
        clock_origin: u32,
        last_retirement_clock: u32,
        recorded_external_steps: usize,
    ) !void {
        try self.validateClockAuthority();
        if (self.clock_origin != clock_origin or
            self.last_retirement_clock != last_retirement_clock or
            self.recorded_external_steps != recorded_external_steps)
        {
            return error.ProfileClockAuthorityMismatch;
        }
    }

    fn clockAuthorityIsValid(self: *const Trace) bool {
        return clockStateIsValid(
            self.clock_origin,
            self.rows.items.len,
            self.recorded_external_steps,
            self.last_retirement_clock,
        );
    }

    fn clockStateIsValid(
        origin: u32,
        core_steps: usize,
        external_steps: usize,
        last: u32,
    ) bool {
        const core_u32 = std.math.cast(u32, core_steps) orelse return false;
        const external_u32 = std.math.cast(u32, external_steps) orelse return false;
        const after_core = std.math.add(u32, origin, core_u32) catch return false;
        const expected = std.math.add(u32, after_core, external_u32) catch return false;
        return expected == last;
    }

    pub fn groupByOpcodeFamily(self: *const Trace, _: std.mem.Allocator) !OpcodeFamilyCounts {
        var counts = OpcodeFamilyCounts{};
        for (self.rows.items) |row| {
            counts.increment(opcodeFamily(try ProofOpcode.classify(row.opcode)));
        }
        return counts;
    }

    /// The filter, as a value every later stage can carry.
    ///
    /// `groupByOpcodeFamily` answers *how many* rows each family has and
    /// discards the classification it computed to find out; a stage that runs
    /// after it then has to reclassify, and until this returned a `ProofOpcode`
    /// the only cheap way to do that was a total map over raw `Opcode` whose
    /// precondition lived in a doc comment.
    ///
    /// The returned slice is index-parallel to `rows`. Holding it is the
    /// caller's proof that the filter ran: `opcodeFamily` accepts nothing else,
    /// so a stage that has one cannot reach an execution-only opcode, and a
    /// stage that does not have one cannot compile against the total map at
    /// all. Fails closed on the first row with no proof encoding, exactly as
    /// `groupByOpcodeFamily` does.
    pub fn proofOpcodes(self: *const Trace, allocator: std.mem.Allocator) ![]ProofOpcode {
        const result = try allocator.alloc(ProofOpcode, self.rows.items.len);
        errdefer allocator.free(result);
        for (self.rows.items, result) |row, *slot| {
            slot.* = try ProofOpcode.classify(row.opcode);
        }
        return result;
    }

    pub fn columnsForFamily(
        self: *const Trace,
        allocator: std.mem.Allocator,
        family: OpcodeFamily,
        log_size: u32,
    ) !TraceColumns {
        const size = @as(usize, 1) << @intCast(log_size);
        const count = nColumnsForFamily(family);
        var columns: [MAX_FAMILY_COLUMNS][]M31 = undefined;
        var initialized: usize = 0;
        errdefer for (columns[0..initialized]) |column| allocator.free(column);
        for (0..count) |column| {
            columns[column] = try allocator.alloc(M31, size);
            @memset(columns[column], M31.zero());
            initialized += 1;
        }
        var index: usize = 0;
        for (self.rows.items) |row| {
            if (opcodeFamily(try ProofOpcode.classify(row.opcode)) != family) continue;
            if (index == size) break;
            fillFamilyColumns(&columns, index, row, family);
            index += 1;
        }
        return .{ .columns = columns, .n_columns = count, .n_real_rows = index };
    }
};

/// Maximum committed opcode width, derived from the same typed authorities
/// that own composition geometry.  Keeping this as a compile-time constant
/// preserves fixed stack storage in every hot trace/prover consumer.
pub const MAX_FAMILY_COLUMNS: usize = composition_manifest.MAX_MAIN_COLUMNS;

pub const TraceColumns = struct {
    columns: [MAX_FAMILY_COLUMNS][]M31,
    n_columns: usize,
    n_real_rows: usize,

    pub fn deinit(self: *TraceColumns, allocator: std.mem.Allocator) void {
        for (self.columns[0..self.n_columns]) |column| allocator.free(column);
        self.* = undefined;
    }
};

pub fn nColumnsForFamily(family: OpcodeFamily) u32 {
    return @intCast(composition_manifest.mainColumnCount(family));
}

pub fn fillFamilyColumns(
    columns: *[MAX_FAMILY_COLUMNS][]M31,
    index: usize,
    row: TraceRow,
    family: OpcodeFamily,
) void {
    // Several authenticated writers deliberately unroll their fixed physical
    // recipes. Raising the compiler's analysis quota here keeps the total
    // family dispatch exhaustive without changing generated runtime code.
    @setEvalBranchQuota(100_000);
    switch (family) {
        .base_alu_reg => BASE_ALU_REG_AUTHORITY.writeActiveRow(columns, index, row),
        .base_alu_imm => typed_base_alu_imm_witness.writeActiveRow(columns, index, row),
        .shifts_reg => SHIFTS_REG_AUTHORITY.writeActiveRow(columns, index, row),
        .shifts_imm => SHIFTS_IMM_AUTHORITY.writeActiveRow(columns, index, row),
        .lt_reg => LT_REG_AUTHORITY.writeActiveRow(columns, index, row),
        .lt_imm => LT_IMM_AUTHORITY.writeActiveRow(columns, index, row),
        .branch_eq => BRANCH_EQ_AUTHORITY.writeActiveRow(columns, index, row),
        .branch_lt => BRANCH_LT_AUTHORITY.writeActiveRow(columns, index, row),
        .lui => typed_lui_witness.writeActiveRow(columns, index, row),
        .auipc => typed_auipc_witness.writeActiveRow(columns, index, row),
        .jalr => JALR_AUTHORITY.writeActiveRow(columns, index, row),
        .jal => JAL_AUTHORITY.writeActiveRow(columns, index, row),
        .load_store => LOAD_STORE_AUTHORITY.writeActiveRow(columns, index, row),
        .mul => MUL_AUTHORITY.writeActiveRow(columns, index, row),
        .mulh => MULH_AUTHORITY.writeActiveRow(columns, index, row),
        .div => DIV_AUTHORITY.writeActiveRow(columns, index, row),
        .fence => typed_fence_witness.writeActiveRow(columns, index, row),
    }
}

/// Validates an externally supplied retirement row against the same typed
/// authority that owns its witness projection. Production proving calls this
/// before entering `fillFamilyColumns`, whose infallible contract is reserved
/// for rows already admitted by an authority or constructed by trusted tests.
///
/// Every family validator currently reports only `InvalidTraceRow`; normalize
/// the wider executor error set here so callers cannot accidentally depend on
/// implementation-only geometry and alias errors from a single-row check.
pub const FamilyRowValidationError = error{InvalidTraceRow};

pub fn validateFamilyRow(
    row: TraceRow,
    family: OpcodeFamily,
) FamilyRowValidationError!void {
    @setEvalBranchQuota(100_000);
    switch (family) {
        .base_alu_reg => typed_base_alu_reg_authority.validateTraceRow(row) catch
            return error.InvalidTraceRow,
        .base_alu_imm => typed_base_alu_imm_authority.validateTraceRow(row) catch
            return error.InvalidTraceRow,
        .shifts_reg => typed_shifts_reg_authority.validateTraceRow(row) catch
            return error.InvalidTraceRow,
        .shifts_imm => typed_shifts_imm_authority.validateTraceRow(row) catch
            return error.InvalidTraceRow,
        .lt_reg => typed_lt_reg_authority.validateTraceRow(row) catch
            return error.InvalidTraceRow,
        .lt_imm => typed_lt_imm_authority.validateTraceRow(row) catch
            return error.InvalidTraceRow,
        .branch_eq => typed_branch_eq_authority.validateTraceRow(row) catch
            return error.InvalidTraceRow,
        .branch_lt => typed_branch_lt_authority.validateTraceRow(row) catch
            return error.InvalidTraceRow,
        .lui => typed_lui_authority.validateTraceRow(row) catch
            return error.InvalidTraceRow,
        .auipc => typed_auipc_authority.validateTraceRow(row) catch
            return error.InvalidTraceRow,
        .jalr => typed_jalr_authority.validateTraceRow(row) catch
            return error.InvalidTraceRow,
        .jal => typed_jal_authority.validateTraceRow(row) catch
            return error.InvalidTraceRow,
        .load_store => typed_load_store_authority.validateTraceRow(row) catch
            return error.InvalidTraceRow,
        .mul => typed_mul_authority.validateTraceRow(row) catch
            return error.InvalidTraceRow,
        .mulh => typed_mulh_authority.validateTraceRow(row) catch
            return error.InvalidTraceRow,
        .div => typed_div_authority.validateTraceRow(row) catch
            return error.InvalidTraceRow,
        .fence => typed_fence_authority.validateTraceRow(row) catch
            return error.InvalidTraceRow,
    }
}

pub const OpcodeFamily = opcode_manifest.Family;

pub const N_FAMILIES: usize = @typeInfo(OpcodeFamily).@"enum".fields.len;

/// An architectural opcode that has passed the proof filter.
///
/// The one field is an `opcode_manifest.Opcode`, the enum of opcodes the proof
/// system can represent. That enum has no ECALL and no EBREAK, so *every*
/// inhabitant of `ProofOpcode` -- however it is spelled, including a struct
/// literal -- names an opcode with a family. The filter is therefore not a
/// convention a caller can forget: it is the only total function from
/// `isa.Opcode` into this type, and it is fallible.
///
/// This replaces a precondition that lived in a doc comment. `opcodeFamily`
/// used to take a raw `Opcode` and resolve it with `catch unreachable`; nothing
/// enforced the "runs after the filter" claim, one of four call sites violated
/// it, and `unreachable` in ReleaseFast is undefined behaviour -- an
/// ECALL-terminated trace silently produced a garbage family that surfaced much
/// later as an unrelated-looking `error.InvalidRegisterAccessChain`. Making the
/// total map take a `ProofOpcode` turns "the filter has run" into a fact the
/// compiler checks: a pre-filter caller cannot obtain one without handling
/// `error.UnsupportedForProof`.
pub const ProofOpcode = struct {
    id: opcode_manifest.Opcode,

    /// The filter. The only route from an architectural opcode to a
    /// `ProofOpcode`, and the only fallible step in the pair.
    pub fn classify(opcode: Opcode) decode.ProofOpcodeError!ProofOpcode {
        return .{ .id = try decode.proofOpcode(opcode) };
    }

    /// Total on this type by construction.
    pub fn family(self: ProofOpcode) OpcodeFamily {
        return opcode_manifest.family(self.id);
    }
};

/// Fallible family map over raw architectural opcodes.
///
/// The only family map available to a caller that has not run the filter, and
/// the one every pre-filter caller must use.
pub fn proofOpcodeFamily(opcode: Opcode) decode.ProofOpcodeError!OpcodeFamily {
    return (try ProofOpcode.classify(opcode)).family();
}

/// Total family map over filtered opcodes.
///
/// Infallible with no run-time guard, because there is nothing left to guard:
/// the argument type cannot hold an opcode without a family. Callers that run
/// before the filter cannot call this at all -- they have no `ProofOpcode` --
/// which is the whole point of the newtype.
pub fn opcodeFamily(proof: ProofOpcode) OpcodeFamily {
    return proof.family();
}

pub const OpcodeFamilyCounts = struct {
    counts: [N_FAMILIES]usize = .{0} ** N_FAMILIES,

    pub fn increment(self: *OpcodeFamilyCounts, family: OpcodeFamily) void {
        self.counts[@intFromEnum(family)] += 1;
    }

    pub fn get(self: *const OpcodeFamilyCounts, family: OpcodeFamily) usize {
        return self.counts[@intFromEnum(family)];
    }

    pub fn total(self: *const OpcodeFamilyCounts) usize {
        var result: usize = 0;
        for (self.counts) |count| result += count;
        return result;
    }
};
