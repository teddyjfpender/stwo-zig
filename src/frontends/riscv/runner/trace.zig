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
const QM31 = @import("stwo_core").fields.qm31.QM31;
const semantics = @import("../air/semantics/mod.zig");
const base_alu_reg_test_oracle =
    @import("../air/semantics/base_alu_reg.zig").Semantics(QM31);
const jal_test_oracle =
    @import("../air/semantics/jal_legacy_test_oracle.zig").Semantics(QM31);
const jalr_test_oracle =
    @import("../air/semantics/jalr_legacy_test_oracle.zig").Semantics(QM31);
const branch_eq_test_oracle =
    @import("../air/semantics/branch_eq_legacy_test_oracle.zig").Semantics(QM31);
const branch_lt_test_oracle =
    @import("../air/semantics/branch_lt_legacy_test_oracle.zig").Semantics(QM31);
const lt_imm_test_oracle =
    @import("../air/semantics/lt_imm_legacy_test_oracle.zig").Semantics(QM31);
const lt_reg_test_oracle =
    @import("../air/semantics/lt_reg_legacy_test_oracle.zig").Semantics(QM31);
const shifts_imm_test_oracle =
    @import("../air/semantics/shifts_imm_legacy_test_oracle.zig").Semantics(QM31);
const shifts_reg_test_oracle =
    @import("../air/semantics/shifts_reg_legacy_test_oracle.zig").Semantics(QM31);
const load_store_test_oracle =
    @import("../air/semantics/load_store_legacy_test_oracle.zig").Semantics(QM31);
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

test "trace groups opcode families" {
    try std.testing.expectEqual(OpcodeFamily.base_alu_reg, try proofOpcodeFamily(.ADD));
    try std.testing.expectEqual(OpcodeFamily.shifts_imm, try proofOpcodeFamily(.SRAI));
    try std.testing.expectEqual(OpcodeFamily.branch_lt, try proofOpcodeFamily(.BGEU));
    try std.testing.expectEqual(OpcodeFamily.load_store, try proofOpcodeFamily(.SW));
    try std.testing.expectEqual(OpcodeFamily.div, try proofOpcodeFamily(.REMU));
    try std.testing.expectEqual(OpcodeFamily.fence, try proofOpcodeFamily(.FENCE));
    try std.testing.expectError(error.UnsupportedForProof, proofOpcodeFamily(.ECALL));
    try std.testing.expectError(error.UnsupportedForProof, proofOpcodeFamily(.EBREAK));
}

test "trace rejects execution-only opcodes before family witness generation" {
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    try trace.append(testRow(.ECALL));
    try std.testing.expectError(error.UnsupportedForProof, trace.groupByOpcodeFamily(std.testing.allocator));
    try std.testing.expectError(
        error.UnsupportedForProof,
        trace.columnsForFamily(std.testing.allocator, .base_alu_reg, 0),
    );
    try std.testing.expectError(
        error.UnsupportedForProof,
        trace.proofOpcodes(std.testing.allocator),
    );
}

test "trace hands out filtered opcodes index-parallel to its rows" {
    const allocator = std.testing.allocator;
    var trace = Trace.init(allocator);
    defer trace.deinit();
    var add = testRow(.ADD);
    add.clk = 1;
    var store = testRow(.SW);
    store.clk = 2;
    var fence = testRow(.FENCE);
    fence.clk = 3;
    try trace.append(add);
    try trace.append(store);
    try trace.append(fence);

    const filtered = try trace.proofOpcodes(allocator);
    defer allocator.free(filtered);
    try std.testing.expectEqual(trace.rows.items.len, filtered.len);
    try std.testing.expectEqual(OpcodeFamily.base_alu_reg, opcodeFamily(filtered[0]));
    try std.testing.expectEqual(OpcodeFamily.load_store, opcodeFamily(filtered[1]));
    try std.testing.expectEqual(OpcodeFamily.fence, opcodeFamily(filtered[2]));
}

test "the total family map is reachable only through the filter" {
    // The structural half of the fix, and the half a revert cannot survive.
    //
    // NOTE: this file's tests are compiled by no gate -- `src/frontends/riscv`
    // is its own Zig module and only its own `build.zig` `test` step reaches
    // them. The copy of this assertion that runs is in
    // `src/tests/riscv/opcode_family_precondition_test.zig`; keep the two in
    // step, and prefer adding obligations there.
    //
    // The defect was not that `opcodeFamily` mishandled ECALL -- it was that
    // `opcodeFamily` *accepted* ECALL's type at all, so "the filter has already
    // run" was a claim in prose that one of four call sites did not honour.
    // Restoring the raw-`Opcode` signature restores exactly that hazard, and
    // fails here at compile time rather than in whichever caller is next to
    // forget.
    const total = @typeInfo(@TypeOf(opcodeFamily)).@"fn";
    try std.testing.expectEqual(@as(usize, 1), total.params.len);
    try std.testing.expectEqual(ProofOpcode, total.params[0].type.?);
    // Total: no error union, so no caller is invited to decide what to do with
    // an opcode that has no family. There is no such value of this type.
    try std.testing.expectEqual(OpcodeFamily, total.return_type.?);

    // And the only constructor from a raw opcode is fallible, so the type
    // cannot be entered without discharging the admission question.
    const filter = @typeInfo(@TypeOf(ProofOpcode.classify)).@"fn";
    try std.testing.expectEqual(Opcode, filter.params[0].type.?);
    const returns = @typeInfo(filter.return_type.?);
    try std.testing.expect(returns == .error_union);
    try std.testing.expectEqual(ProofOpcode, returns.error_union.payload);

    // The filtered type is a newtype over the proof opcode set, not over the
    // architectural one: a `ProofOpcode` written as a struct literal still
    // cannot name ECALL, because `opcode_manifest.Opcode` has no such tag.
    const fields = @typeInfo(ProofOpcode).@"struct".fields;
    try std.testing.expectEqual(@as(usize, 1), fields.len);
    try std.testing.expectEqual(opcode_manifest.Opcode, fields[0].type);
    for (std.enums.values(opcode_manifest.Opcode)) |id| {
        // Total on every inhabitant; this loop is the totality proof.
        _ = opcodeFamily(.{ .id = id });
    }
}

fn testRow(opcode: Opcode) TraceRow {
    return .{
        .clk = 1,
        .pc = 100,
        .opcode = opcode,
        .rd = 1,
        .rs1 = 2,
        .rs2 = 3,
        .imm = 0,
        .rs1_val = 0,
        .rs2_val = 0,
        .rd_val = 0,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 104,
    };
}

fn filledRow(comptime n: usize, row: TraceRow, family: OpcodeFamily) [n]QM31 {
    var storage: [MAX_FAMILY_COLUMNS][1]M31 = .{.{M31.zero()}} ** MAX_FAMILY_COLUMNS;
    var columns: [MAX_FAMILY_COLUMNS][]M31 = undefined;
    for (&columns, &storage) |*column, *values| column.* = values;
    fillFamilyColumns(&columns, 0, row, family);
    var result: [n]QM31 = undefined;
    for (&result, columns[0..n]) |*value, column| value.* = QM31.fromBase(column[0]);
    return result;
}

test "witness rows satisfy base and shift semantic evaluators" {
    var row = testRow(.ADD);
    row.rs1_val = 1;
    row.rs2_val = 2;
    row.rd_val = 3;
    var base_reg_columns = filledRow(base_alu_reg_test_oracle.N_ORACLE_COLUMNS, row, .base_alu_reg);
    const base_reg = try base_alu_reg_test_oracle.Row.fromOracleColumns(&base_reg_columns);
    try std.testing.expect(base_alu_reg_test_oracle.evaluate(base_reg).allZero());

    row = testRow(.ADDI);
    row.imm = -1;
    row.rs1_val = 1;
    row.rd_val = 0;
    var base_imm_columns = filledRow(semantics.base_alu_imm.N_ORACLE_COLUMNS, row, .base_alu_imm);
    const base_imm = try semantics.base_alu_imm.Row.fromOracleColumns(&base_imm_columns);
    try std.testing.expect(semantics.base_alu_imm.evaluate(base_imm).allZero());

    row = testRow(.SLL);
    row.rs1_val = 1;
    row.rs2_val = 1;
    row.rd_val = 2;
    var shift_reg_columns = filledRow(shifts_reg_test_oracle.N_ORACLE_COLUMNS, row, .shifts_reg);
    const shift_reg = try shifts_reg_test_oracle.Row.fromOracleColumns(&shift_reg_columns);
    try std.testing.expect(shifts_reg_test_oracle.evaluate(shift_reg).allZero());

    row = testRow(.SRAI);
    row.imm = 1;
    row.rs1_val = 0x80000000;
    row.rd_val = 0xc0000000;
    var shift_imm_columns = filledRow(shifts_imm_test_oracle.N_ORACLE_COLUMNS, row, .shifts_imm);
    const shift_imm = try shifts_imm_test_oracle.Row.fromOracleColumns(&shift_imm_columns);
    try std.testing.expect(shifts_imm_test_oracle.evaluate(shift_imm).allZero());
}

test "witness rows satisfy comparison and branch semantic evaluators" {
    var row = testRow(.SLTU);
    row.rs1_val = 1;
    row.rs2_val = 2;
    row.rd_val = 1;
    var lt_reg_columns = filledRow(lt_reg_test_oracle.N_ORACLE_COLUMNS, row, .lt_reg);
    const lt_reg = try lt_reg_test_oracle.Row.fromOracleColumns(&lt_reg_columns);
    try std.testing.expect(lt_reg_test_oracle.evaluate(lt_reg).allZero());

    row = testRow(.SLTI);
    row.imm = 2;
    row.rs1_val = 1;
    row.rd_val = 1;
    var lt_imm_columns = filledRow(lt_imm_test_oracle.N_ORACLE_COLUMNS, row, .lt_imm);
    const lt_imm = try lt_imm_test_oracle.Row.fromOracleColumns(&lt_imm_columns);
    try std.testing.expect(lt_imm_test_oracle.evaluate(lt_imm).allZero());

    row = testRow(.BEQ);
    row.rs1_val = 7;
    row.rs2_val = 7;
    row.imm = 8;
    row.next_pc = 108;
    row.branch_taken = true;
    var branch_eq_columns = filledRow(branch_eq_test_oracle.N_MAIN_COLUMNS, row, .branch_eq);
    const branch_eq = try branch_eq_test_oracle.Row.fromMainColumns(&branch_eq_columns);
    try std.testing.expect(branch_eq_test_oracle.evaluate(branch_eq).allZero());

    row = testRow(.BLTU);
    row.rs1_val = 1;
    row.rs2_val = 2;
    row.imm = 8;
    row.next_pc = 108;
    row.branch_taken = true;
    var branch_lt_columns = filledRow(branch_lt_test_oracle.N_MAIN_COLUMNS, row, .branch_lt);
    const branch_lt = try branch_lt_test_oracle.Row.fromMainColumns(&branch_lt_columns);
    try std.testing.expect(branch_lt_test_oracle.evaluate(branch_lt).allZero());
}

test "witness rows satisfy upper jump and memory semantic evaluators" {
    const legacy_lui = @import("../air/semantics/lui_legacy_test_oracle.zig")
        .Semantics(QM31);
    const legacy_auipc = @import("../air/semantics/auipc_legacy_test_oracle.zig")
        .Semantics(QM31);
    var row = testRow(.LUI);
    row.imm = @bitCast(@as(u32, 0x12345000));
    row.rd_val = 0x12345000;
    var lui_columns = filledRow(legacy_lui.N_MAIN_COLUMNS, row, .lui);
    const lui = try legacy_lui.Row.fromMainColumns(&lui_columns);
    try std.testing.expect(legacy_lui.evaluate(lui).allZero());

    row = testRow(.AUIPC);
    // U-type immediates are 4096-aligned; the decoder can never emit 20.
    // The AIR now pins imm_limbs[0] == 0 (anti-aliasing), so the fixture must
    // use an architecturally reachable immediate.
    row.imm = @bitCast(@as(u32, 0x5000));
    row.rd_val = 100 + 0x5000;
    var auipc_columns = filledRow(legacy_auipc.N_MAIN_COLUMNS, row, .auipc);
    const auipc = try legacy_auipc.Row.fromMainColumns(&auipc_columns);
    try std.testing.expect(legacy_auipc.evaluate(auipc).allZero());

    row = testRow(.JAL);
    row.imm = 8;
    row.rd_val = 104;
    row.next_pc = 108;
    row.branch_taken = true;
    var jal_columns = filledRow(jal_test_oracle.N_MAIN_COLUMNS, row, .jal);
    const jal = try jal_test_oracle.Row.fromMainColumns(&jal_columns);
    try std.testing.expect(jal_test_oracle.evaluate(jal).allZero());

    row = testRow(.JALR);
    row.imm = 4;
    row.rs1_val = 101;
    row.rd_val = 104;
    row.next_pc = 104;
    var jalr_columns = filledRow(jalr_test_oracle.N_MAIN_COLUMNS, row, .jalr);
    const jalr = try jalr_test_oracle.Row.fromMainColumns(&jalr_columns);
    try std.testing.expect(jalr_test_oracle.evaluate(jalr).allZero());

    row = testRow(.LW);
    row.rd = 4;
    // I-type decode retains immediate[4:0] in `rs2`; the authority binds both
    // that metadata and every instruction bit to the committed program word.
    row.rs2 = 0;
    row.inst_word = 0x0001_2203; // LW x4, 0(x2)
    row.rs1_val = 100;
    row.rd_val = 0x04030201;
    row.mem_addr = 100;
    row.mem_val = row.rd_val;
    row.mem_prev_word = row.rd_val;
    row.mem_next_word = row.rd_val;
    row.is_load = true;
    var memory_columns = filledRow(load_store_test_oracle.N_ORACLE_COLUMNS, row, .load_store);
    const memory = try load_store_test_oracle.Row.fromOracleColumns(&memory_columns);
    try std.testing.expect(load_store_test_oracle.evaluate(memory).allZero());

    row = testRow(.LB);
    row.rd = 4;
    row.rs2 = 0;
    row.inst_word = 0x0001_0203; // LB x4, 0(x2)
    row.rs1_val = 101;
    row.rd_val = 0xffffff80;
    row.mem_addr = 101;
    row.mem_val = 0x80;
    row.mem_prev_word = 0x00008000;
    row.mem_next_word = 0x00008000;
    row.is_load = true;
    memory_columns = filledRow(load_store_test_oracle.N_ORACLE_COLUMNS, row, .load_store);
    const byte_load = try load_store_test_oracle.Row.fromOracleColumns(&memory_columns);
    try std.testing.expect(load_store_test_oracle.evaluate(byte_load).allZero());

    row = testRow(.SH);
    // S-type decode retains immediate[4:0] in `rd`.
    row.rd = 0;
    row.inst_word = 0x0031_1023; // SH x3, 0(x2)
    row.rs1_val = 102;
    row.rs2_val = 0xbeef;
    row.mem_addr = 102;
    row.mem_val = 0xbeef;
    row.mem_prev_word = 0;
    row.mem_next_word = 0xbeef0000;
    row.is_store = true;
    memory_columns = filledRow(load_store_test_oracle.N_ORACLE_COLUMNS, row, .load_store);
    const half_store = try load_store_test_oracle.Row.fromOracleColumns(&memory_columns);
    try std.testing.expect(load_store_test_oracle.evaluate(half_store).allZero());
}

test "padding rows remain inactive for flag and explicit-enabler families" {
    const zero = [_]QM31{QM31.zero()} ** base_alu_reg_test_oracle.N_ORACLE_COLUMNS;
    const base = try base_alu_reg_test_oracle.Row.fromOracleColumns(&zero);
    try std.testing.expect(base.active().isZero());
    try std.testing.expect(base_alu_reg_test_oracle.evaluate(base).allZero());

    const control_zero = [_]QM31{QM31.zero()} ** jal_test_oracle.N_MAIN_COLUMNS;
    const control = try jal_test_oracle.Row.fromMainColumns(&control_zero);
    try std.testing.expect(control.enabler.isZero());
    try std.testing.expect(jal_test_oracle.evaluate(control).allZero());
}
