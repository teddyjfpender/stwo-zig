//! Core test-only mutation of committed witness values before commitment.
//!
//! Five mutation shapes exist because they answer different questions, and the
//! stage each one is applied at is what makes the difference — not the shape of the edit.
//!
//! `.preprocessed` / `.main` add a delta to one cell of an otherwise honest row, applied
//! to the *duplicated* committed columns after every derived artefact already exists.
//! The adversary they model is incoherent on purpose: the question is only "does the
//! commitment bind this cell at all", and the answer is yes for any cell that any tree
//! reads. An additive delta cannot express a forgery whose soundness argument depends on
//! several columns agreeing — perturbing one limb also breaks the sibling relations the
//! forged row must still satisfy, so the row is rejected for an unrelated reason and the
//! test would still pass with the range check under scrutiny deleted. That is
//! coverage-shaped, not coverage.
//!
//! `.main_row` therefore assigns absolute values to several columns of one row in a
//! single pass, so a forged row can be self-consistent rather than a perturbation of the
//! honest one. The DIVU divisor forgery is the motivating case: limbs `[0, 0, 0, 256]`
//! compose to 2^32, which is 2 mod p, so the divisor's field value is 2 while its limbs
//! are non-bytes; `q = 0, r = 100` then satisfies the recurrence and only a byte range
//! check on the divisor limbs rejects the row. Building that row means setting the
//! divisor limbs, quotient, remainder and product carries coherently at once.
//!
//! ## Why `.main_row` is applied through `applyOpcodeWitness`, not `applyMain`
//!
//! A real malicious prover picks its witness and then derives *everything* from that
//! witness: the committed main trace, the lookup multiplicities, and the interaction
//! columns. Applying a row override to the committed duplicate alone simulates a prover
//! who forges tree 1 and then honestly derives tree 2 from the true witness. The two
//! trees then disagree, so the prover's own composition check refuses the row whatever
//! the AIR would have said, and no `.main_row` forgery can be attributed to the
//! constraint it names. `applyOpcodeWitness` therefore writes into the workspace opcode
//! buffers *before* `lookup_sources.ingest`, which is the single point all three
//! consumers read. `applyMain` keeps `.main` at its post-generation position and ignores
//! `.main_row`; applying a row override at both sites would apply it twice.
//!
//! `.interaction` perturbs one committed Tree-2 cell after the complete honest
//! interaction trace and claim have been derived, but before the claim is mixed
//! and Tree 2 is committed. It checks that cumulative LogUp columns -- including
//! their cross-row recurrence -- are constrained rather than merely present in
//! the commitment. Both Tree-2 executors expose this same test-only point; no
//! production call supplies a mutation.
//!
//! Ownership: a `RowOverride`'s `values` slice is borrowed for the duration of the apply
//! call and is never retained.
//!
//! The `legacy_*_authority` variants are not adversarial mutations. They are
//! serial A/B acceptance hooks for generated typed-witness cutovers: every
//! selected family component is cleared and independently regenerated with its
//! retired handwritten algorithm before lookup ingestion and commitment. The
//! resulting statement, transcript, and proof bytes must remain identical.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const statement_mod = @import("../air/statement.zig");
const infra = @import("../infra_trace.zig");
const trace = @import("../runner/trace.zig");
const legacy_lui = @import("../runner/witness/lui_legacy_test_oracle.zig");
const legacy_base_alu_imm =
    @import("../runner/witness/base_alu_imm_legacy_test_oracle.zig");
const legacy_base_alu_reg =
    @import("../runner/witness/base_alu_reg_legacy_test_oracle.zig");
const legacy_auipc = @import("../runner/witness/auipc_legacy_test_oracle.zig");
const legacy_branch_eq = @import("../runner/witness/branch_eq_legacy_test_oracle.zig");
const legacy_branch_lt = @import("../runner/witness/branch_lt_legacy_test_oracle.zig");
const legacy_jalr = @import("../runner/witness/jalr_legacy_test_oracle.zig");
const legacy_jal = @import("../runner/witness/jal_legacy_test_oracle.zig");
const legacy_fence = @import("../runner/witness/fence_legacy_test_oracle.zig");
const legacy_div = @import("../runner/witness/div_legacy_test_oracle.zig");
const legacy_load_store =
    @import("../runner/witness/load_store_legacy_test_oracle.zig");
const legacy_lt_imm = @import("../runner/witness/lt_imm_legacy_test_oracle.zig");
const legacy_lt_reg = @import("../runner/witness/lt_reg_legacy_test_oracle.zig");
const legacy_mul = @import("../runner/witness/mul_legacy_test_oracle.zig");
const legacy_mulh = @import("../runner/witness/mulh_legacy_test_oracle.zig");
const legacy_shifts_imm =
    @import("../runner/witness/shifts_imm_legacy_test_oracle.zig");
const legacy_shifts_reg =
    @import("../runner/witness/shifts_reg_legacy_test_oracle.zig");
const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");

pub const Target = union(enum) {
    opcode: struct {
        family: trace.OpcodeFamily,
        shard: u32 = 0,
    },
    infrastructure: struct {
        kind: statement_mod.InfraKind,
        occurrence: u32 = 0,
    },
};

pub const Cell = struct {
    target: Target,
    column: u32,
    logical_row: u32,
    delta: u32 = 1,
};

/// One absolute committed value. `value` is reduced into F_p rather than rejected, so a
/// caller may name a field element by any of its representatives.
pub const ColumnValue = struct {
    column: u32,
    value: u32,
};

/// Absolute values for several columns of one logical row of one component.
/// `values` is borrowed by the apply call.
pub const RowOverride = struct {
    target: Target,
    logical_row: u32,
    values: []const ColumnValue,
};

pub const Mutation = union(enum) {
    preprocessed: Cell,
    main: Cell,
    interaction: Cell,
    main_row: RowOverride,
    legacy_lui_authority,
    legacy_base_alu_imm_authority,
    legacy_base_alu_reg_authority,
    legacy_auipc_authority,
    legacy_branch_eq_authority,
    legacy_branch_lt_authority,
    legacy_jalr_authority,
    legacy_jal_authority,
    legacy_fence_authority,
    legacy_div_authority,
    legacy_load_store_authority,
    legacy_lt_imm_authority,
    legacy_lt_reg_authority,
    legacy_mul_authority,
    legacy_mulh_authority,
    legacy_shifts_imm_authority,
    legacy_shifts_reg_authority,
};

pub const Error = error{
    InvalidMutationTarget,
    InvalidMutationColumn,
    InvalidMutationRow,
    InvalidMutationDelta,
    InvalidTraceShape,
    EmptyMutationRowOverride,
    DuplicateMutationColumn,
};

const Location = struct {
    column_offset: usize,
    log_size: u32,
    n_rows: u32,
    n_columns: u32,
};

pub fn applyPreprocessed(
    allocator: std.mem.Allocator,
    statement: statement_mod.RiscVStatement,
    columns: []prover_pcs.ColumnEvaluation,
    mutation: Mutation,
) !void {
    const cell = switch (mutation) {
        .preprocessed => |value| value,
        .main,
        .interaction,
        .main_row,
        .legacy_lui_authority,
        .legacy_base_alu_imm_authority,
        .legacy_base_alu_reg_authority,
        .legacy_auipc_authority,
        .legacy_branch_eq_authority,
        .legacy_branch_lt_authority,
        .legacy_jalr_authority,
        .legacy_jal_authority,
        .legacy_fence_authority,
        .legacy_div_authority,
        .legacy_load_store_authority,
        .legacy_lt_imm_authority,
        .legacy_lt_reg_authority,
        .legacy_mul_authority,
        .legacy_mulh_authority,
        .legacy_shifts_imm_authority,
        .legacy_shifts_reg_authority,
        => return,
    };
    if (columns.len != statement.nPreprocessedColumns()) return Error.InvalidTraceShape;
    try mutate(allocator, columns, try locatePreprocessed(statement, cell.target), cell);
}

/// Single-cell tamper of the committed main columns, after every derived artefact
/// exists. `.main_row` is deliberately not handled here; see the module comment.
pub fn applyMain(
    allocator: std.mem.Allocator,
    statement: statement_mod.RiscVStatement,
    columns: []prover_pcs.ColumnEvaluation,
    mutation: Mutation,
) !void {
    const cell = switch (mutation) {
        .preprocessed,
        .interaction,
        .main_row,
        .legacy_lui_authority,
        .legacy_base_alu_imm_authority,
        .legacy_base_alu_reg_authority,
        .legacy_auipc_authority,
        .legacy_branch_eq_authority,
        .legacy_branch_lt_authority,
        .legacy_jalr_authority,
        .legacy_jal_authority,
        .legacy_fence_authority,
        .legacy_div_authority,
        .legacy_load_store_authority,
        .legacy_lt_imm_authority,
        .legacy_lt_reg_authority,
        .legacy_mul_authority,
        .legacy_mulh_authority,
        .legacy_shifts_imm_authority,
        .legacy_shifts_reg_authority,
        => return,
        .main => |value| value,
    };
    if (columns.len != statement.nMainColumns()) return Error.InvalidTraceShape;
    try mutate(allocator, columns, try locateMain(statement, cell.target), cell);
}

/// Single-cell tamper of the complete committed interaction trace, after its
/// honest cumulative columns and transcript-visible claims already exist.
pub fn applyInteraction(
    allocator: std.mem.Allocator,
    statement: statement_mod.RiscVStatement,
    columns: []prover_pcs.ColumnEvaluation,
    mutation: Mutation,
) !void {
    const cell = switch (mutation) {
        .preprocessed,
        .main,
        .main_row,
        .legacy_lui_authority,
        .legacy_base_alu_imm_authority,
        .legacy_base_alu_reg_authority,
        .legacy_auipc_authority,
        .legacy_branch_eq_authority,
        .legacy_branch_lt_authority,
        .legacy_jalr_authority,
        .legacy_jal_authority,
        .legacy_fence_authority,
        .legacy_div_authority,
        .legacy_load_store_authority,
        .legacy_lt_imm_authority,
        .legacy_lt_reg_authority,
        .legacy_mul_authority,
        .legacy_mulh_authority,
        .legacy_shifts_imm_authority,
        .legacy_shifts_reg_authority,
        => return,
        .interaction => |value| value,
    };
    if (columns.len != statement.nInteractionColumns()) return Error.InvalidTraceShape;
    try mutate(allocator, columns, try locateInteraction(statement, cell.target), cell);
}

/// Lets planned Tree 1 distinguish a Tree-2-only test mutation from a witness
/// mutation that would detach its retained lookup sources.
pub fn isInteraction(mutation: Mutation) bool {
    return switch (mutation) {
        .interaction => true,
        else => false,
    };
}

/// Applies a `.main_row` override to the generated opcode witness itself, so the
/// multiplicity counters, the interaction columns and the committed main trace are all
/// derived from the forged row rather than from two different witnesses.
///
/// `components` is the workspace array `main_trace.copyOpcodeColumns` later duplicates
/// into the committed prefix, indexed by statement component order.
///
/// Returns whether a row was forged. The caller needs that to decide the ingestion
/// policy for unrepresentable lookup requests: a forged row may ask a table for a tuple
/// the table does not contain, which the honest pipeline treats as a prover bug.
pub fn applyOpcodeWitness(
    allocator: std.mem.Allocator,
    statement: statement_mod.RiscVStatement,
    components: []trace.TraceColumns,
    mutation: Mutation,
) !bool {
    const override = switch (mutation) {
        .preprocessed,
        .main,
        .interaction,
        .legacy_lui_authority,
        .legacy_base_alu_imm_authority,
        .legacy_base_alu_reg_authority,
        .legacy_auipc_authority,
        .legacy_branch_eq_authority,
        .legacy_branch_lt_authority,
        .legacy_jalr_authority,
        .legacy_jal_authority,
        .legacy_fence_authority,
        .legacy_div_authority,
        .legacy_load_store_authority,
        .legacy_lt_imm_authority,
        .legacy_lt_reg_authority,
        .legacy_mul_authority,
        .legacy_mulh_authority,
        .legacy_shifts_imm_authority,
        .legacy_shifts_reg_authority,
        => return false,
        .main_row => |value| value,
    };
    // Infrastructure columns have no workspace buffer that every consumer reads, so an
    // infrastructure row override cannot be made coherent at this stage. Refusing beats
    // committing a forgery whose two trees disagree for a reason the test never names.
    const wanted = switch (override.target) {
        .opcode => |value| value,
        .infrastructure => return Error.InvalidMutationTarget,
    };
    const index = try opcodeComponentIndex(statement, wanted.family, wanted.shard);
    const desc = statement.component_descs[index];
    const component = &components[index];
    if (component.n_columns != desc.n_columns) return Error.InvalidTraceShape;
    try validateRowOverride(desc.n_rows, desc.n_columns, override);
    const domain = @as(usize, 1) << @intCast(desc.log_size);
    for (override.values) |value| {
        if (component.columns[value.column].len != domain) return Error.InvalidTraceShape;
    }

    const placement = try infra.BitReversalTable.init(allocator, desc.log_size);
    defer placement.deinit(allocator);
    const row = placement.map(override.logical_row);
    for (override.values) |value| {
        component.columns[value.column][row] = M31.fromU64(value.value);
    }
    return true;
}

const LegacyAuthority = enum {
    lui,
    base_alu_imm,
    base_alu_reg,
    auipc,
    branch_eq,
    branch_lt,
    jalr,
    jal,
    fence,
    div,
    load_store,
    lt_imm,
    lt_reg,
    mul,
    mulh,
    shifts_imm,
    shifts_reg,

    fn family(self: LegacyAuthority) trace.OpcodeFamily {
        return switch (self) {
            .lui => .lui,
            .base_alu_imm => .base_alu_imm,
            .base_alu_reg => .base_alu_reg,
            .auipc => .auipc,
            .branch_eq => .branch_eq,
            .branch_lt => .branch_lt,
            .jalr => .jalr,
            .jal => .jal,
            .fence => .fence,
            .div => .div,
            .load_store => .load_store,
            .lt_imm => .lt_imm,
            .lt_reg => .lt_reg,
            .mul => .mul,
            .mulh => .mulh,
            .shifts_imm => .shifts_imm,
            .shifts_reg => .shifts_reg,
        };
    }
};

/// Replace every active selected-family workspace row with its independent
/// retired writer.
///
/// All dimensions, active-row counts, execution-row counts, and bit-reversal
/// tables are validated before the first cell is cleared. Once mutation begins
/// no operation can fail, so a rejected invocation preserves the witness byte
/// for byte. This deliberately operates on final shard storage, at the same
/// boundary consumed by lookup ingestion, commitment, and interaction traces.
pub fn applyLegacyOpcodeAuthority(
    allocator: std.mem.Allocator,
    statement: statement_mod.RiscVStatement,
    components: []trace.TraceColumns,
    exec_trace: *const trace.Trace,
    mutation: Mutation,
) !bool {
    const authority: LegacyAuthority = switch (mutation) {
        .legacy_lui_authority => .lui,
        .legacy_base_alu_imm_authority => .base_alu_imm,
        .legacy_base_alu_reg_authority => .base_alu_reg,
        .legacy_auipc_authority => .auipc,
        .legacy_branch_eq_authority => .branch_eq,
        .legacy_branch_lt_authority => .branch_lt,
        .legacy_jalr_authority => .jalr,
        .legacy_jal_authority => .jal,
        .legacy_fence_authority => .fence,
        .legacy_div_authority => .div,
        .legacy_load_store_authority => .load_store,
        .legacy_lt_imm_authority => .lt_imm,
        .legacy_lt_reg_authority => .lt_reg,
        .legacy_mul_authority => .mul,
        .legacy_mulh_authority => .mulh,
        .legacy_shifts_imm_authority => .shifts_imm,
        .legacy_shifts_reg_authority => .shifts_reg,
        .preprocessed, .main, .interaction, .main_row => return false,
    };
    const family = authority.family();
    if (components.len < statement.n_components) return Error.InvalidTraceShape;

    var component_indices: [statement_mod.MAX_COMPONENTS]usize = undefined;
    var placements: [statement_mod.MAX_COMPONENTS]?infra.BitReversalTable =
        .{null} ** statement_mod.MAX_COMPONENTS;
    var n_family_components: usize = 0;
    var expected_rows: usize = 0;
    errdefer deinitLegacyPlacements(allocator, &placements, n_family_components);

    for (0..statement.n_components) |component_index| {
        const desc = statement.component_descs[component_index];
        if (desc.family != family) continue;
        const domain = @as(usize, 1) << @intCast(desc.log_size);
        const component = &components[component_index];
        if (desc.n_columns != trace.nColumnsForFamily(family) or
            component.n_columns != desc.n_columns or
            component.n_real_rows != desc.n_rows or
            desc.n_rows == 0 or
            desc.n_rows > domain)
        {
            return Error.InvalidTraceShape;
        }
        for (component.columns[0..component.n_columns]) |column| {
            if (column.len != domain) return Error.InvalidTraceShape;
        }
        expected_rows = std.math.add(usize, expected_rows, @intCast(desc.n_rows)) catch
            return Error.InvalidTraceShape;
        component_indices[n_family_components] = component_index;
        placements[n_family_components] = try infra.BitReversalTable.init(
            allocator,
            desc.log_size,
        );
        n_family_components += 1;
    }
    if (n_family_components == 0) return Error.InvalidMutationTarget;

    var observed_rows: usize = 0;
    for (exec_trace.rows.items) |row| {
        if (matchesLegacyAuthority(authority, row.opcode)) observed_rows += 1;
    }
    if (observed_rows != expected_rows) return Error.InvalidTraceShape;

    // No fallible operation occurs beyond this point.
    for (component_indices[0..n_family_components]) |component_index| {
        const component = &components[component_index];
        for (component.columns[0..component.n_columns]) |column| {
            @memset(column, M31.zero());
        }
    }

    var shard: usize = 0;
    var logical_row: usize = 0;
    for (exec_trace.rows.items) |row| {
        if (!matchesLegacyAuthority(authority, row.opcode)) continue;
        while (logical_row == statement.component_descs[component_indices[shard]].n_rows) {
            shard += 1;
            logical_row = 0;
        }
        const component_index = component_indices[shard];
        const physical_row = placements[shard].?.map(logical_row);
        writeLegacyAuthorityRow(
            authority,
            &components[component_index].columns,
            physical_row,
            row,
        );
        logical_row += 1;
    }
    deinitLegacyPlacements(allocator, &placements, n_family_components);
    return true;
}

/// Compatibility entry retained for the focused LUI hook tests.
pub fn applyLegacyLuiAuthority(
    allocator: std.mem.Allocator,
    statement: statement_mod.RiscVStatement,
    components: []trace.TraceColumns,
    exec_trace: *const trace.Trace,
    mutation: Mutation,
) !bool {
    return applyLegacyOpcodeAuthority(
        allocator,
        statement,
        components,
        exec_trace,
        mutation,
    );
}

fn matchesLegacyAuthority(authority: LegacyAuthority, opcode: anytype) bool {
    return switch (authority) {
        .lui => opcode == .LUI,
        .base_alu_imm => switch (opcode) {
            .ADDI, .XORI, .ORI, .ANDI => true,
            else => false,
        },
        .base_alu_reg => switch (opcode) {
            .ADD, .SUB, .XOR, .OR, .AND => true,
            else => false,
        },
        .auipc => opcode == .AUIPC,
        .branch_eq => opcode == .BEQ or opcode == .BNE,
        .branch_lt => switch (opcode) {
            .BLT, .BLTU, .BGE, .BGEU => true,
            else => false,
        },
        .jalr => opcode == .JALR,
        .jal => opcode == .JAL,
        .fence => opcode == .FENCE,
        .div => switch (opcode) {
            .DIV, .DIVU, .REM, .REMU => true,
            else => false,
        },
        .load_store => switch (opcode) {
            .LB, .LH, .LBU, .LHU, .LW, .SB, .SH, .SW => true,
            else => false,
        },
        .lt_imm => switch (opcode) {
            .SLTI, .SLTIU => true,
            else => false,
        },
        .lt_reg => switch (opcode) {
            .SLT, .SLTU => true,
            else => false,
        },
        .mul => opcode == .MUL,
        .mulh => switch (opcode) {
            .MULH, .MULHSU, .MULHU => true,
            else => false,
        },
        .shifts_imm => switch (opcode) {
            .SLLI, .SRLI, .SRAI => true,
            else => false,
        },
        .shifts_reg => switch (opcode) {
            .SLL, .SRL, .SRA => true,
            else => false,
        },
    };
}

inline fn writeLegacyAuthorityRow(
    authority: LegacyAuthority,
    columns: anytype,
    physical_row: usize,
    row: trace.TraceRow,
) void {
    switch (authority) {
        .lui => legacy_lui.writeRow(columns, physical_row, row),
        .base_alu_imm => legacy_base_alu_imm.writeRow(columns, physical_row, row),
        .base_alu_reg => legacy_base_alu_reg.writeRow(columns, physical_row, row),
        .auipc => legacy_auipc.writeRow(columns, physical_row, row),
        .branch_eq => legacy_branch_eq.writeRow(columns, physical_row, row),
        .branch_lt => legacy_branch_lt.writeRow(columns, physical_row, row),
        .jalr => legacy_jalr.writeRow(columns, physical_row, row),
        .jal => legacy_jal.writeRow(columns, physical_row, row),
        .fence => legacy_fence.writeRow(columns, physical_row, row),
        .div => legacy_div.writeRow(columns, physical_row, row),
        .load_store => legacy_load_store.writeRow(columns, physical_row, row),
        .lt_imm => legacy_lt_imm.writeRow(columns, physical_row, row),
        .lt_reg => legacy_lt_reg.writeRow(columns, physical_row, row),
        .mul => legacy_mul.writeRow(columns, physical_row, row),
        .mulh => legacy_mulh.writeRow(columns, physical_row, row),
        .shifts_imm => legacy_shifts_imm.writeRow(columns, physical_row, row),
        .shifts_reg => legacy_shifts_reg.writeRow(columns, physical_row, row),
    }
}

fn deinitLegacyPlacements(
    allocator: std.mem.Allocator,
    placements: *[statement_mod.MAX_COMPONENTS]?infra.BitReversalTable,
    initialized: usize,
) void {
    for (placements[0..initialized]) |*placement| {
        if (placement.*) |table| table.deinit(allocator);
        placement.* = null;
    }
}

fn mutate(
    allocator: std.mem.Allocator,
    columns: []prover_pcs.ColumnEvaluation,
    location: Location,
    cell: Cell,
) !void {
    if (cell.delta == 0) return Error.InvalidMutationDelta;
    if (cell.column >= location.n_columns) return Error.InvalidMutationColumn;
    if (cell.logical_row >= location.n_rows) return Error.InvalidMutationRow;
    if (location.column_offset > columns.len or
        location.n_columns > columns.len - location.column_offset)
    {
        return Error.InvalidTraceShape;
    }
    const column = &columns[location.column_offset + cell.column];
    if (column.log_size != location.log_size) return Error.InvalidTraceShape;
    if (location.log_size >= @bitSizeOf(usize) or
        column.values.len != @as(usize, 1) << @intCast(location.log_size))
    {
        return Error.InvalidTraceShape;
    }
    const placement = try infra.BitReversalTable.init(allocator, location.log_size);
    defer placement.deinit(allocator);
    const row = placement.map(cell.logical_row);
    const values = @constCast(column.values);
    values[row] = values[row].add(M31.fromU64(cell.delta));
}

/// Assign every requested cell of one logical row, or assign none of them.
///
/// The whole point of the primitive is that the resulting row is coherent, so a partially
/// applied override would produce a row whose rejection reason says nothing about the
/// constraint under test. Validation therefore completes before the first write.
fn validateRowOverride(n_rows: u32, n_columns: u32, override: RowOverride) Error!void {
    if (override.values.len == 0) return Error.EmptyMutationRowOverride;
    if (override.logical_row >= n_rows) return Error.InvalidMutationRow;
    for (override.values, 0..) |entry, index| {
        if (entry.column >= n_columns) return Error.InvalidMutationColumn;
        // Two entries for one cell mean the caller holds two intentions for it. Silently
        // letting the last one win would hide a broken forgery recipe, so reject instead.
        // The scan is quadratic in a list bounded by the component's column count.
        for (override.values[index + 1 ..]) |later| {
            if (later.column == entry.column) return Error.DuplicateMutationColumn;
        }
    }
}

fn locateMain(statement: statement_mod.RiscVStatement, target: Target) Error!Location {
    return switch (target) {
        .opcode => |wanted| locateOpcodeMain(statement, wanted.family, wanted.shard),
        .infrastructure => |wanted| locateInfraMain(statement, wanted.kind, wanted.occurrence),
    };
}

fn locateInteraction(statement: statement_mod.RiscVStatement, target: Target) Error!Location {
    return switch (target) {
        .opcode => |wanted| locateOpcodeInteraction(
            statement,
            wanted.family,
            wanted.shard,
        ),
        .infrastructure => |wanted| locateInfraInteraction(
            statement,
            wanted.kind,
            wanted.occurrence,
        ),
    };
}

/// Statement position of one shard of one family, which is also its position in the
/// workspace opcode-column array.
fn opcodeComponentIndex(
    statement: statement_mod.RiscVStatement,
    family: trace.OpcodeFamily,
    wanted_shard: u32,
) Error!usize {
    var shard: u32 = 0;
    for (0..statement.n_components) |index| {
        if (statement.component_descs[index].family != family) continue;
        if (shard == wanted_shard) return index;
        shard += 1;
    }
    return Error.InvalidMutationTarget;
}

fn locateOpcodeMain(
    statement: statement_mod.RiscVStatement,
    family: trace.OpcodeFamily,
    wanted_shard: u32,
) Error!Location {
    const wanted = try opcodeComponentIndex(statement, family, wanted_shard);
    var offset: usize = 0;
    for (0..wanted) |index| offset += statement.component_descs[index].n_columns;
    const desc = statement.component_descs[wanted];
    return .{
        .column_offset = offset,
        .log_size = desc.log_size,
        .n_rows = desc.n_rows,
        .n_columns = desc.n_columns,
    };
}

fn locateOpcodeInteraction(
    statement: statement_mod.RiscVStatement,
    family: trace.OpcodeFamily,
    wanted_shard: u32,
) Error!Location {
    const wanted = try opcodeComponentIndex(statement, family, wanted_shard);
    var offset: usize = 0;
    for (0..wanted) |index| {
        offset += opcode_interaction.nColumns(statement.component_descs[index].family);
    }
    const desc = statement.component_descs[wanted];
    return .{
        .column_offset = offset,
        .log_size = desc.log_size,
        .n_rows = desc.n_rows,
        .n_columns = @intCast(opcode_interaction.nColumns(desc.family)),
    };
}

fn locateInfraMain(
    statement: statement_mod.RiscVStatement,
    kind: statement_mod.InfraKind,
    wanted_occurrence: u32,
) Error!Location {
    var offset: usize = statement.nOpcodeMainColumns();
    var occurrence: u32 = 0;
    for (0..statement.n_infra) |index| {
        const desc = statement.infra_descs[index];
        if (desc.kind == kind) {
            if (occurrence == wanted_occurrence) return .{
                .column_offset = offset,
                .log_size = desc.log_size,
                .n_rows = desc.n_rows,
                .n_columns = desc.n_columns,
            };
            occurrence += 1;
        }
        offset += desc.n_columns;
    }
    return Error.InvalidMutationTarget;
}

fn locateInfraInteraction(
    statement: statement_mod.RiscVStatement,
    kind: statement_mod.InfraKind,
    wanted_occurrence: u32,
) Error!Location {
    var offset: usize = 0;
    for (0..statement.n_components) |index| {
        offset += opcode_interaction.nColumns(statement.component_descs[index].family);
    }
    var occurrence: u32 = 0;
    for (0..statement.n_infra) |index| {
        const desc = statement.infra_descs[index];
        const n_columns = statement_mod.nInteractionColsForInfra(desc.kind);
        if (desc.kind == kind) {
            if (occurrence == wanted_occurrence) return .{
                .column_offset = offset,
                .log_size = desc.log_size,
                .n_rows = desc.n_rows,
                .n_columns = n_columns,
            };
            occurrence += 1;
        }
        offset += n_columns;
    }
    return Error.InvalidMutationTarget;
}

fn locatePreprocessed(statement: statement_mod.RiscVStatement, target: Target) Error!Location {
    const wanted = switch (target) {
        .opcode => return Error.InvalidMutationTarget,
        .infrastructure => |value| value,
    };
    var occurrence: u32 = 0;
    for (0..statement.n_infra) |index| {
        const desc = statement.infra_descs[index];
        if (desc.kind == wanted.kind) {
            if (occurrence == wanted.occurrence) return .{
                .column_offset = statement.preprocessedOffsetForInfra(index),
                .log_size = desc.log_size,
                .n_rows = @intCast(@as(usize, 1) << @intCast(desc.log_size)),
                .n_columns = statement_mod.nPreprocessedColumnsForInfra(desc.kind),
            };
            occurrence += 1;
        }
    }
    return Error.InvalidMutationTarget;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const TEST_LOG_SIZE: u32 = 2;
const TEST_DOMAIN: usize = @as(usize, 1) << TEST_LOG_SIZE;
const TEST_N_ROWS: u32 = 3;
const TEST_N_COLUMNS: u32 = 3;
