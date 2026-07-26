//! Witness-rigidity audit over every committed RV32IM opcode column.
//!
//! The obligation this suite mechanises: a committed column the AIR does not
//! pin is a free prover choice. Three properties, all driven by real runner
//! traces over the committed ELF corpus and all decided by `row_admissibility`
//! — direct constraints AND preprocessed lookup membership, because several
//! bindings exist only as lookup requests. Column indices come from
//! `committed_row_layout`, which derives them from the committed layout structs
//! rather than repeating them here.
//!
//! 1. OBSERVABILITY. Perturbing a committed column of an honest row must move
//!    the constraint vector or some emitted relation tuple. Accumulated across
//!    the corpus: a column is observable if any honest row of any program makes
//!    it so.
//!
//! 2. SELECTOR RIGIDITY. Relabelling an honest row's opcode selector from A to
//!    B must be rejected whenever A and B disagree architecturally on that
//!    row's operands. The qualifier is decided by the runner's reference
//!    `execute` on a scratch machine carrying the row's own operands, not by an
//!    exception list: LB and LBU genuinely agree on a byte below 128, so
//!    acceptance there is not a soundness failure.
//!
//! 3. ACCESS DETERMINACY. Every committed access emits `previous` and `next` as
//!    two independent column groups onto the memory bus, and nothing in the
//!    global LogUp closure relates them. So `next` must be a function of the
//!    row's other committed columns: read-only accesses must reject any `next`
//!    away from `previous`, and the written access must reject any `next` away
//!    from the row's computed result. This is the property the branch's five
//!    AIR bugs all violated, and neither 1 nor 2 can see it — `previous` and
//!    `next` are each individually observable, and the selector is untouched.
//!
//! Bounds, honestly stated. `LOG_ROWS` rows are materialised per family per
//! program and at most `ROWS_PER_PROGRAM` honest rows are probed. Property 3
//! runs an exhaustive sweep over the byte domain of each `next` limb on the
//! first honest row of each family in each program, which decides determinacy
//! over that domain, and a `DELTAS` sweep on the remaining rows, which only
//! shows the probed perturbations move. Neither tier proves rigidity over all
//! of M31.
//!
//! Cost: 8.9 s wall for the four tests in a Debug build on an Apple M5 Max,
//! dominated by executing the 20-program corpus once per property. Raising
//! `ROWS_PER_PROGRAM` or making the byte sweep unconditional is what turns this
//! into a slow gate, so both are constants here.
//!
//! `DEAD_COLUMNS` records the one finding that is real but not a soundness
//! failure, with its cause, instead of deleting the check that reports it.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const layout = @import("committed_row_layout.zig");
const oracle = @import("row_admissibility.zig");
const opcode_memory = @import("../../frontends/riscv/air/opcode_memory.zig");
const runner = @import("../../frontends/riscv/runner/mod.zig");
const trace_mod = @import("../../frontends/riscv/runner/trace.zig");
const execute_mod = @import("../../frontends/riscv/runner/execute.zig");
const isa_decode = @import("../../frontends/riscv/isa/decode.zig");

const OpcodeFamily = trace_mod.OpcodeFamily;
const TraceRow = trace_mod.TraceRow;
const Opcode = isa_decode.Opcode;
const RowBuffer = [trace_mod.MAX_FAMILY_COLUMNS]QM31;

// ---------------------------------------------------------------------------
// Corpus and probe budget
// ---------------------------------------------------------------------------

/// Every committed RV32IM ELF the runner executes within `MAX_STEPS`. The three
/// vendored cryptographic guests are included deliberately: they are the only
/// programs in the tree that reach `auipc`, `jalr` with a non-`x0` destination,
/// or `mul` more than once. `crypto/ecdsa.elf` is excluded because it does not
/// terminate within `MAX_STEPS`.
const CORPUS = [_][]const u8{
    "vectors/riscv_elfs/shift_logic.elf",
    "vectors/riscv_elfs/mem_ls.elf",
    "vectors/riscv_elfs/mul_div.elf",
    "vectors/riscv_elfs/alu_test.elf",
    "vectors/riscv_elfs/branch_fib.elf",
    "vectors/riscv_elfs/jal_jalr.elf",
    "vectors/riscv_elfs/mulhu_only.elf",
    "vectors/riscv_elfs/memcpy_loop.elf",
    "vectors/riscv_elfs/bubble_sort.elf",
    "vectors/riscv_elfs/sieve_primes.elf",
    "vectors/riscv_elfs/gcd_euclid.elf",
    "vectors/riscv_elfs/collatz.elf",
    "vectors/riscv_elfs/xorshift_prng.elf",
    "vectors/riscv_elfs/fib_iter.elf",
    "vectors/riscv_elfs/fence.elf",
    "vectors/riscv_elfs/declared_region.elf",
    "vectors/riscv_elfs/multi_shard_addi.elf",
    "vectors/riscv_elfs/crypto/sha2_input.elf",
    "vectors/riscv_elfs/crypto/keccak_input.elf",
    "vectors/riscv_elfs/crypto/poseidon2_m31.elf",
};

/// The longest corpus program, `multi_shard_addi.elf`, runs 131 078 steps.
const MAX_STEPS: usize = 200_000;

/// Committed rows materialised per family per program. 2^10 covers every family
/// of every small program completely and samples the hot families.
const LOG_ROWS: u32 = 10;

/// Honest rows probed per family per program.
const ROWS_PER_PROGRAM: usize = 64;

/// Perturbations for the cheap probe tier. `1` and `2` leave any `{0, 1}`
/// encoding, `128` flips the sign bit of a byte limb, `255` leaves the byte
/// range. A column no delta moves is read by nothing.
const DELTAS = [_]u32{ 1, 2, 128, 255 };

/// Access limbs are byte limbs, so sweeping `0..256` decides determinacy over
/// their whole domain.
const BYTE_VALUES: u32 = 256;

/// Committed columns that are provably dead rather than unconstrained.
///
/// `semantics/common.accessChain` takes the bus address as an explicit
/// parameter and `load_store` passes the constrained `src_addr_selector` /
/// `dst_addr_selector` instead of the access block's own `addr` column, so
/// these two cells reach neither a constraint nor a tuple. Two wasted columns
/// in the widest hot family: a layout fix, not a soundness fix. The
/// observability test asserts they are still dead, so removing them (or
/// wiring them up) fails here and forces this note to be revisited.
const DEAD_COLUMNS = [_]struct { family: OpcodeFamily, column: usize }{
    .{ .family = .load_store, .column = 2 }, // dst_addr
    .{ .family = .load_store, .column = 22 }, // src_addr
};

fn isKnownDead(family: OpcodeFamily, column: usize) bool {
    for (DEAD_COLUMNS) |dead| {
        if (dead.family == family and dead.column == column) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Corpus access
// ---------------------------------------------------------------------------

/// One executed corpus program. `elf` is owned; `run` owns the trace.
const Program = struct {
    allocator: std.mem.Allocator,
    elf: []u8,
    run: runner.RunResult,

    fn load(allocator: std.mem.Allocator, path: []const u8) !Program {
        const elf = try std.fs.cwd().readFileAlloc(allocator, path, 16 << 20);
        errdefer allocator.free(elf);
        const run = try runner.runWithInput(allocator, elf, &.{}, MAX_STEPS);
        return .{ .allocator = allocator, .elf = elf, .run = run };
    }

    fn deinit(self: *Program) void {
        self.run.deinit();
        self.allocator.free(self.elf);
        self.* = undefined;
    }
};

/// Pairs each committed row with the trace row that produced it.
///
/// `Trace.columnsForFamily` fills family rows in execution order, so the k-th
/// real committed row is the k-th trace row of that family. The trace row
/// carries the architectural operands the reference semantics need; the
/// committed row carries the columns the AIR sees.
const FamilyRows = struct {
    rows: []const TraceRow,
    columns: *const trace_mod.TraceColumns,
    family: OpcodeFamily,
    cursor: usize = 0,
    emitted: usize = 0,

    /// Writes the next committed row into `out` and returns its trace row, or
    /// null once the materialised rows are exhausted. `out` is borrowed.
    fn next(self: *FamilyRows, out: []QM31) ?TraceRow {
        while (self.cursor < self.rows.len and self.emitted < self.columns.n_real_rows) {
            const row = self.rows[self.cursor];
            self.cursor += 1;
            const family = trace_mod.proofOpcodeFamily(row.opcode) catch continue;
            if (family != self.family) continue;
            for (out, self.columns.columns[0..self.columns.n_columns]) |*value, column| {
                value.* = QM31.fromBase(column[self.emitted]);
            }
            self.emitted += 1;
            return row;
        }
        return null;
    }
};

// ---------------------------------------------------------------------------
// Reference architectural effect
// ---------------------------------------------------------------------------

/// The architectural effect of one opcode on one trace row's operands.
const Effect = struct {
    rd: u32,
    pc: u32,
    word: u32,

    fn eql(self: Effect, other: Effect) bool {
        return self.rd == other.rd and self.pc == other.pc and self.word == other.word;
    }
};

/// Run the runner's reference `execute` for `opcode` on a three-register
/// scratch machine carrying this row's operands: `x1 = rs1_val`,
/// `x2 = rs2_val`, destination `x3`, `pc = row.pc`, and the row's memory word
/// resident at its aligned address. Routing the destination to `x3` keeps a
/// discarded `x0` write from making every relabelling look identical.
///
/// Returns null when the opcode is architecturally illegal on these operands —
/// a misaligned half or word access, say. The caller treats that as a
/// difference, because the AIR must still reject the relabelling.
fn referenceEffect(memory: *runner.Memory, row: TraceRow, opcode: Opcode) ?Effect {
    const aligned = row.mem_addr & ~@as(u32, 3);
    memory.writeU32(aligned, row.mem_prev_word);
    var cpu = runner.Cpu.init(row.pc, 0);
    cpu.regs[1] = row.rs1_val;
    cpu.regs[2] = row.rs2_val;
    execute_mod.execute(&cpu, memory, .{
        .opcode = opcode,
        .rd = 3,
        .rs1 = 1,
        .rs2 = 2,
        .imm = row.imm,
    }) catch return null;
    return .{ .rd = cpu.regs[3], .pc = cpu.pc, .word = memory.readU32(aligned) };
}

fn sameOperandRoles(lhs: Opcode, rhs: Opcode) bool {
    const a = isa_decode.operandUsage(lhs);
    const b = isa_decode.operandUsage(rhs);
    return a.reads_rs1 == b.reads_rs1 and
        a.reads_rs2 == b.reads_rs2 and
        a.writes_rd == b.writes_rd;
}

// ---------------------------------------------------------------------------
// Property 1: observability
// ---------------------------------------------------------------------------

test "witness rigidity: every committed column is observable somewhere" {
    const allocator = std.testing.allocator;

    var observable = [_][trace_mod.MAX_FAMILY_COLUMNS]bool{
        [_]bool{false} ** trace_mod.MAX_FAMILY_COLUMNS,
    } ** trace_mod.N_FAMILIES;
    var widths = [_]usize{0} ** trace_mod.N_FAMILIES;
    var probed = [_]usize{0} ** trace_mod.N_FAMILIES;
    var corpus_rows = [_]usize{0} ** trace_mod.N_FAMILIES;

    for (CORPUS) |path| {
        var program = try Program.load(allocator, path);
        defer program.deinit();
        const rows = program.run.execution_trace.rows.items;
        for (rows) |row| {
            const family = trace_mod.proofOpcodeFamily(row.opcode) catch continue;
            corpus_rows[@intFromEnum(family)] += 1;
        }

        for (0..trace_mod.N_FAMILIES) |family_index| {
            const family: OpcodeFamily = @enumFromInt(family_index);
            var columns = try program.run.execution_trace
                .columnsForFamily(allocator, family, LOG_ROWS);
            defer columns.deinit(allocator);
            if (columns.n_real_rows == 0) continue;
            widths[family_index] = columns.n_columns;

            var honest: RowBuffer = undefined;
            var probe: RowBuffer = undefined;
            var iterator = FamilyRows{ .rows = rows, .columns = &columns, .family = family };
            const view = honest[0..columns.n_columns];
            const probe_view = probe[0..columns.n_columns];
            var visited: usize = 0;
            while (iterator.next(view)) |trace_row| {
                if (visited == ROWS_PER_PROGRAM) break;
                // An honest row that the row-local oracle rejects is a witness
                // generator bug, not a row to skip.
                const accepted = try oracle.accepts(family, view);
                if (!accepted) {
                    std.debug.print(
                        "  HONEST REJECT path={s} family={s} pc=0x{x} rs1=0x{x} imm={d} next_pc=0x{x}\n",
                        .{
                            path,
                            @tagName(family),
                            trace_row.pc,
                            trace_row.rs1_val,
                            trace_row.imm,
                            trace_row.next_pc,
                        },
                    );
                }
                try std.testing.expect(accepted);
                visited += 1;
                probed[family_index] += 1;
                try markObservable(family, view, probe_view, &observable[family_index]);
            }
        }
    }

    std.debug.print("\n  family         cols  probed  corpus rows\n", .{});
    for (0..trace_mod.N_FAMILIES) |family_index| {
        std.debug.print("  {s: <14} {d: >4}  {d: >6}  {d: >11}\n", .{
            @tagName(@as(OpcodeFamily, @enumFromInt(family_index))),
            widths[family_index],
            probed[family_index],
            corpus_rows[family_index],
        });
    }

    var unobservable: usize = 0;
    for (0..trace_mod.N_FAMILIES) |family_index| {
        const family: OpcodeFamily = @enumFromInt(family_index);
        try std.testing.expect(probed[family_index] > 0);
        for (0..widths[family_index]) |column| {
            if (observable[family_index][column]) continue;
            if (isKnownDead(family, column)) continue;
            unobservable += 1;
            std.debug.print(
                "  UNOBSERVABLE family={s} column={d}\n",
                .{ @tagName(family), column },
            );
        }
    }
    // A dead column that becomes observable means the layout changed and the
    // exemption above must be re-derived rather than carried forward.
    for (DEAD_COLUMNS) |dead| {
        try std.testing.expect(!observable[@intFromEnum(dead.family)][dead.column]);
    }
    try std.testing.expectEqual(@as(usize, 0), unobservable);
}

/// Mark every column of `honest` that some delta makes visible, either by
/// breaking admissibility or by moving the emitted relation tuples. Columns
/// already marked by an earlier row are skipped: observability accumulates.
/// `probe` is borrowed scratch of the same width as `honest`.
fn markObservable(
    family: OpcodeFamily,
    honest: []const QM31,
    probe: []QM31,
    observable: *[trace_mod.MAX_FAMILY_COLUMNS]bool,
) !void {
    const base_entries = try oracle.fingerprint(family, honest);
    for (0..honest.len) |column| {
        if (observable[column]) continue;
        for (DELTAS) |delta| {
            @memcpy(probe, honest);
            probe[column] = probe[column].add(QM31.fromBase(M31.fromCanonical(delta)));
            if (!try oracle.accepts(family, probe) or
                try oracle.fingerprint(family, probe) != base_entries)
            {
                observable[column] = true;
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Property 2: selector rigidity
// ---------------------------------------------------------------------------

const Confusion = struct {
    family: OpcodeFamily,
    from: Opcode,
    to: Opcode,
};

/// Accumulates the relabelling verdicts across the whole corpus.
///
/// `settled` records ordered (from, to) pairs already probed on a row where the
/// two opcodes architecturally differ: one discriminating row establishes that
/// the AIR separates them, and further rows only cost time. `executed` records
/// which selectors the corpus runs at all, so an unreachable pair is not
/// reported as an undiscriminated one.
const SelectorAudit = struct {
    allocator: std.mem.Allocator,
    memory: *runner.Memory,
    confusions: std.ArrayList(Confusion) = .{},
    settled: [trace_mod.N_FAMILIES][layout.MAX_SELECTORS][layout.MAX_SELECTORS]bool =
        .{.{.{false} ** layout.MAX_SELECTORS} ** layout.MAX_SELECTORS} ** trace_mod.N_FAMILIES,
    executed: [trace_mod.N_FAMILIES][layout.MAX_SELECTORS]bool =
        .{.{false} ** layout.MAX_SELECTORS} ** trace_mod.N_FAMILIES,
    discriminating: usize = 0,
    identical: usize = 0,

    fn deinit(self: *SelectorAudit) void {
        self.confusions.deinit(self.allocator);
        self.* = undefined;
    }

    /// Relabel one honest row into every other selector of its family whose
    /// architectural effect on these operands differs, and record acceptance.
    /// `probe` is borrowed scratch of the same width as `honest`.
    fn probeRow(
        self: *SelectorAudit,
        family: OpcodeFamily,
        row: TraceRow,
        honest: []const QM31,
        probe: []QM31,
    ) !void {
        const family_index = @intFromEnum(family);
        const selectors = layout.SELECTORS[family_index];
        const from = selectors.indexOf(row.opcode) orelse
            return error.UnmappedOpcodeSelector;
        self.executed[family_index][from] = true;
        // Verify the selector table: the committed flags must agree with the
        // executed opcode, or every probe below is aimed at the wrong column.
        for (0..selectors.len) |index| {
            const expected = if (index == from) QM31.one() else QM31.zero();
            try std.testing.expect(honest[selectors.column(index)].eql(expected));
        }
        const honest_effect = referenceEffect(self.memory, row, row.opcode) orelse
            return error.HonestRowRejectedByReference;

        for (0..selectors.len) |to| {
            if (to == from or self.settled[family_index][from][to]) continue;
            const to_opcode = selectors.opcodes[to];
            // Relabelling across different operand roles would also have to
            // re-derive the operand columns, which is outside this
            // minimal-perturbation model.
            if (!sameOperandRoles(row.opcode, to_opcode)) continue;
            if (referenceEffect(self.memory, row, to_opcode)) |effect| {
                if (effect.eql(honest_effect)) {
                    self.identical += 1;
                    continue;
                }
            }

            @memcpy(probe, honest);
            probe[selectors.column(from)] = QM31.zero();
            probe[selectors.column(to)] = QM31.one();
            self.discriminating += 1;
            self.settled[family_index][from][to] = true;
            if (try oracle.accepts(family, probe)) {
                try self.confusions.append(self.allocator, .{
                    .family = family,
                    .from = row.opcode,
                    .to = to_opcode,
                });
            }
        }
    }

    /// Undiscriminated pairs are pairs the corpus executes but never separates:
    /// the two opcodes agreed architecturally on every operand pattern reached,
    /// so this suite says nothing about whether the AIR can tell them apart.
    /// Reported, not failed — the fix is a corpus program, not an AIR change.
    fn report(self: *const SelectorAudit) void {
        std.debug.print(
            "\n  selector relabellings: {d} discriminating, {d} architecturally identical\n",
            .{ self.discriminating, self.identical },
        );
        for (self.confusions.items) |item| {
            std.debug.print("  INDISTINGUISHABLE {s}: {s} -> {s}\n", .{
                @tagName(item.family), @tagName(item.from), @tagName(item.to),
            });
        }
        for (0..trace_mod.N_FAMILIES) |family_index| {
            const selectors = layout.SELECTORS[family_index];
            for (0..selectors.len) |from| {
                if (!self.executed[family_index][from]) continue;
                for (0..selectors.len) |to| {
                    if (to == from or self.settled[family_index][from][to]) continue;
                    if (!sameOperandRoles(selectors.opcodes[from], selectors.opcodes[to])) continue;
                    std.debug.print("  NO DISCRIMINATING ROW {s}: {s} -> {s}\n", .{
                        @tagName(@as(OpcodeFamily, @enumFromInt(family_index))),
                        @tagName(selectors.opcodes[from]),
                        @tagName(selectors.opcodes[to]),
                    });
                }
            }
        }
    }
};

test "witness rigidity: opcode selectors are not interchangeable" {
    const allocator = std.testing.allocator;
    var memory = runner.Memory.init(allocator);
    defer memory.deinit();
    var audit = SelectorAudit{ .allocator = allocator, .memory = &memory };
    defer audit.deinit();

    for (CORPUS) |path| {
        var program = try Program.load(allocator, path);
        defer program.deinit();
        const rows = program.run.execution_trace.rows.items;

        for (0..trace_mod.N_FAMILIES) |family_index| {
            const family: OpcodeFamily = @enumFromInt(family_index);
            if (layout.SELECTORS[family_index].len < 2) continue;
            var columns = try program.run.execution_trace
                .columnsForFamily(allocator, family, LOG_ROWS);
            defer columns.deinit(allocator);
            if (columns.n_real_rows == 0) continue;

            var honest: RowBuffer = undefined;
            var probe: RowBuffer = undefined;
            var iterator = FamilyRows{ .rows = rows, .columns = &columns, .family = family };
            const view = honest[0..columns.n_columns];
            const probe_view = probe[0..columns.n_columns];
            var visited: usize = 0;
            while (iterator.next(view)) |row| {
                if (visited == ROWS_PER_PROGRAM) break;
                // An honest row the row-local oracle rejects is a witness
                // generator bug, not a row to skip.
                try std.testing.expect(try oracle.accepts(family, view));
                visited += 1;
                try audit.probeRow(family, row, view, probe_view);
            }
        }
    }

    audit.report();
    try std.testing.expectEqual(@as(usize, 0), audit.confusions.items.len);
    try std.testing.expect(audit.discriminating > 0);
}

// ---------------------------------------------------------------------------
// Property 3: access determinacy
// ---------------------------------------------------------------------------

const Indeterminacy = struct {
    family: OpcodeFamily,
    slot: usize,
    written: bool,
    limb: usize,
    forged: u32,
    exhaustive: bool,
};

test "witness rigidity: every committed access emits a determined value" {
    const allocator = std.testing.allocator;
    var failures = std.ArrayList(Indeterminacy){};
    defer failures.deinit(allocator);
    var probed: usize = 0;
    var swept: usize = 0;

    for (CORPUS) |path| {
        var program = try Program.load(allocator, path);
        defer program.deinit();
        const rows = program.run.execution_trace.rows.items;

        for (0..trace_mod.N_FAMILIES) |family_index| {
            const family: OpcodeFamily = @enumFromInt(family_index);
            const n_accesses = opcode_memory.accessCount(family);
            if (n_accesses == 0) continue;
            var columns = try program.run.execution_trace
                .columnsForFamily(allocator, family, LOG_ROWS);
            defer columns.deinit(allocator);
            if (columns.n_real_rows == 0) continue;

            var honest: RowBuffer = undefined;
            var iterator = FamilyRows{ .rows = rows, .columns = &columns, .family = family };
            const view = honest[0..columns.n_columns];
            var visited: usize = 0;
            while (iterator.next(view)) |_| {
                if (visited == ROWS_PER_PROGRAM) break;
                // An honest row that the row-local oracle rejects is a witness
                // generator bug, not a row to skip.
                try std.testing.expect(try oracle.accepts(family, view));
                // The exhaustive byte sweep runs on the first honest row of
                // each family in each program; the rest get the delta probe.
                const exhaustive = visited == 0;
                visited += 1;
                probed += 1;
                if (exhaustive) swept += 1;

                for (0..n_accesses) |slot| {
                    try probeAccessNext(allocator, family, view, slot, exhaustive, &failures);
                }
            }
        }
    }

    std.debug.print(
        "\n  access determinacy: {d} honest rows probed, {d} exhaustively swept\n",
        .{ probed, swept },
    );
    for (failures.items) |item| {
        std.debug.print("  INDETERMINATE {s} slot {d} ({s}) next[{d}] accepts {d} ({s})\n", .{
            @tagName(item.family),
            item.slot,
            if (item.written) "written" else "read-only",
            item.limb,
            item.forged,
            if (item.exhaustive) "exhaustive" else "delta",
        });
    }
    try std.testing.expectEqual(@as(usize, 0), failures.items.len);
    try std.testing.expect(probed > 0);
}

/// Every alternative value of every `next` limb of one access must be
/// rejected: for a read-only slot because `next` must equal `previous`, for the
/// written slot because `next` must equal the row's computed result. Nothing in
/// the global LogUp closure relates the emitted `next` to the consumed
/// `previous`, so this has to hold row-locally.
fn probeAccessNext(
    allocator: std.mem.Allocator,
    family: OpcodeFamily,
    honest: []const QM31,
    slot: usize,
    exhaustive: bool,
    failures: *std.ArrayList(Indeterminacy),
) !void {
    var probe: RowBuffer = undefined;
    const view = probe[0..honest.len];

    for (0..4) |limb| {
        const column = layout.nextLimbColumn(family, slot, limb);
        // Access limbs are written as byte limbs, which is what makes the
        // exhaustive tier a complete determinacy argument over their domain.
        const canonical = (honest[column].tryIntoM31() catch
            return error.AccessLimbNotBaseField).v;
        if (canonical > 0xff) return error.AccessLimbNotAByte;

        const candidates: usize = if (exhaustive) BYTE_VALUES else DELTAS.len;
        for (0..candidates) |index| {
            const forged: u32 = if (exhaustive)
                @intCast(index)
            else
                (canonical + DELTAS[index]) % m31.Modulus;
            if (forged == canonical) continue;

            @memcpy(view, honest);
            view[column] = QM31.fromBase(M31.fromCanonical(forged));
            if (!try oracle.accepts(family, view)) continue;
            try failures.append(allocator, .{
                .family = family,
                .slot = slot,
                .written = layout.writtenSlot(family) == slot,
                .limb = limb,
                .forged = forged,
                .exhaustive = exhaustive,
            });
            // One accepted alternative already refutes determinacy for this
            // limb; the rest would only repeat the finding.
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Layout facts bound to the AIR
// ---------------------------------------------------------------------------

test "witness rigidity: probed access columns match the AIR layout map" {
    for (0..trace_mod.N_FAMILIES) |family_index| {
        const family: OpcodeFamily = @enumFromInt(family_index);
        const width = trace_mod.nColumnsForFamily(family);
        for (0..opcode_memory.accessCount(family)) |slot| {
            var columns = [_]QM31{QM31.zero()} ** trace_mod.MAX_FAMILY_COLUMNS;
            // Distinct sentinels so a transposed limb or group cannot pass.
            for (0..4) |limb| {
                const offset: u32 = @intCast(limb);
                columns[layout.previousLimbColumn(family, slot, limb)] =
                    QM31.fromBase(M31.fromCanonical(0x10 + offset));
                columns[layout.nextLimbColumn(family, slot, limb)] =
                    QM31.fromBase(M31.fromCanonical(0x40 + offset));
            }
            const access = try opcode_memory
                .accessFromMain(family, columns[0..width], slot, QM31.one());
            for (0..4) |limb| {
                const offset: u32 = @intCast(limb);
                try std.testing.expect(access.previous[limb]
                    .eql(QM31.fromBase(M31.fromCanonical(0x10 + offset))));
                try std.testing.expect(access.next[limb]
                    .eql(QM31.fromBase(M31.fromCanonical(0x40 + offset))));
            }
            try std.testing.expect(layout.nextLimbColumn(family, slot, 3) < width);
        }
    }
}
