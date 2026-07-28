//! Witness-rigidity audit over every committed RV32IM opcode column.
//!
//! The obligation this suite mechanises: a committed column the AIR does not
//! pin is a free prover choice. Three properties, all driven by real runner
//! traces over the committed ELF corpus and all decided by `row_admissibility`
//! — direct constraints AND preprocessed lookup membership, because several
//! bindings exist only as lookup requests. Column indices come from
//! `committed_row_layout`, which derives them from the committed layout structs
//! rather than repeating them here. The honest rows, the profile that bounds
//! them and the evaluation budget that prices them come from `rigidity_corpus`.
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
//! Bounds, honestly stated. Rows swept exhaustively over the byte domain of
//! each `next` limb decide determinacy over that domain; every other probe is
//! a `DELTAS` sweep, which only shows the probed perturbations move. Neither
//! tier proves rigidity over all of M31, and neither profile probes every
//! honest row of the corpus.
//!
//! Cost, measured in a Debug build on an 18-core Apple M5 Max, warm cache:
//! 0.4 s wall / 1.8 s CPU for the four tests under the default `fast` profile
//! and 0.5 s / 3.1 s under `exhaustive`, against 8.7 s / 7.9 s for the
//! single-threaded prefix sweep these profiles replaced. Each property prints
//! the admissibility evaluations it actually spent next to its ceiling, so a
//! probe that starts costing more says so instead of quietly slowing the gate.
//! `zig build test-riscv-rigidity` runs the exhaustive profile on its own.
//!
//! `DEAD_COLUMNS` records the one finding that is real but not a soundness
//! failure, with its cause, instead of deleting the check that reports it.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const corpus_mod = @import("rigidity_corpus.zig");
const layout = @import("committed_row_layout.zig");
const opcode_memory = @import("stwo_riscv_frontend").air.opcode_memory;
const runner = @import("stwo_riscv_frontend").runner;
const trace_mod = @import("stwo_riscv_frontend").runner.trace;
const execute_mod = @import("stwo_riscv_frontend").runner.execute_mod;
const isa_decode = @import("stwo_riscv_frontend").isa.decode;

const Budget = corpus_mod.Budget;
const OpcodeFamily = trace_mod.OpcodeFamily;
const Opcode = isa_decode.Opcode;
const PROFILE = corpus_mod.PROFILE;
const Sample = corpus_mod.Sample;
const TraceRow = trace_mod.TraceRow;
const RowBuffer = [trace_mod.MAX_FAMILY_COLUMNS]QM31;

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
    const corpus = try corpus_mod.shared();
    var budget = Budget{ .label = "observability", .cap = PROFILE.observability_budget };

    var observable = [_][trace_mod.MAX_FAMILY_COLUMNS]bool{
        [_]bool{false} ** trace_mod.MAX_FAMILY_COLUMNS,
    } ** trace_mod.N_FAMILIES;

    // Sequential and in corpus order: observability accumulates, so which rows
    // do work depends on which columns earlier rows already marked, and only a
    // fixed traversal makes the realised evaluation count reproducible.
    var probe: RowBuffer = undefined;
    for (corpus.samples) |*sample| {
        const family_index = @intFromEnum(sample.family);
        if (settledObservable(&observable[family_index], sample.family, sample.width)) continue;
        try markObservable(
            &budget,
            sample,
            probe[0..sample.width],
            &observable[family_index],
        );
    }

    corpus.report();
    budget.report();

    var unobservable: usize = 0;
    for (corpus.stats, 0..) |stat, family_index| {
        const family: OpcodeFamily = @enumFromInt(family_index);
        try std.testing.expect(stat.sampled > 0);
        for (0..stat.width) |column| {
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

/// True once every column of the family that this suite can mark is marked, so
/// no later row of it can do anything but re-confirm. Skipping there is what
/// keeps the cost proportional to the AIR rather than to the corpus.
fn settledObservable(
    observable: *const [trace_mod.MAX_FAMILY_COLUMNS]bool,
    family: OpcodeFamily,
    width: usize,
) bool {
    for (0..width) |column| {
        if (!observable[column] and !isKnownDead(family, column)) return false;
    }
    return true;
}

/// Mark every column of `sample` that some delta makes visible, either by
/// breaking admissibility or by moving the emitted relation tuples. Columns
/// already marked by an earlier row are skipped: observability accumulates.
/// `probe` is borrowed scratch of the same width as the sample.
fn markObservable(
    budget: *Budget,
    sample: *const Sample,
    probe: []QM31,
    observable: *[trace_mod.MAX_FAMILY_COLUMNS]bool,
) !void {
    const honest = sample.view();
    // One honest fingerprint for the whole row rather than one per delta.
    const base_entries = try budget.fingerprint(sample.family, honest);
    for (0..honest.len) |column| {
        if (observable[column]) continue;
        for (DELTAS) |delta| {
            @memcpy(probe, honest);
            probe[column] = probe[column].add(QM31.fromBase(M31.fromCanonical(delta)));
            if (!try budget.accepts(sample.family, probe) or
                try budget.fingerprint(sample.family, probe) != base_entries)
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
    budget: *Budget,
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
    /// `probe` is borrowed scratch of the same width as the sample.
    fn probeRow(self: *SelectorAudit, sample: *const Sample, probe: []QM31) !void {
        const family_index = @intFromEnum(sample.family);
        const selectors = layout.SELECTORS[family_index];
        const row = sample.trace_row;
        const honest = sample.view();
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
            if (try self.budget.accepts(sample.family, probe)) {
                try self.confusions.append(self.allocator, .{
                    .family = sample.family,
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
            "  [{s}] selector relabellings: {d} discriminating, {d} architecturally identical\n",
            .{ PROFILE.name, self.discriminating, self.identical },
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
    const corpus = try corpus_mod.shared();
    var budget = Budget{ .label = "selector rigidity", .cap = PROFILE.selector_budget };
    var memory = runner.Memory.init(allocator);
    defer memory.deinit();
    var audit = SelectorAudit{ .allocator = allocator, .memory = &memory, .budget = &budget };
    defer audit.deinit();

    // Sequential for the same reason as observability: `settled` accumulates.
    var probe: RowBuffer = undefined;
    for (corpus.samples) |*sample| {
        if (layout.SELECTORS[@intFromEnum(sample.family)].len < 2) continue;
        try audit.probeRow(sample, probe[0..sample.width]);
    }

    audit.report();
    budget.report();
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

/// One sampled row's share of the determinacy sweep. The rows are independent
/// and their costs differ by two orders of magnitude — a byte-swept
/// `load_store` row is 3072 evaluations, a delta-probed `fence` row is none —
/// so one task per row is what keeps the pool balanced. Nothing here is shared
/// with another task except the atomic budget, so the work set, and therefore
/// the realised evaluation count, does not depend on scheduling.
const DeterminacyTask = struct {
    sample: *const Sample,
    budget: *Budget,
    allocator: std.mem.Allocator,
    failures: std.ArrayList(Indeterminacy) = .{},
    failure: ?anyerror = null,
};

test "witness rigidity: every committed access emits a determined value" {
    const allocator = std.testing.allocator;
    const corpus = try corpus_mod.shared();
    var budget = Budget{ .label = "access determinacy", .cap = PROFILE.determinacy_budget };

    const tasks = try allocator.alloc(DeterminacyTask, corpus.samples.len);
    defer allocator.free(tasks);
    var pool: std.Thread.Pool = undefined;
    try pool.init(.{ .allocator = allocator });
    defer pool.deinit();

    var probed: usize = 0;
    var swept: usize = 0;
    var wait_group: std.Thread.WaitGroup = .{};
    for (tasks, corpus.samples) |*task, *sample| {
        task.* = .{ .sample = sample, .budget = &budget, .allocator = allocator };
        if (opcode_memory.accessCount(sample.family) == 0) continue;
        probed += 1;
        if (sample.sweep) swept += 1;
        pool.spawnWg(&wait_group, sweepRow, .{task});
    }
    pool.waitAndWork(&wait_group);

    var indeterminate: usize = 0;
    for (tasks) |*task| {
        defer task.failures.deinit(allocator);
        if (task.failure) |err| return err;
        indeterminate += task.failures.items.len;
        for (task.failures.items) |item| reportIndeterminacy(item);
    }

    std.debug.print(
        "  [{s}] access determinacy: {d} honest rows probed, {d} exhaustively swept\n",
        .{ PROFILE.name, probed, swept },
    );
    budget.report();
    try std.testing.expectEqual(@as(usize, 0), indeterminate);
    try std.testing.expect(probed > 0);
}

fn reportIndeterminacy(item: Indeterminacy) void {
    std.debug.print("  INDETERMINATE {s} slot {d} ({s}) next[{d}] accepts {d} ({s})\n", .{
        @tagName(item.family),
        item.slot,
        if (item.written) "written" else "read-only",
        item.limb,
        item.forged,
        if (item.exhaustive) "exhaustive" else "delta",
    });
}

fn sweepRow(task: *DeterminacyTask) void {
    for (0..opcode_memory.accessCount(task.sample.family)) |slot| {
        probeAccessNext(task, slot) catch |err| {
            task.failure = err;
            return;
        };
    }
}

/// Every alternative value of every `next` limb of one access must be
/// rejected: for a read-only slot because `next` must equal `previous`, for the
/// written slot because `next` must equal the row's computed result. Nothing in
/// the global LogUp closure relates the emitted `next` to the consumed
/// `previous`, so this has to hold row-locally.
fn probeAccessNext(task: *DeterminacyTask, slot: usize) !void {
    const sample = task.sample;
    const honest = sample.view();
    const family = sample.family;
    var probe: RowBuffer = undefined;
    const view = probe[0..honest.len];

    for (0..4) |limb| {
        const column = layout.nextLimbColumn(family, slot, limb);
        // Access limbs are written as byte limbs, which is what makes the
        // exhaustive tier a complete determinacy argument over their domain.
        const canonical = (honest[column].tryIntoM31() catch
            return error.AccessLimbNotBaseField).v;
        if (canonical > 0xff) return error.AccessLimbNotAByte;

        const candidates: usize = if (sample.sweep) BYTE_VALUES else DELTAS.len;
        for (0..candidates) |index| {
            const forged: u32 = if (sample.sweep)
                @intCast(index)
            else
                (canonical + DELTAS[index]) % m31.Modulus;
            if (forged == canonical) continue;

            @memcpy(view, honest);
            view[column] = QM31.fromBase(M31.fromCanonical(forged));
            if (!try task.budget.accepts(family, view)) continue;
            try task.failures.append(task.allocator, .{
                .family = family,
                .slot = slot,
                .written = layout.writtenSlot(family) == slot,
                .limb = limb,
                .forged = forged,
                .exhaustive = sample.sweep,
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
