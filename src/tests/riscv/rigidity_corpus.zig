//! Honest committed rows for the witness-rigidity audit, sampled once and
//! charged against an explicit work budget.
//!
//! All three rigidity properties consume the same object: honest committed rows
//! of every opcode family, paired with the trace row that produced them.
//! Producing it is the expensive half — executing the ELF corpus and
//! materialising every family's committed columns — and it used to be paid once
//! per property. It is paid once here, across a thread pool, and the runner
//! traces are released as soon as the rows are copied out.
//!
//! The cheap half is the probes, and their cost is why this module exists
//! rather than a few constants in the test. A gate whose cost is a silent
//! function of corpus size stops being run, so every `row_admissibility` call
//! goes through a `Budget` with a stated ceiling and the realised count is
//! printed. Exceeding the ceiling raises — a cap that silently drops coverage
//! is worse than a slow gate.
//!
//! Two profiles, selected by the `riscv_rigidity_exhaustive` build option:
//!
//! - `fast` (default) samples a bounded number of rows per family, biased so
//!   that every opcode selector the corpus executes is represented, and gives
//!   the exhaustive `next`-limb byte sweep to the first row of each selector.
//!   A column is observable if ANY honest row makes it so and a byte sweep
//!   decides determinacy over the limb's whole domain, so distinct rows buy
//!   power and repeated rows buy almost none.
//! - `exhaustive` keeps the original bounds — a prefix of every family's
//!   materialised rows in every program, byte-swept once per program — so the
//!   slower sweep remains a faithful superset of what it always probed.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const test_options = @import("test_options");

const layout = @import("committed_row_layout.zig");
const oracle = @import("row_admissibility.zig");
const isa_decode = @import("../../frontends/riscv/isa/decode.zig");
const runner = @import("../../frontends/riscv/runner/mod.zig");
const trace_mod = @import("../../frontends/riscv/runner/trace.zig");

pub const OpcodeFamily = trace_mod.OpcodeFamily;
pub const TraceRow = trace_mod.TraceRow;
pub const Opcode = isa_decode.Opcode;

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

pub const SweepPolicy = enum {
    /// One byte sweep on the first sampled row of each family in each program.
    first_row_per_program,
    /// One byte sweep on the first sampled row of each (family, selector). A
    /// `next` limb is a byte limb, so one complete sweep decides determinacy
    /// over its whole domain for that opcode; a second sweep on another row of
    /// the same opcode re-decides what the first already settled.
    first_row_per_selector,
};

pub const Profile = struct {
    name: []const u8,
    /// Committed rows materialised per family per program.
    log_rows: u32,
    /// Honest rows sampled per family per program.
    rows_per_program: usize,
    /// Honest rows sampled per family across the whole corpus.
    rows_per_family: usize,
    /// Spread the per-program quota across the materialised rows instead of
    /// taking a prefix. The fast profile takes few rows and wants them far
    /// apart; the exhaustive profile takes a prefix because that is the set it
    /// has always probed, and keeping it a superset is the point of keeping it.
    spread: bool,
    sweep: SweepPolicy,
    sampling_budget: usize,
    observability_budget: usize,
    selector_budget: usize,
    determinacy_budget: usize,
};

/// A `test_options` built before this option existed still selects the fast
/// profile rather than failing to compile: the focused `zig test` recipe in
/// CONTRIBUTING and in several running workflows writes the option struct by
/// hand, and a missing field there must not be a build break.
const exhaustive_profile = @hasDecl(test_options, "riscv_rigidity_exhaustive") and
    test_options.riscv_rigidity_exhaustive;

pub const PROFILE: Profile = if (exhaustive_profile) .{
    .name = "exhaustive",
    .log_rows = 10,
    .rows_per_program = 64,
    .rows_per_family = std.math.maxInt(usize),
    .spread = false,
    .sweep = .first_row_per_program,
    .sampling_budget = 8_000,
    .observability_budget = 400_000,
    .selector_budget = 20_000,
    .determinacy_budget = 1_200_000,
} else .{
    .name = "fast",
    .log_rows = 10,
    .rows_per_program = 2,
    .rows_per_family = 24,
    .spread = true,
    .sweep = .first_row_per_selector,
    .sampling_budget = 1_000,
    .observability_budget = 20_000,
    .selector_budget = 2_000,
    .determinacy_budget = 200_000,
};

/// Every committed RV32IM ELF the runner executes within `MAX_STEPS`. The three
/// vendored cryptographic guests are included deliberately: they are the only
/// programs in the tree that reach `auipc`, `jalr` with a non-`x0` destination,
/// or `mul` more than once. `crypto/ecdsa.elf` is excluded because it does not
/// terminate within `MAX_STEPS`. Both profiles use the whole corpus — it is
/// what supplies selector coverage, and executing it is now a parallel
/// one-off.
pub const CORPUS = [_][]const u8{
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

// ---------------------------------------------------------------------------
// Work accounting
// ---------------------------------------------------------------------------

/// Counts row-admissibility evaluations and refuses to exceed its ceiling.
///
/// One unit is one full traversal of a candidate row — the constraint vector
/// plus preprocessed lookup membership for `accepts`, the emitted entry list
/// for `fingerprint`. `fingerprint` is the cheaper of the two; charging both
/// the same unit over-counts its cost rather than hiding it.
pub const Budget = struct {
    label: []const u8,
    cap: usize,
    used: std.atomic.Value(usize) = .init(0),

    pub fn accepts(self: *Budget, family: OpcodeFamily, columns: []const QM31) !bool {
        try self.charge();
        return oracle.accepts(family, columns);
    }

    pub fn fingerprint(self: *Budget, family: OpcodeFamily, columns: []const QM31) !u64 {
        try self.charge();
        return oracle.fingerprint(family, columns);
    }

    pub fn realised(self: *const Budget) usize {
        return self.used.load(.monotonic);
    }

    pub fn report(self: *const Budget) void {
        std.debug.print("  [{s}] {s}: {d} admissibility evaluations, budget {d}\n", .{
            PROFILE.name, self.label, self.realised(), self.cap,
        });
    }

    fn charge(self: *Budget) !void {
        if (self.used.fetchAdd(1, .monotonic) < self.cap) return;
        return error.EvaluationBudgetExceeded;
    }
};

// ---------------------------------------------------------------------------
// Sampled honest rows
// ---------------------------------------------------------------------------

/// One honest committed row, detached from the trace that produced it.
pub const Sample = struct {
    family: OpcodeFamily,
    /// Index into `CORPUS`, for diagnostics that must name the program.
    program: u16,
    width: u16,
    /// Give this row the exhaustive `next`-limb byte sweep.
    sweep: bool,
    columns: [trace_mod.MAX_FAMILY_COLUMNS]QM31,
    /// The architectural operands the reference semantics need. The committed
    /// columns carry what the AIR sees; this carries what the ISA saw.
    trace_row: TraceRow,

    pub fn view(self: *const Sample) []const QM31 {
        return self.columns[0..self.width];
    }
};

pub const FamilyStats = struct {
    /// Committed columns of the family, zero when the corpus never runs it.
    width: usize = 0,
    sampled: usize = 0,
    /// Rows of this family across the whole corpus, before any sampling.
    corpus_rows: usize = 0,
};

pub const Corpus = struct {
    samples: []const Sample,
    stats: [trace_mod.N_FAMILIES]FamilyStats,

    pub fn report(self: *const Corpus) void {
        std.debug.print("\n  family         cols  sampled  corpus rows\n", .{});
        for (self.stats, 0..) |stat, index| {
            std.debug.print("  {s: <14} {d: >4}  {d: >7}  {d: >11}\n", .{
                @tagName(@as(OpcodeFamily, @enumFromInt(index))),
                stat.width,
                stat.sampled,
                stat.corpus_rows,
            });
        }
    }
};

/// The corpus, executed and sampled on first use.
///
/// Built lazily from a test body, and the test runner runs tests one at a time
/// on one thread, so this needs no guard of its own; the pools below are the
/// only concurrency. Deliberately never freed and deliberately not on
/// `std.testing.allocator`: the runner checks that allocator for leaks after
/// every test, so a cache shared BETWEEN tests cannot live there. Only the
/// sample array is retained — the runner traces it was copied from are
/// released before this returns.
var cache: ?Corpus = null;

pub fn shared() !*const Corpus {
    if (cache == null) cache = try build();
    return &cache.?;
}

fn build() !Corpus {
    const allocator = std.heap.smp_allocator;
    var pool: std.Thread.Pool = undefined;
    try pool.init(.{ .allocator = allocator });
    defer pool.deinit();

    // Both arrays are populated before either phase runs so that their cleanup
    // is registered over initialised memory, whichever phase fails.
    const programs = try allocator.alloc(Program, CORPUS.len);
    for (programs) |*program| program.* = .{ .allocator = allocator };
    defer {
        for (programs) |*program| program.deinit();
        allocator.free(programs);
    }
    const samplers = try allocator.alloc(FamilySampler, trace_mod.N_FAMILIES);
    for (samplers, 0..) |*sampler, index| sampler.* = .{ .family = @enumFromInt(index) };
    defer {
        for (samplers) |*sampler| sampler.samples.deinit(allocator);
        allocator.free(samplers);
    }

    try executeCorpus(&pool, allocator, programs);
    var budget = Budget{ .label = "corpus sampling", .cap = PROFILE.sampling_budget };
    try sampleFamilies(&pool, allocator, programs, samplers, &budget);
    budget.report();
    return try collect(allocator, samplers);
}

/// Flatten the per-family sample lists into one owned array, family by family.
fn collect(allocator: std.mem.Allocator, samplers: []const FamilySampler) !Corpus {
    var total: usize = 0;
    for (samplers) |sampler| total += sampler.samples.items.len;
    const samples = try allocator.alloc(Sample, total);
    var stats: [trace_mod.N_FAMILIES]FamilyStats = undefined;
    var cursor: usize = 0;
    for (samplers, &stats) |sampler, *stat| {
        @memcpy(samples[cursor..][0..sampler.samples.items.len], sampler.samples.items);
        cursor += sampler.samples.items.len;
        stat.* = .{
            .width = sampler.width,
            .sampled = sampler.samples.items.len,
            .corpus_rows = sampler.corpus_rows,
        };
    }
    return .{ .samples = samples, .stats = stats };
}

// ---------------------------------------------------------------------------
// Phase A: execute every program
// ---------------------------------------------------------------------------

/// One executed corpus program. `elf` is owned; `run` owns the trace.
const Program = struct {
    allocator: std.mem.Allocator,
    elf: []u8 = &.{},
    run: ?runner.RunResult = null,
    failure: ?anyerror = null,

    fn deinit(self: *Program) void {
        if (self.run) |*run| run.deinit();
        self.allocator.free(self.elf);
        self.* = undefined;
    }
};

fn executeCorpus(
    pool: *std.Thread.Pool,
    allocator: std.mem.Allocator,
    programs: []Program,
) !void {
    var wait_group: std.Thread.WaitGroup = .{};
    for (CORPUS, programs) |path, *program| {
        pool.spawnWg(&wait_group, executeProgram, .{ allocator, path, program });
    }
    pool.waitAndWork(&wait_group);
    for (programs) |program| if (program.failure) |err| return err;
}

fn executeProgram(allocator: std.mem.Allocator, path: []const u8, out: *Program) void {
    out.elf = std.fs.cwd().readFileAlloc(allocator, path, 16 << 20) catch |err| {
        out.failure = err;
        return;
    };
    if (runner.runWithInput(allocator, out.elf, &.{}, MAX_STEPS)) |run| {
        out.run = run;
    } else |err| {
        out.failure = err;
    }
}

// ---------------------------------------------------------------------------
// Phase B: sample honest rows, one task per family
// ---------------------------------------------------------------------------

/// Per-family sampling state. Families are independent, and each task walks the
/// programs in corpus order, so the selected set does not depend on scheduling.
const FamilySampler = struct {
    family: OpcodeFamily = undefined,
    width: usize = 0,
    corpus_rows: usize = 0,
    seen_selector: [layout.MAX_SELECTORS]bool = .{false} ** layout.MAX_SELECTORS,
    swept_selector: [layout.MAX_SELECTORS]bool = .{false} ** layout.MAX_SELECTORS,
    samples: std.ArrayList(Sample) = .{},
    failure: ?anyerror = null,
};

fn sampleFamilies(
    pool: *std.Thread.Pool,
    allocator: std.mem.Allocator,
    programs: []const Program,
    samplers: []FamilySampler,
    budget: *Budget,
) !void {
    var wait_group: std.Thread.WaitGroup = .{};
    for (samplers) |*sampler| {
        pool.spawnWg(&wait_group, sampleFamily, .{ allocator, programs, sampler, budget });
    }
    pool.waitAndWork(&wait_group);
    for (samplers) |sampler| if (sampler.failure) |err| return err;
}

fn sampleFamily(
    allocator: std.mem.Allocator,
    programs: []const Program,
    sampler: *FamilySampler,
    budget: *Budget,
) void {
    for (programs, 0..) |*program, index| {
        sampleProgram(allocator, program, @intCast(index), sampler, budget) catch |err| {
            sampler.failure = err;
            return;
        };
    }
}

fn sampleProgram(
    allocator: std.mem.Allocator,
    program: *const Program,
    index: u16,
    sampler: *FamilySampler,
    budget: *Budget,
) !void {
    const trace = &program.run.?.execution_trace;
    for (trace.rows.items) |row| {
        const family = trace_mod.proofOpcodeFamily(row.opcode) catch continue;
        if (family == sampler.family) sampler.corpus_rows += 1;
    }

    var columns = try trace.columnsForFamily(allocator, sampler.family, PROFILE.log_rows);
    defer columns.deinit(allocator);
    if (columns.n_real_rows == 0) return;
    sampler.width = columns.n_columns;

    const stride = if (PROFILE.spread)
        @max(1, columns.n_real_rows / PROFILE.rows_per_program)
    else
        1;
    var rows = FamilyRows{
        .rows = trace.rows.items,
        .columns = &columns,
        .family = sampler.family,
    };
    var sample = Sample{
        .family = sampler.family,
        .program = index,
        .width = @intCast(columns.n_columns),
        .sweep = false,
        .columns = undefined,
        .trace_row = undefined,
    };
    var taken: usize = 0;
    var position: usize = 0;
    while (rows.next(sample.columns[0..columns.n_columns])) |trace_row| : (position += 1) {
        const selector = selectorIndex(sampler.family, trace_row.opcode);
        const novel = !sampler.seen_selector[selector];
        const on_quota = taken < PROFILE.rows_per_program and
            position % stride == 0 and
            sampler.samples.items.len < PROFILE.rows_per_family;
        // The corpus-wide cap bounds quota rows but never a row introducing a
        // selector this family has not shown yet. "Every executed selector is
        // represented" is the property the fast profile trades row count for,
        // so it has to be structural rather than a coincidence of the cap.
        if (!novel and !on_quota) continue;

        // An honest row the row-local oracle rejects is a witness generator
        // bug, not a row to skip. Decided once here so the three properties do
        // not each re-decide it.
        if (!try budget.accepts(sampler.family, sample.columns[0..columns.n_columns])) {
            reportHonestReject(CORPUS[index], sampler.family, trace_row);
            return error.HonestRowRejected;
        }
        sample.sweep = switch (PROFILE.sweep) {
            .first_row_per_program => taken == 0,
            .first_row_per_selector => !sampler.swept_selector[selector],
        };
        sample.trace_row = trace_row;
        try sampler.samples.append(allocator, sample);
        sampler.seen_selector[selector] = true;
        if (sample.sweep) sampler.swept_selector[selector] = true;
        taken += 1;
    }
}

fn reportHonestReject(path: []const u8, family: OpcodeFamily, row: TraceRow) void {
    std.debug.print(
        "  HONEST REJECT path={s} family={s} pc=0x{x} rs1=0x{x} imm={d} next_pc=0x{x}\n",
        .{ path, @tagName(family), row.pc, row.rs1_val, row.imm, row.next_pc },
    );
}

/// Selector slot of `opcode` within its family. Single-opcode families have no
/// selector block, and one implicit slot keeps the novelty bookkeeping uniform.
pub fn selectorIndex(family: OpcodeFamily, opcode: Opcode) usize {
    return layout.SELECTORS[@intFromEnum(family)].indexOf(opcode) orelse 0;
}

/// Pairs each committed row with the trace row that produced it.
///
/// `Trace.columnsForFamily` fills family rows in execution order, so the k-th
/// real committed row is the k-th trace row of that family.
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
