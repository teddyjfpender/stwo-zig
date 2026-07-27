//! Emits each opcode family's per-row constraint system as uniqueness IR, and
//! proves the emission is faithful.
//!
//! `Semantics(S)` is generic over its scalar, so instantiating it with a tracing
//! scalar records the exact polynomials the committed AIR evaluates rather than
//! a transcription of them. That is the whole point: a hand-written model of an
//! AIR is correct the day it is written and verifies a system you no longer ship
//! a week later, and a solver result about a drifted model is worse than no
//! result because it reads as assurance.
//!
//! Extraction alone does not earn that, though. A tracing scalar that dropped a
//! term, mis-ordered a subtraction, or interned two distinct nodes as one would
//! emit a system that is *easier* to satisfy uniquely, and every family would
//! come back UNSAT. So the differential below is not a nicety attached to the
//! extractor; it is the reason any UNSAT verdict downstream means anything.
//! It evaluates the emitted DAG and `Semantics(QM31)` at the same fixed-seed
//! random assignments and requires them equal constraint by constraint.
//!
//! Two things beyond the constraint system are emitted, and both exist because
//! a query built from committed columns alone answers a weaker question than it
//! appears to. `next_pc` is an alias column recovered from the state-chain
//! request, without which no family is ever asked where it jumps. A declared
//! `domain` records the range and alignment an input really has, which keeps the
//! solver out of regions no execution reaches -- an assumption, and the only one
//! here that can hide a bug, so each carries its justification into the IR.
//!
//! Runtime: ~1 s. Emission is comptime-driven and the differential is
//! `FAMILIES x TRIALS` DAG walks over base-field arithmetic; neither proves
//! anything, so neither is slow.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const semantic_eval = @import("../../frontends/riscv/air/semantic_eval.zig");
const trace_mod = @import("../../frontends/riscv/runner/trace.zig");
const witness_layout = @import("../../frontends/riscv/witness_layout.zig");
const layout = @import("committed_row_layout.zig");
const opcode_entries = @import("../../frontends/riscv/air/lookups/opcode_entries.zig");
const lookup_entry = @import("../../frontends/riscv/air/lookups/entry.zig");
const profile = @import("../../frontends/riscv/isa/profile.zig");

const OpcodeFamily = trace_mod.OpcodeFamily;
const MODULUS: u64 = (1 << 31) - 1;

/// Fixed so a failure is reproducible from the report alone.
const SEED: u64 = 0x5150_1CE0_1DED_BEEF;
const TRIALS: usize = 32;

// --- the tracing scalar -----------------------------------------------------

/// A DAG node in the flat form `air_uniqueness_lib.ir` consumes directly.
const Node = struct {
    op: []const u8,
    lhs: u32 = 0,
    rhs: u32 = 0,
    value: u64 = 0,
    name: []const u8 = "",
};

/// Module-level because the scalar interface is value-typed: `S.zero()` and
/// `S.one()` take no receiver, so there is nowhere to thread a context. One
/// arena is live at a time, bracketed by `begin`/`end`, and extraction is
/// single-threaded by construction.
var arena: std.ArrayList(Node) = .{};
var arena_allocator: std.mem.Allocator = undefined;

fn begin(allocator: std.mem.Allocator) void {
    arena_allocator = allocator;
    arena = .{};
}

fn end() void {
    arena.deinit(arena_allocator);
}

fn intern(node: Node) u32 {
    // Hash-consing keeps the DAG shared. `derive()` results are reused across
    // many constraints in every family, so without interning the emitted node
    // count explodes and the solver sees the same subterm as many free copies.
    for (arena.items, 0..) |existing, index| {
        if (!std.mem.eql(u8, existing.op, node.op)) continue;
        if (existing.lhs != node.lhs or existing.rhs != node.rhs) continue;
        if (existing.value != node.value) continue;
        if (!std.mem.eql(u8, existing.name, node.name)) continue;
        return @intCast(index);
    }
    arena.append(arena_allocator, node) catch @panic("uniqueness IR arena");
    return @intCast(arena.items.len - 1);
}

/// Records the operations `Semantics(S)` performs instead of computing them.
/// Only the constraint-path operations are implemented; `inv`, `eql` and
/// `tryIntoM31` appear solely in the modules' own QM31 self-tests, which are
/// never instantiated with this scalar.
const Trace = struct {
    idx: u32,

    fn wrap(idx: u32) Trace {
        return .{ .idx = idx };
    }

    pub fn zero() Trace {
        return wrap(intern(.{ .op = "const", .value = 0 }));
    }

    pub fn one() Trace {
        return wrap(intern(.{ .op = "const", .value = 1 }));
    }

    pub fn fromBase(value: M31) Trace {
        return wrap(intern(.{ .op = "const", .value = value.toU32() }));
    }

    pub fn fromU64(value: u64) Trace {
        return wrap(intern(.{ .op = "const", .value = value % MODULUS }));
    }

    pub fn add(self: Trace, other: Trace) Trace {
        return wrap(intern(.{ .op = "add", .lhs = self.idx, .rhs = other.idx }));
    }

    pub fn sub(self: Trace, other: Trace) Trace {
        return wrap(intern(.{ .op = "sub", .lhs = self.idx, .rhs = other.idx }));
    }

    pub fn mul(self: Trace, other: Trace) Trace {
        return wrap(intern(.{ .op = "mul", .lhs = self.idx, .rhs = other.idx }));
    }

    pub fn neg(self: Trace) Trace {
        return wrap(intern(.{ .op = "neg", .lhs = self.idx }));
    }
};

// --- emission ---------------------------------------------------------------

/// Column names come from `witness_layout.LayoutFor`, whose field order is the
/// committed column order and is already pinned by the witness-layout digest.
/// Deriving them here rather than restating them means a layout change moves
/// the IR with it instead of silently renaming a counterexample's variables.
fn columnNames(comptime family: OpcodeFamily) []const []const u8 {
    @setEvalBranchQuota(20_000);
    const Layout = witness_layout.LayoutFor(family);
    const fields = @typeInfo(Layout).@"struct".fields;
    comptime var names: [fields.len][]const u8 = undefined;
    inline for (fields, 0..) |field, index| names[index] = field.name;
    const frozen = names;
    return &frozen;
}

// --- architectural roles ----------------------------------------------------
//
// Uniqueness asks: do two witnesses that agree on the INPUTS have to agree on
// the OUTPUTS? So the classification below is the question being posed, not a
// presentation detail. Getting it wrong yields a board that answers something
// else while looking green.
//
// Derived from the pinned layout field names rather than seventeen hand-kept
// lists, because a hand-kept list drifts the first time a column moves and the
// drift is invisible.
//
//   input    what the instruction consumes: every access's `addr`, `prev_*` and
//            `clock_prev`, plus `pc`, `clock`, `enabler`, the opcode selectors
//            and the immediates.
//   output   what it produces: the WRITTEN access's `next_*`, plus `result_*`
//            and a branch's decision and target.
//   witness  everything else -- carries, one-hot markers, sign bits, inverse
//            certificates, and the SOURCE accesses' `next_*`. Source `next` is
//            witness, not input, and that is deliberate: it is bound to `prev`
//            only by the read-only residuals, so leaving it free is exactly how
//            a solver rediscovers the register-rewrite bug.
fn roleOf(name: []const u8, written_prefix: []const u8) []const u8 {
    if (eq(name, "clock") or eq(name, "pc") or eq(name, "enabler")) return "input";
    if (std.mem.endsWith(u8, name, "_flag")) return "input";
    if (std.mem.startsWith(u8, name, "imm")) return "input";
    if (std.mem.endsWith(u8, name, "_addr")) return "input";
    if (std.mem.endsWith(u8, name, "_clock_prev")) return "input";
    if (std.mem.indexOf(u8, name, "_prev_") != null) return "input";

    if (eq(name, "cmp_result") or eq(name, "branch_target")) return "output";
    if (std.mem.startsWith(u8, name, "result_")) return "output";
    if (written_prefix.len != 0 and
        std.mem.startsWith(u8, name, written_prefix) and
        std.mem.indexOf(u8, name, "_next_") != null) return "output";

    return "witness";
}

fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// Slot 0 is the written access for every writing family, and its prefix is the
/// first `_addr` field in committed order.
fn writtenPrefix(comptime family: OpcodeFamily, names: []const []const u8) []const u8 {
    if (layout.writtenSlot(family) == null) return "";
    for (names) |name| {
        if (std.mem.endsWith(u8, name, "_addr")) {
            return name[0 .. name.len - "_addr".len];
        }
    }
    return "";
}

// --- declared input domains -------------------------------------------------
//
// A column the query leaves free over [0, p) is a column the solver explores
// over [0, p), which both wastes it and manufactures counterexamples at values
// no execution can reach. `jal` reported `sat` at `pc = p - 4` for exactly that
// reason.
//
// A declared domain is therefore an ASSUMPTION IMPORTED FROM OUTSIDE THE ROW,
// and it points the dangerous way: it can only shrink the admitted witness set,
// so it can turn a real `sat` into `unsat` and hide a bug. Three rules keep
// that honest. Only `input` columns may carry one -- bounding an output or a
// witness would delete a forgery the AIR really admits. Every domain carries
// its justification here, in the emitted IR, so the assumption set is auditable
// without reading this emitter. And the solver does not assume any of them
// unless asked: `air_uniqueness.py check --assume-declared-domains` is the
// triage lever for a `sat` at an input no execution presents, not the default.
//
// Implied bounds are NOT declared here. A bound the per-row obligations already
// entail is derived by `air_uniqueness_lib.analysis`, which proves it rather
// than assuming it; duplicating those would blur which is which.
const Domain = struct {
    lo: u64,
    hi: u64,
    /// `value = stride * k`. Alignment is a domain, not a range, and the
    /// program AIR states pc's alignment and its range in one equation.
    stride: u64 = 1,
    why: []const u8,
};

// Candidates considered and REJECTED, so the omissions are decisions rather
// than oversights:
//
//   clock             `statement_validation.zig` bounds total steps below
//                     p - 1, so the implied range is [0, p) -- the default.
//                     What is real is `clock - clock_prev < 2^20`
//                     (`state_chain.zig` MAX_CLOCK_DIFF), and the row already
//                     emits that as a range_check_20 request the query models.
//   *_clock_prev      the same request, other side. Nothing to add.
//   *_prev_* limbs    byte-valued only inductively, through the memory bus.
//                     They appear in no direct constraint and in no table
//                     request -- only inside `memory_access` tuples the query
//                     ignores -- so a byte bound would constrain nothing while
//                     importing an assumption. Where a source operand is read,
//                     the read-only residual already ties `prev` to `next`, and
//                     the family's own byte tables bound `next`.
//   *_addr            register indices are five-bit by decode, but that too is
//                     mediated by the program bus, and no obligation in the row
//                     reads the width.
//   enabler, *_flag   already pinned: `bit()` plus the placement equality make
//                     these exact consequences of the asserted system, and
//                     `analysis.implied_column_bounds` derives them there.
//
/// The one architectural input whose domain is both non-trivial and justified.
fn declaredDomain(name: []const u8, role: []const u8) ?Domain {
    if (!eq(role, "input")) return null;
    if (!eq(name, "pc")) return null;
    return .{
        .lo = 0,
        .hi = profile.max_program_word_address,
        .stride = profile.instruction_alignment,
        .why = "an active row consumes program_access(pc, ..), and the only " ++
            "yielding side is the program commitment table, whose addr is " ++
            "constrained to 4 * (low20 + 2^20 * high8) with low20 and high8 " ++
            "range-checked to 20 and 8 bits (air/program/interaction.zig, " ++
            "isa/profile.zig max_program_word_address). ASSUMPTION: the bus " ++
            "closes, which a per-row query cannot see.",
    };
}

const Lookup = struct {
    domain: []const u8,
    numerator: u32,
    tuple: []const u32,
};

/// A column that is not committed: it names an architectural output the AIR
/// carries as an expression, and is pinned to that expression by one added
/// constraint. `air_uniqueness.py explain` section 7 promises this mechanism;
/// `next_pc` is its first user.
const Alias = struct {
    name: []const u8,
    why: []const u8,
    definition: u32,
};

const Emitted = struct {
    nodes: []const Node,
    /// Extracted from `Semantics(S)`, and the only constraints the extraction
    /// differential may compare -- an alias definition has no counterpart in
    /// `Semantics(QM31)` to compare against.
    constraints: []const u32,
    aliases: []const Alias,
    lookups: []const Lookup,
};

fn emit(comptime family: OpcodeFamily, allocator: std.mem.Allocator) !Emitted {
    const names = comptime columnNames(family);
    begin(allocator);

    var columns: [trace_mod.MAX_FAMILY_COLUMNS]Trace = undefined;
    for (names, 0..) |name, index| {
        columns[index] = Trace.wrap(intern(.{ .op = "col", .name = name }));
    }

    const evaluation = try semantic_eval.Eval(Trace).evaluate(
        family,
        columns[0..names.len],
        Trace.one(),
    );

    var constraints = try allocator.alloc(u32, evaluation.len);
    for (evaluation.values[0..evaluation.len], 0..) |value, index| {
        constraints[index] = value.idx;
    }

    // The same tracing instantiation records what the row asks of the
    // preprocessed tables. Without these the admitted witness set is strictly
    // larger -- nothing forces a limb to be a byte -- so the query is weaker and
    // reports uniqueness failures a range check would have excluded.
    const list = try opcode_entries.Entries(Trace).fromMain(family, columns[0..names.len]);
    var lookups = try allocator.alloc(Lookup, list.len);
    for (list.entries[0..list.len], 0..) |request, index| {
        const tuple = try allocator.alloc(u32, request.arity);
        for (request.values[0..request.arity], 0..) |value, limb| tuple[limb] = value.idx;
        lookups[index] = .{
            .domain = @tagName(request.domain),
            .numerator = request.numerator.idx,
            .tuple = tuple,
        };
    }

    const aliases = try allocator.alloc(Alias, 1);
    aliases[0] = try nextPcAlias(family, columns[0..names.len], list);

    return .{
        .nodes = try arena.toOwnedSlice(arena_allocator),
        .constraints = constraints,
        .aliases = aliases,
        .lookups = lookups,
    };
}

/// The architectural outputs of one retired step are the word written, the next
/// clock, and the next program counter. The first is a committed column in every
/// family. The other two live only inside the `registers_state` emit request, so
/// a query that reads roles off committed columns alone would never ask about
/// them -- and `jalr`, whose jump target is a pair of columns this classifier
/// calls witness, would report `unsat` while saying nothing about where it jumps.
///
/// So both are recovered from the request itself rather than restated per family.
/// The next clock is checked to BE `clock + 1`, which makes it a function of an
/// input and therefore nothing to ask about; the failure of that check is the
/// only way this file can be wrong about it. The next pc is aliased to a column.
fn nextPcAlias(
    comptime family: OpcodeFamily,
    columns: []const Trace,
    list: anytype,
) !Alias {
    const pc = columns[semantic_eval.pcColumn(family)];
    const clock = columns[semantic_eval.clockColumn(family)];

    var found: [2]usize = undefined;
    var seen: usize = 0;
    for (list.entries[0..list.len], 0..) |request, index| {
        if (request.domain != lookup_entry.Domain.registers_state) continue;
        if (seen == found.len) return error.UnexpectedStateRequestCount;
        found[seen] = index;
        seen += 1;
    }
    if (seen != found.len) return error.UnexpectedStateRequestCount;

    // Declaration order is consume then emit, and the two are distinguishable
    // without trusting that order: `stateLookups` negates the enabler on the
    // consume side only, so the consume numerator is the `neg` of the emit's.
    const consume = list.entries[found[0]];
    const produce = list.entries[found[1]];
    const numerator = arena.items[consume.numerator.idx];
    if (!eq(numerator.op, "neg") or numerator.lhs != produce.numerator.idx)
        return error.StateRequestsNotAConsumeEmitPair;
    if (consume.values[0].idx != pc.idx or consume.values[1].idx != clock.idx)
        return error.StateConsumesSomethingOtherThanThisRow;
    if (produce.values[1].idx != clock.add(Trace.one()).idx)
        return error.NextClockIsNotClockPlusOne;

    return .{
        .name = "next_pc",
        .why = "first component of the registers_state emit request, i.e. the " ++
            "program counter this row hands to its successor; the second " ++
            "component is checked to be clock + 1, a function of an input",
        .definition = Trace.wrap(intern(.{ .op = "col", .name = "next_pc" }))
            .sub(produce.values[0]).idx,
    };
}

/// Walks the emitted DAG over M31. This is deliberately a separate evaluator
/// from the one that produced the nodes: if it shared code with the tracing
/// scalar, the differential would compare a mistake against itself.
fn evalNode(nodes: []const Node, assignment: []const M31, names: []const []const u8, idx: u32) M31 {
    const node = nodes[idx];
    if (std.mem.eql(u8, node.op, "const")) return M31.fromU64(node.value);
    if (std.mem.eql(u8, node.op, "col")) {
        for (names, 0..) |name, column| {
            if (std.mem.eql(u8, name, node.name)) return assignment[column];
        }
        @panic("column not found");
    }
    if (std.mem.eql(u8, node.op, "neg")) {
        return M31.zero().sub(evalNode(nodes, assignment, names, node.lhs));
    }
    const lhs = evalNode(nodes, assignment, names, node.lhs);
    const rhs = evalNode(nodes, assignment, names, node.rhs);
    if (std.mem.eql(u8, node.op, "add")) return lhs.add(rhs);
    if (std.mem.eql(u8, node.op, "sub")) return lhs.sub(rhs);
    if (std.mem.eql(u8, node.op, "mul")) return lhs.mul(rhs);
    @panic("unknown op");
}

fn freeEmitted(allocator: std.mem.Allocator, emitted: Emitted) void {
    allocator.free(emitted.nodes);
    allocator.free(emitted.constraints);
    allocator.free(emitted.aliases);
    for (emitted.lookups) |request| allocator.free(request.tuple);
    allocator.free(emitted.lookups);
}

test "uniqueness IR: the emitted system agrees with the committed AIR" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(SEED);
    const random = prng.random();

    var checked: usize = 0;
    inline for (comptime std.enums.values(OpcodeFamily)) |family| {
        const names = comptime columnNames(family);
        const emitted = try emit(family, allocator);
        defer freeEmitted(allocator, emitted);

        for (0..TRIALS) |_| {
            var assignment: [trace_mod.MAX_FAMILY_COLUMNS]M31 = undefined;
            var secure: [trace_mod.MAX_FAMILY_COLUMNS]QM31 = undefined;
            for (0..names.len) |column| {
                // Base-field values only: every committed cell is base-field,
                // and a QM31-valued probe would not exercise the same domain.
                const sample = M31.fromU64(random.uintLessThan(u64, MODULUS));
                assignment[column] = sample;
                secure[column] = QM31.fromBase(sample);
            }

            const reference = try semantic_eval.Eval(QM31).evaluate(
                family,
                secure[0..names.len],
                QM31.one(),
            );
            try std.testing.expectEqual(reference.len, emitted.constraints.len);

            for (emitted.constraints, 0..) |node, index| {
                const extracted = evalNode(emitted.nodes, assignment[0..names.len], names, node);
                const expected = try reference.values[index].tryIntoM31();
                if (!extracted.eql(expected)) {
                    std.debug.print(
                        "\n  {s} constraint {d}: extracted {d} != committed {d}\n",
                        .{ @tagName(family), index, extracted.toU32(), expected.toU32() },
                    );
                    return error.ExtractionDiverged;
                }
            }
        }
        checked += 1;
    }

    std.debug.print(
        "\n  extraction differential: {d} families x {d} trials, seed 0x{x}\n",
        .{ checked, TRIALS, SEED },
    );
    try std.testing.expectEqual(trace_mod.N_FAMILIES, checked);
}

// --- serialisation ----------------------------------------------------------

const Writer = std.ArrayList(u8).Writer;

fn writeColumns(
    w: Writer,
    names: []const []const u8,
    prefix: []const u8,
    aliases: []const Alias,
) !void {
    const total = names.len + aliases.len;
    var written: usize = 0;
    try w.writeAll("  \"columns\": [\n");
    for (names) |name| {
        const role = roleOf(name, prefix);
        written += 1;
        try w.print("    {{\"name\": \"{s}\", \"role\": \"{s}\"", .{ name, role });
        if (declaredDomain(name, role)) |domain| {
            try w.print(
                ", \"domain\": {{\"lo\": {d}, \"hi\": {d}, \"stride\": {d}, \"why\": \"{s}\"}}",
                .{ domain.lo, domain.hi, domain.stride, domain.why },
            );
        }
        try w.print("}}{s}\n", .{if (written == total) "" else ","});
    }
    for (aliases) |alias| {
        written += 1;
        try w.print(
            "    {{\"name\": \"{s}\", \"role\": \"output\", \"alias\": \"{s}\"}}{s}\n",
            .{ alias.name, alias.why, if (written == total) "" else "," },
        );
    }
    try w.writeAll("  ],\n");
}

fn writeNodes(w: Writer, nodes: []const Node) !void {
    try w.writeAll("  \"nodes\": [\n");
    for (nodes, 0..) |node, i| {
        const tail = if (i + 1 == nodes.len) "" else ",";
        if (eq(node.op, "const")) {
            try w.print("    {{\"op\": \"const\", \"value\": {d}}}{s}\n", .{ node.value, tail });
        } else if (eq(node.op, "col")) {
            try w.print("    {{\"op\": \"col\", \"name\": \"{s}\"}}{s}\n", .{ node.name, tail });
        } else if (eq(node.op, "neg")) {
            try w.print("    {{\"op\": \"neg\", \"args\": [{d}]}}{s}\n", .{ node.lhs, tail });
        } else {
            try w.print("    {{\"op\": \"{s}\", \"args\": [{d}, {d}]}}{s}\n", .{ node.op, node.lhs, node.rhs, tail });
        }
    }
    try w.writeAll("  ],\n");
}

fn writeSystem(
    w: Writer,
    comptime family: OpcodeFamily,
    names: []const []const u8,
    emitted: Emitted,
) !void {
    try w.print("{{\n  \"modulus\": {d},\n  \"family\": \"{s}\",\n", .{ MODULUS, @tagName(family) });
    try writeColumns(w, names, writtenPrefix(family, names), emitted.aliases);
    try writeNodes(w, emitted.nodes);

    // Alias definitions follow the extracted constraints, so the prefix of this
    // array is exactly what the differential compared against `Semantics(QM31)`.
    const total = emitted.constraints.len + emitted.aliases.len;
    var written: usize = 0;
    try w.writeAll("  \"constraints\": [");
    for (emitted.constraints) |c| {
        written += 1;
        try w.print("{d}{s}", .{ c, if (written == total) "" else ", " });
    }
    for (emitted.aliases) |alias| {
        written += 1;
        try w.print("{d}{s}", .{ alias.definition, if (written == total) "" else ", " });
    }

    try w.writeAll("],\n  \"lookups\": [\n");
    for (emitted.lookups, 0..) |request, i| {
        try w.print("    {{\"domain\": \"{s}\", \"numerator\": {d}, \"tuple\": [", .{ request.domain, request.numerator });
        for (request.tuple, 0..) |node, j| {
            try w.print("{d}{s}", .{ node, if (j + 1 == request.tuple.len) "" else ", " });
        }
        try w.print("]}}{s}\n", .{if (i + 1 == emitted.lookups.len) "" else ","});
    }
    try w.writeAll("  ],\n  \"notes\": \"extracted from Semantics(S) and Entries(S)\"\n}\n");
}

// Writes one JSON system per family for `scripts/air_uniqueness.py`.
test "uniqueness IR: emit every family" {
    const allocator = std.testing.allocator;
    const dir_path = "zig-out/uniqueness-ir";
    std.fs.cwd().makePath(dir_path) catch {};
    var dir = try std.fs.cwd().openDir(dir_path, .{});
    defer dir.close();

    inline for (comptime std.enums.values(OpcodeFamily)) |family| {
        const names = comptime columnNames(family);
        const emitted = try emit(family, allocator);
        defer freeEmitted(allocator, emitted);

        var out: std.ArrayList(u8) = .{};
        defer out.deinit(allocator);
        try writeSystem(out.writer(allocator), family, names, emitted);

        try dir.writeFile(.{ .sub_path = @tagName(family) ++ ".json", .data = out.items });
        std.debug.print("  {s: <14} {d: >3} columns  {d: >5} nodes  {d: >3} constraints\n", .{
            @tagName(family), names.len, emitted.nodes.len, emitted.constraints.len,
        });
    }
}
