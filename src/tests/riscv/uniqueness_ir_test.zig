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

const Lookup = struct {
    domain: []const u8,
    numerator: u32,
    tuple: []const u32,
};

const Emitted = struct {
    nodes: []const Node,
    constraints: []const u32,
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

    return .{
        .nodes = try arena.toOwnedSlice(arena_allocator),
        .constraints = constraints,
        .lookups = lookups,
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

test "uniqueness IR: the emitted system agrees with the committed AIR" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(SEED);
    const random = prng.random();

    var checked: usize = 0;
    inline for (comptime std.enums.values(OpcodeFamily)) |family| {
        const names = comptime columnNames(family);
        const emitted = try emit(family, allocator);
        defer allocator.free(emitted.nodes);
        defer allocator.free(emitted.constraints);
        defer {
            for (emitted.lookups) |request| allocator.free(request.tuple);
            allocator.free(emitted.lookups);
        }

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

// Writes one JSON system per family for `scripts/air_uniqueness.py`.
//
// Lookup requests are NOT emitted yet, and the omission is deliberate and
// one-directional: without range-table membership the admitted witness set is
// strictly larger, so the query is weaker. An UNSAT verdict therefore still
// holds for the real AIR, while a SAT counterexample may be excluded by a range
// check this system does not carry and must be triaged against
// `row_admissibility` before it is called a bug.
test "uniqueness IR: emit every family" {
    const allocator = std.testing.allocator;
    const dir_path = "zig-out/uniqueness-ir";
    std.fs.cwd().makePath(dir_path) catch {};
    var dir = try std.fs.cwd().openDir(dir_path, .{});
    defer dir.close();

    inline for (comptime std.enums.values(OpcodeFamily)) |family| {
        const names = comptime columnNames(family);
        const prefix = writtenPrefix(family, names);
        const emitted = try emit(family, allocator);
        defer allocator.free(emitted.nodes);
        defer allocator.free(emitted.constraints);
        defer {
            for (emitted.lookups) |request| allocator.free(request.tuple);
            allocator.free(emitted.lookups);
        }

        var out: std.ArrayList(u8) = .{};
        defer out.deinit(allocator);
        const w = out.writer(allocator);

        try w.print("{{\n  \"modulus\": {d},\n  \"family\": \"{s}\",\n  \"columns\": [\n", .{ MODULUS, @tagName(family) });
        for (names, 0..) |name, i| {
            try w.print("    {{\"name\": \"{s}\", \"role\": \"{s}\"}}{s}\n", .{
                name, roleOf(name, prefix), if (i + 1 == names.len) "" else ",",
            });
        }
        try w.writeAll("  ],\n  \"nodes\": [\n");
        for (emitted.nodes, 0..) |node, i| {
            const tail = if (i + 1 == emitted.nodes.len) "" else ",";
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
        try w.writeAll("  ],\n  \"constraints\": [");
        for (emitted.constraints, 0..) |c, i| {
            try w.print("{d}{s}", .{ c, if (i + 1 == emitted.constraints.len) "" else ", " });
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

        try dir.writeFile(.{ .sub_path = @tagName(family) ++ ".json", .data = out.items });
        std.debug.print("  {s: <14} {d: >3} columns  {d: >5} nodes  {d: >3} constraints\n", .{
            @tagName(family), names.len, emitted.nodes.len, emitted.constraints.len,
        });
    }
}
