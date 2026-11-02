//! Composition IR export cases: truths (see catalog.zig for the pattern).
//! Every adapter below reproduces the mask slicing of the component's own
//! domain evaluator (component-local columns, signed row offsets) and calls
//! the same generic emit function that evaluator runs natively.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const R = @import("record.zig");
const K = @import("case.zig");
const Lane = R.Lane;
const Sink = R.Sink;
const Q = R.Q;
const Case = K.Case;
const caseWith = K.caseWith;

const KC = A.crypto.keccak;
const S = A.crypto.secp256k1;
const SH = A.crypto.sha256;
const AR = A.crypto.arith256;
const CV = A.crypto.curves;
const BYTE = A.providers.byte;
const RANGE = A.range.provider;

fn in(tree: u8, column: usize, offset: i8) Lane {
    return Lane.input(tree, column, offset);
}
/// Four consecutive base columns as one secure value (`secureAt` natively).
fn sec(tree: u8, column: usize, offset: i8) Lane {
    return A.evaluation.secureFromCoordinatesFor(Lane, .{ in(tree, column, offset), in(tree, column + 1, offset), in(tree, column + 2, offset), in(tree, column + 3, offset) });
}

// ---------------------------------------------------------------- Keccak

/// Mirrors `parallel.zig`/`packed_rows.zig`: fixed and MAIN at row 0, the
/// 1600 state columns also at MASK_OFFSETS -2,-1,+1,+2, the three header
/// columns from ACTIVE_A at -1, every batch at 0 and the last batch at -1.
fn keccakEmit(a: std.mem.Allocator, c: *const KC.component.Component, sink: *Sink) anyerror!void {
    const L = KC.layout;
    const inter = c.interactionCount();
    const previous = sec(2, inter - 4, -1);
    if (c.kind != .permutation) {
        var tuple: [6]Lane = undefined;
        for (&tuple, 0..) |*v, col| v.* = in(0, col, 0);
        sink.emit(KC.component.tableResidualFor(Lane, c, &tuple, in(0, 6, 0), in(1, 0, 0), sec(2, 0, 0), previous));
        return;
    }
    const scratch = try a.create(KC.component.ScratchFor(Lane));
    defer a.destroy(scratch);
    for (&scratch.fixed, 0..) |*v, col| v.* = in(0, col, 0);
    for (&scratch.main, 0..) |*v, col| v.* = in(1, col, 0);
    for (&scratch.shifted, L.MASK_OFFSETS[1..]) |*state, offset| for (state, 0..) |*v, col| {
        v.* = in(1, col, @intCast(offset));
    };
    for (&scratch.previous_header, 0..) |*v, j| v.* = in(1, L.ACTIVE_A + j, -1);
    const batches = c.policy.batches();
    for (scratch.interaction[0..batches], 0..) |*v, b| v.* = sec(2, 4 * b, 0);
    KC.equations.emitForPolicy(Lane, c.policy, scratch.row(), scratch.interaction[0..batches], previous, c.claim, c.challenges, .{ .calls = c.calls, .first_id = c.first_call_id }, sink);
}

fn keccakCase(a: std.mem.Allocator, rng: std.Random, comptime policy: KC.equations.BatchPolicy, comptime kind: KC.component.Kind) !Case {
    const log: u32 = switch (kind) {
        .permutation => @max(5, try KC.layout.logSizeFor(policy.geometry(), 1)),
        .chi => policy.tableLog(.chi),
        .xor5 => policy.tableLog(.xor5),
    };
    var c = KC.component.Component{ .kind = kind, .log_size = log, .calls = if (kind == .permutation) 1 else 0, .first_call_id = 1, .challenges = std.mem.zeroes(KC.equations.Challenges), .claim = R.randomQ(rng), .policy = policy };
    R.randomize(&c.challenges, rng);
    return fromKeccak(a, c);
}
/// Any Keccak truth instance (offsets zeroed by the caller).
pub fn fromKeccak(a: std.mem.Allocator, c: KC.component.Component) !Case {
    const name = switch (c.kind) {
        inline else => |kind| switch (c.policy) {
            inline else => |policy| "keccak." ++ @tagName(kind) ++ "." ++ @tagName(policy),
        },
    };
    const widths = [3]usize{ c.fixedCount(), c.mainCount(), c.interactionCount() };
    return caseWith(a, KC.component.Component, name, "keccak", c, widths, keccakEmit);
}

// ---------------------------------------------------------------- secp

fn secpEmit(_: std.mem.Allocator, c: *const S.component.Component, sink: *Sink) anyerror!void {
    const L = S.layout;
    const width = L.main(c.kind);
    const inter = L.interactionFor(c.kind, c.byte_policy);
    const batches = L.batchesFor(c.kind, c.byte_policy);
    var fixed: [L.FIXED]Lane = undefined;
    for (&fixed, 0..) |*v, col| v.* = in(0, col, 0);
    var main: [319]Lane = undefined;
    for (main[0..width], 0..) |*v, col| v.* = in(1, col, 0);
    var current: [96]Lane = undefined;
    for (current[0..batches], 0..) |*v, b| v.* = sec(2, 4 * b, 0);
    S.equations.emitGenericForPolicy(Lane, c.kind, c.byte_policy, c.program, .{ .fixed = &fixed, .main = main[0..width], .previous_active = in(1, 0, -1), .previous_id = in(1, L.base(c.kind), -1) }, current[0..batches], sec(2, inter - 4, -1), c.claim, c.challenges, c.public, sink);
}

fn secpCase(a: std.mem.Allocator, rng: std.Random, comptime program: S.program.Kind, comptime kind: S.layout.Kind) !Case {
    const policy = S.layout.BytePolicy.canonical_inputs;
    const p = S.program.get(program);
    var c = S.component.Component{ .kind = kind, .byte_policy = policy, .program = p, .log_size = try S.layout.logSize(kind, p, 1), .public = .{ .calls = 1, .first_id = 1 }, .challenges = std.mem.zeroes(S.equations.Challenges), .claim = R.randomQ(rng) };
    R.randomize(&c.challenges, rng);
    return fromSecp(a, c);
}
/// Any secp truth arithmetic instance (product or linear; offsets zeroed).
pub fn fromSecp(a: std.mem.Allocator, c: S.component.Component) !Case {
    const program: []const u8 = inline for (comptime std.meta.tags(S.program.Kind)) |k| {
        if (c.program == S.program.get(k)) break @tagName(k);
    } else "custom";
    const name = switch (c.kind) {
        inline else => |kind| switch (c.byte_policy) {
            inline else => |policy| if (std.mem.eql(u8, program, "add")) "secp.add." ++ @tagName(kind) ++ "." ++ @tagName(policy) else if (std.mem.eql(u8, program, "double")) "secp.double." ++ @tagName(kind) ++ "." ++ @tagName(policy) else "secp.custom." ++ @tagName(kind) ++ "." ++ @tagName(policy),
        },
    };
    const widths = [3]usize{ S.layout.FIXED, S.layout.main(c.kind), S.layout.interactionFor(c.kind, c.byte_policy) };
    return caseWith(a, S.component.Component, name, "secp", c, widths, secpEmit);
}

/// Mirrors the byte provider's domain loop: (value, first, last) fixed,
/// multiplicity, inverse batch at 0 and the running sum at 0 and -1.
fn byteEmit(_: std.mem.Allocator, c: *const BYTE.Component, sink: *Sink) anyerror!void {
    for (RANGE.evaluateFor(Lane, in(0, 0, 0), in(0, 1, 0), in(0, 2, 0), in(1, 0, 0), sec(2, 0, 0), sec(2, 4, 0), sec(2, 4, -1), c.claim, c.alpha)) |r| sink.emit(r);
}

fn byteCase(a: std.mem.Allocator, rng: std.Random) !Case {
    return fromByte(a, .{ .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .alpha = R.randomQ(rng), .claim = R.randomQ(rng) });
}
/// Any byte provider instance (offsets zeroed by the caller).
pub fn fromByte(a: std.mem.Allocator, c: BYTE.Component) !Case {
    return caseWith(a, BYTE.Component, "secp.bytes", "secp", c, .{ 3, 1, 8 }, byteEmit);
}

// ------------------------------------------- SHA-256, arith256, curves, rows

/// Mask view of the degree-3/4 row truths (SHA-256, arith256_mod, curve and
/// secp row truths): every column at 0, ACTIVE at -1, and the cumulative
/// interaction columns the equations ask for at -1.
fn RowView(comptime active: usize) type {
    return struct {
        pub fn fixed(_: *const @This(), c: usize) Lane {
            return in(0, c, 0);
        }
        pub fn main(_: *const @This(), c: usize) Lane {
            return in(1, c, 0);
        }
        pub fn previousActive(_: *const @This()) Lane {
            return in(1, active, -1);
        }
        pub fn interaction(_: *const @This(), c: usize) Lane {
            return in(2, c, 0);
        }
        pub fn previousInteraction(_: *const @This(), c: usize) Lane {
            return in(2, c, -1);
        }
    };
}

fn shaEmit(_: std.mem.Allocator, c: *const SH.component.Component, sink: *Sink) anyerror!void {
    const view = RowView(SH.layout.ACTIVE){};
    SH.equations.emit(Lane, &view, c.public, c.claim, c.wire, sink);
}
fn shaCase(a: std.mem.Allocator, rng: std.Random) !Case {
    var c = SH.component.Component{ .log_size = try SH.layout.logSize(1), .public = .{ .calls = 1, .first_id = 1 }, .claim = R.randomQ(rng), .wire = std.mem.zeroes(SH.equations.Wire) };
    R.randomize(&c.wire, rng);
    return fromSha(a, c);
}
pub fn fromSha(a: std.mem.Allocator, c: SH.component.Component) !Case {
    return caseWith(a, SH.component.Component, "sha256", "sha256", c, SH.layout.widths(), shaEmit);
}

fn arithEmit(_: std.mem.Allocator, c: *const AR.component.Component, sink: *Sink) anyerror!void {
    const view = RowView(AR.layout.ACTIVE){};
    AR.equations.emit(Lane, &view, c.public, c.claim, c.challenges, sink);
}
fn arithCase(a: std.mem.Allocator, rng: std.Random) !Case {
    var c = AR.component.Component{ .log_size = try AR.layout.logSize(1), .public = .{ .calls = 1, .first_id = 1 }, .claim = R.randomQ(rng), .challenges = std.mem.zeroes(AR.equations.Challenges) };
    R.randomize(&c.challenges, rng);
    return fromArith(a, c);
}
pub fn fromArith(a: std.mem.Allocator, c: AR.component.Component) !Case {
    return caseWith(a, AR.component.Component, "arith256_mod", "arith256_mod", c, AR.layout.widths(), arithEmit);
}

/// Builder for one curve/field op (`CV.Op`) or secp row kind (`SecpKind`):
/// both are `CV.Component(op)` and share the row-truth equations.
fn Curve(comptime op: anytype) type {
    return struct {
        const T = CV.Component(op);
        const name = (if (@TypeOf(op) == CV.spec.SecpKind) "secp_row." else "curve.") ++ @tagName(op);
        const group = if (@TypeOf(op) == CV.spec.SecpKind) "secp_row" else "curve";
        fn run(_: std.mem.Allocator, c: *const T, sink: *Sink) anyerror!void {
            const view = RowView(T.L.ACTIVE){};
            T.Eq.emit(Lane, &view, c.public, c.claim, c.challenges, sink);
        }
        /// Any instance of this op's truth (offsets zeroed by the caller).
        pub fn from(a: std.mem.Allocator, c: T) !Case {
            return caseWith(a, T, name, group, c, T.L.widths(), run);
        }
        fn random(a: std.mem.Allocator, rng: std.Random) !Case {
            var c = T{ .log_size = try T.L.logSize(1), .public = .{ .calls = 1, .first_id = 1 }, .claim = R.randomQ(rng), .challenges = std.mem.zeroes(CV.equations.Challenges) };
            R.randomize(&c.challenges, rng);
            return from(a, c);
        }
    };
}
const curve_ops = std.meta.tags(CV.Op);
const secp_rows = std.meta.tags(CV.spec.SecpKind);

/// One `.{ T, fromT }` per distinct component type whose `asProverComponent`
/// a v3 truth proof uses (union rosters: the inner type the handle borrows).
pub const handlers = .{
    .{ KC.component.Component, fromKeccak },
    .{ S.component.Component, fromSecp },
    .{ BYTE.Component, fromByte },
    .{ SH.component.Component, fromSha },
    .{ AR.component.Component, fromArith },
    .{ CV.Component(CV.Op.bn254_g1_add), Curve(CV.Op.bn254_g1_add).from },
    .{ CV.Component(CV.Op.bn254_g1_double), Curve(CV.Op.bn254_g1_double).from },
    .{ CV.Component(CV.Op.bn254_fp2_mul), Curve(CV.Op.bn254_fp2_mul).from },
    .{ CV.Component(CV.Op.bls12_381_fp2_mul), Curve(CV.Op.bls12_381_fp2_mul).from },
    .{ CV.Component(CV.Op.arith384_mont), Curve(CV.Op.arith384_mont).from },
    .{ CV.Component(CV.Op.bls12_381_g1_add), Curve(CV.Op.bls12_381_g1_add).from },
    .{ CV.Component(CV.Op.bls12_381_g1_double), Curve(CV.Op.bls12_381_g1_double).from },
    .{ CV.Component(CV.spec.SecpKind.add), Curve(CV.spec.SecpKind.add).from },
    .{ CV.Component(CV.spec.SecpKind.double), Curve(CV.spec.SecpKind.double).from },
};
comptime {
    // Every curve op and secp row kind has exactly one handler above.
    if (handlers.len != 5 + curve_ops.len + secp_rows.len) @compileError("truth handler roster drifted");
}

/// Appends one sample case per exported component kind/layout.
pub fn all(a: std.mem.Allocator, rng: std.Random, out: *std.ArrayList(Case)) !void {
    // Keccak: permutation for every v3 batch policy; the chi/xor5 tables
    // depend on the policy only through their (fixed) log size.
    inline for (.{ .triple_v2, .throughput_v1, .throughput_quartet_v1, .throughput_r27_v1 }) |policy| {
        try out.append(a, try keccakCase(a, rng, policy, .permutation));
    }
    try out.append(a, try keccakCase(a, rng, .triple_v2, .chi));
    try out.append(a, try keccakCase(a, rng, .triple_v2, .xor5));
    try out.append(a, try keccakCase(a, rng, .throughput_v1, .xor5));
    try out.append(a, try keccakCase(a, rng, .throughput_v1, .chi));
    // secp truth: product/linear per program, plus its byte provider.
    inline for (.{ .add, .double }) |program| inline for (.{ .product, .linear }) |kind| {
        try out.append(a, try secpCase(a, rng, program, kind));
    };
    try out.append(a, try byteCase(a, rng));
    try out.append(a, try shaCase(a, rng));
    try out.append(a, try arithCase(a, rng));
    inline for (curve_ops) |op| try out.append(a, try Curve(op).random(a, rng));
    inline for (secp_rows) |kind| try out.append(a, try Curve(kind).random(a, rng));
}
