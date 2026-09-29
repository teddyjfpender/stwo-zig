//! The small test circuits of `crates/circuit_prover/src/prover_test.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230), as the oracle's
//! `tools/stwo-circuit-oracle-rs/src/contexts.rs` transcribes them. R5
//! (finalization and padding) and R7 (proofs) build the same circuits, so
//! this is their one definition.
//!
//! Each build is generic over the value type: `QM31` (value mode, where the
//! `prover_test.rs` value snapshots are checked) and `NoValue` (topology
//! mode, which must emit the same gates).

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");

const QM31 = core.fields.qm31.QM31;
const builder = circuit.builder;
const ivalue = builder.ivalue;
const wrappers = builder.wrappers;
const Var = builder.Var;
const U32Wrapper = wrappers.U32Wrapper;
const N_RESERVED = circuit.common.component_list.N_RESERVED;

pub const TestContext = enum {
    fibonacci,
    permutation,
    blake,
    triple_xor,
    m31_to_u32,
    blake_g_gate,

    pub const all = std.enums.values(TestContext);

    pub fn nReserved(self: TestContext) usize {
        return switch (self) {
            .permutation, .blake => 0,
            else => N_RESERVED,
        };
    }
};

pub const Error = builder.context.Error || error{ OutputCountMismatch, SnapshotMismatch };

/// `TestContext::context`: a fresh context holding the circuit. `blake` runs
/// with `assert_eq_on_eval`, as upstream.
pub fn build(comptime V: type, gpa: std.mem.Allocator, which: TestContext) Error!builder.Context(V) {
    var ctx = try builder.Context(V).init(gpa, which.nReserved());
    errdefer ctx.deinit();
    switch (which) {
        .fibonacci => try fibonacci(V, &ctx),
        .permutation => try permutation(V, &ctx),
        .blake => {
            ctx.assert_eq_on_eval = true;
            try blake(V, &ctx);
        },
        .triple_xor => try tripleXor(V, &ctx),
        .m31_to_u32 => try m31ToU32(V, &ctx),
        .blake_g_gate => try blakeGGate(V, &ctx),
    }
    return ctx;
}

fn value(comptime V: type, a: u32, b: u32, c: u32, d: u32) V {
    return ivalue.fromQm31(V, ivalue.qm31FromU32s(a, b, c, d));
}

/// Checks a value snapshot of `prover_test.rs` (value mode only).
fn expectValue(comptime V: type, ctx: *const builder.Context(V), v: Var, expected: QM31) Error!void {
    if (V != QM31) return;
    if (!ctx.get(v).eql(expected)) return error.SnapshotMismatch;
}

fn guessU32(comptime V: type, ctx: *builder.Context(V), word: u32) Error!U32Wrapper(Var) {
    return wrappers.guessU32(V, ctx, wrappers.u32Value(V, word));
}

/// `set_digest_outputs`: cycles `words` through the reserved output wires.
fn setDigestOutputs(comptime V: type, ctx: *builder.Context(V), words: []const U32Wrapper(Var)) Error!void {
    var outputs: [N_RESERVED]Var = undefined;
    for (&outputs, 0..) |*out, i| out.* = words[i % words.len].get();
    try ctx.setOutputs(&outputs);
}

fn fibonacci(comptime V: type, ctx: *builder.Context(V)) Error!void {
    var a = try ctx.guess(value(V, 0, 0, 0, 0));
    var b = try ctx.guess(value(V, 1, 0, 0, 0));
    for (2..1030) |_| {
        const next = try ctx.add(a, b);
        a = b;
        b = next;
    }
    try expectValue(V, ctx, b, QM31.fromU32Unchecked(809871181, 0, 0, 0));
    const out = try builder.blake.m31ToU32(V, ctx, b);
    try setDigestOutputs(V, ctx, &.{out});
}

fn permutation(comptime V: type, ctx: *builder.Context(V)) Error!void {
    const a = try ctx.guess(value(V, 0, 2, 0, 2));
    const b = try ctx.guess(value(V, 1, 1, 1, 1));
    const first = try ctx.permute(&.{ a, b }, ivalue.sortByUCoordinate(V));
    const copy = [_]Var{ first[0], first[1] };
    _ = try ctx.permute(&copy, ivalue.sortByUCoordinate(V));
}

fn blake(comptime V: type, ctx: *builder.Context(V)) Error!void {
    var inputs: [9]Var = undefined;
    for (&inputs, 0..) |*input, i| {
        const base: u32 = @intCast(4 * i + 82);
        input.* = try ctx.guess(value(V, base, base + 1, base + 2, base + 3));
    }
    for (0..15) |_| {
        const output = try builder.blake.blake2sM31(V, ctx, &inputs, 9 * 16);
        _ = try ctx.add(output.low, output.high);
    }
}

fn tripleXor(comptime V: type, ctx: *builder.Context(V)) Error!void {
    const cases = [_][3]u32{
        .{ 42, 17, 55 },
        .{ 0x10000, 0x20000, 0x30001 },
        .{ 0x30005, 0x10007, 0x4000b },
    };
    const expected = [_]QM31{
        QM31.fromU32Unchecked(12, 0, 0, 0),
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(9, 6, 0, 0),
    };
    var out: U32Wrapper(Var) = undefined;
    for (cases, expected) |case, want| {
        const a = try guessU32(V, ctx, case[0]);
        const b = try guessU32(V, ctx, case[1]);
        const c = try guessU32(V, ctx, case[2]);
        out = try builder.blake.tripleXor(V, ctx, a, b, c);
        try expectValue(V, ctx, out.get(), want);
    }
    try setDigestOutputs(V, ctx, &.{out});
}

fn m31ToU32(comptime V: type, ctx: *builder.Context(V)) Error!void {
    const cases = [_]u32{ 42, 100_000, 2_000_042 };
    const expected = [_]QM31{
        QM31.fromU32Unchecked(42, 0, 0, 0),
        QM31.fromU32Unchecked(34464, 1, 0, 0),
        QM31.fromU32Unchecked(33962, 30, 0, 0),
    };
    var outs: [3]U32Wrapper(Var) = undefined;
    for (cases, expected, &outs) |case, want, *out| {
        const input = try ctx.guess(value(V, case, 0, 0, 0));
        out.* = try builder.blake.m31ToU32(V, ctx, input);
        try expectValue(V, ctx, out.get(), want);
    }
    try setDigestOutputs(V, ctx, &outs);
}

fn blakeGGate(comptime V: type, ctx: *builder.Context(V)) Error!void {
    const words = [_]u32{ 305419896, 4294967295, 2147483647, 123456789, 987654321, 468798 };
    var in: [6]U32Wrapper(Var) = undefined;
    for (&in, words) |*wire, word| wire.* = try guessU32(V, ctx, word);
    const outs = try builder.blake.blakeGGate(V, ctx, in[0], in[1], in[2], in[3], in[4], in[5]);
    const expected = [_]QM31{
        QM31.fromU32Unchecked(49809, 43146, 0, 0),
        QM31.fromU32Unchecked(53691, 63264, 0, 0),
        QM31.fromU32Unchecked(464, 51992, 0, 0),
        QM31.fromU32Unchecked(46984, 55514, 0, 0),
    };
    for (outs, expected) |out, want| try expectValue(V, ctx, out.get(), want);
    try setDigestOutputs(V, ctx, &outs);
}
