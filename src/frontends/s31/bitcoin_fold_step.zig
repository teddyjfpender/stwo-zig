//! A fresh Bitcoin mainnet header step computed directly inside a recursive
//! circuit. It checks a claimed prior hash root, exact previous-hash bytes,
//! SHA256d, compact target and PoW, then returns the new hash root. A future
//! fold must authenticate `prior_root` from its verified child proof.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const sha256d = @import("sha256d.zig");
const bitcoin_target = @import("bitcoin_target.zig");
const poseidon2 = @import("poseidon2.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Var = circuit.builder.Var;
const NoValue = circuit.builder.NoValue;

fn hint(comptime V: type, value: u32) V {
    return circuit.builder.ivalue.fromQm31(V, QM31.fromBase(M31.fromCanonical(value)));
}

fn valueOf(comptime V: type, ctx: *circuit.builder.Context(V), wire: Var) u32 {
    return if (comptime V == QM31) ctx.get(wire).toM31Array()[0].toU32() else 0;
}

/// Unsigned little-endian comparison. The operands are already range-checked
/// u16 limbs. All integer equalities are below 2^18, hence inject into M31.
fn lessEqualU256(comptime V: type, ctx: *circuit.builder.Context(V), lhs: [16]Var, rhs: [16]Var) !Var {
    const base = try ctx.constant(QM31.fromBase(M31.fromCanonical(1 << 16)));
    var incoming = ctx.zero();
    var borrow_value: u32 = 0;
    for (lhs, rhs) |a, b| {
        const av = valueOf(V, ctx, a);
        const bv = valueOf(V, ctx, b);
        const digit_value = (bv + (1 << 16) - av - borrow_value) & 0xffff;
        const next: u32 = @intFromBool(bv < av + borrow_value);
        const digit = try ctx.guessU16(hint(V, digit_value));
        const outgoing = try ctx.guess(hint(V, next));
        try ctx.eq(try ctx.mul(outgoing, outgoing), outgoing);
        try ctx.eq(try ctx.add(b, try ctx.mul(outgoing, base)), try ctx.add(try ctx.add(a, incoming), digit));
        incoming = outgoing;
        borrow_value = next;
    }
    return ctx.sub(ctx.one(), incoming);
}

/// `prior_hash` and `header` are private values. Each limb is guessed as u16,
/// so the serialization and PoW comparison cannot use noncanonical bytes.
/// `authenticated_prior_root` must be wired to the child proof's verified
/// state claim by the caller; this kernel enforces the root equality itself.
pub fn constrainMainnetPowLinkStep(
    comptime V: type,
    ctx: *circuit.builder.Context(V),
    prior_hash_values: [16]V,
    header_values: [40]V,
    authenticated_prior_root: [8]Var,
) ![8]Var {
    return constrainPowLinkStep(V, ctx, prior_hash_values, header_values, authenticated_prior_root, false);
}

fn constrainPowLinkStep(
    comptime V: type,
    ctx: *circuit.builder.Context(V),
    prior_hash_values: [16]V,
    header_values: [40]V,
    authenticated_prior_root: [8]Var,
    comptime genesis_epoch: bool,
) ![8]Var {
    var prior_hash: [16]Var = undefined;
    var header: [40]Var = undefined;
    for (prior_hash_values, &prior_hash) |value, *wire| wire.* = try ctx.guessU16(value);
    for (header_values, &header) |value, *wire| wire.* = try ctx.guessU16(value);

    const computed_prior_root = try poseidon2.leafScalarCircuit(V, ctx, &prior_hash);
    for (computed_prior_root, authenticated_prior_root) |computed, claimed|
        try ctx.eq(computed, claimed);
    for (prior_hash, 0..) |word, i| try ctx.eq(header[i + 2], word);
    if (genesis_epoch) try constrainGenesisEpochBits(V, ctx, &header);

    const child_hash = try sha256d.hashHeader(V, ctx, &header);
    const target = try bitcoin_target.mainnetTarget(V, ctx, &header);
    try ctx.eq(try lessEqualU256(V, ctx, child_hash, target), ctx.one());
    return poseidon2.leafScalarCircuit(V, ctx, &child_hash);
}

/// Bitcoin mainnet keeps the genesis difficulty bits through block height
/// 2015. A fold starting at genesis can use this cheaper exact-field check
/// until the first retarget boundary at height 2016. The caller must enforce
/// the supported height bound in its sealed verification key.
pub fn constrainGenesisEpochBits(comptime V: type, ctx: *circuit.builder.Context(V), header: []const Var) !void {
    if (header.len != 40) return error.InvalidHeaderLength;
    try ctx.eq(header[36], try ctx.constant(QM31.fromBase(M31.fromCanonical(0xffff))));
    try ctx.eq(header[37], try ctx.constant(QM31.fromBase(M31.fromCanonical(0x1d00))));
}

pub fn constrainGenesisEpochPowLinkStep(
    comptime V: type,
    ctx: *circuit.builder.Context(V),
    prior_hash_values: [16]V,
    header_values: [40]V,
    authenticated_prior_root: [8]Var,
) ![8]Var {
    return constrainPowLinkStep(V, ctx, prior_hash_values, header_values, authenticated_prior_root, true);
}

test "genesis epoch bits equality rejects alternate compact targets" {
    for ([_]struct { bits: u32, valid: bool }{
        .{ .bits = 0x1d00ffff, .valid = true },
        .{ .bits = 0x1d00fffe, .valid = false },
        .{ .bits = 0x1c7fffff, .valid = false },
        .{ .bits = 0x1d010000, .valid = false },
    }) |case| {
        var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 1);
        defer ctx.deinit();
        var header = [_]Var{ctx.zero()} ** 40;
        header[36] = try ctx.guessU16(hint(QM31, case.bits & 0xffff));
        header[37] = try ctx.guessU16(hint(QM31, case.bits >> 16));
        try constrainGenesisEpochBits(QM31, &ctx, &header);
        try ctx.setOutputs(&.{header[36]});
        try ctx.finalize(false);
        try std.testing.expectEqual(case.valid, try ctx.isCircuitValid());
    }
}

test "direct fold unsigned comparison handles equality and limb borrows" {
    const Case = struct { lhs: [16]u16, rhs: [16]u16, expected: u32 };
    const zero = [_]u16{0} ** 16;
    const cases = [_]Case{
        .{ .lhs = zero, .rhs = zero, .expected = 1 },
        .{ .lhs = [1]u16{5} ++ [_]u16{0} ** 15, .rhs = [1]u16{4} ++ [_]u16{0} ** 15, .expected = 0 },
        .{ .lhs = [2]u16{ 0, 1 } ++ [_]u16{0} ** 14, .rhs = [1]u16{65535} ++ [_]u16{0} ** 15, .expected = 0 },
        .{ .lhs = [1]u16{65535} ++ [_]u16{0} ** 15, .rhs = [2]u16{ 0, 1 } ++ [_]u16{0} ** 14, .expected = 1 },
        .{ .lhs = [_]u16{65535} ** 16, .rhs = [_]u16{65535} ** 16, .expected = 1 },
    };
    for (cases) |case| {
        var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 1);
        defer ctx.deinit();
        var left: [16]Var = undefined;
        var right: [16]Var = undefined;
        for (case.lhs, &left) |word, *wire| wire.* = try ctx.guessU16(hint(QM31, word));
        for (case.rhs, &right) |word, *wire| wire.* = try ctx.guessU16(hint(QM31, word));
        const result = try lessEqualU256(QM31, &ctx, left, right);
        try ctx.setOutputs(&.{result});
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
        try std.testing.expectEqual(hint(QM31, case.expected), ctx.value_table.items[result.idx]);
    }
}

test "direct recursive header kernel proves genesis-to-block-one link and PoW" {
    const old_u16 = [16]u32{ 57967, 2700, 61878, 29363, 42689, 18082, 25518, 20471, 7827, 25987, 23265, 39944, 54888, 25, 0, 0 };
    const header_u16 = [40]u32{ 1, 0, 57967, 2700, 61878, 29363, 42689, 18082, 25518, 20471, 7827, 25987, 23265, 39944, 54888, 25, 0, 0, 8344, 64849, 19230, 17575, 48827, 3688, 60959, 26388, 41339, 50083, 2900, 45559, 46797, 59398, 9047, 3646, 48225, 18790, 65535, 7424, 58113, 39266 };
    const old_root_u32 = [8]u32{ 93892305, 397617766, 1762064199, 2128125525, 211345822, 958247097, 595994426, 1074837273 };
    const new_root_u32 = [8]u32{ 1230097977, 338045265, 582454319, 1194138423, 159136005, 2049036807, 17165835, 883545160 };
    var old_values: [16]QM31 = undefined;
    var header_values: [40]QM31 = undefined;
    for (old_u16, &old_values) |word, *value| value.* = hint(QM31, word);
    for (header_u16, &header_values) |word, *value| value.* = hint(QM31, word);

    var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 8);
    defer ctx.deinit();
    var prior_root: [8]Var = undefined;
    for (old_root_u32, &prior_root) |word, *wire| wire.* = try ctx.guessM31(hint(QM31, word));
    const new_root = try constrainMainnetPowLinkStep(QM31, &ctx, old_values, header_values, prior_root);
    try ctx.setOutputs(&new_root);
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
    for (new_root, new_root_u32) |wire, want| try std.testing.expectEqual(hint(QM31, want), ctx.value_table.items[wire.idx]);

    const original = ctx.value_table.items[prior_root[0].idx];
    ctx.value_table.items[prior_root[0].idx] = hint(QM31, old_root_u32[0] + 1);
    try std.testing.expect(!try ctx.isCircuitValid());
    ctx.value_table.items[prior_root[0].idx] = original;
    try std.testing.expect(try ctx.isCircuitValid());

    // Recompute the claimed root for a forged predecessor. Every hash and
    // PoW value remains valid; only the serialized prev-hash link can fail.
    var forged_values = old_values;
    forged_values[0] = hint(QM31, old_u16[0] ^ 1);
    var forged_host: [16]M31 = undefined;
    for (old_u16, &forged_host) |word, *value| value.* = M31.fromCanonical(word);
    forged_host[0] = M31.fromCanonical(old_u16[0] ^ 1);
    const forged_root = poseidon2.leafWords(&forged_host);
    var wrong_ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 8);
    defer wrong_ctx.deinit();
    var wrong_root_wires: [8]Var = undefined;
    for (forged_root, &wrong_root_wires) |word, *wire| wire.* = try wrong_ctx.guessM31(QM31.fromBase(word));
    const wrong_output = try constrainMainnetPowLinkStep(QM31, &wrong_ctx, forged_values, header_values, wrong_root_wires);
    try wrong_ctx.setOutputs(&wrong_output);
    try wrong_ctx.finalize(false);
    try std.testing.expect(!try wrong_ctx.isCircuitValid());

    var topology = try circuit.builder.Context(NoValue).init(std.testing.allocator, 8);
    defer topology.deinit();
    var empty_root: [8]Var = undefined;
    for (&empty_root) |*wire| wire.* = try topology.guessM31(.{});
    const empty_output = try constrainMainnetPowLinkStep(NoValue, &topology, [_]NoValue{.{}} ** 16, [_]NoValue{.{}} ** 40, empty_root);
    try topology.setOutputs(&empty_output);
    try topology.finalize(false);
    try std.testing.expectEqual(ctx.circuit.n_vars, topology.circuit.n_vars);
    try std.testing.expectEqualDeep(ctx.circuit.add.items, topology.circuit.add.items);
    try std.testing.expectEqualDeep(ctx.circuit.sub.items, topology.circuit.sub.items);
    try std.testing.expectEqualDeep(ctx.circuit.mul.items, topology.circuit.mul.items);
    try std.testing.expectEqualDeep(ctx.circuit.eq.items, topology.circuit.eq.items);
    try std.testing.expectEqualDeep(ctx.circuit.m31_to_u32.items, topology.circuit.m31_to_u32.items);
    try std.testing.expectEqualDeep(ctx.circuit.output.items, topology.circuit.output.items);
    try std.testing.expectEqualDeep(ctx.circuit.pointwise_mul.items, topology.circuit.pointwise_mul.items);
    try std.testing.expectEqual(@as(usize, 0), ctx.circuit.triple_xor.items.len);
    try std.testing.expectEqual(@as(usize, 0), ctx.circuit.blake_g_gate.items.len);
}
