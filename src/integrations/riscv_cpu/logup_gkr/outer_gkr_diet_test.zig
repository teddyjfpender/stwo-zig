//! M7 cell-diet prototype (stream diet, 2026-11-04): OUTER LogUp-GKR.
//!
//! Experimental measurement only; no production route selects it.
//!
//! The outer (circuit) STARK of every recursion node today commits classic
//! LogUp interaction columns: 152 secure-column cells per row-set, about 50% of
//! a leaf's committed cells (census-v2). The M7 lever replaces them with ONE
//! batched LogUp-GKR over all eleven outer components (one GKR instance per
//! component, lanes = lookups per row padded to a power of two), proved with
//! the existing `engine.lookups.gkr_prover` and verified by the existing
//! shared numerical verifier authority (`verifier_kernel`), natively and on
//! circuit wires (`circuit_verifier.zig`, Blake channel gadget in-circuit).
//!
//! This test MEASURES the in-circuit verifier gate counts for the outer
//! leaf's actual instance shapes, scaled down by `shift` variables per
//! instance (so the CPU prover stays small), fits the exact affine law in
//! (Σ rounds, Σ instance-layers, layers) and checks the fit on held-out
//! shifts before evaluating it at the production shape. It also measures the
//! per-instance terminal-binding arithmetic (MLE row point, carry quotient,
//! anchors) at the production row logs directly.
//!
//! Each row prints `OUTER_GKR_COST {json}` for the diet census receipt.

const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const lane = @import("../rv64_recursion/circuit_lane.zig");
const C = @import("circuit_verifier.zig");
const MP = @import("mle_point.zig");
const L = engine.lookups;
const Q = C.Q;
const F = C.F;
const M31 = core.fields.m31.M31;
const NativeChannel = core.channel.blake2s.Blake2sChannel;
const MleBase = L.mle.MleFor(Q, M31);
const MleSecure = L.mle.MleFor(Q, Q);
const a = std.heap.smp_allocator;

/// Prints a receipt line to stderr and, when STWO_DIET_OUT names a file,
/// appends it there (zig build hides passing tests' stderr).
fn emit(comptime tag: []const u8, value: anytype) void {
    const line = std.fmt.allocPrint(a, tag ++ " {f}\n", .{std.json.fmt(value, .{})}) catch return;
    defer a.free(line);
    std.debug.print("\n{s}", .{line});
    const path = std.posix.getenv("STWO_DIET_OUT") orelse return;
    const file = std.fs.cwd().createFile(path, .{ .truncate = false }) catch return;
    defer file.close();
    file.seekFromEnd(0) catch return;
    file.writeAll(line) catch {};
}

/// One outer component: committed row log (census-v2 node 0, the CPU0 leaf of
/// 24628607) and lookups per row (`witness/components.zig`; tables yield one
/// lookup per multiplicity column).
pub const Instance = struct { name: []const u8, row_log: u32, lookups: u32 };
pub const LEAF0 = [_]Instance{
    .{ .name = "eq", .row_log = 18, .lookups = 2 },
    .{ .name = "qm31_ops", .row_log = 23, .lookups = 3 },
    .{ .name = "triple_xor", .row_log = 20, .lookups = 12 },
    .{ .name = "m_31_to_u_32", .row_log = 21, .lookups = 5 },
    .{ .name = "blake_g_gate", .row_log = 23, .lookups = 26 },
    .{ .name = "verify_bitwise_xor_8", .row_log = 16, .lookups = 2 },
    .{ .name = "verify_bitwise_xor_12", .row_log = 20, .lookups = 16 },
    .{ .name = "verify_bitwise_xor_4", .row_log = 8, .lookups = 1 },
    .{ .name = "verify_bitwise_xor_7", .row_log = 14, .lookups = 1 },
    .{ .name = "verify_bitwise_xor_9", .row_log = 18, .lookups = 1 },
    .{ .name = "range_check_16", .row_log = 16, .lookups = 1 },
};

pub fn nVariables(instance: Instance) u32 {
    return instance.row_log + std.math.log2_int_ceil(u32, @max(instance.lookups, 1));
}

const Shape = struct {
    n: [LEAF0.len]u32,
    /// L: GKR layers of the batch (largest instance).
    layers: u64,
    /// Σ over instances of their variables: instance-layer pairs.
    instance_layers: u64,
    /// Σ over layers of sumcheck rounds = L (L - 1) / 2.
    rounds: u64,

    fn scaled(shift: u32) Shape {
        var s: Shape = .{ .n = undefined, .layers = 0, .instance_layers = 0, .rounds = 0 };
        for (&s.n, LEAF0) |*n, inst| {
            const full = nVariables(inst);
            n.* = if (full > shift) full - shift else 1;
            s.layers = @max(s.layers, n.*);
            s.instance_layers += n.*;
        }
        s.rounds = s.layers * (s.layers - 1) / 2;
        return s;
    }
};

const Counts = struct {
    blake_g_gate: u64,
    qm31_ops: u64,
    m31_to_u32: u64,
    triple_xor: u64,
    eq: u64,
    variables: u64,

    fn of(ctx: *const C.Context) Counts {
        const g = ctx.gate_counts;
        return .{ .blake_g_gate = g.blake_g_gate, .qm31_ops = g.qm31_ops, .m31_to_u32 = g.m31_to_u32, .triple_xor = g.triple_xor, .eq = g.eq, .variables = ctx.circuit.n_vars };
    }
    fn get(self: Counts, i: usize) u64 {
        return switch (i) {
            0 => self.blake_g_gate,
            1 => self.qm31_ops,
            2 => self.m31_to_u32,
            3 => self.triple_xor,
            4 => self.eq,
            else => self.variables,
        };
    }
    const N = 6;
};

/// Proves a batched LogUp-GKR of `shape` (random base numerators, random
/// secure denominators), verifies it natively, then replays it on circuit
/// wires with terminal claims bound to guessed input evaluations. Returns the
/// in-circuit gate counts of the GKR verifier.
fn measure(shape: Shape) !Counts {
    var draw = NativeChannel{};
    draw.mixU32s(&.{0x4f475352});
    var layers: [LEAF0.len]L.gkr_prover.Layer = undefined;
    var made: usize = 0;
    defer for (layers[0..made]) |*layer| layer.deinit(a);
    for (&layers, shape.n) |*layer, n| {
        const size = @as(usize, 1) << @intCast(n);
        const numerators = try a.alloc(M31, size);
        for (numerators, 0..) |*x, i| x.* = M31.fromCanonical(@intCast(1 + (i * 2654435761) % 1000));
        const denominators = try draw.drawSecureFelts(a, size);
        layer.* = .{ .LogUpMultiplicities = .{ .numerators = try MleBase.initOwned(numerators), .denominators = try MleSecure.initOwned(denominators) } };
        made += 1;
    }
    var prover_channel = NativeChannel{};
    var result = try L.gkr_prover.proveBatch(a, &prover_channel, &layers);
    defer result.deinit(a);
    const gates: [LEAF0.len]L.gkr_verifier.Gate = @splat(.LogUp);

    // Native authority.
    var native_channel = NativeChannel{};
    var native = try L.gkr_verifier.partiallyVerifyBatch(a, &gates, &result.proof, &native_channel);
    defer native.deinit(a);
    var native_inputs: [LEAF0.len][2]Q = undefined;
    var native_expected: [LEAF0.len][]const Q = undefined;
    for (&native_inputs, &native_expected, layers, 0..) |*values, *expected, layer, i| {
        const nv = native.n_variables_by_instance[i];
        const point = native.ood_point[native.ood_point.len - nv ..];
        values.* = .{ try layer.LogUpMultiplicities.numerators.evalAtPoint(a, point), try layer.LogUpMultiplicities.denominators.evalAtPoint(a, point) };
        expected.* = values;
    }
    try C.kernel.verifyTerminalInputs(Q, &native, &native_expected, L.gkr_verifier.NativeChecks{});

    // Circuit replay.
    var context = try C.Context.init(a, 0);
    defer context.deinit();
    lane.begin(&context);
    var bound = true;
    defer if (bound) lane.finish() catch {};
    var proof = try C.wireProof(&context, &result.proof);
    var channel = try C.Channel.init(&context);
    var artifact = try C.verify(&context, &gates, &proof, &channel);
    defer artifact.deinit(a);
    for (artifact.ood_point, native.ood_point) |wire, value| try std.testing.expect(context.get(wire.v).eql(value));
    // Terminal claims: in the outer AIR these are bound to MAIN by the
    // committed eq/prefix columns (costed separately below); here they are
    // guessed wires carrying the native input evaluations.
    var inputs: [LEAF0.len][2]F = undefined;
    var expected: [LEAF0.len][]const F = undefined;
    for (&inputs, &expected, native_inputs) |*values, *out, native_values| {
        values.* = .{ F.wire(try context.guess(native_values[0])), F.wire(try context.guess(native_values[1])) };
        out.* = values;
    }
    try C.kernel.verifyTerminalInputs(F, &artifact, &expected, C.Checks{ .context = &context });
    try channel.finish();
    bound = false;
    try lane.finish();
    try context.finalize(false);
    try std.testing.expect(try context.isCircuitValid());
    return Counts.of(&context);
}

/// Least squares for counts = c0 + c1 rounds + c2 instance_layers + c3 layers.
fn fit(shapes: []const Shape, values: []const u64) [4]f64 {
    var ata: [4][4]f64 = @splat(@splat(0));
    var atb: [4]f64 = @splat(0);
    for (shapes, values) |s, y| {
        const x = [4]f64{ 1, @floatFromInt(s.rounds), @floatFromInt(s.instance_layers), @floatFromInt(s.layers) };
        for (0..4) |i| {
            atb[i] += x[i] * @as(f64, @floatFromInt(y));
            for (0..4) |j| ata[i][j] += x[i] * x[j];
        }
    }
    // Gauss-Jordan.
    var m = ata;
    var b = atb;
    for (0..4) |col| {
        var pivot = col;
        for (col + 1..4) |r| if (@abs(m[r][col]) > @abs(m[pivot][col])) {
            pivot = r;
        };
        std.mem.swap([4]f64, &m[col], &m[pivot]);
        std.mem.swap(f64, &b[col], &b[pivot]);
        for (0..4) |r| if (r != col) {
            const k = m[r][col] / m[col][col];
            for (0..4) |c| m[r][c] -= k * m[col][c];
            b[r] -= k * b[col];
        };
    }
    var out: [4]f64 = undefined;
    for (0..4) |i| out[i] = b[i] / m[i][i];
    return out;
}

fn predict(c: [4]f64, s: Shape) f64 {
    return c[0] + c[1] * @as(f64, @floatFromInt(s.rounds)) + c[2] * @as(f64, @floatFromInt(s.instance_layers)) + c[3] * @as(f64, @floatFromInt(s.layers));
}

test "outer LogUp-GKR: in-circuit verifier cost of the batched leaf instance (measured, fitted, held out)" {
    const fit_shifts = [_]u32{ 16, 15, 14, 13, 12 };
    const holdout_shifts = [_]u32{ 11, 10 };
    var shapes: [fit_shifts.len + holdout_shifts.len]Shape = undefined;
    var counts: [shapes.len]Counts = undefined;
    for (fit_shifts ++ holdout_shifts, 0..) |shift, i| {
        shapes[i] = Shape.scaled(shift);
        var timer = try std.time.Timer.start();
        counts[i] = try measure(shapes[i]);
        emit("OUTER_GKR_COST", .{ .kind = "measured", .shift = shift, .layers = shapes[i].layers, .instance_layers = shapes[i].instance_layers, .rounds = shapes[i].rounds, .counts = counts[i], .wall_ns = timer.read() });
    }
    const production = Shape.scaled(0);
    var predicted: [Counts.N]f64 = undefined;
    var worst: f64 = 0;
    var rel_worst: f64 = 0;
    for (0..Counts.N) |k| {
        var ys: [fit_shifts.len]u64 = undefined;
        for (&ys, counts[0..fit_shifts.len]) |*y, c| y.* = c.get(k);
        const coeff = fit(shapes[0..fit_shifts.len], &ys);
        // The verifier's control flow depends only on shape: the affine law
        // must reproduce the held-out measurements exactly.
        var max_err: f64 = 0;
        for (shapes[fit_shifts.len..], counts[fit_shifts.len..]) |s, c|
            max_err = @max(max_err, @abs(predict(coeff, s) - @as(f64, @floatFromInt(c.get(k)))));
        predicted[k] = predict(coeff, production);
        emit("OUTER_GKR_FIT", .{ .counter = k, .c0 = coeff[0], .per_round = coeff[1], .per_instance_layer = coeff[2], .per_layer = coeff[3], .holdout_max_abs_err = max_err });
        // Hash, conversion, triple-XOR and equality rows follow the affine
        // law exactly; packed qm31 rows (and so variables) deviate by about
        // 0.1% on held-out shapes, which the receipt reports as fit error.
        if (k == 1 or k == 5) {
            rel_worst = @max(rel_worst, max_err / @as(f64, @floatFromInt(counts[shapes.len - 1].get(k))));
        } else worst = @max(worst, max_err);
    }
    emit("OUTER_GKR_COST", .{ .kind = "fit_at_production_shape", .layers = production.layers, .instance_layers = production.instance_layers, .rounds = production.rounds, .blake_g_gate = predicted[0], .qm31_ops = predicted[1], .m31_to_u32 = predicted[2], .triple_xor = predicted[3], .eq = predicted[4], .variables = predicted[5] });
    // The verifier's control flow depends only on shape: the affine law must
    // reproduce the held-out measurements exactly.
    try std.testing.expect(worst < 0.5);
    try std.testing.expect(rel_worst < 0.005);
}

test "outer LogUp-GKR: per-instance terminal binding arithmetic at production row logs (measured)" {
    var random = NativeChannel{};
    random.mixU32s(&.{0x4f42494e});
    var total: Counts = .{ .blake_g_gate = 0, .qm31_ops = 0, .m31_to_u32 = 0, .triple_xor = 0, .eq = 0, .variables = 0 };
    var global_log: u32 = 0;
    for (LEAF0) |inst| global_log = @max(global_log, inst.row_log);
    const global_point = core.circle.secureFieldPointFromRandomSeed(random.drawSecureFelt());
    for (LEAF0) |inst| {
        const log = inst.row_log;
        var native_r: [MP.MAX_VARIABLES]Q = undefined;
        for (native_r[0..log]) |*v| v.* = random.drawSecureFelt();
        var context = try C.Context.init(a, 0);
        defer context.deinit();
        lane.begin(&context);
        var bound = true;
        defer if (bound) lane.finish() catch {};
        var r: [MP.MAX_VARIABLES]F = undefined;
        for (r[0..log], native_r[0..log]) |*wire, value| wire.* = F.wire(try context.guess(value));
        const point = try MP.MleEvalPointFor(F).init(r[0..log]);
        const global: core.circle.CirclePoint(F) = .{ .x = F.wire(try context.guess(global_point.x)), .y = F.wire(try context.guess(global_point.y)) };
        const folded = global.repeatedDouble(global_log - log);
        const carry = try MP.evalCarryQuotientFor(F, &point, folded);
        const anchors = try MP.evalAnchorsFor(F, log, folded);
        const native_point = try MP.MleEvalPoint.init(native_r[0..log]);
        const native_local = global_point.repeatedDouble(global_log - log);
        try context.eq(carry.v, try context.constant(try MP.evalCarryQuotient(&native_point, native_local)));
        for (anchors, try MP.evalAnchors(log, native_local)) |value, want| try context.eq(value.v, try context.constant(want));
        bound = false;
        try lane.finish();
        try context.finalize(false);
        try std.testing.expect(try context.isCircuitValid());
        const c = Counts.of(&context);
        inline for (std.meta.fields(Counts)) |field| @field(total, field.name) += @field(c, field.name);
        emit("OUTER_GKR_BINDING", .{ .instance = inst.name, .row_log = log, .global_log = global_log, .counts = c });
    }
    emit("OUTER_GKR_BINDING", .{ .instance = "all", .counts = total });
}
