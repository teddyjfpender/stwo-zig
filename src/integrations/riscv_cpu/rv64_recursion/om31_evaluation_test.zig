const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const A = frontend.rv64_air;
const E = A.evaluation;
const lane = @import("om31_circuit_lane.zig");
const W = lane.Lane;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const PB = E.PackedFields.BaseForField(O);
const PS = E.PackedFields.SecureForField(O);
const a = std.testing.allocator;
fn dense(seed: u32) O {
    var c: [8]M = undefined;
    for (&c, 0..) |*v, i| v.* = M.fromCanonical(seed + @as(u32, @intCast(i * 79)));
    return O.fromM31Array(c);
}
fn lift(comptime F: type, ctx: *lane.Context, value: O) !F {
    if (F == O) return value;
    if (F == W) return F.guess(ctx, value);
    if (F == PB) return F.splat(value.toM31Array()[0]);
    if (F == PS) return F.splat(value);
    @compileError("unsupported test lane");
}
fn generate(comptime T: type, comptime F: type, ctx: *lane.Context, seed: *u32, base: bool) !T {
    if (T == F) {
        seed.* += 11;
        return lift(F, ctx, if (base) O.fromBase(M.fromCanonical(seed.*)) else dense(seed.*));
    }
    var out: T = undefined;
    switch (@typeInfo(T)) {
        .array => for (&out) |*v| {
            v.* = try generate(@TypeOf(v.*), F, ctx, seed, base);
        },
        .@"struct" => inline for (@typeInfo(T).@"struct".fields) |field| {
            @field(out, field.name) = try generate(field.type, F, ctx, seed, base);
        },
        else => @compileError("unsupported test container"),
    }
    return out;
}
fn originals(comptime F: type, ctx: *lane.Context, base: bool, values: []E.SecureFor(F)) !usize {
    var seed: u32 = 3;
    const cpu = A.word16_cpu;
    const fixed = try generate([3]F, F, ctx, &seed, base);
    const main = try generate([cpu.profile.MAX_MAIN]F, F, ctx, &seed, base);
    const previous = try generate([cpu.profile.MAX_MAIN]F, F, ctx, &seed, base);
    var sink = E.SinkFor(F){ .values = values };
    cpu.equations.emitActivityFor(F, &fixed, &main, &previous, 17, &sink);
    cpu.equations.emitDataFor(F, .alu_binary_v2, &fixed, &main, &sink);
    const alu = A.word16_v1.alu_experiment.equations;
    const row = try generate(alu.RowFor(F), F, ctx, &seed, base);
    alu.emitFor(F, &row, &sink);
    const ls = A.memory.load_store_v1;
    const m = try generate([ls.layout.MAIN]F, F, ctx, &seed, base);
    const pm = try generate([ls.layout.MAIN]F, F, ctx, &seed, base);
    ls.equations.emitLocalWithPublicFor(F, &fixed, &m, &pm, E.qFor(F, 23), E.qFor(F, 1), &sink);
    return sink.count;
}
test "OM31 original CPU ALU LS local equations match all eight circuit coordinates" {
    comptime E.assertExternalLane(W);
    var ctx = try lane.Context.init(a, 0);
    defer ctx.deinit();
    lane.begin(&ctx);
    var bound = true;
    defer if (bound) lane.finish() catch {};
    var native: [4096]O = undefined;
    var wires: [4096]W = undefined;
    const n = try originals(O, &ctx, false, &native);
    try std.testing.expectEqual(n, try originals(W, &ctx, false, &wires));
    for (native[0..n], wires[0..n]) |expected, wire| {
        try std.testing.expectEqualDeep(expected.toM31Array(), wire.value().toM31Array());
        try ctx.eq(wire.c0.v, (try W.guess(&ctx, expected)).c0.v);
        try ctx.eq(wire.c1.v, (try W.guess(&ctx, expected)).c1.v);
    }
    bound = false;
    try lane.finish();
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}
test "OM31 original CPU ALU LS base and secure packets preserve native residuals" {
    var ctx = try lane.Context.init(a, 0);
    defer ctx.deinit();
    var native: [4096]O = undefined;
    var packets: [4096]PS = undefined;
    const n = try originals(O, &ctx, true, &native);
    try std.testing.expectEqual(n, try originals(PB, &ctx, true, &packets));
    for (native[0..n], packets[0..n]) |expected, actual| for (0..E.LANES) |i| try std.testing.expect(actual.lane(i).eql(expected));
    const wide_count = try originals(O, &ctx, false, &native);
    try std.testing.expectEqual(wide_count, try originals(PS, &ctx, false, &packets));
    for (native[0..wide_count], packets[0..wide_count]) |expected, actual| for (0..E.LANES) |i| try std.testing.expectEqualDeep(actual.lane(i).toM31Array(), expected.toM31Array());
}
test "OM31 explicit eight-coordinate decoding and SIMD accumulation preserve high halves" {
    var ctx = try lane.Context.init(a, 0);
    defer ctx.deinit();
    lane.begin(&ctx);
    var bound = true;
    defer if (bound) lane.finish() catch {};
    var native: [8]O = undefined;
    var wires: [8]W = undefined;
    var packets: [8]PS = undefined;
    var base: [8]PB = undefined;
    for (0..8) |i| {
        native[i] = dense(@intCast(i * 997 + 5));
        wires[i] = try W.guess(&ctx, native[i]);
        packets[i] = PS.splat(native[i]);
        base[i] = PB.fromCanonical(@intCast(i + 2));
    }
    const expected = E.secureFromCoordinatesForField(O, O, native);
    try std.testing.expect(expected.eql(E.secureFromCoordinatesForField(W, W, wires).value()));
    const result = E.secureFromCoordinatesForField(O, PS, packets);
    for (0..16) |i| try std.testing.expect(result.lane(i).eql(expected));
    var coords: [8]M = undefined;
    for (&coords, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i + 2));
    const from_base = E.secureFromCoordinatesForField(O, PB, base);
    try std.testing.expect(from_base.lane(15).eql(O.fromM31Array(coords)));
    var weights = [_]O{ dense(17), dense(29), dense(43) };
    var acc = E.WeightedAccumulatorFor(PB){ .powers = &weights };
    var sink = E.SinkFor(PB){ .weighted_accumulator = &acc, .scale = PS.splat(dense(53)) };
    sink.emit(PB.fromCanonical(7));
    sink.zeros(1);
    sink.emit(PS.splat(dense(61)));
    const want = weights[2].mul(dense(53)).mul(O.fromBase(M.fromCanonical(7))).add(weights[0].mul(dense(53)).mul(dense(61)));
    for (0..16) |i| try std.testing.expect(acc.accumulation.lane(i).eql(want));
    bound = false;
    try lane.finish();
}
test "OM31 typed counts remain integers and geometry matches circuit norm inverse" {
    comptime {
        if (E.CountFor(O) != u32 or E.CountFor(W) != W) @compileError("wide public count identity drift");
    }
    var ctx = try lane.Context.init(a, 0);
    defer ctx.deinit();
    lane.begin(&ctx);
    var bound = true;
    defer if (bound) lane.finish() catch {};
    const p = core.circle.CirclePoint(O){ .x = dense(271), .y = dense(811) };
    const wp = core.circle.CirclePoint(W){ .x = try W.guess(&ctx, p.x), .y = try W.guess(&ctx, p.y) };
    const expected = try A.geometry.denominatorInverseFor(O, p, 12, 8);
    const actual = try A.geometry.denominatorInverseFor(W, wp, 12, 8);
    try std.testing.expect(expected.eql(actual.value()));
    try ctx.markAsMaybeUnused(actual.c0.v);
    try ctx.markAsMaybeUnused(actual.c1.v);
    bound = false;
    try lane.finish();
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

fn wireContainer(comptime Target: type, source: anytype, ctx: *lane.Context) !Target {
    if (Target == W) return W.guess(ctx, if (@TypeOf(source) == O) source else O.fromBase(M.fromCanonical(source)));
    var out: Target = undefined;
    switch (@typeInfo(Target)) {
        .array => for (&out, source) |*v, s| {
            v.* = try wireContainer(@TypeOf(v.*), s, ctx);
        },
        .@"struct" => inline for (@typeInfo(Target).@"struct".fields) |field| {
            @field(out, field.name) = try wireContainer(field.type, @field(source, field.name), ctx);
        },
        else => @compileError("unsupported wire container"),
    }
    return out;
}
fn compareWires(native: anytype, wires: anytype, ctx: *lane.Context) !void {
    if (@TypeOf(native) == O) {
        try std.testing.expectEqualDeep(native.toM31Array(), wires.value().toM31Array());
        if (!ctx.maybe_unused_vars.contains(wires.c0.v.idx)) try ctx.markAsMaybeUnused(wires.c0.v);
        if (!ctx.maybe_unused_vars.contains(wires.c1.v.idx)) try ctx.markAsMaybeUnused(wires.c1.v);
        return;
    }
    switch (@typeInfo(@TypeOf(native))) {
        .array => for (native, wires) |n, w| try compareWires(n, w, ctx),
        .@"struct" => inline for (@typeInfo(@TypeOf(native)).@"struct".fields) |field| try compareWires(@field(native, field.name), @field(wires, field.name), ctx),
        else => @compileError("unsupported comparison container"),
    }
}
test "OM31 production CPU REG FUNCTION ROM OWNER range denominators share exact eight-coordinate wire authority" {
    var ctx = try lane.Context.init(a, 0);
    defer ctx.deinit();
    lane.begin(&ctx);
    var bound = true;
    defer if (bound) lane.finish() catch {};
    const cpu = A.word16_execution;
    var seed: u32 = 43;
    const fixed = try generate([3]O, O, &ctx, &seed, false);
    const row = try generate([cpu.layout.main.COUNT]O, O, &ctx, &seed, false);
    const ch = try generate(cpu.types.ChallengesFor(O), O, &ctx, &seed, false);
    const public = cpu.types.InputsFor(O){ .steps = 17, .initial_pc = .{ 4, 5, 6, 7 }, .final_pc = .{ 8, 9, 10, 11 }, .epoch = 3 };
    const wf = try wireContainer([3]W, fixed, &ctx);
    const wr = try wireContainer([cpu.layout.main.COUNT]W, row, &ctx);
    const wc = try wireContainer(cpu.types.ChallengesFor(W), ch, &ctx);
    const wp = try wireContainer(cpu.types.InputsFor(W), public, &ctx);
    const nd = cpu.equations.denominatorsFor(O, &fixed, &row, public, ch);
    const wd = cpu.equations.denominatorsFor(W, &wf, &wr, wp, wc);
    try compareWires(nd, wd, &ctx);
    const native_inverse_denominators = cpu.equations.inverseDenominatorsFor(O, nd);
    const wire_inverse_denominators = cpu.equations.inverseDenominatorsFor(W, wd);
    try compareWires(native_inverse_denominators, wire_inverse_denominators, &ctx);
    bound = false;
    try lane.finish();
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

test "OM31 packed lane products and masks preserve distinct rows and eighth coordinate" {
    var left: [16]O = undefined;
    var right: [16]O = undefined;
    var base: [16]M = undefined;
    for (0..16) |i| {
        left[i] = dense(@intCast(i * 37 + 3));
        right[i] = dense(@intCast(i * 97 + 11));
        base[i] = M.fromCanonical(@intCast(i * 7 + 2));
    }
    const x = PS.fromLanes(left);
    const y = PS.fromLanes(right);
    const b = PB.fromLanes(base);
    const roundtrip = PS.fromCoordinates(x.coordinates());
    for (0..16) |i| {
        try std.testing.expect(roundtrip.lane(i).eql(left[i]));
        try std.testing.expect(x.mul(y).lane(i).eql(left[i].mul(right[i])));
        try std.testing.expect(x.mulBase(b).lane(i).eql(left[i].mulM31(base[i])));
        try std.testing.expect(x.add(y).lane(i).eql(left[i].add(right[i])));
        try std.testing.expect(x.sub(y).lane(i).eql(left[i].sub(right[i])));
    }
    var samples: [8][1]O = undefined;
    var columns: [8][]O = undefined;
    for (0..8) |i| {
        samples[i][0] = dense(@intCast(i * 997 + 7));
        columns[i] = &samples[i];
    }
    var trees = [_][][]O{&columns};
    // Borrowed test view; no ownership transfer or deinit of stack storage.
    var storage = core.pcs.TreeVec([][]O){ .items = &trees };
    const masks = E.lane.NativeMasksForField(O){ .values = &storage };
    const expected = E.secureForField(O, O, &.{ samples[0][0], samples[1][0], samples[2][0], samples[3][0], samples[4][0], samples[5][0], samples[6][0], samples[7][0] }, 0);
    try std.testing.expect(expected.eql(try E.lane.secureSampleForField(O, O, masks, 0, 0, 0, 1)));
    try std.testing.expectError(error.InvalidRv64MaskShape, E.lane.secureSampleForField(O, O, masks, 0, 1, 0, 1));
    try std.testing.expectError(error.InvalidRv64MaskShape, masks.at(0, 8, 0));
}

test "OM31 shared packed basis remix preserves distinct polynomials in all sixteen rows" {
    var native: [8][16]O = undefined;
    var packets: [8]PS = undefined;
    for (&native, &packets, 0..) |*values, *packet, column| {
        for (values, 0..) |*v, row| v.* = dense(@intCast(71 + column * 997 + row * 1709));
        packet.* = PS.fromLanes(values.*);
    }
    const actual = PS.fromPartialEvals(packets);
    for (0..16) |row| {
        var expected = O.zero();
        for (0..8) |column| {
            var basis = [_]M{M.zero()} ** 8;
            basis[column] = M.one();
            expected = expected.add(native[column][row].mul(O.fromM31Array(basis)));
        }
        try std.testing.expectEqualDeep(expected.toM31Array(), actual.lane(row).toM31Array());
    }
}
