//! Live source lowering only. No R7 PCS/recursive receiver admission yet.
const std = @import("std");
const Core = @import("stwo_core");
const C = @import("../context.zig");
const Common = @import("../../rv64_recursion/om31_poseidon/common.zig");
const DotHook = @import("../../rv64_recursion/om31_native/deep_dot.zig");
const Scope = @import("scope.zig").Scope;
const Source = @import("authority.zig").Source;
const Lane = Common.lane;
const Q = C.Q;
const O = Core.fields.om31.OM31;
const M = Core.fields.m31.M31;
const a = std.testing.allocator;
fn number(n: u32) O {
    var coordinates: [8]M = undefined;
    for (&coordinates, 0..) |*v, i| v.* = M.fromCanonical(n + @as(u32, @intCast(i)));
    return O.fromM31Array(coordinates);
}
fn sum(owner: *C.Context, weights: []const Common.F, scalars: []const Common.Var) !Common.F {
    if (DotHook.current()) |lower| return lower(owner.algebra(), weights, scalars);
    var value = Common.F.zero();
    for (weights, scalars) |weight, scalar| value = value.add(weight.mulInner(Common.Inner.wire(scalar)));
    return value;
}
const Built = struct { owner: C.Context, output: [4]C.Var };
fn graph(allocator: std.mem.Allocator, native: bool, trace_only: bool) !Built {
    var owner = if (trace_only) try C.Context.initTraceOnly(allocator, 4) else try C.Context.init(allocator, 4);
    errdefer owner.deinit();
    var structural = Lane.StructuralScope.init();
    defer structural.deinit();
    var mul = @import("../native_omul/scope.zig").begin();
    defer mul.deinit();
    var dot: ?Scope = if (native) Scope.begin(&owner) else null;
    defer if (dot) |*s| s.deinit();
    Common.begin(&owner);
    var active = true;
    defer if (active) Common.finish() catch {};
    const x = try Common.F.guess(owner.algebra(), number(3));
    const y = try Common.F.guess(owner.algebra(), number(17));
    const w = x.mul(y);
    const scalar0 = try owner.base.guess(Q.fromBase(M.fromCanonical(5)));
    const scalar1 = try owner.base.guess(Q.fromBase(M.fromCanonical(11)));
    const result = try sum(&owner, &.{ w, x, x }, &.{ scalar0, scalar1, scalar0 });
    const empty = try sum(&owner, &.{}, &.{});
    // P2 and native multiplication share this same source usage authority.
    _ = try owner.permute(@splat(scalar0));
    try Common.finish();
    active = false;
    const outputs = [4]C.Var{ result.c0.v, result.c1.v, empty.c0.v, empty.c1.v };
    try owner.setOutputs(&outputs);
    if (native) try owner.finalizeForNativeDot() else try owner.finalize();
    return .{ .owner = owner, .output = outputs };
}
test "OP R7 live dot lowering joint source usage trace parity and legacy zero allocation guards" {
    var control = try graph(a, false, false);
    defer control.owner.deinit();
    var native = try graph(a, true, false);
    defer native.owner.deinit();
    var trace = try graph(a, true, true);
    defer trace.owner.deinit();
    try std.testing.expect(control.owner.finalized and !control.owner.native_dot_finalized);
    try std.testing.expect(native.owner.native_dot_finalized and !native.owner.finalized);
    try std.testing.expect(native.owner.isClosed());
    try std.testing.expect(native.owner.base.gate_counts.qm31_ops < control.owner.base.gate_counts.qm31_ops);
    try std.testing.expect(try native.owner.isCircuitValid());
    for (control.output, native.output) |old, new| try std.testing.expect(control.owner.base.get(old).eql(native.owner.base.get(new)));
    try std.testing.expectEqual(@as(usize, 2), native.owner.native_dot_calls.items.len);
    try std.testing.expectEqualDeep(native.owner.native_dot_calls.items, trace.owner.native_dot_calls.items);
    try std.testing.expectEqualDeep(native.owner.native_mul_calls.items, trace.owner.native_mul_calls.items);
    try std.testing.expectEqualDeep(native.owner.base.circuit.add.items, trace.owner.base.circuit.add.items);
    try std.testing.expectEqualDeep(native.owner.usage.?.counts, trace.owner.usage.?.counts);
    var counts = try native.owner.sourceMultiplicitiesForNativeDot(a);
    defer counts.deinit(a);
    for (counts.n_yields) |n| try std.testing.expectEqual(@as(u32, 1), n);
    try std.testing.expectEqualDeep(counts.n_uses, native.owner.usage.?.counts);
    var source = try Source.compile(a, native.owner.native_dot_calls.items, counts.n_uses);
    defer source.deinit();
    try std.testing.expectEqual(@as(usize, 4), source.raw_rows);
    const raw = try native.owner.rawCountsForNativeDot();
    try std.testing.expectEqual(@as(u64, 4), raw[6]);
    try std.testing.expectEqual(@as(u64, 1), raw[5]);
    try std.testing.expectError(error.PoseidonContextNotFinalized, native.owner.rawCounts());
    // No legacy authority can construct a key while silently omitting dot debt.
    var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.PoseidonContextNotFinalized, @import("../authority.zig").Authority.init(fail.allocator(), &native.owner));
    try std.testing.expectError(error.PoseidonContextNotFinalized, @import("../native_omul/authority.zig").Key.init(fail.allocator(), &native.owner, .op_target_b4_q72_p0_fold4_v1));
    try std.testing.expect(!fail.has_induced_failure);
    try std.testing.expectError(error.NativeDotRequiresR7, native.owner.sourceMultiplicities(fail.allocator()));
    try std.testing.expect(!fail.has_induced_failure);
    try std.testing.expectError(error.PoseidonContextClosed, native.owner.finalize());
    try std.testing.expectError(error.PoseidonContextClosed, native.owner.finalizeForNativeDot());
    try std.testing.expectError(error.InvalidWitnessOrigin, native.owner.nativeDot(&.{}));
    try std.testing.expectError(error.InvalidWitnessOrigin, native.owner.nativeOmul(@splat(.{ .idx = 0 })));
    try std.testing.expectError(error.PoseidonContextClosed, native.owner.permute(@splat(.{ .idx = 0 })));
    try std.testing.expectError(error.PoseidonContextClosed, native.owner.setOutputs(&.{}));
    const output = native.output[0].idx;
    const saved = native.owner.base.value_table.items[output];
    native.owner.base.value_table.items[output] = saved.add(Q.one());
    try std.testing.expect(!try native.owner.isCircuitValid());
    native.owner.base.value_table.items[output] = saved;
}
fn refuse(_: *Common.Context, _: []const Common.F, _: []const Common.Var) anyerror!Common.F {
    return error.InjectedDotFailure;
}
test "OP R7 dot scope restores nested errors and refuses wrong context and hidden scalar coordinates" {
    try std.testing.expect(DotHook.current() == null);
    var owner = try C.Context.init(a, 0);
    defer owner.deinit();
    var other = try C.Context.init(a, 0);
    defer other.deinit();
    {
        var outer = Scope.begin(&owner);
        defer outer.deinit();
        const hook = DotHook.current().?;
        try std.testing.expectError(error.NativeDotScopeMismatch, hook(other.algebra(), &.{}, &.{}));
        {
            var inner = DotHook.Scope.init(refuse);
            defer inner.deinit();
            try std.testing.expectError(error.InjectedDotFailure, DotHook.current().?(owner.algebra(), &.{}, &.{}));
        }
        try std.testing.expect(DotHook.current().? == hook);
        try std.testing.expectError(error.NativeDotScopeMismatch, hook(owner.algebra(), &.{Common.F.zero()}, &.{}));
        _ = try hook(owner.algebra(), &.{}, &.{});
    }
    try std.testing.expect(DotHook.current() == null);
    const bad = try owner.base.guess(Q.fromM31Array(.{ M.one(), M.one(), M.zero(), M.zero() }));
    const term = @import("authority.zig").Term{ .weight = .{ 0, 0 }, .scalar = bad.idx };
    try std.testing.expectError(error.InvalidWitnessOrigin, owner.nativeDot(&.{term}));
    try std.testing.expect(owner.poisoned);
    try std.testing.expectError(error.PoseidonContextClosed, owner.finalizeForNativeDot());
}

test "OP R7 dot finalization refuses legacy omission and duplicate producers" {
    var omitted = try C.Context.init(a, 0);
    defer omitted.deinit();
    _ = try omitted.nativeDot(&.{});
    try std.testing.expectError(error.NativeDotRequiresR7, omitted.finalize());
    try std.testing.expect(omitted.poisoned and !omitted.finalized and !omitted.native_dot_finalized);
    var duplicate = try C.Context.init(a, 0);
    defer duplicate.deinit();
    const first = try duplicate.nativeDot(&.{});
    _ = try duplicate.nativeDot(&.{});
    duplicate.native_dot_calls.items[1].outputs[0] = first[0].idx;
    try std.testing.expectError(error.PoseidonProducerConflict, duplicate.finalizeForNativeDot());
    try std.testing.expect(duplicate.poisoned and !duplicate.finalized and !duplicate.native_dot_finalized);
}
fn deepGraph(allocator: std.mem.Allocator, native: bool) !Built {
    const Circuit = @import("stwo_circuit_frontend");
    const Base = Circuit.builder.wrappers.M31Wrapper(C.Var);
    const Simd = Circuit.builder.simd;
    const Shape = @import("../../rv64_recursion/om31_native/shape.zig");
    var owner = try C.Context.init(allocator, 4);
    errdefer owner.deinit();
    var structural = Lane.StructuralScope.init();
    defer structural.deinit();
    var mul = @import("../native_omul/scope.zig").begin();
    defer mul.deinit();
    var dot: ?Scope = if (native) Scope.begin(&owner) else null;
    defer if (dot) |*s| s.deinit();
    Common.begin(&owner);
    var active = true;
    defer if (active) Common.finish() catch {};
    const point = try Core.circle.secureFieldPointFromRandomSeedCheckedFor(O, number(17));
    const oods = Common.Point{ .x = try Common.F.guess(owner.algebra(), point.x), .y = try Common.F.guess(owner.algebra(), point.y) };
    const alpha = try Common.F.guess(owner.algebra(), number(29));
    const sampled0 = [_]Common.F{try Common.F.guess(owner.algebra(), number(5))};
    const sampled1 = [_]Common.F{try Common.F.guess(owner.algebra(), number(11))};
    const sampled_columns = [_][]const Common.F{ &sampled0, &sampled1 };
    const sampled = [_][]const []const Common.F{&sampled_columns};
    const queried0 = [_]Base{ Base.newUnsafe(try owner.base.guess(Q.fromBase(M.fromCanonical(7)))), Base.newUnsafe(try owner.base.guess(Q.fromBase(M.fromCanonical(13)))) };
    const queried1 = [_]Base{ Base.newUnsafe(try owner.base.guess(Q.fromBase(M.fromCanonical(19)))), Base.newUnsafe(try owner.base.guess(Q.fromBase(M.fromCanonical(23)))) };
    const queried_columns = [_][]const Base{ &queried0, &queried1 };
    const queried = [_][]const []const Base{&queried_columns};
    const zero = Base.newUnsafe(owner.base.zero());
    const one = Base.newUnsafe(owner.base.one());
    const points = Circuit.stark_verifier.circle.Point(Simd.Simd){ .x = try Simd.pack(Q, owner.algebra(), &.{ one, zero }), .y = try Simd.pack(Q, owner.algebra(), &.{ zero, one }) };
    const refs = [_]Shape.SampleRef{
        .{ .tree = 0, .column = 0, .sample = 0, .flat_column = 0, .power = 0 },
        .{ .tree = 0, .column = 1, .sample = 0, .flat_column = 1, .power = 1 },
    };
    const batches = [_]Shape.Batch{.{ .shift = .{ .v = 0 }, .entries = &refs }};
    const plan = Shape.SamplePlan{ .n_samples = 2, .batches = &batches };
    const result = try @import("../../rv64_recursion/om31_native/deep.zig").friInput(owner.algebra(), &plan, oods, &sampled, alpha, points, &queried);
    try Common.finish();
    active = false;
    const output = [4]C.Var{ result[0].c0.v, result[0].c1.v, result[1].c0.v, result[1].c1.v };
    try owner.setOutputs(&output);
    if (native) try owner.finalizeForNativeDot() else try owner.finalize();
    return .{ .owner = owner, .output = output };
}
test "OP R7 actual DEEP entrypoint lowers complete numerators and preserves numerical result" {
    var control = try deepGraph(a, false);
    defer control.owner.deinit();
    var native = try deepGraph(a, true);
    defer native.owner.deinit();
    try std.testing.expect(try control.owner.isCircuitValid());
    try std.testing.expect(try native.owner.isCircuitValid());
    for (control.output, native.output) |old, new| try std.testing.expect(control.owner.base.get(old).eql(native.owner.base.get(new)));
    try std.testing.expectEqual(@as(usize, 2), native.owner.native_dot_calls.items.len);
    for (native.owner.native_dot_calls.items) |call| try std.testing.expectEqual(@as(usize, 2), call.terms.len);
    try std.testing.expect(native.owner.base.gate_counts.qm31_ops < control.owner.base.gate_counts.qm31_ops);
    try std.testing.expect(DotHook.current() == null);
}

fn allocationGraph(allocator: std.mem.Allocator) !void {
    var built = try graph(allocator, true, false);
    defer built.owner.deinit();
}
test "OP R7 source lowering allocation failures retain unique custody and restore scopes" {
    try std.testing.checkAllAllocationFailures(a, allocationGraph, .{});
    try std.testing.expect(DotHook.current() == null);
}

test "OP R7 v2 free input origins reject orphans duplicates constants and dedicated outputs" {
    var orphan = try C.Context.init(a, 0);
    defer orphan.deinit();
    _ = try orphan.base.newVar(Q.one());
    try std.testing.expectError(error.PoseidonMissingProducer, orphan.finalizeForNativeDot());
    for (0..8) |kind| {
        var owner = try C.Context.init(a, 0);
        defer owner.deinit();
        const genuine = try owner.base.guess(Q.fromBase(M.fromCanonical(7)));
        const bad: C.Var = switch (kind) {
            0 => owner.base.zero(),
            1 => owner.base.one(),
            2 => try owner.base.constant(Q.fromBase(M.fromCanonical(17))),
            3 => genuine,
            4 => (try owner.permute(@splat(owner.base.zero())))[0],
            5 => (try owner.nativeOmul(@splat(owner.base.one())))[0],
            6 => (try owner.nativeDot(&.{}))[0],
            7 => try owner.base.add(owner.base.one(), owner.base.one()),
            else => unreachable,
        };
        try owner.base.guessed_vars.append(a, .{ .qm31 = bad });
        try std.testing.expectError(error.InvalidWitnessOrigin, owner.finalizeForNativeDot());
        try std.testing.expect(owner.poisoned and !owner.native_dot_finalized and !owner.finalized);
    }
    // Injecting a supposed input before finalization is never an orphan repair.
    var injected = try C.Context.init(a, 0);
    defer injected.deinit();
    const raw = try injected.base.newVar(Q.one());
    try injected.native_input_ids.append(a, raw.idx);
    try std.testing.expectError(error.InvalidNativeInputOrigin, injected.finalizeForNativeDot());
}

test "OP R7 v2 QM sink preserves typed canonical constraints and restores after wrong context" {
    var owner = try C.Context.init(a, 0);
    defer owner.deinit();
    const unrestricted = try owner.base.guess(Q.fromM31Array(.{ M.one(), M.one(), M.one(), M.one() }));
    _ = try owner.base.guessM31(Q.fromBase(M.fromCanonical(5)));
    _ = try owner.base.guessU16(Q.fromBase(M.fromCanonical(9)));
    try owner.finalizeForNativeDot();
    try std.testing.expectEqualSlices(u32, &.{unrestricted.idx}, owner.native_input_ids.items);
    try std.testing.expectEqual(@as(usize, 1), owner.base.circuit.pointwise_mul.items.len);
    try std.testing.expectEqual(@as(usize, 1), owner.base.circuit.m31_to_u32.items.len);
    try std.testing.expect(try owner.isCircuitValid());
    const saved = owner.native_input_ids.items[0];
    owner.native_input_ids.items[0] = 0;
    try std.testing.expectError(error.InvalidNativeInputOrigin, owner.sourceMultiplicitiesForNativeDot(a));
    owner.native_input_ids.items[0] = saved;
    var target = try C.Context.init(a, 0);
    defer target.deinit();
    {
        var dispatch = @import("input_registry.zig").Dispatch{ .owner = &target };
        defer dispatch.deinit();
        var sink = @import("stwo_circuit_frontend").builder.context.Qm31GuessSinkScope.init(.{ .context = &dispatch, .emit = @import("input_registry.zig").Dispatch.emit });
        defer sink.deinit();
        var other = try C.Algebra.init(a, 0);
        defer other.deinit();
        _ = try other.guess(Q.one());
        try std.testing.expectError(error.InvalidWitnessOrigin, other.finalize(false));
    }
    var legacy = try C.Context.init(a, 0);
    defer legacy.deinit();
    _ = try legacy.base.guess(Q.one());
    try legacy.finalize();
    try std.testing.expect(legacy.finalized and !legacy.native_dot_finalized);
    try std.testing.expectEqual(@as(usize, 0), legacy.native_input_ids.items.len);
    try std.testing.expect(try legacy.isCircuitValid());
}
