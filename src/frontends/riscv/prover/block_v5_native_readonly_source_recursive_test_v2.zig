//! Scalar/packed/symbolic original-AIR and transcript/transport ownership
//! oracles only. No PCS, STARK, FRI, recursive proof or guest invocation.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const P = core.fields.packed_qm31.PackedQM31;
const Original = @import("block_v5_readonly_input_proof_v1.zig");
const Air = @import("block_v5_readonly_input_component_v1.zig");
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const Native = @import("block_v5_native_readonly_source_proof_v2.zig");
const Trace = @import("block_v5_native_readonly_source_trace_v2.zig");
const Global = @import("block_v5_readonly_input_global_protocol_v2.zig");
const Statement = @import("../recursion/air/block_v5_native_readonly_source_statement_v2.zig");
const Bus = @import("../recursion/block_v5_native_readonly_source_recursive_public_bus_v2.zig");
const Framework = @import("../recursion/air/framework_interaction.zig");
const Event = @import("../air/block/memory_transition.zig").Transition;
const intervals = [_]Plan.Interval{
    .{ .lower = 0, .upper = 1, .readonly = false, .value = 0 },
    .{ .lower = 1, .upper = 2, .readonly = true, .value = 0xfedcba98 },
    .{ .lower = 2, .upper = Plan.WORD_LIMIT, .readonly = false, .value = 0 },
};
const events = [_]Event{
    .{ .space = 1, .address = 0, .clock = 0xffffffffffffffff, .before = 2, .after = 3 },
    .{ .space = 1, .address = 4, .clock = 0x8000000000000001, .before = 0xfedcba98, .after = 0xfedcba98 },
    .{ .space = 1, .address = 0xfffffffc, .clock = 0x100000001, .before = 9, .after = 13 },
};
fn physical() !Original.Pin {
    return .{ .plan_digest = @splat(1), .source_identity = @splat(2), .events = 3, .row_log = 2, .roots = .{ @splat(3), @splat(4) }, .config = .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) } };
}
fn source() !Native.Pin {
    return .{ .ordinal = 9, .group_id = 7, .index = 3, .source_roots = .{ @splat(5), @splat(6), @splat(7) }, .census = .{ .all_rw = 3, .mutable = 2, .readonly = 1 }, .classifier = try physical() };
}
fn claim() @import("block_v5_readonly_input_protocol_v1.zig").Claim {
    return .{ .source_sum = Q.fromBase(M.fromCanonical(17)), .mutable_sum = Q.fromBase(M.fromCanonical(19)), .classification_sum = Q.fromBase(M.fromCanonical(23)), .read_sum = Q.fromBase(M.fromCanonical(29)), .readonly_count = 1 };
}
fn stream(a: std.mem.Allocator) !Trace.Owned {
    var builder = try Trace.Builder.init(a, try physical(), &intervals, @splat(1));
    defer builder.deinit();
    for (events, [_]usize{ 0, 1, 2 }) |event, ordinal| try builder.append(event, ordinal);
    return builder.finish();
}
fn streamingFault(a: std.mem.Allocator) !void {
    var owned = try stream(a);
    defer owned.deinit();
    const pin = try physical();
    var oracle = try Original.Trace.initIntervals(a, &intervals, pin.plan_digest, &events, pin);
    defer oracle.deinit(a);
    if (!std.mem.eql(M, oracle.storage, owned.original.storage) or owned.original.counters.len != 0) return error.NativeReadonlyV2WitnessMismatch;
}
test "readonly native recursive v2: streaming full-clock original witness parity and every allocation fault" {
    try streamingFault(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, streamingFault, .{});
}
test "readonly native recursive v2: exact event census partition membership and immutable writes reject" {
    const a = std.testing.allocator;
    var builder = try Trace.Builder.init(a, try physical(), &intervals, @splat(1));
    defer builder.deinit();
    try std.testing.expectError(error.InvalidNativeReadonlyV2TraceCensus, builder.finish());
    try std.testing.expectError(error.InvalidReadonlyInputClassification, builder.append(events[0], 1));
    var altered = events[1];
    altered.after ^= 1;
    try std.testing.expectError(error.InvalidReadonlyInputClassification, builder.append(altered, 1));
    for (events, [_]usize{ 0, 1, 2 }) |event, ordinal| try builder.append(event, ordinal);
    try std.testing.expectError(error.InvalidNativeReadonlyV2TraceCensus, builder.append(events[0], 0));
    var owned = try builder.finish();
    defer owned.deinit();
    try std.testing.expectError(error.NativeReadonlyV2TraceFinished, builder.finish());
    var invalid = intervals;
    invalid[2].lower += 1;
    try std.testing.expectError(error.InvalidReadonlyInputPartition, Trace.Builder.init(a, try physical(), &invalid, @splat(1)));
    try std.testing.expectError(error.UntrustedNativeReadonlyV2TracePlan, Trace.Builder.init(a, try physical(), &intervals, @splat(8)));
}
fn framingFault(a: std.mem.Allocator) !void {
    const pin = try source();
    const epoch = Global.Epoch{ .plan_digest = @splat(1), .roster_digest = @splat(11) };
    var frame = try Statement.record(a, pin, @splat(13), epoch, claim());
    defer frame.deinit();
    var first = core.proof_suites.Blake3.Channel{};
    try frame.replay(&first, frame.first);
    if (!std.meta.eql(first, Native.firstChannel(pin))) return error.NativeReadonlyV2FrameMismatch;
    var replay = core.proof_suites.Blake3.Channel{};
    var direct = replay;
    try frame.replay(&replay, frame.claims[0..4]);
    Global.mixSuffix(&direct, epoch.plan_digest, epoch.roster_digest);
    if (!std.meta.eql(replay, direct)) return error.NativeReadonlyV2FrameMismatch;
    const replay_draws = try replay.drawSecureFelts(a, 4);
    defer a.free(replay_draws);
    const direct_draws = try direct.drawSecureFelts(a, 4);
    defer a.free(direct_draws);
    if (!std.meta.eql(replay_draws, direct_draws) or !std.meta.eql(replay, direct)) return error.NativeReadonlyV2FrameMismatch;
    // The original post-draw operations remain exactly framed. No authenticated
    // epoch or verified proof result is fabricated by this channel oracle.
    try frame.replay(&replay, frame.claims[4..]);
    try Native.mixPcsSuffix(&direct, pin, claim());
    if (!std.meta.eql(replay, direct)) return error.NativeReadonlyV2FrameMismatch;
    for (0..2) |i| if (!std.meta.eql(try frame.digest(frame.roots_offset[i]), pin.classifier.roots[i])) return error.NativeReadonlyV2FrameMismatch;
    var cloned = try frame.clone(a);
    defer cloned.deinit();
    if (!std.meta.eql(frame.words, cloned.words) or !std.meta.eql(frame.claims, cloned.claims)) return error.NativeReadonlyV2FrameMismatch;
}
test "readonly native recursive v2: exact original first shared suffix claim frames and owner faults" {
    try framingFault(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, framingFault, .{});
}
test "readonly native recursive v2: public byte roots group claims and framing tamper are exact" {
    const a = std.testing.allocator;
    const pin = try source();
    const epoch = Global.Epoch{ .plan_digest = @splat(1), .roster_digest = @splat(11) };
    var frame = try Statement.record(a, pin, @splat(13), epoch, claim());
    defer frame.deinit();
    var values = Bus.Values{ .allocator = a, .template = @splat(17), .statement = try frame.clone(a), .public = try a.alloc(Q, 6), .roots_count = 2 };
    defer values.deinit();
    values.public[0..4].* = .{ claim().source_sum, claim().mutable_sum, claim().classification_sum, claim().read_sum };
    values.public[4] = Q.one();
    values.public[5] = Q.fromBase(M.fromCanonical(pin.group_id));
    try values.validate();
    const bytes = try values.at(.first_root, 0);
    for (bytes) |byte| try std.testing.expectEqual(@as(u32, 3), byte.toU32());
    try std.testing.expectEqualDeep(values.public[5].toM31Array(), try values.at(.public_input, 5));
    try std.testing.expectError(error.InvalidFusedRecursivePublicSchedule, values.at(.public_input, 6));
    var owned = try values.clone(a);
    defer owned.deinit();
    values.statement.words[values.statement.roots_offset[0]] ^= 1;
    try std.testing.expect(!std.meta.eql(try owned.at(.first_root, 0), try values.at(.first_root, 0)));
    var invalid = claim();
    invalid.readonly_count += 1;
    try std.testing.expectError(error.InvalidNativeReadonlyV2Claim, Statement.record(a, pin, @splat(13), epoch, invalid));
    var replay = core.proof_suites.Blake3.Channel{};
    const retained = frame.first[0];
    frame.first[0] = .{ .words = .{ .first = @intCast(frame.words.len), .len = 1 } };
    try std.testing.expectError(error.InvalidRecursiveStatementFrames, frame.replay(&replay, frame.first));
    frame.first[0] = retained;
}
fn equations(a: std.mem.Allocator, mutate: bool) !void {
    var trace = try stream(a);
    defer trace.deinit();
    var channel = core.proof_suites.Blake3.Channel{};
    const shared = try Global.drawFromChannel(a, &channel, @splat(1), @splat(11));
    const group = try Global.forGroup(shared, 7);
    var interaction = try Original.generateInteraction(a, &trace.original, try physical(), &group);
    defer interaction.deinit(a);
    const domain = try (Air.Spec{ .claim = interaction.claim, .challenges = &group }).prepareDomain(4);
    const Recorder = @import("../recursion/air/composition_graph_recorder.zig");
    const Graph = @import("../recursion/air/block_v5_native_readonly_source_composition_v2.zig");
    var builder = Recorder.Builder.init(a);
    defer builder.deinit();
    var inputs: [145]Q = undefined;
    var cursor: usize = 0;
    const symbol = (try builder.input()).value;
    const now = Framework.committedRow(1, 2);
    const before = Framework.committedRow(0, 2);
    inputs[cursor] = Q.fromBase(trace.original.fixed[0].values[now]);
    cursor += 1;
    var main: [103]Recorder.Scalar = undefined;
    var current: [20]Recorder.Scalar = undefined;
    var previous: [20]Recorder.Scalar = undefined;
    for (&main, trace.original.main) |*out, column| {
        out.* = (try builder.input()).value;
        inputs[cursor] = Q.fromBase(column.values[now]);
        cursor += 1;
    }
    for (&current, interaction.columns) |*out, column| {
        out.* = (try builder.input()).value;
        inputs[cursor] = Q.fromBase(column.values[now]);
        cursor += 1;
    }
    for (&previous, interaction.columns) |*out, column| {
        out.* = (try builder.input()).value;
        inputs[cursor] = Q.fromBase(column.values[before]);
        cursor += 1;
    }
    const group_symbol = (try builder.input()).value;
    inputs[cursor] = Q.fromBase(M.fromCanonical(7));
    cursor += 1;
    std.debug.assert(cursor == inputs.len);
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    const S = Recorder.Scalar;
    var shifts: [5]S = undefined;
    for (&shifts, domain.shifts) |*out, value| out.* = S.fromSecure(value);
    const graph_challenges = Graph.groupedChallenges(.{ S.fromSecure(shared.word.transition.z), S.fromSecure(shared.word.transition.alpha) }, .{ S.fromSecure(shared.classification.z), S.fromSecure(shared.classification.alpha) }, .{ S.fromSecure(shared.read.z), S.fromSecure(shared.read.alpha) }, group_symbol);
    for (Air.Algebra(S).equations(symbol, main, current, previous, shifts, &graph_challenges)) |equation| try builder.constrainZero(equation);
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const values = try a.alloc(Q, circuit.nodes.len);
    defer a.free(values);
    if (mutate) {
        inputs[144] = inputs[144].add(Q.one());
        circuit.evaluateInto(&inputs, values) catch |err| {
            if (err != error.UnsatisfiedCircuit) return err;
            inputs[144] = inputs[144].sub(Q.one());
            inputs[1 + Air.Layout.after] = inputs[1 + Air.Layout.after].add(Q.one());
            circuit.evaluateInto(&inputs, values) catch |second| {
                if (second == error.UnsatisfiedCircuit) return;
                return second;
            };
            return error.TestExpectedError;
        };
        return error.TestExpectedError;
    }
    try circuit.evaluateInto(&inputs, values);
    // The same exact205 expressions also remain valid in SIMD broadcasting.
    var pm: [103]P = undefined;
    var pc: [20]P = undefined;
    var pp: [20]P = undefined;
    for (&pm, inputs[1..104]) |*out, value| out.* = P.splat(value);
    for (&pc, inputs[104..124]) |*out, value| out.* = P.splat(value);
    for (&pp, inputs[124..144]) |*out, value| out.* = P.splat(value);
    const pe = Air.Algebra(P).equations(P.splat(inputs[0]), pm, pc, pp, domain.packed_shifts, &group);
    for (pe) |equation| for (0..core.fields.m31.PACK_WIDTH) |lane| if (!equation.lane(lane).isZero()) return error.NativeReadonlyV2PackedMismatch;
}
fn equationFault(a: std.mem.Allocator) !void {
    try equations(a, false);
    try equations(a, true);
}
test "readonly native recursive v2: original205 symbolic SIMD mutation and every graph allocation fault" {
    try equationFault(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, equationFault, .{});
}
