//! Pure witness/equation/unsigned/range oracle checks; no commitments or proofs.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const P = core.fields.packed_qm31.PackedQM31;
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const Protocol = @import("block_v5_readonly_input_global_protocol_v2.zig");
const Table = @import("block_v5_readonly_input_provider_v2.zig");
const Air = @import("block_v5_readonly_input_provider_component_v2.zig");
const Interaction = @import("block_v5_readonly_input_provider_interaction_v2.zig");
const Framework = @import("../recursion/air/framework_interaction.zig");
const intervals = [_]Plan.Interval{
    .{ .lower = 0, .upper = 1, .readonly = false, .value = 0 },
    .{ .lower = 1, .upper = 2, .readonly = true, .value = 0xffffffff },
    .{ .lower = 2, .upper = Plan.WORD_LIMIT, .readonly = false, .value = 0 },
};
const fragments = [_]Table.Fragment{
    .{ .interval_index = 0, .count = 65535 }, .{ .interval_index = 0, .count = 1 }, .{ .interval_index = 1, .count = 3 },
};
fn shared(a: std.mem.Allocator) !Protocol.Challenges {
    var channel = core.proof_suites.Blake3.Channel{};
    return Protocol.drawFromChannel(a, &channel, @as([32]u8, @splat(2)), @as([32]u8, @splat(3)));
}
fn all(trace: *const Table.Columns, generated: *const Interaction.Generated, challenges: *const Protocol.Challenges) !bool {
    const spec = Air.Spec{ .claim = generated.claim, .challenges = challenges };
    const rows: usize = @as(usize, 1) << @intCast(trace.shape.row_log);
    var domain = try spec.prepareDomain(@intCast(rows));
    for (0..rows) |logical| {
        const now = Framework.committedRow(logical, trace.shape.row_log);
        const before = Framework.committedRow((logical + rows - 1) % rows, trace.shape.row_log);
        var fixed: [10]Q = undefined;
        var main: [18]Q = undefined;
        var prior: [18]Q = undefined;
        var current: [44]Q = undefined;
        var previous: [44]Q = undefined;
        for (&fixed, trace.fixed.columns) |*v, c| v.* = Q.fromBase(c.values[now]);
        for (&main, &prior, trace.main) |*v, *p, c| {
            v.* = Q.fromBase(c.values[now]);
            p.* = Q.fromBase(c.values[before]);
        }
        for (&current, &previous, generated.columns) |*v, *p, c| {
            v.* = Q.fromBase(c.values[now]);
            p.* = Q.fromBase(c.values[before]);
        }
        const equations = try domain.evaluate(fixed, main, prior, current, previous, @intCast(rows));
        var pf: [10]P = undefined;
        var pm: [18]P = undefined;
        var pp: [18]P = undefined;
        var pc: [44]P = undefined;
        var pb: [44]P = undefined;
        for (&pf, fixed) |*v, x| v.* = P.splat(x);
        for (&pm, main) |*v, x| v.* = P.splat(x);
        for (&pp, prior) |*v, x| v.* = P.splat(x);
        for (&pc, current) |*v, x| v.* = P.splat(x);
        for (&pb, previous) |*v, x| v.* = P.splat(x);
        const packed_equations = domain.evaluatePacked(pf, pm, pp, pc, pb);
        for (equations, packed_equations) |equation, packed_equation| {
            if (!equation.isZero()) return false;
            for (0..core.fields.m31.PACK_WIDTH) |lane| if (!packed_equation.lane(lane).eql(equation)) return false;
        }
    }
    return true;
}
test "readonly global provider: fragmented integer carry scalar SIMD and original provider oracle" {
    const a = std.testing.allocator;
    const shape = try Table.shard(0, 7, 0, &intervals, &fragments);
    var trace = try Table.Columns.init(a, &intervals, &fragments, shape, .{});
    defer trace.deinit();
    const base = try shared(a);
    const group = try Protocol.forGroup(base, 7);
    var generated = try Interaction.generate(a, &trace, base);
    defer generated.deinit();
    try std.testing.expect(try all(&trace, &generated, &group));
    try std.testing.expectEqual(@as(u64, 65539), shape.counts.events);
    try std.testing.expectEqual(@as(u64, 3), shape.counts.readonly);
    const Original = @import("block_v5_readonly_input_proof_v1.zig");
    var plan = Plan.Owned{ .a = a, .intervals = try a.dupe(Plan.Interval, &intervals), .digest = @splat(1) };
    defer plan.deinit();
    const pin = Original.Pin{ .plan_digest = plan.digest, .source_identity = @splat(2), .roots = .{ @splat(3), @splat(4) }, .events = 65539, .row_log = 17, .config = .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) } };
    try Original.checkProviders(plan, pin, .{ .source_sum = Q.zero(), .mutable_sum = Q.zero(), .classification_sum = generated.claim.classification_sum.neg(), .read_sum = generated.claim.read_sum.neg(), .readonly_count = 3 }, &.{ 65536, 3, 0 }, &group);
    const Elements = @import("../air/relation_challenges.zig").RelationElements;
    const tuple = @import("block_v5_readonly_input_protocol_v1.zig").intervalTuple(intervals[1]);
    const explicit = Elements(6).init(base.classification.z, base.classification.alpha);
    try std.testing.expect(explicit.combineBase(tuple ++ [_]M{M.fromCanonical(7)}).eql(group.classification.combineBase(tuple)));
}
test "readonly global provider: padding exact range supply and group separation" {
    const a = std.testing.allocator;
    const shape = try Table.shard(0, 1, 0, &intervals, &fragments);
    var trace = try Table.Columns.init(a, &intervals, &fragments, shape, .{});
    defer trace.deinit();
    var counter = try @import("block_v5_range16_v1.zig").Counter.init(a);
    defer counter.deinit();
    try trace.addRangeCounters(&counter);
    try std.testing.expectEqual(shape.counts.range_requests, counter.total);
    try std.testing.expectEqual(@as(u64, 36), counter.total);
    const base = try shared(a);
    var generated = try Interaction.generate(a, &trace, base);
    defer generated.deinit();
    var expected = Q.zero();
    for (counter.values, 0..) |count, value| if (count != 0) {
        expected = expected.add((try base.word.range16.combineBase(.{M.fromCanonical(@intCast(value))}).inv()).mulM31(M.fromCanonical(count)));
    };
    var sum = Q.zero();
    for (generated.claim.range_sums) |v| sum = sum.add(v);
    try std.testing.expect(sum.eql(expected));
    const wrong = try Protocol.forGroup(base, 2);
    try std.testing.expect(!try all(&trace, &generated, &wrong));
}
test "readonly global provider: coherent prefix count padding and public census mutations fail" {
    const a = std.testing.allocator;
    const shape = try Table.shard(0, 0, 0, &intervals, &fragments);
    var trace = try Table.Columns.init(a, &intervals, &fragments, shape, .{});
    defer trace.deinit();
    const base = try shared(a);
    var generated = try Interaction.generate(a, &trace, base);
    defer generated.deinit();
    const rows: usize = 4;
    const physical = Framework.committedRow(1, shape.row_log);
    for ([_]usize{ 0, 1, 9, 13, 17 }) |column| {
        const at = column * rows + physical;
        const value = trace.storage[at];
        trace.storage[at] = value.add(M.one());
        try std.testing.expect(!try all(&trace, &generated, &base));
        trace.storage[at] = value;
    }
    const padding = Framework.committedRow(3, shape.row_log);
    trace.storage[padding] = M.one();
    try std.testing.expect(!try all(&trace, &generated, &base));
    trace.storage[padding] = M.zero();
    generated.claim.counts.events += 65536;
    try std.testing.expect(!try all(&trace, &generated, &base));
}
fn fault(a: std.mem.Allocator) !void {
    const shape = try Table.shard(0, 3, 0, &intervals, &fragments);
    var trace = try Table.Columns.init(a, &intervals, &fragments, shape, .{});
    defer trace.deinit();
    const base = try shared(a);
    const group = try Protocol.forGroup(base, 3);
    var generated = try Interaction.generate(a, &trace, base);
    defer generated.deinit();
    if (!try all(&trace, &generated, &group)) return error.UnsatisfiedReadonlyProvider;
    var counter = try @import("block_v5_range16_v1.zig").Counter.init(a);
    defer counter.deinit();
    try trace.addRangeCounters(&counter);
}
test "readonly global provider: complete column interaction and range allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, fault, .{});
}
test "readonly global provider: invalid order zero fragments group mass and budget reject" {
    try std.testing.expectError(error.InvalidReadonlyProviderFragments, Table.shard(0, 0, 0, &intervals, &.{.{ .interval_index = 0, .count = 0 }}));
    try std.testing.expectError(error.InvalidReadonlyProviderFragments, Table.shard(0, 0, 0, &intervals, &.{ .{ .interval_index = 1, .count = 1 }, .{ .interval_index = 0, .count = 1 } }));
    try std.testing.expectError(error.InvalidReadonlyProviderShard, Table.shard(0, core.fields.m31.Modulus, 0, &intervals, &fragments));
    var shape = try Table.shard(0, 0, 0, &intervals, &fragments);
    shape.counts.events = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidReadonlyProviderShard, shape.require());
    const valid = try Table.shard(0, 0, 0, &intervals, &fragments);
    try std.testing.expectError(error.ReadonlyProviderResourceLimit, Table.Columns.init(std.testing.allocator, &intervals, &fragments, valid, .{ .max_matrix_bytes = 1 }));
}
fn symbolic(a: std.mem.Allocator, mutate: bool) !void {
    const Graph = @import("../recursion/air/block_v5_readonly_input_provider_composition_v2.zig");
    const Recorder = @import("../recursion/air/composition_graph_recorder.zig");
    const shape = try Table.shard(0, 4, 0, &intervals, &fragments);
    var trace = try Table.Columns.init(a, &intervals, &fragments, shape, .{});
    defer trace.deinit();
    const base = try shared(a);
    const challenges = try Protocol.forGroup(base, 4);
    var generated = try Interaction.generate(a, &trace, base);
    defer generated.deinit();
    const domain = try (Air.Spec{ .claim = generated.claim, .challenges = &challenges }).prepareDomain(4);
    var builder = Recorder.Builder.init(a);
    defer builder.deinit();
    var inputs: [134]Q = undefined;
    var cursor: usize = 0;
    var fixed: [10]Graph.S = undefined;
    var main: [18]Graph.S = undefined;
    var prior: [18]Graph.S = undefined;
    var current: [44]Graph.S = undefined;
    var previous: [44]Graph.S = undefined;
    const now = Framework.committedRow(1, shape.row_log);
    const before = Framework.committedRow(0, shape.row_log);
    for (&fixed, trace.fixed.columns) |*value, column| {
        value.* = (try builder.input()).value;
        inputs[cursor] = Q.fromBase(column.values[now]);
        cursor += 1;
    }
    for (&main, trace.main) |*value, column| {
        value.* = (try builder.input()).value;
        inputs[cursor] = Q.fromBase(column.values[now]);
        cursor += 1;
    }
    for (&prior, trace.main) |*value, column| {
        value.* = (try builder.input()).value;
        inputs[cursor] = Q.fromBase(column.values[before]);
        cursor += 1;
    }
    for (&current, generated.columns) |*value, column| {
        value.* = (try builder.input()).value;
        inputs[cursor] = Q.fromBase(column.values[now]);
        cursor += 1;
    }
    for (&previous, generated.columns) |*value, column| {
        value.* = (try builder.input()).value;
        inputs[cursor] = Q.fromBase(column.values[before]);
        cursor += 1;
    }
    std.debug.assert(cursor == inputs.len);
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var shifts: [11]Graph.S = undefined;
    var totals: [8]Graph.S = undefined;
    for (&shifts, domain.shifts) |*value, constant| value.* = Graph.S.fromSecure(constant);
    for (&totals, domain.totals) |*value, constant| value.* = Graph.S.fromSecure(constant);
    const equations = Air.Algebra(Graph.S).equations(fixed, main, prior, current, previous, shifts, &Graph.constants(challenges), totals);
    for (equations) |equation| try builder.constrainZero(equation);
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const values = try a.alloc(Q, circuit.nodes.len);
    defer a.free(values);
    if (mutate) inputs[10 + 9] = inputs[10 + 9].add(Q.one());
    if (mutate) {
        circuit.evaluateInto(&inputs, values) catch |err| {
            if (err == error.UnsatisfiedCircuit) return;
            return err;
        };
        return error.TestExpectedError;
    }
    try circuit.evaluateInto(&inputs, values);
}
fn symbolicFault(a: std.mem.Allocator) !void {
    try symbolic(a, false);
    try symbolic(a, true);
}
test "readonly global provider: original unsigned equations symbolic parity mutation and every graph allocation fault" {
    try symbolic(std.testing.allocator, false);
    try symbolic(std.testing.allocator, true);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, symbolicFault, .{});
}
test "readonly global provider: streaming large multiplicities exact exhaustion census" {
    var cursor = try Table.FragmentCursor.init(&.{ 131071, 0, 65536 }, 196607);
    const expected = [_]Table.Fragment{ .{ .interval_index = 0, .count = 65535 }, .{ .interval_index = 0, .count = 65535 }, .{ .interval_index = 0, .count = 1 }, .{ .interval_index = 2, .count = 65535 }, .{ .interval_index = 2, .count = 1 } };
    for (expected) |fragment| try std.testing.expectEqualDeep(fragment, (try cursor.next()).?);
    try std.testing.expect((try cursor.next()) == null);
    try std.testing.expectEqual(@as(u64, 5), cursor.emitted);
    var wrong = try Table.FragmentCursor.init(&.{1}, 2);
    _ = try wrong.next();
    try std.testing.expectError(error.UntrustedReadonlyProviderCensus, wrong.next());
    var overflow = try Table.FragmentCursor.init(&.{65536}, 65535);
    try std.testing.expectError(error.UntrustedReadonlyProviderCensus, overflow.next());
}
