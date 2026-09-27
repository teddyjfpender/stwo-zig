//! Full six-table point-equation oracle, independent policy, public closure and
//! allocation cleanup. Arbitrary OODS values/literal roots are not proof captures.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const tables = @import("../air/lookups/tables/mod.zig");
const Native = @import("block_v5_native_lookup_proof_v1.zig");
const Assembly = @import("block_v5_native_lookup_assembly_v1.zig");
const Admission = @import("block_v5_native_lookup_recursive_admission_v1.zig");
const Bus = @import("../recursion/block_v5_native_lookup_recursive_public_bus_v1.zig");
const Protocol = @import("../recursion/block_v5_reusable_native_lookup_parent_protocol_v1.zig");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Recorder = @import("../recursion/air/composition_graph_recorder.zig");
const S = Recorder.Scalar;
const Composition = @import("../recursion/air/block_v5_native_lookup_composition_v1.zig");
const Universal = @import("../recursion/air/universal_challenges.zig");
const Shared = @import("../recursion/air/universal_provider_relations.zig");
fn scalar(seed: u32) Q {
    return Q.fromU32Unchecked(seed + 1, seed + 2, seed + 3, seed + 4);
}
const Fixture = struct {
    plan: Native.Plan,
    roots: [2][32]u8,
    entries: [6]Seal.Entry,
    pins: Seal.Pins,
    sealed: Seal.Sealed,
    fn init() !Fixture {
        const plan = Native.Plan{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = .{ 11, 12, 13, 14, 15, 16 } };
        const roots: [2][32]u8 = .{ @splat(8), @splat(9) };
        const entries = [_]Seal.Entry{
            .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
            .{ .family = .execution, .index = 0, .instance_id = @splat(20), .roots = .{ @splat(21), @splat(22) } },
            .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(30), .roots = .{ @splat(31), @splat(32) } },
            .{ .family = .program_request, .index = 0, .instance_id = @splat(40), .roots = .{ @splat(41), @splat(42) } },
            .{ .family = .memory, .index = 0, .instance_id = @splat(50), .roots = .{ @splat(51), @splat(52) } },
            .{ .family = .native_lookup, .index = 0, .instance_id = try plan.identity(), .roots = roots },
        };
        var counts: [Seal.family_count]u32 = @splat(0);
        for (entries) |entry| counts[@intFromEnum(entry.family) - 1] += 1;
        const pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = @splat(6), .initial_source_plan_digest = @splat(7), .config = Base.PCS_CONFIG, .counts = counts };
        return .{ .plan = plan, .roots = roots, .entries = entries, .pins = pins, .sealed = try Seal.seal(pins, &entries) };
    }
    fn prepared(self: *const Fixture, a: std.mem.Allocator) !Admission.Prepared {
        return Admission.Prepared.init(a, self.plan, self.roots, self.sealed, self.pins, &self.entries, .{});
    }
};
const Equation = struct {
    arena: std.heap.ArenaAllocator,
    circuit: Recorder.Circuit,
    inputs: []Q,
    evaluated: []Q,
    claims: [6]usize,
    main: [6]usize,
    fixed: [6]usize,
    previous: [6]usize,
    challenges: [6]usize,
    chunk: usize,
    fn deinit(self: *Equation) void {
        self.circuit.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
    fn evaluate(self: *Equation) !void {
        try self.circuit.evaluateInto(self.inputs, self.evaluated);
    }
};
fn input(builder: *Recorder.Builder, a: std.mem.Allocator, inputs: *std.ArrayList(Q), value: Q) !S {
    const symbol = try builder.input();
    try inputs.append(a, value);
    return symbol.value;
}
fn equation(a: std.mem.Allocator, claim_seed: u32) !Equation {
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var channel = core.proof_suites.Blake3.Channel{};
    const universal = try Universal.UniversalRelations.draw(temp, &channel);
    const relations = try Shared.SharedProviderRelations.init(&universal);
    var claims: [6]Q = undefined;
    for (&claims, 0..) |*claim, index| claim.* = scalar(claim_seed + @as(u32, @intCast(7 * index)));
    const owner = try Assembly.Owner.init(a, relations, claims);
    defer owner.destroy(a);
    const handles = owner.verifierHandles();
    const all = core.air.components.Components{ .components = &handles, .n_preprocessed_columns = Composition.FIXED_COLUMNS };
    try std.testing.expectEqual(Composition.COMPOSITION_LOG, all.compositionLogDegreeBound());
    try std.testing.expectEqual(@as(u32, 1), try all.compositionLogSplit());
    const point = try core.circle.secureFieldPointFromRandomSeedChecked(scalar(71));
    var masks = try all.maskPoints(temp, point, Composition.MASK_LOG, false);
    defer masks.deinitDeep(temp);
    const widths = [_]usize{ 20, 6, 24 };
    var builder = Recorder.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var fixed: [20]S = undefined;
    var main: [6]S = undefined;
    var current: [24]S = undefined;
    var previous: [24]S = undefined;
    var out = Equation{ .arena = undefined, .circuit = undefined, .inputs = undefined, .evaluated = undefined, .claims = undefined, .main = undefined, .fixed = undefined, .previous = undefined, .challenges = undefined, .chunk = undefined };
    const concrete = try temp.alloc([][]Q, 3);
    for (masks.items, concrete, widths, 0..) |tree, *values, width, t| {
        try std.testing.expectEqual(width, tree.len);
        values.* = try temp.alloc([]Q, width);
        for (tree, values.*, 0..) |points, *coordinates, column| {
            try std.testing.expectEqual(if (t == 2) @as(usize, 2) else 1, points.len);
            coordinates.* = try temp.alloc(Q, points.len);
            for (coordinates.*, 0..) |*value, j| {
                value.* = scalar(@intCast(10 + 101 * t + 7 * column + 3 * j));
                const offset = inputs.items.len;
                const symbol = try input(&builder, temp, &inputs, value.*);
                if (t == 0) fixed[column] = symbol else if (t == 1) {
                    main[column] = symbol;
                    out.main[column] = offset;
                } else if (j == 0) current[column] = symbol else {
                    previous[column] = symbol;
                    if (column % 4 == 0) out.previous[column / 4] = offset;
                }
            }
        }
    }
    var fixed_at: usize = 0;
    for (0..6) |index| {
        out.fixed[index] = fixed_at;
        fixed_at += 1 + tables.schema.arity(@enumFromInt(index));
    }
    var draws: [Universal.RELATION_COUNT][2]S = undefined;
    for (&draws, universal.elements, 0..) |*pair, element, index| {
        for (0..6) |kind| if (index == @intFromEnum(tables.schema.domain(@enumFromInt(kind)))) {
            out.challenges[kind] = inputs.items.len;
        };
        pair[0] = try input(&builder, temp, &inputs, element.z);
        pair[1] = try input(&builder, temp, &inputs, element.alpha);
    }
    var claims_symbol: [6]S = undefined;
    for (&claims_symbol, claims, 0..) |*symbol, value, index| {
        out.claims[index] = inputs.items.len;
        symbol.* = try input(&builder, temp, &inputs, value);
    }
    const randomness = scalar(17);
    var native_mask = core.air.components.MaskValues{ .items = concrete };
    const accumulated = try all.evalCompositionPolynomialAtPoint(point, &native_mask, randomness, Composition.MASK_LOG);
    const chunk1 = scalar(33);
    // The native split recombines two chunks with T_(log-2)(x), not
    // T_(log-1)(x). Check this fixture against the actual proof extractor,
    // independently of the symbolic recorder that consumes these chunks.
    const chunk0 = accumulated.sub(point.repeatedDouble(Composition.COMPOSITION_LOG - 2).x.mul(chunk1));
    const rebuilt = core.proof.reconstructCompositionChunkEvals(&.{ chunk0, chunk1 }, point, Composition.COMPOSITION_LOG, 1) orelse return error.InvalidLookupOracleComposition;
    try std.testing.expect(rebuilt.eql(accumulated));
    const shifted_chunk0 = accumulated.sub(point.repeatedDouble(Composition.COMPOSITION_LOG - 1).x.mul(chunk1));
    const shifted = core.proof.reconstructCompositionChunkEvals(&.{ shifted_chunk0, chunk1 }, point, Composition.COMPOSITION_LOG, 1) orelse return error.InvalidLookupOracleComposition;
    try std.testing.expect(!shifted.eql(accumulated));
    const random_symbol = try input(&builder, temp, &inputs, randomness);
    const seed_symbol = try input(&builder, temp, &inputs, scalar(71));
    out.chunk = inputs.items.len;
    const chunks = [2]S{ try input(&builder, temp, &inputs, chunk0), try input(&builder, temp, &inputs, chunk1) };
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    const challenges = try Recorder.ChallengeSet.init(draws);
    try Composition.recordEquation(&builder, fixed, main, current, previous, claims_symbol, &challenges, random_symbol, seed_symbol, chunks);
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const evaluated = try temp.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs.items, evaluated);
    out.arena = arena;
    out.circuit = circuit;
    out.inputs = inputs.items;
    out.evaluated = evaluated;
    return out;
}
test "lookup recursion: all six original mixed-domain CPU equations and masks equal symbolic recurrence and split quotient" {
    var first = try equation(std.testing.allocator, 111);
    defer first.deinit();
    var second = try equation(std.testing.allocator, 211);
    defer second.deinit();
    try std.testing.expectEqualDeep(first.circuit.identity_digest, second.circuit.identity_digest);
    for ([_][6]usize{ first.claims, first.main, first.fixed, first.previous, first.challenges }) |indices| for (indices) |index| {
        const old = first.inputs[index];
        first.inputs[index] = old.add(Q.one());
        defer first.inputs[index] = old;
        try std.testing.expectError(error.UnsatisfiedCircuit, first.evaluate());
        first.inputs[index] = old;
        try first.evaluate();
    };
    first.inputs[first.chunk] = first.inputs[first.chunk].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, first.evaluate());
}
fn equationAllocation(a: std.mem.Allocator) !void {
    var owned = try equation(a, 111);
    defer owned.deinit();
    try owned.evaluate();
}
test "lookup recursion: full equation graph allocation failures release arena owner and recorder" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, equationAllocation, .{});
}
fn policyAllocation(a: std.mem.Allocator) !void {
    const fixture = try Fixture.init();
    var admitted = try fixture.prepared(a);
    defer admitted.deinit();
    try admitted.validate(admitted.template_id);
}
test "lookup recursion: independent full table geometry group roots bounds and configuration reject substitutions" {
    const fixture = try Fixture.init();
    var admitted = try fixture.prepared(std.testing.allocator);
    defer admitted.deinit();
    try admitted.validate(admitted.template_id);
    const widths = [_]usize{ 20, 6, 24 };
    for (admitted.logs, widths) |logs, width| try std.testing.expectEqual(width, logs.len);
    for (admitted.logs) |logs| for (logs) |*log| {
        const old = log.*;
        log.* += 1;
        defer log.* = old;
        try std.testing.expectError(error.UntrustedLookupRecursiveGeometry, admitted.validate(admitted.template_id));
        log.* = old;
    };
    var wrong = admitted;
    wrong.plan.max_requests[1] += 1;
    try std.testing.expectError(error.UntrustedBlockV5NativeLookupRoots, wrong.validate(admitted.template_id));
    wrong = admitted;
    wrong.plan.execution_count += 1;
    try std.testing.expectError(error.InvalidBlockV5LookupExecutionSpan, wrong.validate(admitted.template_id));
    wrong = admitted;
    wrong.roots[1][0] ^= 1;
    try std.testing.expectError(error.UntrustedBlockV5NativeLookupRoots, wrong.validate(admitted.template_id));
    wrong = admitted;
    wrong.index = 1;
    try std.testing.expectError(error.UntrustedLookupRecursiveAdmission, wrong.validate(admitted.template_id));
    wrong = admitted;
    wrong.config.pow_bits += 1;
    try std.testing.expectError(error.UntrustedLookupRecursiveAdmission, wrong.validate(admitted.template_id));
    wrong = admitted;
    wrong.limits.max_preparation_bytes = 0;
    try std.testing.expectError(error.UntrustedLookupRecursiveAdmission, wrong.validate(admitted.template_id));
    wrong = admitted;
    wrong.limits.max_capture_bytes = 0;
    try std.testing.expectError(error.UntrustedLookupRecursiveAdmission, wrong.validate(admitted.template_id));
    var expected = admitted.template_id;
    expected[0] ^= 1;
    try std.testing.expectError(error.UntrustedLookupRecursiveAdmission, admitted.validate(expected));
    try std.testing.checkAllAllocationFailures(std.testing.allocator, policyAllocation, .{});
}
test "lookup recursion: original B5SS universal and all six B5LT claim frames replay exact channel without restart" {
    const fixture = try Fixture.init();
    var admitted = try fixture.prepared(std.testing.allocator);
    defer admitted.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var r = @import("../recursion/air/blake3_native_recorder.zig").Recorder{ .a = arena.allocator(), .universal_relations = true };
    var claims: [6]Q = undefined;
    for (&claims, 0..) |*claim, index| claim.* = scalar(@intCast(41 + index));
    const actual = try @import("../recursion/air/block_v5_native_lookup_transcript_v1.zig").prefix(arena.allocator(), &r, &admitted, claims);
    const expected = try Native.channelFor(arena.allocator(), fixture.plan, fixture.roots, fixture.sealed, claims);
    try std.testing.expectEqualDeep(expected, r.native);
    try std.testing.expectEqual(@as(usize, 47), r.relation_count);
    try std.testing.expectEqual(@as(usize, 2), r.root_count);
    var original = fixture.sealed.sharedChannel();
    try std.testing.expectEqualDeep(try Universal.UniversalRelations.draw(arena.allocator(), &original), actual);
    for (r.operations.items) |operation| try std.testing.expect(operation != .restart);
    for (0..6) |index| {
        var changed = claims;
        changed[index] = changed[index].add(Q.one());
        const other = try Native.channelFor(arena.allocator(), fixture.plan, fixture.roots, fixture.sealed, changed);
        try std.testing.expect(!std.meta.eql(expected.digestBytes(), other.digestBytes()));
    }
}
const public_wires = [_]Bus.Wire{
    .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = 0, .uses = 2, .source = .sealed, .coordinate = 0 },
    .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = 8, .uses = 2, .source = .plan, .coordinate = 0 },
    .{ .circuit = 1500, .wire = 1, .uses = 1, .source = .claim, .coordinate = 0 },
    .{ .circuit = 1500, .wire = 2, .uses = 1, .source = .claim, .coordinate = 1 },
    .{ .circuit = 1500, .wire = 3, .uses = 1, .source = .claim, .coordinate = 2 },
    .{ .circuit = 1500, .wire = 4, .uses = 1, .source = .claim, .coordinate = 3 },
    .{ .circuit = 1500, .wire = 5, .uses = 1, .source = .claim, .coordinate = 4 },
    .{ .circuit = 1500, .wire = 6, .uses = 1, .source = .claim, .coordinate = 5 },
    .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = 39, .uses = 2, .source = .claim_words, .coordinate = 23 },
    .{ .circuit = @import("../recursion/air/blake3_root_sources.zig").CIRCUIT, .wire = 8, .uses = 8, .source = .main_root, .coordinate = 0 },
};
fn publicValues() !Bus.Values {
    const plan = Native.Plan{ .index = 0, .first_execution = 0, .execution_count = 3, .max_requests = .{ 2, 3, 4, 5, 6, 7 } };
    var claims: [6]Q = undefined;
    for (&claims, 0..) |*claim, index| claim.* = scalar(@intCast(51 + index));
    return .{ .template = @splat(1), .sealed = @splat(2), .plan = plan, .plan_id = try plan.identity(), .roots = .{ @splat(4), @splat(5) }, .claims = claims };
}
test "lookup recursion: independent full group and six public claims reject key schedule closure or count relabel" {
    const first = try publicValues();
    const key = try Protocol.Key.fromGeometry(.{ .profile = .diagnostic_q8_pow0, .config = Base.PCS_CONFIG, .context = .{ .child_key_id = first.template, .child_config = Base.PCS_CONFIG, .graph_ids = .{ @splat(6), @splat(7), @splat(8) }, .transcript_plan_id = @splat(9) }, .log_sizes = @splat(4), .preprocessed_root = @splat(10) }, &public_wires);
    const id = try key.identity();
    const authority = try Protocol.Admission.init(key, id, &public_wires, first);
    var channel = core.proof_suites.Blake3.Channel{};
    const relations = try Universal.UniversalRelations.draw(std.testing.allocator, &channel);
    const baseline = try Bus.supply(&public_wires, first, relations);
    var closed: @import("../recursion/blake3_native_parent_artifact.zig").Claims = @splat(Q.zero());
    closed[0] = baseline.neg();
    try authority.validateClaimsForRelations(closed, relations);
    for (0..6) |index| {
        var changed = first;
        changed.claims[index] = changed.claims[index].add(Q.one());
        const other = try Protocol.Admission.init(key, id, &public_wires, changed);
        try std.testing.expect(!std.meta.eql(try authority.publicInputIdentity(), try other.publicInputIdentity()));
        try std.testing.expectError(error.InvalidReusableLookupParentPublicClosure, other.validateClaimsForRelations(closed, relations));
    }
    var changed = first;
    changed.plan.max_requests[0] += 1;
    try std.testing.expectError(error.InvalidLookupPublicInputs, changed.validate());
    changed.plan_id = try changed.plan.identity();
    const other = try Protocol.Admission.init(key, id, &public_wires, changed);
    try std.testing.expectError(error.InvalidReusableLookupParentPublicClosure, other.validateClaimsForRelations(closed, relations));
    var stale = id;
    stale[0] ^= 1;
    try std.testing.expectError(error.UntrustedReusableLookupParentKey, Protocol.Admission.init(key, stale, &public_wires, first));
    var schedule = public_wires;
    schedule[8].coordinate = 24;
    try std.testing.expectError(error.InvalidLookupPublicSchedule, Bus.scheduleDigest(&schedule));
    schedule = public_wires;
    schedule[3].wire = schedule[2].wire;
    try std.testing.expectError(error.InvalidLookupPublicSchedule, Bus.scheduleDigest(&schedule));
    changed = first;
    changed.template[0] ^= 1;
    try std.testing.expectError(error.UntrustedLookupRecursiveTemplate, Protocol.Admission.init(key, id, &public_wires, changed));
    changed = first;
    changed.plan.max_requests[0] = core.fields.m31.Modulus;
    try std.testing.expectError(error.BlockV5LookupGroupExceedsField, changed.validate());
    changed = first;
    changed.claims[1].c0.a.v = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidLookupPublicInputs, changed.validate());
}
fn countersAllocation(a: std.mem.Allocator) !void {
    var counters = try tables.counter.Set.init(a);
    defer counters.deinit(a);
    const plan = Native.Plan{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = @splat(1) };
    for (&counters.counters, 0..) |*counter, index| try counter.registerBase(if (index % 2 == 0) M.one() else M.one().neg(), (try tables.schema.tupleAt(counter.kind, index)).slice());
    try Native.validateSourceCounters(&counters, plan);
    var too_small = plan;
    too_small.max_requests[1] = 0;
    try std.testing.expectError(error.BlockV5NativeLookupDemandExceeded, Native.validateSourceCounters(&counters, too_small));
    {
        const old = counters.counters[0].values[0];
        counters.counters[0].values[0].v = core.fields.m31.Modulus;
        defer counters.counters[0].values[0] = old;
        try std.testing.expectError(error.NonCanonicalM31, Native.validateSourceCounters(&counters, plan));
    }
    {
        const full = counters.counters[5].values;
        counters.counters[5].values = full[0 .. full.len - 1];
        defer counters.counters[5].values = full;
        try std.testing.expectError(error.InvalidBlockV5NativeLookupCounter, Native.validateSourceCounters(&counters, plan));
    }
}
test "lookup recursion: all six actual counter schemas retain signed absolute census and allocation cleanup" {
    try countersAllocation(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, countersAllocation, .{});
}
test "lookup recursion: leaf independent policy rejects stale recursive ID before proof decoding and stage profile before capture" {
    const fixture = try Fixture.init();
    var admitted = try fixture.prepared(std.testing.allocator);
    defer admitted.deinit();
    var claims: [6]Q = undefined;
    var total = Q.zero();
    for (&claims, 0..) |*claim, index| {
        claim.* = scalar(@intCast(51 + index));
        total = total.add(claim.*);
    }
    const candidate = Native.OpenReceipt{ .plan_id = try fixture.plan.identity(), .roots = fixture.roots, .sealed_digest = fixture.sealed.digest, .claims = claims, .total = total };
    const values = try Bus.Values.fromLookup(&admitted, candidate);
    const key = try Protocol.Key.fromGeometry(.{ .profile = .diagnostic_q8_pow0, .config = Base.PCS_CONFIG, .context = .{ .child_key_id = values.template, .child_config = Base.PCS_CONFIG, .graph_ids = .{ @splat(6), @splat(7), @splat(8) }, .transcript_plan_id = @splat(9) }, .log_sizes = @splat(4), .preprocessed_root = @splat(10) }, &public_wires);
    var stale = try key.identity();
    stale[0] ^= 1;
    try std.testing.expectError(error.UntrustedReusableLookupParentKey, @import("../recursion/block_v5_native_lookup_recursive_leaf_v1.zig").verify(std.testing.allocator, &.{}, key, stale, &public_wires, &admitted, candidate));
    var tampered = candidate;
    tampered.total = tampered.total.add(Q.one());
    try std.testing.expectError(error.UntrustedLookupPublicInputs, Bus.Values.fromLookup(&admitted, tampered));
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const Stage = @import("block_v5_native_lookup_recursive_stage_v1.zig").ForBackend(Cpu);
    const Reject = struct {
        fn put(_: *anyopaque, _: u32, _: *@import("block_v5_native_lookup_recursive_stage_v1.zig").Artifact) anyerror!void {
            return error.UnexpectedLookupPublication;
        }
    };
    var placeholder: u8 = 0;
    try std.testing.expectError(error.LookupRecursiveSecurityMismatch, Stage.publish(std.testing.allocator, undefined, &admitted, .{ .profile = .csp_q70_pow26 }, .{ .context = &placeholder, .put_lookup = Reject.put }));
}
