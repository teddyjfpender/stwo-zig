//! Original scalar quotient oracle, transcript-byte parity and independent
//! policy/ownership faults. No proof capture or STARK success is fabricated.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const R = @import("../recursion/air/composition_graph_recorder.zig");
const S = R.Scalar;
const BaseFixture = @import("tests/block_v5_caller_capture_unit_test.zig").Fixture;
const Admission = @import("block_v5_caller_readonly_global_recursive_admission_v2.zig");
const Composition = @import("../recursion/air/block_v5_caller_readonly_global_composition_v2.zig");
const Statement = @import("../recursion/air/block_v5_caller_readonly_global_statement_v2.zig");
const Bus = @import("../recursion/block_v5_caller_readonly_global_recursive_public_bus_v2.zig");
const Fused = Admission.Fused;
const Original1 = @import("block_v5_caller_readonly_proof_v1.zig");
const Roster = @import("block_v5_readonly_input_global_roster_v2.zig");
const Global = @import("block_v5_readonly_input_global_protocol_v2.zig");
fn value(seed: usize) Q {
    return Q.fromU32Unchecked(@intCast(7 + seed * 3), @intCast(11 + seed * 5), @intCast(13 + seed * 7), @intCast(17 + seed * 11));
}
const Readonly = @import("block_v5_caller_readonly_protocol_v1.zig");
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const Selection = @import("block_v5_readonly_input_selection_v1.zig");
const Sources = @import("block_v5_initial_sources_v1.zig");
const base: u32 = 0x900000;
const input = [_]u8{ 7, 0, 0, 0, 9, 8, 7 };
const addresses = [_]u32{ base, base + 8 };
fn sources() !Sources.Pins {
    const Tree = @import("../air/memory_commitment/blake3_state_tree.zig");
    const leaves = [_]Tree.Leaf{ .{ .index = base / 4, .value = 7 }, .{ .index = base / 4 + 1, .value = 0x070809 } };
    var words: [16]u8 = undefined;
    inline for (0..2) |i| {
        std.mem.writeInt(u32, words[i * 8 ..][0..4], base + i * 4, .little);
        std.mem.writeInt(u32, words[i * 8 + 4 ..][0..4], leaves[i].value, .little);
    }
    // Final source file describes only the candidate mutable first touch.
    // Full initial input roster/root still include every original word.
    var touch: [9]u8 = undefined;
    touch[0] = 1;
    std.mem.writeInt(u32, touch[1..5], base + 4, .little);
    std.mem.writeInt(u32, touch[5..9], 0x070809, .little);
    return .{ .layout = .{ .program_base = 0x1000, .program_end = 0x2000, .data_base = base, .data_end = base + 4096, .stack_bottom = 0, .stack_top = 0, .io_base = 0, .io_end = 0, .input_base = base, .input_end = base + 16, .output_len_addr = base + 32, .output_data_addr = base + 36, .output_base = base + 32, .output_end = base + 128 }, .initial_rw_root = (try Tree.TreeHasher.init(.memory).root(&leaves)).bytes, .initial_registers = @splat(0), .public_input_sha256 = Sources.sha256(&input), .public_input_len = input.len, .input_words = .{ .sha256 = Sources.sha256(&words), .records = 2 }, .rw_words = .{ .sha256 = Sources.sha256(&.{}), .records = 0 }, .first_touches = .{ .sha256 = Sources.sha256(&touch), .records = 1 } };
}
/// Real independently sealed metadata, never a proof/capture fixture.
const Fixture = struct {
    original: BaseFixture,
    selected: Selection.Owned,
    plan: Plan.Owned,
    source: Sources.Pins,
    roster: ?Roster.Authority = null,
    fn init(a: std.mem.Allocator) !Fixture {
        return initWithKeccak(a, 0);
    }
    fn initWithKeccak(a: std.mem.Allocator, keccak_calls: u32) !Fixture {
        var original = try BaseFixture.initWithKeccak(a, keccak_calls);
        const source = try sources();
        var selected = try Selection.derive(a, try Selection.Authority.fromSources(source), &input, &.{base}, .{});
        errdefer selected.deinit();
        var plan = try Plan.derive(a, source, &input, &.{base}, .{});
        errdefer plan.deinit();
        var result = Fixture{ .original = original, .selected = selected, .plan = plan, .source = source };
        original.pins.register_custody_mode = 1;
        original.pins.initial_source_plan_digest = try source.digest();
        var schedule = try @import("block_v5_caller_fused_schedule_v1.zig").Schedule.init(a, &original.statement, original.frame.cycle_count, original.frame, 1);
        defer schedule.deinit();
        original.rw = schedule.rw_events;
        original.entries[6] = Original1.entry(original.binding, original.witness, original.frame, 1, &schedule, result.authority());
        original.entries[7] = Original1.accessEntry(original.binding, original.witness, original.frame, &schedule, result.authority());
        original.sealed = try @import("block_v5_source_seal_v1.zig").seal(original.pins, &original.entries);
        original.binding.sealed_digest = original.sealed.digest;
        const mass = original.rw;
        const shape = try @import("block_v5_readonly_input_provider_v2.zig").shard(0, 0, 0, plan.intervals, &.{.{ .interval_index = 1, .count = std.math.cast(u16, mass) orelse return error.FixtureMassTooLarge }});
        const source_records = [_]Roster.SourceRecord{
            .{ .kind = .native, .index = 0, .group_id = 0, .roots = .{ original.entries[1].roots[0], original.entries[1].roots[1], original.entries[2].roots[0] }, .classifier_roots = null, .row_log = 0, .counter_digest = @splat(81), .census = .{ .all_rw = 0, .mutable = 0, .readonly = 0 } },
            .{ .kind = .caller, .index = 0, .group_id = 0, .roots = .{ original.binding.first_roots[0], original.binding.first_roots[1], original.witness }, .classifier_roots = null, .row_log = 0, .counter_digest = @splat(82), .census = .{ .all_rw = mass, .mutable = 0, .readonly = mass } },
        };
        const groups = [_]Roster.Group{.{ .index = 0, .first_source = 0, .source_count = 2, .census = .{ .all_rw = mass, .mutable = 0, .readonly = mass } }};
        const providers = [_]Roster.ProviderPin{.{ .shape = shape, .roots = .{ @splat(83), @splat(84) }, .ordinal_digest = @splat(85), .plan_digest = plan.digest, .config = original.pins.config, .range_index = 0 }};
        const ranges = [_]Roster.RangePin{.{ .index = 0, .group_id = 0, .provider_index = 0, .shard = .{ .index = 0, .first_instance = 0, .instance_count = 1, .request_count = shape.counts.range_requests }, .plan_digest = Roster.rangePlanDigest(plan.digest, shape), .roots = .{ @splat(86), @splat(87) }, .counter_digest = @splat(88), .config = original.pins.config }};
        const inventory = Roster.Inputs{ .plan_digest = plan.digest, .selection_digest = selected.digest, .initial_source_plan_digest = try source.digest(), .config = original.pins.config, .sources = &source_records, .groups = &groups, .providers = &providers, .ranges = &ranges };
        original.pins.readonly_roster_digest = try Roster.digest(inventory);
        original.sealed = try @import("block_v5_source_seal_v1.zig").seal(original.pins, &original.entries);
        original.binding.sealed_digest = original.sealed.digest;
        result.original = original;
        result.roster = try Roster.Authority.admit(a, inventory, result.authority(), original.sealed, original.pins, &original.entries, .{});
        return result;
    }
    fn deinit(self: *Fixture) void {
        if (self.roster) |*roster| roster.deinit();
        self.plan.deinit();
        self.selected.deinit();
    }
    fn authority(self: *const Fixture) Readonly.Authority {
        return .{ .selection = .{ .authority = self.selected.authority, .addresses = self.selected.addresses, .expected_digest = self.selected.digest }, .plan = .{ .source = self.source, .addresses = self.selected.addresses, .expected_digest = self.plan.digest }, .input = &input };
    }
    fn pin(self: *const Fixture) !Admission.Receiver.Pin {
        const p = self.original.pin();
        const roster = if (self.roster) |*r| r else return error.MissingFixtureRoster;
        return .{ .statement = p.statement, .total_steps = p.total_steps, .execution_instance_id = p.execution_instance_id, .expected_key_id = p.expected_key_id, .expected_caller_instance_id = p.expected_caller_instance_id, .roots = p.roots, .witness_root = p.witness_root, .frame = p.frame, .expected_rw_events = p.expected_rw_events, .readonly = try Fused.Authority.init(self.authority(), roster, self.original.sealed, 1) };
    }
};
fn prepared(a: std.mem.Allocator, fixture: *const Fixture) !Admission.Prepared {
    return Admission.Prepared.init(a, 0, try fixture.pin(), fixture.original.sealed, fixture.original.pins, &fixture.original.entries, .{});
}
fn claimFrames(a: std.mem.Allocator, admitted: *const Admission.Prepared) !Fused.ClaimFrames {
    const schedule = &admitted.schedule;
    const program = try a.alloc(@import("block_v5_program_extension_proof_v1.zig").Claim, schedule.program.len);
    errdefer a.free(program);
    for (program, schedule.program, 0..) |*claim, slot, i| claim.* = .{ .sum = value(i + 1), .fetch_count = slot.active_calls };
    const state = try a.dupe(@import("block_v5_program_extension_proof_v1.zig").Claim, program);
    errdefer a.free(state);
    const tables = try a.alloc(@import("block_v5_precompile_lookup_algebra_v1.zig").Claim, schedule.tables.len);
    errdefer a.free(tables);
    for (tables, schedule.tables, 0..) |*claim, slot, i| claim.* = .{ .sum = value(i + 100), .row_count = slot.n_rows };
    const memory = try a.alloc(@import("block_v5_external_memory_sidecar_proof_v1.zig").Claim, schedule.memory.len);
    for (memory, schedule.memory, 0..) |*claim, slot, i| claim.* = .{ .active_count = if (slot.kind == .sha) admitted.statement.sha.call_count else if (slot.kind == .keccak) admitted.statement.ethereum.counts.keccak_calls else admitted.statement.ethereum.counts.signer_calls, .transition_sum = value(i + 200), .universal_sum = value(i + 300), .range_claims = @splat(value(i + 400)) };
    errdefer a.free(memory);
    const ro = try a.alloc(Fused.Slot, memory.len);
    errdefer a.free(ro);
    const challenges = try Fused.classification(a, admitted.sealed, admitted.plan, admitted.binding, admitted.witness_root, admitted.frame, &admitted.schedule, admitted.readonly);
    for (ro, memory) |*out, source| {
        const Original = @import("block_v5_readonly_input_protocol_v1.zig");
        const interval = admitted.plan.intervals[1];
        const count = core.fields.m31.M31.fromCanonical(@intCast(source.active_count));
        out.* = .{ .claim = .{ .mutable_sum = Q.zero(), .classification_sum = (try challenges.classification.combineBase(Original.intervalTuple(interval)).inv()).mulM31(count), .read_sum = (try challenges.read.combineBase(Original.inputTuple(interval.lower * 4, interval.value)).inv()).mulM31(count), .readonly_count = source.active_count } };
    }
    return .{ .readonly_claims = ro, .program_claims = program, .state_claims = state, .table_claims = tables, .memory_claims = memory };
}
fn input(builder: *R.Builder, a: std.mem.Allocator, inputs: *std.ArrayList(Q), concrete: Q) !S {
    const symbol = try builder.input();
    try inputs.append(a, concrete);
    return symbol.value;
}
test "caller readonly global recursion: all original scalar OODS equations match symbolic replay with sample and claim mutations" {
    const a = std.testing.allocator;
    var fixture = try Fixture.initWithKeccak(a, 1);
    defer fixture.deinit();
    var admitted = try prepared(a, &fixture);
    defer admitted.deinit();
    var claims = try claimFrames(a, &admitted);
    defer claims.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    const relations = try Admission.Protocol.drawRelations(temp, admitted.sealed);
    const word = try @import("block_v5_word_memory_protocol_v1.zig").Challenges.draw(temp, admitted.sealed);
    const shared = try Global.draw(temp, admitted.sealed, admitted.readonly.roster.epoch());
    const classification = try Global.forGroup(shared, admitted.readonly.group_id);
    const memory = try @import("block_memory_relation_v2.zig").Challenges.draw(temp, admitted.sealed);
    var components = try Fused.Components.init(temp, &admitted.schedule, &claims, &relations, &memory, &word, admitted.logs[3], admitted.logs[2], admitted.sealed.register_custody_mode, &classification);
    defer components.deinit();
    const handles = try components.verifier();
    const all = core.air.components.Components{ .components = handles, .n_preprocessed_columns = admitted.logs[0].len };
    const mask_log = all.compositionLogDegreeBound() - try all.compositionLogSplit();
    const seed = value(50);
    const point = try core.circle.secureFieldPointFromRandomSeedChecked(seed);
    var masks = try all.maskPoints(temp, point, mask_log, false);
    defer masks.deinitDeep(temp);
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var symbols: std.ArrayList(S) = .empty;
    var samples = Composition.Samples{ .offsets = undefined, .lengths = undefined, .values = undefined };
    const scalar_masks = try temp.alloc([][]Q, 4);
    var sample_input: usize = 0;
    for (masks.items, scalar_masks, 0..) |columns, *out, tree| {
        out.* = try temp.alloc([]Q, columns.len);
        samples.offsets[tree] = try temp.alloc(usize, columns.len);
        samples.lengths[tree] = try temp.alloc(usize, columns.len);
        for (columns, out.*, 0..) |points, *values, column| {
            values.* = try temp.alloc(Q, points.len);
            samples.offsets[tree][column] = symbols.items.len;
            samples.lengths[tree][column] = points.len;
            for (values.*, 0..) |*concrete, ordinal| {
                concrete.* = value(100 + tree * 100 + column * 3 + ordinal);
                if (tree == 2 and column == 0) sample_input = inputs.items.len;
                try symbols.append(temp, try input(&builder, temp, &inputs, concrete.*));
            }
        }
    }
    samples.offsets[4] = &.{};
    samples.lengths[4] = &.{};
    samples.values = symbols.items;
    const scalar_mask = core.air.components.MaskValues{ .items = scalar_masks };
    const random = value(70);
    const expected = try all.evalCompositionPolynomialAtPoint(point, &scalar_mask, random, mask_log);
    var prefix_channel = admitted.sealed.sharedChannel();
    const universal = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(temp, &prefix_channel);
    var draws: [47][2]S = undefined;
    for (&draws, universal.elements) |*out, element| out.* = .{ try input(&builder, temp, &inputs, element.z), try input(&builder, temp, &inputs, element.alpha) };
    var word_draws: [10]S = undefined;
    inline for (.{ "transition", "link", "initial", "endpoint", "range16" }, 0..) |name, i| {
        const element = @field(word, name);
        word_draws[2 * i] = try input(&builder, temp, &inputs, element.z);
        word_draws[2 * i + 1] = try input(&builder, temp, &inputs, element.alpha);
    }
    var class_draws: [4]S = undefined;
    inline for (.{ "classification", "read" }, 0..) |name, i| {
        const element = @field(shared, name);
        class_draws[2 * i] = try input(&builder, temp, &inputs, element.z);
        class_draws[2 * i + 1] = try input(&builder, temp, &inputs, element.alpha);
    }
    const public_values = try Composition.publicInputs(temp, &admitted, claims);
    const public = try temp.alloc(S, public_values.len);
    const group_input = inputs.items.len + public_values.len - 1;
    const claim_input = inputs.items.len + 8;
    for (public, public_values) |*out, concrete| out.* = try input(&builder, temp, &inputs, concrete);
    const random_symbol = try input(&builder, temp, &inputs, random);
    const seed_symbol = try input(&builder, temp, &inputs, seed);
    const expected_symbol = try input(&builder, temp, &inputs, expected);
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var accumulated = S.zero();
    const count = try Composition.recordConstraints(&admitted, samples, public, draws, word_draws, class_draws, random_symbol, R.pointFromSeed(seed_symbol), mask_log, &accumulated);
    var expected_count: usize = 0;
    for (handles) |component| expected_count += component.nConstraints();
    try std.testing.expectEqual(expected_count, count);
    try builder.constrainZero(accumulated.sub(expected_symbol));
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const outputs = try temp.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs.items, outputs);
    inputs.items[sample_input] = inputs.items[sample_input].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(inputs.items, outputs));
    inputs.items[sample_input] = inputs.items[sample_input].sub(Q.one());
    inputs.items[group_input] = inputs.items[group_input].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(inputs.items, outputs));
    inputs.items[group_input] = inputs.items[group_input].sub(Q.one());
    inputs.items[claim_input] = inputs.items[claim_input].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(inputs.items, outputs));
}
fn fault(a: std.mem.Allocator, admitted: *const Admission.Prepared, claims: Fused.ClaimFrames) !void {
    var values = try Bus.Values.init(a, admitted, claims);
    defer values.deinit();
    var clone = try values.clone(a);
    defer clone.deinit();
    try std.testing.expect(clone.public.ptr != values.public.ptr);
    try std.testing.expect(clone.statement.words.ptr != values.statement.words.ptr);
    try std.testing.expectEqualDeep(values.public, clone.public);
}
test "caller readonly global recursion: owned statement and public claims survive cloning and every allocation failure" {
    const a = std.testing.allocator;
    var fixture = try Fixture.init(a);
    defer fixture.deinit();
    var admitted = try prepared(a, &fixture);
    defer admitted.deinit();
    var claims = try claimFrames(a, &admitted);
    defer claims.deinit(a);
    try fault(a, &admitted, claims);
    try std.testing.checkAllAllocationFailures(a, fault, .{ &admitted, claims });
    claims.program_claims[0].fetch_count += 1;
    try std.testing.expectError(error.InvalidV5CallerCompositeClaims, Bus.Values.init(a, &admitted, claims));
    claims.program_claims[0].fetch_count -= 1;
    claims.memory_claims[0].active_count += 1;
    try std.testing.expectError(error.UntrustedV5CallerCompositeEventCensus, Bus.Values.init(a, &admitted, claims));
}

test "caller readonly global recursion: original admission borrows only independent roster Plan and rejects scope changes" {
    const a = std.testing.allocator;
    var fixture = try Fixture.init(a);
    defer fixture.deinit();
    const pin = try fixture.pin();
    var empty: [0]u8 = .{};
    var denied = std.heap.FixedBufferAllocator.init(&empty);
    var plan = try pin.readonly.admit(denied.allocator());
    defer plan.deinit();
    const normative = try pin.readonly.roster.borrowedPlan(fixture.original.sealed);
    try std.testing.expect(plan.intervals.ptr == normative.intervals.ptr);
    try std.testing.expectEqualDeep(fixture.plan.intervals, plan.intervals);
    var changed = pin.readonly;
    changed.group_id += 1;
    try std.testing.expectError(error.UntrustedGlobalReadonlySource, changed.admit(a));
    changed = pin.readonly;
    changed.census.readonly -= 1;
    try std.testing.expectError(error.UntrustedGlobalReadonlySource, changed.admit(a));
    changed = pin.readonly;
    changed.selection.expected_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedGlobalReadonlyOriginalPolicy, changed.admit(a));
}

test "caller readonly global recursion: genuine54 global draws and compact B5IC2 transcript bytes remain exact" {
    const a = std.testing.allocator;
    var fixture = try Fixture.initWithKeccak(a, 1);
    defer fixture.deinit();
    var admitted = try prepared(a, &fixture);
    defer admitted.deinit();
    var claims = try claimFrames(a, &admitted);
    defer claims.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    var statement = try Statement.initClaims(temp, &admitted, claims);
    defer statement.deinit();
    var recorder = @import("../recursion/air/blake3_native_recorder.zig").Recorder{ .a = temp, .universal_relations = true };
    _ = try @import("../recursion/air/block_v5_caller_readonly_global_transcript_v2.zig").prefix(temp, &recorder, &admitted, &statement);
    var expected = try Fused.proofChannel(temp, admitted.sealed, admitted.readonly);
    expected.mixRoot(try Fused.instanceId(admitted.binding, admitted.witness_root, admitted.frame, 1, &admitted.schedule, admitted.readonly));
    const group_challenges = try Fused.classification(temp, admitted.sealed, admitted.plan, admitted.binding, admitted.witness_root, admitted.frame, &admitted.schedule, admitted.readonly);
    try Fused.mixClaims(&expected, admitted.binding, &admitted.schedule, &claims, admitted.plan, &group_challenges, admitted.readonly);
    try std.testing.expectEqualDeep(expected, recorder.native);
    try std.testing.expectEqual(@as(usize, 54), recorder.relation_count);
    var resets: usize = 0;
    var omitted: usize = 0;
    for (recorder.operations.items) |operation| switch (operation) {
        .restart => resets += 1,
        .secure => |draw| if (draw.output == null) {
            omitted += 1;
        },
        else => {},
    };
    try std.testing.expectEqual(@as(usize, 2), resets);
    try std.testing.expectEqual(@as(usize, 52), omitted);
    try std.testing.expect(!@hasField(Fused.Slot, "counters"));
    claims.readonly_claims[0].claim.readonly_count -= 1;
    try std.testing.expectError(error.UntrustedGlobalCallerSourceCensus, Bus.Values.init(a, &admitted, claims));
}
fn cloneCompact(a: std.mem.Allocator, original: *const Fused.ClaimFrames) !void {
    var clone = try Fused.ClaimFrames.clone(a, original);
    defer clone.deinit(a);
    try std.testing.expect(clone.readonly_claims.ptr != original.readonly_claims.ptr);
    try std.testing.expectEqualDeep(original.readonly_claims, clone.readonly_claims);
    clone.readonly_claims[0].claim.read_sum = clone.readonly_claims[0].claim.read_sum.add(Q.one());
    try std.testing.expect(!clone.readonly_claims[0].claim.read_sum.eql(original.readonly_claims[0].claim.read_sum));
}
test "caller readonly global recursion: five compact claim families have independent failure safe custody" {
    const a = std.testing.allocator;
    var fixture = try Fixture.init(a);
    defer fixture.deinit();
    var admitted = try prepared(a, &fixture);
    defer admitted.deinit();
    var claims = try claimFrames(a, &admitted);
    defer claims.deinit(a);
    try cloneCompact(a, &claims);
    try std.testing.checkAllAllocationFailures(a, cloneCompact, .{&claims});
}

test "caller readonly global recursion: global group shift equals original extended tuple oracle" {
    const a = std.testing.allocator;
    var fixture = try Fixture.init(a);
    defer fixture.deinit();
    const authority = (try fixture.pin()).readonly;
    const shared = try Global.draw(a, authority.sealed, authority.roster.epoch());
    const Relations = @import("../air/relation_challenges.zig").RelationElements;
    for ([_]u32{ 0, 1, 37, core.fields.m31.Modulus - 1 }) |group| {
        const shifted = try Global.forGroup(shared, group);
        const interval = (try authority.admit(a)).intervals[1];
        const protocol = @import("block_v5_readonly_input_protocol_v1.zig");
        const tuple = protocol.intervalTuple(interval);
        const read = protocol.inputTuple(interval.lower * 4, interval.value);
        // The oracle appends the actual public group as a genuine final cell,
        // instead of applying the production shift recipe.
        const expected_class = Relations(6).init(shared.classification.z, shared.classification.alpha).combineBase(tuple ++ [1]core.fields.m31.M31{core.fields.m31.M31.fromCanonical(group)});
        const expected_read = Relations(5).init(shared.read.z, shared.read.alpha).combineBase(read ++ [1]core.fields.m31.M31{core.fields.m31.M31.fromCanonical(group)});
        try std.testing.expect(shifted.classification.combineBase(tuple).eql(expected_class));
        try std.testing.expect(shifted.read.combineBase(read).eql(expected_read));
    }
    try std.testing.expectError(error.InvalidGlobalReadonlyGroup, Global.forGroup(shared, core.fields.m31.Modulus));
}

const Witness = @import("block_v5_caller_readonly_witness_v1.zig");
const Source = @import("block_execution_external_trace_v2.zig");
fn traceFixture(a: std.mem.Allocator) !Source.Trace {
    const M = core.fields.m31.M31;
    const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
    const sha = @import("../air/guest_precompile/sha256_memory_caller.zig");
    const fixed = try a.alloc(Column, 1);
    fixed[0] = .{ .values = try a.dupe(M, &.{ M.one(), M.zero() }), .log_size = 1 };
    const main = try a.alloc(Column, sha.PHYSICAL_MAIN_COLUMN_COUNT);
    const matrix = try a.alloc(M, 2 * main.len);
    @memset(matrix, M.zero());
    for (main, 0..) |*column, i| column.* = .{ .values = matrix[2 * i ..][0..2], .log_size = 1 };
    matrix[2 * sha.Layout.addresses] = M.fromCanonical(base / 4);
    matrix[2 * sha.Layout.memory_clock] = M.fromCanonical(2);
    matrix[2 * sha.Layout.before] = M.fromCanonical(7);
    matrix[2 * sha.Layout.output] = M.fromCanonical(7);
    return Source.Trace.init(a, .{ .kind = .sha, .slot = 2, .log_size = 1, .fixed_offset = 0, .main_offset = 0, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = (@as(u64, 1) << 40) + 1, .cycle_count = 1 } }, fixed, main);
}
const Observer = struct {
    observed: usize = 0,
    last: u32 = std.math.maxInt(u32),
    reject: bool = false,
    fn observe(raw: *anyopaque, ordinal: u32) !void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (self.reject) return error.InjectedCallerObservationFailure;
        self.observed += 1;
        self.last = ordinal;
    }
    fn sink(self: *@This()) Witness.Metadata.Observer {
        return .{ .context = self, .observe = observe };
    }
};
fn metadataCase(a: std.mem.Allocator, trace: *const Source.Trace, authority: Fused.Authority) !void {
    var metadata = try Witness.Metadata.initOpenSource(a, trace, authority.roster, authority.sealed, authority.limits);
    defer metadata.deinit(a);
    try std.testing.expectEqual(@as(usize, 0), metadata.counters.len);
    try std.testing.expectEqual(@as(u64, 1), metadata.events);
    try std.testing.expectEqual(@as(u64, 1), metadata.readonly_events);
    const shared = try Global.draw(a, authority.sealed, authority.roster.epoch());
    const grouped = try Global.forGroup(shared, authority.group_id);
    const plan = try authority.admit(a);
    var generated = try Witness.generateOpenSource(a, trace, &metadata, plan, &grouped, authority.limits);
    defer generated.deinit(a);
    try std.testing.expectEqual(@as(u64, 1), generated.claim.readonly_count);
}
test "caller readonly global recursion: no counter vector replay preserves original metadata and interactions plus OOM" {
    const a = std.testing.allocator;
    var fixture = try Fixture.init(a);
    defer fixture.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var trace = try traceFixture(arena.allocator());
    defer trace.deinit();
    const authority = (try fixture.pin()).readonly;
    var legacy = try Witness.Metadata.init(a, &trace, fixture.plan, authority.limits);
    defer legacy.deinit(a);
    var observer = Observer{};
    var observed = try Witness.Metadata.initIntervalsObserved(a, &trace, fixture.plan.intervals, .{ .max_counter_bytes = 0 }, observer.sink());
    defer observed.deinit(a);
    try std.testing.expectEqualDeep(legacy.storage, observed.storage);
    try std.testing.expectEqual(@as(usize, 1), observer.observed);
    try std.testing.expectEqual(@as(u32, 1), observer.last);
    try std.testing.expectEqual(@as(usize, 0), observed.counters.len);
    const grouped = try Global.forGroup(try Global.draw(a, authority.sealed, authority.roster.epoch()), authority.group_id);
    var original = try Witness.generate(a, &trace, &legacy, fixture.plan, &grouped, authority.limits);
    defer original.deinit(a);
    var replay = try Witness.generateOpenSource(a, &trace, &observed, try authority.admit(a), &grouped, authority.limits);
    defer replay.deinit(a);
    try std.testing.expectEqualDeep(original.claim, replay.claim);
    try std.testing.expectEqualDeep(original.storage, replay.storage);
    observer.reject = true;
    try std.testing.expectError(error.InjectedCallerObservationFailure, Witness.Metadata.initIntervalsObserved(a, &trace, fixture.plan.intervals, authority.limits, observer.sink()));
    try metadataCase(a, &trace, authority);
    try std.testing.checkAllAllocationFailures(a, metadataCase, .{ &trace, authority });
    try std.testing.expectError(error.UntrustedCallerReadonlyMetadata, Witness.generate(a, &trace, &observed, fixture.plan, &grouped, authority.limits));
}
