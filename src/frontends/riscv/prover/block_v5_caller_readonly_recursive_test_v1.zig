//! Original scalar quotient oracle, transcript-byte parity and independent
//! policy/ownership faults. No proof capture or STARK success is fabricated.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const R = @import("../recursion/air/composition_graph_recorder.zig");
const S = R.Scalar;
const BaseFixture = @import("block_v5_caller_capture_unit_test.zig").Fixture;
const Admission = @import("block_v5_caller_readonly_recursive_admission_v1.zig");
const Composition = @import("../recursion/air/block_v5_caller_readonly_composition_v1.zig");
const Statement = @import("../recursion/air/block_v5_caller_readonly_statement_v1.zig");
const Bus = @import("../recursion/block_v5_caller_readonly_recursive_public_bus_v1.zig");
const Fused = Admission.Fused;
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
        original.entries[6] = Fused.entry(original.binding, original.witness, original.frame, 1, &schedule, result.authority());
        original.entries[7] = Fused.accessEntry(original.binding, original.witness, original.frame, &schedule, result.authority());
        original.sealed = try @import("block_v5_source_seal_v1.zig").seal(original.pins, &original.entries);
        original.binding.sealed_digest = original.sealed.digest;
        result.original = original;
        return result;
    }
    fn deinit(self: *Fixture) void {
        self.plan.deinit();
        self.selected.deinit();
    }
    fn authority(self: *const Fixture) Readonly.Authority {
        return .{ .selection = .{ .authority = self.selected.authority, .addresses = self.selected.addresses, .expected_digest = self.selected.digest }, .plan = .{ .source = self.source, .addresses = self.selected.addresses, .expected_digest = self.plan.digest }, .input = &input };
    }
    fn pin(self: *const Fixture) Admission.Receiver.Pin {
        const p = self.original.pin();
        return .{ .statement = p.statement, .total_steps = p.total_steps, .execution_instance_id = p.execution_instance_id, .expected_key_id = p.expected_key_id, .expected_caller_instance_id = p.expected_caller_instance_id, .roots = p.roots, .witness_root = p.witness_root, .frame = p.frame, .expected_rw_events = p.expected_rw_events, .readonly = self.authority() };
    }
};
fn prepared(a: std.mem.Allocator, fixture: *const Fixture) !Admission.Prepared {
    return Admission.Prepared.init(a, 0, fixture.pin(), fixture.original.sealed, fixture.original.pins, &fixture.original.entries, .{});
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
    const ro = try a.alloc(@import("block_v5_caller_readonly_witness_v1.zig").SlotClaim, memory.len);
    var initialized: usize = 0;
    errdefer {
        for (ro[0..initialized]) |claim| a.free(claim.counters);
        a.free(ro);
    }
    const challenges = try Readonly.Challenges.draw(a, admitted.sealed, admitted.plan.digest, Fused.instanceId(admitted.binding, admitted.witness_root, admitted.frame, 1, &admitted.schedule, admitted.readonly), admitted.binding.first_roots);
    for (ro, memory) |*out, source| {
        const counters = try a.alloc(u64, admitted.plan.intervals.len);
        @memset(counters, 0);
        counters[1] = source.active_count; // independently selected readonly singleton
        const Original = @import("block_v5_readonly_input_protocol_v1.zig");
        const interval = admitted.plan.intervals[1];
        const count = core.fields.m31.M31.fromCanonical(@intCast(source.active_count));
        out.* = .{ .claim = .{ .mutable_sum = Q.zero(), .classification_sum = (try challenges.classification.combineBase(Original.intervalTuple(interval)).inv()).mulM31(count), .read_sum = (try challenges.read.combineBase(Original.inputTuple(interval.lower * 4, interval.value)).inv()).mulM31(count), .readonly_count = source.active_count }, .counters = counters };
        initialized += 1;
    }
    return .{ .readonly_claims = ro, .program_claims = program, .state_claims = state, .table_claims = tables, .memory_claims = memory };
}
test "caller readonly recursion: independent exact schedule rejects altered masks slots roots resource policy" {
    const a = std.testing.allocator;
    var fixture = try Fixture.initWithKeccak(a, 1);
    defer fixture.deinit();
    var admitted = try prepared(a, &fixture);
    defer admitted.deinit();
    try admitted.validate(admitted.template_id);
    const saved = admitted.schedule.memory[0];
    const id = admitted.template_id;
    const custody = admitted.custody;
    admitted.schedule.memory[0].slot += 1;
    admitted.template_id = admitted.templateId();
    admitted.custody = admitted.identity();
    try std.testing.expectError(error.UntrustedCallerReadonlyRecursiveGeometry, admitted.validate(admitted.template_id));
    admitted.schedule.memory[0] = saved;
    admitted.template_id = id;
    admitted.custody = custody;
    var pin = fixture.pin();
    pin.witness_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5CallerCompositeEntry, Admission.Prepared.init(a, 0, pin, fixture.original.sealed, fixture.original.pins, &fixture.original.entries, .{}));
    try std.testing.expectError(error.CallerReadonlyRecursiveResourceLimit, Admission.Prepared.init(a, 0, fixture.pin(), fixture.original.sealed, fixture.original.pins, &fixture.original.entries, .{ .max_columns = 1 }));
    try admitted.validate(admitted.template_id);
    const old = admitted.plan.intervals[1];
    admitted.plan.intervals[1].value ^= 1;
    admitted.template_id = admitted.templateId();
    admitted.custody = admitted.identity();
    try std.testing.expectError(error.UntrustedCallerReadonlyRecursiveGeometry, admitted.validate(admitted.template_id));
    admitted.plan.intervals[1] = old;
    admitted.template_id = id;
    admitted.custody = custody;
    try admitted.validate(id);
}
test "caller readonly recursion: exact three channel branch draws exports and original B5IC bytes" {
    const a = std.testing.allocator;
    var fixture = try Fixture.initWithKeccak(a, 1);
    defer fixture.deinit();
    var admitted = try prepared(a, &fixture);
    defer admitted.deinit();
    var claims = try claimFrames(a, &admitted);
    defer claims.deinit(a);
    var statement = try Statement.initClaims(a, &admitted, claims);
    defer statement.deinit();
    var first = core.proof_suites.Blake3.Channel{};
    try statement.replay(&first, statement.first);
    try std.testing.expectEqualDeep(Fused.firstChannel(admitted.binding, admitted.witness_root, admitted.frame, 1, &admitted.schedule, admitted.readonly), first);
    var expected = admitted.sealed.sharedChannel();
    const word = try @import("block_v5_word_memory_protocol_v1.zig").Challenges.drawFromChannel(a, &expected);
    expected.mixU32s(&.{ Fused.TAG, Fused.VERSION, 3 });
    expected.mixRoot(admitted.sealed.digest);
    expected.mixRoot(Fused.instanceId(admitted.binding, admitted.witness_root, admitted.frame, 1, &admitted.schedule, admitted.readonly));
    const classification = try Readonly.Challenges.draw(a, admitted.sealed, admitted.plan.digest, Fused.instanceId(admitted.binding, admitted.witness_root, admitted.frame, 1, &admitted.schedule, admitted.readonly), admitted.binding.first_roots);
    try Fused.mixClaims(&expected, admitted.binding, &admitted.schedule, &claims, admitted.plan, &classification, admitted.readonly.limits);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var recorder = @import("../recursion/air/blake3_native_recorder.zig").Recorder{ .a = arena.allocator(), .universal_relations = true };
    const actual = try @import("../recursion/air/block_v5_caller_readonly_transcript_v1.zig").prefix(arena.allocator(), &recorder, &admitted, &statement);
    try std.testing.expectEqualDeep(expected, recorder.native);
    try std.testing.expectEqualDeep(word, actual);
    try std.testing.expectEqual(@as(usize, 54), recorder.relation_count);
    try std.testing.expectEqual(@as(usize, 3), recorder.root_count);
    var unexported: usize = 0;
    var exported: usize = 0;
    var resets: usize = 0;
    for (recorder.operations.items) |operation| switch (operation) {
        .restart => resets += 1,
        .secure => |draw| {
            if (draw.output == null) {
                unexported += 1;
            } else {
                exported += 1;
            }
        },
        else => {},
    };
    try std.testing.expectEqual(@as(usize, 2), resets);
    try std.testing.expectEqual(@as(usize, 52), unexported);
    try std.testing.expectEqual(@as(usize, 54), exported);
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
test "caller readonly recursion: owned statement and public claims survive cloning and every allocation failure" {
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
fn input(builder: *R.Builder, a: std.mem.Allocator, inputs: *std.ArrayList(Q), concrete: Q) !S {
    const symbol = try builder.input();
    try inputs.append(a, concrete);
    return symbol.value;
}
test "caller readonly recursion: all original scalar OODS equations match symbolic replay with sample and claim mutations" {
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
    const classification = try Readonly.Challenges.draw(temp, admitted.sealed, admitted.plan.digest, Fused.instanceId(admitted.binding, admitted.witness_root, admitted.frame, 1, &admitted.schedule, admitted.readonly), admitted.binding.first_roots);
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
        const element = @field(classification, name);
        class_draws[2 * i] = try input(&builder, temp, &inputs, element.z);
        class_draws[2 * i + 1] = try input(&builder, temp, &inputs, element.alpha);
    }
    const public_values = try Composition.publicInputs(temp, &admitted, claims);
    const public = try temp.alloc(S, public_values.len);
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
    inputs.items[claim_input] = inputs.items[claim_input].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(inputs.items, outputs));
}

fn providersCase(a: std.mem.Allocator, admitted: *const Admission.Prepared, claims: Fused.ClaimFrames) !void {
    const concrete = try Composition.publicInputs(a, admitted, claims);
    defer a.free(concrete);
    const classification = try Readonly.Challenges.draw(a, admitted.sealed, admitted.plan.digest, Fused.instanceId(admitted.binding, admitted.witness_root, admitted.frame, 1, &admitted.schedule, admitted.readonly), admitted.binding.first_roots);
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    defer inputs.deinit(a);
    const public = try a.alloc(S, concrete.len);
    defer a.free(public);
    for (public, concrete) |*out, v| out.* = try input(&builder, a, &inputs, v);
    var draws: [4]S = undefined;
    inline for (.{ "classification", "read" }, 0..) |name, i| {
        const element = @field(classification, name);
        draws[2 * i] = try input(&builder, a, &inputs, element.z);
        draws[2 * i + 1] = try input(&builder, a, &inputs, element.alpha);
    }
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    try Composition.recordProviders(a, &builder, admitted, public, draws);
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const outputs = try a.alloc(Q, circuit.nodes.len);
    defer a.free(outputs);
    try circuit.evaluateInto(inputs.items, outputs);
    const begin = try @import("../recursion/air/block_v5_caller_fused_composition_v1.zig").publicCount(admitted.schedule.program.len, admitted.schedule.tables.len, admitted.schedule.memory.len);
    // Actual interval1 is a readonly singleton. A zero counter in interval0
    // remains a genuine zero-safe provider; neither can be silently omitted.
    const indices = [_]usize{ begin + 1, begin + 2, begin + 3, begin + 4, begin + 5, begin + 6, begin + 7 };
    for (indices) |index| {
        const prior = inputs.items[index];
        inputs.items[index] = prior.add(Q.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(inputs.items, outputs));
        inputs.items[index] = prior;
    }
}
test "caller readonly recursion: all interval providers and exact counters constrain zeros masses and OOM" {
    const a = std.testing.allocator;
    var fixture = try Fixture.init(a);
    defer fixture.deinit();
    var admitted = try prepared(a, &fixture);
    defer admitted.deinit();
    var claims = try claimFrames(a, &admitted);
    defer claims.deinit(a);
    try providersCase(a, &admitted, claims);
    try std.testing.checkAllAllocationFailures(a, providersCase, .{ &admitted, claims });
    claims.readonly_claims[0].counters[0] += 1;
    try std.testing.expectError(error.InvalidCallerReadonlyProviderCensus, Bus.Values.init(a, &admitted, claims));
}
fn cloneClaimsCase(a: std.mem.Allocator, claims: *const Fused.ClaimFrames) !void {
    var copied = try Fused.ClaimFrames.clone(a, claims);
    defer copied.deinit(a);
    try std.testing.expect(copied.readonly_claims.ptr != claims.readonly_claims.ptr);
    for (copied.readonly_claims, claims.readonly_claims) |clone, original| {
        try std.testing.expect(clone.counters.ptr != original.counters.ptr);
        try std.testing.expectEqualSlices(u64, original.counters, clone.counters);
    }
    copied.readonly_claims[0].counters[0] += 1;
    try std.testing.expectEqual(@as(u64, 0), claims.readonly_claims[0].counters[0]);
}
test "caller readonly recursion: five claim families and per slot counters have failure safe independent custody" {
    const a = std.testing.allocator;
    var fixture = try Fixture.init(a);
    defer fixture.deinit();
    var admitted = try prepared(a, &fixture);
    defer admitted.deinit();
    var claims = try claimFrames(a, &admitted);
    defer claims.deinit(a);
    try cloneClaimsCase(a, &claims);
    try std.testing.checkAllAllocationFailures(a, cloneClaimsCase, .{&claims});
}
fn repeatedDraws(a: std.mem.Allocator) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var recorder = @import("../recursion/air/blake3_native_recorder.zig").Recorder{ .a = arena.allocator(), .universal_relations = true };
    const first = try recorder.drawSecureFelts(arena.allocator(), 4);
    try recorder.restartChannel();
    const second = try recorder.drawSecureFeltsUnexported(arena.allocator(), 4);
    try std.testing.expectEqualDeep(first, second);
    try std.testing.expectEqual(@as(usize, 2), recorder.relation_count);
    try std.testing.expect(recorder.operations.items[0].secure.output != null);
    try std.testing.expect(recorder.operations.items[3].secure.output == null);
    try recorder.restartChannel();
    const third = try recorder.drawSecureFelts(arena.allocator(), 2);
    _ = third;
    try std.testing.expectEqual(@as(usize, 3), recorder.relation_count);
    try std.testing.expectEqual(@as(usize, 2), recorder.operations.items[6].secure.output.?.universal);
}
test "caller readonly recursion: repeated genuine draws preserve original exported slot custody and recording OOM" {
    try repeatedDraws(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, repeatedDraws, .{});
}
