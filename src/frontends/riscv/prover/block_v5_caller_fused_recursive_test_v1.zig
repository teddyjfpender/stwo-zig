//! Original scalar quotient oracle, transcript-byte parity and independent
//! policy/ownership faults. No proof capture or STARK success is fabricated.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const R = @import("../recursion/air/composition_graph_recorder.zig");
const S = R.Scalar;
const Fixture = @import("block_v5_caller_capture_unit_test.zig").Fixture;
const Admission = @import("block_v5_caller_fused_recursive_admission_v1.zig");
const Composition = @import("../recursion/air/block_v5_caller_fused_composition_v1.zig");
const Statement = @import("../recursion/air/block_v5_caller_fused_statement_v1.zig");
const Bus = @import("../recursion/block_v5_caller_fused_recursive_public_bus_v1.zig");
const Fused = Admission.Fused;
fn value(seed: usize) Q {
    return Q.fromU32Unchecked(@intCast(7 + seed * 3), @intCast(11 + seed * 5), @intCast(13 + seed * 7), @intCast(17 + seed * 11));
}
fn prepared(a: std.mem.Allocator, fixture: *const Fixture) !Admission.Prepared {
    return Admission.Prepared.init(a, 0, fixture.pin(), fixture.sealed, fixture.pins, &fixture.entries, .{});
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
    return .{ .program_claims = program, .state_claims = state, .table_claims = tables, .memory_claims = memory };
}
test "caller fused recursion: independent exact schedule rejects altered masks slots roots resource policy" {
    const a = std.testing.allocator;
    const fixture = try Fixture.initWithKeccak(a, 1);
    var admitted = try prepared(a, &fixture);
    defer admitted.deinit();
    try admitted.validate(admitted.template_id);
    const saved = admitted.schedule.memory[0];
    const id = admitted.template_id;
    const custody = admitted.custody;
    admitted.schedule.memory[0].slot += 1;
    admitted.template_id = admitted.templateId();
    admitted.custody = admitted.identity();
    try std.testing.expectError(error.UntrustedCallerFusedRecursiveGeometry, admitted.validate(admitted.template_id));
    admitted.schedule.memory[0] = saved;
    admitted.template_id = id;
    admitted.custody = custody;
    var pin = fixture.pin();
    pin.witness_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5CallerCompositeEntry, Admission.Prepared.init(a, 0, pin, fixture.sealed, fixture.pins, &fixture.entries, .{}));
    try std.testing.expectError(error.CallerFusedRecursiveResourceLimit, Admission.Prepared.init(a, 0, fixture.pin(), fixture.sealed, fixture.pins, &fixture.entries, .{ .max_columns = 1 }));
    try admitted.validate(admitted.template_id);
}
test "caller fused recursion: original first phase restart Word5 and full claim frames preserve channel bytes" {
    const a = std.testing.allocator;
    const fixture = try Fixture.initWithKeccak(a, 1);
    var admitted = try prepared(a, &fixture);
    defer admitted.deinit();
    var claims = try claimFrames(a, &admitted);
    defer claims.deinit(a);
    var statement = try Statement.initClaims(a, &admitted, claims);
    defer statement.deinit();
    var first = core.proof_suites.Blake3.Channel{};
    try statement.replay(&first, statement.first);
    try std.testing.expectEqualDeep(Fused.firstChannel(admitted.binding, admitted.witness_root, admitted.frame, admitted.sealed.register_custody_mode, &admitted.schedule), first);
    var expected = try Fused.proofChannel(a, admitted.sealed);
    expected.mixRoot(Fused.instanceId(admitted.binding, admitted.witness_root, admitted.frame, admitted.sealed.register_custody_mode, &admitted.schedule));
    try Fused.mixClaims(&expected, admitted.binding, &admitted.schedule, claims.program_claims, claims.state_claims, claims.table_claims, claims.memory_claims);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var recorder = @import("../recursion/air/blake3_native_recorder.zig").Recorder{ .a = arena.allocator(), .universal_relations = true };
    const actual_challenges = try @import("../recursion/air/block_v5_caller_fused_transcript_v1.zig").prefix(arena.allocator(), &recorder, &admitted, &statement);
    try std.testing.expectEqualDeep(expected, recorder.native);
    try std.testing.expectEqualDeep(try @import("block_v5_word_memory_protocol_v1.zig").Challenges.draw(a, admitted.sealed), actual_challenges);
    try std.testing.expectEqual(@as(usize, 52), recorder.relation_count);
    try std.testing.expectEqual(@as(usize, 3), recorder.root_count);
    var restarts: usize = 0;
    for (recorder.operations.items) |operation| if (operation == .restart) {
        restarts += 1;
    };
    try std.testing.expectEqual(@as(usize, 1), restarts);
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
test "caller fused recursion: owned statement and public claims survive cloning and every allocation failure" {
    const a = std.testing.allocator;
    const fixture = try Fixture.init(a);
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
test "caller fused recursion: all original scalar OODS equations match symbolic replay with sample and claim mutations" {
    const a = std.testing.allocator;
    const fixture = try Fixture.initWithKeccak(a, 1);
    var admitted = try prepared(a, &fixture);
    defer admitted.deinit();
    var claims = try claimFrames(a, &admitted);
    defer claims.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    const relations = try Admission.Protocol.drawRelations(temp, admitted.sealed);
    const word = try @import("block_v5_word_memory_protocol_v1.zig").Challenges.draw(temp, admitted.sealed);
    const memory = try @import("block_memory_relation_v2.zig").Challenges.draw(temp, admitted.sealed);
    var components = try Fused.Components.init(temp, &admitted.schedule, &claims, &relations, &memory, &word, admitted.logs[3], admitted.logs[2], admitted.sealed.register_custody_mode);
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
    const count = try Composition.recordConstraints(&admitted, samples, public, draws, word_draws, random_symbol, R.pointFromSeed(seed_symbol), mask_log, &accumulated);
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
