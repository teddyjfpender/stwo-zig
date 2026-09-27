//! Independent policy, exact original nineteen-component scalar OODS parity,
//! restart and public claim custody. No native or recursive STARK is executed.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const r = @import("../recursion/air/composition_graph_recorder.zig");
const S = r.Scalar;
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Admission = @import("block_v5_caller_arithmetic_recursive_admission_v1.zig");
const Composition = @import("../recursion/air/block_v5_caller_arithmetic_composition_v1.zig");
const Bus = @import("../recursion/block_v5_caller_arithmetic_recursive_public_bus_v1.zig");
const Protocol = Admission.Protocol;
const Profile = Admission.Profile;
const Seal = @import("block_v5_source_seal_v1.zig");
const config = @import("../recursion/blake3_execution_parent_protocol.zig").PCS_CONFIG;
fn scalar(seed: u32) Q {
    return Q.fromU32Unchecked(seed + 1, seed + 2, seed + 3, seed + 4);
}
const Fixture = struct {
    statement: Profile.admission.Statement,
    total_steps: u32 = 1,
    binding: Family.CallerBinding,
    entries: [8]Seal.Entry,
    pins: Seal.Pins,
    sealed: Seal.Sealed,
    fn init(a: std.mem.Allocator) !Fixture {
        var extension = try @import("guest_precompile/ethereum_witness.zig").Witness.initWithCircuitProfileV1(a, &.{}, &.{}, &.{}, &.{}, 1, Protocol.circuit_profile);
        defer extension.deinit();
        var result: Fixture = undefined;
        result.total_steps = 1;
        result.statement = try @import("block_v5_precompile_witness_v1.zig").canonicalStatement(a, 0, 0, 1, extension.shapes());
        const roots: [2][32]u8 = .{ @splat(21), @splat(22) };
        const key = try Protocol.keyId(&result.statement, 1, config, roots[0]);
        result.binding = .{ .execution_index = 0, .caller_entry_index = 0, .execution_instance_id = @splat(20), .caller_key_id = key, .caller_instance_id = Protocol.instanceId(key, @splat(20), 0, roots), .first_roots = roots, .sealed_digest = @splat(0) };
        // Literal roots select independently admitted policy only. No fixture
        // presents these entries as verified source trees or proof authority.
        result.entries = .{
            .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
            .{ .family = .execution, .index = 0, .instance_id = result.binding.execution_instance_id, .roots = .{ @splat(13), @splat(14) } },
            .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(15), .roots = .{ @splat(16), @splat(17) } },
            .{ .family = .program_request, .index = 0, .instance_id = @splat(18), .roots = .{ @splat(19), @splat(20) } },
            .{ .family = .memory, .index = 0, .instance_id = @splat(23), .roots = .{ @splat(24), @splat(25) } },
            .{ .family = .precompile, .index = 0, .instance_id = result.binding.caller_instance_id, .roots = roots },
            .{ .family = .program_extension_request, .index = 0, .instance_id = @splat(30), .roots = roots },
            .{ .family = .execution_external_sidecar, .index = 0, .instance_id = @splat(31), .roots = roots },
        };
        var counts: [Seal.family_count]u32 = @splat(0);
        for (result.entries) |entry| counts[@intFromEnum(entry.family) - 1] += 1;
        result.pins = .{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = @splat(6), .initial_source_plan_digest = @splat(7), .register_endpoint_plan_digest = @splat(8), .register_custody_mode = if (Protocol.execution_recipe == .local_zero_v1) 1 else 0, .config = config, .counts = counts };
        result.sealed = try Seal.seal(result.pins, &result.entries);
        result.binding.sealed_digest = result.sealed.digest;
        return result;
    }
    fn prepared(self: *const Fixture, a: std.mem.Allocator) !Admission.Prepared {
        return Admission.Prepared.init(a, self.statement, self.total_steps, self.binding, self.sealed, self.pins, &self.entries, .{});
    }
};
test "caller arithmetic recursion: actual v5 Keccak log18 geometry is independently admitted with exact nonrounded caller census" {
    const a = std.testing.allocator;
    var fixture = try Fixture.init(a);
    const geometry = @import("../air/guest_precompile/keccakf_authority.zig").geometry;
    const target_log = @import("../air/guest_precompile/keccakf_trace.zig").ethereum_maximum_log_size;
    // First call census whose real paired-slot rows exceed the preceding
    // physical domain. 4519 calls only require log17 (2260 * 29 rows).
    const calls: u32 = @intCast(((@as(usize, 1) << @intCast(target_log - 1)) / geometry.rows_per_slot) * geometry.operations_per_slot + 1);
    const steps = try std.math.add(u32, calls, 1); // One authentic SHA call.
    var extension = try @import("guest_precompile/ethereum_witness.zig").Witness.initWithCircuitProfileV1(a, &.{}, &.{}, &.{}, &.{}, steps, Protocol.circuit_profile);
    defer extension.deinit();
    fixture.statement = try @import("block_v5_precompile_witness_v1.zig").canonicalStatement(a, calls, 0, 1, extension.shapes());
    fixture.total_steps = steps;
    fixture.binding.caller_key_id = try Protocol.keyId(&fixture.statement, fixture.total_steps, config, fixture.binding.first_roots[0]);
    fixture.binding.caller_instance_id = Protocol.instanceId(fixture.binding.caller_key_id, fixture.binding.execution_instance_id, 0, fixture.binding.first_roots);
    fixture.entries[5].instance_id = fixture.binding.caller_instance_id;
    fixture.sealed = try Seal.seal(fixture.pins, &fixture.entries);
    fixture.binding.sealed_digest = fixture.sealed.digest;
    var admitted = try fixture.prepared(a);
    defer admitted.deinit();
    try std.testing.expectEqual(target_log, admitted.components[0].log_size);
    const actual_rows = admitted.statement.ethereum.components[0].n_rows;
    try std.testing.expect(actual_rows > (@as(u32, 1) << @intCast(target_log - 1)));
    try std.testing.expectEqual(try std.math.mul(u32, try std.math.divCeil(u32, calls, geometry.operations_per_slot), geometry.rows_per_slot), actual_rows);
    try std.testing.expectEqual(calls, admitted.statement.ethereum.counts.keccak_calls);
    try std.testing.expectEqual(steps, Profile.externalCount(&admitted.statement));
    try admitted.validate(admitted.template_id);
}
fn admissionAllocation(a: std.mem.Allocator, fixture: *const Fixture) !void {
    var admitted = try fixture.prepared(a);
    defer admitted.deinit();
    try admitted.validate(admitted.template_id);
}
test "caller arithmetic recursion: real nineteen-component admission rejects changed roots recipe geometry and resource policy with clean allocation failures" {
    const a = std.testing.allocator;
    const fixture = try Fixture.init(a);
    var admitted = try fixture.prepared(a);
    defer admitted.deinit();
    try std.testing.expectEqual(@as(usize, 19), admitted.components.len);
    try admitted.validate(admitted.template_id);
    const saved = admitted.logs[1][0];
    const saved_template = admitted.template_id;
    admitted.logs[1][0] += 1;
    admitted.template_id = admitted.identity();
    try std.testing.expectError(error.UntrustedCallerRecursiveGeometry, admitted.validate(admitted.identity()));
    admitted.logs[1][0] = saved;
    admitted.template_id = saved_template;
    var changed = fixture.binding;
    changed.first_roots[1][0] ^= 1;
    try std.testing.expectError(error.UntrustedBlockV5PrecompileInstance, Admission.Prepared.init(a, fixture.statement, 1, changed, fixture.sealed, fixture.pins, &fixture.entries, .{}));
    var statement = fixture.statement;
    statement.ethereum.abi_version += 1;
    try std.testing.expectError(error.AbiMismatch, Admission.Prepared.init(a, statement, 1, fixture.binding, fixture.sealed, fixture.pins, &fixture.entries, .{}));
    try std.testing.expectError(error.CallerRecursiveResourceLimit, Admission.Prepared.init(a, fixture.statement, 1, fixture.binding, fixture.sealed, fixture.pins, &fixture.entries, .{ .max_columns = 1 }));
    try std.testing.checkAllAllocationFailures(a, admissionAllocation, .{&fixture});
}
test "caller arithmetic recursion: original empty-channel restart B5SS47 private14 and complete claim framing match exact native channel" {
    const a = std.testing.allocator;
    const fixture = try Fixture.init(a);
    var admitted = try fixture.prepared(a);
    defer admitted.deinit();
    var claims = try Profile.ExtensionClaim.zeroForStatement(&fixture.statement);
    claims.sha[0] = scalar(50);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var recorder = @import("../recursion/air/blake3_native_recorder.zig").Recorder{ .a = arena.allocator(), .universal_relations = true };
    const actual = try @import("../recursion/air/block_v5_caller_arithmetic_transcript_v1.zig").prefix(arena.allocator(), &recorder, &admitted, &claims);
    var expected = try Protocol.pcsChannel(a, fixture.sealed, fixture.binding);
    claims.mixInto(&expected);
    try std.testing.expectEqualDeep(expected, recorder.native);
    try std.testing.expectEqualDeep(try Protocol.drawRelations(a, fixture.sealed), actual);
    try std.testing.expectEqual(@as(usize, 3), recorder.root_count + 1);
    try std.testing.expectEqual(@as(usize, 61), recorder.relation_count);
    var restart_count: usize = 0;
    for (recorder.operations.items) |operation| if (operation == .restart) {
        restart_count += 1;
    };
    try std.testing.expectEqual(@as(usize, 1), restart_count);
}
const Equation = struct {
    arena: std.heap.ArenaAllocator,
    circuit: r.Circuit,
    inputs: []Q,
    values: []Q,
    sample_input: usize,
    challenge_input: usize,
    expected_input: usize,
    fn deinit(self: *Equation) void {
        self.circuit.deinit();
        self.arena.deinit();
    }
    fn evaluate(self: *Equation) !void {
        try self.circuit.evaluateInto(self.inputs, self.values);
    }
};
fn input(builder: *r.Builder, a: std.mem.Allocator, inputs: *std.ArrayList(Q), value: Q) !S {
    const symbol = try builder.input();
    try inputs.append(a, value);
    return symbol.value;
}
fn equation(a: std.mem.Allocator, admitted: *const Admission.Prepared) !Equation {
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var builder = r.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    const relations = try Protocol.drawRelations(temp, admitted.sealed);
    const claims = try Profile.ExtensionClaim.zeroForStatement(&admitted.statement);
    const owner = try Profile.Assembly(.verifier).createBlockV5Standalone(temp, &admitted.statement, 1, &relations, &claims);
    defer owner.destroy(temp);
    const all = core.air.components.Components{ .components = owner.active(), .n_preprocessed_columns = admitted.logs[0].len };
    const point = try core.circle.secureFieldPointFromRandomSeedChecked(scalar(70));
    var masks = try admitted.maskPoints(temp, point);
    defer masks.deinitDeep(temp);
    const step = core.poly.circle.canonic.CanonicCoset.new(admitted.mask_log).step();
    const previous = point.sub(.{ .x = Q.fromBase(step.x), .y = Q.fromBase(step.y) });
    const concrete = try temp.alloc([][]Q, 3);
    var samples = Composition.Samples{ .offsets = undefined, .layouts = undefined, .values = undefined };
    var symbols: std.ArrayList(S) = .empty;
    var sample_input: usize = 0;
    for (masks.items, concrete, 0..) |columns, *tree_values, tree| {
        tree_values.* = try temp.alloc([]Q, columns.len);
        samples.offsets[tree] = try temp.alloc(usize, columns.len);
        samples.layouts[tree] = try temp.alloc(@import("../recursion/sample_point_layout.zig").Layout, columns.len);
        for (columns, tree_values.*, 0..) |points, *values, column| {
            samples.offsets[tree][column] = symbols.items.len;
            samples.layouts[tree][column] = try @import("../recursion/sample_point_layout.zig").classifyColumn(points, point, previous);
            values.* = try temp.alloc(Q, points.len);
            for (values.*, 0..) |*value, sample| {
                value.* = scalar(@intCast(20 + tree * 103 + column * 7 + sample));
                if (tree == 1 and column == admitted.components[14].spans[1].offset and sample == 0) sample_input = inputs.items.len;
                try symbols.append(temp, try input(&builder, temp, &inputs, value.*));
            }
        }
    }
    samples.offsets[3] = &.{};
    samples.layouts[3] = &.{};
    samples.values = symbols.items;
    var concrete_mask = core.air.components.MaskValues{ .items = concrete };
    const randomness = scalar(90);
    const expected = try all.evalCompositionPolynomialAtPoint(point, &concrete_mask, randomness, admitted.mask_log);
    var details: std.ArrayList(S) = .empty;
    var totals: [19]S = undefined;
    for (claims.componentClaims(), &totals) |view, *total| {
        for (view.detailed) |value| try details.append(temp, try input(&builder, temp, &inputs, value));
        total.* = try input(&builder, temp, &inputs, view.total);
    }
    var channel = admitted.sealed.sharedChannel();
    const vm = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(temp, &channel);
    var draws: [47][2]S = undefined;
    for (&draws, vm.elements) |*pair, element| pair.* = .{ try input(&builder, temp, &inputs, element.z), try input(&builder, temp, &inputs, element.alpha) };
    var suffix: [14][2]S = undefined;
    const extension_draws = relations.draws();
    const challenge_input = inputs.items.len + 26;
    for (&suffix, 0..) |*pair, i| pair.* = .{ try input(&builder, temp, &inputs, extension_draws[2 * i]), try input(&builder, temp, &inputs, extension_draws[2 * i + 1]) };
    const random = try input(&builder, temp, &inputs, randomness);
    const expected_input = inputs.items.len;
    const expected_symbol = try input(&builder, temp, &inputs, expected);
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    const accumulated = try Composition.recordEquations(admitted, owner, samples, details.items, totals, draws, suffix, random, .{ .x = S.fromSecure(point.x), .y = S.fromSecure(point.y) });
    try builder.constrainZero(accumulated.sub(expected_symbol));
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const values = try temp.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs.items, values);
    return .{ .arena = arena, .circuit = circuit, .inputs = inputs.items, .values = values, .sample_input = sample_input, .challenge_input = challenge_input, .expected_input = expected_input };
}
test "caller arithmetic recursion: all nineteen original scalar OODS equations equal symbolic source and reject sample private SHA challenge and quotient mutation" {
    const a = std.testing.allocator;
    const fixture = try Fixture.init(a);
    var admitted = try fixture.prepared(a);
    defer admitted.deinit();
    var replay = try equation(a, &admitted);
    defer replay.deinit();
    for ([_]usize{ replay.sample_input, replay.challenge_input, replay.expected_input }) |index| {
        const saved = replay.inputs[index];
        replay.inputs[index] = saved.add(Q.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, replay.evaluate());
        replay.inputs[index] = saved;
        try replay.evaluate();
    }
}
test "caller arithmetic recursion: full typed detailed claims open sum binding and public schedule cannot relabel independent caller authority" {
    const a = std.testing.allocator;
    const fixture = try Fixture.init(a);
    var admitted = try fixture.prepared(a);
    defer admitted.deinit();
    var claims = try Profile.ExtensionClaim.zeroForStatement(&fixture.statement);
    claims.sha[0] = scalar(1);
    var values = try Bus.Values.fromCaller(&admitted, .{ .binding = fixture.binding, .open_sum = claims.componentSum() }, claims);
    const wire = [_]Bus.Wire{.{ .circuit = 1500, .wire = 1, .uses = 2, .source = .claim, .coordinate = @intCast(values.claimCount() - 5) }};
    const digest = try Bus.scheduleDigest(&wire);
    var channel = core.proof_suites.Blake3.Channel{};
    const relations = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    const before = try Bus.supply(&wire, values, relations);
    values.claims.sha[0] = values.claims.sha[0].add(Q.one());
    values.open_sum = values.claims.componentSum();
    try std.testing.expect(!(try Bus.supply(&wire, values, relations)).eql(before));
    values.binding.caller_key_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedCallerRecursivePublicInputs, values.validate());
    var bad = wire;
    bad[0].coordinate = Composition.MAX_PUBLIC_CLAIMS;
    try std.testing.expectError(error.InvalidCallerRecursiveSchedule, Bus.scheduleDigest(&bad));
    var swapped = wire;
    swapped[0].source = .open_sum;
    swapped[0].coordinate = 0;
    try std.testing.expect(!std.meta.eql(digest, try Bus.scheduleDigest(&swapped)));
}
