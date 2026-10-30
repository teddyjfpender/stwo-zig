//! Genuine original proof -> owned verification capture -> independently
//! constructed native composition. This is not a complete recursive block.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Q = core.fields.qm31.QM31;
const Native = @import("block_v7_native_proof_v1.zig");
const E = @import("block_v7_execution_epoch_v1.zig");
const Profile = @import("../recursion/block_v7_native_fixed_profile_v1.zig");
const Composition = @import("../recursion/air/block_v7_native_composition_v1.zig");
const instructions = [_]u32{ 0x00100537, 0x00100293, 0x02552423, 0x0000006f };
const elf = @import("../runner/guest_precompile/test_elf.zig").buildReleaseProgram(instructions.len, &instructions, 64, .rv32im_zkvm_v1);
test "v7 native recursion original access and no access composition after producer destruction" {
    try run(2, false);
    try run(3, false);
}
test "v7 native independently keyed parent with and without access" {
    try run(2, true);
    try run(3, true);
}
fn run(comptime steps: u32, comptime parent: bool) !void {
    const a = std.testing.allocator;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8), .lifting_log_size = null };
    var session = try @import("../runner/mod.zig").BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var executed = try session.startSegment(steps);
    defer executed.deinit();
    var counters = try @import("../air/lookups/tables/mod.zig").counter.Set.init(a);
    defer counters.deinit(a);
    var segment = try @import("block_v7_execution_test_support.zig").Segment.init(a, &executed, config, @splat(7), 0, .rv32im_zkvm_v1, 0, &counters);
    var segment_live = true;
    defer if (segment_live) segment.deinit();
    const entries = [_]E.Entry{try segment.pin.entry(a)};
    var counts: E.Counts = @splat(0);
    counts[0] = 1;
    const epoch = try E.Epoch.init(@splat(9), config, counts, &entries, entries.len);
    const profile = try Profile.Owned.derive(a, segment.pin, epoch, &entries, .{});
    defer profile.deinit();
    var compiled = try Composition.compile(a, profile);
    defer compiled.deinit();
    var proof = try Native.For(Cpu).prove(a, &segment.first, segment.owner, segment.source.inputs, segment.pin, epoch, &entries);
    var proof_live = true;
    defer if (proof_live) proof.deinit(a);
    try @import("block_v7_execution_test_support.zig").roundTrip(a, &proof.stark);
    var captured = try Native.For(Cpu).verifyAndCapture(a, &proof, segment.pin, epoch, &entries);
    defer captured.deinit();
    // Neither the original proof, its claims, nor producer witness may supply
    // geometry or authoritative state to the cold composition compiler.
    proof.deinit(a);
    proof_live = false;
    segment.deinit();
    segment_live = false;
    try profile.validate();
    try compiled.validateAgainst(profile);
    try std.testing.expectEqual(@as(usize, if (steps == 2) 3 else 4), profile.trace_count);
    var deep_inputs = try @import("../recursion/pcs_arithmetic_capture.zig").Owned.init(a, profile.shape.deepProfile(), &captured.proof);
    defer deep_inputs.deinit();
    var deep_graph = try @import("../recursion/air/pcs_deep_circuit.zig").build(a, profile.shape.deepProfile());
    defer deep_graph.deinit();
    var deep = @import("../recursion/air/blake3_native_deep.zig").Prepared{ .graph = deep_graph, .inputs = deep_inputs, .evaluation = try deep_graph.evaluate(a, deep_inputs.inputs) };
    defer deep.evaluation.deinit();
    var fri = try @import("../recursion/air/blake3_native_fri.zig").prepareCaptured(a, &captured.proof, config, &deep, 1502, 1504);
    defer fri.deinit();
    const public = try Composition.publicInputs(a, profile, captured.claims, captured.memory_claims);
    defer a.free(public);
    const drawn = try epoch.draw(a);
    var challenge: [106]Q = undefined;
    for (drawn.word.universal_prefix.elements, 0..) |element, i| {
        challenge[2 * i] = element.z;
        challenge[2 * i + 1] = element.alpha;
    }
    inline for (.{ drawn.word.transition, drawn.word.link, drawn.word.initial, drawn.word.endpoint, drawn.word.range16 }, 0..) |element, i| {
        challenge[94 + 2 * i] = element.z;
        challenge[95 + 2 * i] = element.alpha;
    }
    challenge[104] = drawn.memory.interval.z;
    challenge[105] = drawn.memory.interval.powers[1];
    var live_transcript = try @import("../recursion/air/block_v7_native_transcript_v1.zig").planReplay(a, profile, &captured, 8);
    defer live_transcript.deinit();
    var fixed_transcript = try @import("../recursion/block_v7_native_fixed_transcript_v1.zig").derive(a, profile, captured.claims, captured.memory_claims, 8, .{});
    defer fixed_transcript.deinit();
    try std.testing.expectEqualDeep(live_transcript.plan.id, fixed_transcript.id);
    // End-channel equality alone can conceal incorrectly batched secure draws
    // when a later mix resets the counter. Check every exported scalar too.
    var seen: [106]bool = @splat(false);
    for (live_transcript.operations) |operation| switch (operation) {
        .secure => |secure| if (secure.output) |role| switch (role) {
            .universal => |relation| {
                for (0..2) |half| {
                    const i = 2 * relation + half;
                    try std.testing.expect(!seen[i]);
                    try std.testing.expectEqualDeep(challenge[i].toM31Array(), secure.values[4 * half ..][0..4].*);
                    seen[i] = true;
                }
            },
            .universal_half => |part| {
                const i = 2 * part.relation + part.half;
                try std.testing.expect(!seen[i]);
                try std.testing.expectEqualDeep(challenge[i].toM31Array(), secure.values[0..4].*);
                seen[i] = true;
            },
            else => {},
        },
        else => {},
    };
    try std.testing.expect(std.mem.allEqual(bool, &seen, true));
    const inputs = try a.alloc(Q, compiled.sources.len);
    defer a.free(inputs);
    for (compiled.sources, inputs) |source, *value| value.* = switch (source) {
        .sample => |i| captured.proof.sampled_values[i],
        .challenge => |i| challenge[i],
        .public_input => |i| public[i],
        .composition => captured.proof.composition_randomness,
        .oods => captured.proof.oods_seed,
        else => return error.UnexpectedNativeCompositionSource,
    };
    const values = try a.alloc(Q, compiled.circuit.nodes.len);
    defer a.free(values);
    try compiled.circuit.evaluateInto(inputs, values);
    var checked: usize = 0;
    for (compiled.sources, inputs) |source, *value| {
        if (source == .public_input and source.public_input >= 8) {
            const original = value.*;
            value.* = original.add(Q.one());
            try std.testing.expectError(error.UnsatisfiedCircuit, compiled.circuit.evaluateInto(inputs, values));
            value.* = original;
            checked += 1;
        }
    }
    try std.testing.expect(checked > 0);
    const old_mask = profile.shape.mask_log;
    profile.shape.mask_log += 1;
    try std.testing.expectError(error.MutatedNativeFixedProfile, profile.validate());
    profile.shape.mask_log = old_mask;
    const old_source = compiled.sources[0];
    compiled.sources[0] = .oods;
    compiled.seal = compiled.identity();
    try std.testing.expectError(error.UntrustedNativeComposition, compiled.validateAgainst(profile));
    compiled.sources[0] = old_source;
    compiled.seal = compiled.identity();
    if (parent) try @import("tests/block_v7_native_parent_test_support.zig").qualify(a, profile, &captured);
    try std.testing.expectError(error.IncompleteV7Epoch, epoch.requireCompleteFamilies());
    std.debug.print("V7_NATIVE_RECURSIVE_COMPOSITION access={any} copied_capture=true producer_destroyed=true physical_claim_mutations={d} cold_live_transcript=true exact_106_draws=true outer_parent=false\n", .{ steps == 3, checked });
}
