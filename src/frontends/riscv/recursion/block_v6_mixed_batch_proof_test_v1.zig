//! Genuine two-batch recursive proof. Original range/ROM equations, then one
//! independently fixed batch-verifier root. Global block closure is NOT claimed.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Provider = @import("block_v6_provider_batch_prepare_v1.zig");
const ProviderBus = @import("block_v6_provider_batch_public_v1.zig");
const Mixed = @import("block_v6_mixed_direct_public_v1.zig");
const Direct = @import("block_v6_mixed_direct_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Capture = @import("block_v6_mixed_batch_capture_v1.zig");
const Batch = @import("block_v6_mixed_batch_public_v1.zig");
const Protocol = @import("block_v6_mixed_batch_protocol_v1.zig");
const Prepare = @import("block_v6_mixed_batch_prepare_v1.zig");
const Cold = @import("block_v6_mixed_batch_fixed_join_v1.zig");
const profile: Parent.protocol.Profile = .diagnostic_q8_pow0;
const config = profile.config();
fn originals(a: std.mem.Allocator) ![2]Provider.Prepared {
    const Range = @import("../prover/block_v5_range16_v1.zig");
    const RangeProof = @import("../prover/block_v5_range16_proof_v1.zig");
    const Rom = @import("../prover/block_v5_program_table_v1.zig");
    const RomProof = @import("../prover/block_v5_program_table_proof_v1.zig");
    const Seal = @import("../prover/block_v5_source_seal_v1.zig");
    const Tree = @import("../air/memory_commitment/blake3_state_tree.zig");
    var counter = try Range.Counter.init(a);
    defer counter.deinit();
    try counter.add(17);
    const shard = Range.Shard{ .index = 0, .first_instance = 0, .instance_count = 1, .request_count = counter.total };
    const range_plan: [32]u8 = @splat(70);
    var range_first = try RangeProof.ForBackend(Cpu).commitFirstRound(a, &counter, shard, range_plan, config, true);
    defer range_first.deinit(a);
    const leaves = [_]Tree.Leaf{ .{ .index = 0, .value = 1 }, .{ .index = 1, .value = 2 }, .{ .index = 2, .value = 3 }, .{ .index = 3, .value = 4 } };
    const program_root = try Tree.TreeHasher.init(.program).root(&leaves);
    const rom_plan = Rom.Plan{ .program_root = program_root, .leaves = &leaves, .multiplicities = &.{5}, .expected_fetches = 5, .log_size = 7 };
    var rom_first = try RomProof.ForBackend(Cpu).commitFirstRound(a, rom_plan, config);
    defer rom_first.deinit(a);
    // Other seal entries are fixed scope metadata only. This test claims no
    // proof of their families, execution validity, or complete memory closure.
    const entries = [_]Seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = try rom_plan.digest(), .roots = rom_first.roots },
        .{ .family = .execution, .index = 0, .instance_id = @splat(20), .roots = .{ @splat(21), @splat(22) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(30), .roots = .{ @splat(31), @splat(32) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(40), .roots = .{ @splat(41), @splat(42) } },
        .{ .family = .memory, .index = 0, .instance_id = @splat(50), .roots = .{ @splat(51), @splat(52) } },
        .{ .family = .memory_range, .index = 0, .instance_id = RangeProof.instanceId(range_plan, 0), .roots = range_first.roots() },
    };
    var counts: [Seal.family_count]u32 = @splat(0);
    for (entries) |entry| counts[@intFromEnum(entry.family) - 1] += 1;
    const pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = program_root.bytes, .program_plan_digest = try rom_plan.digest(), .memory_plan_digest = range_plan, .initial_source_plan_digest = @splat(7), .register_endpoint_plan_digest = @splat(8), .register_custody_mode = 1, .config = config, .counts = counts };
    const sealed = try Seal.seal(pins, &entries);
    var range_proof = try RangeProof.ForBackend(Cpu).prove(a, &range_first, &counter, shard, range_plan, sealed, pins, &entries);
    defer range_proof.deinit(a);
    var rom_proof = try RomProof.ForBackend(Cpu).prove(a, &rom_first, rom_plan, sealed.programSeal());
    defer rom_proof.deinit(a);
    var range_admission = try ProviderBus.Definition(.range16).Prepared.init(a, shard, range_plan, range_first.roots(), sealed, pins, &entries, .{});
    defer range_admission.deinit();
    var rom_admission = try ProviderBus.Definition(.program_table).Prepared.init(a, rom_plan, 0, sealed, pins, &entries, .{});
    defer rom_admission.deinit();
    var range_capture = try @import("../prover/block_v5_range16_recursive_capture_v1.zig").ForBackend(Cpu).verifyBorrowed(a, &range_proof, &range_admission);
    defer range_capture.deinit();
    var rom_capture = try @import("../prover/block_v5_program_table_recursive_capture_v1.zig").ForBackend(Cpu).verifyBorrowed(a, &rom_proof, &rom_admission);
    defer rom_capture.deinit();
    const inputs = [2]Provider.Input{ .{ .range16 = .{ .admitted = &range_admission, .capture = &range_capture } }, .{ .program_table = .{ .admitted = &rom_admission, .capture = &rom_capture } } };
    var out: [2]Provider.Prepared = undefined;
    var done: usize = 0;
    errdefer for (out[0..done]) |*piece| piece.deinit();
    for (inputs, &out) |input, *piece| {
        const expected = (try input.publicChild()).expected();
        piece.* = try Provider.prepare(a, &.{input}, &.{expected}, 2);
        done += 1;
    }
    return out;
}
test "mixed batch genuine original range ROM proofs reduce through independently compiled verifier root" {
    const a = std.testing.allocator;
    var pool: @import("stwo_prover_engine").work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try @import("stwo_prover_engine").work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var base = try originals(a);
    var originals_owned = true;
    defer if (originals_owned) for (&base) |*piece| piece.deinit();
    std.debug.print("MIXED_BATCH_PROOF stage=originals\n", .{});
    var children: [2]Mixed.Child = undefined;
    var roster: [2]Mixed.Expected = undefined;
    var wires: [2][]Mixed.Wire = @splat(&.{});
    defer for (wires) |slice| a.free(slice);
    var keys: [2]Direct.Key = undefined;
    var policies: [2]Capture.Policy = undefined;
    var captures: [2]Capture.Captured = undefined;
    var captured: usize = 0;
    defer for (captures[0..captured]) |*capture| capture.deinit();
    var expected: [2]Batch.Expected = undefined;
    for (&base, &children, &roster) |*piece, *child, *pin| {
        child.* = .{ .provider = piece.children[0] };
        pin.* = child.expected();
    }
    for (&base, &wires, &keys, &policies, &captures, &expected, 0..) |*piece, *schedule, *key, *policy, *capture, *pin, i| {
        schedule.* = try a.alloc(Mixed.Wire, piece.wires.len);
        for (piece.wires, schedule.*) |wire, *out| out.* = .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .child = 0, .source = .{ .provider = wire.source }, .coordinate = wire.coordinate };
        const geometry = try Parent.ForBackend(Cpu).deriveKeyWithProfile(a, &piece.recursive, profile);
        key.* = try Direct.Key.fromGeometry(geometry, schedule.*, roster[i..][0..1]);
        const key_id = try key.identity();
        const admission = try Direct.Admission.init(key.*, key_id, schedule.*, .{ .children = children[i..][0..1] }, roster[i..][0..1]);
        const Plan = @import("blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Direct);
        const plan = try Plan.init(a, &piece.recursive.rows, admission);
        defer plan.deinit();
        var proof = try plan.prove(a, &piece.recursive.rows);
        defer proof.deinit();
        const bytes = try Parent.codec.encode(a, &proof, &admission);
        defer a.free(bytes);
        policy.* = .{ .scope = .{ .sealed_digest = roster[0].provider.sealed, .profile = profile, .public_input_identity = @splat(77) }, .whole_roster = &roster, .counts = &.{ 1, 1 }, .ordinal = @intCast(i), .key = key.*, .expected_key = key_id, .wires = schedule.*, .values = .{ .children = children[i..][0..1] }, .expected_public_input_identity = try admission.publicInputIdentity() };
        capture.* = try Capture.verifyAndCapture(a, bytes, policy.*, .{});
        captured += 1;
        pin.* = try Batch.Expected.fromPolicy(a, policy.*, .{});
        std.debug.print("MIXED_BATCH_PROOF stage=batch-capture index={d} proof_bytes={d}\n", .{ i, bytes.len });
    }
    for (&base) |*piece| piece.deinit();
    originals_owned = false;
    const pointers = [_]*const Capture.Captured{ &captures[0], &captures[1] };
    var ready = try Prepare.prepare(a, &pointers, &expected, .{});
    var ready_owned = true;
    defer if (ready_owned) ready.deinit();
    std.debug.print("MIXED_BATCH_PROOF stage=prepared\n", .{});
    var cold = try Cold.Owned.derive(a, &policies, &expected, 2, .{});
    defer cold.deinit();
    try cold.validateLive(&ready);
    std.debug.print("MIXED_BATCH_PROOF stage=independent-fixed-parity matched=true\n", .{});
    const key = try cold.deriveKey(Cpu, a);
    const key_id = try key.identity();
    const bytes = produce: {
        const admitted = try Protocol.Admission.init(key, key_id, cold.wires, ready.values(), cold.expected);
        const Plan = @import("blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
        const plan = try Plan.init(a, &ready.recursive.rows, admitted);
        defer plan.deinit();
        var proof = try plan.prove(a, &ready.recursive.rows);
        defer proof.deinit();
        break :produce try Parent.codec.encode(a, &proof, &admitted);
    };
    defer a.free(bytes);
    ready.deinit();
    ready_owned = false;
    for (captures[0..captured]) |*capture| capture.deinit();
    captured = 0;
    // Fresh receiver owns only independently re-admitted policy and typed
    // metadata. Original STARKs, captures and every wide MAIN owner are gone.
    var fresh: [2]*Capture.Source = undefined;
    var fresh_count: usize = 0;
    defer for (fresh[0..fresh_count]) |source| source.deinit();
    for (policies, &fresh) |policy, *source| {
        source.* = try Capture.Source.create(a, policy, .{});
        fresh_count += 1;
    }
    const receiver_children = [_]*const Capture.Source{ fresh[0], fresh[1] };
    const values = Batch.Values{ .children = &receiver_children };
    const admission = try Protocol.Admission.init(key, key_id, cold.wires, values, cold.expected);
    var decoded = try Parent.codec.decode(a, bytes, &admission);
    var verified = try Parent.verify(&decoded, &admission);
    defer verified.deinit();
    var hostile = try Parent.codec.decode(a, bytes, &admission);
    const samples = hostile.proof.?.commitment_scheme_proof.sampled_values.items;
    samples[3][0][0] = samples[3][0][0].add(core.fields.qm31.QM31.one());
    try hostile.validate(&admission); // Valid envelope, unchanged claims/key.
    if (Parent.verify(&hostile, &admission)) |accepted| {
        var bad = accepted;
        bad.deinit();
        return error.AcceptedChangedMixedBatchOods;
    } else |err| {
        std.debug.print("MIXED_BATCH_PROOF hostile_oods_rejected={s}\n", .{@errorName(err)});
        try std.testing.expect(err == error.OodsNotMatching);
    }
    const original = fresh[1].range;
    fresh[1].range.first += 1;
    try std.testing.expectError(error.InvalidMixedBatchAdjacency, admission.validate());
    fresh[1].range = original;
    var wrong = key_id;
    wrong[0] ^= 1;
    try std.testing.expectError(error.UntrustedProviderBatchKey, Protocol.Admission.init(key, wrong, cold.wires, values, cold.expected));
    std.debug.print("MIXED_BATCH_PROOF verified=true batches=2 original_providers=2 proof_bytes={d} cold_key=true producer_captures=0 producer_rows=0 hostile_oods_rejected=true global_block_authority=false\n", .{bytes.len});
}
