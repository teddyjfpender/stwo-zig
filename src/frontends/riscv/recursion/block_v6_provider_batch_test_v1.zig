const std = @import("std");
const core = @import("stwo_core");
const Bus = @import("block_v6_provider_batch_public_v1.zig");
const Prep = @import("block_v6_provider_batch_prepare_v1.zig");
const Protocol = @import("block_v6_provider_batch_protocol_v1.zig");
const Receive = @import("block_v6_provider_batch_receiver_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Q = core.fields.qm31.QM31;

fn literals() [2]Bus.Child {
    return .{
        .{ .range16 = .{ .template = @splat(1), .sealed = @splat(2), .plan = @splat(3), .roots = .{ @splat(4), @splat(5) }, .shard = .{ .index = 0, .first_instance = 0, .instance_count = 1, .request_count = 37 }, .sum = Q.one(), .count = 37 } },
        .{ .program_table = .{ .template = @splat(6), .sealed = @splat(2), .native_roster = @splat(7), .plan = @splat(8), .program_root = @splat(9), .roots = .{ @splat(10), @splat(11) }, .index = 0, .log_size = 7, .fetch_count = 5, .claim = Q.one() } },
    };
}
test "provider direct batch typed roster rejects omission duplication family order and mixed seals" {
    // These are metadata proposals only, never real captures or proof authority.
    var children = literals();
    const expected = [_]Bus.Expected{ children[0].expected(), children[1].expected() };
    const values = Bus.Values{ .children = &children };
    try values.requireRoster(&expected);
    _ = try Bus.rosterDigest(&expected);
    try std.testing.expectError(error.UntrustedProviderBatchRoster, values.requireRoster(expected[0..1]));
    children[1] = children[0];
    try std.testing.expectError(error.InvalidProviderBatchOrder, values.validate());
    children = literals();
    std.mem.swap(Bus.Child, &children[0], &children[1]);
    try std.testing.expectError(error.InvalidProviderBatchOrder, values.validate());
    children = literals();
    children[1].program_table.sealed[0] ^= 1;
    try std.testing.expectError(error.MixedProviderBatchSeal, values.validate());
    children = literals();
    children[0].range16.roots[1][0] ^= 1;
    try std.testing.expectError(error.UntrustedProviderBatchRoster, values.requireRoster(&expected));
}
test "provider direct batch public schedule preserves family and coordinate identity" {
    const children = literals();
    const values = Bus.Values{ .children = &children };
    var wires = [_]Bus.Wire{
        .{ .circuit = 1, .wire = 1, .uses = 1, .child = 0, .source = .{ .range16 = .sum }, .coordinate = 0 },
        .{ .circuit = 2, .wire = 1, .uses = 1, .child = 1, .source = .{ .program_table = .claim }, .coordinate = 0 },
    };
    _ = try Bus.scheduleDigest(&wires);
    try std.testing.expectEqualDeep(Q.one().toM31Array(), try values.at(wires[0]));
    wires[0].source = .{ .program_table = .claim };
    try std.testing.expectError(error.InvalidProviderBatchWire, values.at(wires[0]));
    wires[0].source = .{ .range16 = .sum };
    wires[0].coordinate = 1;
    try std.testing.expectError(error.InvalidRangePublicSchedule, Bus.scheduleDigest(&wires));
    wires[0].coordinate = 0;
    wires[1].circuit = 1;
    try std.testing.expectError(error.InvalidProviderBatchSchedule, Bus.scheduleDigest(&wires));
}

test "provider direct batch four real range RAM ROM lookup base proofs join once and freshly verify" {
    const a = std.testing.allocator;
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const Range = @import("../prover/block_v5_range16_v1.zig");
    const RangeProof = @import("../prover/block_v5_range16_proof_v1.zig");
    const Rom = @import("../prover/block_v5_program_table_v1.zig");
    const RomProof = @import("../prover/block_v5_program_table_proof_v1.zig");
    const Seal = @import("../prover/block_v5_source_seal_v1.zig");
    const Ram = @import("../prover/block_v5_ram_lanes_proof_v1.zig");
    const RamTrace = @import("../air/block/word_memory_lanes_trace_v1.zig").Trace;
    const Lookup = @import("../prover/block_v5_native_lookup_proof_v1.zig");
    const Tables = @import("../air/lookups/tables/mod.zig");
    const Tree = @import("../air/memory_commitment/blake3_state_tree.zig");
    const profile: Parent.protocol.Profile = .diagnostic_q8_pow0;
    const config = profile.config();
    var pool: @import("stwo_prover_engine").work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 8, .backing_allocator = a });
    defer pool.deinit();
    var binding = try @import("stwo_prover_engine").work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var expected: [4]Bus.Expected = undefined;
    var prepared = build: {
        var counter = try Range.Counter.init(a);
        defer counter.deinit();
        const Event = @import("../air/block/memory_transition.zig").Transition;
        const events = [_]Event{
            .{ .space = 1, .address = 0x2000, .clock = 1, .before = 0, .after = 1 },
            .{ .space = 1, .address = 0x2000, .clock = 2, .before = 1, .after = 2 },
            .{ .space = 1, .address = 0x2000, .clock = 3, .before = 2, .after = 3 },
        };
        var ram_trace = try RamTrace.init(a, .{ .first_event = 0, .total_events = 3, .events = 3, .row_log = 2, .first = events[0], .last = events[2], .preceding = null }, .{ .max_row_log = 4, .max_events = 16, .max_owned_bytes = 1 << 20 });
        defer ram_trace.deinit();
        for (events) |event| try ram_trace.append(event);
        try ram_trace.seal();
        var ram_first = try Ram.ForBackend(Cpu).commitFirstRoundWithCounter(a, &ram_trace, 0, config, true, .{}, &counter);
        defer ram_first.deinit(a);
        const shard = Range.Shard{ .index = 0, .first_instance = 0, .instance_count = 1, .request_count = counter.total };
        var lookup_counters = try Tables.counter.Set.init(a);
        defer lookup_counters.deinit(a);
        for (&lookup_counters.counters, 0..) |*one, index| try one.registerBase(core.fields.m31.M31.one(), (try Tables.schema.tupleAt(one.kind, index)).slice());
        const lookup_plan = Lookup.Plan{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = @splat(1) };
        var lookup_first = try Lookup.ForBackend(Cpu).commitFirstRound(a, &lookup_counters, lookup_plan, config);
        defer lookup_first.deinit(a);
        const range_plan: [32]u8 = @splat(70);
        var range_first = try RangeProof.ForBackend(Cpu).commitFirstRound(a, &counter, shard, range_plan, config, true);
        defer range_first.deinit(a);
        const leaves = [_]Tree.Leaf{ .{ .index = 0, .value = 1 }, .{ .index = 1, .value = 2 }, .{ .index = 2, .value = 3 }, .{ .index = 3, .value = 4 } };
        const program_root = try Tree.TreeHasher.init(.program).root(&leaves);
        const rom_plan = Rom.Plan{ .program_root = program_root, .leaves = &leaves, .multiplicities = &.{5}, .expected_fetches = 5, .log_size = 7 };
        var rom_first = try RomProof.ForBackend(Cpu).commitFirstRound(a, rom_plan, config);
        defer rom_first.deinit(a);
        const entries = [_]Seal.Entry{
            .{ .family = .program, .index = 0, .instance_id = try rom_plan.digest(), .roots = rom_first.roots },
            .{ .family = .execution, .index = 0, .instance_id = @splat(20), .roots = .{ @splat(21), @splat(22) } },
            .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(30), .roots = .{ @splat(31), @splat(32) } },
            .{ .family = .program_request, .index = 0, .instance_id = @splat(40), .roots = .{ @splat(41), @splat(42) } },
            try ram_first.pin.entry(),
            .{ .family = .memory_range, .index = 0, .instance_id = RangeProof.instanceId(range_plan, 0), .roots = range_first.roots() },
            try lookup_first.entry(lookup_plan),
        };
        var counts: [Seal.family_count]u32 = @splat(0);
        for (entries) |entry| counts[@intFromEnum(entry.family) - 1] += 1;
        const pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = program_root.bytes, .program_plan_digest = try rom_plan.digest(), .memory_plan_digest = range_plan, .initial_source_plan_digest = @splat(7), .register_endpoint_plan_digest = @splat(8), .register_custody_mode = 1, .config = config, .counts = counts };
        const sealed = try Seal.seal(pins, &entries);
        const ram_challenges = try @import("../prover/block_v5_ram_lanes_protocol_v1.zig").Challenges.draw(a, sealed);
        var inverses = try @import("../prover/block_v5_range16_inverse_table_v1.zig").Table.init(a, ram_challenges.range16);
        defer inverses.deinit();
        var ram_proof = try Ram.ForBackend(Cpu).provePrepared(a, &ram_first, &ram_trace, ram_first.pin, sealed, pins, &entries, &inverses, .{});
        defer ram_proof.deinit(a);
        var lookup_proof = try Lookup.ForBackend(Cpu).prove(a, &lookup_first, &lookup_counters, lookup_plan, sealed, pins, &entries);
        defer lookup_proof.deinit(a);
        var range_proof = try RangeProof.ForBackend(Cpu).prove(a, &range_first, &counter, shard, range_plan, sealed, pins, &entries);
        defer range_proof.deinit(a);
        var rom_proof = try RomProof.ForBackend(Cpu).prove(a, &rom_first, rom_plan, sealed.programSeal());
        defer rom_proof.deinit(a);
        var range_admission = try Bus.Definition(.range16).Prepared.init(a, shard, range_plan, range_first.roots(), sealed, pins, &entries, .{});
        defer range_admission.deinit();
        var rom_admission = try Bus.Definition(.program_table).Prepared.init(a, rom_plan, 0, sealed, pins, &entries, .{});
        defer rom_admission.deinit();
        var range_capture = try @import("../prover/block_v5_range16_recursive_capture_v1.zig").ForBackend(Cpu).verifyBorrowed(a, &range_proof, &range_admission);
        defer range_capture.deinit();
        var rom_capture = try @import("../prover/block_v5_program_table_recursive_capture_v1.zig").ForBackend(Cpu).verifyBorrowed(a, &rom_proof, &rom_admission);
        defer rom_capture.deinit();
        var ram_admission = try Bus.Definition(.ram_lanes).Prepared.init(a, ram_first.pin, sealed, pins, &entries, .{});
        defer ram_admission.deinit();
        var lookup_admission = try Bus.Definition(.native_lookup).Prepared.init(a, lookup_plan, lookup_first.roots, sealed, pins, &entries, .{});
        defer lookup_admission.deinit();
        var ram_capture = try @import("../prover/block_v5_ram_lanes_recursive_capture_v1.zig").ForBackend(Cpu).verifyBorrowed(a, &ram_proof, &ram_admission);
        defer ram_capture.deinit();
        var lookup_capture = try @import("../prover/block_v5_native_lookup_recursive_capture_v1.zig").ForBackend(Cpu).verifyBorrowed(a, &lookup_proof, &lookup_admission);
        defer lookup_capture.deinit();
        const inputs = [_]Prep.Input{
            .{ .range16 = .{ .admitted = &range_admission, .capture = &range_capture } },
            .{ .ram_lanes = .{ .admitted = &ram_admission, .capture = &ram_capture } },
            .{ .program_table = .{ .admitted = &rom_admission, .capture = &rom_capture } },
            .{ .native_lookup = .{ .admitted = &lookup_admission, .capture = &lookup_capture } },
        };
        for (inputs, &expected) |input, *out| out.* = (try input.publicChild()).expected();
        var ready = try Prep.prepare(a, &inputs, &expected, 2);
        errdefer ready.deinit();
        const ClaimTypes = @import("block_v6_mixed_claim_types_v1.zig");
        const ClaimCodec = @import("block_v6_mixed_claim_codec_v1.zig");
        const Reconstruct = @import("block_v6_mixed_claim_reconstruct_v1.zig");
        var mixed_expected: [4]ClaimTypes.Bus.Expected = undefined;
        var records: [4]ClaimTypes.Record = undefined;
        var independent: [4]Reconstruct.Input = undefined;
        for (inputs, expected, &mixed_expected, &records, &independent) |input, pin, *mixed_pin, *record, *source| switch (input) {
            inline else => |value, family| {
                mixed_pin.* = .{ .provider = pin };
                record.* = .{ .index = pin.index, .claim = @unionInit(ClaimTypes.Claim, @tagName(family), Bus.Definition(family).claim(value.capture.receipt)) };
                source.* = @unionInit(Reconstruct.Input, @tagName(family), value.admitted);
            },
        };
        const metadata = try ClaimCodec.encode(a, &records, &mixed_expected, .{});
        defer a.free(metadata);
        var decoded_claims = try ClaimCodec.decode(a, metadata, &mixed_expected, .{});
        defer decoded_claims.deinit();
        var rebuilt = try Reconstruct.reconstruct(a, decoded_claims.records, &mixed_expected, &independent);
        defer rebuilt.deinit();
        for (ready.children, rebuilt.children) |*original, reconstructed| {
            try std.testing.expect(std.meta.eql(original.*, reconstructed.provider));
            original.* = reconstructed.provider;
        }
        break :build ready;
    };
    defer prepared.deinit();
    // Original base proofs, captures, admissions and first-round owners were
    // destroyed above. Parent authority comes only from owned rows and metadata.

    const geometry = try Parent.ForBackend(Cpu).deriveKeyWithProfile(a, &prepared.recursive, profile);
    const key = try Protocol.Key.fromGeometry(geometry, prepared.wires, &expected);
    const key_id = try key.identity();
    const admission = try Protocol.Admission.init(key, key_id, prepared.wires, prepared.values(), &expected);
    const Plan = @import("blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
    const plan = try Plan.init(a, &prepared.recursive.rows, admission);
    defer plan.deinit();
    var proved = try plan.prove(a, &prepared.recursive.rows);
    defer proved.deinit();
    const bytes = try Parent.codec.encode(a, &proved, &admission);
    defer a.free(bytes);
    var verified = try Receive.verify(a, bytes, key, key_id, prepared.wires, &expected, prepared.values());
    defer verified.deinit();
    try std.testing.expectEqual(@as(usize, 4), verified.values.children.len);
    var changed = try a.dupe(Bus.Child, prepared.children);
    defer a.free(changed);
    changed[0].range16.sum = changed[0].range16.sum.add(Q.one());
    if (Receive.verify(a, bytes, key, key_id, prepared.wires, &expected, .{ .children = changed })) |result| {
        var bad = result;
        bad.deinit();
        return error.AcceptedChangedProviderClaim;
    } else |_| {}
    try std.testing.expectError(error.UntrustedProviderBatchRoster, Receive.verify(a, bytes, key, key_id, prepared.wires, expected[0..1], prepared.values()));
    var wrong_key = key_id;
    wrong_key[0] ^= 1;
    try std.testing.expectError(error.UntrustedProviderBatchKey, Receive.verify(a, bytes, key, wrong_key, prepared.wires, &expected, prepared.values()));
}
