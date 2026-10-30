//! Genuine two-segment RV32 execution. This is an original-proof integration
//! gate, not recursive/canonical Ethereum qualification or a throughput test.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Q = core.fields.qm31.QM31;
const Epoch = @import("block_v7_execution_epoch_v1.zig");
const Native = @import("block_v7_native_proof_v1.zig");
const Stage = @import("block_v5_native_memory_stage_v1.zig");
const Physical = @import("block_v5_cpu_native_root_proposal_v1.zig").ForBackend(Cpu);
const Owner = @import("blake3_execution_trace.zig").Owner;
const IO = @import("blake3_segment_public.zig").Owned;
const Tables = @import("../air/lookups/tables/mod.zig");
const Initial = @import("block_v7_initial_intervals_v1.zig");
const Policy = @import("block_v7_execution_policy_v1.zig");
const Memory = @import("block_v7_memory_stage_v1.zig").For(Cpu);
const MemorySource = @import("block_v7_memory_source_v1.zig");
const ROM = @import("block_v7_program_provider_v1.zig");
const Lookup = @import("block_v7_lookup_provider_v1.zig");
const LookupPlan = @import("block_v5_native_lookup_plan_v1.zig");
const Event = @import("../air/block/memory_transition.zig").Transition;
const instructions = [_]u32{ 0x001002b7, 0x10028293, 0x08028313, @import("../isa/sha256_compression_v1.zig").encode(5, 6), @import("../isa/custom0.zig").encodeKeccakf(5), 0x00100537, 0x00100393, 0x02752423, 0x02b00393, 0x00752223, 0x00100393, 0x00752023, 0x0000006f };
const raw = @import("../runner/guest_precompile/test_elf.zig").buildReleaseProgram(instructions.len, &instructions, 256, .rv32im_zkvm_ethereum_sha_v1);
const elf = blk: {
    var bytes = raw;
    const table = std.mem.readInt(u32, bytes[264..268], .little);
    for ([4]usize{ 2, 3, 7, 8 }, [4]u32{ 0x100100, 256, 0x100300, 0x100310 }) |index, value|
        std.mem.writeInt(u32, bytes[table + (index + 1) * 16 + 4 ..][0..4], value, .little);
    break :blk bytes;
};
const Support = @import("block_v7_execution_test_support.zig");
const Segment = Support.Segment;
const roundTrip = Support.roundTrip;
test "v7 authentic SHA Keccak two segment execution closes all original sources" {
    try runFixture(false, false, NoConsumer);
}
test "v7 authentic SHA Keccak joint memory reduces original proof roster" {
    try runFixture(true, false, NoConsumer);
}
test "v7 authentic SHA Keccak compact lookup closes all original sources" {
    try runFixture(true, true, NoConsumer);
}
pub const Fixture = struct {
    allocator: std.mem.Allocator,
    trusted: @import("block_v7_execution_receiver_v1.zig").Trusted,
    input: @import("block_v7_execution_receiver_v1.zig").Input,
    policy: Policy.Policy,
    original: @import("block_v7_execution_receiver_v1.zig").Verified,
};
const NoConsumer = struct {
    pub const Result = void;
    pub fn consume(_: Fixture) !void {}
};
/// The consumer may return owned proof bytes and independently reconstructed
/// metadata. All original producers and proofs are destroyed before this
/// function returns, enabling a genuinely detached outer receiver test.
pub fn runFixture(comptime joint: bool, comptime compact: bool, comptime Consumer: type) !Consumer.Result {
    const a = std.testing.allocator;
    const engine = @import("stwo_prover_engine");
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var scoped = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer scoped.deinit();
    const Caller = @import("block_v7_caller_joint_proof_v1.zig");

    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8), .lifting_log_size = null };
    var initialized = try Initial.Owned.derive(a, &elf, @import("block_v5_initial_sources_v1.zig").sha256(&elf), .rv32im_zkvm_ethereum_sha_v1, .{});
    defer initialized.deinit();
    var image = try @import("block_v7_program_image_v1.zig").Owned.init(a, &elf, &initialized, .{});
    defer image.deinit();
    var output: [43]u8 = @splat(0);
    output[32] = 1;
    const policy = Policy.Policy{ .initialized = &initialized, .program_root = image.root.bytes, .terminal = .{ .final_cycle = 12, .halt_address = initialized.info.halt_flag, .length_address = initialized.info.output_len, .data_address = initialized.info.output_data, .output_end = initialized.info.output_end, .output = output }, .config = config };
    var session = try @import("../runner/mod.zig").EthereumShaExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local, .stop_on_halt_flag = true });
    defer session.deinit();
    var run0 = try session.startSegment(8);
    defer run0.deinit();
    var run1 = try session.resumeSegment(run0.base.continuation.?, 4);
    defer run1.deinit();
    var counters = try Tables.counter.Set.init(a);
    defer counters.deinit(a);
    var s0 = try Segment.init(a, &run0.base, config, image.root.bytes, 0, .rv32im_zkvm_ethereum_sha_v1, 2, &counters);
    defer s0.deinit();
    var s1 = try Segment.init(a, &run1.base, config, image.root.bytes, 1, .rv32im_zkvm_ethereum_sha_v1, 0, &counters);
    defer s1.deinit();
    const windows = [_]Policy.Native{ .{ .shape = s0.pin.shape, .frame = s0.pin.frame, .external_retirements = 2 }, .{ .shape = s1.pin.shape, .frame = s1.pin.frame } };
    try policy.validateWindows(&windows);
    var guest: std.ArrayList(Event) = .empty;
    defer guest.deinit(a);
    var demand: [6]u64 = @splat(0);
    for ([_]*Segment{ &s0, &s1 }) |s| {
        try LookupPlan.addDemand(&demand, try LookupPlan.nativeDemand(s.pin.shape, s.pin.template.external_retirements));
        try LookupPlan.addDemand(&demand, try LookupPlan.sidecarMemoryDemand(s.pin.expected_events));
        for (s.source.inputs) |input| for (0..input.trace.domainSize()) |i| {
            const row = try input.trace.row(i);
            if (row.active) try guest.append(a, try @import("block_memory_relation_v2.zig").decodeTransitionTuple(row.tuple));
        };
    }
    try std.testing.expectEqual(@as(usize, 3), guest.items.len);
    var witness = try @import("block_v5_precompile_witness_v1.zig").Witness.initSegment(a, &run0);
    defer witness.deinit();
    try std.testing.expectEqual(@as(u32, 1), witness.statement.sha.call_count);
    try std.testing.expectEqual(@as(u32, 1), witness.statement.ethereum.counts.keccak_calls);
    try (@import("../air/guest_precompile/ethereum_lookup_registration.zig").Context{ .keccak = run0.extension.keccakf_calls.records(), .recovery = run0.extension.signer_recovery_calls.records() }).register(&counters);
    try @import("../air/guest_precompile/sha256_lookup_registration.zig").register(a, &witness.sha_rows, &counters);
    var caller_first = try @import("block_v5_precompile_family_proof_v1.zig").ForBackend(Cpu).commitPhysicalFirstRound(a, &witness, witness.total_steps, config);
    defer caller_first.deinit(a);
    var caller_memory = try @import("block_v5_caller_external_stage_v1.zig").ForBackend(Cpu).Prepared.initForMode(a, &caller_first, &witness.statement, s0.pin.frame, 0, counters.get(.range_check_8_8), 1);
    defer caller_memory.deinit(a);
    const caller_pin = Caller.Pin{ .index = 0, .execution_index = 0, .execution_identity = (try s0.pin.entry(a)).identity, .statement = &witness.statement, .total_steps = witness.total_steps, .frame = s0.pin.frame, .roots = caller_first.roots, .access_root = caller_memory.first.roots[2], .config = config };
    try @import("block_v5_precompile_table_demand_v1.zig").add(a, &demand, &witness.statement, witness.total_steps, config);
    try LookupPlan.addDemand(&demand, try LookupPlan.sidecarMemoryDemand(caller_memory.byte_demand.event_count));
    for (caller_memory.inputs) |input| for (0..input.trace.domainSize()) |i| {
        const row = try input.trace.row(i);
        if (row.active) try guest.append(a, try @import("block_memory_relation_v2.zig").decodeTransitionTuple(row.tuple));
    };
    const Joint = @import("block_v7_memory_joint_proof_v1.zig");
    const memory = if (joint) try Joint.For(Cpu).Stage.init(a, policy, guest.items, 0, 64, .{}) else blk: {
        const ptr = try a.create(Memory);
        errdefer a.destroy(ptr);
        ptr.* = try Memory.init(a, policy, guest.items, 0, 64, .{});
        break :blk ptr;
    };
    defer {
        memory.deinit();
        if (!joint) a.destroy(memory);
    }
    const memory_entries = if (joint) try a.dupe(Epoch.Entry, &.{try memory.entry()}) else try memory.entries(a);
    defer a.free(memory_entries);
    const rom_plan = @import("block_v5_program_table_v1.zig").Plan{ .program_root = image.root, .leaves = image.leaves, .multiplicities = &.{ 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 0 }, .expected_fetches = 13, .log_size = 7 };
    var rom_first = try ROM.ForBackend(Cpu).commit(a, rom_plan, config);
    defer rom_first.deinit(a);
    const lookup_plan = LookupPlan.Plan{ .index = 0, .first_execution = 0, .execution_count = 2, .max_requests = demand };
    const Compact = @import("block_v7_lookup_compact_proof_v1.zig");
    var lookup_first = if (compact) try Compact.For(Cpu).Stage.init(a, &counters, lookup_plan, config, null, .{}) else try Lookup.ForBackend(Cpu).commit(a, &counters, lookup_plan, config);
    defer if (compact) lookup_first.deinit() else lookup_first.deinit(a);
    var roster: std.ArrayList(Epoch.Entry) = .empty;
    defer roster.deinit(a);
    try roster.appendSlice(a, &.{ try s0.pin.entry(a), try s1.pin.entry(a), try caller_pin.entry(a), try ROM.firstEntry(rom_plan, rom_first.roots), if (compact) try Compact.firstEntry(lookup_plan, lookup_first.layout, lookup_first.roots) else try Lookup.firstEntry(lookup_plan, lookup_first.roots) });
    try roster.appendSlice(a, memory_entries);
    var counts: Epoch.Counts = @splat(0);
    for (roster.items) |entry| counts[@intFromEnum(entry.family)] += 1;
    const epoch = try Epoch.Epoch.init(try policy.digest(), config, counts, roster.items, roster.items.len);
    try epoch.requireCompleteFamilies();
    var p0 = try Native.For(Cpu).prove(a, &s0.first, s0.owner, s0.source.inputs, s0.pin, epoch, roster.items);
    defer p0.deinit(a);
    var p1 = try Native.For(Cpu).prove(a, &s1.first, s1.owner, s1.source.inputs, s1.pin, epoch, roster.items);
    defer p1.deinit(a);
    var cp = try Caller.ForBackend(Cpu).prove(a, &caller_memory.first, &caller_first, caller_memory.inputs, caller_pin, epoch, roster.items, &pool);
    defer cp.deinit(a);
    var mp = try memory.prove(epoch, roster.items);
    defer if (joint) mp.deinit() else mp.deinit(a);
    const rp = ROM.Policy{ .plan = rom_plan, .expected_program_root = image.root, .roots = rom_first.roots, .epoch = epoch, .entries = roster.items };
    var rom = try ROM.ForBackend(Cpu).prove(a, &rom_first, rp);
    defer rom.deinit(a);
    const lp = Lookup.Policy{ .plan = lookup_plan, .roots = lookup_first.roots, .epoch = epoch, .entries = roster.items };
    var lookup = if (compact) try lookup_first.prove(epoch, roster.items) else try Lookup.ForBackend(Cpu).prove(a, &lookup_first, &counters, lp);
    defer lookup.deinit(a);
    try roundTrip(a, &cp.stark);
    try roundTrip(a, &p0.stark);
    try roundTrip(a, &p1.stark);
    try roundTrip(a, &rom.stark);
    try roundTrip(a, &lookup.stark);
    if (joint) {
        try roundTrip(mp.allocator, &mp.stark);
    } else {
        for (mp.ram) |*r| try roundTrip(a, &r.proof.stark);
        try roundTrip(a, &mp.interval.stark);
        try roundTrip(a, &mp.range16.stark);
        try roundTrip(a, &mp.terminal.stark);
    }
    const Receiver = @import("block_v7_execution_receiver_v1.zig");
    const trusted = Receiver.Trusted{ .elf = &elf, .elf_sha256 = initialized.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .terminal = policy.terminal, .config = config };
    const native_inputs = [_]Receiver.Native{ .{ .pin = s0.pin, .proof = &p0 }, .{ .pin = s1.pin, .proof = &p1 } };
    const input = Receiver.Input{ .epoch = epoch, .entries = roster.items, .natives = &native_inputs, .callers = &.{.{ .pin = caller_pin, .proof = &cp }}, .program_plan = rom_plan, .program_roots = rom_first.roots, .program = &rom, .lookup_plan = lookup_plan, .lookup_roots = lookup_first.roots, .lookup = if (compact) .{ .compact = .{ .layout = lookup_first.layout, .proof = &lookup } } else .{ .dense = &lookup }, .memory = if (joint) .{ .joint = &mp } else .{ .separate = &mp } };
    const verified = try Receiver.For(Cpu).verify(a, trusted, input, .{});
    try std.testing.expectEqual(@as(u64, guest.items.len), verified.ram_events);
    try std.testing.expectEqual(@as(u64, 13), verified.program_fetches);
    var wrong = input;
    var wrong_pin = caller_pin;
    wrong_pin.execution_index = 1;
    wrong.callers = &.{.{ .pin = wrong_pin, .proof = &cp }};
    try std.testing.expectError(error.UntrustedV7CallerExecution, Receiver.For(Cpu).verify(a, trusted, wrong, .{}));
    wrong = input;
    wrong.callers = &.{};
    try std.testing.expectError(error.InvalidV7CallerRoster, Receiver.For(Cpu).verify(a, trusted, wrong, .{}));
    if (compact) {
        var changed_layout = input;
        var modes: [6]@import("block_v7_lookup_compact_algebra_v1.zig").Mode = undefined;
        var logs: [6]u32 = undefined;
        for (lookup_first.layout.parts, &modes, &logs) |part, *mode, *log| {
            mode.* = part.mode;
            log.* = part.log;
        }
        modes[0] = .dense;
        logs[0] = @import("../air/lookups/tables/schema.zig").logSize(.bitwise);
        const other_layout = try @import("block_v7_lookup_compact_layout_v1.zig").Layout.init(modes, logs);
        try std.testing.expect(!std.meta.eql(other_layout.digest, lookup_first.layout.digest));
        changed_layout.lookup = .{ .compact = .{ .layout = other_layout, .proof = &lookup } };
        try std.testing.expectError(error.UntrustedV7SourceEntry, Receiver.For(Cpu).verify(a, trusted, changed_layout, .{}));
    }
    std.debug.print("v7_authentic_calls segments=2 cycles=12 sha=1 keccak=1 ram_events={} joint_memory={} compact_lookup={} original_proofs={} source_closure=verified recursion=unqualified security=q8_pow0\n", .{ verified.ram_events, joint, compact, if (joint) @as(usize, 6) else 3 + 2 + mp.ram.len + 3 });
    return Consumer.consume(.{ .allocator = a, .trusted = trusted, .input = input, .policy = policy, .original = verified });
}
