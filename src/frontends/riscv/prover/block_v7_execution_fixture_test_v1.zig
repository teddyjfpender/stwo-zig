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
const instructions = [_]u32{ 0x00100537, 0x00100293, 0x02552423, 0x02b00293, 0x00552223, 0x00100293, 0x00552023, 0x0000006f };
const raw = @import("../runner/guest_precompile/test_elf.zig").buildReleaseProgram(instructions.len, &instructions, 64, .rv32im_zkvm_v1);
const elf = blk: {
    var bytes = raw;
    const table = std.mem.readInt(u32, bytes[264..268], .little);
    for ([4]usize{ 2, 3, 7, 8 }, [4]u32{ 0x100100, 64, 0x100180, 0x100190 }) |index, value|
        std.mem.writeInt(u32, bytes[table + (index + 1) * 16 + 4 ..][0..4], value, .little);
    break :blk bytes;
};
const Support = @import("block_v7_execution_test_support.zig");
const Segment = Support.Segment;
const roundTrip = Support.roundTrip;
test "v7 authentic two segment RV32 original proofs close ELF ROM registers RAM and terminal13" {
    try run(4);
}
test "v7 authentic no RAM first segment durable handoff keeps exact two tree source" {
    try run(2);
}
fn run(comptime split: u32) !void {
    const a = std.testing.allocator;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8), .lifting_log_size = null };
    var initialized = try Initial.Owned.derive(a, &elf, @import("block_v5_initial_sources_v1.zig").sha256(&elf), .rv32im_zkvm_v1, .{});
    defer initialized.deinit();
    var image = try @import("block_v7_program_image_v1.zig").Owned.init(a, &elf, &initialized, .{});
    defer image.deinit();
    var output: [43]u8 = @splat(0);
    output[32] = 1;
    const policy = Policy.Policy{ .initialized = &initialized, .program_root = image.root.bytes, .terminal = .{ .final_cycle = 7, .halt_address = initialized.info.halt_flag, .length_address = initialized.info.output_len, .data_address = initialized.info.output_data, .output_end = initialized.info.output_end, .output = output }, .config = config };
    var session = try @import("../runner/mod.zig").BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local, .stop_on_halt_flag = true });
    defer session.deinit();
    var run0 = try session.startSegment(split);
    defer run0.deinit();
    var run1 = try session.resumeSegment(run0.continuation.?, 7 - split);
    defer run1.deinit();
    var counters = try Tables.counter.Set.init(a);
    defer counters.deinit(a);
    var s0 = try Segment.init(a, &run0, config, image.root.bytes, 0, .rv32im_zkvm_v1, 0, &counters);
    var s0_live = true;
    defer if (s0_live) s0.deinit();
    var s1 = try Segment.init(a, &run1, config, image.root.bytes, 1, .rv32im_zkvm_v1, 0, &counters);
    defer s1.deinit();
    const windows = [_]Policy.Native{ .{ .shape = s0.pin.shape, .frame = s0.pin.frame }, .{ .shape = s1.pin.shape, .frame = s1.pin.frame } };
    try policy.validateWindows(&windows);
    var guest: std.ArrayList(Event) = .empty;
    defer guest.deinit(a);
    var demand: [6]u64 = @splat(0);
    for ([_]*Segment{ &s0, &s1 }) |s| {
        try LookupPlan.addDemand(&demand, try LookupPlan.nativeDemand(s.pin.shape, 0));
        try LookupPlan.addDemand(&demand, try LookupPlan.sidecarMemoryDemand(s.pin.expected_events));
        for (s.source.inputs) |input| for (0..input.trace.domainSize()) |i| {
            const row = try input.trace.row(i);
            if (row.active) try guest.append(a, try @import("block_memory_relation_v2.zig").decodeTransitionTuple(row.tuple));
        };
    }
    try std.testing.expectEqual(@as(usize, 3), guest.items.len);
    var memory = try Memory.init(a, policy, guest.items, 0, 7, .{});
    defer memory.deinit();
    const memory_entries = try memory.entries(a);
    defer a.free(memory_entries);
    const rom_plan = @import("block_v5_program_table_v1.zig").Plan{ .program_root = image.root, .leaves = image.leaves, .multiplicities = if (split == 4) &.{ 1, 1, 1, 1, 2, 1, 1, 0 } else &.{ 1, 1, 2, 1, 1, 1, 1, 0 }, .expected_fetches = 8, .log_size = 7 };
    var rom_first = try ROM.ForBackend(Cpu).commit(a, rom_plan, config);
    defer rom_first.deinit(a);
    const lookup_plan = LookupPlan.Plan{ .index = 0, .first_execution = 0, .execution_count = 2, .max_requests = demand };
    var lookup_first = try Lookup.ForBackend(Cpu).commit(a, &counters, lookup_plan, config);
    defer lookup_first.deinit(a);
    var roster: std.ArrayList(Epoch.Entry) = .empty;
    defer roster.deinit(a);
    try roster.appendSlice(a, &.{ try s0.pin.entry(a), try s1.pin.entry(a), try ROM.firstEntry(rom_plan, rom_first.roots), try Lookup.firstEntry(lookup_plan, lookup_first.roots) });
    try roster.appendSlice(a, memory_entries);
    var counts: Epoch.Counts = @splat(0);
    for (roster.items) |entry| counts[@intFromEnum(entry.family)] += 1;
    const epoch = try Epoch.Epoch.init(try policy.digest(), config, counts, roster.items, roster.items.len);
    try epoch.requireCompleteFamilies();
    var p0 = try Native.For(Cpu).prove(a, &s0.first, s0.owner, s0.source.inputs, s0.pin, epoch, roster.items);
    defer p0.deinit(a);
    var p1 = try Native.For(Cpu).prove(a, &s1.first, s1.owner, s1.source.inputs, s1.pin, epoch, roster.items);
    defer p1.deinit(a);
    var mp = try memory.prove(epoch, roster.items);
    defer mp.deinit(a);
    const rp = ROM.Policy{ .plan = rom_plan, .expected_program_root = image.root, .roots = rom_first.roots, .epoch = epoch, .entries = roster.items };
    var rom = try ROM.ForBackend(Cpu).prove(a, &rom_first, rp);
    defer rom.deinit(a);
    const lp = Lookup.Policy{ .plan = lookup_plan, .roots = lookup_first.roots, .epoch = epoch, .entries = roster.items };
    var lookup = try Lookup.ForBackend(Cpu).prove(a, &lookup_first, &counters, lp);
    defer lookup.deinit(a);
    try roundTrip(a, &p0.stark);
    try roundTrip(a, &p1.stark);
    try roundTrip(a, &rom.stark);
    try roundTrip(a, &lookup.stark);
    for (mp.ram) |*r| try roundTrip(a, &r.proof.stark);
    try roundTrip(a, &mp.interval.stark);
    try roundTrip(a, &mp.range16.stark);
    try roundTrip(a, &mp.terminal.stark);
    const Receiver = @import("block_v7_execution_receiver_v1.zig");
    const trusted = Receiver.Trusted{ .elf = &elf, .elf_sha256 = initialized.elf_sha256, .profile = .rv32im_zkvm_v1, .terminal = policy.terminal, .config = config };
    const native_inputs = [_]Receiver.Native{ .{ .pin = s0.pin, .proof = &p0 }, .{ .pin = s1.pin, .proof = &p1 } };
    const input = Receiver.Input{ .epoch = epoch, .entries = roster.items, .natives = &native_inputs, .program_plan = rom_plan, .program_roots = rom_first.roots, .program = &rom, .lookup_plan = lookup_plan, .lookup_roots = lookup_first.roots, .lookup = .{ .dense = &lookup }, .memory = .{ .separate = &mp } };
    const verified = try Receiver.For(Cpu).verify(a, trusted, input, .{});
    try std.testing.expectEqual(@as(u64, 3), verified.ram_events);
    try std.testing.expectEqual(@as(u64, 8), verified.program_fetches);
    // Independent boundaries reject before any provider work.
    var wrong = trusted;
    wrong.terminal.output[0] ^= 1;
    try std.testing.expectError(error.UntrustedV7Epoch, Receiver.For(Cpu).verify(a, wrong, input, .{}));
    var changed = input;
    var swapped = native_inputs;
    std.mem.swap(Receiver.Native, &swapped[0], &swapped[1]);
    changed.natives = &swapped;
    try std.testing.expectError(error.UntrustedV7NativeRoster, Receiver.For(Cpu).verify(a, trusted, changed, .{}));
    const initial_sp = s0.owner.statement.public_data.initial_regs[2];
    s0.owner.statement.public_data.initial_regs[2] ^= 16;
    try std.testing.expectError(error.UntrustedV7ExecutionBoundary, Receiver.For(Cpu).verify(a, trusted, input, .{}));
    s0.owner.statement.public_data.initial_regs[2] = initial_sp;
    const old_sum = p0.claims[0].sum;
    p0.claims[0].sum = old_sum.add(Q.one());
    try std.testing.expectError(error.OodsNotMatching, Native.For(Cpu).verify(a, &p0, s0.pin, epoch, roster.items));
    p0.claims[0].sum = old_sum;
    // Qualify the bounded persistence seam against these same original roots.
    // Destroy the original native owner/physical/access witnesses before load.
    const Cache = @import("block_v7_native_checkpoint_v1.zig");
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var restored_counters = try Tables.counter.Set.init(a);
    defer restored_counters.deinit(a);
    const Sink = struct {
        count: usize = 0,
        fn put(raw_context: *anyopaque, _: Event) !void {
            const self: *@This() = @ptrCast(@alignCast(raw_context));
            self.count += 1;
        }
    };
    var sink = Sink{};
    const names = Cache.Names{ .raw = "segment.raw", .native = "segment.pcs", .access = "segment.access" };
    const cache_limits = Cache.Limits{ .columns = .{ .columns = .{ .max_columns = 4096, .max_log_size = 20, .max_file_bytes = 1 << 28, .max_loaded_bytes = 1 << 28 }, .max_public_words = 0, .max_public_bytes = 0 }, .pcs = .{ .max_columns = 4096, .max_log_size = 20, .max_file_bytes = 1 << 28, .max_loaded_bytes = 1 << 28 }, .source = .{ .max_slots = 100, .max_witness_cells = 1 << 20, .max_metadata_bytes = 1 << 20, .register_custody_mode = 1 }, .max_total_bytes = 1 << 29 };
    var too_small = cache_limits;
    too_small.max_total_bytes = 1;
    if (Cache.collect(a, temporary.dir, names, s0.owner, config, .rv32im_zkvm_v1, 0, 1, &restored_counters, .{ .context = &sink, .put = Sink.put }, too_small)) |value| {
        var unexpected = value;
        unexpected.deinit();
        return error.ExpectedCheckpointBudgetRejection;
    } else |err| try std.testing.expectEqual(error.V5WitnessColumnLimit, err);
    try std.testing.expectEqual(@as(usize, 0), sink.count);
    try std.testing.expectError(error.FileNotFound, temporary.dir.access(names.raw, .{}));
    try std.testing.expectError(error.FileNotFound, temporary.dir.access(names.native, .{}));
    try std.testing.expectError(error.FileNotFound, temporary.dir.access(names.access, .{}));
    for (restored_counters.counters) |counter| for (counter.values) |value| try std.testing.expect(value.isZero());
    var record = try Cache.collect(a, temporary.dir, names, s0.owner, config, .rv32im_zkvm_v1, 0, 1, &restored_counters, .{ .context = &sink, .put = Sink.put }, cache_limits);
    defer record.deinit();
    try std.testing.expectEqual(@as(usize, if (split == 4) 1 else 0), sink.count);
    try std.testing.expectEqualDeep(try s0.pin.entry(a), try record.entry(a));
    s0.deinit();
    s0_live = false;
    var limited = cache_limits;
    limited.max_total_bytes = record.stats.written_bytes - 1;
    try std.testing.expectError(error.InvalidV7CheckpointPolicy, Cache.load(a, temporary.dir, names, &record, limited));
    var replay = try Cache.proveOne(a, temporary.dir, names, &record, cache_limits, epoch, roster.items);
    defer replay.deinit(a);
    try std.testing.expectEqualDeep(p0.claims, replay.claims);
    try std.testing.expectEqualDeep(p0.memory_claims, replay.memory_claims);
    var expected_bytes = std.Io.Writer.Allocating.init(a);
    defer expected_bytes.deinit();
    var actual_bytes = std.Io.Writer.Allocating.init(a);
    defer actual_bytes.deinit();
    const wire = @import("interop_postcard");
    try wire.serializeProof(core.proof_suites.Blake3.Hasher, &expected_bytes.writer, p0.stark);
    try wire.serializeProof(core.proof_suites.Blake3.Hasher, &actual_bytes.writer, replay.stark);
    try std.testing.expectEqualSlices(u8, expected_bytes.written(), actual_bytes.written());
    try temporary.dir.deleteFile(names.raw);
    try temporary.dir.deleteFile(names.native);
    if (record.auxiliary != null) try temporary.dir.deleteFile(names.access);
    var restored_inputs = native_inputs;
    restored_inputs[0] = .{ .pin = record.pin(), .proof = &replay };
    var restored_input = input;
    restored_input.natives = &restored_inputs;
    _ = try Receiver.For(Cpu).verify(a, trusted, restored_input, .{});
    std.debug.print("v7_native_checkpoint bytes={} raw={} pcs={} access={} loaded_codec_bytes={} proof_bytes_identical=true files_deleted_before_receiver=true\n", .{ record.stats.written_bytes, record.stats.raw_bytes, record.stats.native_pcs_bytes, record.stats.access_bytes, record.stats.retained_loaded_bytes });
    std.debug.print("v7_authentic_execution segments=2 cycles=7 ram_events={} original_proofs={} source_closure=verified recursion=unqualified security=q8_pow0\n", .{ verified.ram_events, 2 + 2 + mp.ram.len + 3 });
}

test "v7 actual continued RV32 execution cannot reinterpret an early halt as final completion" {
    const a = std.testing.allocator;
    var hostile_elf = elf;
    const text_offset = std.mem.readInt(u32, hostile_elf[56..60], .little);
    // Actual RV32 stores: set halt at instruction 3, continue with length and
    // success stores through instruction 7. Terminal RAM is otherwise correct.
    std.mem.writeInt(u32, hostile_elf[text_offset + 2 * 4 ..][0..4], 0x00552023, .little);
    std.mem.writeInt(u32, hostile_elf[text_offset + 6 * 4 ..][0..4], 0x02552423, .little);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8), .lifting_log_size = null };
    var initialized = try Initial.Owned.derive(a, &hostile_elf, @import("block_v5_initial_sources_v1.zig").sha256(&hostile_elf), .rv32im_zkvm_v1, .{});
    defer initialized.deinit();
    var image = try @import("block_v7_program_image_v1.zig").Owned.init(a, &hostile_elf, &initialized, .{});
    defer image.deinit();
    var output: [43]u8 = @splat(0);
    output[32] = 1;
    const policy = Policy.Policy{ .initialized = &initialized, .program_root = image.root.bytes, .terminal = .{ .final_cycle = 7, .halt_address = initialized.info.halt_flag, .length_address = initialized.info.output_len, .data_address = initialized.info.output_data, .output_end = initialized.info.output_end, .output = output }, .config = config };
    var session = try @import("../runner/mod.zig").BaseExecutionSession.init(a, &hostile_elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local, .stop_on_halt_flag = false });
    defer session.deinit();
    var run0 = try session.startSegment(4);
    defer run0.deinit();
    var run1 = try session.resumeSegment(run0.continuation.?, 3);
    defer run1.deinit();
    var counters = try Tables.counter.Set.init(a);
    defer counters.deinit(a);
    var s0 = try Segment.init(a, &run0, config, image.root.bytes, 0, .rv32im_zkvm_v1, 0, &counters);
    defer s0.deinit();
    var s1 = try Segment.init(a, &run1, config, image.root.bytes, 1, .rv32im_zkvm_v1, 0, &counters);
    defer s1.deinit();
    var guest: std.ArrayList(Event) = .empty;
    defer guest.deinit(a);
    for ([_]*Segment{ &s0, &s1 }) |s| {
        for (s.source.inputs) |input| {
            for (0..input.trace.domainSize()) |i| {
                const row = try input.trace.row(i);
                if (row.active) try guest.append(a, try @import("block_memory_relation_v2.zig").decodeTransitionTuple(row.tuple));
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 3), guest.items.len);
    var early = false;
    for (guest.items) |event| if (event.address == policy.terminal.halt_address and event.after == 1 and event.clock < 25) {
        early = true;
    };
    try std.testing.expect(early);
    var memory = try Memory.init(a, policy, guest.items, 0, 7, .{});
    defer memory.deinit();
    const entries = try memory.entries(a);
    defer a.free(entries);
    var counts: Epoch.Counts = @splat(0);
    for (entries) |entry| counts[@intFromEnum(entry.family)] += 1;
    const epoch = try Epoch.Epoch.init(try policy.digest(), config, counts, entries, entries.len);
    // This scoped original RAM proof must reject before any receiver could
    // treat a host completion record as authority. No native validity shortcut.
    if (memory.prove(epoch, entries)) |value| {
        var unexpected = value;
        unexpected.deinit(a);
        return error.ExpectedFirstHaltRejection;
    } else |err| try std.testing.expectEqual(error.ConstraintsNotSatisfied, err);
}
