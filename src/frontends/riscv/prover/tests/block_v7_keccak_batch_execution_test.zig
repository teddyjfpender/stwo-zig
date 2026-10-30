//! Genuine native windows with identical local caller control and chained RAM.
//! The malicious case rebuilds every affected commitment and all proofs under
//! the new epoch; it cannot be rejected merely by retaining an old source root.
const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Runner = @import("../../runner/mod.zig");
const Guest = @import("block_v7_keccak_execution_test_support.zig");
const Batch = @import("../block_v7_keccak_batch_proof_v1.zig");
const Source = @import("../block_v7_keccak_batch_source_v1.zig");
const Native = @import("../block_v7_native_proof_v1.zig");
const ROM = @import("../block_v7_program_provider_v1.zig");
const Lookup = @import("../block_v7_lookup_compact_proof_v1.zig");
const Joint = @import("../block_v7_memory_joint_proof_v1.zig");
const Epoch = @import("../block_v7_execution_epoch_v1.zig");
const Support = @import("../block_v7_execution_test_support.zig");
const LP = @import("../block_v5_native_lookup_plan_v1.zig");
const Event = @import("../../air/block/memory_transition.zig").Transition;
const Shape = @import("../../air/statement.zig").Blake3ExecutionStatement;
const Receiver = @import("../block_v7_keccak_execution_receiver_v1.zig");
const Union = @import("../block_v7_keccak_union_proof_v1.zig");

fn qualify(comptime swap_owners: bool, comptime combined: bool) !void {
    const backing = std.testing.allocator;
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(backing, 8 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var whole = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    const canonical = std.process.hasEnvVarConstant("STWO_V7_KECCAK_CANONICAL");
    const elf = Guest.elf();
    const Profile = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile;
    const config = (if (canonical) Profile.csp_q70_pow26 else Profile.diagnostic_q8_pow0).config();
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var initial = try @import("../block_v7_initial_intervals_v1.zig").Owned.derive(a, &elf, @import("../block_v5_initial_sources_v1.zig").sha256(&elf), .rv32im_zkvm_ethereum_sha_v1, .{});
    defer initial.deinit();
    var image = try @import("../block_v7_program_image_v1.zig").Owned.init(a, &elf, &initial, .{});
    defer image.deinit();
    const policy = @import("../block_v7_execution_policy_v1.zig").Policy{ .initialized = &initial, .program_root = image.root.bytes, .terminal = .{ .final_cycle = Guest.cycles, .halt_address = initial.info.halt_flag, .length_address = initial.info.output_len, .data_address = initial.info.output_data, .output_end = initial.info.output_end, .output = Guest.output }, .config = config };
    const trusted = @import("../block_v7_execution_receiver_v1.zig").Trusted{ .elf = &elf, .elf_sha256 = initial.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .terminal = policy.terminal, .config = config };
    var session = try Runner.EthereumShaExecutionSession.init(a, &elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned, .stop_on_halt_flag = true, .require_current_output_accesses = false });
    var session_live = true;
    defer if (session_live) session.deinit();
    var counters = try @import("../../air/lookups/tables/counter.zig").Set.init(a);
    var counters_live = true;
    defer if (counters_live) counters.deinit(a);
    var runs: [4]Runner.EthereumShaSegmentResult = undefined;
    var run_count: usize = 0;
    defer for (runs[0..run_count]) |*r| r.deinit();
    var segments: [4]Support.Segment = undefined;
    var segment_count: usize = 0;
    defer for (segments[0..segment_count]) |*s| s.deinit();
    var shapes: [4]Shape = undefined;
    var native_pins: [4]Native.Pin = undefined;
    var records: [2]@import("../../runner/guest_precompile/keccakf_call_buffer.zig").Record = undefined;
    var windows: [2]Source.Window = undefined;
    var calls: usize = 0;
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(a);
    const multiplicities = try a.alloc(u64, image.leaves.len / 4);
    defer a.free(multiplicities);
    @memset(multiplicities, 0);
    var demand: [6]u64 = @splat(0);
    var fetches: u64 = 0;
    var token: ?@import("../../runner/result.zig").ContinuationToken = null;
    for (Guest.cuts, 0..) |cut, i| {
        runs[i] = if (token) |t| try session.resumeSegment(t, cut) else try session.startSegment(cut);
        run_count += 1;
        const run = &runs[i];
        token = run.base.continuation;
        const external = try @import("../block_v5_cpu_execution_source_v1.zig").externalCount(run);
        segments[i] = try Support.Segment.initWithSourceLimits(a, &run.base, config, image.root.bytes, @intCast(i), .rv32im_zkvm_ethereum_sha_v1, external, &counters, .{ .max_slots = 100, .max_witness_cells = 16 << 20, .max_metadata_bytes = 1 << 20, .register_custody_mode = 1 });
        segment_count += 1;
        const segment = &segments[i];
        shapes[i] = segment.owner.statement;
        shapes[i].public_data.io_entries.input_words = &.{};
        shapes[i].public_data.io_entries.output_words = &.{};
        native_pins[i] = segment.pin;
        native_pins[i].shape = &shapes[i];
        for (segment.source.inputs) |input| for (0..input.trace.domainSize()) |r| {
            const row = try input.trace.row(r);
            if (row.active) try events.append(a, try @import("../block_memory_relation_v2.zig").decodeTransitionTuple(row.tuple));
        };
        try LP.addDemand(&demand, try LP.nativeDemand(&shapes[i], external));
        try LP.addDemand(&demand, try LP.sidecarMemoryDemand(native_pins[i].expected_events));
        const Program = @import("../../air/program/commitment.zig");
        const rows = try Program.declaredRows(a, Program.DeclaredDecodeAuthority{ .profile = .rv32im_zkvm_ethereum_sha_v1 }, .{ run.base.execution_trace.rows.items, run.extension.keccakf_execution_rows.rows(), run.extension.signer_recovery_execution_rows.rows(), run.extension.sha_calls.records() }, run.base.rw_memory.program_words, @import("../commitment_program_witness.zig").completionFetch(segment.io.data.completion));
        defer a.free(rows);
        for (rows) |row| if (row.multiplicity != 0) {
            const at = (row.addr - initial.info.memory_layout.program_base) / 4;
            multiplicities[at] += row.multiplicity;
            fetches += row.multiplicity;
        };
        if (external != 0) {
            try std.testing.expectEqual(@as(u32, 1), external);
            const record = run.extension.keccakf_calls.records()[0];
            records[calls] = record;
            windows[calls] = .{ .execution_index = @intCast(i), .native_identity = (try native_pins[i].entry(a)).identity, .frame = native_pins[i].frame, .calls = 1 };
            calls += 1;
            // Independent actual execution events: this list is never handed to
            // the batch AIR. The sorted RAM proof binds their before/after chain.
            for (record.input, record.output, 0..) |before, after, word| try events.append(a, .{ .space = 1, .address = record.state_ptr + @as(u32, @intCast(4 * word)), .clock = (native_pins[i].frame.global_first_cycle + record.execution_clock - 2) * 4 + 2, .before = before, .after = after });
        }
    }
    try std.testing.expectEqual(@as(usize, 2), calls);
    try std.testing.expect(token == null);
    try std.testing.expectEqualSlices(u8, &Guest.output, runs[3].base.output.?);
    try std.testing.expectEqual(records[0].pc, records[1].pc);
    try std.testing.expectEqual(records[0].execution_clock, records[1].execution_clock);
    try std.testing.expectEqual(records[0].pointer_register, records[1].pointer_register);
    try std.testing.expectEqual(records[0].pointer_previous_clock, records[1].pointer_previous_clock);
    try std.testing.expectEqualSlices(u32, &records[0].output, &records[1].input);
    if (swap_owners) std.mem.swap(@TypeOf(records[0]), &records[0], &records[1]);
    // Re-register the submitted rows (the owner swap keeps this multiset).
    try @import("../block_v7_keccak_window_lookup_v1.zig").register(a, &records, &counters);
    const stage = try Batch.ForBackend(Cpu).Stage.init(a, &records, &windows, 0, config, counters.get(.range_check_8_8), .{});
    var stage_live = true;
    defer if (stage_live) stage.deinit();
    const pin = stage.pin;
    try LP.addDemand(&demand, try Receiver.batchDemand(a, pin, .{}));
    const plan = @import("../block_v5_program_table_v1.zig").Plan{ .program_root = image.root, .leaves = image.leaves, .multiplicities = multiplicities, .expected_fetches = fetches, .log_size = @max(7, std.math.log2_int_ceil(usize, multiplicities.len)) };
    var first = try ROM.ForBackend(Cpu).commit(a, plan, config);
    var first_live = true;
    defer if (first_live) first.deinit(a);
    const lookup_plan = LP.Plan{ .index = 0, .first_execution = 0, .execution_count = 4, .max_requests = demand };
    var lookup_stage = try Lookup.For(Cpu).Stage.init(a, &counters, lookup_plan, config, null, .{});
    var lookup_live = true;
    defer if (lookup_live) lookup_stage.deinit();
    const memory_stage = try Joint.For(Cpu).Stage.init(a, policy, events.items, 0, 64, .{});
    var memory_live = true;
    defer if (memory_live) memory_stage.deinit();
    var entries: [8]Epoch.Entry = undefined;
    for (native_pins, entries[0..4]) |np, *entry| entry.* = try np.entry(a);
    entries[4] = try pin.entry(a, &native_pins, .{});
    entries[5] = try ROM.firstEntry(plan, first.roots);
    entries[6] = try lookup_stage.entry();
    entries[7] = try memory_stage.entry();
    var counts: Epoch.Counts = @splat(0);
    for (entries) |entry| counts[@intFromEnum(entry.family)] += 1;
    const epoch = try Epoch.Epoch.init(try policy.digest(), config, counts, &entries, 8);
    const setup_ns = phase.lap();
    const batch_setup = stage.timings;
    const rom_roots = first.roots;
    const lookup_roots = lookup_stage.roots;
    const lookup_layout = lookup_stage.layout;
    // Independent metadata survives every producer and original proof below.
    var detached_pin = pin;
    detached_pin.windows = &windows;
    const ram_geometry = try a.alloc(@import("../block_v5_ram_lanes_protocol_v1.zig").Claim, memory_stage.witness.ram.len);
    defer a.free(ram_geometry);
    for (ram_geometry, memory_stage.witness.ram) |*out, row| out.* = row.geometry;
    const union_input = Union.Input{ .epoch = epoch, .entries = &entries, .natives = &native_pins, .batches = &.{detached_pin}, .program_plan = plan, .program_roots = rom_roots, .lookup_plan = lookup_plan, .lookup_layout = lookup_layout, .lookup_roots = lookup_roots, .memory_roots = memory_stage.roots, .memory_geometry = ram_geometry, .interval_log = memory_stage.witness.interval.log };
    const union_limits = Union.Limits{ .max_retained_pcs_bytes = 4 << 30 };
    var union_proof: ?Union.Proof = null;
    defer if (union_proof) |*p| p.deinit(a);
    if (combined) {
        var native_stages: [4]Union.NativeStage = undefined;
        for (&native_stages, &segments) |*out, *segment| out.* = .{ .allocator = a, .first = &segment.first, .owner = segment.owner, .inputs = segment.source.inputs };
        union_proof = try Union.prove(a, trusted, union_input, .{ .natives = &native_stages, .batches = &.{stage}, .program = &first, .program_allocator = a, .lookup = &lookup_stage, .memory = memory_stage }, &pool, union_limits);
    }
    const union_ns = phase.lap();
    var timings: Batch.Timings = .{};
    var proof = try Batch.ForBackend(Cpu).prove(a, stage, &native_pins, epoch, &entries, &pool, &timings);
    var proof_live = true;
    defer if (proof_live) proof.deinit(a);
    const batch_ns = phase.lap();
    var originals: [4]Native.Proof = undefined;
    var ready: usize = 0;
    defer for (originals[0..ready]) |*p| p.deinit(a);
    var native_sources: [4]@import("../block_v7_execution_receiver_v1.zig").Native = undefined;
    for (&segments, native_pins, &originals, &native_sources) |*segment, np, *p, *source| {
        p.* = try Native.For(Cpu).prove(a, &segment.first, segment.owner, segment.source.inputs, np, epoch, &entries);
        ready += 1;
        source.* = .{ .pin = np, .proof = p };
    }
    const native_ns = phase.lap();
    var rom = try ROM.ForBackend(Cpu).prove(a, &first, .{ .plan = plan, .expected_program_root = image.root, .roots = first.roots, .epoch = epoch, .entries = &entries });
    var rom_live = true;
    defer if (rom_live) rom.deinit(a);
    const rom_ns = phase.lap();
    var lookup = try lookup_stage.prove(epoch, &entries);
    var lookup_proof_live = true;
    defer if (lookup_proof_live) lookup.deinit(a);
    const lookup_ns = phase.lap();
    var memory = try memory_stage.prove(epoch, &entries);
    var memory_proof_live = true;
    defer if (memory_proof_live) memory.deinit();
    const memory_ns = phase.lap();
    if (union_proof) |*p| {
        for (originals, p.claims.native) |original, claims| {
            try std.testing.expectEqualDeep(original.claims, claims.claims);
            try std.testing.expectEqualDeep(original.memory_claims, claims.access);
        }
        try std.testing.expectEqualDeep(proof.claims, p.claims.batches[0]);
        try std.testing.expectEqualDeep(rom.claim, p.claims.program);
        try std.testing.expectEqualDeep(lookup.claims, p.claims.lookup);
        try std.testing.expectEqualDeep(memory.claims(), p.claims.memory());
    }
    // Pin window metadata is retained independently; no wide witness is needed.
    stage.deinit();
    stage_live = false;
    for (segments[0..segment_count]) |*s| s.deinit();
    segment_count = 0;
    for (runs[0..run_count]) |*r| r.deinit();
    run_count = 0;
    counters.deinit(a);
    counters_live = false;
    session.deinit();
    session_live = false;
    first.deinit(a);
    first_live = false;
    lookup_stage.deinit();
    lookup_live = false;
    memory_stage.deinit();
    memory_live = false;
    const destruction_ns = phase.lap();
    try roundTrip(a, &proof.stark, "batch");
    for (&originals) |*p| try roundTrip(a, &p.stark, "native");
    try roundTrip(a, &rom.stark, "rom");
    try roundTrip(a, &lookup.stark, "lookup");
    try roundTrip(memory.allocator, &memory.stark, "memory");
    const codec_ns = phase.lap();
    _ = try Batch.ForBackend(Cpu).verify(a, &proof, detached_pin, &native_pins, epoch, &entries, .{});
    const batch_verify_ns = phase.lap();
    const input = Receiver.Input{ .epoch = epoch, .entries = &entries, .natives = &native_sources, .batches = &.{.{ .pin = detached_pin, .proof = &proof }}, .program_plan = plan, .program_roots = rom_roots, .program = &rom, .lookup_plan = lookup_plan, .lookup_roots = lookup_roots, .lookup = .{ .layout = lookup_layout, .proof = &lookup }, .memory = &memory };
    if (swap_owners) {
        try std.testing.expectError(error.UnclosedV7ExecutionRelations, Receiver.For(Cpu).verify(a, trusted, input, .{}));
        if (union_proof) |*p| {
            proof.deinit(a);
            proof_live = false;
            for (originals[0..ready]) |*original| original.deinit(a);
            ready = 0;
            rom.deinit(a);
            rom_live = false;
            lookup.deinit(a);
            lookup_proof_live = false;
            memory.deinit();
            memory_proof_live = false;
            try roundTrip(a, &p.stark, "combined_union_owner_swap");
            // The combined STARK itself verifies first. Original per-window
            // control tuples are equal; independent RAM closure must reject.
            try std.testing.expectError(error.UnclosedV7ExecutionRelations, Union.verify(a, trusted, union_input, p, union_limits));
            std.debug.print("V7_KECCAK_UNION_OWNER_SWAP all_originals_recommitted=true union_recommitted=true originals_destroyed=true rejected_by_global_ram=true\n", .{});
        }
    } else {
        const accepted = try Receiver.For(Cpu).verify(a, trusted, input, .{});
        try std.testing.expectEqual(Guest.cycles, accepted.cycles);
        try std.testing.expectEqualSlices(u8, &Guest.output, &accepted.output);
        const old = proof.claims.memory[0].transition_sum;
        proof.claims.memory[0].transition_sum = old.add(core.fields.qm31.QM31.one());
        if (Batch.ForBackend(Cpu).verify(a, &proof, detached_pin, &native_pins, epoch, &entries, .{})) |_| return error.AcceptedPhysicalClaimForgery else |err| if (err == error.OutOfMemory) return err;
        proof.claims.memory[0].transition_sum = old;
        if (union_proof) |*p| {
            // Independent combined verification has no access to original proof
            // objects, original committed trees, rows, counters or runner state.
            proof.deinit(a);
            proof_live = false;
            for (originals[0..ready]) |*original| original.deinit(a);
            ready = 0;
            rom.deinit(a);
            rom_live = false;
            lookup.deinit(a);
            lookup_proof_live = false;
            memory.deinit();
            memory_proof_live = false;
            try roundTrip(a, &p.stark, "combined_union");
            var verify_clock = try std.time.Timer.start();
            const fresh = try Union.verify(a, trusted, union_input, p, union_limits);
            const union_verify_ns = verify_clock.read();
            try std.testing.expectEqualDeep(accepted, fresh);
            const Codec = @import("../block_v7_keccak_union_codec_v1.zig");
            const wire = try Codec.encode(a, p.view(), union_input, .{ .scope = union_limits });
            defer a.free(wire);
            try std.testing.expectEqualDeep(fresh, try @import("block_v7_keccak_union_wire_test_support.zig").check(a, wire, trusted, union_input, union_limits));
            if (std.posix.getenv("STWO_V7_KECCAK_UNION_SAVE_DIR")) |path| try @import("block_v7_keccak_union_wire_test_support.zig").save(a, path, p.view(), trusted, union_input, union_limits, fresh);

            const physical = p.claims.batches[0].memory[0].transition_sum;
            p.claims.batches[0].memory[0].transition_sum = physical.add(core.fields.qm31.QM31.one());
            if (Union.verify(a, trusted, union_input, p, union_limits)) |_| return error.AcceptedUnionPhysicalClaimForgery else |err| if (err == error.OutOfMemory) return err;
            p.claims.batches[0].memory[0].transition_sum = physical;
            var altered = trusted;
            altered.terminal.output[0] ^= 1;
            if (Union.verify(a, altered, union_input, p, union_limits)) |_| return error.AcceptedUnionWrongOutput else |err| if (err == error.OutOfMemory) return err;
            std.debug.print("V7_KECCAK_UNION canonical={} original_starks=8 combined_starks=1 exact_physical_claims=true all_producers_and_original_proofs_destroyed=true union_prove_ns={d} union_verify_ns={d} charged_peak={d}\n", .{ canonical, union_ns, union_verify_ns, budget.snapshot().peak_live_bytes });
        }
    }
    std.debug.print("V7_KECCAK_SHARED swap={} canonical={} batch_setup={any} batch_stages={any} setup_ns={d} batch_ns={d} native_ns={d} rom_ns={d} lookup_ns={d} memory_ns={d} destruction_ns={d} codec_ns={d} batch_verify_ns={d} receiver_and_negatives_ns={d} whole_ns={d} charged_peak={d}\n", .{ swap_owners, canonical, batch_setup, timings, setup_ns, batch_ns, native_ns, rom_ns, lookup_ns, memory_ns, destruction_ns, codec_ns, batch_verify_ns, phase.read(), whole.read(), budget.snapshot().peak_live_bytes });
}
test "Keccak shared original proof closes genuine native and global RAM sources" {
    try qualify(false, false);
}
test "Keccak shared fully recommitted identical-control owner swap rejects at global RAM" {
    if (std.process.hasEnvVarConstant("STWO_V7_KECCAK_CANONICAL")) return error.SkipZigTest;
    try qualify(true, false);
}

test "Keccak shared combined union matches every original claim and verifies detached" {
    try qualify(false, true);
}

test "Keccak shared combined union fully recommitted identical-control owner swap rejects" {
    if (std.process.hasEnvVarConstant("STWO_V7_KECCAK_CANONICAL")) return error.SkipZigTest;
    try qualify(true, true);
}

fn roundTrip(a: std.mem.Allocator, proof: *core.proof_suites.Blake3.Proof, name: []const u8) !void {
    const wire = @import("interop_postcard");
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    try wire.serializeProof(core.proof_suites.Blake3.Hasher, &writer.writer, proof.*);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(writer.written(), &digest, .{});
    const bytes = writer.written().len;
    var reader = std.io.fixedBufferStream(writer.written());
    const fresh = try wire.deserializeProof(core.proof_suites.Blake3.Hasher, a, reader.reader());
    proof.deinit(a);
    proof.* = fresh;
    try std.testing.expectEqual(bytes, reader.pos);
    std.debug.print("V7_KECCAK_PROOF family={s} bytes={d} sha256={s}\n", .{ name, bytes, std.fmt.bytesToHex(digest, .lower) });
}
