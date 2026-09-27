const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../runner/mod.zig");
const profile = @import("blake3_ethereum_sha_profile.zig");
const family = @import("block_v5_precompile_family_proof_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const Batch = @import("block_v5_precompile_batch_v1.zig");
const Lookup = @import("block_v5_precompile_lookup_proof_v1.zig");
const Stage = @import("block_v5_precompile_lookup_stage_v1.zig").ForBackend(Cpu);
const Witness = @import("block_v5_precompile_witness_v1.zig").Witness;
const Program = @import("block_v5_program_extension_proof_v1.zig");
const ProgramStage = @import("block_v5_program_extension_stage_v1.zig");
const State = @import("block_v5_precompile_state_request_proof_v1.zig");
const Pipeline = @import("block_v5_caller_pipeline_v1.zig");
const External = @import("block_v5_external_memory_sidecar_proof_v1.zig");

test "block-v5 caller shared-table projection freshly verifies SHA and Keccak" {
    const fixture = @import("../runner/guest_precompile/test_elf.zig");
    const diagnostic = fixture.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    const elf = fixture.withReleaseAbi(diagnostic.len, &diagnostic);
    try exercise(&elf);
}
test "block-v5 caller shared-table projection freshly verifies active signer and Keccak" {
    const fixture = @import("../runner/guest_precompile/test_elf.zig");
    const diagnostic = fixture.buildEthereumWithCompletionForProfile(.ecall, .rv32im_zkvm_ethereum_sha_v1);
    const elf = fixture.withReleaseAbi(diagnostic.len, &diagnostic);
    try exercise(&elf);
}
fn exercise(elf: []const u8) !void {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var scoped = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer scoped.deinit();
    var session = try runner.EthereumShaExecutionSession.init(a, elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
    defer session.deinit();
    var segment = try session.startSegment(16);
    defer segment.deinit();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const Api = family.ForBackend(Cpu);
    const execution_id: [32]u8 = @splat(22);
    var transport = Transport{ .a = a, .segment = &segment };
    defer transport.deinit();
    var collected_counters = try @import("../air/lookups/tables/counter.zig").Set.init(a);
    defer collected_counters.deinit(a);
    const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = segment.base.clock_frame, .global_first_cycle = segment.base.global_first_cycle, .cycle_count = @intCast(segment.base.cycle_count) };
    var proposal = Pipeline.ForBackend(Cpu).collectSegment(a, &segment, 0, frame, config, .{ .max_metadata_bytes = 65536, .max_external_slots = 128 }, &collected_counters) catch |err| {
        std.debug.print("caller collect: {s}\n", .{@errorName(err)});
        return err;
    };
    defer proposal.deinit();
    const bound = try proposal.lateBind(a, execution_id);
    var changed_bound = bound;
    changed_bound.record.roots[1][0] ^= 1;
    try std.testing.expectError(error.ChangedV5BoundCaller, changed_bound.require(a));
    var changed_proposal = proposal;
    changed_proposal.key_id[0] ^= 1;
    try std.testing.expectError(error.ChangedV5PhysicalCallerProposal, changed_proposal.lateBind(a, execution_id));
    const alternative = try proposal.lateBind(a, @splat(33));
    try std.testing.expect(!std.meta.eql(bound.family11.instance_id, alternative.family11.instance_id));
    try std.testing.expect(!std.meta.eql(bound.family12.instance_id, alternative.family12.instance_id));
    try std.testing.expect(!std.meta.eql(bound.family13.instance_id, alternative.family13.instance_id));
    const record = bound.record;
    try std.testing.expectEqual(try @import("block_execution_external_trace_v2.zig").expectedEventCount(&record.statement), record.statement.ethereum.admission.memory_relation_terms);
    var counts: [seal.family_count]u32 = @splat(0);
    inline for ([_]seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory, .precompile }) |kind| counts[@intFromEnum(kind) - 1] = 1;
    counts[@intFromEnum(seal.Family.program_extension_request) - 1] = 1;
    counts[@intFromEnum(seal.Family.execution_external_sidecar) - 1] = 1;
    const pins = seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = @splat(6), .initial_source_plan_digest = @splat(7), .config = config, .counts = counts };
    const entries = [_]seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        .{ .family = .execution, .index = 0, .instance_id = execution_id, .roots = .{ @splat(13), @splat(14) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(15), .roots = .{ @splat(16), @splat(17) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(18), .roots = .{ @splat(19), @splat(20) } },
        .{ .family = .memory, .index = 0, .instance_id = @splat(23), .roots = .{ @splat(24), @splat(25) } },
        bound.family11,
        bound.family12,
        bound.family13,
    };
    const sealed = try seal.seal(pins, &entries);
    const StateApi = Lookup.ForBackend(Cpu);
    var wrong_record = record;
    wrong_record.key_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5WarmProgramRecord, ProgramStage.firstRoundEntry(a, &wrong_record, config));
    Pipeline.ForBackend(Cpu).proveSegment(a, &segment, &bound, sealed, pins, &entries, &pool, .{ .context = &transport, .put_caller = Transport.putFamily, .put_program = Transport.putProgram, .put_state = Transport.putState, .put_tables = Transport.putTables, .put_memory = Transport.putMemory }, .{ .context = &transport, .on_caller_proof = Transport.onCallerProof }) catch |err| {
        std.debug.print("caller prove: {s}\n", .{@errorName(err)});
        return err;
    };
    try std.testing.expectEqual(@as(u32, 1), transport.proof_callbacks);
    var state_proof = transport.tables orelse return error.MissingCallerTables;
    transport.tables = null;
    var state_owned = true;
    defer if (state_owned) state_proof.deinit(a);
    const caller_proof = transport.arithmetic orelse return error.MissingCallerArithmetic;
    transport.arithmetic = null;
    const fresh = try Api.verifyOwned(a, caller_proof, &record.statement, record.total_steps, record.key_id, execution_id, 0, sealed, pins, &entries);
    try verifyMemory(a, &transport, &bound, &fresh, sealed, pins, &entries);
    const caller_state = transport.state orelse return error.MissingWarmCallerState;
    transport.state = null;
    const fresh_state = try State.ForBackend(Cpu).verifyOwned(a, caller_state, sealed, pins, &entries, &fresh, &record.statement, record.total_steps);
    try std.testing.expectEqual(@as(u64, profile.externalCount(&record.statement)), fresh_state.caller_count);
    const program_proof = transport.program orelse return error.MissingWarmCallerProgram;
    transport.program = null;
    const program_receipt = try verifyProgram(a, program_proof, record, fresh, sealed, config);
    try std.testing.expectEqual(@as(u64, profile.externalCount(&record.statement)), program_receipt.fetch_count);
    var changed = try cloneState(a, state_proof);
    changed.claims[0].sum = changed.claims[0].sum.add(core.fields.qm31.QM31.one());
    if (StateApi.verifyOwned(a, changed, sealed, pins, &entries, &fresh, &record.statement, record.total_steps)) |_|
        return error.AcceptedChangedCallerTableClaim
    else |_| {}
    var changed_binding = fresh;
    changed_binding.binding.first_roots[1][0] ^= 1;
    try std.testing.expectError(error.UntrustedBlockV5PrecompileInstance, StateApi.verifyOwned(a, try cloneState(a, state_proof), sealed, pins, &entries, &changed_binding, &record.statement, record.total_steps));
    state_owned = false;
    const receipt = try StateApi.verifyOwned(a, state_proof, sealed, pins, &entries, &fresh, &record.statement, record.total_steps);
    try std.testing.expectEqual(try @import("block_execution_external_trace_v2.zig").expectedEventCount(&record.statement), receipt.memory_event_count);
    try std.testing.expect(receipt.auxiliary_clock_memory_sum.isZero());
    var witness = try Witness.initSegment(a, &segment);
    defer witness.deinit();
    const bounds = try @import("block_v5_precompile_table_demand_v1.zig").fromStatement(a, &record.statement, record.total_steps, config);
    var changed_statement = record.statement;
    changed_statement.ethereum.admission.extended_fixed_table_bounds[0] += 1;
    try std.testing.expectError(error.InvalidBlockV5StandaloneAdmission, @import("block_v5_precompile_table_demand_v1.zig").fromStatement(a, &changed_statement, record.total_steps, config));
    const tables = @import("../air/lookups/tables/mod.zig");
    var counters = try tables.counter.Set.init(a);
    defer counters.deinit(a);
    try (@import("../air/guest_precompile/ethereum_lookup_registration.zig").Context{
        .keccak = segment.extension.keccakf_calls.records(),
        .recovery = segment.extension.signer_recovery_calls.records(),
    }).register(&counters);
    try @import("../air/guest_precompile/sha256_lookup_registration.zig").register(a, &witness.sha_rows, &counters);
    var channel = sealed.sharedChannel();
    const relations = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    for (counters.counters, receipt.claims, bounds) |counter, actual, max_requests| {
        var expected = core.fields.qm31.QM31.zero();
        var mass: u64 = 0;
        for (counter.values, 0..) |weight, row| {
            if (weight.isZero()) continue;
            const tuple = try tables.schema.tupleAt(counter.kind, row);
            const denominator = try relations.get(switch (counter.kind) {
                .bitwise => .bitwise,
                .range_check_20 => .range_check_20,
                .range_check_8_11 => .range_check_8_11,
                .range_check_8_8_4 => .range_check_8_8_4,
                .range_check_8_8 => .range_check_8_8,
                .range_check_m31 => .range_check_m31,
            }).combineBase(tuple.slice());
            expected = expected.add((try denominator.inv()).mulM31(weight));
            const canonical = weight.toU32();
            mass += @min(canonical, core.fields.m31.Modulus - canonical);
        }
        try std.testing.expect(mass <= max_requests);
        try std.testing.expectEqualDeep(expected, actual);
    }
    std.debug.print("BLOCK_V5_CALLER_TABLES live_segment=true late_binding=true physical_commit=true memory_borrowed=true family12_borrowed=true selected_columns=true state_borrowed=true authentic_six_partitions=true sha={d} keccak={d} signer={d} memory_events={d} auxiliary_clock=0 complete=false\n", .{ record.statement.sha.call_count, record.statement.ethereum.counts.keccak_calls, record.statement.ethereum.counts.signer_calls, receipt.memory_event_count });
}

fn verifyMemory(a: std.mem.Allocator, transport: *Transport, bound: *const Pipeline.Bound, fresh: *const family.OpenReceipt, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !void {
    var proof = transport.memory orelse return error.MissingWarmCallerMemory;
    transport.memory = null;
    var owned = true;
    defer if (owned) proof.deinit(a);
    const protocol = @import("block_v5_precompile_protocol_v1.zig");
    const fixed_logs = try protocol.columnLogs(a, &bound.record.statement, .fixed);
    defer a.free(fixed_logs);
    const main_logs = try protocol.columnLogs(a, &bound.record.statement, .main);
    defer a.free(main_logs);
    const slots = try @import("block_execution_external_trace_v2.zig").descriptorsFromStatement(a, &bound.record.statement, fixed_logs, main_logs, bound.proposal.frame);
    defer a.free(slots);
    var changed = try cloneProjection(External.Proof, a, proof);
    changed.claims[0].universal_sum = changed.claims[0].universal_sum.add(core.fields.qm31.QM31.one());
    if (External.ForPackedBackend(Cpu).verifyOwned(a, changed, sealed, pins, entries, &fresh.binding, bound.record.execution.index, slots, fixed_logs, main_logs, bound.proposal.witness_root, pins.config)) |receipt| {
        var unexpected = receipt;
        unexpected.deinit(a);
        return error.AcceptedChangedWarmCallerMemory;
    } else |_| {}
    owned = false;
    var receipt = try External.ForPackedBackend(Cpu).verifyOwned(a, proof, sealed, pins, entries, &fresh.binding, bound.record.execution.index, slots, fixed_logs, main_logs, bound.proposal.witness_root, pins.config);
    defer receipt.deinit(a);
    try std.testing.expectEqual(bound.proposal.byte_demand.event_count, receipt.event_count);
    _ = try @import("block_v5_memory_byte_demand_v1.zig").freshRequests(receipt, bound.proposal.byte_demand, sealed.digest);
}

fn verifyProgram(a: std.mem.Allocator, proof: Program.Proof, record: Batch.Record, fresh: family.OpenReceipt, sealed: seal.Sealed, config: core.pcs.PcsConfig) !Program.VerifiedReceipt {
    var owned = proof;
    var retain = true;
    defer if (retain) owned.deinit(a);
    const protocol = @import("block_v5_precompile_protocol_v1.zig");
    const fixed_logs = try protocol.columnLogs(a, &record.statement, .fixed);
    defer a.free(fixed_logs);
    const main_logs = try protocol.columnLogs(a, &record.statement, .main);
    defer a.free(main_logs);
    const slots = try @import("block_v5_program_extension_slots_v1.zig").fromProfile(a, &record.statement, fixed_logs, main_logs, 0, 0);
    defer a.free(slots);
    var changed = try cloneProgram(a, proof);
    changed.claims[0].sum = changed.claims[0].sum.add(core.fields.qm31.QM31.one());
    if (Program.ForBackend(Cpu).verifyOwned(a, changed, sealed.programSeal(), record.execution.index, record.instance_id, record.execution.instance_id, slots, fixed_logs, main_logs, fresh.binding.first_roots, record.roots, config)) |_|
        return error.AcceptedChangedWarmCallerProgramClaim
    else |_| {}
    var foreign_roots = fresh.binding.first_roots;
    foreign_roots[1][0] ^= 1;
    try std.testing.expectError(error.InvalidProgramRequestProof, Program.ForBackend(Cpu).verifyOwned(a, try cloneProgram(a, proof), sealed.programSeal(), record.execution.index, record.instance_id, record.execution.instance_id, slots, fixed_logs, main_logs, foreign_roots, record.roots, config));
    retain = false;
    return Program.ForBackend(Cpu).verifyOwned(a, owned, sealed.programSeal(), record.execution.index, record.instance_id, record.execution.instance_id, slots, fixed_logs, main_logs, fresh.binding.first_roots, record.roots, config);
}
fn cloneProgram(a: std.mem.Allocator, proof: Program.Proof) !Program.Proof {
    return cloneProjection(Program.Proof, a, proof);
}

fn cloneState(a: std.mem.Allocator, proof: @import("block_v5_precompile_lookup_proof_v1.zig").Proof) !@import("block_v5_precompile_lookup_proof_v1.zig").Proof {
    return cloneProjection(Lookup.Proof, a, proof);
}
fn cloneProjection(comptime Proof: type, a: std.mem.Allocator, proof: Proof) !Proof {
    const postcard = @import("interop_postcard");
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    try postcard.serializeProof(core.proof_suites.Blake3.Hasher, &writer.writer, proof.stark);
    var stream = std.io.fixedBufferStream(writer.written());
    var stark = try postcard.deserializeProof(core.proof_suites.Blake3.Hasher, a, stream.reader());
    errdefer stark.deinit(a);
    return .{ .stark = stark, .claims = try a.dupe(@typeInfo(@TypeOf(proof.claims)).pointer.child, proof.claims) };
}

const Transport = struct {
    a: std.mem.Allocator,
    segment: *const runner.EthereumShaSegmentResult,
    proof_callbacks: u32 = 0,
    tables: ?Lookup.Proof = null,
    arithmetic: ?family.Proof = null,
    program: ?Program.Proof = null,
    state: ?State.Proof = null,
    memory: ?External.Proof = null,
    fn deinit(self: *Transport) void {
        if (self.tables) |*proof| proof.deinit(self.a);
        if (self.arithmetic) |*proof| proof.deinit(self.a);
        if (self.program) |*proof| proof.deinit(self.a);
        if (self.state) |*proof| proof.deinit(self.a);
        if (self.memory) |*proof| proof.deinit(self.a);
    }
    fn putTables(raw: *anyopaque, index: u32, proof: *Lookup.Proof) !void {
        const self: *Transport = @ptrCast(@alignCast(raw));
        if (index != 0 or self.tables != null) return error.DuplicateCallerTables;
        self.tables = proof.*;
        proof.* = undefined;
    }
    fn putFamily(raw: *anyopaque, index: u32, proof: *family.Proof) !void {
        const self: *Transport = @ptrCast(@alignCast(raw));
        if (index != 0 or self.arithmetic != null) return error.DuplicateCallerArithmetic;
        self.arithmetic = proof.*;
        proof.* = undefined;
    }
    fn onCallerProof(raw: *anyopaque, a: std.mem.Allocator, warm: Batch.ForBackend(Cpu).WarmCaller, proof: *const family.Proof) !void {
        _ = a;
        const self: *Transport = @ptrCast(@alignCast(raw));
        const roots = proof.stark.commitment_scheme_proof.commitments.items;
        try std.testing.expect(std.meta.eql(roots[0..2].*, warm.record.roots));
        self.proof_callbacks += 1;
    }
    fn putProgram(raw: *anyopaque, index: u32, proof: *Program.Proof) !void {
        const self: *Transport = @ptrCast(@alignCast(raw));
        if (index != 0 or self.program != null) return error.DuplicateCallerProgram;
        self.program = proof.*;
        proof.* = undefined;
    }
    fn putState(raw: *anyopaque, index: u32, proof: *State.Proof) !void {
        const self: *Transport = @ptrCast(@alignCast(raw));
        if (index != 0 or self.state != null) return error.DuplicateCallerState;
        self.state = proof.*;
        proof.* = undefined;
    }
    fn putMemory(raw: *anyopaque, index: u32, proof: *External.Proof) !void {
        const self: *Transport = @ptrCast(@alignCast(raw));
        if (index != 0 or self.memory != null) return error.DuplicateCallerMemory;
        self.memory = proof.*;
        proof.* = undefined;
    }
};
