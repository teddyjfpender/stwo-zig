//! Fresh family11 arithmetic plus same-root family12/global-ROM closure.
//! Native retirement linkage and other VM buses remain separate obligations.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../runner/mod.zig");
const profile = @import("blake3_ethereum_sha_profile.zig");
const family = @import("block_v5_precompile_family_proof_v1.zig");
const caller = @import("block_v5_precompile_protocol_v1.zig");
const witness = @import("block_v5_precompile_witness_v1.zig");
const request = @import("block_v5_program_extension_proof_v1.zig");
const receiver = @import("block_v5_program_extension_receiver_v1.zig");
const slots_mod = @import("block_v5_program_extension_slots_v1.zig");
const table = @import("block_v5_program_table_proof_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");

test "block-v5 fresh standalone SHA Keccak roots bind program request and complete ROM" {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var scoped = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer scoped.deinit();
    const fixture = @import("../runner/guest_precompile/test_elf.zig");
    const diagnostic = fixture.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    const elf = fixture.withReleaseAbi(diagnostic.len, &diagnostic);
    var session = try runner.EthereumShaExecutionSession.init(a, &elf,
        .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
    defer session.deinit();
    var segment = try session.startSegment(16);
    defer segment.deinit();
    var owner = try witness.Witness.initSegment(a, &segment);
    defer owner.deinit();
    const tapes = &segment.extension;
    var rom = try @import("../air/program/blake3_commitment.zig").buildDeclared(a,
        @import("../air/program/commitment.zig").DeclaredDecodeAuthority{
            .profile = .rv32im_zkvm_ethereum_sha_v1 },
        .{ tapes.keccakf_execution_rows.rows(), tapes.signer_recovery_execution_rows.rows(),
            tapes.sha_calls.records() }, segment.base.rw_memory.program_words, null);
    defer rom.deinit();
    const multiplicities = try a.alloc(u64, rom.rows.len);
    defer a.free(multiplicities);
    var fetches: u64 = 0;
    for (rom.rows, multiplicities) |row, *count| {
        count.* = row.multiplicity;
        fetches = try std.math.add(u64, fetches, count.*);
    }
    try std.testing.expectEqual(@as(u64, 3), fetches);
    const plan = @import("block_v5_program_table_v1.zig").Plan{
        .program_root = rom.root, .leaves = rom.leaves, .multiplicities = multiplicities,
        .expected_fetches = fetches, .log_size = 7,
    };
    const config = core.pcs.PcsConfig{ .pow_bits = 0,
        .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const Api = family.ForBackend(Cpu);
    const RequestApi = request.ForBackend(Cpu);
    const TableApi = table.ForBackend(Cpu);
    const execution_id: [32]u8 = @splat(22);
    var first = try Api.commitFirstRound(a, &owner, owner.total_steps, config, 0, execution_id);
    defer first.deinit(a);
    const fixed_logs = try caller.columnLogs(a, &owner.statement, .fixed);
    defer a.free(fixed_logs);
    const main_logs = try caller.columnLogs(a, &owner.statement, .main);
    defer a.free(main_logs);
    const slots = try slots_mod.fromProfile(a, &owner.statement, fixed_logs, main_logs, 0, 0);
    defer a.free(slots);
    const fixed = try profile.preprocessed(a, &owner.statement);
    defer {
        for (fixed) |column| a.free(column.values);
        a.free(fixed);
    }
    var main = try profile.mainWitness(a, &owner);
    defer main.deinit(a);
    var request_first = try RequestApi.commitFirstRound(a, fixed, main.columns, slots,
        first.instance_id, execution_id, 0, config);
    defer request_first.deinit(a);
    try std.testing.expectEqualDeep(first.roots, request_first.roots);
    var table_first = try TableApi.commitFirstRound(a, plan, config);
    defer table_first.deinit(a);
    var counts: [seal.family_count]u32 = @splat(0);
    inline for ([_]seal.Family{ .program, .execution, .execution_sidecar,
        .program_request, .memory, .precompile, .program_extension_request }) |kind|
        counts[@intFromEnum(kind) - 1] = 1;
    const pins = seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2),
        .native_template_id = @splat(3), .program_root = rom.root.bytes,
        .program_plan_digest = try plan.digest(), .memory_plan_digest = @splat(6),
        .initial_source_plan_digest = @splat(7), .config = config, .counts = counts };
    const entries = [_]seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = try table.instanceId(plan), .roots = table_first.roots },
        .{ .family = .execution, .index = 0, .instance_id = execution_id, .roots = .{ @splat(13), @splat(14) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(15), .roots = .{ @splat(16), @splat(17) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(18), .roots = .{ @splat(19), @splat(20) } },
        .{ .family = .memory, .index = 0, .instance_id = @splat(23), .roots = .{ @splat(24), @splat(25) } },
        first.entry(),
        .{ .family = .program_extension_request, .index = 0,
            .instance_id = request.instanceId(first.instance_id, execution_id, 0, slots),
            .roots = request_first.roots },
    };
    const sealed = try seal.seal(pins, &entries);
    const request_proof = try RequestApi.prove(a, &request_first, fixed, main.columns,
        slots, sealed.programSeal(), first.instance_id, execution_id, 0, first.roots);
    const family_proof = try Api.prove(a, &first, sealed, pins, &entries, &pool);
    const table_proof = try TableApi.prove(a, &table_first, plan, sealed.programSeal());
    const arithmetic = try Api.verifyOwned(a, family_proof, &owner.statement,
        owner.total_steps, first.key_id, execution_id, 0, sealed, pins, &entries);
    const program = try receiver.ForBackend(Cpu).verifyOwned(a, request_proof,
        sealed, pins, &entries, arithmetic.binding, &owner.statement, owner.total_steps,
        fixed_logs, main_logs);
    const provider = try TableApi.verifyOwned(a, table_proof, plan, sealed.programSeal(),
        rom.root, table_first.roots, config);
    try std.testing.expectEqual(fetches, program.fetch_count);
    try table.closed(provider, &.{program.closureReceipt()}, sealed.programSeal());
}
