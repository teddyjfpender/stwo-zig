//! Real caller arithmetic and packed same-root memory proofs above the old
//! shard ceiling. Other global buses remain explicitly open in this fixture.
const std = @import("std");
const core = @import("stwo_core");
const runner = @import("../runner/mod.zig");
const fixture = @import("../runner/guest_precompile/test_elf.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Witness = @import("block_v5_precompile_witness_v1.zig");
const trace = @import("../air/guest_precompile/keccakf_trace.zig");

test "block-v5 caller real Keccak census crosses legacy4518 profile ceiling" {
    const a = std.testing.allocator;
    const count = trace.maximum_calls_per_shard + 1;
    const words = [_]u32{ 0x001002b7, 0x10028293, 0x08028313 } ++
        [_]u32{@import("../isa/custom0.zig").encodeKeccakf(5)} ** count ++
        [_]u32{ 0x00100137, 0x00100193, 0x00312223, 0x00312423, 0x00312023, 0x0000006f };
    const elf = comptime blk: {
        @setEvalBranchQuota(1_000_000);
        break :blk fixture.buildReleaseProgram(words.len, &words, 256, .rv32im_zkvm_ethereum_sha_v1);
    };
    var session = try runner.EthereumShaExecutionSession.init(a, &elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
    defer session.deinit();
    var segment = try session.startSegment(words.len);
    defer segment.deinit();
    try std.testing.expectEqual(count, segment.extension.keccakf_calls.records().len);
    const tapes = &segment.extension;
    const steps: u32 = @intCast(segment.base.cycle_count);
    try std.testing.expectError(error.CallRangeTooLarge, @import("guest_precompile/ethereum_witness.zig").Witness.init(a, tapes.keccakf_calls.records(), tapes.keccakf_execution_rows.rows(), tapes.signer_recovery_calls.records(), tapes.signer_recovery_execution_rows.rows(), steps));
    var witness = try Witness.Witness.initSegment(a, &segment);
    defer witness.deinit();
    try std.testing.expectEqual(@as(u32, @intCast(count)), witness.statement.ethereum.counts.keccak_calls);
    try std.testing.expectEqual(@as(u32, 17), witness.extension.keccak_shard.log_size);
    try std.testing.expectEqual(@as(u32, 17), witness.statement.ethereum.components[0].log_size);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    try Protocol.validate(&witness.statement, steps, config);
    try Witness.validateAdmission(a, &witness.statement);
    const demand = try @import("block_v5_precompile_table_demand_v1.zig").fromStatement(a, &witness.statement, steps, config);
    const fixed = try Protocol.columnLogs(a, &witness.statement, .fixed);
    defer a.free(fixed);
    const main = try Protocol.columnLogs(a, &witness.statement, .main);
    defer a.free(main);
    const slots = try @import("block_execution_external_trace_v2.zig").descriptorsFromStatement(a, &witness.statement, fixed, main, .{ .clock_frame = segment.base.clock_frame, .global_first_cycle = segment.base.global_first_cycle, .cycle_count = steps });
    defer a.free(slots);
    const bytes = try @import("block_v5_memory_byte_demand_v1.zig").externalDemand(&witness.statement, slots);
    try std.testing.expectEqual(@as(u64, count * 51), bytes.event_count);
    try std.testing.expectEqual(@as(u64, count * 51 * 14), bytes.request_count);
    try std.testing.expectEqual(@as(usize, 51), slots.len);
    for (slots) |slot| try std.testing.expectEqual(@as(u32, 17), slot.log_size);
    try std.testing.expectError(error.InvalidComponentGeometry, @import("../air/guest_precompile/ethereum_statement.zig").Statement.canonicalWithAdmission(@intCast(count), 0, witness.extension.shapes(), witness.statement.ethereum.admission));
    var changed = witness.statement;
    changed.ethereum.components[0].log_size = 16;
    try std.testing.expectError(error.InvalidComponentGeometry, Witness.validateAdmission(a, &changed));
    const key = try Protocol.keyId(&witness.statement, steps, config, @splat(45));
    try std.testing.expect(!std.meta.eql(key, try legacyKey(&witness.statement, steps, config, @splat(45))));
    try exerciseProofs(a, &witness, .{ .clock_frame = segment.base.clock_frame, .global_first_cycle = segment.base.global_first_cycle, .cycle_count = steps }, config);
    std.debug.print("BLOCK_V5_CALLER_LARGE_PROFILE keccak_calls={d} log_size=17 profile=ethereum_v5 protocol_version=2 memory_events={d} byte_requests={d} table_range20_bound={d} legacy_rejected=true complete=false\n", .{ count, bytes.event_count, bytes.request_count, demand[@intFromEnum(@import("../air/lookups/tables/schema.zig").Kind.range_check_20)] });
}

fn exerciseProofs(a: std.mem.Allocator, witness: *const Witness.Witness, frame: @import("../air/block/memory_event.zig").Frame, config: core.pcs.PcsConfig) !void {
    const engine = @import("stwo_prover_engine");
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const Family = @import("block_v5_precompile_family_proof_v1.zig");
    const External = @import("block_v5_external_memory_sidecar_proof_v1.zig");
    const Seal = @import("block_v5_source_seal_v1.zig");
    const Api = Family.ForBackend(Cpu);
    const Memory = External.ForPackedBackend(Cpu);
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var scoped = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer scoped.deinit();
    var physical = try Api.commitPhysicalFirstRound(a, witness, witness.total_steps, config);
    defer physical.deinit(a);
    var counter = try @import("../air/lookups/tables/counter.zig").Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    var memory = try @import("block_v5_caller_external_stage_v1.zig").ForBackend(Cpu).Prepared.init(a, &physical, &witness.statement, frame, 0, &counter);
    defer memory.deinit(a);
    const execution_id: [32]u8 = @splat(22);
    var first = try physical.bind(0, execution_id);
    defer first.deinit(a);
    const record = @import("block_v5_precompile_batch_v1.zig").Record{ .execution = .{ .index = 0, .instance_id = execution_id }, .total_steps = witness.total_steps, .statement = witness.statement, .key_id = first.key_id, .instance_id = first.instance_id, .roots = first.roots };
    const witness_root = memory.first.roots[2];
    var counts: [Seal.family_count]u32 = @splat(0);
    inline for ([_]Seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory, .precompile, .program_extension_request, .execution_external_sidecar }) |kind| counts[@intFromEnum(kind) - 1] = 1;
    const pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = @splat(6), .initial_source_plan_digest = @splat(7), .config = config, .counts = counts };
    // Only family11/13 are freshly proved here. Other entries explicitly scope
    // the common challenge transcript, and confer no native/global authority.
    const entries = [_]Seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        .{ .family = .execution, .index = 0, .instance_id = execution_id, .roots = .{ @splat(13), @splat(14) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(15), .roots = .{ @splat(16), @splat(17) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(18), .roots = .{ @splat(19), @splat(20) } },
        .{ .family = .memory, .index = 0, .instance_id = @splat(23), .roots = .{ @splat(24), @splat(25) } },
        first.entry(),
        try @import("block_v5_program_extension_stage_v1.zig").firstRoundEntry(a, &record, config),
        External.packedEntry(execution_id, first.instance_id, first.key_id, first.roots, witness_root, 0, memory.slots),
    };
    const sealed = try Seal.seal(pins, &entries);
    const binding = first.binding(sealed);
    var external_proof = try Memory.prove(a, &memory.first, memory.inputs, memory.slots, sealed, pins, &entries, &binding, 0, witness_root);
    var external_owned = true;
    defer if (external_owned) external_proof.deinit(a);
    var arithmetic = try Api.prove(a, &first, sealed, pins, &entries, &pool);
    defer arithmetic.deinit(a);
    const Codec = @import("block_v5_precompile_codec_v1.zig");
    const raw = try Codec.encode(a, &arithmetic, &record.statement, .{});
    defer a.free(raw);
    const legacy = try legacyKey(&record.statement, record.total_steps, config, record.roots[0]);
    try std.testing.expectError(error.UntrustedBlockV5PrecompileKey, Api.verifyOwned(a, try Codec.decode(a, raw, &record.statement, config, .{}), &record.statement, record.total_steps, legacy, execution_id, 0, sealed, pins, &entries));
    const fresh = try Api.verifyOwned(a, try Codec.decode(a, raw, &record.statement, config, .{}), &record.statement, record.total_steps, record.key_id, execution_id, 0, sealed, pins, &entries);
    const fixed_logs = try Protocol.columnLogs(a, &record.statement, .fixed);
    defer a.free(fixed_logs);
    const main_logs = try Protocol.columnLogs(a, &record.statement, .main);
    defer a.free(main_logs);
    external_owned = false;
    var receipt = try Memory.verifyOwned(a, external_proof, sealed, pins, &entries, &fresh.binding, 0, memory.slots, fixed_logs, main_logs, witness_root, config);
    defer receipt.deinit(a);
    try std.testing.expectEqual(memory.byte_demand.event_count, receipt.event_count);
    _ = try @import("block_v5_memory_byte_demand_v1.zig").freshRequests(receipt, memory.byte_demand, sealed.digest);
    std.debug.print("BLOCK_V5_CALLER_LARGE_PROOFS arithmetic_fresh=true packed_memory_fresh=true shared_roots=true codec_roundtrip=true legacy_key_rejected=true arithmetic_wire_bytes={d} memory_events={d} complete=false\n", .{ raw.len, receipt.event_count });
}

fn legacyKey(statement: *const Profile.admission.Statement, steps: u32, config: core.pcs.PcsConfig, fixed_root: [32]u8) ![32]u8 {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ Protocol.TAG, 1, steps, @intFromEnum(Profile.execution_profile) });
    config.mixInto(&channel);
    channel.mixRoot(@import("../air/lang/relation.zig").registryOrderDigest());
    statement.ethereum.mixValidatedInto(&channel);
    try statement.sha.mixInto(&channel);
    channel.mixRoot(fixed_root);
    return channel.digestBytes();
}
