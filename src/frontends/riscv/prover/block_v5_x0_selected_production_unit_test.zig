//! Real caller first-round commitments, staged replay and scalar window
//! equations only. No guest execution, segment, STARK, driver or device runs.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Q = core.fields.qm31.QM31;
const RecipeModule = @import("block_v5_execution_recipe_v1.zig");
const recipe = RecipeModule.canonical;
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const WitnessModule = @import("block_v5_precompile_witness_v1.zig");
const Family = @import("block_v5_precompile_family_proof_v1.zig").ForBackend(Cpu);
const Stage = @import("block_v5_caller_columns_stage_v1.zig");

test "block-v5 selected production recipe rejects native caller window and source relabeling" {
    const a = std.testing.allocator;
    try std.testing.expectEqual(@as(u32, @field(@import("root"), "BLOCK_V5_EXECUTION_RECIPE")), @intFromEnum(recipe));
    try std.testing.expectEqual(recipe.callerProfile(), Protocol.circuit_profile);
    try std.testing.expectEqual(recipe.callerProtocolVersion(), Protocol.VERSION);
    const wrong: RecipeModule.Recipe = if (recipe == .local_zero_v1) .custody_v2 else .local_zero_v1;
    try std.testing.expectError(error.UnsupportedV5ExecutableRecipe, wrong.requireCompiled());
    try std.testing.expectError(error.MixedV5ExecutionRecipe, recipe.requireWindowVersion(wrong.windowVersion()));
    var shape: @import("../air/statement.zig").Blake3ExecutionStatement = undefined;
    shape.x0_local_custody_version = wrong.nativeVersion();
    // Exact recipe mismatch is rejected before unrelated shape fields are read.
    try std.testing.expectError(error.MixedV5ExecutionRecipe, recipe.requireNative(&shape));
    const zero = RecipeModule.Recipe.local_zero_v1;
    try std.testing.expectError(error.UntrustedV5ExecutionRecipeMode, zero.requireMode(0));
    var extension = try @import("guest_precompile/ethereum_witness.zig").Witness.initWithCircuitProfileV1(a, &.{}, &.{}, &.{}, &.{}, 0, recipe.callerProfile());
    defer extension.deinit();
    const statement = try WitnessModule.canonicalStatement(a, 0, 0, 0, extension.shapes());
    try recipe.requireCaller(&statement, 0);
    try std.testing.expectError(error.StatementVersionMismatch, wrong.requireCaller(&statement, 0));
    var first = core.proof_suites.Blake3.Channel{};
    var second = first;
    RecipeModule.Recipe.custody_v2.mixNewSourceIdentity(&first);
    RecipeModule.Recipe.local_zero_v1.mixNewSourceIdentity(&second);
    try std.testing.expect(!std.meta.eql(first.digestBytes(), second.digestBytes()));
    const Runner = @import("block_v4_cpu_runner_source.zig");
    var source: Runner.Source = undefined;
    source.execution_recipe = wrong;
    const policy = @import("block_v5_cpu_driver_admission_v1.zig").InputPolicy{
        .runner_pins = .{ .execution_recipe = recipe, .elf_sha256 = @splat(0), .input_sha256 = @splat(0), .oracle_sha256 = @splat(0), .initial_rw_root = .{ .bytes = @splat(0) }, .program_root = .{ .bytes = @splat(0) } },
        .job_id = @splat(1),
        .expected_final_rw_root = @splat(2),
    };
    try std.testing.expectError(error.MixedV5ExecutionRecipe, policy.requireSource(&source, .{ .max_executions = 1, .max_rom_words = 1, .max_metadata_bytes = 1024, .max_source_bytes = 1024, .lookup_request_limit = 1024 }));
}

test "block-v5 selected production mixed caller real roots staged warm leases and register window agree" {
    const a = std.testing.allocator;
    const ShaRecord = @import("../air/guest_precompile/sha256_memory_record.zig").Record;
    const sha_call = ShaRecord{ .execution_clock = 1, .pc = 0, .state_register = 0, .block_register = 1, .state_ptr = 0, .block_ptr = 128, .pointer_previous_clocks = .{ 0, 0 }, .memory_previous_clocks = @splat(0), .state = @splat(0), .block = @splat(0), .output = @import("../air/guest_precompile/sha256_compression.zig").compress(@splat(0), @splat(0)) };
    try sha_call.validate();
    const sha_entries = [_]@import("../runner/guest_precompile/sha256_compression_v1.zig").Entry{.{ .call = sha_call, .instruction = sha_call.instruction() }};
    const Buffer = @import("../runner/guest_precompile/keccakf_call_buffer.zig");
    const KTrace = @import("../air/guest_precompile/keccakf_trace.zig");
    var input: [Buffer.word_count]u32 = @splat(0);
    @memcpy(input[0..8], &sha_call.output);
    var state = KTrace.stateFromWords(input);
    @import("../air/guest_precompile/keccakf_authority.zig").permute(&state);
    var output: [Buffer.word_count]u32 = undefined;
    for (state, 0..) |lane, i| {
        output[2 * i] = @truncate(lane);
        output[2 * i + 1] = @truncate(lane >> 32);
    }
    var previous: [Buffer.word_count]u32 = @splat(0);
    @memset(previous[0..8], @import("../access_clock.zig").encode(1, .second));
    const call = Buffer.Record{ .execution_clock = 2, .pc = 4, .state_ptr = 0, .pointer_register = 0, .pointer_previous_clock = if (recipe == .local_zero_v1) 0 else @import("../access_clock.zig").encode(1, .first), .input = input, .output = output, .memory_previous_clocks = previous };
    const fetch = @import("../runner/guest_precompile/keccakf_v1.zig").ExecutionRow{ .execution_clock = 2, .pc = 4, .inst_word = @import("../isa/custom0.zig").encodeKeccakf(0), .call_index = 0 };
    var witness = blk: {
        var extension = try @import("guest_precompile/ethereum_witness.zig").Witness.initWithCircuitProfileV1(a, &.{call}, &.{fetch}, &.{}, &.{}, 2, recipe.callerProfile());
        errdefer extension.deinit();
        var sha = try @import("../air/guest_precompile/sha256_memory_rows.zig").prepareForRecipe(recipe == .local_zero_v1, a, &sha_entries, 2);
        errdefer sha.deinit();
        const statement = try WitnessModule.canonicalStatement(a, 1, 0, 1, extension.shapes());
        break :blk WitnessModule.Witness{ .extension = extension, .sha_rows = sha, .statement = statement, .total_steps = 2 };
    };
    defer witness.deinit();
    try WitnessModule.validateAdmission(a, &witness.statement);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var first = try Family.commitPhysicalFirstRound(a, &witness, 2, config);
    defer first.deinit(a);
    const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 2 };
    const descriptor = Stage.Descriptor{ .statement = witness.statement, .total_steps = 2, .index = 0, .frame = frame, .config = config, .key_id = first.key_id, .roots = first.roots };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const pin = try Stage.write(a, tmp.dir, "caller.columns", &witness, &descriptor, .{});
    var restored = try Stage.ForBackend(Cpu).load(a, tmp.dir, "caller.columns", &descriptor, pin, .{});
    defer restored.deinit(a);
    try std.testing.expectEqualDeep(first.roots, restored.first.roots);
    try std.testing.expectEqualDeep(first.key_id, restored.first.key_id);
    const Counter = @import("../air/lookups/tables/counter.zig");
    var original = try Counter.Set.init(a);
    defer original.deinit(a);
    try Stage.registerCounters(a, &witness, &original);
    for (original.counters, restored.owner.counters.counters) |expected, found| try std.testing.expectEqualSlices(core.fields.m31.M31, expected.values, found.values);
    var byte_counter = try Counter.Counter.init(a, .range_check_8_8);
    defer byte_counter.deinit(a);
    var warm = try @import("block_v5_caller_external_stage_v1.zig").ForBackend(Cpu).Prepared.initForMode(a, &restored.first, &witness.statement, frame, 0, &byte_counter, 1);
    defer warm.deinit(a);
    try std.testing.expectEqualDeep(first.roots, warm.first.roots[0..2].*);
    try std.testing.expectEqual(@as(u64, 74), warm.byte_demand.event_count);
    try std.testing.expectEqual(@as(u64, 14 * 74), warm.byte_demand.request_count);
    var roots = try restored.first.scheme.roots(a);
    defer roots.deinit(a);
    try std.testing.expectEqualDeep(first.roots, roots.items[0..2].*);
    const main = try Profile.mainWitness(a, &witness);
    var owned_main = main;
    defer owned_main.deinit(a);
    const fixed = try Profile.preprocessed(a, &witness.statement);
    defer {
        for (fixed) |column| a.free(column.values);
        a.free(fixed);
    }
    var channel = core.proof_suites.Blake3.Channel{};
    const vm = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    const relations = try Profile.Relations.drawAfterVm(a, &channel, vm);
    const Source = @import("block_v5_precompile_lookup_source_v1.zig");
    const owner = try Source.Owner.init(a);
    defer owner.destroy(a);
    const slots = try owner.slotsForMode(a, &witness.statement, 1);
    defer a.free(slots);
    var register_sum = Q.zero();
    for (slots) |slot| if (slot.table == .register_memory) {
        for (0..@as(usize, 1) << @intCast(slot.log_size)) |logical| {
            const physical = @import("../recursion/air/framework_interaction.zig").committedRow(logical, slot.log_size);
            var row: [Source.MAX_MAIN]Q = undefined;
            var pp: [Source.MAX_FIXED]Q = undefined;
            for (row[0..slot.width], main.columns[slot.main_offset..][0..slot.width]) |*value, column| value.* = Q.fromBase(column.values[physical]);
            for (pp[0..slot.fixed_width], fixed[slot.fixed_offset..][0..slot.fixed_width]) |*value, column| value.* = Q.fromBase(column.values[physical]);
            const pair = try owner.pair(slot, pp[0..slot.fixed_width], row[0..slot.width], &relations);
            register_sum = register_sum.add(try pair.n1.div(pair.d1)).add(try pair.n2.div(pair.d2));
        }
    };
    const Windows = @import("block_v5_register_windows_v1.zig");
    var registers: [32]u32 = @splat(0);
    registers[1] = 128;
    var clocks: [32]u32 = @splat(0);
    clocks[1] = @import("../access_clock.zig").encode(1, .first);
    if (recipe == .custody_v2) clocks[0] = @import("../access_clock.zig").encode(2, .first);
    const windows = [_]Windows.Window{.{ .index = 0, .first_cycle = 1, .cycle_count = 2, .initial_registers = registers, .final_registers = registers, .final_clocks = clocks }};
    const plan = Windows.Plan{ .version = recipe.windowVersion(), .initial_registers = registers, .final_registers = registers, .windows = &windows };
    try plan.validate();
    try plan.requireCaller(&witness.statement);
    const shared = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&vm);
    try std.testing.expect(register_sum.add(try plan.compensation(0, &shared.native)).isZero());
}

fn putFused(store: *@import("block_v5_cpu_bundle_store_v1.zig").Store, index: u32, proof: *@import("block_v5_caller_fused_proof_v1.zig").Proof) !void {
    return store.put(.caller_fused, index, proof);
}
fn takeFused(store: *@import("block_v5_cpu_bundle_store_v1.zig").Store, index: u32) !@import("block_v5_caller_fused_proof_v1.zig").Proof {
    return store.take(.caller_fused, index);
}
test "block-v5 selected production cold warm driver codec and global bodies generate without invocation" {
    const Pipeline = @import("block_v5_caller_pipeline_v1.zig").ForBackend(Cpu);
    const Fused = @import("block_v5_caller_fused_proof_v1.zig").ForBackend(Cpu);
    const Receiver = @import("block_v5_caller_fused_receiver_v1.zig").ForBackend(Cpu);
    const StagedNative = @import("block_v5_cpu_staged_execution_source_v1.zig").Source;
    const Global = @import("block_v5_global_receiver_v1.zig").ForBackend(Cpu);
    inline for (.{ &Family.commitPhysicalFirstRound, &Family.prove, &Family.verifyOwned, &Pipeline.collectSegmentWithStaging, &Pipeline.proveSegment, &Pipeline.proveStaged, &Fused.proveForCallerFirstRound, &Fused.verifyAfterFreshCaller, &Receiver.verifyOwned, &Stage.write, &Stage.ForBackend(Cpu).load, &StagedNative.initForRecipe, &StagedNative.takeFirstRound, &@import("block_v5_cpu_execution_source_v1.zig").Current.initForRecipe, &@import("block_v5_cpu_driver_v1.zig").run, &@import("block_v5_cpu_assembly_v1.zig").assemble, &@import("block_v5_cpu_collect_v1.zig").collect, &@import("block_v5_cpu_bundle_policy_v1.zig").collect, &@import("block_v5_precompile_codec_v1.zig").encode, &@import("block_v5_precompile_codec_v1.zig").decode, &putFused, &takeFused, &Global.verifyCompleteDetached, &@import("../ethereum_block_v5_cpu_produce.zig").main, &@import("../ethereum_block_v5_cpu_verify.zig").main }) |function| std.mem.doNotOptimizeAway(function);
}
