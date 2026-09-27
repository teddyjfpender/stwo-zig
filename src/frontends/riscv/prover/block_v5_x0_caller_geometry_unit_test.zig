//! Nonproving migration checks. These metadata and scalar fixtures carry no
//! STARK, global closure, device or execution-segment proof authority.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Geometry = @import("../air/guest_precompile/ethereum_statement.zig");
const Extension = @import("guest_precompile/ethereum_witness.zig").Witness;
const Sha = @import("../air/guest_precompile/sha256_component_profile.zig");

test "block-v5 x0 caller physical profiles reject independently relabeled legacy geometry" {
    const a = std.testing.allocator;
    var witness = try Extension.initWithCircuitProfileV1(a, &.{}, &.{}, &.{}, &.{}, 0, .ethereum_local_zero_v1);
    defer witness.deinit();
    const admission = Geometry.Admission{ .extra_memory_terms = 0, .memory_relation_terms = 0, .base_fixed_table_bounds = @splat(0), .extended_fixed_table_bounds = @splat(0) };
    const current = try Geometry.Statement.canonicalWithAdmissionForCircuitProfileV1(0, 0, witness.shapes(), admission, .ethereum_local_zero_v1);
    try current.validateGeometryWithCircuitProfileV1(0, .ethereum_local_zero_v1);
    try std.testing.expectEqual(witness.keccak_shard.mainColumnCount(), current.components[0].main_columns);
    try std.testing.expectEqual(@as(usize, @import("../air/guest_precompile/secp256k1_component_config.zig").RecoveryCallerLocalZero.main_column_count), current.components[13].main_columns);
    try std.testing.expect(witness.recovery_caller_local_zero != null);
    // A separately resealed legacy statement still cannot select the new AIR.
    try std.testing.expectError(error.StatementVersionMismatch, current.validateGeometryWithCircuitProfileV1(0, .ethereum_v5));
    var changed = current;
    changed.components[0].main_columns -= 2;
    try std.testing.expectError(error.InvalidComponentGeometry, changed.validateGeometryWithCircuitProfileV1(0, .ethereum_local_zero_v1));
    changed = current;
    changed.semantic_digest[0] ^= 1;
    try std.testing.expectError(error.SemanticDigestMismatch, changed.validateGeometryWithCircuitProfileV1(0, .ethereum_local_zero_v1));
    const profile = try Sha.Profile.canonicalForRecipe(0, true);
    try profile.validateForRecipe(0, true);
    try std.testing.expectError(error.InvalidShaComponentProfile, profile.validate(0));
    const manifest = try profile.manifestForRecipe(.{}, true);
    _ = try manifest.placement(@enumFromInt(4));
    var rows = try @import("../air/guest_precompile/sha256_memory_rows.zig").prepareForRecipe(true, a, &.{}, 0);
    defer rows.deinit();
    try std.testing.expectEqual(@as(usize, 243), @typeInfo(@TypeOf(rows.callers[0])).array.len);
    var main = try @import("guest_precompile/ethereum_main_columns.zig").generate(a, &witness);
    defer main.deinit(a);
    try std.testing.expectEqual(@as(usize, current.components[0].main_columns), main.ranges[0].count);
    try std.testing.expectEqual(@as(usize, current.components[13].main_columns), main.ranges[13].count);
    const statement = @import("blake3_ethereum_sha_statement.zig").Statement{ .ethereum = current, .sha = profile };
    const Wire = @import("guest_precompile/ethereum_sha_statement_wire.zig");
    var encoded = std.Io.Writer.Allocating.init(a);
    defer encoded.deinit();
    try Wire.encodeExtensionForRecipe(&encoded.writer, &statement, true);
    try std.testing.expectEqualDeep(statement, try Wire.decodeExtensionForRecipe(encoded.written(), true));
    try std.testing.expectError(error.UnsupportedShaStatementVersion, Wire.decodeExtension(encoded.written()));
    try std.testing.expectError(error.StatementVersionMismatch, Wire.encodeExtension(&encoded.writer, &statement));
    // Even an independently recomputed envelope cannot hide a changed AIR
    // descriptor behind the new containing schema.
    var altered = statement;
    altered.sha.descriptors[4].main_columns -= 4;
    try std.testing.expectError(error.InvalidShaComponentProfile, Wire.encodeExtensionForRecipe(&encoded.writer, &altered, true));
    var channel = core.proof_suites.Blake3.Channel{};
    const vm = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    const relations = try @import("guest_precompile/ethereum_sha_relations.zig").Relations.drawAfterVm(a, &channel, vm);
    const claims = try @import("guest_precompile/ethereum_sha_types.zig").ExtensionClaim.zeroForStatement(&statement);
    const Assembly = @import("guest_precompile/ethereum_sha_assembly.zig").Assembly;
    // Construct genuine component owners and masks only; no STARK is run.
    const prover = try Assembly(.prover).createBlockV5StandaloneForCircuitProfileV1(a, &statement, 0, &relations, &claims, .ethereum_local_zero_v1);
    defer prover.destroy(a);
    const verifier = try Assembly(.verifier).createBlockV5StandaloneForCircuitProfileV1(a, &statement, 0, &relations, &claims, .ethereum_local_zero_v1);
    defer verifier.destroy(a);
    try std.testing.expectEqual(prover.active().len, verifier.active().len);
    try std.testing.expect(prover.sha_owner_local_zero != null and verifier.sha_owner_local_zero != null);
}

test "block-v5 x0 caller component opens exact hints and generates selected scalar domain bodies" {
    const K = @import("../air/guest_precompile/keccakf_component.zig");
    const relations = @import("../air/guest_precompile/keccakf_relations.zig").Relations.dummy();
    const claim = K.Claim{ .log_size = 5, .n_rows = 0, .first_call_index = 0, .call_count = 0, .batch_sums = @splat(Q.zero()), .component_sum = Q.zero() };
    const component = try K.KeccakShardComponent.initForRecipe(claim, .{ .preprocessed_offset = 0, .main_offset = 0, .interaction_offset = 0 }, &relations, 18, true);
    try std.testing.expectEqual(K.constraint_count + 19, component.nConstraints());
    var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(K.main_column_count + 2, bounds.items[1].len);
    const point = core.circle.CirclePointQM31{ .x = Q.one(), .y = Q.zero() };
    var mask = try component.maskPoints(std.testing.allocator, point, 6);
    defer mask.deinitDeep(std.testing.allocator);
    for (mask.items[1][K.main_column_count..]) |column| {
        try std.testing.expectEqual(@as(usize, 1), column.len);
        try std.testing.expect(column[0].eql(point));
    }
    const prover = component.asProverComponent();
    const verifier = component.asVerifierComponent();
    std.mem.doNotOptimizeAway(prover);
    std.mem.doNotOptimizeAway(verifier);
    const Config = @import("../air/guest_precompile/secp256k1_component_config.zig").RecoveryCallerLocalZero;
    const Signer = @import("../air/guest_precompile/secp256k1_component.zig").Component(Config);
    const signer_relations = @import("../air/guest_precompile/secp256k1_relations.zig").Relations.dummy();
    const signer = try Signer.init(.{ .log_size = 1, .n_rows = 0, .batch_sums = @splat(Q.zero()), .component_sum = Q.zero() }, .{ .preprocessed_offset = 0, .main_offset = 0, .interaction_offset = 0 }, &signer_relations);
    std.mem.doNotOptimizeAway(signer.asProverComponent());
    std.mem.doNotOptimizeAway(signer.asVerifierComponent());
}

test "block-v5 x0 window and tracker keep nonzero chains and reject nonzero zero-register values" {
    const Tracker = @import("../runner/state_chain.zig");
    const a = std.testing.allocator;
    var legacy = Tracker.StateChainTracker.init(a);
    defer legacy.deinit();
    var current = Tracker.StateChainTracker.initLocalZero(a);
    defer current.deinit();
    const clock = 3 * Tracker.MAX_ACCESS_CLOCK_DIFF + 5;
    try legacy.recordRegTransition(0, clock, 0, 0);
    try current.recordRegTransition(0, clock, 0, 0);
    try std.testing.expect(legacy.clock_updates_reg.items.len != 0);
    try std.testing.expectEqual(@as(usize, 0), current.clock_updates_reg.items.len);
    try std.testing.expectEqual(@as(usize, 0), current.accesses.items.len);
    try std.testing.expectEqual(@as(u32, 0), current.reg_last_clk[0]);
    try std.testing.expectError(error.NonzeroX0CustodyTransition, current.recordRegTransition(0, clock, 1, 0));
    try std.testing.expectError(error.NonzeroX0CustodyTransition, current.recordRegTransition(0, clock, 0, 1));
    // Preserve the independently ordered nonzero register access and exact gaps.
    var oracle = Tracker.StateChainTracker.init(a);
    defer oracle.deinit();
    try current.recordRegTransition(7, clock, 23, 41);
    try oracle.recordRegTransition(7, clock, 23, 41);
    try std.testing.expectEqualSlices(Tracker.Access, oracle.accesses.items, current.accesses.items);
    try std.testing.expectEqualSlices(Tracker.ClockUpdate, oracle.clock_updates_reg.items, current.clock_updates_reg.items);
    const Windows = @import("block_v5_register_windows_v1.zig");
    var window = Windows.Window{ .index = 0, .first_cycle = 1, .cycle_count = 8, .initial_registers = @splat(0), .final_registers = @splat(0), .final_clocks = @splat(0) };
    const plan = Windows.Plan{ .version = Windows.LOCAL_ZERO_VERSION, .initial_registers = @splat(0), .final_registers = @splat(0), .windows = @as(*const [1]Windows.Window, @ptrCast(&window)) };
    try plan.validate();
    var old = plan;
    old.version = Windows.VERSION;
    try std.testing.expect(!std.meta.eql(try plan.digest(), try old.digest()));
    const relations = @import("../air/relation_challenges.zig").Relations.dummy();
    try std.testing.expect((try plan.compensation(0, &relations)).eql(try old.compensation(0, &relations)));
    window.final_clocks[0] = 1;
    try std.testing.expectError(error.UntrustedX0LocalPublicBoundary, plan.validate());
    try std.testing.expectError(error.UntrustedX0LocalPublicBoundary, plan.compensation(0, &relations));
}

test "block-v5 x0 caller restored counters omit only the authentic zero-pointer gap transactionally" {
    const a = std.testing.allocator;
    const M = core.fields.m31.M31;
    const Buffer = @import("../runner/guest_precompile/keccakf_call_buffer.zig");
    const Trace = @import("../air/guest_precompile/keccakf_trace.zig");
    const input: [Buffer.word_count]u32 = @splat(0);
    var state = Trace.stateFromWords(input);
    @import("../air/guest_precompile/keccakf_authority.zig").permute(&state);
    var output: [Buffer.word_count]u32 = undefined;
    for (state, 0..) |lane, i| {
        output[2 * i] = @truncate(lane);
        output[2 * i + 1] = @truncate(lane >> 32);
    }
    const record = Buffer.Record{ .execution_clock = 1, .pc = 16, .state_ptr = 0, .pointer_register = 0, .pointer_previous_clock = 0, .input = input, .output = output, .memory_previous_clocks = @splat(0) };
    const row = @import("../runner/guest_precompile/keccakf_v1.zig").ExecutionRow{ .execution_clock = 1, .pc = 16, .inst_word = @import("../isa/custom0.zig").encodeKeccakf(0), .call_index = 0 };
    var extension = try Extension.initWithCircuitProfileV1(a, &.{record}, &.{row}, &.{}, &.{}, 1, .ethereum_local_zero_v1);
    defer extension.deinit();
    var sha = try @import("../air/guest_precompile/sha256_memory_rows.zig").prepareForRecipe(true, a, &.{}, 1);
    defer sha.deinit();
    // Open host-census metadata only; no statement/key/seal or receipt is
    // admitted here. All cells above came from the authentic execution tapes.
    const witness = .{ .extension = extension, .sha_rows = sha, .total_steps = @as(u32, 1), .statement = .{ .ethereum = .{ .counts = .{ .keccak_calls = @as(u32, 1), .signer_calls = @as(u32, 0) } } } };
    const Tables = @import("../air/lookups/tables/mod.zig");
    var current = try Tables.counter.Set.init(a);
    defer current.deinit(a);
    var reference = try Tables.counter.Set.init(a);
    defer reference.deinit(a);
    try @import("block_v5_caller_columns_stage_v1.zig").registerCounters(a, &witness, &current);
    try (@import("../air/guest_precompile/ethereum_lookup_registration.zig").Context{ .keccak = &.{record}, .recovery = &.{} }).register(&reference);
    var old_sha = try @import("../air/guest_precompile/sha256_memory_rows.zig").prepare(a, &.{}, 1);
    defer old_sha.deinit();
    try @import("../air/guest_precompile/sha256_lookup_registration.zig").register(a, &old_sha, &reference);
    for (current.counters, reference.counters) |new, old| {
        for (new.values, old.values, 0..) |found, wanted, index| {
            const expected = if (new.kind == .range_check_20 and index == 0) wanted.add(M.one()) else wanted;
            try std.testing.expect(found.eql(expected));
        }
    }
    var totals: [Tables.schema.KIND_COUNT]M = undefined;
    for (current.counters, &totals) |counter, *total| total.* = counter.signedTotal();
    const Caller = @import("../air/guest_precompile/keccakf_caller.zig");
    @constCast(extension.keccak_shard.mainColumn(Trace.Layout.caller + Caller.Layout.pointer_bytes))[0] = M.one();
    try std.testing.expectError(error.NonzeroX0CustodyTransition, @import("block_v5_caller_columns_stage_v1.zig").registerCounters(a, &witness, &current));
    for (current.counters, totals) |counter, total| try std.testing.expect(counter.signedTotal().eql(total));
}
