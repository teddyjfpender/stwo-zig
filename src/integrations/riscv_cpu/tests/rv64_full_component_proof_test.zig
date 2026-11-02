//! Complete small full-execution proof, with a private control path and three
//! independently reconstructed immutable preprocessing components.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const B = @import("stwo_cpu_backend").CpuBackend;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const rv = @import("stwo_riscv_frontend").rv64_air;
const E = rv.evaluation;
const L = E.L;
const frame = rv.full.frame;
const cpu = rv.full.component;
const S = rv.statement;
const W = rv.witness;
const P = rv.protocol;
const Plan = rv.encoding.Plan;
const relations = rv.relations;
const rom = rv.program.setup;
const compact = rv.program.compact;
const rom_provider = rv.program.provider;
const rom_component = rv.program.component;
const byte_provider = rv.range.provider;
const byte_component = rv.providers.byte;
const byte_cpu = rv.range.cpu;
const tables = rv.providers.tables;
const Column = engine.pcs.ColumnEvaluation;
const Scheme = engine.pcs.CommitmentSchemeProver(B, P.Hasher, P.MerkleChannel);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(P.Hasher, P.MerkleChannel);
const CPU_LOG: u32 = 10;
const CPU_SIZE: usize = 1 << CPU_LOG;
fn appendColumns(output: []Column, storage: []const M, log: u32) void {
    const size = @as(usize, 1) << @intCast(log);
    for (output, 0..) |*column, c| column.* = .{ .log_size = log, .values = storage[c * size ..][0..size] };
}
fn store(data: []M, size: usize, row: usize, column: usize, value: Q) void {
    for (value.toM31Array(), 0..) |coordinate, c| data[(column + c) * size + row] = coordinate;
}
fn mix(channel: *P.Channel, config: core.pcs.PcsConfig) void {
    channel.mixU32s(&.{ 0x46554c4c, 1, CPU_LOG, 1, 0x1000, 0x1004, 0x00100093 });
    config.mixInto(channel);
}
test "full CPU private control frame closes ROM and bytes in one native proof" {
    const a = std.testing.allocator;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 12) };
    const program = [_]u32{0x00100093}; // addi x1,x0,1
    var final: [32]u64 = @splat(0);
    final[1] = 1;
    const public = S.Statement{ .program_base = 0x1000, .program = &program, .initial_pc = 0x1000, .final_pc = 0x1004, .initial_registers = @splat(0), .final_registers = final, .memory = &.{}, .steps = 1 };
    var witness = try W.Witness.build(a, public);
    defer witness.deinit();
    const opcodes = [_]E.O{.ADDI};
    const plan = Plan.fromOpcodes(&opcodes);
    var setup = try rom.Setup.init(a, .{ .base = 0x1000, .words = &program });
    defer setup.deinit();
    var rom_request = try rom_provider.Request.init(a, &setup, witness.metadata.path);
    defer rom_request.deinit();
    const geometry = try frame.fixedColumns(a, CPU_LOG);
    defer a.free(geometry);
    const width = plan.main_count + frame.WIDTH;
    const main = try a.alloc(M, width * CPU_SIZE);
    defer a.free(main);
    const zero_row: rv.rows.Main = @splat(M.zero());
    for (0..CPU_SIZE) |i| {
        const row = W.physical(i, CPU_LOG);
        const source = if (i == 0) &witness.rows[0] else &zero_row;
        for (0..plan.main_count) |c| main[c * CPU_SIZE + row] = plan.projectValue(source, c);
        const advice = frame.fromRow(&setup.rows[0], 0x1004, i == 0);
        for (advice, 0..) |value, c| main[(plan.main_count + c) * CPU_SIZE + row] = try value.tryIntoM31();
    }
    const physical_columns = try a.alloc([]const M, plan.main_count);
    defer a.free(physical_columns);
    var counts: [256]u64 = @splat(0);
    for (physical_columns, 0..) |*column, c| column.* = main[c * CPU_SIZE ..][0..CPU_SIZE];
    for (plan.range_sources[0..plan.range_count]) |c| for (physical_columns[c]) |value| {
        if (value.v > 255) return error.InvalidFixtureRange;
        counts[value.v] += 1;
    };
    var byte_table = try byte_provider.Trace.init(a, &counts);
    defer byte_table.deinit();
    const rom_fixed = try setup.compactFixedColumns(a);
    defer a.free(rom_fixed);
    const fixed_count = 3 + compact.COUNT + 2 + 3;
    const fixed_columns = try a.alloc(Column, fixed_count);
    defer a.free(fixed_columns);
    appendColumns(fixed_columns[0..3], geometry, CPU_LOG);
    appendColumns(fixed_columns[3..][0 .. compact.COUNT + 2], rom_fixed, setup.log_size);
    appendColumns(fixed_columns[3 + compact.COUNT + 2 ..], byte_table.fixed, 8);
    const main_columns = try a.alloc(Column, width + 2);
    defer a.free(main_columns);
    appendColumns(main_columns[0..width], main, CPU_LOG);
    appendColumns(main_columns[width..][0..1], rom_request.multiplicities, setup.log_size);
    appendColumns(main_columns[width + 1 ..], byte_table.main, 8);
    var channel = P.Channel{};
    mix(&channel, config);
    var scheme = try Scheme.init(a, config);
    scheme.setCompactPolynomialStorage(5);
    var owns_scheme = true;
    errdefer if (owns_scheme) scheme.deinit(a);
    try scheme.commit(a, fixed_columns, &channel);
    try scheme.commit(a, main_columns, &channel);
    const state_challenges = relations.Challenges.draw(&channel);
    const rom_challenges = compact.draw(&channel);
    const alpha = channel.drawSecureFelt();
    const typed = tables.Challenges{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) };
    const target = try relations.expected(public, witness.metadata, state_challenges);
    const base_interaction = try a.alloc(M, 44 * CPU_SIZE);
    defer a.free(base_interaction);
    @memset(base_interaction, M.zero());
    var state_sum = Q.zero();
    var rom_sum = Q.zero();
    for (0..CPU_SIZE) |i| {
        const row = W.physical(i, CPU_LOG);
        var physical: [L.MAIN + frame.WIDTH]Q = undefined;
        for (physical[0..width], 0..) |*value, c| value.* = Q.fromBase(main[c * CPU_SIZE + row]);
        const logical = plan.inflateMain(physical[0..plan.main_count]);
        const advice = physical[plan.main_count..][0..frame.WIDTH].*;
        const fixed = frame.inflate(&advice, .{ E.q(@intCast(i)), E.q(@intFromBool(i == 0)), E.q(@intFromBool(i == CPU_SIZE - 1)) });
        const view = E.View{ .f = &fixed, .m = &logical };
        for (0..4) |slot| {
            if (fixed[L.fixed.slot_start + slot].isZero()) continue;
            const before = try state_challenges.denominator(relations.tuple(view, slot, true)).inv();
            const after = try state_challenges.denominator(relations.tuple(view, slot, false)).inv();
            store(base_interaction, CPU_SIZE, row, slot * 8, before);
            store(base_interaction, CPU_SIZE, row, slot * 8 + 4, after);
            state_sum = state_sum.add(before).sub(after);
        }
        store(base_interaction, CPU_SIZE, row, 32, state_sum);
        if (i == 0) {
            var entry = compact.expand(&frame.entry(&advice));
            entry[rom.field.valid] = Q.one();
            const inverse = try rom_challenges.denominator(&entry).inv();
            store(base_interaction, CPU_SIZE, row, 36, inverse);
            rom_sum = rom_sum.add(inverse);
        }
        store(base_interaction, CPU_SIZE, row, 40, rom_sum);
    }
    try std.testing.expect(state_sum.eql(target));
    var byte_interaction = try byte_cpu.buildInteraction(a, &plan, physical_columns, CPU_LOG, alpha);
    defer byte_interaction.deinit();
    const rom_claim = try rom_request.generateInteraction(&setup, rom_challenges);
    const byte_claim = try byte_table.generateInteraction(alpha);
    try std.testing.expect(rom_sum.add(rom_claim).isZero());
    try std.testing.expect(byte_interaction.claim.add(byte_claim).isZero());
    const claims = cpu.Claims{ .state = target, .rom = rom_sum, .bytes = byte_interaction.claim, .bitwise = Q.zero(), .shifts = Q.zero() };
    const challenges = cpu.Challenges{ .state = state_challenges, .rom = rom_challenges, .bytes = alpha, .bitwise = typed, .shifts = typed };
    const component = try cpu.Component.init(CPU_LOG, &plan, .{ .steps = 1, .initial_pc = 0x1000, .final_pc = 0x1004 }, challenges, claims, .{});
    const interaction_columns = try a.alloc(Column, component.interactionCount() + 16);
    defer a.free(interaction_columns);
    appendColumns(interaction_columns[0..44], base_interaction, CPU_LOG);
    appendColumns(interaction_columns[44..component.interactionCount()], byte_interaction.storage, CPU_LOG);
    appendColumns(interaction_columns[component.interactionCount()..][0..8], rom_request.interaction, setup.log_size);
    appendColumns(interaction_columns[component.interactionCount() + 8 ..], byte_table.interaction, 8);
    channel.mixFelts(&.{ rom_sum, rom_claim, byte_interaction.claim, byte_claim });
    try scheme.commit(a, interaction_columns, &channel);
    const rom_air = rom_component.Component{ .log_size = setup.log_size, .encoding = .compact41, .fixed_offset = 3, .main_offset = width, .interaction_offset = component.interactionCount(), .challenges = rom_challenges, .claim = rom_claim };
    const byte_air = byte_component.Component{ .fixed_offset = 3 + compact.COUNT + 2, .main_offset = width + 1, .interaction_offset = component.interactionCount() + 8, .alpha = alpha, .claim = byte_claim };
    const components = [_]engine.air.component_prover.ComponentProver{ component.asProverComponent(), rom_air.asProverComponent(), byte_air.asProverComponent() };
    // Retain the original fully materialized 4n CPU evaluator only in this
    // integration test. Both routes consume identical commitments/challenges.
    var reference_scheme = try Scheme.init(a, config);
    var owns_reference = true;
    errdefer if (owns_reference) reference_scheme.deinit(a);
    reference_scheme.setCompactPolynomialStorage(5);
    var reference_channel = P.Channel{};
    mix(&reference_channel, config);
    try reference_scheme.commit(a, fixed_columns, &reference_channel);
    try reference_scheme.commit(a, main_columns, &reference_channel);
    _ = relations.Challenges.draw(&reference_channel);
    _ = compact.draw(&reference_channel);
    _ = reference_channel.drawSecureFelt();
    reference_channel.mixFelts(&.{ rom_sum, rom_claim, byte_interaction.claim, byte_claim });
    try reference_scheme.commit(a, interaction_columns, &reference_channel);
    const reference_cpu = @import("rv64_full_reference_component.zig").Reference{ .component = &component };
    const reference_components = [_]engine.air.component_prover.ComponentProver{ reference_cpu.asProverComponent(), rom_air.asProverComponent(), byte_air.asProverComponent() };
    owns_reference = false;
    var reference_proof = try engine.prove.prove(B, P.Hasher, P.MerkleChannel, a, &reference_components, &reference_channel, reference_scheme);
    defer reference_proof.deinit(a);
    const wire = @import("stwo_proof_wire");
    const reference_bytes = try wire.encodeProofBytesBinary(a, reference_proof);
    defer a.free(reference_bytes);
    var tile_binding = try rv.full.parallel.testing.TileRowsBinding.init(64);
    defer tile_binding.deinit();
    for ([_]usize{ 1, 8, 16 }) |workers| {
        var variant_pool: engine.work_pool.WorkPool = undefined;
        try variant_pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 2 * 1024 * 1024, .backing_allocator = a });
        defer variant_pool.deinit();
        var variant_binding = try engine.work_pool.ScopedPoolBinding.init(&variant_pool);
        defer variant_binding.deinit();
        var variant_scheme = try Scheme.init(a, config);
        var owns_variant = true;
        errdefer if (owns_variant) variant_scheme.deinit(a);
        variant_scheme.setCompactPolynomialStorage(5);
        var variant_channel = P.Channel{};
        mix(&variant_channel, config);
        try variant_scheme.commit(a, fixed_columns, &variant_channel);
        try variant_scheme.commit(a, main_columns, &variant_channel);
        _ = relations.Challenges.draw(&variant_channel);
        _ = compact.draw(&variant_channel);
        _ = variant_channel.drawSecureFelt();
        variant_channel.mixFelts(&.{ rom_sum, rom_claim, byte_interaction.claim, byte_claim });
        try variant_scheme.commit(a, interaction_columns, &variant_channel);
        const before_waves = rv.full.parallel.testing.dynamicWaveCount();
        owns_variant = false;
        var variant = try engine.prove.prove(B, P.Hasher, P.MerkleChannel, a, &components, &variant_channel, variant_scheme);
        defer variant.deinit(a);
        const variant_bytes = try wire.encodeProofBytesBinary(a, variant);
        defer a.free(variant_bytes);
        try std.testing.expectEqualSlices(u8, reference_bytes, variant_bytes);
        if (workers != 1) try std.testing.expect(rv.full.parallel.testing.dynamicWaveCount() >= before_waves + 4);
    }
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = 2 * 1024 * 1024 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const before_three = rv.full.parallel.testing.dynamicWaveCount();
    owns_scheme = false;
    var proof = try engine.prove.prove(B, P.Hasher, P.MerkleChannel, a, &components, &channel, scheme);
    var owns_proof = true;
    defer if (owns_proof) proof.deinit(a);
    const optimized_bytes = try wire.encodeProofBytesBinary(a, proof);
    defer a.free(optimized_bytes);
    try std.testing.expectEqualSlices(u8, reference_bytes, optimized_bytes);
    try std.testing.expect(rv.full.parallel.testing.dynamicWaveCount() >= before_three + 4);

    // Receiver-owned geometry and canonical ROM/byte roots are rebuilt before
    // sampled-value verification. No private PC path is mixed into replay.
    const trusted_geometry = try frame.fixedColumns(a, CPU_LOG);
    defer a.free(trusted_geometry);
    var trusted_rom = try rom.Setup.init(a, .{ .base = 0x1000, .words = &program });
    defer trusted_rom.deinit();
    const trusted_rom_fixed = try trusted_rom.compactFixedColumns(a);
    defer a.free(trusted_rom_fixed);
    const empty_counts: [256]u64 = @splat(0);
    var trusted_byte = try byte_provider.Trace.init(a, &empty_counts);
    defer trusted_byte.deinit();
    const trusted_columns = try a.alloc(Column, fixed_count);
    defer a.free(trusted_columns);
    appendColumns(trusted_columns[0..3], trusted_geometry, CPU_LOG);
    appendColumns(trusted_columns[3..][0 .. compact.COUNT + 2], trusted_rom_fixed, setup.log_size);
    appendColumns(trusted_columns[3 + compact.COUNT + 2 ..], trusted_byte.fixed, 8);
    var fixed_scheme = try Scheme.init(a, config);
    defer fixed_scheme.deinit(a);
    var root_channel = P.Channel{};
    try fixed_scheme.commit(a, trusted_columns, &root_channel);
    var roots = try fixed_scheme.roots(a);
    defer roots.deinit(a);
    try std.testing.expectEqualSlices(u8, &roots.items[0], &proof.commitment_scheme_proof.commitments.items[0]);
    var verifier = try Verifier.init(a, config);
    defer verifier.deinit(a);
    var replay = P.Channel{};
    mix(&replay, config);
    const fixed_logs = try a.alloc(u32, fixed_count);
    defer a.free(fixed_logs);
    const main_logs = try a.alloc(u32, width + 2);
    defer a.free(main_logs);
    const interaction_logs = try a.alloc(u32, component.interactionCount() + 16);
    defer a.free(interaction_logs);
    for (fixed_columns, fixed_logs) |column, *log| log.* = column.log_size;
    for (main_columns, main_logs) |column, *log| log.* = column.log_size;
    for (interaction_columns, interaction_logs) |column, *log| log.* = column.log_size;
    const commitments = proof.commitment_scheme_proof.commitments.items;
    try verifier.commit(a, commitments[0], fixed_logs, &replay);
    try verifier.commit(a, commitments[1], main_logs, &replay);
    _ = relations.Challenges.draw(&replay);
    _ = compact.draw(&replay);
    _ = replay.drawSecureFelt();
    replay.mixFelts(&.{ rom_sum, rom_claim, byte_interaction.claim, byte_claim });
    try verifier.commit(a, commitments[2], interaction_logs, &replay);
    const receiver_components = [_]core.air.components.Component{ component.asVerifierComponent(), rom_air.asVerifierComponent(), byte_air.asVerifierComponent() };
    owns_proof = false;
    try core.verifier.verify(P.Hasher, P.MerkleChannel, a, &receiver_components, &replay, &verifier, proof);
}
