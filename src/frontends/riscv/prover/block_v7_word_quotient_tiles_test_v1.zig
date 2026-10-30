const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const E = @import("block_v7_execution_epoch_v1.zig");
const Initial = @import("block_v7_initial_intervals_v1.zig");
const Terminal = @import("block_v7_terminal_protocol_v1.zig");
const Policy = @import("block_v7_execution_policy_v1.zig").Policy;
const Event = @import("../air/block/memory_transition.zig").Transition;
const Raw = @import("../runner/guest_precompile/test_elf.zig").buildReleaseProgram(1, &.{0x0000006f}, 64, .rv32im_zkvm_v1);
const elf = blk: {
    var bytes = Raw;
    const table = std.mem.readInt(u32, bytes[264..268], .little);
    for ([4]usize{ 2, 3, 7, 8 }, [4]u32{ 0x100100, 64, 0x100180, 0x100190 }) |index, value|
        std.mem.writeInt(u32, bytes[table + (index + 1) * 16 + 4 ..][0..4], value, .little);
    std.mem.writeInt(u32, bytes[644..648], 0x44332211, .little);
    break :blk bytes;
};

test "v7 RAM tiled quotient preserves complete original proofs with and without coefficient retention" {
    const a = std.testing.allocator;
    const Engine = @import("stwo_prover_engine");
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var initialized = try Initial.Owned.derive(a, &elf, @import("block_v5_initial_sources_v1.zig").sha256(&elf), .rv32im_zkvm_v1, .{});
    defer initialized.deinit();
    var image = try @import("block_v7_program_image_v1.zig").Owned.init(a, &elf, &initialized, .{});
    defer image.deinit();
    var output: [43]u8 = @splat(0);
    output[32] = 1;
    const extra_events = if (std.posix.getenv("STWO_WORD_QUOTIENT_EXTRA_EVENTS")) |value| try std.fmt.parseInt(usize, value, 10) else 33;
    if (extra_events == 0 or extra_events > 4194304) return error.InvalidTestEventCount;
    const matrix_cap: usize = if (extra_events > 1048576) 4 << 30 else 1 << 30;
    const policy = Policy{ .initialized = &initialized, .program_root = image.root.bytes, .terminal = .{ .final_cycle = if (extra_events > 1048576) 4000000 else 1000000, .halt_address = initialized.info.halt_flag, .length_address = initialized.info.output_len, .data_address = initialized.info.output_data, .output_end = initialized.info.output_end, .output = output }, .config = @import("../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config() };
    const terminal = try Terminal.Plan.init(policy.terminal);
    const guest = try a.alloc(Event, 13 + extra_events);
    defer a.free(guest);
    for (guest[0..13], 0..) |*event, i| {
        const read = try terminal.transition(i, 0xa5);
        event.* = .{ .space = 1, .address = read.address, .clock = if (read.address == initialized.info.halt_flag) 4 * (policy.terminal.final_cycle - 1) + 1 else 4 * (i / 3) + i % 3 + 1, .before = (try initialized.find(read.address)).value, .after = read.before };
    }
    for (guest[13..], 0..) |*event, i| event.* = .{ .space = 1, .address = 0x100100, .clock = @intCast(4 * (10 + i / 3) + i % 3 + 1), .before = if (i == 0) (try initialized.find(0x100100)).value else @intCast(i), .after = @intCast(i + 1) };
    var stage = try @import("block_v7_memory_stage_v1.zig").For(Cpu).init(a, policy, guest, 0xa5, @intCast(guest.len + 13), .{ .max_events = 5000000, .max_row_log = 22, .max_matrix_bytes = matrix_cap });
    defer stage.deinit();
    try std.testing.expectEqual(@as(usize, 1), stage.ram.len);
    const entries = try stage.entries(a);
    defer a.free(entries);
    var counts: E.Counts = @splat(0);
    inline for (.{ E.Family.ram, E.Family.interval, E.Family.range16, E.Family.terminal }) |family| counts[@intFromEnum(family)] = 1;
    const epoch = try E.Epoch.init(try policy.digest(), policy.config, counts, entries, entries.len);
    const drawn = try epoch.draw(a);
    const Ram = @import("block_v7_ram_component_v1.zig");
    const T = @import("block_v7_memory_trace_v1.zig");
    var spec = Ram.Spec{ .claim = stage.ram[0].geometry, .halt = try @import("block_v7_halt_algebra_v1.zig").derive(policy.terminal), .sums = @splat(Q.zero()), .challenges = drawn.memory };
    var generated = try T.interactions(Ram.PLANES, a, stage.ram[0].matrix, @import("block_v7_memory_bundle_v1.zig").RamContext{ .spec = spec }, matrix_cap);
    defer generated.deinit();
    spec.sums = generated.sums;
    try requireBaseRowsParity(try spec.prepareDomain(spec.claim.rowCapacity()));
    const Source = @import("block_v7_memory_source_v1.zig");
    const first_channel = try Source.firstChannel(policy, .ram, 0, spec.claim.row_log);
    const proof_channel = try Source.channel(&drawn, entries[0], &spec.sums);
    const tiled_only = std.process.hasEnvVarConstant("STWO_WORD_QUOTIENT_TILED_ONLY");
    var expected_digest: ?[32]u8 = null;
    if (tiled_only) {
        const text = std.posix.getenv("STWO_WORD_QUOTIENT_EXPECTED_SHA256") orelse return error.MissingOriginalControlDigest;
        var digest: [32]u8 = undefined;
        if ((try std.fmt.hexToBytes(&digest, text)).len != digest.len) return error.InvalidOriginalControlDigest;
        expected_digest = digest;
    }
    var reference: ?[]u8 = null;
    defer if (reference) |bytes| a.free(bytes);
    var tile_options = (try (@import("block_v7_ram_quotient_policy_v1.zig").Policy{ .bounded_tiles = .{ .minimum_trace_log = 4 } }).select(spec.claim.row_log, 8 << 30)).?;
    if (spec.claim.row_log <= 13) {
        tile_options.tile_log = if (spec.claim.row_log <= 5) 3 else 11;
        tile_options.group_bytes = if (spec.claim.row_log <= 5) 4096 else 2 << 20;
    }
    const group_bytes = if (std.posix.getenv("STWO_WORD_QUOTIENT_GROUP_BYTES")) |value| try std.fmt.parseInt(usize, value, 10) else tile_options.group_bytes;
    tile_options.group_bytes = group_bytes;
    if (std.process.hasEnvVarConstant("STWO_WORD_QUOTIENT_FACTOR_RANGE_PAIRS")) tile_options.factor_range_pairs = true;
    if (std.process.hasEnvVarConstant("STWO_WORD_QUOTIENT_BASE_ROWS")) tile_options.base_field_rows = true;
    if (std.process.hasEnvVarConstant("STWO_WORD_QUOTIENT_GENERIC_ROWS")) tile_options.base_field_rows = false;
    if (std.posix.getenv("STWO_WORD_QUOTIENT_TILE_LOG")) |value| {
        tile_options.tile_log = try std.fmt.parseInt(u32, value, 10);
        tile_options.retained_tile_log = null;
        if (tile_options.tile_log < 3 or tile_options.tile_log > 23) return error.InvalidTestTileLog;
    }
    if (group_bytes > 4 << 30) return error.InvalidTestGroupBytes;
    if (std.process.hasEnvVarConstant("STWO_WORD_QUOTIENT_RETAINED_ONLY") and std.process.hasEnvVarConstant("STWO_WORD_QUOTIENT_RECOVERED_ONLY")) return error.InvalidTestCaseSelection;
    for ([_]bool{ true, false }) |retain| {
        if (!retain and std.process.hasEnvVarConstant("STWO_WORD_QUOTIENT_RETAINED_ONLY")) continue;
        if (retain and std.process.hasEnvVarConstant("STWO_WORD_QUOTIENT_RECOVERED_ONLY")) continue;
        for ([_]bool{ false, true }) |tiled| {
            if (tiled_only and !tiled) continue;
            const got = try prove(a, stage.ram[0].matrix, generated.matrix, spec, policy.config, first_channel, proof_channel, retain, if (tiled) tile_options else null);
            defer a.free(got.bytes);
            if (reference) |bytes| try std.testing.expectEqualSlices(u8, bytes, got.bytes) else reference = try a.dupe(u8, got.bytes);
            var proof_digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(got.bytes, &proof_digest, .{});
            if (expected_digest) |expected| try std.testing.expectEqualSlices(u8, &expected, &proof_digest);
            std.debug.print("V7_RAM_PROOF_SHA256 {s}\n", .{std.fmt.bytesToHex(proof_digest, .lower)});
            std.debug.print("V7_RAM_QUOTIENT_TILES retain={} tiled={} row_log={d} proof_bytes={d} charged_peak={d} commit_ns={d} proof_ns={d} verification_ns={d} exact_original_verification=true\n", .{ retain, tiled, spec.claim.row_log, got.bytes.len, got.peak, got.commit_ns, got.proof_ns, got.verification_ns });
        }
    }
    try std.testing.expectError(error.WordQuotientTileBudgetExceeded, prove(a, stage.ram[0].matrix, generated.matrix, spec, policy.config, first_channel, proof_channel, false, .{ .tile_log = 3, .max_workspace_bytes = 1 }));
}
fn prove(backing: std.mem.Allocator, matrix: @import("block_v7_memory_trace_v1.zig").Matrix, interaction: @import("block_v7_memory_trace_v1.zig").Matrix, spec: @import("block_v7_ram_component_v1.zig").Spec, config: core.pcs.PcsConfig, first_channel: core.proof_suites.Blake3.Channel, proof_channel: core.proof_suites.Blake3.Channel, retain: bool, options: ?@import("block_v7_word_quotient_tiles_v1.zig").Options) !struct { bytes: []u8, peak: usize, commit_ns: u64, proof_ns: u64, verification_ns: u64 } {
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const budget = try Budget.createRetainingParent(backing, if (spec.claim.row_log > 20) 32 << 30 else 8 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    const PC = @import("block_v5_word_pcs_v1.zig").For(Cpu, @import("block_v7_ram_component_v1.zig").Spec);
    var phase = try std.time.Timer.start();
    const compact = retain and std.process.hasEnvVarConstant("STWO_WORD_QUOTIENT_COMPACT_INPUT");
    var first = try PC.commitWithStorage(a, matrix.columns[0..24], matrix.columns[24..], first_channel, config, retain, if (compact) 1 else null);
    if (std.process.hasEnvVarConstant("STWO_WORD_QUOTIENT_INTERACTION_RECOVERY")) first.scheme.setCoefficientRetentionPolicy(.never);
    defer first.deinit(a);
    std.debug.print("V7_RAM_INPUT_STORAGE compact={} retain={} interaction_recovery={}\n", .{ compact, retain, std.process.hasEnvVarConstant("STWO_WORD_QUOTIENT_INTERACTION_RECOVERY") });
    const roots = first.roots;
    const commit_ns = phase.lap();
    const input_live = budget.snapshot().live_bytes;
    const compact_interaction = retain and std.process.hasEnvVarConstant("STWO_WORD_QUOTIENT_COMPACT_INTERACTION");
    if (compact_interaction and std.process.hasEnvVarConstant("STWO_WORD_QUOTIENT_INTERACTION_RECOVERY")) return error.InvalidTestStorageCombination;
    if (compact_interaction) first.scheme.setCompactPolynomialStorage(1);
    var committed_channel = proof_channel;
    try first.scheme.commitBorrowedStreaming(a, interaction.columns, 8, &committed_channel);
    first.scheme.compact_polynomial_storage = false;
    const interaction_live = budget.snapshot().live_bytes;
    std.debug.print("V7_RAM_PHASE_LIVE input_bytes={d} interaction_bytes={d} before_core_bytes={d} compact_interaction={}\n", .{ input_live, interaction_live, budget.snapshot().live_bytes, compact_interaction });
    const interaction_commit_ns = phase.read();
    const StageProfile = @import("stwo_prover_engine").stage_profile;
    var recorder = StageProfile.Recorder.initWithOptions(a, "cpu", "v7_ram_original", .{ .capture_tasks = false, .capture_work = false });
    defer recorder.deinit();
    const record_core = std.process.hasEnvVarConstant("STWO_WORD_QUOTIENT_CORE_PROFILE");
    var proof = try PC.proveCommittedWithDomainOptionsAndRecorder(a, &first, spec, matrix.log, committed_channel, options, if (record_core) &recorder else null);
    defer proof.deinit(a);
    const proof_ns = phase.lap();
    var capture = try PC.verifyCaptureBorrowed(a, &proof, spec, matrix.log, matrix.columns[0..24], roots, config, first_channel, proof_channel);
    defer capture.deinit(a);
    const verification_ns = phase.lap();
    if (record_core) {
        var captured = try recorder.snapshot(a);
        defer captured.deinit(a);
        std.debug.print("V7_RAM_CORE_PROFILE interaction_commit_ns={d} {f}\n", .{ interaction_commit_ns, std.json.fmt(captured, .{}) });
    }
    var wire = std.Io.Writer.Allocating.init(backing);
    defer wire.deinit();
    try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &wire.writer, proof);
    return .{ .bytes = try backing.dupe(u8, wire.written()), .peak = budget.snapshot().peak_live_bytes, .commit_ns = commit_ns, .proof_ns = proof_ns, .verification_ns = verification_ns };
}

test "v7 RAM tiled production defaults select only large memory components" {
    const cohort = @import("block_v7_memory_cohorts_v1.zig").Limits{};
    const joint = @import("block_v7_memory_joint_proof_v1.zig").Limits{};
    inline for (.{ cohort.ram_quotient, joint.ram_quotient }) |selected| {
        try std.testing.expect((try selected.select(17, 8 << 30)) == null);
        try std.testing.expectEqual(@as(usize, 32 << 20), (try selected.select(18, 8 << 30)).?.group_bytes);
        try std.testing.expectEqual(@as(usize, 1 << 30), (try selected.select(22, 8 << 30)).?.group_bytes);
    }
    const overridden = @import("block_v7_memory_cohorts_v1.zig").Limits{ .ram_quotient = .whole_domain };
    try std.testing.expect((try overridden.ram_quotient.select(22, 8 << 30)) == null);
}

fn requireBaseRowsParity(original: @import("block_v7_ram_component_v1.zig").Spec.Domain) !void {
    const Fast = @import("block_v7_ram_packed_base_v1.zig");
    const M = core.fields.m31.M31;
    const P = core.fields.packed_qm31.PackedQM31;
    const width = core.fields.m31.PACK_WIDTH;
    var random = std.Random.DefaultPrng.init(0x72616d5f62617365);
    for (0..3) |geometry_case| {
        var domain = original;
        if (geometry_case != 0) {
            domain.claim.first_event = 1;
            domain.claim.total_events = domain.claim.events + @as(u64, if (geometry_case == 1) 2 else 1);
            domain.claim.preceding = domain.claim.first;
        }
        for (0..6) |challenge_case| {
            const a: Q = switch (challenge_case) {
                0 => original.challenges.range16.powers[0],
                1, 2 => Q.zero(),
                3 => Q.fromBase(M.fromCanonical(7)),
                else => Q.fromM31Array(.{ M.fromCanonical(3), M.fromCanonical(5), M.fromCanonical(7), M.fromCanonical(11) }),
            };
            const z: Q = switch (challenge_case) {
                0 => original.challenges.range16.z,
                1, 3, 5 => Q.zero(),
                else => Q.fromM31Array(.{ M.fromCanonical(13), M.fromCanonical(17), M.fromCanonical(19), M.fromCanonical(23) }),
            };
            domain.challenges.range16 = .{ .powers = .{a}, .z = z };
            domain.packed_challenges = .from(domain.challenges);
            const fast = try Fast.Prepared.initWithRangeFactoring(domain, true);
            for (0..8) |_| {
                var cells: [24 + 88 + 88 + 116 + 116]core.fields.m31.PackedM31 = undefined;
                for (&cells) |*cell| for (0..width) |lane| {
                    cell[lane] = random.random().uintLessThan(u32, core.fields.m31.Modulus);
                };
                const fixed = cells[0..24].*;
                const row = cells[24..112].*;
                const prior = cells[112..200].*;
                const interaction = cells[200..316].*;
                const previous = cells[316..432].*;
                const expected = domain.evaluatePacked(Fast.lift(24, fixed), Fast.lift(88, row), Fast.lift(88, prior), Fast.lift(116, interaction), Fast.lift(116, previous));
                const scalar = try domain.evaluate(scalarLane(24, fixed, 0), scalarLane(88, row, 0), scalarLane(88, prior, 0), scalarLane(116, interaction, 0), scalarLane(116, previous, 0), domain.claim.rowCapacity());
                for (expected, scalar) |vector, one| try std.testing.expect(vector.lane(0).eql(one));
                const split = fast.evaluate(fixed, row, prior, interaction, previous);
                const actual = blk: {
                    var result: [161]P = undefined;
                    for (&result, 0..) |*value, i| value.* = if (i < 132) P.fromBase(split.direct[i].value) else split.interaction[i - 132];
                    break :blk result;
                };
                var powers: [161]P = undefined;
                var reference_fold = P.zero();
                for (actual, expected, &powers) |got, want, *power| {
                    for (0..width) |lane| try std.testing.expect(got.lane(lane).eql(want.lane(lane)));
                    var limbs: [4]M = undefined;
                    for (&limbs) |*limb| limb.* = M.fromCanonical(random.random().uintLessThan(u32, core.fields.m31.Modulus));
                    power.* = P.splat(Q.fromM31Array(limbs));
                    reference_fold = reference_fold.add(want.mul(power.*));
                }
                const folded = fast.fold(fixed, row, prior, interaction, previous, &powers);
                for (0..width) |lane| try std.testing.expect(folded.lane(lane).eql(reference_fold.lane(lane)));
                // The window specialization must retain both additional
                // state-delta planes, including arbitrary secure challenges.
                const Window = @import("block_v7_window_ram_component_v1.zig");
                const WindowFast = @import("block_v7_window_ram_packed_base_v1.zig");
                var wd = Window.Spec.Domain{ .original = domain, .delta = undefined, .packed_delta = undefined, .normalized = .{ Q.fromU32Unchecked(3, 5, 7, 11), Q.fromU32Unchecked(13, 17, 19, 23) } };
                wd.delta.z = Q.fromU32Unchecked(29, 31, 37, 41);
                wd.packed_delta.z = P.splat(wd.delta.z);
                for (&wd.delta.powers, &wd.packed_delta.powers, 0..) |*value, *packed_value, coordinate| {
                    value.* = Q.fromU32Unchecked(@intCast(43 + coordinate), 47, 53, 59);
                    packed_value.* = P.splat(value.*);
                }
                var extra_cells: [16]core.fields.m31.PackedM31 = undefined;
                for (&extra_cells) |*cell| for (0..width) |lane| {
                    cell[lane] = random.random().uintLessThan(u32, core.fields.m31.Modulus);
                };
                const wc = interaction ++ extra_cells[0..8].*;
                const wb = previous ++ extra_cells[8..16].*;
                const window_expected = wd.evaluatePacked(Fast.lift(24, fixed), Fast.lift(88, row), Fast.lift(88, prior), Fast.lift(124, wc), Fast.lift(124, wb));
                const window_fast = try WindowFast.Prepared.initWithRangeFactoring(wd, true);
                var wp: [163]P = undefined;
                var window_reference = P.zero();
                for (&wp, window_expected, 0..) |*power, equation, i| {
                    power.* = if (i < 161) powers[i] else P.splat(Q.fromU32Unchecked(@intCast(i), 61, 67, 71));
                    window_reference = window_reference.add(equation.mul(power.*));
                }
                const window_fold = window_fast.fold(fixed, row, prior, wc, wb, &wp);
                for (0..width) |lane| try std.testing.expect(window_fold.lane(lane).eql(window_reference.lane(lane)));
            }
        }
    }
    var bad = original;
    bad.halt.address[0] = Q.fromM31Array(.{ M.zero(), M.one(), M.zero(), M.zero() });
    try std.testing.expectError(error.InvalidV7BaseHaltConstant, Fast.Prepared.init(bad));
}

fn scalarLane(comptime n: usize, values: [n]core.fields.m31.PackedM31, lane: usize) [n]Q {
    var result: [n]Q = undefined;
    for (&result, values) |*value, vector| value.* = Q.fromBase(core.fields.m31.M31.fromCanonical(vector[lane]));
    return result;
}
