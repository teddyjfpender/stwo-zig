//! Real runner -> original committed PCS -> bounded disk -> unchanged proof.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Root = @import("../block_v5_cpu_native_root_proposal_v1.zig");
const Stage = @import("../block_v5_native_columns_stage_v1.zig");
const Store = @import("../block_v6_native_commitment_store_v1.zig");
const Native = @import("../block_v5_native_execution_proof_v3.zig");
const Seal = @import("../block_v5_source_seal_v1.zig");
const Catalog = @import("../block_v5_native_template_catalog_v1.zig");
const Fixture = @import("block_v5_lightweight_native_proof_test.zig").Fixture;
const Codec = @import("../block_v5_native_codec_v3.zig");
const profile = @import("../../isa/execution_profile.zig").ExecutionProfile.rv32im_zkvm_v1;
const limits = Stage.Limits{ .columns = .{ .max_columns = 1024, .max_log_size = 22, .max_file_bytes = 64 << 20, .max_loaded_bytes = 64 << 20 }, .max_public_words = 1024, .max_public_bytes = 64 << 10 };

test "native commitment checkpoint restores original PCS and produces byte-identical verified proof" {
    const a = std.testing.allocator;
    const code = [_]u32{ 0x00700293, 0x00328313, 0x005302b3, 0x0000006f };
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildProgram(code.len, &code, 64, profile);
    var session = try @import("../../runner/mod.zig").BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var segment = try session.startSegment(3);
    defer segment.deinit();
    var counts: [Seal.family_count]u32 = @splat(0);
    for ([_]Seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory }) |f| counts[@intFromEnum(f) - 1] = 1;
    var pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(25), .native_template_catalog_digest = @splat(26), .config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config(), .counts = counts };
    var fixture = try Fixture.init(a, &segment, pins);
    defer fixture.deinit();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    var proposal: Root.Proposal = undefined;
    const stored = blk: {
        var first = try Root.ForBackend(Cpu).collectRetained(a, fixture.owner, pins.config, profile, 0, 1, .{ .max_public_words = 1024, .max_metadata_bytes = 1 << 20 });
        defer first.first.deinit(a);
        errdefer first.proposal.deinit();
        const checkpoint = try Store.write(a, temp.dir, "native.pcs", &first.proposal, &first.first, .{});
        var replay = try Store.load(a, temp.dir, "native.pcs", &first.proposal, checkpoint, .{});
        defer replay.deinit(a);
        for (first.first.scheme.trees.items, replay.scheme.trees.items) |original, restored| {
            for (original.columns, restored.columns) |left, right| try std.testing.expectEqualDeep(left, right);
            for (original.commitment.layers, restored.commitment.layers) |left, right| try std.testing.expectEqualSlices([32]u8, left, right);
        }
        try negativeStructure(a, temp.dir, &first.proposal, &first.first, checkpoint);
        try std.testing.checkAllAllocationFailures(a, restoreAndRelease, .{ temp.dir, &first.proposal, checkpoint });
        proposal = first.proposal;
        break :blk checkpoint;
    };
    defer proposal.deinit();
    // Original PCS is destroyed above. Both proof paths are independent owners.
    const raw = try Stage.write(a, temp.dir, "native.columns", fixture.owner, &proposal, limits);
    var cold = try Stage.ForBackend(Cpu).load(a, temp.dir, "native.columns", &proposal, raw, limits, profile);
    defer cold.deinit(a);
    var reused = try Stage.ForBackend(Cpu).loadWithCommitment(a, temp.dir, "native.columns", &proposal, raw, limits, profile, "native.pcs", stored, .{});
    defer reused.deinit(a);
    try std.testing.expect(cold.owner.opcode_columns.lookup_counters != null);
    try std.testing.expect(reused.owner.opcode_columns.lookup_counters == null);
    try std.testing.expectEqualDeep(cold.owner.main.items, reused.owner.main.items);
    try std.testing.expectEqualDeep(cold.owner.preprocessed.items, reused.owner.preprocessed.items);
    {
        var proof_only = try Stage.ForBackend(Cpu).loadForProving(a, temp.dir, "native.columns", &proposal, raw, limits, profile);
        defer proof_only.deinit(a);
        try std.testing.expect(proof_only.owner.opcode_columns.lookup_counters == null);
        try std.testing.expectEqualDeep(cold.first.roots, proof_only.first.roots);
        try std.testing.expectEqualDeep(cold.owner.main.items, proof_only.owner.main.items);
    }
    var cold_first = try cold.takeFirstRound(&proposal, fixture.pin);
    defer cold_first.deinit(a);
    var reused_first = try reused.takeFirstRound(&proposal, fixture.pin);
    defer reused_first.deinit(a);
    try std.testing.expectError(error.ChangedV5StagedNativeAdmission, reused.takeFirstRound(&proposal, fixture.pin));
    const records = [_]Catalog.Record{.{ .index = 0, .template_id = cold_first.template_id, .geometry_digest = cold_first.template.geometry_digest, .fixed_root = cold_first.roots[0] }};
    const catalog = Catalog.Admission{ .records = &records };
    pins.native_template_catalog_digest = try catalog.digest();
    const entries = [_]Seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(7), .roots = .{ @splat(8), @splat(9) } },
        cold_first.entry(),
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(13), .roots = .{ @splat(14), @splat(15) } },
        .{ .family = .memory, .index = 0, .instance_id = @splat(16), .roots = .{ @splat(17), @splat(18) } },
    };
    const sealed = try Seal.seal(pins, &entries);
    const Api = Native.ForBackend(Cpu);
    const expected = Codec.Expected{ .shape = &proposal.shape, .external_retirements = proposal.template.external_retirements, .template_id = proposal.template_id, .instance_id = cold_first.instance_id, .config = pins.config };
    var original_proof = try Api.proveWithCatalog(a, &cold_first, sealed, pins, &entries, catalog);
    defer original_proof.deinit(a);
    const original_bytes = try Codec.encode(a, &original_proof, expected, .{});
    defer a.free(original_bytes);
    var restored_proof = try Api.proveWithCatalog(a, &reused_first, sealed, pins, &entries, catalog);
    defer restored_proof.deinit(a);
    const restored_bytes = try Codec.encode(a, &restored_proof, expected, .{});
    defer a.free(restored_bytes);
    try std.testing.expectEqualSlices(u8, original_bytes, restored_bytes);
    var first_capture = try Api.verifyCaptureBorrowedWithCatalog(a, &original_proof, &proposal.shape, fixture.pin, proposal.template, proposal.template_id, profile, 0, sealed, pins, &entries, catalog);
    defer first_capture.deinit();
    var reused_capture = try Api.verifyCaptureBorrowedWithCatalog(a, &restored_proof, &proposal.shape, fixture.pin, proposal.template, proposal.template_id, profile, 0, sealed, pins, &entries, catalog);
    defer reused_capture.deinit();
    try std.testing.expectEqualDeep(first_capture.receipt, reused_capture.receipt);
    // Deliberately corrupt a canonical cached LDE without changing its original
    // root. Structural loading is not verification; resulting proofs must fail.
    var bad = try Stage.ForBackend(Cpu).loadWithCommitment(a, temp.dir, "native.columns", &proposal, raw, limits, profile, "native.pcs", stored, .{});
    defer bad.deinit(a);
    for (@constCast(bad.first.scheme.trees.items[1].columns[0].values)) |*value| value.* = value.add(core.fields.m31.M31.one());
    var bad_first = try bad.takeFirstRound(&proposal, fixture.pin);
    defer bad_first.deinit(a);
    if (Api.proveWithCatalog(a, &bad_first, sealed, pins, &entries, catalog)) |proof| {
        var bad_proof = proof;
        defer bad_proof.deinit(a);
        if (Api.verifyCaptureBorrowedWithCatalog(a, &bad_proof, &proposal.shape, fixture.pin, proposal.template, proposal.template_id, profile, 0, sealed, pins, &entries, catalog)) |capture| {
            var accepted = capture;
            accepted.deinit();
            return error.AcceptedTamperedNativeCheckpoint;
        } else |err| return err;
    } else |err| {
        try std.testing.expectEqual(error.ConstraintsNotSatisfied, err);
        std.debug.print("NATIVE_CHECKPOINT_TAMPER rejected_by_prover={s}\n", .{@errorName(err)});
    }
    std.debug.print("NATIVE_CHECKPOINT verified=true proof_byte_parity=true original_pcs_destroyed=true bytes={d} column_bytes={d} merkle_bytes={d} loaded_bytes={d} global_claims_open=true\n", .{ stored.bytes, stored.column_bytes, stored.merkle_bytes, stored.loaded_bytes });
}

fn restoreAndRelease(a: std.mem.Allocator, dir: std.fs.Dir, proposal: *const Root.Proposal, pin: Store.Pin) !void {
    var restored = try Store.load(a, dir, "native.pcs", proposal, pin, .{});
    defer restored.deinit(a);
}

fn negativeStructure(a: std.mem.Allocator, dir: std.fs.Dir, proposal: *const Root.Proposal, first: *const Root.ForBackend(Cpu).PhysicalFirstRound, pin: Store.Pin) !void {
    var wrong = proposal.*;
    wrong.index = 1;
    try std.testing.expectError(error.ChangedNativeCheckpointScope, Store.load(a, dir, "native.pcs", &wrong, pin, .{}));
    wrong = proposal.*;
    wrong.roots[1][0] ^= 1;
    try std.testing.expectError(error.ChangedNativeCheckpointScope, Store.load(a, dir, "native.pcs", &wrong, pin, .{}));
    var cap = Store.Limits{ .max_file_bytes = pin.bytes - 1 };
    try std.testing.expectError(error.NativeCheckpointResourceLimit, Store.write(a, dir, "over-limit.pcs", proposal, first, cap));
    try std.testing.expectError(error.FileNotFound, dir.openFile("over-limit.pcs", .{}));
    cap = .{ .max_loaded_bytes = pin.loaded_bytes - 1 };
    try std.testing.expectError(error.NativeCheckpointResourceLimit, Store.load(a, dir, "native.pcs", proposal, pin, cap));
    try std.testing.expectError(error.NativeCheckpointAlreadyExists, Store.write(a, dir, "native.pcs", proposal, first, .{}));
    const file = try dir.openFile("native.pcs", .{ .mode = .read_write });
    defer file.close();
    var first_root_offset: u64 = 160 + 8 + 8;
    for (first.scheme.trees.items[0].columns) |column| first_root_offset += 4 + column.values.len * 4;
    var root_byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try file.preadAll(&root_byte, first_root_offset));
    root_byte[0] ^= 1;
    try file.pwriteAll(&root_byte, first_root_offset);
    try std.testing.expectError(error.ChangedNativeCheckpointRoot, Store.load(a, dir, "native.pcs", proposal, pin, .{}));
    root_byte[0] ^= 1;
    try file.pwriteAll(&root_byte, first_root_offset);
    // First tree first column log follows the fixed header + tree descriptor.
    var old: [4]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 4), try file.preadAll(&old, 168));
    try file.pwriteAll(&.{ 255, 255, 255, 255 }, 168);
    try std.testing.expectError(error.ChangedNativeCheckpointGeometry, Store.load(a, dir, "native.pcs", proposal, pin, .{}));
    try file.pwriteAll(&old, 168);
    try std.testing.expectEqual(@as(usize, 4), try file.preadAll(&old, 172));
    try file.pwriteAll(&.{ 255, 255, 255, 127 }, 172);
    try std.testing.expectError(error.NonCanonicalNativeCheckpointM31, Store.load(a, dir, "native.pcs", proposal, pin, .{}));
    try file.pwriteAll(&old, 172);
    try file.setEndPos(pin.bytes - 1);
    try std.testing.expectError(error.InvalidNativeCheckpointLength, Store.load(a, dir, "native.pcs", proposal, pin, .{}));
    // Restore the byte-exact original through a fresh bounded serialization.
    try dir.deleteFile("native.pcs");
    const restored = try Store.write(a, dir, "native.pcs", proposal, first, .{});
    try std.testing.expectEqualDeep(pin, restored);
}
