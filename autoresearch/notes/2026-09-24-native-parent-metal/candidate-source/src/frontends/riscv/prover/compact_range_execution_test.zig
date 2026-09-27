const std = @import("std");
const core = @import("stwo_core");
test "compact range provider real execution replaces shared fixed tables before commitment" {
    const a = std.testing.allocator;
    const instructions = [_]u32{ 0x00500093, 0x00708093, 0x00100137, 0x00100193, 0x00312223, 0x00312423, 0x0000006f };
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildReleaseProgram(instructions.len, &instructions, 0, .rv32im_zkvm_v1);
    var run = try @import("../runner/mod.zig").runWithInput(a, &elf, &.{}, 100);
    defer run.deinit();
    var original = try @import("blake3_segment_execution.zig").Owner.initRun(a, &run);
    defer original.deinit();
    const Native = @import("blake3_execution_trace.zig").Owner;
    const compact = try Native.init(a, &run.execution_trace, original.native.statement.public_data, &run.state_chain_tracker);
    defer compact.deinit();
    try compact.includeCompactCommitments(original.hashes);
    const ranges = compact.compact_ranges orelse return error.MissingCompactProviders;
    try std.testing.expect(ranges.merged);
    const contract_mod = @import("compact_execution_contract.zig");
    const contract = contract_mod.Contract{ .native = &compact.statement, .ranges = ranges.plan };
    try contract.validate(0);
    const duplicate = contract_mod.Contract{ .native = &original.native.statement, .ranges = ranges.plan };
    try std.testing.expectError(error.DuplicateCompactRangeProvider, duplicate.validate(0));
    const config: core.pcs.PcsConfig = .{ .pow_bits = 26, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 70, .fold_step = 1 } };
    var compact_channel = core.channel.blake3.Channel{};
    const pin = try original.admission();
    const manifest = @import("blake3_execution_manifest.zig");
    const compact_manifest = @import("compact_execution_manifest.zig");
    const source_id = try @import("blake3_execution_source.zig").validate(a, &elf, &.{}, &compact.statement.public_data);
    const legacy_metadata = try manifest.encode(a, &original.native.statement, pin, config, source_id, .{});
    defer a.free(legacy_metadata);
    var legacy_admitted = try manifest.decode(a, legacy_metadata, manifest.identity(legacy_metadata), source_id, config, .{});
    defer legacy_admitted.deinit();
    try std.testing.expect(legacy_admitted.ranges == null);
    const metadata = try compact_manifest.encode(a, &compact.statement, pin, config, source_id, .{}, ranges.plan);
    defer a.free(metadata);
    const manifest_id = manifest.identity(metadata);
    var admitted = try manifest.decode(a, metadata, manifest_id, source_id, config, .{});
    defer admitted.deinit();
    try std.testing.expectEqualDeep(ranges.plan, admitted.ranges.?);
    var wrong_source = source_id;
    wrong_source.input_sha256[0] ^= 1;
    try std.testing.expectError(error.ExecutionSourceMismatch, manifest.decode(a, metadata, manifest_id, wrong_source, config, .{}));
    try std.testing.expectError(error.ExecutionManifestResourceLimit, manifest.decode(a, metadata, manifest_id, source_id, config, .{ .max_bytes = metadata.len - 1 }));
    metadata[12] ^= 1;
    try std.testing.expectError(error.UntrustedExecutionManifest, manifest.decode(a, metadata, manifest_id, source_id, config, .{}));
    try std.testing.expectError(error.UntrustedCompactRangeGeometry, manifest.decode(a, metadata, manifest.identity(metadata), source_id, config, .{}));
    metadata[12] ^= 1;

    try std.testing.expectError(error.CompactRangeProtocolNotAdmitted, @import("blake3_execution_proof.zig").ForBackend(void).validateForProving(compact, original.hashes, pin));
    try contract.mix(&compact_channel, config, pin, 0);
    var old_channel = core.channel.blake3.Channel{};
    try @import("blake3_execution_protocol.zig").mix(&old_channel, config, &compact.statement, pin);
    try std.testing.expect(!std.mem.eql(u8, &compact_channel.digestBytes(), &old_channel.digestBytes()));
    inline for (.{ @import("blake3_execution_protocol.zig").ColumnTree.main, .interaction }) |tree| {
        const logs = try contract.columnLogs(a, original.hashes.logs, tree, 0);
        defer a.free(logs);
        const base_logs = try @import("blake3_execution_protocol.zig").columnLogs(a, &compact.statement, original.hashes.logs, tree);
        defer a.free(base_logs);
        const prefix = if (tree == .main) compact.statement.nMainColumns() else compact.statement.nInteractionColumns();
        const extra: usize = if (tree == .main) 23 else 12;
        try std.testing.expectEqual(base_logs.len + extra, logs.len);
        try std.testing.expectEqualSlices(u32, base_logs[0..prefix], logs[0..prefix]);
        try std.testing.expectEqualSlices(u32, base_logs[prefix..], logs[prefix + extra ..]);
    }

    try std.testing.expectEqual(original.native.statement.n_components, compact.statement.n_components);
    try std.testing.expectEqualSlices(u8, &original.native.statement.public_data.program_root.?.bytes, &compact.statement.public_data.program_root.?.bytes);
    for (compact.statement.infra_descs[0..compact.statement.n_infra]) |desc| {
        try std.testing.expect(desc.kind != .range_check_20 and desc.kind != .range_check_8_11 and desc.kind != .range_check_8_8_4);
    }
    try std.testing.expectEqual(@as(usize, 23), ranges.columns.len);
    var old_cells: usize = 0;
    var new_cells: usize = 0;
    for (original.native.main.items) |column| old_cells += column.values.len;
    for (compact.main.items) |column| new_cells += column.values.len;
    for (ranges.columns) |column| new_cells += column.values.len;
    try std.testing.expect(new_cells < old_cells);
    const bytes = compact.opcode_columns.lookup_counters.?.get(.range_check_8_8);
    const previous = original.native.opcode_columns.lookup_counters.?.get(.range_check_8_8);
    for (bytes.values, previous.values, 0..) |actual, before, row| {
        var expected = before;
        inline for (0..3) |i| expected = expected.add(ranges.witnesses[i].byte_counts[row]);
        try std.testing.expectEqual(expected, actual);
    }
    var channel = core.channel.blake3.Channel{};
    const relations = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    const native = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&relations);
    try std.testing.expectError(error.CompactRangeProtocolNotAdmitted, compact.generateInteractions(&native.native));
    try std.testing.expect(!compact.failed);
    try compact.generateCompactNativeInteractions(&native.native);
    const Q = core.fields.qm31.QM31;
    const empty_hash_claims: [@import("blake3_commitment_components.zig").Airs.len]Q = @splat(Q.zero());
    const before_claims = compact_channel;
    try contract.mixClaims(&compact_channel, &compact.claims, @splat(Q.zero()), &empty_hash_claims, 0);
    var changed_claims_channel = before_claims;
    try contract.mixClaims(&changed_claims_channel, &compact.claims, .{ Q.one(), Q.zero(), Q.zero() }, &empty_hash_claims, 0);
    try std.testing.expect(!std.mem.eql(u8, &compact_channel.digestBytes(), &changed_claims_channel.digestBytes()));
    const saved_claim_digest = compact_channel.digestBytes();
    compact.claims.n_infra += 1;
    try std.testing.expectError(error.InvalidInteractionClaim, contract.mixClaims(&compact_channel, &compact.claims, @splat(Q.zero()), &empty_hash_claims, 0));
    compact.claims.n_infra -= 1;
    try std.testing.expectEqual(saved_claim_digest, compact_channel.digestBytes());
    try std.testing.expectEqual(compact.statement.nInteractionColumns(), compact.interaction.items.len);
    try original.native.generateInteractions(&native.native);
    var compact_total = try claimTotal(compact);
    inline for (@import("../recursion/air/compact_range_geometry.zig").kinds, 0..) |kind, i| {
        const P = @import("../recursion/air/compact_range_interaction.zig").Prepared(kind);
        const prepared = try P.init(a, ranges.plan, ranges.identity);
        defer prepared.deinit();
        var generated = try prepared.generate(&ranges.witnesses[i], &relations);
        defer generated.deinit(a);
        compact_total = compact_total.add(generated.claimed_sum);
    }
    try std.testing.expectEqual(try claimTotal(original.native), compact_total);

    try std.testing.expectError(error.LookupTablesAlreadyPrepared, compact.includeCompactCommitments(original.hashes));
    std.debug.print("COMPACT_RANGE_EXECUTION old_main_cells={d} compact_main_cells={d} counts={d}/{d}/{d}\n", .{ old_cells, new_cells, ranges.plan.shapes[0].n_rows, ranges.plan.shapes[1].n_rows, ranges.plan.shapes[2].n_rows });
}

fn claimTotal(owner: *const @import("blake3_execution_trace.zig").Owner) !core.fields.qm31.QM31 {
    var total = core.fields.qm31.QM31.zero();
    for (owner.statement.component_descs[0..owner.statement.n_components], 0..) |desc, i| total = total.add(try owner.claims.opcodeClaimTotal(desc.family, i));
    for (owner.statement.infra_descs[0..owner.statement.n_infra], 0..) |desc, i| total = total.add(try owner.claims.infraClaimTotal(desc.kind, i));
    return total;
}

test "compact range provider base STARK proves and independently verifies" {
    try checkProof(false);
}
test "compact range provider canonical recursive parent verifies" {
    checkProof(true) catch |err| {
        std.debug.print("COMPACT_PARENT_ERROR {s}\n", .{@errorName(err)});
        return err;
    };
}
fn checkProof(comptime recurse: bool) !void {
    return checkProofForBackend(recurse, @import("stwo_cpu_backend").CpuBackend);
}
/// Same admitted CPU child and parent checks, with only parent proving backend varied.
pub fn checkProofForBackend(comptime recurse: bool, comptime ParentBackend: type) !void {
    const a = std.testing.allocator;
    const instructions = [_]u32{ 0x00500093, 0x00708093, 0x00100137, 0x00100193, 0x00312223, 0x00312423, 0x0000006f };
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildReleaseProgram(instructions.len, &instructions, 0, .rv32im_zkvm_v1);
    var run = try @import("../runner/mod.zig").runWithInput(a, &elf, &.{}, 100);
    defer run.deinit();
    var source = try @import("blake3_segment_execution.zig").Owner.initCompactRun(a, &run);
    defer source.deinit();
    const native = source.native;
    const ranges = native.compact_ranges.?;
    const api = @import("blake3_execution_proof.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend);
    const config: core.pcs.PcsConfig = .{ .pow_bits = 26, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 70, .fold_step = 1 } };
    const pin = try source.admission();
    const prepared = try api.PreparedVerifier.initCompact(a, &native.statement, pin, config, ranges.plan);
    defer prepared.deinit();
    var proved = try api.proveCompact(a, native, source.hashes, pin, config);
    defer proved.proof.deinit(a);
    const codec = @import("blake3_execution_codec.zig");
    const artifact = @import("blake3_execution_artifact.zig");
    const published = try artifact.encode(a, &proved.proof, prepared, &elf, &.{}, .{});
    defer a.free(published.bytes);
    const fresh = try artifact.ForBackend(@import("stwo_cpu_backend").CpuBackend).verify(a, published.bytes, published.statement_id, config, &elf, &.{}, .{});
    try std.testing.expectEqual(proved.transcript_digest, fresh);
    var wrong_statement = published.statement_id;
    wrong_statement[0] ^= 1;
    try std.testing.expectError(error.UntrustedExecutionManifest, artifact.ForBackend(@import("stwo_cpu_backend").CpuBackend).verify(a, published.bytes, wrong_statement, config, &elf, &.{}, .{}));
    const encoded = try codec.encode(a, &proved.proof, prepared, prepared.id);
    defer a.free(encoded);
    try std.testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, encoded[8..12], .little));
    const actual = try api.verifyPreparedOwned(a, try codec.decode(a, encoded, prepared, prepared.id), prepared, prepared.id);
    try std.testing.expectEqual(proved.transcript_digest, actual);
    var bad = try codec.decode(a, encoded, prepared, prepared.id);
    bad.compact_claims[0] = bad.compact_claims[0].add(core.fields.qm31.QM31.one());
    try std.testing.expectError(error.UnclosedExecutionRelations, api.verifyPreparedOwned(a, bad, prepared, prepared.id));
    const old = try api.PreparedVerifier.init(a, &native.statement, pin, config);
    defer old.deinit();
    try std.testing.expectError(error.InvalidExecutionArtifactVersion, codec.decode(a, encoded, old, old.id));
    var captured = try api.verifyPreparedCaptureOwned(a, try codec.decode(a, encoded, prepared, prepared.id), prepared, prepared.id);
    defer captured.deinit();
    try @import("blake3_extension_replay_test_support.zig").check(a, prepared, &captured, prepared.id);
    captured.compact_claims[0] = captured.compact_claims[0].add(core.fields.qm31.QM31.one());
    try std.testing.expectError(error.InvalidExecutionCapture, captured.validate(prepared, prepared.id));
    captured.compact_claims[0] = captured.compact_claims[0].sub(core.fields.qm31.QM31.one());
    if (recurse) {
        var parent = try @import("../recursion/blake3_execution_parent_preparation.zig").prepare(a, prepared, &captured, prepared.id, 2);
        defer parent.deinit();
        try @import("blake3_parent_profile_test_support.zig").checkWithBackend(ParentBackend, a, &parent, 24 * 1024 * 1024 * 1024);
        std.debug.print("COMPACT_RECURSIVE_PARENT child_queries=70 child_pow_bits=26 parent_queries=70 parent_pow_bits=26 independently_verified=true\n", .{});
    }
    std.debug.print("COMPACT_BASE_PROOF queries={d} pow_bits={d} bytes={d} independently_verified=true\n", .{ config.fri_config.n_queries, config.pow_bits, encoded.len });
}
