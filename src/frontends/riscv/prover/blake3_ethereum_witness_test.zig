const std = @import("std");
const core = @import("stwo_core");
const runner = @import("../runner/mod.zig");
const public = @import("../air/public_data.zig");
const witness = @import("blake3_ethereum_witness.zig");
test "BLAKE3 execution commitment Ethereum external witness census" {
    check(false, false, false) catch |err| {
        std.debug.print("BLAKE3 Ethereum integration failed: {s}\n", .{@errorName(err)});
        return err;
    };
}
test "BLAKE3 execution commitment Ethereum full proof independently verifies" {
    check(true, false, false) catch |err| {
        std.debug.print("BLAKE3 Ethereum full proof failed: {s}\n", .{@errorName(err)});
        return err;
    };
}
test "BLAKE3 execution commitment Ethereum recursive parent independently verifies" {
    try check(true, true, false);
}
test "BLAKE3 execution commitment Ethereum canonical recursive parent independently verifies" {
    try check(true, true, true);
}
fn check(comptime prove: bool, comptime recurse: bool, comptime canonical_parent: bool) !void {
    const a = std.testing.allocator;
    const pool_mod = @import("stwo_prover_engine").work_pool;
    var pool: pool_mod.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try pool_mod.ScopedPoolBinding.init(&pool);
    var binding_alive = true;
    defer if (binding_alive) binding.deinit();
    const fixture = @import("../runner/guest_precompile/test_elf.zig");
    const diagnostic_elf = fixture.buildEthereumWithCompletion(.self_loop);
    const elf = fixture.withReleaseAbi(diagnostic_elf.len, &diagnostic_elf);
    var run = try runner.runEthereumExtensionWithInput(a, &elf, &.{}, 100);
    defer run.deinit();
    try std.testing.expectEqual(@as(usize, 1), run.signer_recovery_calls.len());
    try std.testing.expectEqual(@as(usize, 1), run.keccakf_calls.len());
    const base = &run.base;
    const outputs = try a.alloc(public.OutputWord, base.output_words.len);
    defer a.free(outputs);
    for (outputs, base.output_words) |*target, word| target.* = .{ .addr = word.addr, .value = word.value, .clock = word.clock };
    const data = public.Blake3PublicData{
        .initial_pc = base.initial_pc,
        .final_pc = base.final_pc,
        .clock = @intCast(base.step_count),
        .initial_regs = base.initial_regs,
        .final_regs = base.final_regs,
        .reg_last_clock = base.state_chain_tracker.reg_last_clk,
        .program_root = null,
        .initial_rw_root = null,
        .final_rw_root = null,
        .completion = try public.completionFromRun(base.*),
        .io_entries = .{ .input_start = base.input_start, .input_len = 0, .input_words = &.{}, .output_len = 0, .output_len_addr = base.output_len_addr, .output_data_addr = base.output_data_addr, .output_words = outputs },
    };
    try std.testing.expect(outputs.len != 0);
    var missing_output = data;
    missing_output.io_entries.output_words = &.{};
    try std.testing.expectError(error.InvalidExecutionPublicIo, witness.Owner.init(a, &run, missing_output));
    var owned = witness.Owner.initRun(a, &run) catch |err| {
        std.debug.print("Ethereum BLAKE3 witness construction: {s}\n", .{@errorName(err)});
        return err;
    };
    var owned_alive = true;
    defer if (owned_alive) owned.deinit();
    try std.testing.expectEqual(@as(u32, 2), owned.native.external_retirements);
    if (!prove) {
        const admission_api = @import("blake3_ethereum_statement.zig");
        const sha_bounds = @import("../air/guest_precompile/sha256_coefficient_bounds.zig");
        const pin = try owned.admission();
        const combined_statement = @import("blake3_ethereum_sha_statement.zig").Statement;
        const combined = try combined_statement.canonical(a, &owned.native.statement, pin, owned.hashes.logs, 1, 1, 0, owned.extension.shapes());
        var mutated = combined;
        mutated.sha.descriptors[0].semantic_digest[0] ^= 1;
        try std.testing.expectError(error.InvalidShaComponentProfile, mutated.validate(a, &owned.native.statement, pin, owned.hashes.logs));
        mutated = combined;
        mutated.ethereum.admission.memory_relation_terms += 1;
        try std.testing.expectError(error.AdmissionCertificateMismatch, mutated.validate(a, &owned.native.statement, pin, owned.hashes.logs));
        const canonical_config = @import("../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG;
        var combined_channel = core.proof_suites.Blake3.Channel{};
        var old_channel = core.proof_suites.Blake3.Channel{};
        try combined.mix(a, &combined_channel, canonical_config, &owned.native.statement, pin, owned.hashes.logs);
        try @import("blake3_ethereum_protocol.zig").mix(&old_channel, canonical_config, &owned.native.statement, &owned.statement, pin, owned.hashes.logs);
        try std.testing.expect(!std.mem.eql(u8, &combined_channel.digestBytes(), &old_channel.digestBytes()));
        const empty_sha = try sha_bounds.derive(a, 0);
        const with_empty_sha = try admission_api.admissionWithSha(a, &owned.native.statement, pin, owned.hashes.logs, 1, 1, 0);
        try std.testing.expectEqual(owned.statement.admission.extra_memory_terms, with_empty_sha.extra_memory_terms);
        try std.testing.expectEqual(owned.statement.admission.memory_relation_terms, with_empty_sha.memory_relation_terms);
        for (with_empty_sha.extended_fixed_table_bounds, owned.statement.admission.extended_fixed_table_bounds, empty_sha.tables) |actual, previous, extra| try std.testing.expectEqual(previous + extra, actual);
        // Coefficient admission checks retirement geometry, not program semantics:
        // substitute one SHA for one recovery at the same external count.
        const single_sha = try sha_bounds.derive(a, 1);
        const with_sha = try admission_api.admissionWithSha(a, &owned.native.statement, pin, owned.hashes.logs, 1, 0, 1);
        try std.testing.expectEqual(owned.statement.admission.extra_memory_terms - 40 + 23, with_sha.extra_memory_terms);
        try std.testing.expectEqual(owned.statement.admission.memory_relation_terms - 40 + 23, with_sha.memory_relation_terms);
        var expected = owned.statement.admission.extended_fixed_table_bounds;
        const Kind = @import("../air/lookups/tables/schema.zig").Kind;
        expected[@intFromEnum(Kind.range_check_20)] -= 43;
        expected[@intFromEnum(Kind.range_check_8_8)] -= 1;
        expected[@intFromEnum(Kind.range_check_8_8_4)] -= 1;
        for (&expected, single_sha.tables) |*value, extra| value.* += extra;
        try std.testing.expectEqualDeep(expected, with_sha.extended_fixed_table_bounds);
        try std.testing.expectError(error.InvalidStatement, admission_api.admissionWithSha(a, &owned.native.statement, pin, owned.hashes.logs, 1, 1, 1));
    }
    try owned.native.statement.validateBlake3ExecutionWithExternal(2);
    try std.testing.expectError(error.InvalidStatement, owned.native.statement.validateBlake3ExecutionWithExternal(1));
    try std.testing.expectError(error.InvalidStatement, owned.native.statement.validateBlake3Execution());
    var channel = core.proof_suites.Blake3.Channel{};
    const config = core.pcs.PcsConfig{ .pow_bits = if (prove and (!recurse or canonical_parent)) 26 else 0, .fri_config = try core.fri.FriConfig.init(0, 1, if (prove and (!recurse or canonical_parent)) 70 else 8) };
    const source_api = @import("blake3_execution_source.zig");
    const source = try source_api.validateProfile(.rv32im_zkvm_ethereum_v1, a, &elf, &.{}, &owned.native.statement.public_data);
    try std.testing.expectError(error.MissingReleaseAbiSymbol, source_api.validateProfile(.rv32im_zkvm_ethereum_v1, a, &diagnostic_elf, &.{}, &owned.native.statement.public_data));
    const manifest = @import("blake3_ethereum_manifest.zig");
    const metadata = try manifest.encode(a, &owned.native.statement, owned.statement, try owned.admission(), config, source, .{});
    defer a.free(metadata);
    const statement_id = manifest.identity(metadata);
    {
        var decoded_metadata = try manifest.decode(a, metadata, statement_id, source, config, .{});
        defer decoded_metadata.deinit();
        try std.testing.expectEqualDeep(owned.statement, decoded_metadata.extension);
        try std.testing.expectEqualSlices(u32, &owned.hashes.logs, &(try @import("blake3_commitment_columns.zig").traceLogs(a, try decoded_metadata.base.admission())));
        const inner = metadata[manifest.PREFIX_BYTES..];
        const base_manifest = @import("blake3_execution_manifest.zig");
        try std.testing.expectError(error.InvalidStatement, base_manifest.decode(a, inner, base_manifest.identity(inner), source, config, .{}));
    }
    var wrong_source = source;
    wrong_source.elf_sha256[31] ^= 1;
    try std.testing.expectError(error.ExecutionSourceMismatch, manifest.decode(a, metadata, statement_id, wrong_source, config, .{}));
    var fail_before_allocation = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    metadata[12] ^= 1;
    try std.testing.expectError(error.UntrustedExecutionManifest, manifest.decode(fail_before_allocation.allocator(), metadata, statement_id, source, config, .{}));
    metadata[12] ^= 1;
    // An external native prefix cannot masquerade as a complete base proof.
    try std.testing.expectError(error.InvalidStatement, @import("blake3_execution_protocol.zig").mix(&channel, config, &owned.native.statement, try owned.admission()));
    try std.testing.expect(!owned.native.interaction_ready);
    for (owned.native.statement.infra_descs[0..owned.native.statement.n_infra]) |desc| switch (desc.kind) {
        .program, .memory, .merkle, .poseidon2 => return error.LegacyCommitmentInBlake3Execution,
        else => {},
    };
    // Every external fetch must be represented in the full-width program plan.
    for (run.keccakf_execution_rows.rows()) |row| try expectFetch(&owned, row.pc);
    for (run.signer_recovery_execution_rows.rows()) |row| try expectFetch(&owned, row.pc);
    try std.testing.expect(owned.native.tables_ready);
    var invalid = data;
    invalid.clock += 1;
    try std.testing.expectError(error.InvalidExecutionTrace, witness.Owner.init(a, &run, invalid));
    std.debug.print("BLAKE3_ETHEREUM_WITNESS_READY external_retirements=2\n", .{});
    if (comptime prove) {
        const Api = @import("blake3_ethereum_proof.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend);
        const prepared = blk: {
            var decoded_metadata = try manifest.decode(a, metadata, statement_id, source, config, .{});
            defer decoded_metadata.deinit();
            break :blk try Api.PreparedVerifier.init(a, &decoded_metadata.base.statement.value, decoded_metadata.extension, try decoded_metadata.base.admission(), config);
        };
        defer prepared.deinit();
        const expected = prepared.id;
        var wrong = expected;
        wrong[0] ^= 1;
        try std.testing.expectError(error.UntrustedExecutionKey, Api.prove(a, &owned, prepared, wrong, &pool));
        try std.testing.expect(!owned.native.interaction_ready);
        const certificate = prepared.extension.admission;
        prepared.extension.admission.memory_relation_terms += 1;
        try std.testing.expectError(error.AdmissionCertificateMismatch, prepared.validate(expected));
        prepared.extension.admission = certificate;
        const codec = @import("blake3_ethereum_codec.zig");
        const leaf = try leafArtifact(canonical_parent, a, &owned, prepared, expected, &pool);
        const raw = leaf.raw;
        defer a.free(raw);
        owned.deinit();
        owned_alive = false;
        outputs[0].value ^= 1;
        try prepared.validate(expected);
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
        const no_alloc = failing.allocator();
        try std.testing.expectError(error.InvalidExecutionArtifactLength, codec.decode(no_alloc, raw[0 .. raw.len - 1], prepared, expected));
        raw[0] ^= 1;
        try std.testing.expectError(error.InvalidExecutionArtifactVersion, codec.decode(no_alloc, raw, prepared, expected));
        raw[0] ^= 1;
        raw[12] ^= 1;
        try std.testing.expectError(error.UntrustedExecutionKey, codec.decode(no_alloc, raw, prepared, expected));
        raw[12] ^= 1;
        const first = raw[codec.HEADER_BYTES..][0..4].*;
        std.mem.writeInt(u32, raw[codec.HEADER_BYTES..][0..4], core.fields.m31.Modulus, .little);
        try std.testing.expectError(error.InvalidInteractionClaim, codec.decode(no_alloc, raw, prepared, expected));
        @memcpy(raw[codec.HEADER_BYTES..][0..4], &first);
        var decoded = try codec.decode(a, raw, prepared, expected);
        var decoded_alive = true;
        defer if (decoded_alive) decoded.deinit(a);
        const roundtrip = try codec.encode(a, &decoded, prepared, expected);
        defer a.free(roundtrip);
        try std.testing.expectEqualSlices(u8, raw, roundtrip);
        const artifact = @import("blake3_profile_artifact.zig").ForProfile(true);
        const published = try artifact.encode(a, &decoded, prepared, &elf, &.{}, .{});
        defer a.free(published.bytes);
        try std.testing.expectEqualSlices(u8, &statement_id, &published.statement_id);
        const fresh_digest = try artifact.ForBackend(@import("stwo_cpu_backend").CpuBackend).verify(a, published.bytes, statement_id, config, &elf, &.{}, .{});
        if (leaf.digest) |digest| try std.testing.expectEqualSlices(u8, &digest, &fresh_digest);
        var wrong_statement = statement_id;
        wrong_statement[31] ^= 1;
        try std.testing.expectError(error.UntrustedExecutionManifest, artifact.ForBackend(@import("stwo_cpu_backend").CpuBackend).verify(a, published.bytes, wrong_statement, config, &elf, &.{}, .{}));
        try std.testing.expectError(error.InvalidExecutionArtifactLength, artifact.split(published.bytes[0 .. published.bytes.len - 1], .{}));
        try std.testing.expectError(error.InvalidExecutionArtifactVersion, @import("blake3_execution_artifact.zig").split(published.bytes, .{}));
        decoded_alive = false;
        var captured = try Api.verifyCaptureOwned(a, decoded, prepared, expected);
        defer captured.deinit();
        try captured.validate(prepared, expected);
        if (leaf.digest) |digest| try std.testing.expectEqualSlices(u8, &digest, &captured.final_channel.digestBytes());
        const draw = captured.extension_draws[0];
        captured.extension_draws[0] = draw.add(core.fields.qm31.QM31.one());
        try std.testing.expectError(error.InvalidExecutionCapture, captured.validate(prepared, expected));
        captured.extension_draws[0] = draw;
        captured.extension_placements[0].main_offset += 1;
        try std.testing.expectError(error.InvalidExecutionCapture, captured.validate(prepared, expected));
        captured.extension_placements[0].main_offset -= 1;
        const power = captured.relations.elements[0].alpha_powers[0];
        captured.relations.elements[0].alpha_powers[0] = core.fields.qm31.QM31.zero();
        try std.testing.expectError(error.InvalidExecutionCapture, captured.validate(prepared, expected));
        captured.relations.elements[0].alpha_powers[0] = power;
        try captured.validate(prepared, expected);
        const digest = try Api.verifyOwned(a, try codec.decode(a, raw, prepared, expected), prepared, expected);
        try std.testing.expectEqualSlices(u8, &captured.final_channel.digestBytes(), &digest);
        if (!recurse) try @import("blake3_extension_replay_test_support.zig").check(a, prepared, &captured, expected);
        if (recurse) {
            binding.deinit();
            binding_alive = false;
            checkParent(canonical_parent, a, prepared, &captured, expected, &pool) catch |err| {
                std.debug.print("BLAKE3_ETHEREUM_PARENT_FAILED error={s}\n", .{@errorName(err)});
                return err;
            };
        }
        std.debug.print("BLAKE3_ETHEREUM_PROOF verified=true keccak=1 signer=1 queries={d} pow_bits={d} witness_released=true admission_independent=true artifact_roundtrip=true capture_mutations_rejected=true\n", .{ config.fri_config.n_queries, config.pow_bits });
    } else try checkClosure(a, &owned, &pool);
    std.debug.print("BLAKE3_ETHEREUM_WITNESS keccak=1 signer=1 external_retirements=2 legacy_commitments=0 base_protocol_rejects=true relations_closed=true\n", .{});
}
fn expectFetch(owned: *const witness.Owner, pc: u32) !void {
    for (owned.memory.programs) |item| {
        if (item.address == pc) return;
    }
    return error.MissingExternalProgramFetch;
}

fn checkClosure(a: std.mem.Allocator, owned: *witness.Owner, pool: *@import("stwo_prover_engine").work_pool.WorkPool) !void {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{0x45544833});
    const universal = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    const shared = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&universal);
    const relations = try @import("guest_precompile/ethereum_transcript.zig").Relations.drawAfterBase(a, &channel, shared.native);
    try owned.native.generateInteractions(&shared.native);
    var hashes = try owned.hashes.interactions(a, &universal);
    defer hashes.deinit();
    var extension = try @import("guest_precompile/ethereum_interaction.zig").generate(a, &owned.extension, &relations, pool);
    defer extension.deinit(a);
    const shape = &owned.native.statement;
    const claims = &owned.native.claims;
    var total = (try @import("../air/public_logup.zig").blake3RelationSums(&shape.public_data, &shared.native)).total();
    for (shape.component_descs[0..shape.n_components], 0..) |desc, i| total = total.add(try claims.opcodeClaimTotal(desc.family, i));
    for (shape.infra_descs[0..shape.n_infra], 0..) |desc, i| total = total.add(try claims.infraClaimTotal(desc.kind, i));
    for (hashes.claims) |claim| total = total.add(claim);
    try std.testing.expect(!extension.claim.componentSum().isZero());
    try std.testing.expect(!total.isZero());
    const residual = total.add(extension.claim.componentSum());
    if (!residual.isZero()) std.debug.print("BLAKE3_ETHEREUM_CLOSURE residual={any} native_hashes={any} extension={any}\n", .{ residual, total, extension.claim.componentSum() });
    try std.testing.expect(residual.isZero());
}

const checkParent = @import("blake3_extension_parent_test_support.zig").check;

const LeafArtifact = struct { raw: []u8, digest: ?[32]u8 };
/// Optional local devex cache. Admission is always independently reconstructed;
/// cached bytes still pass bounded decode and full verification on every run.
fn leafArtifact(comptime allow_cache: bool, a: std.mem.Allocator, owner: *witness.Owner, prepared: anytype, expected: [32]u8, pool: anytype) !LeafArtifact {
    const Api = @import("blake3_ethereum_proof.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend);
    const codec = @import("blake3_ethereum_codec.zig");
    const path = if (allow_cache) std.process.getEnvVarOwned(a, "STWO_B3EH_LEAF_ARTIFACT") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    } else null;
    defer if (path) |value| a.free(value);
    if (path) |value| {
        const cached = std.fs.cwd().readFileAlloc(a, value, codec.MAX_PROOF_BYTES + 4 * 1024 * 1024) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        if (cached) |raw| {
            std.debug.print("BLAKE3_ETHEREUM_LEAF_ARTIFACT reused=true bytes={d}\n", .{raw.len});
            return .{ .raw = raw, .digest = null };
        }
    }
    var proved = try Api.prove(a, owner, prepared, expected, pool);
    defer proved.proof.deinit(a);
    const raw = try codec.encode(a, &proved.proof, prepared, expected);
    errdefer a.free(raw);
    if (path) |value| {
        try std.fs.cwd().writeFile(.{ .sub_path = value, .data = raw });
        std.debug.print("BLAKE3_ETHEREUM_LEAF_ARTIFACT reused=false bytes={d}\n", .{raw.len});
    }
    return .{ .raw = raw, .digest = proved.transcript_digest };
}
