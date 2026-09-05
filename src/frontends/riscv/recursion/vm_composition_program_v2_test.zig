const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const affine = @import("../air/guest_precompile/secp256k1_affine.zig");
const keccak_direct = @import("../air/guest_precompile/keccakf_direct.zig");
const keccak_interaction =
    @import("../air/guest_precompile/keccakf_interaction_plan.zig");
const keccak_relations =
    @import("../air/guest_precompile/keccakf_relations.zig");
const keccak_table =
    @import("../air/guest_precompile/keccakf_table_component.zig");
const keccak_tables = @import("../air/guest_precompile/keccakf_tables.zig");
const keccak_trace = @import("../air/guest_precompile/keccakf_trace.zig");
const keccak_witness = @import("../air/guest_precompile/keccakf_witness.zig");
const secp_config =
    @import("../air/guest_precompile/secp256k1_component_config.zig");
const ethereum_statement =
    @import("../air/guest_precompile/ethereum_statement.zig");
const lookup_batch = @import("../air/lang/lookup_batch_execution.zig");
const lookup_manifest_mod =
    @import("../air/lang/lookup_physical_manifest_v2.zig");
const relations_mod = @import("../air/relation_challenges.zig");
const trace = @import("../runner/trace.zig");
const support = @import("ethereum_leaf_context_v1_test_support.zig");
const geometry_mod = @import("vm_composition_base_geometry_v2.zig");
const lookup_compiler_mod = @import("vm_selected_lookup_compiler_v2.zig");
const profile_mod = @import("vm_air_profile_v2.zig");
const circuit = @import("vm_air_composition_circuit.zig");
const ethereum_relations = @import("ethereum_composition_relations_v2.zig");
const extension_geometry =
    @import("ethereum_composition_extension_geometry_v2.zig");
const program_v2 = @import("ethereum_vm_composition_program_v2.zig");
const program_field_authority =
    @import("ethereum_vm_program_field_authority_v1.zig");
const verified_program_descriptor =
    @import("ethereum_vm_verified_program_descriptor_v1.zig");
const provider_authority =
    @import("../prover/memory_provider_shards/authority.zig");
const provider_program = @import("provider_shard_composition_program_v1.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const shard_planner = @import("stwo_prover_engine").pcs.residency_shard_plan;

test "authenticated VM AIR ProfileV2 composition geometry is cold-derived" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    var geometry = try geometry_mod.GeometryV2.init(
        allocator,
        &fixture.profile,
    );
    defer geometry.deinit();
    try geometry.validateAgainst(&fixture.profile);
    try std.testing.expectEqual(
        fixture.profile.input_profile.sampled_value_count,
        geometry.sampled_value_count,
    );
    try std.testing.expectEqual(
        @as(usize, fixture.profile.preprocessed_column_count),
        geometry.columns[geometry_mod.PREPROCESSED_TREE].len,
    );
    try std.testing.expectEqual(
        @as(usize, fixture.profile.interaction_column_count),
        geometry.columns[geometry_mod.INTERACTION_TREE].len,
    );
    const interaction = geometry.columns[geometry_mod.INTERACTION_TREE][0];
    try std.testing.expectEqual(@as(u8, 2), interaction.sample_count);
    try std.testing.expectEqual(
        geometry_mod.RowOffset.previous,
        interaction.samples[1],
    );

    geometry.columns[geometry_mod.MAIN_TREE][0].log_size += 1;
    geometry_mod.testing.reseal(&geometry);
    try std.testing.expectError(
        error.InvalidProfileAuthority,
        geometry.validateAgainst(&fixture.profile),
    );
}

test "authenticated VM AIR ProfileV2 provider shard program cold-reopens typed plan" {
    const allocator = std.testing.allocator;
    const calls = try providerCalls(allocator, 33);
    defer allocator.free(calls);
    var plan = try provider_authority.ProviderShardPlanV1.create(
        allocator,
        [_]u8{0x5a} ** 32,
        calls,
        providerResidencyRequest(calls.len),
    );
    defer plan.deinit(allocator);
    const input = provider_program.CompilerInputV1{
        .plan = &plan,
        .calls = calls,
        .shard_index = 1,
    };
    var program = try provider_program.compile(allocator, input);
    defer program.deinit();
    try program.validateAgainst(input);
    try std.testing.expectEqual(@as(u64, 16), program.geometry.first_call);
    try std.testing.expectEqual(@as(u32, 16), program.geometry.call_count);
    try std.testing.expectEqual(@as(u32, 4), program.geometry.log_size);
    try std.testing.expectEqual(
        @as(u32, provider_program.SAMPLED_VALUE_COUNT),
        program.input_profile.sampled_value_count,
    );
    try std.testing.expectEqual(
        @as(u32, provider_program.CLAIMED_SUM_COUNT),
        program.input_profile.claimed_sum_count,
    );

    var mutated = false;
    for (program.nodes) |*node| switch (node.op) {
        .constant => |*words| {
            words[0] +%= 1;
            mutated = true;
            break;
        },
        else => {},
    };
    try std.testing.expect(mutated);
    try provider_program.testing.reseal(&program);
    try program.validate();
    try std.testing.expectError(
        error.ProviderShardVerifierProgramMismatch,
        program.validateAgainst(input),
    );
}

test "authenticated VM AIR ProfileV2 selected compiler binds mul eleven batches" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    var compiler = try lookup_compiler_mod.CompilerV2.init(
        allocator,
        &fixture.statement,
        &fixture.manifest,
        &fixture.authenticated,
        &fixture.profile,
    );
    try compiler.validateAuthority(
        allocator,
        &fixture.statement,
        &fixture.manifest,
        &fixture.authenticated,
        &fixture.profile,
    );
    const physical = fixture.manifest.entryForFamily(.mul);
    try std.testing.expectEqual(@as(u32, 11), physical.lookup_authority.batch_count);
    try std.testing.expectEqual(
        @as(u32, 11),
        compiler.programForFamily(.mul).batch_count,
    );

    const profile_entry = lookupEntry(&fixture.profile, .mul) orelse
        return error.TestUnexpectedResult;
    var main = [_]QM31{QM31.zero()} ** trace.MAX_FAMILY_COLUMNS;
    var entries = try lookup_compiler_mod.buildTypedEntries(
        QM31,
        .mul,
        main[0..trace.nColumnsForFamily(.mul)],
    );
    const relations = relations_mod.Relations.dummy();
    for (physical.activeBatches(), 0..) |batch, batch_index| {
        const actual = try lookup_compiler_mod.rowPairForProfileEntry(
            QM31,
            &compiler,
            profile_entry,
            &fixture.manifest,
            &entries,
            batch_index,
            &relations,
        );
        const expected = try lookup_batch.rowPairFromRange(
            &entries,
            batch.first_entry,
            batch.entry_count,
            &relations,
        );
        try expectPair(expected, actual);
    }

    compiler.families[@intFromEnum(trace.OpcodeFamily.mul)]
        .authority.program_identity[0] ^= 1;
    lookup_compiler_mod.testing.reseal(&compiler);
    try std.testing.expectError(
        error.InvalidFamilyAuthority,
        compiler.validateAgainstManifest(&fixture.manifest),
    );
}

test "Ethereum extension evaluators replay over the canonical recording scalar" {
    const allocator = std.testing.allocator;
    var builder = circuit.Builder.init(allocator);
    defer builder.deinit();
    circuit.installBuilder(&builder);
    defer circuit.uninstallBuilder();

    const zero_pair = [2]circuit.Scalar{
        circuit.Scalar.fromBase(M31.fromCanonical(2)),
        circuit.Scalar.fromBase(M31.fromCanonical(3)),
    };
    const base_draws = [_][2]circuit.Scalar{zero_pair} **
        ethereum_relations.BASE_RELATION_COUNT;
    const extension_draws = [_][2]circuit.Scalar{zero_pair} **
        ethereum_relations.EXTENSION_RELATION_COUNT;
    const relations = ethereum_relations.RelationsV2.init(
        base_draws,
        extension_draws,
    );

    inline for (.{
        secp_config.Product(affine.ModulusKind.base),
        secp_config.Product(affine.ModulusKind.scalar),
        secp_config.Linear(affine.ModulusKind.base),
        secp_config.Linear(affine.ModulusKind.scalar),
        secp_config.Point,
        secp_config.Split,
        secp_config.ScalarProgram,
        secp_config.Table,
        secp_config.Recovery,
        secp_config.ByteTable,
        secp_config.RecoveryCaller,
    }) |Config| try recordSecpConfig(Config, &relations.secp);

    var main = [_]circuit.Scalar{circuit.Scalar.zero()} **
        keccak_trace.Layout.main_columns;
    var previous_io = [_]circuit.Scalar{circuit.Scalar.zero()} **
        (2 * keccak_relations.io_arity);
    var state = [_]circuit.Scalar{circuit.Scalar.zero()} **
        keccak_witness.state_cell_count;
    var selectors = [_]circuit.Scalar{circuit.Scalar.zero()} **
        keccak_witness.row_count;
    var sink = CountingSink{};
    try keccak_direct.evaluateGeneric(
        circuit.Scalar,
        &main,
        &previous_io,
        &state,
        &state,
        &state,
        &state,
        &selectors,
        circuit.Scalar.zero(),
        &sink,
    );
    try std.testing.expectEqual(keccak_direct.constraint_count, sink.count);
    _ = try keccak_interaction.rowPairsGeneric(
        circuit.Scalar,
        &main,
        &state,
        &state,
        &selectors,
        &relations.keccak,
    );
    const tuple = [_]circuit.Scalar{circuit.Scalar.zero()} **
        keccak_tables.arity;
    inline for (.{ keccak_tables.Kind.chi, keccak_tables.Kind.xor5 }) |kind| {
        _ = try keccak_table.evaluateRowGeneric(
            circuit.Scalar,
            kind,
            &tuple,
            circuit.Scalar.zero(),
            circuit.Scalar.zero(),
            circuit.Scalar.zero(),
            circuit.Scalar.zero(),
            circuit.Scalar.zero(),
            &relations.keccak,
        );
    }
    try builder.check();
}

test "Ethereum extension mask geometry is derived from production vtables" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    const extension = try ethereum_statement.Statement.canonical(
        &fixture.statement,
        0,
        0,
        support.emptySecpShapes(),
    );
    var geometry = try extension_geometry.GeometryV2.init(
        allocator,
        &fixture.profile,
        &fixture.statement,
        &extension,
    );
    defer geometry.deinit();
    try geometry.validateAgainst(
        &fixture.profile,
        &fixture.statement,
        &extension,
    );
    try std.testing.expectEqual(
        fixture.profile.main_column_count,
        geometry.base_column_counts[1],
    );
    const keccak_main = geometry.components[0].spans[1];
    try std.testing.expectEqual(
        @as(u8, 6),
        geometry.columns[1][keccak_main.offset + keccak_trace.Layout.state]
            .sample_count,
    );
    const secp_main = geometry.components[3].spans[1];
    try std.testing.expectEqual(
        @as(u8, 3),
        geometry.columns[1][secp_main.offset].sample_count,
    );
    try std.testing.expectEqual(
        @as(u32, 0),
        geometry.components[1].direct_constraint_count,
    );
    try std.testing.expectEqual(
        @as(u32, 1),
        geometry.components[1].interaction_batch_count,
    );
    try std.testing.expect(geometry.detailed_claim_count > 1000);

    geometry.columns[1][keccak_main.offset].log_size += 1;
    extension_geometry.testing.reseal(&geometry);
    try geometry.validate();
    try std.testing.expectError(
        error.InvalidExtensionAuthority,
        geometry.validateAgainst(
            &fixture.profile,
            &fixture.statement,
            &extension,
        ),
    );
}

test "authenticated VM AIR ProfileV2 cold-compiles the Ethereum verifier program" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    const extension = try ethereum_statement.Statement.canonical(
        &fixture.statement,
        0,
        0,
        support.emptySecpShapes(),
    );
    const input = program_v2.CompilerInputV2{
        .core_statement = &fixture.statement,
        .extension_statement = &extension,
        .lookup_manifest = &fixture.manifest,
        .authenticated_lookup = &fixture.authenticated,
        .base_profile = &fixture.profile,
    };
    var program = try program_v2.compile(allocator, input);
    defer program.deinit();
    try program.validateAgainst(input);
    try std.testing.expectEqual(@as(u32, 25), program.input_profile.relation_challenge_count);
    try std.testing.expectEqual(@as(u32, 42), program.input_profile.transcript_claimed_sum_count);
    try std.testing.expect(program.nodes.len > program.bindings.len);

    var mutated = false;
    for (program.nodes) |*node| switch (node.op) {
        .constant => |words| {
            var replacement = words;
            replacement[0] = if (replacement[0] == 0) 1 else 0;
            node.op = .{ .constant = replacement };
            mutated = true;
            break;
        },
        else => {},
    };
    try std.testing.expect(mutated);
    try program_v2.testing.reseal(&program);
    try program.validate();
    try std.testing.expectError(
        error.VerifierProgramMismatch,
        program.validateAgainst(input),
    );
}

test "authenticated VM AIR ProfileV2 has a cold-recompiled field-native authority" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    const extension = try ethereum_statement.Statement.canonical(
        &fixture.statement,
        0,
        0,
        support.emptySecpShapes(),
    );
    const input = program_v2.CompilerInputV2{
        .core_statement = &fixture.statement,
        .extension_statement = &extension,
        .lookup_manifest = &fixture.manifest,
        .authenticated_lookup = &fixture.authenticated,
        .base_profile = &fixture.profile,
    };
    var program = try program_v2.compile(allocator, input);
    defer program.deinit();
    const authority = try program_field_authority.compile(
        allocator,
        &program,
        input,
    );
    try authority.validateAgainst(allocator, &program, input);
    try std.testing.expect(authority.program_word_count > program.nodes.len);
    try std.testing.expect(authority.manifest_word_count > fixture.profile.entries.len);

    var changed_program = authority;
    changed_program.verifier_program_authority[0] +%= 1;
    try std.testing.expectError(
        error.InvalidEthereumVmFieldAuthority,
        changed_program.validateAgainst(allocator, &program, input),
    );
    var changed_manifest = authority;
    changed_manifest.component_manifest_authority[0] +%= 1;
    try std.testing.expectError(
        error.InvalidEthereumVmFieldAuthority,
        changed_manifest.validateAgainst(allocator, &program, input),
    );
}

test "authenticated VM AIR ProfileV2 descriptor transports compiler and Tree0 custody" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    const extension = try ethereum_statement.Statement.canonical(
        &fixture.statement,
        0,
        0,
        support.emptySecpShapes(),
    );
    const input = program_v2.CompilerInputV2{
        .core_statement = &fixture.statement,
        .extension_statement = &extension,
        .lookup_manifest = &fixture.manifest,
        .authenticated_lookup = &fixture.authenticated,
        .base_profile = &fixture.profile,
    };
    var program = try program_v2.compile(allocator, input);
    defer program.deinit();

    const tree0 = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const proof_capture = [_]u8{0x5a} ** 32;
    const capture_identity = [_]u8{0xa5} ** 32;
    const descriptor = verified_program_descriptor.project(
        &program,
        tree0,
        proof_capture,
        capture_identity,
    );
    try descriptor.validateAgainstProgram(&program);
    const encoded = try descriptor.encodeCanonical();
    const decoded = try verified_program_descriptor.DescriptorV1
        .decodeCanonical(&encoded);
    try std.testing.expectEqualDeep(descriptor, decoded);

    var changed_tree0 = tree0;
    changed_tree0[0] += 1;
    const changed = verified_program_descriptor.project(
        &program,
        changed_tree0,
        proof_capture,
        capture_identity,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &descriptor.instance_sha256,
        &changed.instance_sha256,
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        &descriptor.descriptor_sha256,
        &changed.descriptor_sha256,
    ));

    var corrupted = encoded;
    corrupted[64] ^= 1;
    try std.testing.expectError(
        error.InvalidVerifiedProgramDescriptor,
        verified_program_descriptor.DescriptorV1.decodeCanonical(&corrupted),
    );
}

const CountingSink = struct {
    count: usize = 0,

    pub fn add(self: *CountingSink, _: circuit.Scalar, _: u8) void {
        self.count += 1;
    }
};

fn recordSecpConfig(comptime Config: type, relations: anytype) !void {
    var main = [_]circuit.Scalar{circuit.Scalar.zero()} **
        Config.main_column_count;
    var previous = [_]circuit.Scalar{circuit.Scalar.zero()} **
        Config.main_column_count;
    var next = [_]circuit.Scalar{circuit.Scalar.zero()} **
        Config.main_column_count;
    var sink = CountingSink{};
    Config.evaluate(
        circuit.Scalar,
        &main,
        &previous,
        &next,
        circuit.Scalar.zero(),
        circuit.Scalar.zero(),
        relations,
        &sink,
    );
    try std.testing.expectEqual(Config.direct_constraint_count, sink.count);
    _ = Config.rowPairs(
        circuit.Scalar,
        &main,
        &previous,
        &next,
        relations,
    );
}

test "authenticated VM AIR ProfileV2 rejects aggregate sample-count substitution" {
    const allocator = std.testing.allocator;
    var statement = support.retainedSegmentZeroCore();
    var manifest = lookup_manifest_mod.Manifest.native();
    const authenticated = try lookup_manifest_mod.AuthenticatedStatement.init(
        &statement,
        &manifest,
    );
    const facts = try profile_mod.testing.expectedFacts(
        allocator,
        &statement,
        &manifest,
    );
    defer allocator.free(facts);
    const exact = try geometry_mod.expectedSampledValueCount(
        &statement,
        &manifest,
    );
    var profile = try profile_mod.testing.deriveFromFacts(
        allocator,
        &statement,
        &manifest,
        &authenticated,
        facts,
        exact + 1,
    );
    defer profile.deinit();
    try std.testing.expectError(
        error.SampledValueCountMismatch,
        geometry_mod.GeometryV2.init(allocator, &profile),
    );
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    statement: @import("../air/statement.zig").RiscVStatement,
    manifest: lookup_manifest_mod.Manifest,
    authenticated: lookup_manifest_mod.AuthenticatedStatement,
    facts: []profile_mod.Facts,
    profile: profile_mod.ProfileV2,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var statement = support.retainedSegmentZeroCore();
        var manifest = lookup_manifest_mod.Manifest.native();
        const authenticated = try lookup_manifest_mod.AuthenticatedStatement.init(
            &statement,
            &manifest,
        );
        const facts = try profile_mod.testing.expectedFacts(
            allocator,
            &statement,
            &manifest,
        );
        errdefer allocator.free(facts);
        const sampled = try geometry_mod.expectedSampledValueCount(
            &statement,
            &manifest,
        );
        const profile = try profile_mod.testing.deriveFromFacts(
            allocator,
            &statement,
            &manifest,
            &authenticated,
            facts,
            sampled,
        );
        return .{
            .allocator = allocator,
            .statement = statement,
            .manifest = manifest,
            .authenticated = authenticated,
            .facts = facts,
            .profile = profile,
        };
    }

    fn deinit(self: *Fixture) void {
        self.profile.deinit();
        self.allocator.free(self.facts);
        self.* = undefined;
    }
};

fn lookupEntry(
    profile: *const profile_mod.ProfileV2,
    family: trace.OpcodeFamily,
) ?profile_mod.EntryV2 {
    for (profile.entries) |entry| switch (entry.registry) {
        .opcode_lookup => |key| if (key.family == family) return entry,
        else => {},
    };
    return null;
}

fn expectPair(expected: anytype, actual: anytype) !void {
    try std.testing.expect(expected.n1.eql(actual.n1));
    try std.testing.expect(expected.d1.eql(actual.d1));
    try std.testing.expect(expected.n2.eql(actual.n2));
    try std.testing.expect(expected.d2.eql(actual.d2));
}

fn providerCalls(
    allocator: std.mem.Allocator,
    count: usize,
) ![]poseidon2_air.Call {
    const result = try allocator.alloc(poseidon2_air.Call, count);
    for (result, 0..) |*call, index| call.* =
        poseidon2_air.Call.narrowWithOutput(
            @intCast(index + 1),
            @intCast(index + 2),
            @intCast(index + 3),
        );
    return result;
}

fn providerResidencyRequest(count: usize) shard_planner.Request {
    return .{
        .logical_row_count = @intCast(count),
        .column_count = provider_authority.main_column_count,
        .min_shard_log_size = 4,
        .max_shard_log_size = 4,
        .log_blowup_factor = 1,
        .retention_policy = .never,
        .host_byte_budget = 1024 * 1024 * 1024,
        .reserved_host_bytes = 0,
        .requested_parallel_shards = 1,
    };
}
