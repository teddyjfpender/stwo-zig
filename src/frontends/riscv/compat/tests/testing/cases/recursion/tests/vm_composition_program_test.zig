const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const affine = @import("stwo_riscv_precompiles").air.secp256k1_affine;
const keccak_row = @import("stwo_riscv_rv32").air.guest_precompile.keccakf_row;
const keccak_relations =
    @import("stwo_riscv_precompiles").air.keccakf_relations;
const keccak_table =
    @import("stwo_riscv_precompiles").air.keccakf_table_component;
const keccak_tables = @import("stwo_riscv_precompiles").air.keccakf_tables;
const keccak_trace = @import("stwo_riscv_rv32").air.guest_precompile.keccakf_trace;
const keccak_witness = @import("stwo_riscv_precompiles").air.keccakf_witness;
const secp_config =
    @import("stwo_riscv_rv32").air.guest_precompile.secp256k1_component_config;
const ethereum_statement =
    @import("../../../../../../air/guest_precompile/ethereum_statement.zig");
const lookup_batch = @import("stwo_riscv_rv32").air.lang.lookup_batch_execution;
const lookup_manifest_mod =
    @import("stwo_riscv_rv32").air.lang.lookup_physical_manifest;
const relations_mod = @import("stwo_riscv_air_lang").evaluation.relation_challenges;
const trace = @import("stwo_riscv_rv32").execution.trace;
const support = @import("../../../../../product_tree/recursion/ethereum_leaf_context_test_support.zig");
const geometry_mod = @import("stwo_riscv_rv32").recursion.vm_composition_base_geometry;
const lookup_compiler_mod = @import("stwo_riscv_recursion").vm_selected_lookup_compiler;
const profile_mod = @import("../../../../../product_tree/recursion/ethereum_vm_air_profile_v2.zig");
const circuit = @import("stwo_riscv_recursion").vm_air_composition_circuit;
const ethereum_relations = @import("../../../../../product_tree/recursion/ethereum_composition_relations.zig");
const extension_geometry =
    @import("../../../../../product_tree/recursion/ethereum_composition_extension_geometry.zig");
const program_v2 = @import("../../../../../product_tree/recursion/ethereum_vm_composition_program.zig");

test "authenticated VM AIR ProfileV2 composition geometry is cold-derived" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    var geometry = try geometry_mod.ForProfile(profile_mod.ProfileV2).init(
        allocator,
        &fixture.profile,
    );
    defer geometry.deinit();
    try geometry_mod.ForProfile(profile_mod.ProfileV2).validateAgainst(&geometry, &fixture.profile);
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
        geometry_mod.ForProfile(profile_mod.ProfileV2).validateAgainst(&geometry, &fixture.profile),
    );
}

test "authenticated VM AIR ProfileV2 selected compiler binds mul eleven batches" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    var compiler = try lookup_compiler_mod.ForProfile(profile_mod.ProfileV2).init(
        allocator,
        &fixture.statement,
        &fixture.manifest,
        &fixture.authenticated,
        &fixture.profile,
    );
    try lookup_compiler_mod.ForProfile(profile_mod.ProfileV2).validateAuthority(
        &compiler,
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
    const Reader = struct {
        begin_count: usize = 0,
        batch_count: usize = 0,

        pub fn begin(self: *@This()) error{}!circuit.Scalar {
            self.begin_count += 1;
            return circuit.Scalar.zero();
        }

        pub fn at(self: *@This(), batch: usize) error{}!keccak_row.Batch(circuit.Scalar) {
            std.debug.assert(batch == self.batch_count);
            self.batch_count += 1;
            return .{
                .current = circuit.Scalar.zero(),
                .previous = circuit.Scalar.zero(),
                .claimed = circuit.Scalar.zero(),
            };
        }
    };
    var reader: Reader = .{};
    try keccak_row.evaluateGeneric(circuit.Scalar, .{
        .main = &main,
        .previous_io = &previous_io,
        .state_minus_two = &state,
        .state_minus_one = &state,
        .state_plus_one = &state,
        .state_plus_two = &state,
        .state_plus_twenty_seven = &state,
        .selectors = &selectors,
        .second_active = circuit.Scalar.zero(),
    }, &relations.keccak, &reader, &sink);
    try std.testing.expectEqual(keccak_row.constraint_count, sink.count);
    try std.testing.expectEqual(@as(usize, 1), reader.begin_count);
    try std.testing.expectEqual(keccak_row.interaction_constraint_count, reader.batch_count);
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
    std.debug.print("C3_GRAPH_RECEIPT kind=product profile={s} geometry={s} extension_geometry={s} graph={s} reference={s} schedule={s} authority={s} nodes={d} outputs={d} bindings={d}\n", .{ std.fmt.bytesToHex(program.base_profile_sha256, .lower), std.fmt.bytesToHex(program.base_geometry_sha256, .lower), std.fmt.bytesToHex(program.extension_geometry_sha256, .lower), std.fmt.bytesToHex(program.graph_sha256, .lower), std.fmt.bytesToHex(program.reference_sha256, .lower), std.fmt.bytesToHex(program.schedule_sha256, .lower), std.fmt.bytesToHex(program.verifier_program_authority, .lower), program.nodes.len, program.outputs.len, program.bindings.len });
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
        geometry_mod.ForProfile(profile_mod.ProfileV2).init(allocator, &profile),
    );
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    statement: @import("stwo_riscv_rv32").air.statement.RiscVStatement,
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

test "authenticated VM AIR ProfileV2 schema5 compiles fixed program and narrow Poseidon through active Ethereum program" {
    const allocator = std.testing.allocator;
    var native = support.retainedSegmentZeroCore();
    for (native.infra_descs[0..native.n_infra]) |*descriptor| if (descriptor.kind == .poseidon2) {
        descriptor.n_columns = @import("stwo_riscv_memory").air.poseidon2_narrow_degree3.N_MAIN_COLUMNS;
    };
    const manifest = lookup_manifest_mod.Manifest.native();
    const authenticated = try lookup_manifest_mod.AuthenticatedStatement.init(&native, &manifest);
    const count = try @import("stwo_riscv_rv32").recursion.vm_composition_sample_geometry.expectedSampledValueCountWithLayout(&native, &manifest, .fixed_decoded_narrow);
    var profile = try profile_mod.deriveAuthorityWithCircuitProfile(allocator, &native, &manifest, &authenticated, count, .fixed_program_narrow_v1);
    defer profile.deinit();
    const extension = try ethereum_statement.Statement.canonical(&native, 0, 0, support.emptySecpShapes());
    var geometry = try extension_geometry.GeometryV2.init(allocator, &profile, &native, &extension);
    defer geometry.deinit();
    const bridge_mod = @import("../../../../../assembly/rv32/prover/incremental_bridge_external.zig");
    const prefix: bridge_mod.PrefixColumnsV3 = .{
        .preprocessed = @intCast(profile.preprocessed_column_count + geometry.columns[0].len + @import("stwo_riscv_rv32").air.program.interaction.FIXED_COLUMN_COUNT),
        .main = @intCast(profile.main_column_count + geometry.columns[1].len),
        .interaction = @intCast(profile.interaction_column_count + geometry.columns[2].len),
    };
    const incremental = @import("../../../../../product_tree/recursion/incremental_ethereum_vm_composition_program.zig");
    const input: incremental.StatementRootCompilerInput = .{ .core_statement = &native, .extension_statement = &extension, .lookup_manifest = &manifest, .authenticated_lookup = &authenticated, .base_profile = &profile, .bridge_geometry = try bridge_mod.GeometryV3.canonicalAfterPrefix(1, prefix) };
    var compiled = try @import("../../../../../assembly/recursion/vm_composition_preparation.zig").Compiled.initEthereumWithClaimAliases(allocator, input);
    defer compiled.deinit();
    const program = compiled.program();
    try std.testing.expectEqual(count + geometry.sampled_value_count + incremental.BRIDGE_SAMPLED_VALUE_COUNT + @import("stwo_riscv_rv32").air.program.interaction.FIXED_COLUMN_COUNT, program.input_profile.sampled_value_count);
    try std.testing.expect(program.nodes.len > program.bindings.len);
    // Retained graph construction traverses the production symbolic program
    // and Poseidon evaluators. Admission must still require the six PP columns.
    var omitted = input;
    var missing_prefix = prefix;
    missing_prefix.preprocessed -= @import("stwo_riscv_rv32").air.program.interaction.FIXED_COLUMN_COUNT;
    omitted.bridge_geometry = try bridge_mod.GeometryV3.canonicalAfterPrefix(1, missing_prefix);
    if (@import("../../../../../assembly/recursion/vm_composition_preparation.zig").Compiled.initEthereumWithClaimAliases(allocator, omitted)) |unexpected| {
        var invalid = unexpected;
        invalid.deinit();
        return error.TestUnexpectedResult;
    } else |_| {}
}
