//! Contract-level tests for the concrete binary outer cohort.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const cohort_mod = @import("recursive_binary_outer_cohort.zig");
const driver = @import("recursive_binary_outer.zig");
const fixed_wire = frontend.recursion.fixed_wire;
const protocol = frontend.recursion.protocol;
const fixture_mod = frontend.testing.binary_pair_outer_fixture;
const M31 = stwo_core.fields.m31.M31;
const manifest_mod = frontend.recursion.air.universal_adapter_manifest;
const universal = frontend.recursion.air.universal_challenges;
const shared_provider = frontend.recursion.air.universal_shared_provider;

const CHILD_DIMENSIONS = fixed_wire.Dimensions{
    .commitment_count = 4,
    .claimed_sum_count = 36,
    .sampled_value_count = 19,
    .queried_value_count = 11 * protocol.FRI_QUERY_COUNT,
    .trace_path_count = 4 * protocol.FRI_QUERY_COUNT,
    .fri_layer_count = 1,
    .query_count = protocol.FRI_QUERY_COUNT,
    .maximum_fold_width = 16,
    .last_layer_coefficient_count = 1,
    .maximum_merkle_depth = 5,
};

const STATEMENT_DIMENSIONS = fixed_wire.Dimensions{
    .commitment_count = 4,
    .claimed_sum_count = 36,
    .sampled_value_count = 4,
    .queried_value_count = 4 * 3,
    .trace_path_count = 4 * 3,
    .fri_layer_count = 5,
    .query_count = 3,
    .maximum_fold_width = 2,
    .last_layer_coefficient_count = 1,
    .maximum_merkle_depth = 6,
};

const Cohort = cohort_mod.Cohort(CHILD_DIMENSIONS, STATEMENT_DIMENSIONS);
const Kernel = driver.EngineKernel(Cohort);

comptime {
    if (!std.meta.eql(CHILD_DIMENSIONS, fixture_mod.CHILD_DIMENSIONS) or
        !std.meta.eql(STATEMENT_DIMENSIONS, fixture_mod.STATEMENT_DIMENSIONS))
    {
        @compileError("binary cohort and shared fixture dimensions drifted");
    }
}

test "binary outer cohort exposes the complete proof-kernel contract" {
    const capabilities = driver.ProofContractCapabilitiesV1.inspect(Cohort);
    try std.testing.expect(capabilities.ready());
    try std.testing.expectEqual(@as(usize, 36), cohort_mod.COMPLETE_ROW_COUNT);
    try std.testing.expectEqual(@as(usize, 18), cohort_mod.FRI_FIRST_ROW);
    try std.testing.expectEqual(@as(usize, 17), cohort_mod.FRI_ROW_COUNT);
    try std.testing.expectEqual(@as(usize, 35), cohort_mod.PROVIDER_ROW);
    try std.testing.expect(cohort_mod.PROTOCOL_SUBSTRATE_ONLY);
    try std.testing.expect(!cohort_mod.AUTHENTICATED_TEMPORAL_V2);
    try std.testing.expect(!cohort_mod.WHOLE_FRONTEND_VERIFIED);
    try std.testing.expect(!cohort_mod.PRODUCTION_ACTIVATION);
    try std.testing.expectEqual(
        @as(usize, 0),
        cohort_mod.HOT_ENVELOPE_HEAP_ALLOCATIONS,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        cohort_mod.VERIFIER_REBUILD_PEAK_LIVE_TREE_COUNT,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        cohort_mod.ROW34_REPLAYED_SCALAR_PERMUTATIONS,
    );
    _ = Kernel;
}

test "binary outer cohort declarations remain analyzable" {
    std.testing.refAllDeclsRecursive(Cohort);
}

test "binary outer cohort closes all 47 domains before proving" {
    var fixture = try fixture_mod.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const inputs = Cohort.AuthorityInputs{
        .non_fri = try fixture.nonFriInputs(),
        .fri_source = fixture.friSource(),
    };
    var cohort = try Cohort.init(std.testing.allocator, inputs);
    defer cohort.deinit();
    const publication_authority = try cohort.publicationAuthority();
    try std.testing.expect(
        publication_authority.authority ==
            &inputs.non_fri.transcript_prepared.authority,
    );
    try std.testing.expect(
        publication_authority.record ==
            &inputs.non_fri.transcript_prepared.record,
    );
    try std.testing.expectEqualDeep(
        inputs.non_fri.root_pin,
        publication_authority.root_pin.*,
    );
    try std.testing.expect(!std.mem.allEqual(
        u8,
        &publication_authority.cohort_authority_sha_id,
        0,
    ));

    var main = try TestTree.init(
        std.testing.allocator,
        cohort.manifest(),
        manifest_mod.MAIN_TREE_INDEX,
    );
    defer main.deinit();
    try cohort.fillMainInto(cohort.manifest(), main.columns);

    var channel = driver.Engine.Channel{};
    const relations = try universal.UniversalRelations.draw(
        std.testing.allocator,
        &channel,
    );
    const provider_relations =
        try shared_provider.SharedProviderRelations.init(&relations);
    var interaction = try TestTree.init(
        std.testing.allocator,
        cohort.manifest(),
        manifest_mod.INTERACTION_TREE_INDEX,
    );
    defer interaction.deinit();
    const generated = try cohort.fillInteractionInto(
        cohort.manifest(),
        &relations,
        &provider_relations,
        interaction.columns,
    );
    const claims = try cohort.claimVector(&generated);
    try cohort.auditGlobalClosure(
        &generated,
        &claims,
        &relations,
        &provider_relations,
    );
}

test "binary outer cohort proves and independently verifies all 36 rows" {
    var fixture = try fixture_mod.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const inputs = Cohort.AuthorityInputs{
        .non_fri = try fixture.nonFriInputs(),
        .fri_source = fixture.friSource(),
    };

    var capture: driver.OuterProofCapture = undefined;
    var publication: driver.VerifiedBinaryClosurePublicationV2 = undefined;
    const receipt = try Kernel.proveAndVerifyWithExecution(
        std.testing.allocator,
        inputs,
        .{ .worker_count = 4 },
        &capture,
        &publication,
    );
    defer capture.deinit(std.testing.allocator);
    try publication.validate();
    try std.testing.expectEqual(@as(u8, 36), receipt.roster_count);
    try std.testing.expect(receipt.preprocessed_columns > 0);
    try std.testing.expect(receipt.main_columns > 0);
    try std.testing.expect(receipt.interaction_columns > 0);
    try std.testing.expect(receipt.proof_size_estimate > 0);
    try std.testing.expect(receipt.canonical_proof_bytes > 0);
    try std.testing.expectEqual(
        receipt.canonical_proof_bytes *
            driver.CANONICAL_PROOF_SERIALIZATION_PASSES,
        receipt.canonical_proof_streamed_bytes,
    );
    try std.testing.expectEqual(
        driver.CANONICAL_PROOF_SERIALIZATION_PASSES,
        receipt.canonical_proof_serialization_passes,
    );
    try std.testing.expectEqual(
        driver.RETAINED_CANONICAL_PROOF_BYTES,
        receipt.canonical_proof_retained_bytes,
    );
    try std.testing.expect(!std.mem.allEqual(u8, &receipt.canonical_proof_sha256, 0));
    try std.testing.expectEqual(
        @as(u32, @intCast(receipt.canonical_proof_bytes)),
        publication.canonical_proof_byte_count,
    );
    try std.testing.expectEqual(
        receipt.canonical_proof_id,
        publication.proof_id,
    );
    try std.testing.expectEqualSlices(
        u8,
        &receipt.canonical_proof_sha256,
        &publication.canonical_proof_sha_id,
    );
    try std.testing.expectEqualSlices(
        u8,
        &receipt.cohort_authority_sha256,
        &publication.cohort_authority_sha_id,
    );
    try std.testing.expectEqualSlices(
        u8,
        &receipt.closure_receipt_sha256,
        &publication.closure_receipt.closure_id,
    );
    try std.testing.expectEqual(
        frontend.recursion.poseidon2_channel.bytePermutationCount(
            receipt.canonical_proof_bytes,
        ),
        receipt.canonical_proof_id_poseidon_permutations,
    );
    try std.testing.expectEqual(
        frontend.recursion.pair_node.AuthenticationPermutationCostV1
            .successful_context_prepared_root,
        receipt.pair_authentication_poseidon_permutations,
    );
    try std.testing.expect(receipt.transcript_draws > 0);
    try std.testing.expectEqual(@as(usize, 4), receipt.worker_count);
    const proof_sha256_hex = std.fmt.bytesToHex(
        receipt.canonical_proof_sha256,
        .lower,
    );

    std.debug.print(
        "binary-cohort receipt: proof_estimate={d}B canonical={d}B " ++
            "streamed={d}B sha256={s} prove={d}ns canonicalize={d}ns " ++
            "verify={d}ns pair_prepare={d}ns publish={d}ns " ++
            "columns={d}/{d}/{d} " ++
            "rows={d} draws={d} workers={d}\n",
        .{
            receipt.proof_size_estimate,
            receipt.canonical_proof_bytes,
            receipt.canonical_proof_streamed_bytes,
            &proof_sha256_hex,
            receipt.prove_ns,
            receipt.proof_canonicalize_ns,
            receipt.verify_ns,
            receipt.pair_authority_prepare_ns,
            receipt.publication_ns,
            receipt.preprocessed_columns,
            receipt.main_columns,
            receipt.interaction_columns,
            receipt.roster_count,
            receipt.transcript_draws,
            receipt.worker_count,
        },
    );
}

test "binary outer cohort canonical proof identity is worker-count invariant" {
    var fixture = try fixture_mod.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const inputs = Cohort.AuthorityInputs{
        .non_fri = try fixture.nonFriInputs(),
        .fri_source = fixture.friSource(),
    };

    var serial_capture: driver.OuterProofCapture = undefined;
    var serial_publication: driver.VerifiedBinaryClosurePublicationV2 = undefined;
    const serial = try Kernel.proveAndVerifyWithExecution(
        std.testing.allocator,
        inputs,
        .{ .worker_count = 1 },
        &serial_capture,
        &serial_publication,
    );
    defer serial_capture.deinit(std.testing.allocator);

    var parallel_capture: driver.OuterProofCapture = undefined;
    var parallel_publication: driver.VerifiedBinaryClosurePublicationV2 = undefined;
    const parallel = try Kernel.proveAndVerifyWithExecution(
        std.testing.allocator,
        inputs,
        .{ .worker_count = 4 },
        &parallel_capture,
        &parallel_publication,
    );
    defer parallel_capture.deinit(std.testing.allocator);

    try std.testing.expectEqual(
        serial.canonical_proof_bytes,
        parallel.canonical_proof_bytes,
    );
    try std.testing.expectEqualSlices(
        u8,
        &serial.canonical_proof_sha256,
        &parallel.canonical_proof_sha256,
    );
    try std.testing.expectEqual(
        serial.canonical_proof_id,
        parallel.canonical_proof_id,
    );
    try std.testing.expectEqualDeep(serial_publication, parallel_publication);
    try std.testing.expectEqual(serial.transcript_draws, parallel.transcript_draws);
    try std.testing.expectEqual(@as(usize, 1), serial.worker_count);
    try std.testing.expectEqual(@as(usize, 4), parallel.worker_count);

    const proof_sha256_hex = std.fmt.bytesToHex(
        serial.canonical_proof_sha256,
        .lower,
    );
    std.debug.print(
        "binary-cohort worker parity: canonical={d}B sha256={s} " ++
            "serial_prove={d}ns parallel_prove={d}ns\n",
        .{
            serial.canonical_proof_bytes,
            &proof_sha256_hex,
            serial.prove_ns,
            parallel.prove_ns,
        },
    );
}

test "binary outer cohort authority mismatch is capture-fail-atomic" {
    var fixture = try fixture_mod.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var inputs = Cohort.AuthorityInputs{
        .non_fri = try fixture.nonFriInputs(),
        .fri_source = fixture.friSource(),
    };
    inputs.non_fri.root_pin.expected_aggregator_vk_id[0] ^= 1;

    var capture: driver.OuterProofCapture = undefined;
    @memset(std.mem.asBytes(&capture), 0xa5);
    const before = std.mem.asBytes(&capture)[0..@sizeOf(driver.OuterProofCapture)].*;
    var publication: driver.VerifiedBinaryClosurePublicationV2 = undefined;
    @memset(std.mem.asBytes(&publication), 0x5a);
    const publication_before =
        std.mem.asBytes(&publication)[0..@sizeOf(driver.VerifiedBinaryClosurePublicationV2)].*;
    try std.testing.expectError(
        error.CrossCustodyMismatch,
        Kernel.proveAndVerify(
            std.testing.allocator,
            inputs,
            &capture,
            &publication,
        ),
    );
    try std.testing.expectEqualSlices(u8, &before, std.mem.asBytes(&capture));
    try std.testing.expectEqualSlices(
        u8,
        &publication_before,
        std.mem.asBytes(&publication),
    );
}

test "binary outer cohort rejects aliased transaction outputs before work" {
    var fixture = try fixture_mod.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const inputs = Cohort.AuthorityInputs{
        .non_fri = try fixture.nonFriInputs(),
        .fri_source = fixture.friSource(),
    };

    comptime std.debug.assert(
        @sizeOf(driver.VerifiedBinaryClosurePublicationV2) >=
            @sizeOf(driver.OuterProofCapture),
    );
    comptime std.debug.assert(
        @alignOf(driver.VerifiedBinaryClosurePublicationV2) >=
            @alignOf(driver.OuterProofCapture),
    );
    var publication: driver.VerifiedBinaryClosurePublicationV2 = undefined;
    @memset(std.mem.asBytes(&publication), 0x6d);
    const before =
        std.mem.asBytes(&publication)[0..@sizeOf(driver.VerifiedBinaryClosurePublicationV2)].*;
    const aliased_capture: *driver.OuterProofCapture = @ptrCast(
        @alignCast(&publication),
    );
    try std.testing.expectError(
        error.TransactionOutputAlias,
        Kernel.proveAndVerify(
            std.testing.allocator,
            inputs,
            aliased_capture,
            &publication,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &before,
        std.mem.asBytes(&publication),
    );
}

const TestTree = struct {
    allocator: std.mem.Allocator,
    columns: [][]M31,
    storage: []M31,

    fn init(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
        tree: usize,
    ) !TestTree {
        const column_count = switch (tree) {
            manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
            manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
            else => return error.InvalidTreeIndex,
        };
        const columns = try allocator.alloc([]M31, column_count);
        errdefer allocator.free(columns);
        var cell_count: usize = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            const count: usize = switch (tree) {
                manifest_mod.MAIN_TREE_INDEX => placement.geometry.main_columns,
                manifest_mod.INTERACTION_TREE_INDEX => placement.geometry.interaction_columns,
                else => unreachable,
            };
            cell_count = try std.math.add(
                usize,
                cell_count,
                try std.math.mul(
                    usize,
                    count,
                    @as(usize, 1) << @intCast(placement.geometry.log_size),
                ),
            );
        }
        const storage = try allocator.alloc(M31, cell_count);
        errdefer allocator.free(storage);
        @memset(storage, M31.zero());
        var cursor: usize = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            const offset: usize = switch (tree) {
                manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
                manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
                else => unreachable,
            };
            const count: usize = switch (tree) {
                manifest_mod.MAIN_TREE_INDEX => placement.geometry.main_columns,
                manifest_mod.INTERACTION_TREE_INDEX => placement.geometry.interaction_columns,
                else => unreachable,
            };
            const row_count = @as(usize, 1) << @intCast(placement.geometry.log_size);
            for (columns[offset..][0..count]) |*column| {
                column.* = storage[cursor..][0..row_count];
                cursor += row_count;
            }
        }
        std.debug.assert(cursor == storage.len);
        return .{
            .allocator = allocator,
            .columns = columns,
            .storage = storage,
        };
    }

    fn deinit(self: *TestTree) void {
        self.allocator.free(self.storage);
        self.allocator.free(self.columns);
        self.* = undefined;
    }
};
