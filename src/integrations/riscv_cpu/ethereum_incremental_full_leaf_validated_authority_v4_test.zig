const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const fixture_mod =
    @import("ethereum_incremental_boundary_artifact_v3_test_support.zig");
const lease_mod =
    @import("ethereum_incremental_full_leaf_validated_lease_v2.zig");
const authority_mod =
    @import("ethereum_incremental_full_leaf_validated_authority_v4.zig");

const statement = frontend.air.statement;
const statement_v2 = frontend.air.statement_v2;
const segment_v2 = frontend.recursion.segment_statement_v2;
const statement_wire = frontend.prover_mod.guest_precompile
    .ethereum_segment_artifact_statement_wire;

const Validator = struct {
    pub fn validateOwnedBoundary(
        _: Validator,
        native: *const statement_v2.RiscVStatementV2,
        _: *const frontend.air.public_data.PublicData,
    ) ![32]u8 {
        try native.validate();
        return [_]u8{0x5a} ** 32;
    }
};

test "validated lease copies sources and records one trust boundary" {
    const allocator = std.testing.allocator;
    var fixture = try fixture_mod.Fixture.init();
    const source = fixture.leftSource();
    var wire = try fixture_mod.OwnedWire.init(allocator, &source);
    defer wire.deinit();
    const native = try nativeStatement(&wire.data);
    var input_words = [_]u32{ 7, 11 };
    var output_words = [_]frontend.air.public_data.OutputWord{.{
        .addr = 0x2104,
        .value = 13,
        .clock = 2,
    }};
    var role_public = native.core.public_data;
    role_public.io_entries = .{
        .input_start = 0x2000,
        .input_len = 8,
        .input_words = &input_words,
        .output_len = 4,
        .output_len_addr = 0x2100,
        .output_data_addr = 0x2104,
        .output_words = &output_words,
    };
    const retained = try retainedSnapshots(&wire.data);
    var counters = lease_mod.ValidationCountersV2{};
    var lease = try lease_mod.ValidatedLeaseV2.initOwned(
        allocator,
        &native,
        &role_public,
        retained,
        Validator{},
        &counters,
    );
    defer lease.deinit();

    const original_wire_word = lease.canonicalWords()[0];
    const original_input_word = lease.rolePublic().io_entries.input_words[0];
    wire.words[0] = wire.words[0].add(@import("stwo_core").fields.m31.M31.one());
    input_words[0] ^= 0xffff;
    output_words[0].value ^= 0xffff;
    try std.testing.expect(lease.canonicalWords()[0].eql(original_wire_word));
    try std.testing.expectEqual(
        original_input_word,
        lease.rolePublic().io_entries.input_words[0],
    );
    try lease.validateBorrowed();
    const snapshot = counters.snapshot();
    try std.testing.expectEqual(
        @as(u64, 1),
        snapshot.retained_root_authentications,
    );
    try std.testing.expectEqual(@as(u64, 1), snapshot.authority_validations);
    try std.testing.expect(snapshot.cached_view_reuses >= 2);
    try std.testing.expectEqual(
        @as(u64, 0),
        snapshot.legacy_full_authentications,
    );

    lease.validation_binding_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidIncrementalFullLeafValidatedLeaseV2,
        lease.validateBorrowed(),
    );
}

test "validated lease releases every partial allocation" {
    const allocator = std.testing.allocator;
    var fixture = try fixture_mod.Fixture.init();
    const source = fixture.leftSource();
    var wire = try fixture_mod.OwnedWire.init(allocator, &source);
    defer wire.deinit();
    const native = try nativeStatement(&wire.data);
    const role_public = native.core.public_data;
    const retained = try retainedSnapshots(&wire.data);
    try std.testing.checkAllAllocationFailures(
        allocator,
        exerciseLeaseAllocation,
        .{ &native, &role_public, retained },
    );
}

test "retained statement decode moves one lease into fresh public custody" {
    const allocator = std.testing.allocator;
    var fixture = try fixture_mod.Fixture.init();
    const source = fixture.leftSource();
    var wire = try fixture_mod.OwnedWire.init(allocator, &source);
    defer wire.deinit();
    const native = try nativeStatement(&wire.data);
    const retained = try retainedSnapshots(&wire.data);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try statement_wire.encode(
        encoded.writer(allocator),
        &native,
        64 * 1024 * 1024,
    );

    var wrong_retained = retained;
    wrong_retained.entry.root ^= 1;
    try std.testing.expectError(
        error.BoundaryIdentityMismatch,
        statement_wire.decodeWithRetainedLease(
            allocator,
            encoded.items,
            64 * 1024 * 1024,
            wrong_retained,
            null,
        ),
    );

    var counters = lease_mod.ValidationCountersV2{};
    var decoded = try statement_wire.decodeWithRetainedLease(
        allocator,
        encoded.items,
        64 * 1024 * 1024,
        retained,
        &counters,
    );
    var decoded_owned = true;
    defer if (decoded_owned) decoded.deinit();
    var moving_lease: ?frontend.air.public_data_v2.PublicDataV2
        .OwnedValidatedLeaseV2 = decoded.lease;
    decoded_owned = false;
    var owned = try statement_v2.OwnedPublicDataV2.initVerifiedTakingLease(
        allocator,
        &decoded.value.public_data,
        &moving_lease,
    );
    defer owned.deinit();
    try std.testing.expect(moving_lease == null);
    try owned.validate();
    const snapshot = counters.snapshot();
    try std.testing.expectEqual(
        @as(u64, 1),
        snapshot.retained_root_authentications,
    );
    try std.testing.expect(snapshot.cached_view_reuses >= 4);
    try std.testing.expectEqual(
        @as(u64, 0),
        snapshot.legacy_full_authentications,
    );
}

test "validated authority surface stays process-local and exposes lease paths" {
    std.testing.refAllDecls(authority_mod);
    try std.testing.expect(!authority_mod.SERIALIZABLE);
    try std.testing.expect(!authority_mod.DIGEST_IS_ADMISSION);
    try std.testing.expect(
        authority_mod.VALIDATED_TRANSCRIPT_FAST_PATH_AVAILABLE,
    );
    try std.testing.expect(
        authority_mod.VALIDATED_CODEC_FAST_PATH_AVAILABLE,
    );
    try std.testing.expect(
        authority_mod.VALIDATED_ORCHESTRATION_FAST_PATH_AVAILABLE,
    );
    try std.testing.expect(
        authority_mod.VALIDATED_COLD_VERIFIER_FAST_PATH_AVAILABLE,
    );
}

fn exerciseLeaseAllocation(
    allocator: std.mem.Allocator,
    native: *const statement_v2.RiscVStatementV2,
    role_public: *const frontend.air.public_data.PublicData,
    retained: frontend.air.public_data_v2.PublicDataV2.RetainedSnapshots,
) !void {
    var lease = try lease_mod.ValidatedLeaseV2.initOwned(
        allocator,
        native,
        role_public,
        retained,
        Validator{},
        null,
    );
    defer lease.deinit();
    try lease.validateBorrowed();
}

fn nativeStatement(
    wire: *const frontend.air.public_data_v2.PublicDataV2,
) !statement_v2.RiscVStatementV2 {
    const core_public = try statement_v2.canonicalCorePublicData(wire);
    var core: statement.RiscVStatement = undefined;
    core.initializeDescriptorStorage();
    core.n_components = 0;
    core.initial_pc = core_public.initial_pc;
    core.final_pc = core_public.final_pc;
    core.total_steps = core_public.clock;
    core.n_infra = 0;
    core.public_data = core_public;
    return statement_v2.RiscVStatementV2.init(core, wire.*);
}

fn retainedSnapshots(
    wire: *const frontend.air.public_data_v2.PublicDataV2,
) !frontend.air.public_data_v2.PublicDataV2.RetainedSnapshots {
    const view = try segment_v2.authenticateCanonicalWire(wire.words());
    return .{
        .entry = .{
            .id = view.statement.entry_snapshot_id,
            .count = view.statement.entry_snapshot_count,
            .root = view.statement.entry_continuation_root,
        },
        .exit = .{
            .id = view.statement.exit_snapshot_id,
            .count = view.statement.exit_snapshot_count,
            .root = view.statement.exit_continuation_root,
        },
    };
}
