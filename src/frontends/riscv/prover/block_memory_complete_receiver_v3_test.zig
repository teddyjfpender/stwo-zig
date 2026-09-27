const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const protocol = @import("../recursion/blake3_execution_parent_protocol.zig");
const fixture = @import("block_memory_core_sha_fixture_test.zig");
const singleton = @import("block_v3_canonical_singleton_test_support.zig");
const receiver = @import("block_memory_complete_receiver_v3.zig");
const batch = @import("block_memory_batch_verify_v2.zig");

fn verifySingleton(a: std.mem.Allocator, view: fixture.FixtureView, comptime with_extension: bool) !void {
    var recursive = try singleton.prove(a, view);
    defer recursive.deinit(a);
    var statement = view.statement;
    var pins = statement.complete_pins.?;
    pins.outer_recursive_key_id = recursive.outer_admission.expected_id;
    pins.forest_roster_digest = recursive.forest_digest;
    statement.complete_pins = pins;

    const execution_pins = [_]batch.EthereumShaExecutionPin(Cpu){view.execution_pin};
    const leaf_pins = [_]receiver.ProofPin{.{
        .admission = recursive.leaf_admission,
        .expected_key_id = recursive.leaf_admission.expected_id,
    }};
    const leaf_bytes = [_][]const u8{recursive.leaf_bytes};
    const root_indices = [_]u32{0};
    const recursion_pins = receiver.RecursionPins{
        .leaf = &leaf_pins,
        .dyadic = &.{},
        .root_indices = &root_indices,
        .outer = .{ .admission = recursive.outer_admission, .expected_key_id = recursive.outer_admission.expected_id },
    };
    const recursion_bytes = receiver.RecursionBytes{
        .leaf = &leaf_bytes,
        .dyadic = &.{},
        .outer = recursive.outer_bytes,
    };
    const received = if (with_extension)
        try receiver.verifyCanonicalEthereumShaWithExtension(Cpu, a, statement, view.wire, &execution_pins, view.public_initial, recursion_pins, recursion_bytes, view.config)
    else
        try receiver.verifyCanonicalEthereumSha(Cpu, a, statement, view.wire, &execution_pins, view.public_initial, recursion_pins, recursion_bytes, view.config);
    try std.testing.expectEqual(batch.CompleteBlock.complete_block_verified, received);

    var wrong_statement = statement;
    var wrong_pins = wrong_statement.complete_pins.?;
    wrong_pins.outer_recursive_key_id[0] ^= 1;
    wrong_statement.complete_pins = wrong_pins;
    if (with_extension) {
        try std.testing.expectError(error.UntrustedBlockOuterKey, receiver.verifyCanonicalEthereumShaWithExtension(Cpu, a, wrong_statement, view.wire, &execution_pins, view.public_initial, recursion_pins, recursion_bytes, view.config));
    } else {
        try std.testing.expectError(error.UntrustedBlockOuterKey, receiver.verifyCanonicalEthereumSha(Cpu, a, wrong_statement, view.wire, &execution_pins, view.public_initial, recursion_pins, recursion_bytes, view.config));
    }
    std.debug.print(
        "BLOCK_V{d}_COMPLETE verified=true segments=1 profile=q70_pow26 events={d} leaf_bytes={d} outer_bytes={d} recursion_peak_bytes={d} leaf_prove_ns={d} outer_prove_ns={d}\n",
        .{ if (with_extension) @as(u32, 4) else @as(u32, 3), view.verified.event_count, recursive.leaf_bytes.len, recursive.outer_bytes.len, recursive.peak_live_bytes, recursive.leaf_prove_ns, recursive.outer_prove_ns },
    );
}

test "block-v3 canonical complete receiver verifies one coherent execution memory and recursive root" {
    const callback = struct {
        fn verify(a: std.mem.Allocator, view: fixture.FixtureView) !void {
            try verifySingleton(a, view, false);
        }
    };
    try fixture.withCoherentCoreFixture(protocol.CSP_CONFIG, callback.verify);
}

test "block-v4 canonical complete receiver verifies SHA Keccak memory and recursive root" {
    const callback = struct {
        fn verify(a: std.mem.Allocator, view: fixture.FixtureView) !void {
            try verifySingleton(a, view, true);
        }
    };
    try fixture.withExtendedCoreFixture(protocol.CSP_CONFIG, callback.verify);
}

test "block-v4 canonical complete receiver verifies signer Keccak memory and recursive root" {
    const callback = struct {
        fn verify(a: std.mem.Allocator, view: fixture.FixtureView) !void {
            try std.testing.expectEqual(@as(u64, 103), view.verified.event_count);
            try verifySingleton(a, view, true);
        }
    };
    try fixture.withSignerCoreFixture(protocol.CSP_CONFIG, callback.verify);
}
