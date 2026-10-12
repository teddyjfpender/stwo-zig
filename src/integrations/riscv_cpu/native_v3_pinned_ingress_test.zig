//! Explicit heavy gate for the independently pinned V3 native ingress.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const fixture = @import("recursive_segment_v3_native_test_fixture.zig");
const pinned_ingress = @import("recursive_segment_v3_native_security_ingress.zig");

const Engine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);
/// Versioned key-setup pin for this exact two-leaf ELF and local V2 projection.
/// Recorded in a separate verified setup run; the proof under test cannot
/// supply or modify either this root or the expected key identity.
const known_tree0 = [8]u32{
    2053578112, 2007969840, 1758814271, 1936034131,
    1603516961, 444025432,  32631551,   1362738667,
};
const known_key_id = [32]u8{
    0x0d, 0xe4, 0xa3, 0x90, 0x93, 0x1c, 0xa0, 0xa3,
    0x66, 0x39, 0x57, 0x5a, 0x0b, 0x76, 0x40, 0x38,
    0x0c, 0xfb, 0x4b, 0xa7, 0x1d, 0xc1, 0x34, 0x23,
    0xbc, 0xa4, 0x47, 0x36, 0xa1, 0x41, 0x61, 0xe9,
};

test "real V3 native ingress accepts independently pinned q193 Tree0" {
    const allocator = std.testing.allocator;
    const elf = frontend.testing.guest_precompile_test_elf.build(false, .self_loop);
    var session = try frontend.runner.Poseidon2ExecutionSession.init(allocator, &elf, .{
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer session.deinit();
    var left = try session.startSegment(1);
    defer left.deinit();
    var right = try session.resumeSegment(left.base.continuation.?, 16);
    defer right.deinit();
    const source = try fixture.rightGlobal(allocator, &left.base, &right.base);
    const pinned_key = try pinned_ingress.PinnedKeyV1.admit(known_tree0, known_key_id);
    var timer = try std.time.Timer.start();
    var verified = try pinned_ingress.proveAndVerifyPinned(
        Engine,
        allocator,
        &source,
        frontend.recursion.poseidon2_channel.hashBytes("native-local-v3-session", 0x4e56_3250),
        pinned_key,
    );
    defer verified.deinit();
    try verified.validate();
    try std.testing.expectEqualDeep(known_tree0, verified.native.capture.proof.commitments[0]);
    try std.testing.expect(verified.native.global_metadata.global_cycle_start > 0);
    std.debug.print("V3_NATIVE_PINNED_INGRESS status=verified wall_ns={d} proof_bytes={d} outer_proof_created=false\n", .{
        timer.read(), verified.native.proof_bytes.len,
    });
}
