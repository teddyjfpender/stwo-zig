//! Actual Keccak execution from FIRST instruction through native final halt,
//! one direct three-original recursive root, then independent full receiving.
const std = @import("std");
const Saved = @import("../block_v8_endpoint_mixed_join_saved_v1.zig");
const Receiver = @import("../block_v8_endpoint_mixed_join_receiver_v1.zig");
const Upper = @import("../block_v8_window_root_receiver_v1.zig");
const Full = @import("../../prover/block_v8_full_boundary_policy_v1.zig");
const Capture = @import("../../prover/block_v7_real_window_capture_v1.zig");
const Fixture = @import("../../prover/tests/block_v8_terminal_mixed_fixture.zig");
const Wire = @import("../../prover/block_v7_union_claim_wire_v1.zig");
const Manifest = struct { external: Receiver.External, input: Receiver.Input, main_root: [32]u8 };
const Observer = struct {
    pub const budget_bytes: usize = 48 << 30;
    pub fn observeFiles(a: std.mem.Allocator, files: std.fs.Dir, external: Receiver.External, _: *const Full.Owned) !void {
        var saved = try Saved.produce(a, files, external, .{});
        var live = true;
        defer if (live) saved.deinit();
        var verified = try saved.verify(a, external);
        const main_root = verified.capture.commitments[1];
        verified.deinit();
        var writer = @import("../../prover/bounded_artifact_writer_v1.zig").Writer.init(a, 16 << 20);
        defer writer.deinit();
        var remaining: usize = 1 << 20;
        try Wire.encode(Manifest, &writer, .{ .external = external, .input = .{ .root = &.{}, .physical_claims = saved.claims, .mixed_metadata = saved.metadata, .global_roots = saved.data.memory_roots, .cohort_policy = saved.data.cohort_policy, .selected_addresses = saved.data.selected_initial_addresses }, .main_root = main_root }, &remaining);
        try files.writeFile(.{ .sub_path = "terminal-mixed-root.proof", .data = saved.root.bytes });
        try files.writeFile(.{ .sub_path = "terminal-mixed-root-metadata.bin", .data = writer.bytes.items });
        const stats = saved.root.stats;
        saved.deinit();
        live = false;
        const proof = try files.readFileAlloc(a, "terminal-mixed-root.proof", 16 << 20);
        defer a.free(proof);
        const metadata_bytes = try files.readFileAlloc(a, "terminal-mixed-root-metadata.bin", 16 << 20);
        defer a.free(metadata_bytes);
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        var cursor = @import("../../prover/guest_precompile/proof_artifact_wire.zig").Cursor{ .bytes = metadata_bytes };
        remaining = 1 << 20;
        const metadata = try Wire.decode(Manifest, arena.allocator(), &cursor, &remaining);
        try cursor.requireDone();
        const tree = Upper.Tree{ .mixed_leaf = .{ .external = metadata.external, .input = metadata.input, .main_root = metadata.main_root } };
        const trusted = Full.Trusted{ .elf_sha256 = Capture.sha(metadata.external.elf), .input_sha256 = Capture.sha(&.{}), .total_cycles = 9, .expected_output = Fixture.expectedOutput(), .config = external.config };
        var boundary = try Full.Owned.derive(a, metadata.external.elf, &.{}, trusted, .{});
        defer boundary.deinit();
        var fresh = try Upper.verifyFull(a, proof, tree, &boundary);
        fresh.deinit();
        var bad = tree;
        bad.mixed_leaf.external.boundary.initial = null;
        try std.testing.expectError(error.UntrustedB8FullExecutionBoundary, Upper.verifyFull(a, proof, bad, &boundary));
        bad = tree;
        bad.mixed_leaf.external.boundary.terminal = null;
        try std.testing.expectError(error.UntrustedB8FullExecutionBoundary, Upper.verifyFull(a, proof, bad, &boundary));
        var wrong = trusted;
        wrong.expected_output[0] ^= 1;
        var wrong_boundary = try Full.Owned.derive(a, metadata.external.elf, &.{}, wrong, .{});
        defer wrong_boundary.deinit();
        try std.testing.expectError(error.UntrustedB8FullExecutionBoundary, Upper.verifyFull(a, proof, tree, &wrong_boundary));
        var sha: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(proof, &sha, .{});
        std.debug.print("B8_TERMINAL_MIXED_ROOT q=70 pow=26 first_cycle=1 cycles=9 keccak=1 root_bytes={d} sha256={s} parent_core_ns={d} typed_caller_halt=true terminal_output_authenticated=true fresh_byte_only_full_receiver=true\n", .{ proof.len, std.fmt.bytesToHex(sha, .lower), stats.proof_ns });
        if (std.posix.getenv("STWO_B8_TERMINAL_MIXED_ARTIFACT_DIR")) |path| {
            try std.fs.cwd().makePath(path);
            var dir = try std.fs.cwd().openDir(path, .{});
            defer dir.close();
            if (dir.access("root.proof", .{})) |_| return error.RefuseOverwriteTerminalMixedRoot else |err| if (err != error.FileNotFound) return err;
            try dir.writeFile(.{ .sub_path = "root.proof", .data = proof });
            try dir.writeFile(.{ .sub_path = "public-metadata.bin", .data = metadata_bytes });
            const report = try std.json.Stringify.valueAlloc(a, .{ .schema = "stwo-b8-terminal-mixed-root-qualification-v1", .scope = "complete nine-instruction Keccak fixture; not retained Ethereum block", .queries = @as(u32, 70), .pow_bits = @as(u32, 26), .source_originals = @as(u32, 3), .intermediate_recursive_proofs = @as(u32, 0), .root_bytes = proof.len, .root_sha256 = std.fmt.bytesToHex(sha, .lower), .stats = stats, .fresh_full_receiver = true, .wrong_output_rejects = true, .missing_initial_rejects = true, .missing_terminal_rejects = true, .timing_isolated = false }, .{ .whitespace = .indent_2 });
            defer a.free(report);
            try dir.writeFile(.{ .sub_path = "qualification.json", .data = report });
        }
    }
};
test "canonical terminal mixed FIRST instruction Keccak final halt output to single root" {
    try Fixture.qualifyWithObserver(Observer);
}
