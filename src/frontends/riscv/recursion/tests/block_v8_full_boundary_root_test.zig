//! FIRST instruction -> terminal halt/output -> ONE genuine recursive root.
//! Fresh receiving reconstructs only public metadata and independent boundaries.
const std = @import("std");
const core = @import("stwo_core");
const Saved = @import("../block_v8_window_root_saved_v1.zig");
const Receiver = @import("../block_v8_window_root_receiver_v1.zig");
const Full = @import("../../prover/block_v8_full_boundary_policy_v1.zig");
const Capture = @import("../../prover/block_v7_real_window_capture_v1.zig");
const Fixture = @import("../../prover/tests/block_v8_full_boundary_test.zig");
const Wire = @import("../../prover/block_v7_union_claim_wire_v1.zig");
const Manifest = struct { external: Receiver.External, input: Receiver.Leaf };
const Observer = struct {
    pub const budget_bytes = 48 << 30;
    pub fn observeFiles(a: std.mem.Allocator, files: std.fs.Dir, external: Receiver.External, _: *const Full.Owned) !void {
        var root = try Saved.produce(a, files, external);
        var live = true;
        defer if (live) root.deinit();
        if (root.metadata != .leaf) return error.ExpectedSingleFullBoundaryLeaf;
        var writer = @import("../../prover/bounded_artifact_writer_v1.zig").Writer.init(a, 16 << 20);
        defer writer.deinit();
        var remaining: usize = 1 << 20;
        try Wire.encode(Manifest, &writer, .{ .external = root.metadata.leaf.external, .input = root.metadata.leaf.input }, &remaining);
        try files.writeFile(.{ .sub_path = "full-root.proof", .data = root.root.bytes });
        try files.writeFile(.{ .sub_path = "full-root-metadata.bin", .data = writer.bytes.items });
        const proof_ns = root.root.proof_ns;
        const whole_ns = root.root.whole_ns;
        const stats = root.root.stats;
        root.deinit();
        live = false;
        // Only bytes survive this boundary. No originals, captures, keys,
        // producer profiles or successful receiving receipt are passed onward.
        const bytes = try files.readFileAlloc(a, "full-root.proof", 16 << 20);
        defer a.free(bytes);
        const metadata_bytes = try files.readFileAlloc(a, "full-root-metadata.bin", 16 << 20);
        defer a.free(metadata_bytes);
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        var cursor = @import("../../prover/guest_precompile/proof_artifact_wire.zig").Cursor{ .bytes = metadata_bytes };
        remaining = 1 << 20;
        const metadata = try Wire.decode(Manifest, arena.allocator(), &cursor, &remaining);
        try std.testing.expectEqual(metadata_bytes.len, cursor.position);
        const tree = Receiver.Tree{ .leaf = .{ .external = metadata.external, .input = metadata.input } };
        var output: [43]u8 = @splat(0);
        output[32] = 1;
        const trusted = Full.Trusted{ .elf_sha256 = Capture.sha(&Fixture.elf), .input_sha256 = Capture.sha(&.{}), .total_cycles = 7, .expected_output = output, .config = @import("../blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config() };
        // Recreate the full statement from this fixture's independent expected
        // input/output, rather than reusing the original producer's policy.
        var boundary = try Full.Owned.derive(a, metadata.external.elf, &.{}, trusted, .{});
        defer boundary.deinit();
        var verified = try Receiver.verifyFull(a, bytes, tree, &boundary);
        verified.deinit();
        var bad = tree;
        bad.leaf.external.boundary.initial = null;
        try std.testing.expectError(error.UntrustedB8FullExecutionBoundary, Receiver.verifyFull(a, bytes, bad, &boundary));
        bad = tree;
        bad.leaf.external.boundary.terminal = null;
        try std.testing.expectError(error.UntrustedB8FullExecutionBoundary, Receiver.verifyFull(a, bytes, bad, &boundary));
        bad = tree;
        bad.leaf.external.trusted.window.skip_cycles = 1;
        bad.leaf.external.trusted.window.cycles = 6;
        try std.testing.expectError(error.UntrustedB8FullExecutionBoundary, Receiver.verifyFull(a, bytes, bad, &boundary));
        var wrong = trusted;
        wrong.expected_output[0] = 9;
        var wrong_boundary = try Full.Owned.derive(a, metadata.external.elf, &.{}, wrong, .{});
        defer wrong_boundary.deinit();
        try std.testing.expectError(error.UntrustedB8FullExecutionBoundary, Receiver.verifyFull(a, bytes, tree, &wrong_boundary));
        var sha: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &sha, .{});
        std.debug.print("B8_FULL_BOUNDARY_ROOT queries=70 pow=26 first_cycle=1 skip=0 cycles=7 cohorts=2 local_originals=2 bridge_originals=1 compact_originals=1 bytes={d} sha256={s} proof_ns={d} whole_ns={d} fresh_metadata_only_full_receiver=true output43_authenticated=true\n", .{ bytes.len, std.fmt.bytesToHex(sha, .lower), proof_ns, whole_ns });
        if (std.posix.getenv("STWO_B8_FULL_BOUNDARY_ROOT_ARTIFACT_DIR")) |path| {
            try std.fs.cwd().makePath(path);
            var archive = try std.fs.cwd().openDir(path, .{});
            defer archive.close();
            if (archive.access("root.proof", .{})) |_| return error.RefuseOverwriteFullBoundaryRoot else |err| if (err != error.FileNotFound) return err;
            try archive.writeFile(.{ .sub_path = "root.proof", .data = bytes });
            try archive.writeFile(.{ .sub_path = "public-metadata.bin", .data = metadata_bytes });
            const report = try std.json.Stringify.valueAlloc(a, .{ .schema = "stwo-b8-full-initial-terminal-root-qualification-v1", .scope = "complete seven-instruction fixture; not retained Ethereum block", .queries = @as(u32, 70), .pow_bits = @as(u32, 26), .cycles = @as(u64, 7), .first_cycle = @as(u64, 1), .cohorts = @as(u32, 2), .source_originals = @as(u32, 4), .proof_bytes = bytes.len, .proof_sha256 = std.fmt.bytesToHex(sha, .lower), .full_boundary_digest = boundary.digest, .initial_policy_id = boundary.initial_policy.policy_id, .terminal_policy_id = boundary.terminal_policy.policy_id, .expected_output = output, .stats = stats, .parent_whole_ns = whole_ns, .fresh_metadata_only_full_receiver = true, .missing_initial_rejects = true, .missing_terminal_rejects = true, .skip1_rejects = true, .wrong_expected_output_rejects = true, .timing_isolated = false }, .{ .whitespace = .indent_2 });
            defer a.free(report);
            try archive.writeFile(.{ .sub_path = "qualification.json", .data = report });
        }
    }
};
test "canonical full FIRST through TERMINAL single root fresh metadata-only full receiver" {
    try Fixture.qualifyWithObserver(Observer);
}
