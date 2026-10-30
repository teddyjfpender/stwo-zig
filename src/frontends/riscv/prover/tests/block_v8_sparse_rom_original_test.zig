const std = @import("std");
const core = @import("stwo_core");
const Source = @import("../block_v8_sparse_rom_v1.zig");
const Original = @import("../block_v8_sparse_rom_original_v1.zig");
const Image = @import("../block_v8_endpoint_local_program_v1.zig");
const Profile = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile;
const code = blk: {
    var words: [4096]u32 = @splat(0x00000013);
    words[0] = 0x00700293;
    words[1] = 0x00328313;
    words[2] = 0x005303b3;
    words[3] = 0x0000006f;
    break :blk words;
};
const elf = blk: {
    @setEvalBranchQuota(200000);
    var e = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 1024, .rv32im_zkvm_v1);
    const table = std.mem.readInt(u32, e[264..268], .little);
    for ([4]usize{ 2, 3, 7, 8 }, [4]u32{ 0x100100, 1024, 0x100800, 0x100810 }) |i, v| std.mem.writeInt(u32, e[table + (i + 1) * 16 + 4 ..][0..4], v, .little);
    break :blk e;
};
const entries = [_]Source.Entry{ .{ .pc = 0x1000, .count = 1 }, .{ .pc = 0x1004, .count = 1 }, .{ .pc = 0x1008, .count = 1 }, .{ .pc = 0x100c, .count = 1 } };
fn expectedHash() [32]u8 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&elf, &h, .{});
    return h;
}
fn publish(a: std.mem.Allocator, profile: Profile, comptime joint: bool, t: Original.Trusted, raw: []const u8, summary: Original.Summary) !void {
    const base = std.posix.getenv("STWO_SPARSE_ROM_OUTPUT") orelse return;
    const path = try std.fs.path.join(a, &.{ base, if (joint) "native_joint" else "standalone", @tagName(profile) });
    defer a.free(path);
    try std.fs.cwd().makePath(path);
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    try dir.writeFile(.{ .sub_path = "math.proof", .data = raw });
    try dir.writeFile(.{ .sub_path = "guest.elf", .data = &elf });
    const report = try std.json.Stringify.valueAlloc(a, .{ .schema = "stwo-sparse-rom-original-v1", .scope = "new sparse-ROM identity; original canonical public-program AIR; full VM providers OPEN", .profile = @tagName(profile), .native_joint = joint, .elf_sha256 = std.fmt.bytesToHex(t.rom.elf_sha256, .lower), .expected_program_root = t.rom.program_root, .support = entries, .expected_fetches = t.rom.expected_fetches, .shape = if (joint) t.shape.?.* else null, .summary = summary, .proof_bytes = raw.len, .fresh_fixed_key_verified = true, .whole_vm_qualified = false }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try dir.writeFile(.{ .sub_path = "report.json", .data = report });
}
fn run(comptime joint: bool, profile: Profile) !void {
    const a = std.testing.allocator;
    var image = try Image.Owned.init(a, &elf, expectedHash(), .rv32im_zkvm_v1, .{});
    defer image.deinit();
    const rt = Source.Trusted{ .elf = &elf, .elf_sha256 = expectedHash(), .profile = .rv32im_zkvm_v1, .program_root = image.root, .expected_fetches = 4 };
    var session = try @import("../../runner/mod.zig").BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var segment = try session.startSegment(3);
    defer segment.deinit();
    try std.testing.expectEqual(@as(u32, 17), segment.exit_cpu.regs[7]);
    var io = try @import("../blake3_segment_public.zig").Owned.init(a, &segment);
    defer io.deinit();
    io.data.program_root = .{ .bytes = image.root.bytes };
    io.data.initial_rw_root = null;
    io.data.final_rw_root = null;
    io.data.io_entries.input_len = 0;
    io.data.io_entries.input_words = &.{};
    io.data.io_entries.output_len = 0;
    io.data.io_entries.output_words = &.{};
    const native = try @import("../blake3_execution_trace.zig").Owner.initWithExternal(a, &segment.execution_trace, io.data, &segment.state_chain_tracker, 0);
    defer native.deinit();
    try native.sealNativeOnly();
    const t = Original.Trusted{ .rom = rt, .config = profile.config(), .shape = if (joint) &native.statement else null };
    const Protocol = Original.For(joint);
    const proof = try Protocol.produce(a, t, &entries, if (joint) native.main.items else &.{});
    var live = true;
    defer if (live) proof.deinit();
    const summary = try Protocol.verify(a, t, &entries, &proof.stark, proof.native_claims, proof.rom_claim);
    try std.testing.expectEqual(@as(u32, 4), summary.selected_pcs);
    try std.testing.expectEqual(@as(u32, 4), summary.sparse_log);
    try std.testing.expectEqual(@as(u64, 4096), summary.complete_rom_rows);
    try std.testing.expectEqual(joint, summary.program_closed);
    try std.testing.expectEqual(joint, summary.state_closed);
    try std.testing.expectEqual(joint, summary.registers_closed);
    try std.testing.expect(summary.ram_open.isZero());
    if (Protocol.verify(a, t, &entries, &proof.stark, proof.native_claims, proof.rom_claim.add(core.fields.qm31.QM31.one()))) |_| return error.AcceptedSparseRomPhysicalClaimMutation else |err| if (err == error.OutOfMemory) return err;
    const raw = try Protocol.encode(a, proof);
    defer a.free(raw);
    proof.deinit();
    live = false;
    try std.testing.expectEqualDeep(summary, try Protocol.verifyBytes(a, t, &entries, raw));
    try publish(a, profile, joint, t, raw, summary);
    std.debug.print("SPARSE_ROM_ORIGINAL_FRESH_VERIFIED joint={} profile={s} selected=4 rows=16 fullRows=4096 bytes={d}\n", .{ joint, @tagName(profile), raw.len });
    const bad = try a.dupe(u8, raw);
    defer a.free(bad);
    std.mem.writeInt(u32, bad[16..20], 99999, .little);
    try std.testing.expectError(error.InvalidSparseRomEnvelope, Protocol.verifyBytes(a, t, &entries, bad));
    if (joint) {
        var missing = entries;
        missing[3].pc = 0x1010;
        try std.testing.expectError(error.UnclosedSparseRomRequests, Protocol.produce(a, t, &missing, native.main.items));
    }
}
test "sparse ROM standalone canonical original q70 independently reconstructs ELF support" {
    try run(false, .csp_q70_pow26);
}
test "sparse ROM native joint canonical original q70 closes actual native requests" {
    try run(true, .csp_q70_pow26);
}
test "sparse ROM standalone diagnostic original q8 independently reconstructs ELF support" {
    try run(false, .diagnostic_q8_pow0);
}
test "sparse ROM native joint diagnostic original q8 closes actual native requests" {
    try run(true, .diagnostic_q8_pow0);
}
test "sparse ROM inventory rejects duplicate missing altered root and field count aliases" {
    const a = std.testing.allocator;
    var image = try Image.Owned.init(a, &elf, expectedHash(), .rv32im_zkvm_v1, .{});
    defer image.deinit();
    const t = Source.Trusted{ .elf = &elf, .elf_sha256 = expectedHash(), .profile = .rv32im_zkvm_v1, .program_root = image.root, .expected_fetches = 4 };
    var plan = try Source.Owned.derive(a, t, &entries, .{});
    defer plan.deinit();
    try std.testing.expectEqual(@as(u32, 4), plan.log_size);
    var bad = entries;
    bad[1].pc = bad[0].pc;
    try std.testing.expectError(error.InvalidSparseRomInventory, Source.Owned.derive(a, t, &bad, .{}));
    bad = entries;
    bad[0].pc += 2;
    try std.testing.expectError(error.InvalidSparseRomInventory, Source.Owned.derive(a, t, &bad, .{}));
    bad = entries;
    bad[0].count = 0;
    try std.testing.expectError(error.InvalidSparseRomInventory, Source.Owned.derive(a, t, &bad, .{}));
    bad = entries;
    bad[0].count = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidSparseRomInventory, Source.Owned.derive(a, t, &bad, .{}));
    bad = entries;
    bad[0].count = 2;
    try std.testing.expectError(error.SparseRomFetchCountMismatch, Source.Owned.derive(a, t, &bad, .{}));
    var changed = t;
    changed.program_root.bytes[0] ^= 1;
    try std.testing.expectError(error.UntrustedSparseRomImage, Source.Owned.derive(a, changed, &entries, .{}));
    var altered = elf;
    altered[642] ^= 0x10;
    changed = t;
    changed.elf = &altered;
    std.crypto.hash.sha2.Sha256.hash(&altered, &changed.elf_sha256, .{});
    try std.testing.expectError(error.UntrustedSparseRomImage, Source.Owned.derive(a, changed, &entries, .{}));
    // A proposed missing used PC remains a valid independent ROM provider.
    // Native joint closure, above, is the necessary coverage proof.
    bad = entries;
    bad[3].pc = 0x1010;
    var sparse = try Source.Owned.derive(a, t, &bad, .{});
    defer sparse.deinit();
}

test "sparse ROM retained ELF actual cohort support canonical original q70" {
    const path = std.posix.getenv("STWO_SPARSE_ROM_RETAINED_METADATA") orelse return error.SkipZigTest;
    const a = std.testing.allocator;
    const metadata = try std.fs.cwd().readFileAlloc(a, path, 32 << 20);
    defer a.free(metadata);
    const parsed = try std.json.parseFromSlice(std.json.Value, a, metadata, .{});
    defer parsed.deinit();
    const plan = parsed.value.object.get("program_plan").?.object;
    const counts = plan.get("multiplicities").?.array.items;
    const root_bytes = plan.get("program_root").?.object.get("bytes").?.array.items;
    var root: @FieldType(Source.Trusted, "program_root") = undefined;
    for (&root.bytes, root_bytes) |*b, v| b.* = @intCast(v.integer);
    const real_elf = try std.fs.cwd().readFileAlloc(a, "vectors/reports/block-v7-real-window-corpus-20261029/source/guest.elf", 16 << 20);
    defer a.free(real_elf);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(real_elf, &hash, .{});
    var pinned_bytes: [32]u8 = undefined;
    const pinned = try std.fmt.hexToBytes(&pinned_bytes, "ef68fdca9e627a4969e64aa97119f52f2d9c9d6b6e8d5cbbeb541fb93dab0688");
    try std.testing.expectEqualSlices(u8, pinned, &hash);
    const profile = @import("../../runner/elf_loader.zig").ExecutionProfile.rv32im_zkvm_ethereum_sha_v1;
    var image = try Image.Owned.init(a, real_elf, hash, profile, .{});
    defer image.deinit();
    try std.testing.expectEqualDeep(root, image.root);
    if (counts.len != image.leaves.len / 4) return error.InvalidRetainedSparseRomCensus;
    var support: std.ArrayList(Source.Entry) = .empty;
    defer support.deinit(a);
    for (counts, 0..) |count, i| if (count.integer > 0) try support.append(a, .{ .pc = image.info.memory_layout.program_base + 4 * @as(u32, @intCast(i)), .count = @intCast(count.integer) });
    const rt = Source.Trusted{ .elf = real_elf, .elf_sha256 = hash, .profile = profile, .program_root = root, .expected_fetches = @intCast(plan.get("expected_fetches").?.integer) };
    const trusted_input = Original.Trusted{ .rom = rt, .config = Profile.csp_q70_pow26.config() };
    const Protocol = Original.For(false);
    const proof = try Protocol.produce(a, trusted_input, support.items, &.{});
    var live = true;
    defer if (live) proof.deinit();
    const summary = try Protocol.verify(a, trusted_input, support.items, &proof.stark, &.{}, proof.rom_claim);
    const raw = try Protocol.encode(a, proof);
    defer a.free(raw);
    proof.deinit();
    live = false;
    try std.testing.expectEqualDeep(summary, try Protocol.verifyBytes(a, trusted_input, support.items, raw));
    if (std.posix.getenv("STWO_SPARSE_ROM_OUTPUT")) |base| {
        const output = try std.fs.path.join(a, &.{ base, "retained_standalone", "csp_q70_pow26" });
        defer a.free(output);
        try std.fs.cwd().makePath(output);
        var dir = try std.fs.cwd().openDir(output, .{});
        defer dir.close();
        try dir.writeFile(.{ .sub_path = "math.proof", .data = raw });
        const report = try std.json.Stringify.valueAlloc(a, .{ .schema = "stwo-sparse-retained-ELF-ROM-original-v1", .scope = "standalone canonical ROM original over actual retained ELF and saved cohort public census; native/local proof integration OPEN", .elf_sha256 = std.fmt.bytesToHex(hash, .lower), .expected_program_root = root, .support = support.items, .expected_fetches = rt.expected_fetches, .summary = summary, .proof_bytes = raw.len, .fresh_fixed_key_verified = true, .whole_vm_qualified = false, .saved_metadata = path }, .{ .whitespace = .indent_2 });
        defer a.free(report);
        try dir.writeFile(.{ .sub_path = "report.json", .data = report });
    }
    std.debug.print("SPARSE_RETAINED_ROM_ORIGINAL_FRESH_VERIFIED selected={d} log={d} fullRows={d} bytes={d}\n", .{ summary.selected_pcs, summary.sparse_log, summary.complete_rom_rows, raw.len });
}
