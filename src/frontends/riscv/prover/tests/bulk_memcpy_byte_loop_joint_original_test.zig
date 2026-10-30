const std = @import("std");
const core = @import("stwo_core");
const Joint = @import("../bulk_memcpy_byte_loop_joint_original_v1.zig");
const Macro = @import("../bulk_memcpy_byte_loop_original_v1.zig");
const Scope = @import("../bulk_memcpy_byte_loop_scope_v1.zig");
const C = @import("../../air/guest_precompile/bulk_memcpy_byte_loop_certificate_v1.zig");
const Endpoint = @import("../block_v8_ram_endpoint_kernel_v1.zig");
const Profile = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile;
const prefix = [_]u32{ 0x001005b7, 0x10158593, 0x001006b7, 0x20268693, 0x01168613, 0x171612b7, 0x51428293, 0x05500713, 0xfe55afa3 };
const code = prefix ++ C.words ++ [_]u32{ 0xffd6a503, 0x0000006f };
const original_source = [_]u32{ 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110 };
const macro_source = [_]u32{ 0x17161514, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110 };
const before = [_]u32{ 0xa1a2a3a4, 0xb1b2b3b4, 0xc1c2c3c4, 0xd1d2d3d4, 0xe1e2e3e4 };
const elf = blk: {
    @setEvalBranchQuota(10000);
    var e = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 1024, .rv32im_zkvm_v1);
    const table = std.mem.readInt(u32, e[264..268], .little);
    for ([4]usize{ 2, 3, 7, 8 }, [4]u32{ 0x100100, 1024, 0x100800, 0x100810 }) |i, v| std.mem.writeInt(u32, e[table + (i + 1) * 16 + 4 ..][0..4], v, .little);
    const data = 640 + code.len * 4;
    for (original_source, 0..) |word, i| std.mem.writeInt(u32, e[data + 4 * i ..][0..4], word, .little);
    for (before, 0..) |word, i| std.mem.writeInt(u32, e[data + 0x100 + 4 * i ..][0..4], word, .little);
    break :blk e;
};
const previous_source = [_]u32{ 35, 0, 0, 0, 0 };
const previous_destination: [5]u32 = @splat(0);
fn trusted(profile: Profile) Macro.Trusted {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&elf, &hash, .{});
    return .{ .elf = &elf, .elf_sha256 = hash, .profile = .rv32im_zkvm_v1, .config = profile.config(), .public = .{ .pc = 0x1024, .call = .{ .entry_cycle = 10, .source = 0x100101, .destination = 0x100202, .destination_end = 0x100213, .length = 17, .max_instruction_cycle = 95 }, .previous_register_clocks = .{ 33, 17, 30, 18 }, .initial_scratch = 0x55, .last_byte = 0x11, .source_previous_clocks = &previous_source, .destination_previous_clocks = &previous_destination } };
}
fn run(profile: Profile) !void {
    const a = std.testing.allocator;
    var session = try @import("../../runner/mod.zig").BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var segment = try session.startSegment(95);
    defer segment.deinit();
    try std.testing.expectEqual(@as(u32, 0x103c), segment.exit_cpu.pc);
    try std.testing.expectEqual(@as(u32, 0xe111100f), segment.exit_cpu.regs[10]);
    var io = try @import("../blake3_segment_public.zig").Owned.init(a, &segment);
    defer io.deinit();
    const mt = trusted(profile);
    const scope = try Scope.Scope.create(a, mt);
    defer scope.deinit();
    io.data.program_root = .{ .bytes = scope.certificate.program_root };
    io.data.initial_rw_root = null;
    io.data.final_rw_root = null;
    io.data.io_entries.input_len = 0;
    io.data.io_entries.input_words = &.{};
    io.data.io_entries.output_len = 0;
    io.data.io_entries.output_words = &.{};
    var filtered = @import("../../runner/trace.zig").Trace.init(a);
    defer filtered.deinit();
    filtered.initial_pc = segment.execution_trace.initial_pc;
    filtered.final_pc = segment.execution_trace.final_pc;
    for (segment.execution_trace.rows.items) |row| if (row.clk < 10 or row.clk >= 95) try filtered.rows.append(a, row);
    filtered.step_count = filtered.rows.items.len;
    try filtered.bindExtractedClockRange(0, 95, 85);
    try std.testing.expectEqual(@as(usize, 10), filtered.rows.items.len);
    const native = try @import("../blake3_execution_trace.zig").Owner.initWithExternal(a, &filtered, io.data, &segment.state_chain_tracker, 85);
    defer native.deinit();
    try native.sealNativeOnly();
    // Legacy zero-external mode cannot authorize this finite candidate.
    try std.testing.expectError(error.InvalidStatement, native.statement.validateBlake3Execution());
    var stage = try Macro.Stage.create(a, scope, .{ .source_words = &macro_source, .destination_before = &before });
    defer stage.deinit();
    var points: [10]Endpoint.Endpoint = undefined;
    for (&points, 0..) |*point, i| {
        const address = (try scope.endpointAt(i)).address;
        var found = false;
        for (segment.rw_memory.words) |word| if (word.addr == address) {
            point.* = .{ .address = address, .initial = word.initial_word, .final = word.final_word, .last_clock = word.final_clock };
            found = true;
            break;
        };
        if (!found) return error.MissingJointEndpoint;
    }
    try Joint.replaceWholeEndpoints(&stage, scope, &points);
    const t = Joint.Trusted{ .macro = mt, .shape = &native.statement };
    const proof = try Joint.produce(a, t, native.main.items, &stage);
    var proof_live = true;
    defer if (proof_live) proof.deinit();
    const summary = try Joint.verify(a, t, &proof.stark, proof.claims());
    std.debug.print("JOINT_ORIGINAL_DIRECT_VERIFIED profile={s} trees={d} columns=", .{ @tagName(profile), proof.stark.commitment_scheme_proof.sampled_values.items.len });
    for (proof.stark.commitment_scheme_proof.sampled_values.items) |tree| std.debug.print("{d},", .{tree.len});
    std.debug.print("\n", .{});
    try std.testing.expectEqual(@as(u32, 95), summary.total_retirements);
    try std.testing.expectEqual(@as(u32, 10), summary.native_retirements);
    try std.testing.expectEqual(@as(u32, 85), summary.macro_retirements);
    try std.testing.expectEqual(@as(u64, 96), summary.fetch_count);
    try std.testing.expect(summary.state_closed and summary.registers_closed and summary.local_ram_closed and !summary.whole_vm_qualified);
    // Reconstruct all keys/transcript in a fresh verifier, retaining no
    // producer owner or relation draw. Claim bytes are independently copied.
    const raw = try Joint.encode(a, proof);
    defer a.free(raw);
    proof.deinit();
    proof_live = false;
    try std.testing.expectEqualDeep(summary, try Joint.verifyBytes(a, t, raw));
    std.debug.print("JOINT_ORIGINAL_FRESH_CODEC_VERIFIED profile={s} bytes={d}\n", .{ @tagName(profile), raw.len });
    if (std.posix.getenv("STWO_BYTE_LOOP_JOINT_OUTPUT")) |base| {
        const path = try std.fs.path.join(a, &.{ base, @tagName(profile) });
        defer a.free(path);
        try std.fs.cwd().makePath(path);
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
        try dir.writeFile(.{ .sub_path = "math.proof", .data = raw });
        try dir.writeFile(.{ .sub_path = "guest.elf", .data = &elf });
        const metadata = try std.json.Stringify.valueAlloc(a, .{ .schema = "stwo-joint-native-same-rom-macro-original-v1", .scope = "finite joint native+macro math theorem; ROM/table/global-memory providers OPEN; not whole VM", .elf_sha256 = std.fmt.bytesToHex(mt.elf_sha256, .lower), .public = mt.public, .shape = native.statement, .summary = summary, .profile = @tagName(profile), .proof_bytes = raw.len, .fresh_fixed_key_verified = true, .whole_vm_qualified = false }, .{ .whitespace = .indent_2 });
        defer a.free(metadata);
        try dir.writeFile(.{ .sub_path = "report.json", .data = metadata });
    }
    const malformed = try a.dupe(u8, raw);
    defer a.free(malformed);
    std.mem.writeInt(u32, malformed[12..16], 0, .little);
    try std.testing.expectError(error.InvalidJointByteLoopEnvelope, Joint.verifyBytes(a, t, malformed));
    var changed = mt;
    var clocks = previous_source;
    clocks[0] = 0;
    changed.public.source_previous_clocks = &clocks;
    const wrong_scope = try Scope.Scope.create(a, changed);
    defer wrong_scope.deinit();
    var wrong = try Macro.Stage.create(a, wrong_scope, .{ .source_words = &macro_source, .destination_before = &before });
    defer wrong.deinit();
    try Joint.replaceWholeEndpoints(&wrong, wrong_scope, &points);
    try std.testing.expectError(error.UnclosedJointByteLoopRam, Joint.produce(a, .{ .macro = changed, .shape = &native.statement }, native.main.items, &wrong));
    changed = mt;
    changed.public.previous_register_clocks[0] = 29;
    const reg_scope = try Scope.Scope.create(a, changed);
    defer reg_scope.deinit();
    var reg = try Macro.Stage.create(a, reg_scope, .{ .source_words = &macro_source, .destination_before = &before });
    defer reg.deinit();
    try Joint.replaceWholeEndpoints(&reg, reg_scope, &points);
    try std.testing.expectError(error.UnclosedJointByteLoopRegisters, Joint.produce(a, .{ .macro = changed, .shape = &native.statement }, native.main.items, &reg));
}
test "diagnostic joint native same ROM macro ORIGINAL closes state registers and RAM" {
    try run(.diagnostic_q8_pow0);
}
test "canonical joint native same ROM macro ORIGINAL closes state registers and RAM" {
    try run(.csp_q70_pow26);
}
