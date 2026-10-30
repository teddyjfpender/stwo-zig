const std = @import("std");
const core = @import("stwo_core");
const K = @import("../block_v8_range20_bytes_kernel_v1.zig");
const P = @import("../block_v8_range20_bytes_profile_v1.zig");
const Original = @import("../block_v8_range20_bytes_original_v1.zig");
const R = @import("../block_v7_memory_relations_v1.zig");
const Counters = @import("../../air/lookups/tables/counter.zig");
const Profile = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile;
const values = [_]u32{ 0, 1, 255, 256, 65535, 65536, (1 << 20) - 1 };
const code = [_]u32{ 0x00700293, 0x00328313, 0x005303b3, 0x0000006f };
const elf = blk: {
    @setEvalBranchQuota(10000);
    var e = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 1024, .rv32im_zkvm_v1);
    const table = std.mem.readInt(u32, e[264..268], .little);
    for ([4]usize{ 2, 3, 7, 8 }, [4]u32{ 0x100100, 1024, 0x100800, 0x100810 }) |i, v| std.mem.writeInt(u32, e[table + (i + 1) * 16 + 4 ..][0..4], v, .little);
    break :blk e;
};
fn hash() [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&elf, &out, .{});
    return out;
}
fn publish(a: std.mem.Allocator, comptime joint: bool, profile: Profile, t: Original.Trusted, raw: []const u8, summary: Original.Summary) !void {
    const base = std.posix.getenv("STWO_RANGE20_BYTES_OUTPUT") orelse return;
    const path = try std.fs.path.join(a, &.{ base, if (joint) "native_consumer" else "standalone", @tagName(profile) });
    defer a.free(path);
    try std.fs.cwd().makePath(path);
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    try dir.writeFile(.{ .sub_path = "math.proof", .data = raw });
    try dir.writeFile(.{ .sub_path = "guest.elf", .data = &elf });
    const metadata = try std.json.Stringify.valueAlloc(a, .{ .schema = "stwo-range20-bytes-seven-plane-original-v1", .scope = "experimental native lookup predicate math theorem; program/global memory OPEN; no whole VM authority", .profile = @tagName(profile), .native_consumer = joint, .layout = t.layout, .public_range20_values = t.values, .native_shape = if (joint) t.shape.?.* else null, .elf_sha256 = std.fmt.bytesToHex(t.elf_sha256, .lower), .summary = summary, .proof_bytes = raw.len, .fresh_fixed_key_verified = true, .default_legacy_claims_unchanged = true }, .{ .whitespace = .indent_2 });
    defer a.free(metadata);
    try dir.writeFile(.{ .sub_path = "report.json", .data = metadata });
}
fn run(comptime joint: bool, profile: Profile) !void {
    const a = std.testing.allocator;
    var counters = try Counters.Set.init(a);
    defer counters.deinit(a);
    for (values) |v| try counters.get(.range_check_20).registerBase(R.M.one().neg(), &.{R.M.fromCanonical(v)});
    var session = try @import("../../runner/mod.zig").BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var segment = try session.startSegment(3);
    defer segment.deinit();
    try std.testing.expectEqual(@as(u32, 17), segment.exit_cpu.regs[7]);
    var image = try @import("../block_v8_endpoint_local_program_v1.zig").Owned.init(a, &elf, hash(), .rv32im_zkvm_v1, .{});
    defer image.deinit();
    var io = try @import("../blake3_segment_public.zig").Owned.init(a, &segment);
    defer io.deinit();
    io.data.program_root = image.root;
    io.data.initial_rw_root = null;
    io.data.final_rw_root = null;
    io.data.io_entries.input_len = 0;
    io.data.io_entries.input_words = &.{};
    io.data.io_entries.output_len = 0;
    io.data.io_entries.output_words = &.{};
    const native = try @import("../blake3_execution_trace.zig").Owner.initWithExternal(a, &segment.execution_trace, io.data, &segment.state_chain_tracker, 0);
    defer native.deinit();
    try native.sealNativeOnly();
    var stage = try P.Stage.create(a, if (joint) &native.opcode_columns.lookup_counters.? else &counters, @intCast(profile.config().fri_config.n_queries));
    defer stage.deinit();
    try std.testing.expectEqual([3]u32{ 1, 4, 8 }, stage.layout.parts[1].width);
    try std.testing.expectEqual(@as(u32, 2), stage.layout.parts[1].claim_count);
    const t = Original.Trusted{ .config = profile.config(), .layout = stage.layout, .shape = if (joint) &native.statement else null, .elf = &elf, .elf_sha256 = hash(), .values = if (joint) &.{} else &values };
    const Protocol = Original.For(joint);
    const proof = try Protocol.produce(a, t, &stage, if (joint) native.main.items else &.{});
    var live = true;
    defer if (live) proof.deinit();
    const summary = try Protocol.verify(a, t, &proof.stark, proof.native_claims, proof.lookup);
    try std.testing.expect(summary.all_lookup_buses_closed and summary.ram_open.isZero() and !summary.whole_vm_qualified);
    try std.testing.expectEqual(joint, summary.state_closed);
    try std.testing.expectEqual(joint, summary.registers_closed);
    // Preserve total byte closure while changing BOTH physical claims. The
    // individual seven-plane transcript/original equations must reject this.
    var forged = proof.lookup;
    forged.native[4] = forged.native[4].add(R.Q.one());
    forged.range20_bytes = forged.range20_bytes.sub(R.Q.one());
    try std.testing.expect(forged.native[4].add(forged.range20_bytes).eql(proof.lookup.native[4].add(proof.lookup.range20_bytes)));
    if (Protocol.verify(a, t, &proof.stark, proof.native_claims, forged)) |_| return error.AcceptedCompensatingRange20Claims else |err| if (err == error.OutOfMemory) return err;
    const raw = try Protocol.encode(a, proof);
    defer a.free(raw);
    proof.deinit();
    live = false;
    try std.testing.expectEqualDeep(summary, try Protocol.verifyBytes(a, t, raw));
    try publish(a, joint, profile, t, raw, summary);
    const bad = try a.dupe(u8, raw);
    defer a.free(bad);
    std.mem.writeInt(u32, bad[12..16], 6, .little);
    try std.testing.expectError(error.InvalidRange20Envelope, Protocol.verifyBytes(a, t, bad));
    if (!joint) {
        const last = stage.matrices[1].size() - 1;
        try std.testing.expect(stage.matrices[1].get(1, last).isZero());
        stage.matrices[1].set(2, last, R.M.fromCanonical(256));
        try std.testing.expectError(error.UnclosedRange20Lookup, Protocol.produce(a, t, &stage, &.{}));
        stage.matrices[1].set(2, last, R.M.zero());
        stage.matrices[1].set(4, last, R.M.fromCanonical(16));
        try std.testing.expectError(error.UnclosedRange20Lookup, Protocol.produce(a, t, &stage, &.{}));
    }
    std.debug.print("RANGE20_BYTES_ORIGINAL_FRESH_VERIFIED joint={} queries={d} main=4 physicalClaims=7 proofBytes={d}\n", .{ joint, profile.config().fri_config.n_queries, raw.len });
}
test "range20 bytes standalone canonical original q70 closes two byte requests per padded row" {
    try run(false, .csp_q70_pow26);
}
test "range20 bytes native consumer canonical original q70 closes all six native lookup buses" {
    try run(true, .csp_q70_pow26);
}
test "range20 bytes standalone diagnostic original q8 closes two byte requests per padded row" {
    try run(false, .diagnostic_q8_pow0);
}
test "range20 bytes native consumer diagnostic original q8 closes all six native lookup buses" {
    try run(true, .diagnostic_q8_pow0);
}
fn q(random: std.Random) R.Q {
    var limbs: [4]R.M = undefined;
    for (&limbs) |*v| v.* = R.M.fromCanonical(random.int(u32) % core.fields.m31.Modulus);
    return R.Q.fromM31Array(limbs);
}
test "range20 bytes packed scalar fold parity and exact no-wrap boundaries" {
    for (values) |v| {
        const row = try K.Spec.witness(v, R.M.one());
        try std.testing.expectEqual(v, (try K.Spec.value(R.Q, .{ R.Q.fromBase(row[0]), R.Q.fromBase(row[1]), R.Q.fromBase(row[2]), R.Q.fromBase(row[3]) }).tryIntoM31()).v);
        try std.testing.expect(row[3].v <= 15);
    }
    try std.testing.expectError(error.InvalidRange20Value, K.Spec.witness(1 << 20, R.M.one()));
    try std.testing.expectError(error.InvalidRange20Value, K.Spec.witness(0x7fffffff, R.M.one()));
    var prng = std.Random.DefaultPrng.init(0x12345678);
    const random = prng.random();
    for (0..32) |_| {
        const spec = K.Spec{ .range20 = .{ .z = q(random), .powers = .{q(random)} }, .bytes = .{ .z = q(random), .powers = .{ q(random), q(random) } }, .sums = .{ q(random), q(random) } };
        const domain = try spec.prepareDomain(16);
        const f = [1]R.Q{q(random)};
        var row: [4]R.Q = undefined;
        for (&row) |*x| x.* = q(random);
        var current: [8]R.Q = undefined;
        var before: [8]R.Q = undefined;
        for (&current) |*x| x.* = q(random);
        for (&before) |*x| x.* = q(random);
        const scalar = try domain.evaluate(f, row, @splat(R.Q.zero()), current, before, 16);
        var pf: [1]R.P = undefined;
        pf[0] = R.P.splat(f[0]);
        var prow: [4]R.P = undefined;
        var pc: [8]R.P = undefined;
        var pb: [8]R.P = undefined;
        for (&prow, row) |*p, x| p.* = R.P.splat(x);
        for (&pc, current) |*p, x| p.* = R.P.splat(x);
        for (&pb, before) |*p, x| p.* = R.P.splat(x);
        const vector = domain.evaluatePacked(pf, prow, @splat(R.P.zero()), pc, pb);
        for (scalar, vector) |x, p| try std.testing.expectEqualDeep(x, p.lane(0));
        const weight = q(random);
        try std.testing.expectEqualDeep(scalar[0].add(scalar[1].mul(weight)), vector[0].add(vector[1].mul(R.P.splat(weight))).lane(0));
    }
    try std.testing.expectEqual(@as(usize, 6), @typeInfo(K.ClaimsFor(.legacy_six)).array.len);
    try std.testing.expectEqual(@as(usize, 7), @typeInfo(@FieldType(K.Claims, "native")).array.len + 1);
}
