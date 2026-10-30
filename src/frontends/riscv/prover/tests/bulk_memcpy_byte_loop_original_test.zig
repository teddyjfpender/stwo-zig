const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Original = @import("../bulk_memcpy_byte_loop_original_v1.zig");
const Scope = @import("../bulk_memcpy_byte_loop_scope_v1.zig");
const C = @import("../../air/guest_precompile/bulk_memcpy_byte_loop_certificate_v1.zig");
const K = @import("../../air/guest_precompile/bulk_memcpy_byte_loop_kernel_v1.zig");
const A = @import("../bulk_memcpy_byte_loop_components_v1.zig");
const Profile = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile;
const code = C.words ++ [_]u32{0x0000006f};
const elf = blk: {
    var image = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 1024, .rv32im_zkvm_v1);
    const table = std.mem.readInt(u32, image[264..268], .little);
    for ([4]usize{ 2, 3, 7, 8 }, [4]u32{ 0x100100, 1024, 0x100800, 0x100810 }) |index, value| std.mem.writeInt(u32, image[table + (index + 1) * 16 + 4 ..][0..4], value, .little);
    break :blk image;
};
const source_words = [5]u32{ 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110 };
const before = [5]u32{ 0xa1a2a3a4, 0xb1b2b3b4, 0xc1c2c3c4, 0xd1d2d3d4, 0xe1e2e3e4 };
const previous: [5]u32 = @splat(0);
fn trusted(profile: Profile) Original.Trusted {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&elf, &hash, .{});
    return .{ .elf = &elf, .elf_sha256 = hash, .profile = .rv32im_zkvm_v1, .config = profile.config(), .public = .{ .pc = 0x1000, .call = .{ .entry_cycle = 7, .source = 0x100101, .destination = 0x100202, .destination_end = 0x100213, .length = 17, .max_instruction_cycle = 91 }, .previous_register_clocks = @splat(0), .initial_scratch = 0xaabbccdd, .last_byte = 0x11, .source_previous_clocks = &previous, .destination_previous_clocks = &previous } };
}
fn rejectProof(a: std.mem.Allocator, t: Original.Trusted, proof: *const Original.Proof, claims: Original.Claims) !void {
    if (Original.verify(a, t, &proof.stark, claims)) |_| return error.AcceptedByteLoopForgery else |err| if (err == error.OutOfMemory) return err;
}
fn rejectStage(a: std.mem.Allocator, scope: *const Scope.Scope, stage: *const Original.Stage) !void {
    if (Original.produceStage(a, scope, stage)) |proof| {
        defer proof.deinit();
        try rejectProof(a, scope.trusted, proof, proof.claims);
    } else |err| {
        if (err == error.OutOfMemory) return err;
        if (err == error.UnclosedByteLoopValueQueries or err == error.UnclosedByteLoopLocalRam or err == error.UnclosedByteLoopEndpointRanges or err == error.UnclosedByteLoopRanges or err == error.UnclosedByteLoopValueCount or err == error.UntrustedByteLoopBoundaryClaims) return error.ExpectedOriginalPackingConstraintRejection;
    }
}
fn publish(a: std.mem.Allocator, profile: Profile, t: Original.Trusted, raw: []const u8, summary: Original.Summary) !void {
    const base = std.posix.getenv("STWO_BYTE_LOOP_ORIGINAL_OUTPUT") orelse return;
    const path = try std.fs.path.join(a, &.{ base, @tagName(profile) });
    defer a.free(path);
    try std.fs.cwd().makePath(path);
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    try dir.writeFile(.{ .sub_path = "math.proof", .data = raw });
    try dir.writeFile(.{ .sub_path = "guest.elf", .data = t.elf });
    const metadata = try std.json.Stringify.valueAlloc(a, .{ .schema = "stwo-same-rom-byte-loop-original-public-v1", .scope = "standalone original macro theorem; external program/state/register/global-transition projections OPEN; not a VM or Ethereum proof", .elf_sha256 = std.fmt.bytesToHex(t.elf_sha256, .lower), .profile = @tagName(t.profile), .config = t.config, .public = t.public }, .{ .whitespace = .indent_2 });
    defer a.free(metadata);
    try dir.writeFile(.{ .sub_path = "public.json", .data = metadata });
    var proof_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &proof_hash, .{});
    const report = try std.json.Stringify.valueAlloc(a, .{ .schema = "stwo-same-rom-byte-loop-original-proof-result-v1", .profile = @tagName(profile), .proof_bytes = raw.len, .proof_sha256 = std.fmt.bytesToHex(proof_hash, .lower), .original_fresh_fixed_key_verified = true, .local_value_queries_closed = true, .byte_ranges_closed = true, .local_ram_closed = true, .physical_claims = 31, .trace_trees = 13, .composition_split = 2, .whole_vm_qualified = false, .summary = summary }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try dir.writeFile(.{ .sub_path = "report.json", .data = report });
}
fn run(profile: Profile) !void {
    const a = std.testing.allocator;
    const t = trusted(profile);
    const proof = try Original.produce(a, t, .{ .source_words = &source_words, .destination_before = &before });
    var proof_live = true;
    defer if (proof_live) proof.deinit();
    const summary = try Original.verify(a, t, &proof.stark, proof.claims);
    try std.testing.expectEqual(@as(u32, 85), summary.retired_instructions);
    try std.testing.expectEqual(@as(u32, 85), summary.program_fetches);
    try std.testing.expectEqual(@as(u32, 34), summary.logical_ram_accesses);
    try std.testing.expectEqual(@as(u32, 10), summary.external_ram_word_edges);
    try std.testing.expect(summary.local_ram_closed);
    try std.testing.expect(!summary.whole_vm_qualified);
    var claims = proof.claims;
    const total = claims.source[0].add(claims.destination[0]);
    claims.source[0] = claims.source[0].add(Q.one());
    claims.destination[0] = claims.destination[0].sub(Q.one());
    try std.testing.expect(total.eql(claims.source[0].add(claims.destination[0])));
    try rejectProof(a, t, proof, claims);
    var changed = t;
    changed.public.last_byte +%= 1;
    try rejectProof(a, changed, proof, proof.claims);
    const raw = try Original.encode(a, proof);
    defer a.free(raw);
    proof.deinit();
    proof_live = false;
    // Producer keys, source values, multiplicities and every original PCS
    // polynomial are gone before these fresh independent reconstructions.
    try std.testing.expectEqualDeep(summary, try Original.verifyBytes(a, t, raw));
    try publish(a, profile, t, raw, summary);
    const malformed = try a.dupe(u8, raw);
    defer a.free(malformed);
    std.mem.writeInt(u32, malformed[12..16], 17, .little);
    try std.testing.expectError(error.InvalidByteLoopEnvelope, Original.verifyBytes(a, t, malformed));
}
test "diagnostic same ROM byte loop original STARK closes ranges and source queries and fresh verifies" {
    try run(.diagnostic_q8_pow0);
}
test "canonical same ROM byte loop original STARK closes ranges and source queries and fresh verifies" {
    try run(.csp_q70_pow26);
}
test "same ROM byte loop original STARK rejects changed packing even with byte supply repaired" {
    const a = std.testing.allocator;
    const t = trusted(.diagnostic_q8_pow0);
    const scope = try Scope.Scope.create(a, t);
    defer scope.deinit();
    var stage = try Original.Stage.create(a, scope, .{ .source_words = &source_words, .destination_before = &before });
    defer stage.deinit();
    const after_column = A.Spec(.destination).FIXED_COUNT + K.Layout.destination_after + 2;
    const old = stage.matrices.destination.get(after_column, 0).v;
    const replacement = (old + 1) % 256;
    stage.matrices.destination.set(after_column, 0, M.fromCanonical(replacement));
    const count_column = A.Spec(.bytes).FIXED_COUNT;
    // Repair the corresponding endpoint and BOTH byte-table occurrences so
    // local RAM and byte claims still close. Only the real packing equations
    // can reject this committed arithmetic mutation.
    const endpoint_row = scope.source_words;
    stage.matrices.endpoints.set(A.EndpointSpec.FIXED_COUNT + 7 + 2, endpoint_row, M.fromCanonical(replacement));
    stage.matrices.bytes.set(count_column, old, stage.matrices.bytes.get(count_column, old).sub(M.fromCanonical(2)));
    stage.matrices.bytes.set(count_column, replacement, stage.matrices.bytes.get(count_column, replacement).add(M.fromCanonical(2)));
    try rejectStage(a, scope, &stage);
}
test "same ROM byte loop original source query and independent public bounds reject substitutions" {
    const a = std.testing.allocator;
    const t = trusted(.diagnostic_q8_pow0);
    const scope = try Scope.Scope.create(a, t);
    defer scope.deinit();
    var stage = try Original.Stage.create(a, scope, .{ .source_words = &source_words, .destination_before = &before });
    defer stage.deinit();
    const column = A.Spec(.destination).FIXED_COUNT + K.Layout.source_high + 1;
    stage.matrices.destination.set(column, 0, stage.matrices.destination.get(column, 0).add(M.one()));
    try std.testing.expectError(error.UnclosedByteLoopValueQueries, Original.produceStage(a, scope, &stage));
    var changed = t;
    changed.public.pc += 4;
    if (Scope.Scope.create(a, changed)) |accepted| {
        accepted.deinit();
        return error.AcceptedByteLoopRomSubstitution;
    } else |err| if (err == error.OutOfMemory) return err;
    changed = t;
    changed.public.call.destination = changed.public.call.source;
    try std.testing.expectError(error.OverlappingByteLoopWords, Scope.Scope.create(a, changed));
    changed = t;
    changed.public.previous_register_clocks[0] = 25;
    try std.testing.expectError(error.InvalidByteLoopRegisterPredecessor, Scope.Scope.create(a, changed));
}
