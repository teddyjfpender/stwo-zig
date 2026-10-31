const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const G = @import("global_manifest.zig");
const B = @import("global_boundary_proof.zig");
const a = std.testing.allocator;
const cells = [_]A.memory.closed_ram.types.Cell{ .{ .address = 0x1000, .state = .{ .value = 0xfedcba9876543210, .rights = 3 } }, .{ .address = 0x2000, .state = .{ .value = 0x8000000012345678, .rights = 1 } } };
var image_context: u8 = 0;
const Image = struct {
    fn word(_: *const anyopaque, address: u64) !u64 {
        for (cells) |cell| if (cell.address == address) return cell.state.value;
        return error.UnknownGenesisWord;
    }
    fn rights(_: *const anyopaque, address: u64) !u2 {
        for (cells) |cell| if (address >= cell.address and address < cell.address + 8) return cell.state.rights;
        return 0;
    }
};
fn expected() B.Expected {
    return .{ .context = .{ .execution = @splat(1), .program = @splat(2), .image = @splat(3), .policy = @splat(4), .opcode_map = @splat(5), .total_steps = 0 }, .image = .{ .context = &image_context, .initial_word = Image.word, .rights_at = Image.rights }, .cells = &cells };
}
test "Complete stage1 manifest fresh-verifies both physical boundary proofs before global RAM closure" {
    var agg = try B.produce(a, expected());
    defer agg.deinit(a);
    try B.verify(a, expected(), &agg);
    try std.testing.expect(!agg.proofs[0].claims[22].isZero());
    try std.testing.expect(agg.proofs[0].claims[22].add(agg.proofs[1].claims[27]).isZero());
    var bad = expected();
    bad.context.image[0] ^= 1;
    try std.testing.expectError(error.GlobalExpectedMismatch, B.verify(a, bad, &agg));
    const original = agg.proofs[0].claims[22];
    agg.proofs[0].claims[22] = original.add(G.Q.one());
    agg.proofs[1].claims[27] = agg.proofs[1].claims[27].sub(G.Q.one());
    try G.closeVerified(&.{ agg.proofs[0].claims, agg.proofs[1].claims });
    try std.testing.expectError(error.GlobalExpectedBoundaryMismatch, B.verify(a, expected(), &agg));
    agg.proofs[0].claims[22] = original;
    agg.proofs[1].claims[27] = original.neg();
    const root = agg.manifest.receipts[0].main;
    agg.manifest.receipts[0].main.bytes[0] ^= 1;
    try std.testing.expectError(error.GlobalManifestChanged, agg.manifest.derive());
    agg.manifest.receipts[0].main = root;
    var proof = try @import("stwo_proof_wire").decodeProofBytesBinary(a, agg.proofs[0].bytes);
    defer proof.deinit(a);
    proof.commitment_scheme_proof.sampled_values.items[1][0][0] = proof.commitment_scheme_proof.sampled_values.items[1][0][0].add(G.Q.one());
    const forged = try @import("stwo_proof_wire").encodeProofBytesBinary(a, proof);
    defer a.free(forged);
    const saved = agg.proofs[0].bytes;
    agg.proofs[0].bytes = forged;
    defer agg.proofs[0].bytes = saved;
    if (B.verify(a, expected(), &agg)) |_| return error.ForgedPhysicalProofAccepted else |_| {}
}
fn synthetic() [2]G.Spec {
    var specs: [2]G.Spec = undefined;
    for (&specs, 0..) |*s, i| s.* = .{ .ordinal = @intCast(i), .role = if (i == 0) .initial else .terminal, .coverage = .{ .first_step = i * 16, .steps = 16, .epoch = @intCast(i + 1), .initial_pc = 0x1000 + i * 64, .final_pc = 0x1040 + i * 64, .initial_registers = @splat(@intCast(i)), .final_registers = @splat(@intCast(i + 1)) }, .schema = @splat(5), .statement = @splat(6), .fixed = .{ .bytes = @splat(7) }, .fixed_logs = &.{ 5, 5, 5 }, .main_logs = &.{ 5, 5 }, .positive_mass = .{ 2, 1, 1 } };
    return specs;
}
fn context() G.Context {
    var c = expected().context;
    c.total_steps = 32;
    return c;
}
fn receipts(specs: []const G.Spec) [2]G.Receipt {
    var r: [2]G.Receipt = undefined;
    for (&r, specs) |*v, s| v.* = .{ .ordinal = s.ordinal, .spec_digest = G.specDigest(s), .fixed = s.fixed, .main = .{ .bytes = @splat(@intCast(s.ordinal + 8)) } };
    return r;
}
test "Global exact inventory epoch coverage adjacency and characteristic admission precede allocation" {
    var s = synthetic();
    const rs = receipts(&s);
    const e = G.Expected{ .context = context(), .specs = &s };
    var m = try G.Manifest.init(a, e, &rs);
    defer m.deinit();
    const shared = try m.derive();
    try std.testing.expect(!shared.ram.offset.eql(shared.owner.offset));
    try std.testing.expectError(error.IncompleteGlobalManifest, G.Manifest.init(a, e, rs[0..1]));
    s[1].coverage.first_step += 1;
    try std.testing.expectError(error.InvalidGlobalCoverage, G.Manifest.init(a, e, &rs));
    s[1].coverage.first_step -= 1;
    s[1].coverage.initial_pc += 1;
    try std.testing.expectError(error.InvalidGlobalAdjacency, G.Manifest.init(a, e, &rs));
    s[1].coverage.initial_pc -= 1;
    s[1].coverage.epoch = 1;
    try std.testing.expectError(error.InvalidGlobalCoverage, G.Manifest.init(a, e, &rs));
    s[1].coverage.epoch = 2;
    s[1].positive_mass[0] = core.fields.m31.Modulus - 2;
    try std.testing.expectError(error.GlobalCharacteristicBound, G.Manifest.init(a, e, &rs));
    s[1].positive_mass[0] = 2;
    var full = e;
    full.context.scope = .full_execution_unqualified;
    try std.testing.expectError(error.UnqualifiedGlobalExecution, G.Manifest.init(a, full, &rs));
    var wrong = rs;
    wrong[0].ordinal = 1;
    try std.testing.expectError(error.GlobalInventoryMismatch, G.Manifest.init(a, e, &wrong));
}
test "Global manifest owns expected inventory with balanced exhaustive allocation failure cleanup" {
    const Runner = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var s = synthetic();
            const rs = receipts(&s);
            var m = try G.Manifest.init(allocator, .{ .context = context(), .specs = &s }, &rs);
            defer m.deinit();
            s[0].schema[0] ^= 1;
            try m.unchanged();
        }
    };
    try std.testing.checkAllAllocationFailures(a, Runner.run, .{});
    var claims: G.PhysicalClaims = @splat(G.Q.zero());
    claims[23] = G.Q.one();
    try std.testing.expectError(error.NonzeroOmittedGlobalClaim, G.validateClaims(claims));
    claims[23] = G.Q.zero();
    claims[0].c0.a.v = core.fields.m31.Modulus;
    try std.testing.expectError(error.NoncanonicalGlobalClaim, G.validateClaims(claims));
}
