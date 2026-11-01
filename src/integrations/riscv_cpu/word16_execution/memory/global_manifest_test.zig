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
    // This diagnostic has its own receiving admission, independent of the
    // execution/global services validator. Invalid public cells must reject
    // before roots or helper construction can turn them into a statement.
    var malformed = cells;
    var bad_public = expected();
    bad_public.cells = &malformed;
    malformed[1] = malformed[0];
    try std.testing.expectError(error.InvalidGlobalGenesis, B.verify(a, bad_public, &agg));
    malformed = .{ cells[1], cells[0] };
    try std.testing.expectError(error.InvalidGlobalGenesis, B.verify(a, bad_public, &agg));
    malformed = cells;
    malformed[0].address |= 1;
    try std.testing.expectError(error.InvalidGlobalGenesis, B.verify(a, bad_public, &agg));
    malformed = cells;
    malformed[0].state.value ^= 1;
    try std.testing.expectError(error.InvalidGlobalGenesis, B.verify(a, bad_public, &agg));

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

fn stagedSpecs() [4]G.Spec {
    var s: [4]G.Spec = undefined;
    for (&s, 0..) |*item, i| {
        const epoch: u16 = @intCast(if (i == 3) 2 else i);
        const start: u64 = if (i < 2) 0 else if (i == 2) 16 else 32;
        const pc: u64 = if (i < 2) 0x1000 else if (i == 2) 0x1020 else 0x1040;
        const next_pc: u64 = if (i == 0) pc else if (i == 1) 0x1020 else 0x1040;
        const before: G.Digest = @splat(@intCast(if (i < 2) 1 else if (i == 2) 2 else 3));
        const after: G.Digest = @splat(@intCast(if (i == 0) 1 else if (i == 1) 2 else 3));
        item.* = .{
            .ordinal = @intCast(i),
            .role = if (i == 0) .initial else if (i == 3) .terminal else .execution,
            .coverage = .{ .first_step = start, .steps = if (i == 1 or i == 2) 16 else 0, .epoch = epoch, .initial_pc = pc, .final_pc = next_pc, .initial_registers = before, .final_registers = after },
            .schema = @splat(5),
            .statement = @splat(6),
            .fixed = .{ .bytes = @splat(7) },
            .fixed_logs = &.{ 5, 6 },
            .main_logs = &.{ 5, 7 },
            .positive_mass = .{ 2, 3, 4 },
        };
    }
    return s;
}
fn stagedContext() G.Context {
    var c = context();
    c.scope = .full_execution_unqualified;
    c.total_steps = 32;
    return c;
}
fn stagedAnchors() G.ExecutionAnchors {
    return .{ .initial_pc = 0x1000, .initial_registers = @splat(1), .terminal_pc = 0x1040, .terminal_registers = @splat(3), .total_steps = 32 };
}
fn stagedCheck(specs: []const G.Spec, anchors: G.ExecutionAnchors) !void {
    try G.validateStagedExecutionPlan(.{ .context = stagedContext(), .specs = specs }, anchors);
}

test "Full global RAM plan validates independent genesis terminal and contiguous epochs without activating proofs" {
    var s = stagedSpecs();
    try stagedCheck(&s, stagedAnchors());
    var c = stagedContext();
    c.scope = .boundary_diagnostic;
    try std.testing.expectError(error.InvalidStagedGlobalScope, G.validateStagedExecutionPlan(.{ .context = c, .specs = &s }, stagedAnchors()));
    var receipts_: [4]G.Receipt = undefined;
    for (&receipts_, s) |*r, item| r.* = .{ .ordinal = item.ordinal, .spec_digest = G.specDigest(item), .fixed = item.fixed, .main = .{ .bytes = @splat(9) } };
    // The staged validator is not the accepting protocol. Do not let passing
    // this metadata preflight turn on production/global proof publication.
    try std.testing.expectError(error.UnqualifiedGlobalExecution, G.Manifest.init(a, .{ .context = stagedContext(), .specs = &s }, &receipts_));
    try std.testing.expectError(error.InvalidStagedGlobalRoster, stagedCheck(s[0..3], stagedAnchors()));
    var anchors = stagedAnchors();
    anchors.terminal_pc ^= 4;
    try std.testing.expectError(error.InvalidStagedGlobalTerminal, stagedCheck(&s, anchors));
    anchors = stagedAnchors();
    anchors.terminal_registers[0] ^= 1;
    try std.testing.expectError(error.InvalidStagedGlobalTerminal, stagedCheck(&s, anchors));
    anchors = stagedAnchors();
    anchors.total_steps = 31;
    try std.testing.expectError(error.InvalidStagedGlobalCoverage, stagedCheck(&s, anchors));
}

test "Full global RAM plan rejects omitted duplicate reordered zero-step and gapped workers" {
    var s = stagedSpecs();
    s[1].ordinal = 2;
    try std.testing.expectError(error.InvalidStagedGlobalRoster, stagedCheck(&s, stagedAnchors()));
    s = stagedSpecs();
    s[2].role = .initial;
    try std.testing.expectError(error.InvalidStagedGlobalRoster, stagedCheck(&s, stagedAnchors()));
    s = stagedSpecs();
    s[1].coverage.epoch = 0;
    try std.testing.expectError(error.InvalidStagedGlobalRoster, stagedCheck(&s, stagedAnchors()));
    s = stagedSpecs();
    s[2].coverage.first_step += 1;
    try std.testing.expectError(error.InvalidStagedGlobalCoverage, stagedCheck(&s, stagedAnchors()));
    s = stagedSpecs();
    s[2].coverage.first_step -= 1;
    try std.testing.expectError(error.InvalidStagedGlobalCoverage, stagedCheck(&s, stagedAnchors()));
    s = stagedSpecs();
    s[1].coverage.steps = 0;
    try std.testing.expectError(error.InvalidStagedGlobalCoverage, stagedCheck(&s, stagedAnchors()));
    s = stagedSpecs();
    s[1].coverage.steps = G.MAX_EXECUTION_STEPS_PER_SHARD + 1;
    try std.testing.expectError(error.InvalidStagedGlobalCoverage, stagedCheck(&s, stagedAnchors()));
    s = stagedSpecs();
    s[0].coverage.steps = 1;
    try std.testing.expectError(error.InvalidStagedGlobalBoundary, stagedCheck(&s, stagedAnchors()));
    s = stagedSpecs();
    s[3].coverage.steps = 1;
    try std.testing.expectError(error.InvalidStagedGlobalBoundary, stagedCheck(&s, stagedAnchors()));
}

test "Full global RAM plan rejects forged adjacency geometry and characteristic claims" {
    var s = stagedSpecs();
    s[2].coverage.initial_pc ^= 4;
    try std.testing.expectError(error.InvalidStagedGlobalAdjacency, stagedCheck(&s, stagedAnchors()));
    s = stagedSpecs();
    s[2].coverage.initial_registers[0] ^= 1;
    try std.testing.expectError(error.InvalidStagedGlobalAdjacency, stagedCheck(&s, stagedAnchors()));
    s = stagedSpecs();
    s[0].coverage.final_pc ^= 4;
    try std.testing.expectError(error.InvalidStagedGlobalBoundary, stagedCheck(&s, stagedAnchors()));
    s = stagedSpecs();
    s[3].coverage.final_registers[0] ^= 1;
    try std.testing.expectError(error.InvalidStagedGlobalBoundary, stagedCheck(&s, stagedAnchors()));
    s = stagedSpecs();
    s[1].main_logs = &.{23};
    try std.testing.expectError(error.InvalidStagedGlobalGeometry, stagedCheck(&s, stagedAnchors()));
    s = stagedSpecs();
    s[1].fixed_logs = &.{};
    try std.testing.expectError(error.InvalidStagedGlobalGeometry, stagedCheck(&s, stagedAnchors()));
    s = stagedSpecs();
    s[1].positive_mass[2] = core.fields.m31.Modulus - 1;
    try std.testing.expectError(error.GlobalCharacteristicBound, stagedCheck(&s, stagedAnchors()));
}
