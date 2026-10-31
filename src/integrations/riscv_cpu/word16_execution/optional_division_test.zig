const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const front = @import("stwo_riscv_frontend");
const X = front.rv64_air.word16_execution;
const Mat = @import("setup.zig");
const P = @import("protocol.zig");
const C = @import("components.zig").Components;
const S = @import("sources.zig").Source;
const Native = @import("prepared.zig").Prepared;
const E = @import("execution.zig");
const Measure = @import("measurement.zig");
const a = std.testing.allocator;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const WORDS = [_]u32{ 0x00700093, 0x0010c133 };
var context: u8 = 0;
const Zero = struct {
    fn word(_: *const anyopaque, _: u64) !u64 {
        return 0;
    }
    fn rights(_: *const anyopaque, _: u64) !u2 {
        return 0;
    }
};
fn admission() E.Admission {
    return .{ .image = .{ .context = &context, .initial_word = Zero.word, .rights_at = Zero.rights }, .image_identity = @splat(9), .initial_pc = 4096, .initial_registers = @splat(0) };
}
const Fixture = struct {
    tape: front.rv64.compact_tape.Tape,
    public: X.types.Boundary,
    fn init() !Fixture {
        var tape = try front.rv64.compact_tape.Tape.init(a, 2, 4096, 0, .ethereum_services_v2);
        tape.len = 2;
        tape.storage[0] = .{ .next_pc = 4100, .lhs = 0, .rhs = 0, .previous_rd = 0, .result = 7, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
        tape.storage[1] = .{ .next_pc = 4104, .lhs = 7, .rhs = 7, .previous_rd = 0, .result = 0, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
        var public: X.types.Boundary = .{ .steps = 2, .initial_pc = 4096, .final_pc = 4104, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) };
        public.final_registers[1] = 7;
        public.register_clocks[1] = 6;
        public.register_clocks[2] = 7;
        return .{ .tape = tape, .public = public };
    }
    fn deinit(self: *Fixture) void {
        self.tape.deinit();
    }
};
fn sampledCounts(bytes: []const u8) ![4]usize {
    var proof = try wire.decodeProofBytesBinary(a, bytes);
    defer proof.deinit(a);
    const trees = proof.commitment_scheme_proof.sampled_values.items;
    if (trees.len != 4) return error.InvalidExecutionSampleTrees;
    var counts: [4]usize = @splat(0);
    for (trees, 0..) |tree, i| for (tree) |column| {
        counts[i] += column.len;
    };
    return counts;
}
fn geometry(omit: bool) Mat.Geometry {
    return .{ .cpu_log = 5, .omit_empty_division = omit };
}

test "Empty DIV shape removes all fixed main interaction and component samples while legacy class remains default" {
    var legacy = try Mat.Materials.init(a, .{ .base = 4096, .words = &WORDS }, geometry(false));
    defer legacy.deinit();
    var omitted = try Mat.Materials.init(a, .{ .base = 4096, .words = &WORDS }, geometry(true));
    defer omitted.deinit();
    try std.testing.expect(!(Mat.Geometry{ .cpu_log = 5 }).omit_empty_division);
    try std.testing.expectEqual([3]usize{ 0, 0, 0 }, omitted.shape(.division).widths);
    try std.testing.expectEqual(@as(usize, 0), omitted.division_fixed.len);
    try std.testing.expectEqual(@as(usize, 16), Mat.G.componentCount(&omitted.shapes()));
    const before = try Mat.G.cells(&legacy.shapes());
    const after = try Mat.G.cells(&omitted.shapes());
    const D = front.rv64_air.arithmetic.division.layout;
    try std.testing.expectEqual(@as(u64, D.FIXED * 32), before.fixed - after.fixed);
    try std.testing.expectEqual(@as(u64, D.MAIN * 32), before.main - after.main);
    try std.testing.expectEqual(@as(u64, D.INTERACTION * 32), before.interaction - after.interaction);
    try std.testing.expectError(error.InvalidOmittedDivisionGeometry, (Mat.Geometry{ .cpu_log = 5, .division_log = 6, .omit_empty_division = true }).validate());
}

test "Omitted DIV proves fresh with exact semantics, canonical zero claim and owned-buffer custody" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var legacy = try Mat.Setup.init(a, .{ .base = 4096, .words = &WORDS }, geometry(false));
    defer legacy.deinit();
    var omitted = try Mat.Setup.init(a, .{ .base = 4096, .words = &WORDS }, geometry(true));
    defer omitted.deinit();
    var old = try E.prove(a, &legacy, admission(), fixture.public, &fixture.tape, null);
    defer old.deinit(a);
    var proof = try E.prove(a, &omitted, admission(), fixture.public, &fixture.tape, null);
    defer proof.deinit(a);
    try std.testing.expectEqualDeep(old.request, proof.request);
    try std.testing.expect(proof.claims.division.isZero());
    const old_samples = try sampledCounts(old.bytes);
    const omitted_samples = try sampledCounts(proof.bytes);
    // Pin the physical DIV withdrawal, independently of unrelated LS/ALU
    // encoding widths: fixed3, main1135 plus one previous mask, interaction8
    // plus four previous-prefix coordinates, and no composition change.
    for (old_samples, omitted_samples, [_]usize{ 3, 1136, 12, 0 }) |normal, absent, removed| {
        try std.testing.expectEqual(removed, normal - absent);
    }
    try std.testing.expectEqual(@as(usize, 1151), (old_samples[0] + old_samples[1] + old_samples[2]) - (omitted_samples[0] + omitted_samples[1] + omitted_samples[2]));
    try std.testing.expect(proof.bytes.len < old.bytes.len);
    try std.testing.expect(!std.mem.eql(u8, proof.bytes, old.bytes));
    var fresh = try Mat.Setup.init(a, .{ .base = 4096, .words = &WORDS }, geometry(true));
    defer fresh.deinit();
    try E.verify(a, &fresh, admission(), proof);
    var wrong = proof;
    wrong.request.division_requests = 1;
    try std.testing.expectError(error.OmittedDivisionRequests, E.verify(a, &fresh, admission(), wrong));
    wrong = proof;
    wrong.claims.division = Q.one();
    wrong.claims.cpu = wrong.claims.cpu.sub(Q.one());
    try wrong.claims.validate(); // Balanced aggregate is insufficient.
    try std.testing.expectError(error.OmittedDivisionClaim, E.verify(a, &fresh, admission(), wrong));
    var native = try Native.capture(a, &omitted.materials.program, fixture.public, 1, 5, &fixture.tape, .{});
    defer native.deinit();
    try std.testing.expect((try native.geometryOmittingEmptyDivision()).omit_empty_division);
    var source = try S.fromPrepared(a, &omitted.materials, admission().image, &native);
    defer source.deinit();
    const div_main = source.division.main.ptr;
    const owned = try source.takeMainForCommit();
    defer owned.deinit(a);
    try std.testing.expect(source.division.owns_main);
    try std.testing.expectEqual(div_main, source.division.main.ptr);
    for (owned.backings) |backing| try std.testing.expect(backing.ptr != div_main);
    var channel = P.T.P.Channel{};
    const ch = P.draw(&channel);
    const claims = try source.generate(ch);
    var components = try C.init(&omitted.materials, source.request(), ch, claims);
    const measured = try Measure.inspect(a, &components);
    try std.testing.expectEqual(@as(u64, 0), measured.components[@intFromEnum(Mat.Role.division)].evaluation_points);
    try std.testing.expect(!measured.components[@intFromEnum(Mat.Role.division)].present);
    const handles = try components.verifiers(a);
    defer a.free(handles);
    try std.testing.expectEqual(@as(usize, 16), handles.len);
}

fn exerciseOmissionOom(allocator: std.mem.Allocator, fixture: *const Fixture) !void {
    var setup = try Mat.Setup.init(allocator, .{ .base = 4096, .words = &WORDS }, geometry(true));
    defer setup.deinit();
    var source = try S.init(allocator, &setup.materials, admission().image, fixture.public, 1, &fixture.tape);
    defer source.deinit();
    const owned = try source.takeMainForCommit();
    defer owned.deinit(allocator);
    try std.testing.expect(source.division.owns_main);
}
test "Omitted unused DIV retains its allocation owner through every setup constructor and MAIN handoff allocation failure" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try std.testing.checkAllAllocationFailures(a, exerciseOmissionOom, .{&fixture});
}

// Independent low-level physical verification deliberately omits only the
// aggregate FUNCTION closure. This private test helper grants no execution
// acceptance and is never exported by the production receiver.
fn verifyPhysicalFragment(setup: *const Mat.Setup, trust: E.Admission, fragment: E.Encoded) !void {
    var proof = try wire.decodeProofBytesBinary(a, fragment.bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    if (!std.mem.eql(u8, &proof.commitment_scheme_proof.commitments.items[0], &setup.fixed_root.value)) return error.UnexpectedFragmentFixedRoot;
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(P.T.P.Hasher, P.T.P.MerkleChannel).init(a, P.T.P.config());
    defer verifier.deinit(a);
    var channel = P.T.P.Channel{};
    try P.mix(&channel, setup, fragment.request, trust.image_identity);
    for ([_]usize{ 0, 1 }) |tree| {
        const logs = try setup.materials.logs(a, tree);
        defer a.free(logs);
        try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[tree], logs, &channel);
    }
    const ch = P.draw(&channel);
    channel.mixFelts(&fragment.claims.values());
    const logs = try setup.materials.logs(a, 2);
    defer a.free(logs);
    try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[2], logs, &channel);
    var components = try C.init(&setup.materials, fragment.request, ch, fragment.claims);
    const handles = try components.verifiers(a);
    defer a.free(handles);
    owns = false;
    try core.verifier.verify(P.T.P.Hasher, P.T.P.MerkleChannel, a, handles, &channel, &verifier, proof);
}

// Test-only open physical fragment. No native arithmetic oracle is called:
// the Tape deliberately says7/2=4 and its DIV request queue is erased after
// capture. Every remaining component can prove, but FUNCTION debt must reject.
test "A physically valid unserved false DIV fragment cannot become a complete execution proof or cancel through placeholder" {
    const div_word: u32 = 0x0220d1b3; // DIVU x3,x1,x2
    var setup = try Mat.Setup.init(a, .{ .base = 4096, .words = &.{div_word} }, geometry(true));
    defer setup.deinit();
    var tape = try front.rv64.compact_tape.Tape.init(a, 1, 4096, 0, .ethereum_services_v2);
    defer tape.deinit();
    tape.len = 1;
    tape.storage[0] = .{ .next_pc = 4100, .lhs = 7, .rhs = 2, .previous_rd = 0, .result = 4, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
    var public: X.types.Boundary = .{ .steps = 1, .initial_pc = 4096, .final_pc = 4100, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) };
    public.initial_registers[1] = 7;
    public.initial_registers[2] = 2;
    public.final_registers = public.initial_registers;
    public.final_registers[3] = 4;
    public.register_clocks[1] = 1;
    public.register_clocks[2] = 2;
    public.register_clocks[3] = 3;
    var trust = admission();
    trust.initial_registers = public.initial_registers;
    var native = try Native.capture(a, &setup.materials.program, public, 1, 5, &tape, .{});
    defer native.deinit();
    try std.testing.expectEqual(@as(usize, 1), native.division.len);
    try std.testing.expectError(error.OmittedDivisionRequests, S.fromPrepared(a, &setup.materials, trust.image, &native));
    // Deliberate hostile witness mutation; this is not a production API.
    a.free(native.division);
    native.division = &.{};
    var source = try S.fromPrepared(a, &setup.materials, trust.image, &native);
    defer source.deinit();
    const request = source.request();
    try trust.validate(&setup, request);
    var scheme = try P.T.Scheme.init(a, P.T.P.config());
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(5);
    var channel = P.T.P.Channel{};
    try P.mix(&channel, &setup, request, trust.image_identity);
    try setup.appendFixed(a, &scheme, &channel);
    const main = try source.columns(a, 1);
    defer a.free(main);
    try scheme.commitBorrowedStreaming(a, main, 8, &channel);
    try source.releaseMain();
    const ch = P.draw(&channel);
    const claims = (try source.generateForKeccakJoin(ch)).physical;
    try std.testing.expect(claims.division.isZero());
    try std.testing.expectError(error.UnclosedExecutionRelations, claims.validate());
    channel.mixFelts(&claims.values());
    const interaction = try source.columns(a, 2);
    defer a.free(interaction);
    try scheme.commitBorrowedStreaming(a, interaction, 8, &channel);
    var components = try C.init(&setup.materials, request, ch, claims);
    const handles = try components.provers(a);
    defer a.free(handles);
    owns = false;
    var result = try engine.prove.proveExWithRecorder(Backend, P.T.P.Hasher, P.T.P.MerkleChannel, a, handles, &channel, scheme, false, null);
    result.aux.deinit(a);
    defer result.proof.deinit(a);
    const bytes = try wire.encodeProofBytesBinary(a, result.proof);
    defer a.free(bytes);
    var fragment = E.Encoded{ .bytes = bytes, .claims = claims, .request = request };
    try verifyPhysicalFragment(&setup, trust, fragment);
    try std.testing.expectError(error.UnclosedExecutionRelations, E.verify(a, &setup, trust, fragment));
    var total = Q.zero();
    for (claims.values()) |value| total = total.add(value);
    fragment.claims.division = total.neg();
    try fragment.claims.validate();
    try std.testing.expectError(error.OmittedDivisionClaim, E.verify(a, &setup, trust, fragment));
}
