//! Diagnostic two-PCS boundary receiver. Actual AIR/FRI verification precedes
//! RAM closure. This is NOT a global execution/CPU coverage certificate.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
const A = @import("stwo_riscv_frontend").rv64_air;
const X = A.memory.load_store_v2;
const R = A.memory.closed_ram;
const G = @import("global_manifest.zig");
const M = core.fields.m31.M31;
const Q = G.Q;
const Col = engine.pcs.ColumnEvaluation;
const Backend = @import("stwo_cpu_backend").CpuBackend;
const FL = [_]u32{5} ** 3 ++ [_]u32{16} ** 3 ++ [_]u32{8} ** 3;
const ML = [_]u32{5} ** 23 ++ [_]u32{16} ++ [_]u32{8};
const IL = [_]u32{5} ** X.layout.BOUND_INTERACTION ++ [_]u32{16} ** 8 ++ [_]u32{8} ** 8;
pub const Encoded = struct {
    bytes: []u8,
    claims: G.PhysicalClaims,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        a.free(self.bytes);
    }
};
pub const Aggregate = struct {
    manifest: G.Manifest,
    proofs: [2]Encoded,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        for (&self.proofs) |*p| p.deinit(a);
        self.manifest.deinit();
    }
};
pub const Expected = struct { context: G.Context, image: @import("statement.zig").Image, cells: []const R.types.Cell };
const Native = struct {
    a: std.mem.Allocator,
    b: X.boundary_source.Source,
    r16: R.trace.Trace,
    r8: R.trace.Trace,
    fn init(a: std.mem.Allocator, initial: bool, cells: []const R.types.Cell) !@This() {
        var b = try X.boundary_source.Source.init(a, if (initial) .initial else .terminal, cells, 5);
        errdefer b.deinit();
        var r16 = try R.trace.Trace.init(a, .range16, 16, 0);
        errdefer r16.deinit();
        try r16.setCounts(b.counts16);
        var r8 = try R.trace.Trace.init(a, .range8, 8, 0);
        errdefer r8.deinit();
        try r8.setCounts(b.counts8);
        return .{ .a = a, .b = b, .r16 = r16, .r8 = r8 };
    }
    fn deinit(self: *@This()) void {
        self.b.deinit();
        self.r16.deinit();
        self.r8.deinit();
    }
    fn cols(self: *const @This(), tree: u2) ![]Col {
        const logs = if (tree == 0) &FL else if (tree == 1) &ML else &IL;
        const data: [3][]const M = if (tree == 0) .{ self.b.fixed, self.r16.fixed, self.r8.fixed } else if (tree == 1) .{ self.b.main, self.r16.main, self.r8.main } else .{ self.b.interaction, self.r16.interaction, self.r8.interaction };
        const out = try self.a.alloc(Col, logs.len);
        var at: usize = 0;
        for (data, [_]u32{ 5, 16, 8 }) |values, log| {
            const n = @as(usize, 1) << @intCast(log);
            for (0..values.len / n) |j| {
                out[at] = .{ .log_size = log, .values = values[j * n ..][0..n] };
                at += 1;
            }
        }
        std.debug.assert(at == logs.len);
        return out;
    }
};
fn fixedRoot(a: std.mem.Allocator, cols: []const Col) !G.Stage1Root {
    var scheme = try G.Scheme.init(a, G.P.config());
    defer scheme.deinit(a);
    var ch = G.P.Channel{};
    try scheme.commitBorrowedStreaming(a, cols, 8, &ch);
    var roots = try scheme.roots(a);
    defer roots.deinit(a);
    return .{ .bytes = roots.items[0] };
}
fn statement(cells: []const R.types.Cell) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64.global-boundary-diagnostic.cells.v1");
    var buf: [8]u8 = undefined;
    for (cells) |cell| {
        for ([_]u64{ cell.address, cell.state.value, cell.state.epoch, cell.state.tick, cell.state.rights }) |v| {
            std.mem.writeInt(u64, &buf, v, .little);
            hash.update(&buf);
        }
    }
    return hash.finalResult();
}
fn specs(a: std.mem.Allocator, expected: Expected) ![2]G.Spec {
    if (expected.cells.len >= 32) return error.DiagnosticBoundaryCapacity;
    for (expected.cells, 0..) |cell, i| {
        if (cell.address & 7 != 0 or (i != 0 and expected.cells[i - 1].address >= cell.address) or cell.state.epoch != 0 or cell.state.tick != 0) return error.InvalidGlobalGenesis;
        if (cell.state.value != try expected.image.initialWord(cell.address) or cell.state.rights != try expected.image.wordRights(cell.address)) return error.InvalidGlobalGenesis;
    }
    var native = try Native.init(a, true, expected.cells);
    defer native.deinit();
    const fixed = try native.cols(0);
    defer a.free(fixed);
    const root = try fixedRoot(a, fixed);
    var out: [2]G.Spec = undefined;
    for (&out, 0..) |*s, index| s.* = .{ .ordinal = @intCast(index), .role = if (index == 0) .initial else .terminal, .coverage = .{ .first_step = 0, .steps = 0, .epoch = @intCast(index + 1), .initial_pc = 0, .final_pc = 0, .initial_registers = @splat(0), .final_registers = @splat(0) }, .schema = X.boundary_encoding.identity(), .statement = statement(expected.cells), .fixed = root, .fixed_logs = &FL, .main_logs = &ML, .positive_mass = .{ @intCast(expected.cells.len), 0, 0 } };
    return out;
}
const Worker = struct {
    a: std.mem.Allocator,
    scheme: G.Scheme,
    ch: G.P.Channel,
    receipt: G.Receipt,
    owns: bool = true,
    fn init(a: std.mem.Allocator, ctx: G.Context, s: G.Spec, n: *Native) !@This() {
        var scheme = try G.Scheme.init(a, G.P.config());
        errdefer scheme.deinit(a);
        var ch = G.P.Channel{};
        G.beginStage1(ctx, s, &ch);
        const f = try n.cols(0);
        defer a.free(f);
        const m = try n.cols(1);
        defer a.free(m);
        try scheme.commitBorrowedStreaming(a, f, 8, &ch);
        try scheme.commitBorrowedStreaming(a, m, 8, &ch);
        return .{ .a = a, .scheme = scheme, .ch = ch, .receipt = try G.fromCommitted(a, &scheme, s) };
    }
    fn deinit(self: *@This()) void {
        if (self.owns) self.scheme.deinit(self.a);
    }
};
fn local(ch: *G.P.Channel, shared: G.Shared) X.types.Challenges {
    ch.mixU32s(&.{ 0x474d4c43, 1 });
    return .{ .ram = shared.ram, .owner = shared.owner, .range16 = .{ .offset = ch.drawSecureFelt(), .coefficient = ch.drawSecureFelt() }, .range8 = .{ .offset = ch.drawSecureFelt(), .coefficient = Q.one() }, .selection = .{ .offset = Q.one(), .coefficients = @splat(Q.zero()) } };
}
fn dictionary(a: std.mem.Allocator, n: usize, ch: @FieldType(X.types.Challenges, "range16")) ![]Q {
    const input = try a.alloc(Q, n);
    defer a.free(input);
    const out = try a.alloc(Q, n);
    errdefer a.free(out);
    for (input, 0..) |*v, index| v.* = ch.denominatorFor(Q, Q.fromBase(M.fromCanonical(@intCast(index))));
    try core.fields.batchInverseInPlace(Q, input, out);
    return out;
}
fn components(initial: bool, rows: u32, ch: X.types.Challenges, claims: G.PhysicalClaims) [3]X.component.Component {
    const at: usize = if (initial) 22 else 27;
    const z = X.types.Claims{ .ram = Q.zero(), .owner = Q.zero(), .range16 = Q.zero(), .range8 = Q.zero(), .selection = Q.zero() };
    var bc = z;
    bc.ram = claims[at];
    bc.range16 = claims[at + 2];
    bc.range8 = claims[at + 3];
    var c16 = z;
    c16.range16 = claims[3];
    var c8 = z;
    c8.range8 = claims[4];
    return .{ .{ .kind = if (initial) .initial else .terminal, .log_size = 5, .rows = rows, .offsets = .{ 0, 0, 0 }, .claims = bc, .challenges = ch }, .{ .kind = .range16, .log_size = 16, .rows = 0, .offsets = .{ 3, 23, X.layout.BOUND_INTERACTION }, .claims = c16, .challenges = ch }, .{ .kind = .range8, .log_size = 8, .rows = 0, .offsets = .{ 6, 24, X.layout.BOUND_INTERACTION + 8 }, .claims = c8, .challenges = ch } };
}
fn finish(w: *Worker, n: *Native, manifest: *const G.Manifest, index: usize) !Encoded {
    const shared = try manifest.resumeWorker(w.a, index, &w.scheme, &w.ch);
    const ch = local(&w.ch, shared);
    const d16 = try dictionary(w.a, 65536, ch.range16);
    defer w.a.free(d16);
    const d8 = try dictionary(w.a, 256, ch.range8);
    defer w.a.free(d8);
    n.b.releaseMain();
    const bc = try n.b.generate(ch, d16, d8);
    const rc = R.types.Challenges{ .ram = ch.ram, .owner = .{ .offset = Q.one(), .coefficients = @splat(Q.zero()) }, .range16 = ch.range16, .range8 = ch.range8 };
    const c16 = try n.r16.generate(rc);
    const c8 = try n.r8.generate(rc);
    var claims: G.PhysicalClaims = @splat(Q.zero());
    const at: usize = if (index == 0) 22 else 27;
    claims[at] = bc.ram;
    claims[at + 2] = bc.range16;
    claims[at + 3] = bc.range8;
    claims[3] = c16.range16;
    claims[4] = c8.range8;
    try G.mixClaims(&w.ch, claims);
    const inter = try n.cols(2);
    defer w.a.free(inter);
    try w.scheme.commitBorrowedStreaming(w.a, inter, 8, &w.ch);
    const list = components(index == 0, n.b.rows, ch, claims);
    var handles: [3]engine.air.component_prover.ComponentProver = undefined;
    for (&list, &handles) |*c, *h| h.* = c.asProverComponent();
    w.owns = false;
    var proof = try engine.prove.prove(Backend, G.P.Hasher, G.P.MerkleChannel, w.a, &handles, &w.ch, w.scheme);
    defer proof.deinit(w.a);
    return .{ .bytes = try wire.encodeProofBytesBinary(w.a, proof), .claims = claims };
}
pub fn produce(a: std.mem.Allocator, expected: Expected) !Aggregate {
    const inventory = try specs(a, expected);
    try G.validateExpected(.{ .context = expected.context, .specs = &inventory });
    var n0 = try Native.init(a, true, expected.cells);
    defer n0.deinit();
    var n1 = try Native.init(a, false, expected.cells);
    defer n1.deinit();
    var w0 = try Worker.init(a, expected.context, inventory[0], &n0);
    defer w0.deinit();
    var w1 = try Worker.init(a, expected.context, inventory[1], &n1);
    defer w1.deinit();
    var manifest = try G.Manifest.init(a, .{ .context = expected.context, .specs = &inventory }, &.{ w0.receipt, w1.receipt });
    errdefer manifest.deinit();
    var p0 = try finish(&w0, &n0, &manifest, 0);
    errdefer p0.deinit(a);
    return .{ .manifest = manifest, .proofs = .{ p0, try finish(&w1, &n1, &manifest, 1) } };
}
fn verifyOne(a: std.mem.Allocator, expected: Expected, manifest: *const G.Manifest, index: usize, encoded: Encoded) !void {
    if (encoded.bytes.len > 16 * 1024 * 1024) return error.GlobalProofLimit;
    try G.validateClaims(encoded.claims);
    const at: usize = if (index == 0) 22 else 27;
    for (encoded.claims, 0..) |q, i| if (i != 3 and i != 4 and i != at and i != at + 2 and i != at + 3 and !q.isZero()) return error.UnphysicalGlobalClaim;
    if (!encoded.claims[3].add(encoded.claims[at + 2]).isZero() or !encoded.claims[4].add(encoded.claims[at + 3]).isZero()) return error.UnclosedLocalRange;
    var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(G.P.Hasher, G.P.MerkleChannel).init(a, G.P.config());
    defer verifier.deinit(a);
    var channel = G.P.Channel{};
    G.beginStage1(expected.context, manifest.specs[index], &channel);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4) return error.InvalidGlobalProof;
    try verifier.commit(a, roots[0], &FL, &channel);
    try verifier.commit(a, roots[1], &ML, &channel);
    const shared = try manifest.resumeReceiver(index, &proof, &channel);
    const ch = local(&channel, shared);
    if (!encoded.claims[at].eql(try X.boundary_source.expectedClaim(expected.cells, index == 0, ch.ram))) return error.GlobalExpectedBoundaryMismatch;
    try G.mixClaims(&channel, encoded.claims);
    try verifier.commit(a, roots[2], &IL, &channel);
    const list = components(index == 0, @intCast(expected.cells.len), ch, encoded.claims);
    var handles: [3]core.air.components.Component = undefined;
    for (&list, &handles) |*c, *h| h.* = c.asVerifierComponent();
    owns = false;
    try core.verifier.verify(G.P.Hasher, G.P.MerkleChannel, a, &handles, &channel, &verifier, proof);
}
/// Independently expected cells must be authorized by the receiver's pristine
/// image/policy. No prover end-image or native root grants that authority.
pub fn verify(a: std.mem.Allocator, expected: Expected, aggregate: *const Aggregate) !void {
    const inventory = try specs(a, expected);
    try aggregate.manifest.check(.{ .context = expected.context, .specs = &inventory });
    for (aggregate.proofs, 0..) |p, index| try verifyOne(a, expected, &aggregate.manifest, index, p);
    try G.closeVerified(&.{ aggregate.proofs[0].claims, aggregate.proofs[1].claims });
}
