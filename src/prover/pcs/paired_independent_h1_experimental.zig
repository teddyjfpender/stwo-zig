//! Host reference prover for the one-height, independent-track degree test.
//! The full source tree and both domain batches are resident. No production
//! prover or verifier selects this path.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Channel = core.channel.blake2s.Blake2sChannel;
const dual = core.pcs.paired_independent_h1_experimental;
const sparse = core.pcs.transposed_merkle_sparse_heights_experimental;
const source_host = @import("transposed_sparse_heights_experimental.zig");
const old = @import("paired_two_height_experimental.zig");
const LineEvaluation = @import("../line.zig").LineEvaluation;

pub const Input = struct {
    columns: []const []const M31,
    log_blowup: u32,
    query_count: usize,
};

pub const OwnedProof = struct {
    arena: std.heap.ArenaAllocator,
    proof: dual.Proof,
    pub fn deinit(self: *OwnedProof) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

fn terminal(allocator: std.mem.Allocator, domain: core.poly.line.LineDomain, values: []const QM31, bound: usize) ![]const QM31 {
    var evaluation = try LineEvaluation.initBorrowed(domain, values);
    var polynomial = try evaluation.interpolate(allocator);
    const ordered = polynomial.intoOrderedCoefficients();
    for (ordered[bound..]) |coefficient|
        if (!coefficient.isZero()) return error.TerminalDegreeExceeded;
    return ordered[0..bound];
}

pub fn prove(allocator: std.mem.Allocator, input: Input, channel: *Channel) !OwnedProof {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    const heights = [_][]const []const M31{input.columns};
    var source = try source_host.Commitment.commit(a, &heights, input.query_count);
    const profile = dual.Profile{ .source = source.profile, .log_blowup = input.log_blowup };
    try dual.validateProfile(profile);
    const root = source.root();
    const k = source.profile.largest_log_size;
    const domain = core.poly.circle.canonic.CanonicCoset.new(k).circleDomain();
    try old.validateSourceDegree(a, domain, input.columns, k - input.log_blowup);

    var staged = channel.*;
    dual.bindVersion(&staged);
    const point = try core.pcs.paired_sparse_cascade_heights_experimental.drawOodPoint(&staged, profile, root);
    const values = try a.alloc(QM31, input.columns.len);
    try old.evaluateClaims(a, domain, input.columns, point, values);
    const claims = try a.alloc([]const QM31, 1);
    claims[0] = values;
    const batch = try core.pcs.paired_sparse_cascade_heights_experimental.drawBatchAfterOod(&staged, claims);
    var context = try dual.RowContext.init(a, point, values, batch);
    const size = domain.size();
    const originals = try a.alloc(QM31, size);
    const quotients = try a.alloc(QM31, size);
    for (0..size) |row| {
        const p = domain.at(core.utils.bitReverseIndex(row, k));
        const word = try context.dense(input.columns, row, p);
        originals[row] = word[0];
        quotients[row] = word[1];
    }
    const alpha = staged.drawSecureFelt();
    const line_domain = core.poly.line.LineDomain.fromCircleDomain(domain);
    const original_line = try a.alloc(QM31, size / 2);
    const quotient_line = try a.alloc(QM31, size / 2);
    @memset(original_line, QM31.zero());
    @memset(quotient_line, QM31.zero());
    var workspace = try core.fri.folding.FoldCircleWorkspace.init(a, size / 2);
    try core.fri.folding.foldCircleIntoLineWithWorkspace(a, original_line, originals, domain, alpha, &workspace);
    try core.fri.folding.foldCircleIntoLineWithWorkspace(a, quotient_line, quotients, domain, alpha, &workspace);
    const original_terminal = try terminal(a, line_domain, original_line, profile.terminalLength());
    const quotient_terminal = try terminal(a, line_domain, quotient_line, profile.terminalLength());
    dual.mixTerminals(&staged, original_terminal, quotient_terminal);
    const raw = try core.queries.drawQueries(&staged, a, k, input.query_count);
    const source_wire = try source.encodeOpenings(a, raw);
    // Arena-backed allocations and source tree stay alive until proof teardown.
    context.deinit();
    channel.* = staged;
    return .{ .arena = arena, .proof = .{
        .profile = profile,
        .source_root = root,
        .sampled_point = point,
        .claims = claims,
        .source_wire = source_wire,
        .original_terminal = original_terminal,
        .quotient_terminal = quotient_terminal,
    } };
}
