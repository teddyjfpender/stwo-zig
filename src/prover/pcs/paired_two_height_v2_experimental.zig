//! Deterministic host prover for experimental P2F02. Production PCS never
//! emits this format and no security bits are assigned to it.

const std = @import("std");
const core = @import("stwo_core");
const circle = core.circle;
const m31 = core.fields.m31;
const qm31 = core.fields.qm31;
const canonic = core.poly.circle.canonic;
const old = @import("paired_two_height_experimental.zig");
const v2 = core.pcs.paired_two_height_v2_wire;
const fri = core.pcs.paired_two_height_fri;
const xdm_prover = @import("transposed_source_experimental.zig");
const SourceProver = @import("../vcs_lifted/prover.zig").MerkleProverLifted(core.pcs.paired_envelope.Hasher);
const LineEvaluation = @import("../line.zig").LineEvaluation;

const M31 = m31.M31;
const QM31 = qm31.QM31;
pub const Input = old.Input;

/// Build a one-root XDM02 source proof and its P2F02 fold layers. The caller
/// must obtain the expected statement independently; decoding the returned
/// bytes is only useful for test fixtures, never application trust.
pub fn prove(allocator: std.mem.Allocator, input: Input, channel: anytype) ![]u8 {
    const shapes = try input.shapes();
    const profile = v2.Profile{
        .largest_log_size = input.largest_log_size,
        .log_blowup = input.log_blowup,
        .large_columns = input.first_columns.len,
        .small_columns = input.second_columns.len,
        .n_queries = input.n_queries,
    };
    try profile.validate();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const first_domain = canonic.CanonicCoset.new(input.largest_log_size).circleDomain();
    const second_domain = canonic.CanonicCoset.new(input.largest_log_size - 1).circleDomain();
    try old.validateSourceDegree(a, first_domain, input.first_columns, shapes[0].log_degree_bound);
    try old.validateSourceDegree(a, second_domain, input.second_columns, shapes[1].log_degree_bound);
    var source = try xdm_prover.Commitment.commit(a, input.first_columns, input.second_columns);
    defer source.deinit();
    const root = source.root();
    var staged = channel.*;
    v2.bindVersion(&staged);
    const point = try v2.drawOodPoint(&staged, profile, root);
    const claims0 = try a.alloc(QM31, input.first_columns.len);
    const claims1 = try a.alloc(QM31, input.second_columns.len);
    try old.evaluateClaims(a, first_domain, input.first_columns, point, claims0);
    try old.evaluateClaims(a, second_domain, input.second_columns, point, claims1);
    const batch = v2.drawBatchAfterOod(&staged, claims0, claims1);
    const alpha0 = staged.drawSecureFelt();
    const challenges = core.pcs.paired_ensemble.Challenges{ .batch = batch };
    const first_batch = try old.pairedHeight(a, first_domain, input.first_columns, claims0, point, challenges);
    const second_batch = try old.pairedHeight(a, second_domain, input.second_columns, claims1, point, challenges);
    const line_values = try a.alloc(QM31, first_batch.len / 2);
    @memset(line_values, QM31.zero());
    var workspace = try core.fri.folding.FoldCircleWorkspace.init(a, line_values.len);
    defer workspace.deinit(a);
    try core.fri.folding.foldCircleIntoLineWithWorkspace(
        a,
        line_values,
        first_batch,
        first_domain,
        alpha0,
        &workspace,
    );
    var line_storage: [4][]M31 = undefined;
    var line_columns: [4][]const M31 = undefined;
    for (&line_storage, &line_columns) |*storage, *column| {
        storage.* = try a.alloc(M31, line_values.len);
        column.* = storage.*;
    }
    for (line_values, 0..) |value, row| {
        const coordinates = value.toM31Array();
        for (line_storage, coordinates) |column, coordinate| column[row] = coordinate;
    }
    var line_tree = try SourceProver.commit(a, &line_columns);
    defer line_tree.deinit(a);
    core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel.mixRoot(&staged, line_tree.root());
    const alpha1 = staged.drawSecureFelt();
    const last_line = try core.fri.multidomain_insertion.insertCircleBatch(
        a,
        line_values,
        core.poly.line.LineDomain.fromCircleDomain(first_domain),
        second_batch,
        second_domain,
        alpha1,
    );
    var evaluation = try LineEvaluation.initBorrowed(last_line.domain, last_line.values);
    var polynomial = try evaluation.interpolate(a);
    defer polynomial.deinit(a);
    const ordered = polynomial.intoOrderedCoefficients();
    const terminal_len = @as(usize, 1) << @intCast(shapes[1].log_degree_bound - 1);
    for (ordered[terminal_len..]) |coefficient| {
        if (!coefficient.isZero()) return error.TerminalDegreeExceeded;
    }
    const terminal = ordered[0..terminal_len];
    staged.mixFelts(terminal);
    var schedule = try fri.sampleQuerySchedule(a, &staged, profile.largest_log_size, profile.n_queries);
    defer schedule.deinit(a);
    const source_wire = try source.encodeOpenings(a, schedule.raw);
    var line_opened = try line_tree.decommit(a, schedule.line_positions, &line_columns);
    defer line_opened.deinit(a);
    const encoded = try v2.encode(allocator, .{
        .profile = profile,
        .source_root = root,
        .sampled_point = point,
        .large_claims = claims0,
        .small_claims = claims1,
        .source_wire = source_wire,
        .intermediate = .{
            .root = line_tree.root(),
            .queried_coordinates = .{
                line_opened.queried_values[0], line_opened.queried_values[1],
                line_opened.queried_values[2], line_opened.queried_values[3],
            },
            .hash_witness = line_opened.decommitment.decommitment.hash_witness,
        },
        .terminal_ordered_coeffs = terminal,
    });
    channel.* = staged;
    return encoded;
}
