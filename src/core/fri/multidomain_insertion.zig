//! Experimental scalar kernel for Protocol 3, Eq. 68 multi-domain insertion.
//!
//! This is not wired into FriProver/FriVerifier or any admitted PCS proof.
//! The production circle fold uses `alpha^2 * previous + circle_fold`, whereas
//! Eq. 68 requires `previous_line_fold + alpha^2 * inserted_circle_fold`.
//! Keeping the two terms separate prevents silently reversing their weights.

const std = @import("std");
const folding = @import("folding.zig");
const qm31 = @import("../fields/qm31.zig");
const line = @import("../poly/line.zig");
const circle_domain = @import("../poly/circle/domain.zig");

const QM31 = qm31.QM31;

/// Insert one smaller circle-domain batch into a previous line layer.
/// Values use the existing native bit-reversed FRI layout and unnormalized
/// inverse butterflies. The output owns its allocation; inputs are unchanged.
/// The matched-domain check prevents equal-length but unrelated cosets from
/// being silently combined. No degree or commitment claim is made here.
pub fn insertCircleBatch(
    allocator: std.mem.Allocator,
    previous: []const QM31,
    previous_domain: line.LineDomain,
    inserted: []const QM31,
    inserted_domain: circle_domain.CircleDomain,
    alpha: QM31,
) !folding.FoldLineResult {
    if (previous.len != previous_domain.size() or
        inserted.len != inserted_domain.size() or
        inserted.len < 2 or
        previous.len != inserted.len or
        !previous_domain.double().coset().eql(inserted_domain.half_coset))
    {
        return error.InvalidInsertionGeometry;
    }

    const output_len = inserted.len / 2;
    var line_workspace = try folding.FoldLineWorkspace.init(allocator, output_len);
    defer line_workspace.deinit(allocator);
    var circle_workspace = try folding.FoldCircleWorkspace.init(allocator, output_len);
    defer circle_workspace.deinit(allocator);

    const previous_fold = try folding.foldLineSingleStep(
        allocator,
        previous,
        previous_domain,
        alpha,
        &line_workspace,
    );
    errdefer allocator.free(previous_fold.values);

    const inserted_fold = try allocator.alloc(QM31, output_len);
    defer allocator.free(inserted_fold);
    @memset(inserted_fold, QM31.zero());
    try folding.foldCircleIntoLineWithWorkspace(
        allocator,
        inserted_fold,
        inserted,
        inserted_domain,
        alpha,
        &circle_workspace,
    );

    const alpha_sq = alpha.square();
    for (previous_fold.values, inserted_fold) |*dst, term| {
        dst.* = dst.*.add(alpha_sq.mul(term));
    }
    return previous_fold;
}
