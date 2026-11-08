//! FRI (Fast Reed-Solomon IOP) operation contracts for prover backends.
//!
//! A backend must provide circle-to-line and line-to-line folding.

const line_evaluation = @import("line_evaluation.zig");
const secure_column = @import("secure_column.zig");
const signature = @import("signature.zig");
const std = @import("std");
const core = @import("stwo_core");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

pub fn FoldLineAndCommitResult(comptime Tree: type) type {
    return struct {
        evaluation: line_evaluation.LineEvaluation,
        /// Coordinate planes already used for the pending tree. A scheduler
        /// that consumes the hook must move this into the next layer instead
        /// of materializing the evaluation a second time.
        column: ?secure_column.SecureColumnByCoords = null,
        tree: Tree,
    };
}

/// Validates a backend's explicitly claimed FRI folding capability.
///
/// When `enabled` is true, required declarations are:
///   - `foldCircleIntoLine(allocator, eval, alpha) !LineEvaluation(B)`
///   - `foldLine(allocator, eval, alpha) !LineEvaluation(B)`
///
/// `multi_fold` additionally requires `foldLineN`. Other optimized hooks remain
/// independently optional because the generic prover has complete fallbacks:
///   - `secureColumnForMerkle(allocator, evaluation) !SecureColumnByCoords`
///   - `secureColumnFromLine(evaluation) !SecureColumnByCoords` (legacy fallback)
///   - `foldLineAndCommitNext(...) !FoldLineAndCommitResult(MerkleTree(H))`
pub fn assertCapability(
    comptime B: type,
    comptime enabled: bool,
    comptime multi_fold: bool,
) void {
    comptime {
        if (!enabled) {
            if (@hasDecl(B, "foldCircleIntoLine") or
                @hasDecl(B, "foldLine") or
                @hasDecl(B, "foldLineN"))
            {
                @compileError(
                    "Backend exposes FRI fold operations without claiming `fri_folding`.",
                );
            }
            return;
        }
        if (!@hasDecl(B, "foldCircleIntoLine")) {
            @compileError(
                "Backend claims `fri_folding` but does not declare `foldCircleIntoLine`.",
            );
        }
        if (!@hasDecl(B, "foldLine")) {
            @compileError(
                "Backend claims `fri_folding` but does not declare `foldLine`.",
            );
        }
        if (multi_fold and !@hasDecl(B, "foldLineN")) {
            @compileError(
                "Backend claims `fri_multi_fold` but does not declare `foldLineN`.",
            );
        }
        if (!multi_fold and @hasDecl(B, "foldLineN")) {
            @compileError(
                "Backend declares `foldLineN` but does not claim `fri_multi_fold`.",
            );
        }

        const CircleResult = @TypeOf(B.foldCircleIntoLine(
            @as(std.mem.Allocator, undefined),
            @as([]QM31, undefined),
            @as([core.fields.qm31.SECURE_EXTENSION_DEGREE][]const M31, undefined),
            @as(core.poly.circle.domain.CircleDomain, undefined),
            @as(QM31, undefined),
            @as(*core.fri.FoldCircleWorkspace, undefined),
        ));
        signature.assertErrorUnionPayload(
            CircleResult,
            void,
            "`foldCircleIntoLine` does not match the backend FRI capability signature.",
        );

        const LineResult = @TypeOf(B.foldLine(
            @as(std.mem.Allocator, undefined),
            @as([]QM31, undefined),
            @as(core.poly.line.LineDomain, undefined),
            @as(QM31, undefined),
            @as(*core.fri.FoldLineWorkspace, undefined),
        ));
        signature.assertErrorUnionPayload(
            LineResult,
            core.fri.FoldLineResult,
            "`foldLine` does not match the backend FRI capability signature.",
        );

        if (multi_fold) {
            const MultiResult = @TypeOf(B.foldLineN(
                @as(std.mem.Allocator, undefined),
                @as([]QM31, undefined),
                @as(core.poly.line.LineDomain, undefined),
                @as(QM31, undefined),
                @as(*core.fri.FoldLineWorkspace, undefined),
                @as(u32, undefined),
            ));
            signature.assertErrorUnionPayload(
                MultiResult,
                core.fri.FoldLineResult,
                "`foldLineN` does not match the backend FRI capability signature.",
            );
        }
    }
}
