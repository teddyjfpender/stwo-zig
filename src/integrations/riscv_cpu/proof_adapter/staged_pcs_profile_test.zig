//! Pins for issue #152 item 7 on the path that publishes proofs.
//!
//! `--production` once set `pow_bits = 24` while every mirror of "the secure
//! profile" said 26, and numbers were published from a profile nobody had
//! reviewed. The repair was to stop *restating* the profile: the adapter's
//! `.secure` arm is `prover.SECURE_PCS_CONFIG` itself, the single source of truth
//! that `scripts/riscv_csp_benchmark_lib/contract.py` mirrors.
//!
//! Two obligations, and only one of them is about numbers.
//!
//! The value obligation -- `select(.secure)` equals the shared constant -- lives
//! beside the profiles in `pcs_profile.zig`. It catches a *drifted*
//! restatement, and a wave-2 verifier confirmed it does: replacing the arm with a
//! literal carrying `pow_bits = 24` turns it red.
//!
//! It cannot catch a *faithful* restatement, because a copy that agrees today
//! compares equal today. That is precisely the state the profile was in before it
//! drifted, so the second obligation is structural and lives here: the arm must
//! *name* the constant and must restate none of its fields. A structural check is
//! the only kind that can distinguish "is the shared profile" from "currently has
//! the same numbers as the shared profile", and the distinction is the entire
//! lesson of the defect.
//!
//! Kept separate from the selector so the structural fixture cannot count its
//! own references; the product adapter imports this file for tests.

const std = @import("std");

/// The selector's own text. Embedded rather than read from disk so the check has
/// no working-directory premise and a moved function fails at compile time.
const PROFILE_SOURCE = @embedFile("pcs_profile.zig");

/// The single cross-language name for the published profile.
const SHARED_CONSTANT = "SECURE_PCS_CONFIG";

/// Return the text of `select`'s `.secure` switch arm.
///
/// Bounded by the next arm rather than by a brace count: the point is to look at
/// what the secure arm alone contains, and the sibling profiles legitimately do
/// restate their own numbers.
fn secureArm(source: []const u8) ![]const u8 {
    const declaration = std.mem.indexOf(u8, source, "pub fn select(") orelse
        return error.StagedPcsConfigMissing;
    const body = source[declaration..];
    const arm = std.mem.indexOf(u8, body, ".secure =>") orelse
        return error.SecureArmMissing;
    const next = std.mem.indexOf(u8, body[arm..], ".functional =>") orelse
        return error.FunctionalArmMissing;
    return body[arm .. arm + next];
}

test "adapter secure profile is the shared constant rather than a second literal" {
    const arm = try secureArm(PROFILE_SOURCE);

    // It names the shared constant.
    if (std.mem.indexOf(u8, arm, SHARED_CONSTANT) == null) {
        std.debug.print(
            "the adapter's secure profile no longer names {s}:\n{s}\n",
            .{ SHARED_CONSTANT, arm },
        );
        return error.SecureProfileIsRestated;
    }

    // And it restates none of its fields. Any one of these appearing here means a
    // second literal exists, whether or not its numbers currently agree: the
    // published profile and the reviewed one would then be two objects that a
    // value comparison cannot tell apart until they have already diverged.
    for ([_][]const u8{
        ".pow_bits",
        ".fri_config",
        ".log_blowup_factor",
        ".log_last_layer_degree_bound",
        ".n_queries",
        ".fold_step",
        ".lifting_log_size",
    }) |field| {
        if (std.mem.indexOf(u8, arm, field) == null) continue;
        std.debug.print(
            "the adapter's secure profile restates {s}; it must be {s} itself:\n{s}\n",
            .{ field, SHARED_CONSTANT, arm },
        );
        return error.SecureProfileIsRestated;
    }
}

test "the staged profile selector reaches the shared constant exactly once" {
    // A second reference inside the selector would mean a second arm resolves to
    // the secure profile -- how `--production` and `--secure` came to disagree
    // about which profile they meant. Counted over the selector rather than the
    // file, because the tests beside it name the constant on purpose.
    const declaration = std.mem.indexOf(u8, PROFILE_SOURCE, "pub fn select(").?;
    const closing = std.mem.indexOf(u8, PROFILE_SOURCE[declaration..], "\n}\n") orelse
        return error.StagedPcsConfigNotClosed;
    const selector = PROFILE_SOURCE[declaration .. declaration + closing];
    try std.testing.expectEqual(
        @as(usize, 1),
        std.mem.count(u8, selector, SHARED_CONSTANT),
    );
}

test "the fixtures this file reads still exist" {
    // Fails closed. Every check above is a substring search, and a search over
    // text that no longer holds the function it describes reports success. This
    // is the pin that says the file is still looking at something.
    try std.testing.expect(PROFILE_SOURCE.len > 512);
    try std.testing.expect((try secureArm(PROFILE_SOURCE)).len != 0);
    try std.testing.expect(
        std.mem.indexOf(u8, PROFILE_SOURCE, "pub fn select(") != null,
    );
}
