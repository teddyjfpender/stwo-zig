//! Receiver/operator-selected profiles; untrusted proof metadata cannot select them.
const std = @import("std");
const Candidate = @import("../../word16_execution/om31_security_candidate.zig");
const CANDIDATE_PROFILE = "experimental-om31-local-gkr-beta2-q256-p0-fold4-engineering";
const CONJECTURED_PROFILE = "experimental-om31-local-gkr-conjectured128-b2-q108-p20-fold4-engineering";
/// Report label of a receiver-selected candidate profile (historical label for proven).
pub fn candidateLabel(profile: Candidate.Profile) []const u8 {
    return switch (profile) {
        .proven_beta2_q256_p0_fold4 => CANDIDATE_PROFILE,
        .conjectured128_b2_q108_p20_fold4 => CONJECTURED_PROFILE,
        .d2_native_b4_q54_p20_fold4 => "experimental-om31-local-gkr-d2-b4-q54-p20-fold4-engineering",
    };
}
/// The receiver's/producer's OWN policy: `--security-profile NAME` before the
/// mode, candidate modes only; default Candidate.DEFAULT_PROFILE. Proof bytes
/// and bundle metadata never select it.
pub const ProfileSelection = struct { profile: Candidate.Profile, explicit: bool, args: []const [:0]u8 };
pub fn selectProfile(all: []const [:0]u8) !ProfileSelection {
    if (all.len >= 3 and std.mem.eql(u8, all[1], "--security-profile"))
        return .{ .profile = try Candidate.Profile.parse(all[2]), .explicit = true, .args = all[2..] };
    return .{ .profile = Candidate.DEFAULT_PROFILE, .explicit = false, .args = all };
}
