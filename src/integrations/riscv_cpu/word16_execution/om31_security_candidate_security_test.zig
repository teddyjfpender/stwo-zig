//! security contract cases for om31_security_candidate.
//! Receiver-owned *candidate* construction and conditional error accountant.
//! No proof acceptance path selects this suite; no 128-bit certificate exists.
//! Values supplied by a proof bundle are not authority for Facts or reviews.
const std = @import("std");
const Owner = @import("om31_security_candidate.zig");
const Channel = Owner.Channel;
const MAX_PROOFS = Owner.MAX_PROOFS;
const MAX_TRACE_LOG = Owner.MAX_TRACE_LOG;
const MAX_COLUMNS = Owner.MAX_COLUMNS;
const MAX_CONSTRAINTS = Owner.MAX_CONSTRAINTS;
const MAX_SAMPLES_PER_COLUMN = Owner.MAX_SAMPLES_PER_COLUMN;
const MAX_AIR_DEGREE = Owner.MAX_AIR_DEGREE;
const MAX_LOCAL_INSTANCES = Owner.MAX_LOCAL_INSTANCES;
const MAX_TUPLE_ARITY = Owner.MAX_TUPLE_ARITY;
const LOCAL_RELATIONS = Owner.LOCAL_RELATIONS;
const GLOBAL_RELATIONS = Owner.GLOBAL_RELATIONS;
const MAX_GKR_VARIABLES = Owner.MAX_GKR_VARIABLES;
const MAX_ROUND_COUNT = Owner.MAX_ROUND_COUNT;
const TARGET_BITS = Owner.TARGET_BITS;
const MAX_AUDITED_LOG_WORK = Owner.MAX_AUDITED_LOG_WORK;
const profileIdentity = Owner.profileIdentity;
const identity = Owner.identity;
const requireIdentity = Owner.requireIdentity;
const Facts = Owner.Facts;

test "public boundary log23 policy v2 separates general clocks and historical identity" {
    var facts = Facts.caps();
    try facts.validate();
    facts.max_trace_log = 23;
    try std.testing.expectError(error.Om31CandidateScopeExceeded, facts.validate());
    facts = Facts.caps();
    facts.max_public_boundary_log = 24;
    try std.testing.expectError(error.Om31CandidateScopeExceeded, facts.validate());
    // Reconstruct the previously admitted v1 candidate identity. This checks
    // intentional rejection of that protocol, rather than silently widening it.
    var old = std.crypto.hash.sha2.Sha256.init(.{});
    old.update("rv64-om31-rawblake-native-localgkr-128-CANDIDATE/v1\x00");
    old.update(&Channel.profile.identity());
    for ([_]u64{ 8, 256, 2, 4, 0, MAX_PROOFS, MAX_TRACE_LOG, MAX_COLUMNS, MAX_CONSTRAINTS, MAX_SAMPLES_PER_COLUMN, MAX_AIR_DEGREE, MAX_LOCAL_INSTANCES, MAX_TUPLE_ARITY, LOCAL_RELATIONS, GLOBAL_RELATIONS, MAX_GKR_VARIABLES, MAX_ROUND_COUNT, TARGET_BITS, MAX_AUDITED_LOG_WORK }) |n| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, n, .little);
        old.update(&bytes);
    }
    try std.testing.expectError(error.UnrecognizedOm31CandidateIdentity, requireIdentity(old.finalResult()));
    try std.testing.expect(!std.mem.eql(u8, &profileIdentity(.proven_beta2_q256_p0_fold4), &profileIdentity(.conjectured128_b2_q108_p20_fold4)));
}
