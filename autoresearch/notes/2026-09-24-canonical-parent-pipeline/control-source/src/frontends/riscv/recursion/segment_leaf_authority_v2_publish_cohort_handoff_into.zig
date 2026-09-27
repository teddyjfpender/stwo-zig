//! Internal segment leaf authority v2 authority shard; use segment_leaf_authority_v2.zig publicly.

const dependency_0 = @import("segment_leaf_authority_v2_contract.zig");
const dependency_1 = @import("segment_leaf_authority_v2_source_preflight_public_log_up_publication_v2.zig");
const dependency_2 = @import("segment_leaf_authority_v2_authority_hash_poseidon_plan_v2.zig");

const Error = dependency_0.Error;
const NativeTemporalPublicationV2 = dependency_2.NativeTemporalPublicationV2;
const PreparedV2 = dependency_1.PreparedV2;
const PublicLogUpPublicationV2 = dependency_1.PublicLogUpPublicationV2;
const ShaClosurePublicationV2 = dependency_2.ShaClosurePublicationV2;
const channel = dependency_0.channel;
const nativePublicationId = dependency_2.nativePublicationId;
const native_relations = dependency_0.native_relations;
const overlap = dependency_1.overlap;
const public_data_v2 = dependency_0.public_data_v2;
const relation = dependency_0.relation;
const std = dependency_0.std;

pub const CohortHandoffV2 = struct {
    native: NativeTemporalPublicationV2,
    sha_closure: ShaClosurePublicationV2,

    pub fn validateAgainst(
        self: *const CohortHandoffV2,
        prepared: *const PreparedV2,
        logup: *const PublicLogUpPublicationV2,
        data: *const public_data_v2.PublicDataV2,
        relations: *const native_relations.Relations,
    ) Error!void {
        try prepared.validateAgainst(data, &prepared.verifier_keys);
        try logup.validateAgainst(prepared, data, relations);
        try self.native.validateAgainst(prepared, logup);
        try self.sha_closure.validate();
        if (!std.meta.eql(
            self.sha_closure.statement_relation,
            prepared.statement_relation_evidence,
        ) or !std.meta.eql(
            self.sha_closure.verifier_input,
            logup.verifier_input_evidence,
        )) return error.InvalidPublication;
    }
};

/// Transactional preimage for the full outer driver.  The driver must bind the
/// two SHA tuple publications into its V2 global-closure receipt and publish
/// `native` only after independent proof verification succeeds.
pub fn publishCohortHandoffInto(
    destination: *CohortHandoffV2,
    prepared: *const PreparedV2,
    logup: *const PublicLogUpPublicationV2,
    data: *const public_data_v2.PublicDataV2,
    relations: *const native_relations.Relations,
) Error!void {
    if (overlap(std.mem.asBytes(destination), std.mem.asBytes(prepared)) or
        overlap(std.mem.asBytes(destination), std.mem.asBytes(logup)) or
        overlap(std.mem.asBytes(destination), std.mem.asBytes(data)) or
        overlap(std.mem.asBytes(destination), std.mem.sliceAsBytes(data.words())) or
        overlap(std.mem.asBytes(destination), std.mem.asBytes(relations)))
    {
        return error.AliasedDestination;
    }
    try prepared.validateAgainst(data, &prepared.verifier_keys);
    try logup.validateAgainst(prepared, data, relations);
    var native = NativeTemporalPublicationV2{
        .context = prepared.context,
        .source_id = prepared.source_id,
        .public_logup_id = logup.identity,
        .identity = undefined,
    };
    native.identity = nativePublicationId(&native);
    try native.validate();
    const staged = CohortHandoffV2{
        .native = native,
        .sha_closure = .{
            .statement_relation = prepared.statement_relation_evidence,
            .verifier_input = logup.verifier_input_evidence,
        },
    };
    try staged.sha_closure.validate();
    destination.* = staged;
}

/// Exact one-pass identity cost after authenticated public LogUp calculation:
/// relation challenge context plus public LogUp publication identity.
pub fn publicLogUpIdentityPoseidonPermutationCount() usize {
    return channel.canonicalWordPermutationCount(98) +
        channel.canonicalWordPermutationCount(46);
}

/// Exact one-pass identity cost for the self-contained native cohort receipt.
pub fn cohortHandoffIdentityPoseidonPermutationCount() usize {
    return channel.canonicalWordPermutationCount(26);
}
