//! Independent claim replay and domain audit for a generated binary bundle.

const std = @import("std");
const air = @import("air/mod.zig");
const relation_interaction = air.relation_interaction;
const universal = air.universal_challenges;
const shared_provider = air.universal_shared_provider;
const poseidon_air = @import("../air/memory_commitment/poseidon2_air.zig");

pub fn audit(
    self: anytype,
    allocator: std.mem.Allocator,
    relations: anytype,
    provider_relations: anytype,
    generated: anytype,
    tuple_ledger: anytype,
    comptime DomainAudits: type,
    comptime AuditedInteractionsV1: type,
    comptime validateGeneratedInteractions: anytype,
    comptime providerCallsPrepared: anytype,
    comptime providerOutputsPrepared: anytype,
    comptime validateAudits: anytype,
    comptime auditedIdentity: anytype,
) !AuditedInteractionsV1 {
    try validateGeneratedInteractions(
        self,
        generated,
        relations,
        provider_relations,
    );
    const calls = try providerCallsPrepared(self);
    const outputs = try providerOutputsPrepared(self);
    const replayed = try poseidon_air.claimsFromIoOutputs(
        calls,
        outputs,
        self.provider_log_size,
        &provider_relations.native,
    );
    if (!replayed.sums[0].eql(generated.claims.poseidon2_partials[0]) or
        !replayed.sums[1].eql(generated.claims.poseidon2_partials[1]))
    {
        return error.ProviderClaimMismatch;
    }
    const typed_audits = if (tuple_ledger) |ledger|
        try self.source.auditTypedInteractionDomainsPreparedWithTupleLedger(
            &self.source_authority,
            allocator,
            &self.relation_rows,
            relations,
            generated.claims.typed_rows,
            ledger,
        )
    else
        try self.source.auditTypedInteractionDomainsPrepared(
            &self.source_authority,
            allocator,
            &self.relation_rows,
            relations,
            generated.claims.typed_rows,
        );
    const audits = DomainAudits{
        .typed_rows = typed_audits,
        .poseidon2 = .{
            .poseidon2 = replayed.sums[0],
            .poseidon2_io = replayed.sums[1],
            .total = replayed.total(),
        },
    };
    try validateAudits(audits, generated.claims);
    var result = AuditedInteractionsV1{
        .generated = generated.*,
        .audits = audits,
        .identity = undefined,
    };
    result.identity = auditedIdentity(&result);
    try result.validateAgainst(self, relations, provider_relations);
    return result;
}
