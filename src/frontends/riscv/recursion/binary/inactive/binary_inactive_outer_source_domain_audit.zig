//! Cold per-domain audit for the binary inactive-row source.

pub fn audit(
    self: anytype,
    typed: anytype,
    vm_plan: anytype,
    recursion_plan: anytype,
    preprocessing: anytype,
    prepared: anytype,
    relations: anytype,
    claims: anytype,
    tuple_ledger: anytype,
    comptime DomainAudits: type,
    comptime appendTupleContributions: anytype,
) !DomainAudits {
    try prepared.validateAgainst(
        self,
        typed,
        vm_plan,
        recursion_plan,
        preprocessing,
    );
    try claims.validateInactive();
    try relations.validate();
    const result: DomainAudits = .{
        try typed.owners.claim_input.relation.auditPreparedDomainSums(
            self.allocator,
            prepared.claim_input_rows,
            relations,
            claims.claim_input,
        ),
        try typed.owners.claim_hash.relation.auditPreparedDomainSums(
            self.allocator,
            prepared.claim_hash_rows,
            relations,
            claims.claim_hash,
        ),
        try typed.owners.io_hash.relation.auditPreparedDomainSums(
            self.allocator,
            prepared.io_hash_rows,
            relations,
            claims.io_hash,
        ),
        try typed.owners.claim_semantics.relation.auditPreparedDomainSums(
            self.allocator,
            prepared.claim_semantics_rows,
            relations,
            claims.claim_semantics,
        ),
        try typed.owners.public_logup.relation.auditPreparedDomainSums(
            self.allocator,
            prepared.public_logup_rows,
            relations,
            claims.public_logup,
        ),
        try typed.owners.public_logup_control.relation.auditPreparedDomainSums(
            self.allocator,
            self.public_logup_control_rows,
            relations,
            claims.public_logup_control,
        ),
    };
    try appendTupleContributions(
        &typed.owners.claim_input.relation,
        tuple_ledger,
        .vm_public_claim_input,
        prepared.claim_input_rows,
    );
    try appendTupleContributions(
        &typed.owners.claim_hash.relation,
        tuple_ledger,
        .vm_public_claim_hash,
        prepared.claim_hash_rows,
    );
    try appendTupleContributions(
        &typed.owners.io_hash.relation,
        tuple_ledger,
        .vm_public_io_hash,
        prepared.io_hash_rows,
    );
    try appendTupleContributions(
        &typed.owners.claim_semantics.relation,
        tuple_ledger,
        .vm_public_claim_semantics_input,
        prepared.claim_semantics_rows,
    );
    try appendTupleContributions(
        &typed.owners.public_logup.relation,
        tuple_ledger,
        .vm_public_logup_input,
        prepared.public_logup_rows,
    );
    try appendTupleContributions(
        &typed.owners.public_logup_control.relation,
        tuple_ledger,
        .vm_public_logup_control,
        self.public_logup_control_rows,
    );
    return result;
}
