//! Failure-atomic Tree2 generation for role-0 rows 10--17.

const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const components =
    @import("recursive_common_ethereum_incremental_leaf_suffix_components_v4.zig");
const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const support =
    @import("recursive_common_ethereum_incremental_leaf_transcript_cohort_v4_support.zig");

const M31 = stwo_core.fields.m31.M31;
const air = frontend.recursion.air;

pub const Generated = struct {
    claims: components.ClaimsV4,
    audits: [8]air.relation_interaction.DomainAudit,
};

pub fn generateAll(
    prepared: anytype,
    relations: *const air.universal_challenges.UniversalRelations,
    destination: []const []M31,
) !Generated {
    const owners = &prepared.components.owners;
    const logs = prepared.components.log_sizes;

    var statement_input = try support.generateWithAudit(
        components.StatementInputFramework,
        prepared.allocator,
        &owners.statement_input.relation,
        prepared.rows.statement_input,
        logs[0],
        relations,
    );
    defer statement_input.deinit(prepared.allocator);
    var statement_semantics =
        try support.generateWithAudit(
            components.StatementSemanticsFramework,
            prepared.allocator,
            &owners.statement_semantics.relation,
            prepared.rows.statement_semantics,
            logs[1],
            relations,
        );
    defer statement_semantics.deinit(prepared.allocator);
    var claim_input = try support.generateWithAudit(
        components.ClaimInputFramework,
        prepared.allocator,
        &owners.claim_input.relation,
        prepared.rows.claim_input,
        logs[2],
        relations,
    );
    defer claim_input.deinit(prepared.allocator);
    var claim_hash = try support.generateWithAudit(
        components.ClaimHashFramework,
        prepared.allocator,
        &owners.claim_hash.relation,
        prepared.rows.claim_hash,
        logs[3],
        relations,
    );
    defer claim_hash.deinit(prepared.allocator);
    var io_hash = try support.generateWithAudit(
        components.IoHashFramework,
        prepared.allocator,
        &owners.io_hash.relation,
        prepared.rows.io_hash,
        logs[4],
        relations,
    );
    defer io_hash.deinit(prepared.allocator);
    var claim_semantics =
        try support.generateWithAudit(
            components.ClaimSemanticsFramework,
            prepared.allocator,
            &owners.claim_semantics.relation,
            prepared.rows.claim_semantics,
            logs[5],
            relations,
        );
    defer claim_semantics.deinit(prepared.allocator);
    var public_logup = try support.generateWithAudit(
        components.PublicLogupFramework,
        prepared.allocator,
        &owners.public_logup.relation,
        prepared.rows.public_logup,
        logs[6],
        relations,
    );
    defer public_logup.deinit(prepared.allocator);
    var public_logup_control =
        try support.generateWithAudit(
            components.PublicLogupControlFramework,
            prepared.allocator,
            &owners.public_logup_control.relation,
            prepared.rows.public_logup_control,
            logs[7],
            relations,
        );
    defer public_logup_control.deinit(prepared.allocator);

    try copy(
        components.StatementInputFramework,
        &statement_input.interaction.columns,
        prepared.manifest,
        .statement_input,
        destination,
    );
    try copy(
        components.StatementSemanticsFramework,
        &statement_semantics.interaction.columns,
        prepared.manifest,
        .statement_semantics_input,
        destination,
    );
    try copy(
        components.ClaimInputFramework,
        &claim_input.interaction.columns,
        prepared.manifest,
        .vm_public_claim_input,
        destination,
    );
    try copy(
        components.ClaimHashFramework,
        &claim_hash.interaction.columns,
        prepared.manifest,
        .vm_public_claim_hash,
        destination,
    );
    try copy(
        components.IoHashFramework,
        &io_hash.interaction.columns,
        prepared.manifest,
        .vm_public_io_hash,
        destination,
    );
    try copy(
        components.ClaimSemanticsFramework,
        &claim_semantics.interaction.columns,
        prepared.manifest,
        .vm_public_claim_semantics_input,
        destination,
    );
    try copy(
        components.PublicLogupFramework,
        &public_logup.interaction.columns,
        prepared.manifest,
        .vm_public_logup_input,
        destination,
    );
    try copy(
        components.PublicLogupControlFramework,
        &public_logup_control.interaction.columns,
        prepared.manifest,
        .vm_public_logup_control,
        destination,
    );

    return .{ .claims = .{ .values = .{
        statement_input.interaction.claimed_sum,
        statement_semantics.interaction.claimed_sum,
        claim_input.interaction.claimed_sum,
        claim_hash.interaction.claimed_sum,
        io_hash.interaction.claimed_sum,
        claim_semantics.interaction.claimed_sum,
        public_logup.interaction.claimed_sum,
        public_logup_control.interaction.claimed_sum,
    } }, .audits = .{
        statement_input.audit,
        statement_semantics.audit,
        claim_input.audit,
        claim_hash.audit,
        io_hash.audit,
        claim_semantics.audit,
        public_logup.audit,
        public_logup_control.audit,
    } };
}

fn copy(
    comptime Framework: type,
    columns: *const [Framework.INTERACTION_COLUMN_COUNT][]M31,
    manifest: *const manifest_mod.Manifest,
    key: manifest_mod.ComponentKey,
    destination: []const []M31,
) !void {
    support.copyInteraction(
        Framework,
        columns,
        try manifest.placement(key),
        destination,
    );
}
