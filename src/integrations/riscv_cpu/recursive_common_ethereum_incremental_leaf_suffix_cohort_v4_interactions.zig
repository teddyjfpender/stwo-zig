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

pub fn generateAll(
    prepared: anytype,
    relations: *const air.universal_challenges.UniversalRelations,
    destination: []const []M31,
) !components.ClaimsV4 {
    const owners = &prepared.components.owners;
    const logs = prepared.components.log_sizes;

    var statement_input = try components.StatementInputFramework.generatePrepared(
        prepared.allocator,
        &owners.statement_input.relation,
        prepared.rows.statement_input,
        logs[0],
        relations,
    );
    defer statement_input.deinit(prepared.allocator);
    var statement_semantics =
        try components.StatementSemanticsFramework.generatePrepared(
            prepared.allocator,
            &owners.statement_semantics.relation,
            prepared.rows.statement_semantics,
            logs[1],
            relations,
        );
    defer statement_semantics.deinit(prepared.allocator);
    var claim_input = try components.ClaimInputFramework.generatePrepared(
        prepared.allocator,
        &owners.claim_input.relation,
        prepared.rows.claim_input,
        logs[2],
        relations,
    );
    defer claim_input.deinit(prepared.allocator);
    var claim_hash = try components.ClaimHashFramework.generatePrepared(
        prepared.allocator,
        &owners.claim_hash.relation,
        prepared.rows.claim_hash,
        logs[3],
        relations,
    );
    defer claim_hash.deinit(prepared.allocator);
    var io_hash = try components.IoHashFramework.generatePrepared(
        prepared.allocator,
        &owners.io_hash.relation,
        prepared.rows.io_hash,
        logs[4],
        relations,
    );
    defer io_hash.deinit(prepared.allocator);
    var claim_semantics =
        try components.ClaimSemanticsFramework.generatePrepared(
            prepared.allocator,
            &owners.claim_semantics.relation,
            prepared.rows.claim_semantics,
            logs[5],
            relations,
        );
    defer claim_semantics.deinit(prepared.allocator);
    var public_logup = try components.PublicLogupFramework.generatePrepared(
        prepared.allocator,
        &owners.public_logup.relation,
        prepared.rows.public_logup,
        logs[6],
        relations,
    );
    defer public_logup.deinit(prepared.allocator);
    var public_logup_control =
        try components.PublicLogupControlFramework.generatePrepared(
            prepared.allocator,
            &owners.public_logup_control.relation,
            prepared.rows.public_logup_control,
            logs[7],
            relations,
        );
    defer public_logup_control.deinit(prepared.allocator);

    try copy(
        components.StatementInputFramework,
        &statement_input.columns,
        prepared.manifest,
        .statement_input,
        destination,
    );
    try copy(
        components.StatementSemanticsFramework,
        &statement_semantics.columns,
        prepared.manifest,
        .statement_semantics_input,
        destination,
    );
    try copy(
        components.ClaimInputFramework,
        &claim_input.columns,
        prepared.manifest,
        .vm_public_claim_input,
        destination,
    );
    try copy(
        components.ClaimHashFramework,
        &claim_hash.columns,
        prepared.manifest,
        .vm_public_claim_hash,
        destination,
    );
    try copy(
        components.IoHashFramework,
        &io_hash.columns,
        prepared.manifest,
        .vm_public_io_hash,
        destination,
    );
    try copy(
        components.ClaimSemanticsFramework,
        &claim_semantics.columns,
        prepared.manifest,
        .vm_public_claim_semantics_input,
        destination,
    );
    try copy(
        components.PublicLogupFramework,
        &public_logup.columns,
        prepared.manifest,
        .vm_public_logup_input,
        destination,
    );
    try copy(
        components.PublicLogupControlFramework,
        &public_logup_control.columns,
        prepared.manifest,
        .vm_public_logup_control,
        destination,
    );

    return .{ .values = .{
        statement_input.claimed_sum,
        statement_semantics.claimed_sum,
        claim_input.claimed_sum,
        claim_hash.claimed_sum,
        io_hash.claimed_sum,
        claim_semantics.claimed_sum,
        public_logup.claimed_sum,
        public_logup_control.claimed_sum,
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
