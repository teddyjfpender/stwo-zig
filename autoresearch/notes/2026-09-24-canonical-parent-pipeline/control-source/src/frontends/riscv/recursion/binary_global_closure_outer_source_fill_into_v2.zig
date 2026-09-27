//! Internal binary global closure outer source authority shard; use binary_global_closure_outer_source.zig publicly.

const dependency_0 = @import("binary_global_closure_outer_source_contract.zig");
const dependency_1 = @import("binary_global_closure_outer_source_public_boundary_claim_v2.zig");
const dependency_2 = @import("binary_global_closure_outer_source_closure_receipt_v2.zig");

const AllocationLedgerV1 = dependency_0.AllocationLedgerV1;
const AllocationLedgerV2 = dependency_0.AllocationLedgerV2;
const BoundaryAuthoritiesV2 = dependency_0.BoundaryAuthoritiesV2;
const BoundaryEvidenceV2 = dependency_0.BoundaryEvidenceV2;
const BoundarySourceV2 = dependency_0.BoundarySourceV2;
const CLOSURE_RECEIPT_FORMAT_VERSION_V2 = dependency_0.CLOSURE_RECEIPT_FORMAT_VERSION_V2;
const ClosureInputV2 = dependency_2.ClosureInputV2;
const ClosureReceiptV1 = dependency_2.ClosureReceiptV1;
const ClosureReceiptV2 = dependency_2.ClosureReceiptV2;
const ContextSeamV2 = dependency_1.ContextSeamV2;
const DOMAIN_COUNT = dependency_0.DOMAIN_COUNT;
const Error = dependency_0.Error;
const PREFIX_ROW_COUNT = dependency_0.PREFIX_ROW_COUNT;
const PROVIDER_DOMAIN = dependency_0.PROVIDER_DOMAIN;
const PROVIDER_ROW = dependency_0.PROVIDER_ROW;
const PreparedAuthorityV1 = dependency_0.PreparedAuthorityV1;
const PreparedAuthorityV2 = dependency_1.PreparedAuthorityV2;
const PublicBoundariesV2 = dependency_1.PublicBoundariesV2;
const PublicBoundaryClaimV2 = dependency_1.PublicBoundaryClaimV2;
const RequiredContextV2 = dependency_0.RequiredContextV2;
const SourceAuthorityV2 = dependency_1.SourceAuthorityV2;
const TOTAL_ROW_COUNT = dependency_0.TOTAL_ROW_COUNT;
const VERIFIER_INPUT_BOUNDARY_DOMAIN = dependency_0.VERIFIER_INPUT_BOUNDARY_DOMAIN;
const WIRE_BOUNDARY_DOMAIN = dependency_0.WIRE_BOUNDARY_DOMAIN;
const Workspace = dependency_1.Workspace;
const boundaryDomainBit = dependency_2.boundaryDomainBit;
const closureIdentityV2 = dependency_2.closureIdentityV2;
const preflightClosureInputV2 = dependency_2.preflightClosureInputV2;
const rejectAliasesV2 = dependency_2.rejectAliasesV2;
const std = dependency_0.std;

/// Allocation-free V2 hot fill. Public boundaries are consumed only from the
/// two source-authenticated claims already sealed by `ClosureInputV2`; this
/// function never observes or constructs a residual-negation correction.
pub fn fillIntoV2(
    workspace: *Workspace,
    prepared: *const PreparedAuthorityV2,
    input: *const ClosureInputV2,
    destination: *ClosureReceiptV2,
) Error!void {
    try rejectAliasesV2(workspace, prepared, input, destination);
    if (!std.meta.eql(destination.*, ClosureReceiptV2.fresh()))
        return error.DestinationNotFresh;
    try workspace.validate();
    const preflight = try preflightClosureInputV2(input, prepared);
    const active_domain_mask = preflight.active_domain_mask |
        boundaryDomainBit(WIRE_BOUNDARY_DOMAIN) |
        boundaryDomainBit(VERIFIER_INPUT_BOUNDARY_DOMAIN);

    workspace.reset(active_domain_mask);
    for (input.rows) |row| {
        for (row.domains, 0..) |claim, domain_index| {
            workspace.prefix_totals[domain_index] =
                workspace.prefix_totals[domain_index].add(claim.value);
        }
        workspace.framework_total = workspace.framework_total.add(row.claimed_sum);
    }
    workspace.closed_totals = workspace.prefix_totals;
    workspace.closed_totals[@intFromEnum(PROVIDER_DOMAIN)] =
        workspace.closed_totals[@intFromEnum(PROVIDER_DOMAIN)].add(
            input.provider_claim.claimed_sum,
        );
    workspace.closed_totals[@intFromEnum(WIRE_BOUNDARY_DOMAIN)] =
        workspace.closed_totals[@intFromEnum(WIRE_BOUNDARY_DOMAIN)].add(
            input.public_boundaries.wire.claimed_sum,
        );
    workspace.closed_totals[@intFromEnum(VERIFIER_INPUT_BOUNDARY_DOMAIN)] =
        workspace.closed_totals[@intFromEnum(VERIFIER_INPUT_BOUNDARY_DOMAIN)].add(
            input.public_boundaries.verifier_input.claimed_sum,
        );
    workspace.framework_total = workspace.framework_total
        .add(input.provider_claim.claimed_sum)
        .add(input.public_boundaries.claimedSum());

    for (workspace.closed_totals) |value|
        if (!value.isZero()) return error.RelationNotClosed;
    if (!workspace.framework_total.isZero()) return error.RelationNotClosed;

    var receipt = ClosureReceiptV2{
        .format_version = CLOSURE_RECEIPT_FORMAT_VERSION_V2,
        .prefix_row_count = PREFIX_ROW_COUNT,
        .total_row_count = TOTAL_ROW_COUNT,
        .domain_count = DOMAIN_COUNT,
        .provider_row = PROVIDER_ROW,
        .provider_domain = PROVIDER_DOMAIN,
        .wire_boundary_domain = WIRE_BOUNDARY_DOMAIN,
        .verifier_input_boundary_domain = VERIFIER_INPUT_BOUNDARY_DOMAIN,
        .padding = .{ 0, 0, 0 },
        .source_authority_id = prepared.source_authority_id,
        .input_id = input.identity,
        .active_domain_mask = active_domain_mask,
        .prefix_totals = workspace.prefix_totals,
        .provider_claim = input.provider_claim,
        .public_boundaries = input.public_boundaries,
        .context_seam = prepared.context_seam,
        .closed_totals = workspace.closed_totals,
        .framework_total = workspace.framework_total,
        .closure_id = undefined,
    };
    receipt.closure_id = closureIdentityV2(&receipt);
    try receipt.validate();
    destination.* = receipt;
}

comptime {
    @setEvalBranchQuota(10_000);
    if (PREFIX_ROW_COUNT != 35 or TOTAL_ROW_COUNT != 36 or DOMAIN_COUNT != 47)
        @compileError("binary global-closure geometry drifted");
    if (@intFromEnum(PROVIDER_ROW) != PREFIX_ROW_COUNT or
        @intFromEnum(PROVIDER_DOMAIN) != 10)
    {
        @compileError("binary global-closure provider identity drifted");
    }
    if (@intFromEnum(WIRE_BOUNDARY_DOMAIN) != 13 or
        @intFromEnum(VERIFIER_INPUT_BOUNDARY_DOMAIN) != 25)
    {
        @compileError("binary global-closure public boundary identity drifted");
    }
    if (DOMAIN_COUNT >= @bitSizeOf(u64) or TOTAL_ROW_COUNT >= @bitSizeOf(u64))
        @compileError("binary global-closure masks overflow u64");
    if (AllocationLedgerV1.authority_preparation_heap_allocations != 0 or
        AllocationLedgerV1.workspace_initialization_heap_allocations != 0 or
        AllocationLedgerV1.fresh_hot_fill_heap_allocations != 0 or
        AllocationLedgerV1.reused_hot_fill_heap_allocations != 0)
    {
        @compileError("binary global-closure allocation ledger drifted");
    }
    if (AllocationLedgerV2.authority_preparation_heap_allocations != 0 or
        AllocationLedgerV2.input_preparation_heap_allocations != 0 or
        AllocationLedgerV2.workspace_initialization_heap_allocations != 0 or
        AllocationLedgerV2.fresh_hot_fill_heap_allocations != 0 or
        AllocationLedgerV2.reused_hot_fill_heap_allocations != 0)
    {
        @compileError("binary global-closure V2 allocation ledger drifted");
    }
    assertPointerFree(PreparedAuthorityV1);
    assertPointerFree(BoundarySourceV2);
    assertPointerFree(BoundaryAuthoritiesV2);
    assertPointerFree(RequiredContextV2);
    assertPointerFree(ContextSeamV2);
    assertPointerFree(SourceAuthorityV2);
    assertPointerFree(PreparedAuthorityV2);
    assertPointerFree(BoundaryEvidenceV2);
    assertPointerFree(PublicBoundaryClaimV2);
    assertPointerFree(PublicBoundariesV2);
    assertPointerFree(Workspace);
    assertPointerFree(ClosureInputV2);
    assertPointerFree(ClosureReceiptV1);
    assertPointerFree(ClosureReceiptV2);
}

pub fn assertPointerFree(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer, .optional, .error_union, .@"union" => @compileError("binary global-closure fixed storage contains dynamic state"),
        .array => |array| assertPointerFree(array.child),
        .@"struct" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        else => {},
    }
}
