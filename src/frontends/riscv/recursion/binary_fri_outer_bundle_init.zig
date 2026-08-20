//! Cold fixed-storage construction for a binary FRI outer bundle.

const std = @import("std");
const logup = @import("../air/logup.zig");
const poseidon_authority_mod = @import("../air/lang/typed_poseidon2_authority.zig");

pub fn init(
    allocator: std.mem.Allocator,
    source: anytype,
    comptime Self: type,
    comptime Source: type,
    comptime providerScratchByteCount: anytype,
    comptime bundleIdentity: anytype,
    comptime validate: anytype,
) !Self {
    const source_authority = try source.prepareAuthority();
    var composition_workspace = try Source.CompositionWorkspace.initPrepared(
        allocator,
        source,
        &source_authority,
    );
    errdefer composition_workspace.deinit();
    var fri_workspace = try Source.Workspace.initPrepared(
        allocator,
        source,
        &source_authority,
    );
    errdefer fri_workspace.deinit();
    var arithmetic_workspace = try Source.ArithmeticWorkspace.initPrepared(
        allocator,
        source,
        &source_authority,
    );
    errdefer arithmetic_workspace.deinit();
    var merkle_workspace = try Source.MerkleWorkspace.initPrepared(
        allocator,
        source,
        &source_authority,
    );
    errdefer merkle_workspace.deinit();
    var relation_rows = try Source.RelationRows.initPrepared(
        allocator,
        source,
        &source_authority,
    );
    errdefer relation_rows.deinit();
    var interaction_workspace = try Source.RelationInteractionWorkspace
        .initColdPrepared(allocator, source, &source_authority);
    errdefer interaction_workspace.deinit();
    var poseidon_authority = try poseidon_authority_mod.Authority.init(allocator);
    errdefer poseidon_authority.deinit();
    const poseidon_program_id = try poseidon_authority.programIdentity();
    if (!poseidon_program_id.isCanonical())
        return error.ProviderIdentityMismatch;
    const scratch_len = try providerScratchByteCount(
        merkle_workspace.provider_log_size,
    );
    const provider_scratch = try allocator.alignedAlloc(
        u8,
        .fromByteUnits(@alignOf(logup.RowPair)),
        scratch_len,
    );
    errdefer allocator.free(provider_scratch);

    var result = Self{
        .allocator = allocator,
        .source = source,
        .source_authority = source_authority,
        .composition_workspace = composition_workspace,
        .fri_workspace = fri_workspace,
        .arithmetic_workspace = arithmetic_workspace,
        .merkle_workspace = merkle_workspace,
        .relation_rows = relation_rows,
        .interaction_workspace = interaction_workspace,
        .poseidon_authority = poseidon_authority,
        .poseidon_program_id = poseidon_program_id,
        .provider_scratch = provider_scratch,
        .provider_custody = .local_core,
        .provider_log_size = merkle_workspace.provider_log_size,
        .shared_layout = null,
        .shared_calls = &.{},
        .owned_shared_calls = &.{},
        .shared_boundary_call_count = 0,
        .shared_outputs = &.{},
        .shared_outputs_ready = false,
        .main_prepared = false,
        .authority_seal = undefined,
    };
    result.authority_seal = bundleIdentity(&result);
    try validate(&result);
    return result;
}
