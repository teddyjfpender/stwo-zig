//! Real PCS commitment preparation for the R-008 caller/provider split.
//!
//! This module is the first split tranche whose `preprocessed_root` and
//! `main_root` are roots returned by the production commitment scheme rather
//! than differential Blake2s seals.  It still does not activate a production
//! proof: Tree 2, composition, openings, the proof-bound ordered-call digest,
//! and recursive verification remain deliberately outside this boundary.
//!
//! Ownership is transactional.  All descriptor/backing metadata is allocated
//! and every source range is admitted before the caller's production
//! `MainCommitment` or either guest arena moves.  After the handoff,
//! `Engine.commitWithBacking` consumes the complete source on both success and
//! failure.  An abort destroys the private scheme and any uncommitted sibling
//! tree; no partial prepared leaf can escape.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const pcs_core = @import("stwo_core").pcs;
const ColumnEvaluation = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const base_statement = @import("../../air/statement.zig");
const component_registry = @import("../../air/guest_precompile/component_registry.zig");
const guest_statement = @import("../../air/guest_precompile/statement.zig");
const guest_main_trace = @import("../../air/guest_precompile/main_trace.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const preprocessed = @import("../preprocessed.zig");
const production = @import("../main_trace_plan_execution_production.zig");
const aggregation_hash = @import("../../aggregation/hash.zig");
const aggregation_manifest = @import("../../aggregation/manifest.zig");
const aggregation_types = @import("../../aggregation/types.zig");
const split_leaf_prepare = @import("split_leaf_prepare.zig");
const split_leaf_statement = @import("split_leaf_statement.zig");

pub const RESEARCH_ONLY = true;
pub const ACTIVATES_PRODUCTION_PROOF = false;
pub const PREPARES_REAL_PCS_ROOTS = true;
pub const RETAINS_REAL_PCS_SCHEME = true;
pub const CALL_COMMITMENT_IS_AIR_PROVED = false;
pub const RETAINS_BASE_TREE2_AUTHORITY = false;
pub const SUPPORTS_EXTERNAL_BASE_TREE2_AUTHORITY = true;
pub const CAN_FINISH_STARK = false;
pub const CREATES_WORK_POOL = false;
pub const ALLOWS_PARALLEL_ROLE_PREPARE = true;
pub const LOCAL_GUEST_CHALLENGE_DRAW_ALLOWED = false;
pub const SHARED_CHALLENGE_DERIVED_ONLY_AFTER_BOTH_ROOTS = true;

pub const Digest = aggregation_hash.Digest;
pub const AcceptedProtocolV1 = aggregation_types.AcceptedProtocolV1;
pub const BaseMainCommitment = production.MainCommitment;
pub const format_version: u32 = 1;
pub const tree_count: usize = 2;
pub const tree0_index: usize = 0;
pub const tree1_index: usize = 1;
pub const caller_relation_source_columns: usize =
    guest_main_trace.caller_relation_source_column_count;
pub const provider_relation_source_columns: usize =
    guest_main_trace.provider_relation_source_column_count;

pub const pcs_commitment_profile =
    "production-pcs-tree0-tree1-retained-scheme-v1\x00";
pub const caller_declaration_domain =
    "stwo-zig/riscv/split/caller-pre-session-pcs/v1\x00";
pub const provider_declaration_domain =
    "stwo-zig/riscv/split/provider-pre-session-pcs/v1\x00";

/// Exact pre-Tree-0 order is:
///
/// 1. the ordinary PCS configuration;
/// 2. caller-only base public data (the provider has no base trace);
/// 3. this role frame;
/// 4. canonical extension-statement, protocol, job, artifact, call-list, and
///    component facts; then
/// 5. Tree 0 followed by Tree 1 through the existing engine.
pub const caller_pre_tree_domain_words = [5]u32{
    0x5357_5453, // "STWS"
    0x3150_4343, // "CCP1"
    format_version,
    @intFromEnum(aggregation_types.LeafRole.core_request),
    tree_count,
};
pub const provider_pre_tree_domain_words = [5]u32{
    0x5357_5453,
    0x3150_4350, // "PCP1"
    format_version,
    @intFromEnum(aggregation_types.LeafRole.poseidon2_provider),
    tree_count,
};

/// Exact post-barrier order is this role frame followed by the complete
/// 133-word canonical session envelope.  The envelope already contains the
/// session digest, both commitment roots through its selected descriptor, and
/// the one manifest-derived `(z, alpha)`.  This transition performs no draw.
pub const caller_post_barrier_domain_words = [5]u32{
    0x5357_5453,
    0x3146_4343, // "CCF1"
    format_version,
    @intFromEnum(aggregation_types.LeafRole.core_request),
    split_leaf_statement.word_count,
};
pub const provider_post_barrier_domain_words = [5]u32{
    0x5357_5453,
    0x3146_4350, // "PCF1"
    format_version,
    @intFromEnum(aggregation_types.LeafRole.poseidon2_provider),
    split_leaf_statement.word_count,
};

pub const CancellationTokenV1 = struct {
    requested: std.atomic.Value(bool) = .init(false),

    pub fn request(self: *CancellationTokenV1) void {
        self.requested.store(true, .release);
    }

    pub fn isRequested(self: *const CancellationTokenV1) bool {
        return self.requested.load(.acquire);
    }
};

pub const CommitmentPhaseV1 = enum {
    commitments_frozen,
    session_bound,
};

pub const TreeOwnershipProfileV1 = struct {
    tree0_columns: usize,
    tree1_columns: usize,
    tree0_cells: usize,
    tree1_cells: usize,
    tree0_source_backings: usize,
    tree1_source_backings: usize,
    /// Copies performed while assembling the role-specific source plans.
    /// This excludes any detach/copy selected inside the commitment backend.
    commitment_source_plan_cell_copies: usize,
    /// Exact projection copied before Tree 1 consumes its source values. This
    /// is the same 191-column retention requirement as the integrated prover,
    /// split into independently owned 158/33-column role allocations.
    relation_source_capture_cell_copies: usize,
    retained_relation_source_cells: usize,
    /// Conservative bound for field elements that the generic PCS layer may
    /// detach from the supplied backing arenas. The engine currently exposes
    /// no per-commit adoption receipt, so this deliberately is not reported as
    /// an observed copy count.
    backend_source_detach_copy_upper_bound_cells: usize,
    retained_schemes: usize,
    retained_channels: usize,
    nested_work_pools: usize,
    local_shared_challenge_draws: usize,
};

/// Minimal post-Tree-1 role projection required to construct guest LogUp
/// columns after the shared session challenge exists. It intentionally does
/// not retain unrelated compatibility columns.
pub fn RoleRelationSourceV1(
    comptime role: aggregation_types.LeafRole,
) type {
    const column_count = switch (role) {
        .core_request => caller_relation_source_columns,
        .poseidon2_provider => provider_relation_source_columns,
    };
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        storage: []M31,
        log_size: u32,
        n_rows: u32,
        domain_size: usize,

        fn capture(allocator: std.mem.Allocator, main: anytype) !Self {
            if (main.log_size >= @bitSizeOf(usize))
                return error.SplitPcsResourceOverflow;
            const domain_size = try domainSize(main.log_size);
            if (main.domain_size != domain_size or main.n_rows > domain_size)
                return error.InvalidSplitPcsRelationSource;
            const cells = try checkedMul(column_count, domain_size);
            const storage = try allocator.alloc(M31, cells);
            errdefer allocator.free(storage);

            if (role == .core_request) {
                for (0..column_count) |column_index| {
                    @memcpy(
                        storage[column_index * domain_size ..][0..domain_size],
                        main.column(column_index),
                    );
                }
            } else {
                // Provider projection is enabled, input[16], output[16]. The
                // output starts after the production Poseidon2 temporaries.
                copyProjectedColumn(storage, domain_size, 0, main.column(0));
                for (0..16) |lane| {
                    copyProjectedColumn(
                        storage,
                        domain_size,
                        1 + lane,
                        main.column(1 + lane),
                    );
                    copyProjectedColumn(
                        storage,
                        domain_size,
                        17 + lane,
                        main.column(provider_output_start + lane),
                    );
                }
            }
            return .{
                .allocator = allocator,
                .storage = storage,
                .log_size = main.log_size,
                .n_rows = main.n_rows,
                .domain_size = domain_size,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.storage.len != 0) self.allocator.free(self.storage);
            self.* = undefined;
        }

        pub fn validate(
            self: *const Self,
            component: component_registry.Descriptor,
        ) !void {
            try component.validate();
            if (component.slot != switch (role) {
                .core_request => .caller,
                .poseidon2_provider => .provider,
            } or
                self.log_size != component.log_size or
                self.n_rows != component.n_rows or
                self.domain_size != try domainSize(component.log_size) or
                self.storage.len != try checkedMul(column_count, self.domain_size))
            {
                return error.InvalidSplitPcsRelationSource;
            }
        }

        pub fn column(self: *const Self, index: usize) []const M31 {
            std.debug.assert(index < column_count);
            const start = index * self.domain_size;
            return self.storage[start..][0..self.domain_size];
        }

        pub fn columnCount(_: *const Self) usize {
            return column_count;
        }
    };
}

pub const CallerRelationSourceV1 = RoleRelationSourceV1(.core_request);
pub const ProviderRelationSourceV1 = RoleRelationSourceV1(
    .poseidon2_provider,
);

pub const SharedChallengeBindingV1 = struct {
    session_digest: Digest,
    challenge_context_digest: Digest,
    guest_z: aggregation_types.SecureFelt,
    guest_alpha: aggregation_types.SecureFelt,
};

pub fn leafIndex(comptime role: aggregation_types.LeafRole) u32 {
    return switch (role) {
        .core_request => 0,
        .poseidon2_provider => 1,
    };
}

pub fn declarationDomain(comptime role: aggregation_types.LeafRole) []const u8 {
    return switch (role) {
        .core_request => caller_declaration_domain,
        .poseidon2_provider => provider_declaration_domain,
    };
}

pub fn preTreeDomainWords(
    comptime role: aggregation_types.LeafRole,
) *const [5]u32 {
    return switch (role) {
        .core_request => &caller_pre_tree_domain_words,
        .poseidon2_provider => &provider_pre_tree_domain_words,
    };
}

pub fn postBarrierDomainWords(
    comptime role: aggregation_types.LeafRole,
) *const [5]u32 {
    return switch (role) {
        .core_request => &caller_post_barrier_domain_words,
        .poseidon2_provider => &provider_post_barrier_domain_words,
    };
}

pub fn RoleAuthority(comptime role: aggregation_types.LeafRole) type {
    return switch (role) {
        .core_request => split_leaf_prepare.CallerPrepareAuthorityV1,
        .poseidon2_provider => split_leaf_prepare.ProviderPrepareAuthorityV1,
    };
}

fn ShadowRole(comptime role: aggregation_types.LeafRole) type {
    return switch (role) {
        .core_request => split_leaf_prepare.PreparedCallerLeafV1,
        .poseidon2_provider => split_leaf_prepare.PreparedProviderLeafV1,
    };
}

pub fn PreparedRolePcsV1(
    comptime Engine: type,
    comptime role: aggregation_types.LeafRole,
) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        scheme: Engine.Scheme,
        channel: Engine.Channel,
        pcs_config: pcs_core.PcsConfig,
        authority: RoleAuthority(role),
        profile_statement_digest: Digest,
        guest_call_commitment: Digest,
        guest_call_count: u64,
        relation_source: RoleRelationSourceV1(role),
        roots: [tree_count]Digest,
        descriptor: aggregation_types.LeafDescriptorV1,
        ownership: TreeOwnershipProfileV1,
        phase: CommitmentPhaseV1 = .commitments_frozen,
        session_binding: ?SharedChallengeBindingV1 = null,

        pub fn deinit(self: *Self) void {
            self.relation_source.deinit();
            Engine.deinit(&self.scheme, self.allocator);
            self.* = undefined;
        }

        /// Cold integrity check at Barrier A.  The scheme remains the root
        /// authority; cached roots and the descriptor must agree with it.
        pub fn validate(self: *Self) !void {
            const count = std.math.cast(u32, self.guest_call_count) orelse
                return error.CallCountOutOfRange;
            try self.authority.validate(count);
            try self.relation_source.validate(self.authority.component);
            try aggregation_types.validateCallCount(self.guest_call_count);
            if (aggregation_hash.isZero(self.profile_statement_digest) or
                aggregation_hash.isZero(self.guest_call_commitment))
            {
                return error.InvalidPreparedPcsIdentity;
            }
            try validateSchemeRoots(Engine, self.allocator, &self.scheme, self.roots);
            const expected = try canonicalDescriptor(
                role,
                self.authority,
                self.profile_statement_digest,
                self.roots[tree0_index],
                self.roots[tree1_index],
                self.guest_call_commitment,
                self.guest_call_count,
            );
            if (!std.meta.eql(expected, self.descriptor))
                return error.PreparedPcsDescriptorMutated;
            if (self.ownership.retained_schemes != 1 or
                self.ownership.retained_channels != 1 or
                self.ownership.nested_work_pools != 0 or
                self.ownership.local_shared_challenge_draws != 0 or
                self.ownership.commitment_source_plan_cell_copies != 0 or
                self.ownership.relation_source_capture_cell_copies !=
                    self.relation_source.storage.len or
                self.ownership.retained_relation_source_cells !=
                    self.relation_source.storage.len or
                self.ownership.tree0_columns == 0 or
                self.ownership.tree1_columns == 0 or
                self.ownership.tree0_source_backings == 0 or
                self.ownership.tree1_source_backings == 0 or
                self.ownership.backend_source_detach_copy_upper_bound_cells !=
                    try checkedAdd(
                        self.ownership.tree0_cells,
                        self.ownership.tree1_cells,
                    ))
            {
                return error.InvalidPreparedPcsOwnership;
            }
            switch (self.phase) {
                .commitments_frozen => if (self.session_binding != null)
                    return error.InvalidPcsBarrierPhase,
                .session_bound => if (self.session_binding == null)
                    return error.InvalidPcsBarrierPhase,
            }
        }

        /// Barrier-B transition. All fallible admission and encoding occurs
        /// before the first channel mix, so a rejection leaves both the phase
        /// and transcript unchanged. The shared guest pair is copied from the
        /// prepared manifest and never sampled from this leaf-local channel.
        pub fn bindSession(
            self: *Self,
            session: *const aggregation_manifest.PreparedSessionV1,
            identities: *const split_leaf_statement.VerifierOwnedLeafIdentitiesV1,
        ) !SharedChallengeBindingV1 {
            if (self.phase != .commitments_frozen)
                return error.PcsSessionAlreadyBound;
            try self.validate();
            const leaf = try session.leaf(leafIndex(role));
            if (!std.meta.eql(leaf.descriptor, self.descriptor))
                return error.PcsSessionDescriptorMismatch;

            const binding = try mixPostBarrierBindingV1(
                role,
                &self.channel,
                session,
                identities,
            );
            self.phase = .session_bound;
            self.session_binding = binding;
            return binding;
        }
    };
}

pub fn PreparedCallerPcsV1(comptime Engine: type) type {
    return PreparedRolePcsV1(Engine, .core_request);
}

pub fn PreparedProviderPcsV1(comptime Engine: type) type {
    return PreparedRolePcsV1(Engine, .poseidon2_provider);
}

pub fn ManifestBarrierV1(comptime Engine: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        accepted_protocol: aggregation_types.AcceptedProtocolV1,
        descriptors: [2]aggregation_types.LeafDescriptorV1,
        leaves: [2]aggregation_manifest.PreparedLeafV1,
        session: aggregation_manifest.PreparedSessionV1,

        pub fn create(
            allocator: std.mem.Allocator,
            accepted_protocol: aggregation_types.AcceptedProtocolV1,
            caller: *PreparedCallerPcsV1(Engine),
            provider: *PreparedProviderPcsV1(Engine),
        ) !*Self {
            try accepted_protocol.validate();
            if (caller.phase != .commitments_frozen or
                provider.phase != .commitments_frozen)
            {
                return error.InvalidPcsBarrierPhase;
            }
            try caller.validate();
            try provider.validate();
            try validatePair(accepted_protocol, caller, provider);

            const result = try allocator.create(Self);
            errdefer allocator.destroy(result);
            result.allocator = allocator;
            result.accepted_protocol = accepted_protocol;
            result.descriptors = .{ caller.descriptor, provider.descriptor };
            const header = aggregation_types.ManifestHeaderV1{
                .proof_protocol_digest = accepted_protocol.proof_protocol_digest,
                .relation_registry_digest = accepted_protocol.relation_registry_digest,
                .leaf_count = result.descriptors.len,
                .request_set_digest = aggregation_manifest.requestLeafDigest(
                    caller.descriptor.job_digest,
                ),
            };
            result.session = try aggregation_manifest.prepare(
                .{ .header = header, .descriptors = &result.descriptors },
                accepted_protocol,
                &result.leaves,
            );
            result.session.leaves = &result.leaves;
            return result;
        }

        pub fn deinit(self: *Self) void {
            const allocator = self.allocator;
            self.* = undefined;
            allocator.destroy(self);
        }
    };
}

pub fn prepareCaller(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    core: *const base_statement.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    base_main: *production.MainCommitment,
    shadow: *split_leaf_prepare.PreparedCallerLeafV1,
    cancellation: ?*const CancellationTokenV1,
) !PreparedCallerPcsV1(Engine) {
    // The preparation API consumes both input owners on every return. This
    // mirrors the engine's own commit contract and removes an otherwise
    // ambiguous "did the failure occur before or after PCS handoff?" state.
    defer base_main.deinit(allocator);
    defer shadow.deinit();
    if (comptime !supportsSplitPcs(Engine))
        return error.UnsupportedSplitPcsEngine;
    return prepareRoleSupported(
        Engine,
        .core_request,
        allocator,
        pcs_config,
        core,
        extension,
        base_main,
        shadow,
        cancellation,
    );
}

/// Preferred bridge from the published production Tree-1 epoch. It proves
/// pointer identity with the complete base statement before moving the main
/// commitment, while the caller retains `base_prepared` as the sole external
/// owner of opcode, clock, and lookup-counter authority needed by Tree 2.
///
/// The returned split PCS owner does not borrow `base_prepared`; a future
/// caller finish must receive that owner explicitly and revalidate it. Both
/// the main commitment and `shadow` are consumed on every return after the
/// production handoff succeeds.
pub fn prepareCallerFromPublishedBase(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    core: *const base_statement.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    base_prepared: *production.Prepared,
    shadow: *split_leaf_prepare.PreparedCallerLeafV1,
    cancellation: ?*const CancellationTokenV1,
) !PreparedCallerPcsV1(Engine) {
    defer shadow.deinit();
    if (comptime !supportsSplitPcs(Engine))
        return error.UnsupportedSplitPcsEngine;
    const retained_statement = try base_prepared.retainedStatement();
    if (retained_statement != core)
        return error.SplitPcsBaseStatementAuthorityMismatch;
    var base_main = try base_prepared.takeMainCommitment();
    defer base_main.deinit(allocator);
    return prepareRoleSupported(
        Engine,
        .core_request,
        allocator,
        pcs_config,
        core,
        extension,
        &base_main,
        shadow,
        cancellation,
    );
}

pub fn prepareProvider(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    core: *const base_statement.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    shadow: *split_leaf_prepare.PreparedProviderLeafV1,
    cancellation: ?*const CancellationTokenV1,
) !PreparedProviderPcsV1(Engine) {
    // Consumed on success and failure; see `prepareCaller`.
    defer shadow.deinit();
    if (comptime !supportsSplitPcs(Engine))
        return error.UnsupportedSplitPcsEngine;
    return prepareRoleSupported(
        Engine,
        .poseidon2_provider,
        allocator,
        pcs_config,
        core,
        extension,
        null,
        shadow,
        cancellation,
    );
}

fn supportsSplitPcs(comptime Engine: type) bool {
    return @hasDecl(Engine, "Scheme") and
        @hasDecl(Engine, "Hasher") and
        @hasDecl(Engine, "Channel") and
        @hasDecl(Engine, "init") and
        @hasDecl(Engine, "deinit") and
        @hasDecl(Engine, "commitWithBacking") and
        @hasDecl(Engine, "flushPendingCommit") and
        @hasDecl(Engine.Scheme, "roots");
}

fn prepareRoleSupported(
    comptime Engine: type,
    comptime role: aggregation_types.LeafRole,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    core: *const base_statement.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    base_main: if (role == .core_request) *production.MainCommitment else ?*production.MainCommitment,
    shadow: *ShadowRole(role),
    cancellation: ?*const CancellationTokenV1,
) !PreparedRolePcsV1(Engine, role) {
    comptime {
        if (Engine.Hasher.Hash != Digest)
            @compileError("R-008 V1 manifest requires 32-byte Blake2s PCS roots");
    }
    try checkCancellation(cancellation);
    try extension.validate(core);
    try shadow.validate();
    try validateRoleAllocator(allocator, shadow);
    const profile_statement_digest = try extension.digest(core);
    if (aggregation_hash.isZero(profile_statement_digest))
        return error.InvalidPreparedPcsIdentity;
    if (role == .core_request) try validateBaseMain(core, base_main);

    var relation_source = try RoleRelationSourceV1(role).capture(
        allocator,
        &shadow.main,
    );
    var relation_source_owned = true;
    errdefer if (relation_source_owned) relation_source.deinit();

    var base_preprocessed: []ColumnEvaluation = &.{};
    if (role == .core_request) {
        base_preprocessed = try preprocessed.generate(allocator, core.*);
    }
    var base_preprocessed_owned = base_preprocessed.len != 0;
    errdefer if (base_preprocessed_owned)
        freeIndependentColumns(allocator, base_preprocessed);

    var tree0 = if (role == .core_request)
        try SourcePlan.initCallerTree0(
            allocator,
            base_preprocessed,
            shadow.selectors.log_size,
            shadow.selectors.storage,
        )
    else
        try SourcePlan.initRoleOnly(
            allocator,
            shadow.selectors.log_size,
            shadow.selectors.storage,
            split_leaf_prepare.selector_column_count,
        );
    errdefer tree0.deinit();

    var tree1 = if (role == .core_request)
        try SourcePlan.initCallerTree1(
            allocator,
            base_main,
            shadow.main.log_size,
            shadow.main.storage,
        )
    else
        try SourcePlan.initRoleOnly(
            allocator,
            shadow.main.log_size,
            shadow.main.storage,
            @intCast(shadow.authority.component.main_columns),
        );
    errdefer tree1.deinit();

    try checkCancellation(cancellation);
    var scheme = try Engine.init(allocator, pcs_config);
    var scheme_owned = true;
    errdefer if (scheme_owned) Engine.deinit(&scheme, allocator);
    var channel = Engine.Channel{};
    mixPreTreePrefixV1(
        role,
        pcs_config,
        &channel,
        core,
        shadow.authority,
        profile_statement_digest,
        shadow.guest_call_commitment,
        shadow.guest_call_count,
    );

    // From this point the inputs are consumed even when a PCS operation fails.
    // Validation above proves both moves and pointer matches cannot fail. No
    // fallible operation is placed between the two handoffs.
    const selector_storage = shadow.selectors.takeStorage() catch unreachable;
    const main_storage = shadow.main.takeStorage() catch unreachable;
    tree0.activateRoleStorage(selector_storage);
    tree1.activateRoleStorage(main_storage);
    if (role == .core_request) {
        allocator.free(base_preprocessed);
        base_preprocessed_owned = false;
        tree1.activateBaseMain(allocator, base_main);
    }

    const tree0_cells = try countCells(tree0.columns);
    const tree1_cells = try countCells(tree1.columns);
    const ownership = TreeOwnershipProfileV1{
        .tree0_columns = tree0.columns.len,
        .tree1_columns = tree1.columns.len,
        .tree0_cells = tree0_cells,
        .tree1_cells = tree1_cells,
        .tree0_source_backings = tree0.backing_buffers.len,
        .tree1_source_backings = tree1.backing_buffers.len,
        .commitment_source_plan_cell_copies = 0,
        .relation_source_capture_cell_copies = relation_source.storage.len,
        .retained_relation_source_cells = relation_source.storage.len,
        .backend_source_detach_copy_upper_bound_cells = try checkedAdd(
            tree0_cells,
            tree1_cells,
        ),
        .retained_schemes = 1,
        .retained_channels = 1,
        .nested_work_pools = 0,
        .local_shared_challenge_draws = 0,
    };

    try commitSource(Engine, allocator, &scheme, &channel, &tree0);
    try checkCancellation(cancellation);
    try commitSource(Engine, allocator, &scheme, &channel, &tree1);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    try checkCancellation(cancellation);

    const roots = try readExactRoots(Engine, allocator, &scheme);
    const descriptor = try canonicalDescriptor(
        role,
        shadow.authority,
        profile_statement_digest,
        roots[tree0_index],
        roots[tree1_index],
        shadow.guest_call_commitment,
        shadow.guest_call_count,
    );
    const result = PreparedRolePcsV1(Engine, role){
        .allocator = allocator,
        .scheme = scheme,
        .channel = channel,
        .pcs_config = pcs_config,
        .authority = shadow.authority,
        .profile_statement_digest = profile_statement_digest,
        .guest_call_commitment = shadow.guest_call_commitment,
        .guest_call_count = shadow.guest_call_count,
        .relation_source = relation_source,
        .roots = roots,
        .descriptor = descriptor,
        .ownership = ownership,
    };
    relation_source_owned = false;
    scheme_owned = false;
    return result;
}

const provider_output_start: usize = 1 + poseidon2_air.N_TEMPORARIES;

const split_support = @import("split_pcs_prepare_support.zig").Ops(@This());
const copyProjectedColumn = split_support.copyProjectedColumn;
const validateRoleAllocator = split_support.validateRoleAllocator;
const checkCancellation = split_support.checkCancellation;
pub const mixPreTreePrefixV1 = split_support.mixPreTreePrefixV1;
pub const mixPostBarrierBindingV1 = split_support.mixPostBarrierBindingV1;
pub const preSessionDeclarationDigest = split_support.preSessionDeclarationDigest;
const canonicalDescriptor = split_support.canonicalDescriptor;
const validatePair = split_support.validatePair;
const readExactRoots = split_support.readExactRoots;
const validateSchemeRoots = split_support.validateSchemeRoots;
const commitSource = split_support.commitSource;
const SourcePlan = split_support.SourcePlan;
const validateBaseMain = split_support.validateBaseMain;
const countCells = split_support.countCells;
const freeIndependentColumns = split_support.freeIndependentColumns;
const domainSize = split_support.domainSize;
const checkedAdd = split_support.checkedAdd;
const checkedMul = split_support.checkedMul;

comptime {
    if (split_leaf_prepare.selector_column_count != 2 or
        component_registry.caller_layout.main_columns != 286 or
        component_registry.provider_main_columns != 445 or
        caller_relation_source_columns != 158 or
        provider_relation_source_columns != 33 or
        provider_output_start != 427 or
        split_leaf_statement.word_count != 133)
    {
        @compileError("R-008 real PCS geometry drifted");
    }
}
