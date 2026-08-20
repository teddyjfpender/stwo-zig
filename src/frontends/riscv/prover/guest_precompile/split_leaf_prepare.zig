//! Failure-atomic pre-challenge ownership for the R-008 split reference.
//!
//! Each role independently repeats the production guest-witness preflight,
//! owns its exact selector and main-component columns, and freezes canonical
//! call/statement identities before a shared challenge exists. The two
//! results can then enter one heap-stable R-007 manifest barrier.
//!
//! This is deliberately the narrowest truthful commitment-state abstraction
//! available without changing production PCS/transcript ownership. The
//! digests below are Blake2s seals over complete component columns; they are
//! not Merkle/PCS roots, the caller seal does not include base RISC-V columns,
//! and the ordered call digest is not constrained by an AIR. Consequently no
//! value produced here is accepted by the production prover or verifier.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const base_statement = @import("../../air/statement.zig");
const component_registry = @import("../../air/guest_precompile/component_registry.zig");
const guest_main_trace = @import("../../air/guest_precompile/main_trace.zig");
const guest_statement = @import("../../air/guest_precompile/statement.zig");
const call_buffer = @import("../../runner/guest_precompile/call_buffer.zig");
const guest_runner = @import("../../runner/guest_precompile/poseidon2_v1.zig");
const aggregation_hash = @import("../../aggregation/hash.zig");
const aggregation_manifest = @import("../../aggregation/manifest.zig");
const aggregation_types = @import("../../aggregation/types.zig");
const split_leaf_statement = @import("split_leaf_statement.zig");
const split_main_trace = @import("split_main_trace.zig");

pub const RESEARCH_ONLY = true;
pub const ACTIVATES_PRODUCTION_PROOF = false;
pub const RETAINS_PCS_SCHEME = false;
pub const SHADOW_ROOTS_ARE_PCS_ROOTS = false;
pub const CALL_COMMITMENT_IS_AIR_PROVED = false;
pub const CALLER_SEAL_INCLUDES_BASE_RISCV_TRACE = false;
pub const PREPARES_BEFORE_SHARED_CHALLENGE = true;
pub const ALLOWS_PARALLEL_ROLE_PREPARE = true;
pub const PREPARED_STATE_IS_MOVE_SAFE = true;

pub const Digest = aggregation_hash.Digest;
pub const format_version: u32 = 1;
pub const selector_column_count: usize = 2;
pub const role_prepare_allocation_count: usize = 2;
pub const manifest_barrier_allocation_count: usize = 1;

pub const ordered_call_domain =
    "stwo-zig/riscv/split/ordered-io-calls-shadow/v1\x00";
pub const caller_selector_domain =
    "stwo-zig/riscv/split/caller-selectors-shadow/v1\x00";
pub const provider_selector_domain =
    "stwo-zig/riscv/split/provider-selectors-shadow/v1\x00";
pub const caller_declaration_domain =
    "stwo-zig/riscv/split/caller-pre-session-shadow/v1\x00";
pub const provider_declaration_domain =
    "stwo-zig/riscv/split/provider-pre-session-shadow/v1\x00";
pub const shadow_commitment_profile =
    "blake2s-complete-component-columns-not-pcs-v1\x00";

fn componentKind(
    comptime role: aggregation_types.LeafRole,
) component_registry.Kind {
    return switch (role) {
        .core_request => .guest_poseidon2_call_v1,
        .poseidon2_provider => .guest_poseidon2_provider_compat_v1,
    };
}

fn leafIndex(comptime role: aggregation_types.LeafRole) u32 {
    return switch (role) {
        .core_request => 0,
        .poseidon2_provider => 1,
    };
}

fn selectorDomain(comptime role: aggregation_types.LeafRole) []const u8 {
    return switch (role) {
        .core_request => caller_selector_domain,
        .poseidon2_provider => provider_selector_domain,
    };
}

fn declarationDomain(comptime role: aggregation_types.LeafRole) []const u8 {
    return switch (role) {
        .core_request => caller_declaration_domain,
        .poseidon2_provider => provider_declaration_domain,
    };
}

/// Prover-side immutable authority selected before role preparation. The
/// protocol digest is still checked independently by the manifest barrier;
/// this value merely freezes what the role claims it is preparing.
pub fn RolePrepareAuthorityV1(
    comptime role: aggregation_types.LeafRole,
) type {
    return struct {
        const Self = @This();

        accepted_protocol: aggregation_types.AcceptedProtocolV1,
        job_digest: Digest,
        air_artifact_digest: Digest,
        component: component_registry.Descriptor,

        pub fn canonical(
            accepted_protocol: aggregation_types.AcceptedProtocolV1,
            job_digest: Digest,
            air_artifact_digest: Digest,
            guest_call_count: u32,
        ) !Self {
            const result = Self{
                .accepted_protocol = accepted_protocol,
                .job_digest = job_digest,
                .air_artifact_digest = air_artifact_digest,
                .component = try component_registry.Descriptor.canonical(
                    componentKind(role),
                    guest_call_count,
                ),
            };
            try result.validate(guest_call_count);
            return result;
        }

        pub fn validate(self: Self, guest_call_count: u32) !void {
            try self.accepted_protocol.validate();
            if (aggregation_hash.isZero(self.job_digest))
                return error.ZeroJobDigest;
            if (aggregation_hash.isZero(self.air_artifact_digest))
                return error.ZeroArtifactIdentity;
            try self.component.validate();
            const expected = try component_registry.Descriptor.canonical(
                componentKind(role),
                guest_call_count,
            );
            if (!std.meta.eql(self.component, expected))
                return error.ArtifactComponentMismatch;
        }
    };
}

pub const CallerPrepareAuthorityV1 = RolePrepareAuthorityV1(.core_request);
pub const ProviderPrepareAuthorityV1 = RolePrepareAuthorityV1(
    .poseidon2_provider,
);

/// One contiguous allocation owns the role's exact `(is_first, is_active)`
/// component selectors in committed circle-bit-reversed order.
fn OwnedSelectorsV1(comptime role: aggregation_types.LeafRole) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        storage: []M31,
        log_size: u32,
        n_rows: u32,
        domain_size: usize,

        fn init(
            allocator: std.mem.Allocator,
            component: component_registry.Descriptor,
        ) !Self {
            try component.validate();
            if (component.kind != componentKind(role))
                return error.ArtifactComponentMismatch;
            if (component.log_size >= @bitSizeOf(usize))
                return error.TraceSizeOverflow;
            const domain_size = @as(usize, 1) << @intCast(component.log_size);
            if (component.n_rows > domain_size)
                return error.InvalidTraceShape;
            const cells = std.math.mul(
                usize,
                selector_column_count,
                domain_size,
            ) catch return error.TraceSizeOverflow;
            _ = std.math.mul(usize, cells, @sizeOf(M31)) catch
                return error.TraceSizeOverflow;
            const storage = try allocator.alloc(M31, cells);
            @memset(storage, M31.zero());
            storage[guest_main_trace.committedRow(0, component.log_size)] =
                M31.one();
            const active = storage[domain_size..];
            for (0..component.n_rows) |logical_row| {
                active[
                    guest_main_trace.committedRow(
                        logical_row,
                        component.log_size,
                    )
                ] = M31.one();
            }
            return .{
                .allocator = allocator,
                .storage = storage,
                .log_size = component.log_size,
                .n_rows = component.n_rows,
                .domain_size = domain_size,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.storage.len != 0) self.allocator.free(self.storage);
            self.* = undefined;
        }

        /// Moves the selector arena into a real PCS Tree-0 owner. A successful
        /// call disarms this value; `deinit` remains valid so the enclosing
        /// prepared-role transaction can be cleaned up uniformly.
        pub fn takeStorage(self: *Self) ![]M31 {
            if (self.storage.len == 0)
                return error.SplitSelectorStorageAlreadyTransferred;
            const result = self.storage;
            self.storage = &.{};
            return result;
        }

        pub fn column(self: *const Self, index: usize) []const M31 {
            std.debug.assert(index < selector_column_count);
            const start = index * self.domain_size;
            return self.storage[start..][0..self.domain_size];
        }

        fn validateCanonical(self: *const Self) !void {
            if (self.log_size >= @bitSizeOf(usize))
                return error.TraceSizeOverflow;
            const expected_domain = @as(usize, 1) << @intCast(self.log_size);
            if (self.domain_size != expected_domain or
                self.n_rows > self.domain_size or
                self.storage.len != selector_column_count * self.domain_size)
            {
                return error.InvalidPreparedSelectorShape;
            }
            const first = self.column(0);
            const active = self.column(1);
            const first_position = guest_main_trace.committedRow(
                0,
                self.log_size,
            );
            var first_count: usize = 0;
            var active_count: usize = 0;
            for (first, active, 0..) |first_value, active_value, position| {
                if (!first_value.isZero()) {
                    if (!first_value.isOne() or position != first_position)
                        return error.NonCanonicalPreparedSelectors;
                    first_count += 1;
                }
                if (!active_value.isZero()) {
                    if (!active_value.isOne())
                        return error.NonCanonicalPreparedSelectors;
                    active_count += 1;
                }
            }
            if (first_count != 1 or active_count != self.n_rows)
                return error.NonCanonicalPreparedSelectors;
            for (0..self.n_rows) |logical_row| {
                if (!active[
                    guest_main_trace.committedRow(
                        logical_row,
                        self.log_size,
                    )
                ].isOne()) return error.NonCanonicalPreparedSelectors;
            }
        }

        fn commitment(self: *const Self) !Digest {
            try self.validateCanonical();
            var sink = aggregation_hash.HashSink.init(selectorDomain(role));
            try sink.writeAll(shadow_commitment_profile);
            try aggregation_hash.writeU32(&sink, format_version);
            try aggregation_hash.writeU32(&sink, self.log_size);
            try aggregation_hash.writeU32(&sink, self.n_rows);
            try aggregation_hash.writeU32(&sink, selector_column_count);
            try aggregation_hash.writeU64(&sink, self.domain_size);
            for (self.storage) |value| {
                const bytes = value.toBytesLe();
                try sink.writeAll(&bytes);
            }
            return sink.finalize();
        }
    };
}

pub const CallerOwnedSelectorsV1 = OwnedSelectorsV1(.core_request);
pub const ProviderOwnedSelectorsV1 = OwnedSelectorsV1(.poseidon2_provider);

/// Canonical duplicate-preserving commitment to the exact ordered public
/// `(input[16], output[16])` relation rows. Execution clocks and memory facts
/// are intentionally excluded: they are caller-local relations, not the
/// caller/provider boundary. Empty input uses R-007's mandated empty digest.
pub fn orderedCallCommitment(records: []const call_buffer.Record) !Digest {
    const count = std.math.cast(u64, records.len) orelse
        return error.CallCountOutOfRange;
    try aggregation_types.validateCallCount(count);
    if (records.len == 0) return aggregation_hash.emptyCallCommitment();

    var sink = aggregation_hash.HashSink.init(ordered_call_domain);
    try aggregation_hash.writeU32(&sink, format_version);
    try aggregation_hash.writeU32(&sink, call_buffer.lane_count);
    try aggregation_hash.writeU64(&sink, count);
    for (records, 0..) |record, index| {
        try aggregation_hash.writeU64(&sink, index);
        for (record.input) |word| {
            if (word >= aggregation_types.M31_MODULUS)
                return error.NonCanonicalCallWord;
            try aggregation_hash.writeU32(&sink, word);
        }
        for (record.output) |word| {
            if (word >= aggregation_types.M31_MODULUS)
                return error.NonCanonicalCallWord;
            try aggregation_hash.writeU32(&sink, word);
        }
    }
    const result = sink.finalize();
    if (aggregation_hash.isZero(result) or
        aggregation_hash.eql(result, aggregation_hash.emptyCallCommitment()))
    {
        return error.InvalidCallCommitment;
    }
    return result;
}

fn MainOwnedV1(comptime role: aggregation_types.LeafRole) type {
    return switch (role) {
        .core_request => split_main_trace.CallerOwnedV1,
        .poseidon2_provider => split_main_trace.ProviderOwnedV1,
    };
}

fn mainCommitment(
    comptime role: aggregation_types.LeafRole,
    main: *const MainOwnedV1(role),
) !Digest {
    if (role == .core_request) {
        const columns = main.committedColumns();
        return split_main_trace.callerTraceDigest(
            main.log_size,
            main.n_rows,
            &columns,
        );
    }
    const columns = main.committedColumns();
    return split_main_trace.providerTraceDigest(
        main.log_size,
        main.n_rows,
        &columns,
    );
}

fn writeComponent(
    sink: anytype,
    component: component_registry.Descriptor,
) !void {
    try aggregation_hash.writeU32(sink, @intFromEnum(component.slot));
    try aggregation_hash.writeU32(sink, @intFromEnum(component.kind));
    try aggregation_hash.writeU16(sink, component.version);
    try aggregation_hash.writeU32(sink, component.n_rows);
    try aggregation_hash.writeU32(sink, component.log_size);
    try aggregation_hash.writeU16(sink, component.preprocessed_columns);
    try aggregation_hash.writeU16(sink, component.main_columns);
    try aggregation_hash.writeU16(sink, component.interaction_columns);
}

/// Hash every pre-session statement field except the digest being defined.
/// Keeping this constructor distinct from the session-bound leaf envelope
/// closes the cycle identified by the preceding R-008 tranche.
pub fn preSessionDeclarationDigest(
    comptime role: aggregation_types.LeafRole,
    descriptor: aggregation_types.LeafDescriptorV1,
    component: component_registry.Descriptor,
) !Digest {
    if (descriptor.role != role or descriptor.leaf_index != leafIndex(role) or
        descriptor.pair_index != 0)
    {
        return error.NonCanonicalLeafPosition;
    }
    var sink = aggregation_hash.HashSink.init(declarationDomain(role));
    try sink.writeAll(shadow_commitment_profile);
    try aggregation_hash.writeU32(&sink, format_version);
    try aggregation_hash.writeU32(&sink, descriptor.leaf_index);
    try aggregation_hash.writeU32(&sink, descriptor.pair_index);
    try sink.writeAll(&.{@intFromEnum(descriptor.role)});
    try sink.writeAll(&.{descriptor.flags});
    try aggregation_hash.writeU16(&sink, descriptor.reserved);
    try sink.writeAll(&descriptor.job_digest);
    // `leaf_statement_digest` is intentionally omitted: this hash defines it.
    try sink.writeAll(&descriptor.leaf_air_artifact_digest);
    try sink.writeAll(&descriptor.preprocessed_root);
    try sink.writeAll(&descriptor.main_root);
    try sink.writeAll(&descriptor.guest_call_commitment);
    try aggregation_hash.writeU64(&sink, descriptor.guest_call_count);
    try sink.writeAll(&descriptor.proof_protocol_digest);
    try aggregation_hash.writeU16(&sink, descriptor.execution_profile_id);
    try aggregation_hash.writeU16(&sink, descriptor.relation_schema_version);
    try sink.writeAll(&descriptor.execution_semantic_digest);
    try sink.writeAll(&descriptor.relation_registry_digest);
    try aggregation_hash.writeU32(&sink, descriptor.relation_schema_id);
    try aggregation_hash.writeU16(&sink, descriptor.relation_arity);
    try aggregation_hash.writeU16(&sink, descriptor.reserved_tail);
    try writeComponent(&sink, component);
    return sink.finalize();
}

fn canonicalDescriptor(
    comptime role: aggregation_types.LeafRole,
    authority: RolePrepareAuthorityV1(role),
    preprocessed_root: Digest,
    main_root: Digest,
    guest_call_commitment: Digest,
    guest_call_count: u64,
) !aggregation_types.LeafDescriptorV1 {
    var descriptor = aggregation_types.LeafDescriptorV1{
        .leaf_index = leafIndex(role),
        .pair_index = 0,
        .role = role,
        .job_digest = authority.job_digest,
        .leaf_statement_digest = .{0} ** 32,
        .leaf_air_artifact_digest = authority.air_artifact_digest,
        .preprocessed_root = preprocessed_root,
        .main_root = main_root,
        .guest_call_commitment = guest_call_commitment,
        .guest_call_count = guest_call_count,
        .proof_protocol_digest = authority.accepted_protocol.proof_protocol_digest,
        .relation_registry_digest = authority.accepted_protocol.relation_registry_digest,
    };
    descriptor.leaf_statement_digest = try preSessionDeclarationDigest(
        role,
        descriptor,
        authority.component,
    );
    if (aggregation_hash.isZero(descriptor.leaf_statement_digest))
        return error.ZeroStatementDigest;
    return descriptor;
}

pub const RoleWorkProfileV1 = struct {
    n_rows: u32,
    domain_size: usize,
    selector_cells: usize,
    main_cells: usize,
    retained_cells: usize,
    retained_bytes: usize,
    construction_allocations: usize,
    retained_allocations: usize,
    hot_path_dynamic_dispatches: usize,
    construction_hash_pass_cells: usize,
    validation_hash_pass_cells: usize,
    validation_selector_scan_cells: usize,
    validation_total_read_cells: usize,
};

pub fn PreparedRoleLeafV1(
    comptime role: aggregation_types.LeafRole,
) type {
    return struct {
        const Self = @This();

        authority: RolePrepareAuthorityV1(role),
        selectors: OwnedSelectorsV1(role),
        main: MainOwnedV1(role),
        guest_call_commitment: Digest,
        guest_call_count: u64,
        descriptor: aggregation_types.LeafDescriptorV1,

        pub fn deinit(self: *Self) void {
            self.main.deinit();
            self.selectors.deinit();
            self.* = undefined;
        }

        /// Cold barrier admission re-hashes the retained component columns.
        /// Any shape, authority, call, declaration, or backing-data mutation
        /// therefore fails before the shared challenge is derived.
        pub fn validate(self: *const Self) !void {
            const count_u32 = std.math.cast(u32, self.guest_call_count) orelse
                return error.CallCountOutOfRange;
            try aggregation_types.validateCallCount(self.guest_call_count);
            try self.authority.validate(count_u32);
            if (self.selectors.log_size != self.authority.component.log_size or
                self.selectors.n_rows != count_u32 or
                self.main.log_size != self.authority.component.log_size or
                self.main.n_rows != count_u32 or
                self.main.domain_size != self.selectors.domain_size)
            {
                return error.InvalidPreparedRoleShape;
            }
            const expected_preprocessed = try self.selectors.commitment();
            const expected_main = try mainCommitment(role, &self.main);
            const expected = try canonicalDescriptor(
                role,
                self.authority,
                expected_preprocessed,
                expected_main,
                self.guest_call_commitment,
                self.guest_call_count,
            );
            if (!std.meta.eql(self.descriptor, expected))
                return error.PreparedRoleMutated;
        }

        pub fn workProfile(self: *const Self) RoleWorkProfileV1 {
            const retained_cells = self.selectors.storage.len +
                self.main.storage.len;
            return .{
                .n_rows = self.main.n_rows,
                .domain_size = self.main.domain_size,
                .selector_cells = self.selectors.storage.len,
                .main_cells = self.main.storage.len,
                .retained_cells = retained_cells,
                .retained_bytes = retained_cells * @sizeOf(M31),
                .construction_allocations = role_prepare_allocation_count,
                .retained_allocations = role_prepare_allocation_count,
                .hot_path_dynamic_dispatches = 0,
                .construction_hash_pass_cells = retained_cells,
                .validation_hash_pass_cells = retained_cells,
                .validation_selector_scan_cells = self.selectors.storage.len,
                .validation_total_read_cells = retained_cells +
                    self.selectors.storage.len,
            };
        }
    };
}

pub const PreparedCallerLeafV1 = PreparedRoleLeafV1(.core_request);
pub const PreparedProviderLeafV1 = PreparedRoleLeafV1(.poseidon2_provider);

fn prepareRole(
    comptime role: aggregation_types.LeafRole,
    allocator: std.mem.Allocator,
    authority: RolePrepareAuthorityV1(role),
    core: *const base_statement.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    calls: *const call_buffer.Frozen,
    execution_rows: *const guest_runner.FrozenExecutionRows,
) !PreparedRoleLeafV1(role) {
    // Every semantic and construction check occurs before an allocation.
    const shadow_authority = try guest_main_trace.prepareShadowSplitMainV1(
        core,
        extension,
        calls,
        execution_rows,
    );
    const guest_call_count = std.math.cast(u64, shadow_authority.records.len) orelse
        return error.CallCountOutOfRange;
    const count_u32 = std.math.cast(u32, guest_call_count) orelse
        return error.CallCountOutOfRange;
    try authority.validate(count_u32);
    const call_commitment = try orderedCallCommitment(shadow_authority.records);

    var selectors = try OwnedSelectorsV1(role).init(
        allocator,
        authority.component,
    );
    errdefer selectors.deinit();
    var main = if (role == .core_request)
        try split_main_trace.generateCallerOwnedFromAuthority(
            allocator,
            shadow_authority,
        )
    else
        try split_main_trace.generateProviderOwnedFromAuthority(
            allocator,
            shadow_authority,
        );
    errdefer main.deinit();

    const preprocessed_root = try selectors.commitment();
    const main_root = try mainCommitment(role, &main);
    const descriptor = try canonicalDescriptor(
        role,
        authority,
        preprocessed_root,
        main_root,
        call_commitment,
        guest_call_count,
    );
    return .{
        .authority = authority,
        .selectors = selectors,
        .main = main,
        .guest_call_commitment = call_commitment,
        .guest_call_count = guest_call_count,
        .descriptor = descriptor,
    };
}

pub fn prepareCaller(
    allocator: std.mem.Allocator,
    authority: CallerPrepareAuthorityV1,
    core: *const base_statement.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    calls: *const call_buffer.Frozen,
    execution_rows: *const guest_runner.FrozenExecutionRows,
) !PreparedCallerLeafV1 {
    return prepareRole(
        .core_request,
        allocator,
        authority,
        core,
        extension,
        calls,
        execution_rows,
    );
}

pub fn prepareProvider(
    allocator: std.mem.Allocator,
    authority: ProviderPrepareAuthorityV1,
    core: *const base_statement.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    calls: *const call_buffer.Frozen,
    execution_rows: *const guest_runner.FrozenExecutionRows,
) !PreparedProviderLeafV1 {
    return prepareRole(
        .poseidon2_provider,
        allocator,
        authority,
        core,
        extension,
        calls,
        execution_rows,
    );
}

pub const BarrierWorkProfileV1 = struct {
    construction_allocations: usize,
    retained_allocations: usize,
    retained_bytes: usize,
    descriptor_count: usize,
    prepared_leaf_count: usize,
    challenge_derivations: usize,
};

/// Heap-pinned because `PreparedSessionV1.leaves` borrows the adjacent fixed
/// array. Construction validates both complete role states and all pair facts
/// before allocation; any later R-007 preparation error destroys the one
/// object and leaves both role owners untouched.
pub const ManifestBarrierV1 = struct {
    allocator: std.mem.Allocator,
    accepted_protocol: aggregation_types.AcceptedProtocolV1,
    descriptors: [2]aggregation_types.LeafDescriptorV1,
    leaves: [2]aggregation_manifest.PreparedLeafV1,
    session: aggregation_manifest.PreparedSessionV1,

    pub fn create(
        allocator: std.mem.Allocator,
        accepted_protocol: aggregation_types.AcceptedProtocolV1,
        caller: *const PreparedCallerLeafV1,
        provider: *const PreparedProviderLeafV1,
    ) !*ManifestBarrierV1 {
        try accepted_protocol.validate();
        try caller.validate();
        try provider.validate();
        try validatePair(accepted_protocol, caller, provider);

        const result = try allocator.create(ManifestBarrierV1);
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
        // Rebind explicitly in the final heap address. This remains correct
        // even if the compiler materialized the returned session temporarily.
        result.session.leaves = &result.leaves;
        return result;
    }

    pub fn deinit(self: *ManifestBarrierV1) void {
        const allocator = self.allocator;
        self.* = undefined;
        allocator.destroy(self);
    }

    pub fn callerStatement(
        self: *const ManifestBarrierV1,
        identities: *const split_leaf_statement.VerifierOwnedLeafIdentitiesV1,
    ) !split_leaf_statement.CallerLeafStatementV1 {
        return split_leaf_statement.CallerLeafStatementV1.init(
            &self.session,
            0,
            identities,
        );
    }

    pub fn providerStatement(
        self: *const ManifestBarrierV1,
        identities: *const split_leaf_statement.VerifierOwnedLeafIdentitiesV1,
    ) !split_leaf_statement.ProviderLeafStatementV1 {
        return split_leaf_statement.ProviderLeafStatementV1.init(
            &self.session,
            1,
            identities,
        );
    }

    pub fn workProfile(_: *const ManifestBarrierV1) BarrierWorkProfileV1 {
        return .{
            .construction_allocations = manifest_barrier_allocation_count,
            .retained_allocations = manifest_barrier_allocation_count,
            .retained_bytes = @sizeOf(ManifestBarrierV1),
            .descriptor_count = 2,
            .prepared_leaf_count = 2,
            .challenge_derivations = 1,
        };
    }
};

fn validatePair(
    accepted_protocol: aggregation_types.AcceptedProtocolV1,
    caller: *const PreparedCallerLeafV1,
    provider: *const PreparedProviderLeafV1,
) !void {
    if (!std.meta.eql(caller.authority.accepted_protocol, accepted_protocol) or
        !std.meta.eql(provider.authority.accepted_protocol, accepted_protocol))
    {
        return error.PairProtocolMismatch;
    }
    if (!aggregation_hash.eql(
        caller.descriptor.job_digest,
        provider.descriptor.job_digest,
    )) return error.PairJobMismatch;
    if (!aggregation_hash.eql(
        caller.guest_call_commitment,
        provider.guest_call_commitment,
    )) return error.PairCallCommitmentMismatch;
    if (caller.guest_call_count != provider.guest_call_count)
        return error.PairCallCountMismatch;
}

comptime {
    if (split_main_trace.caller_column_count != 286 or
        split_main_trace.provider_column_count != 445 or
        component_registry.preprocessed_columns != selector_column_count)
    {
        @compileError("R-008 leaf-prepare geometry drifted");
    }
}
