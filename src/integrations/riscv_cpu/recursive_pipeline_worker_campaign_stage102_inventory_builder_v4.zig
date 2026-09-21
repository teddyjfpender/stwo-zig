//! Seal-last owner for a fresh campaign Stage-102 inventory.
//!
//! The immutable replay session deliberately requires every role-0 output to
//! exist before installation. This sibling is the provider-compatible build
//! phase: it admits 0..runtime-count independently cold-opened Stage-102
//! publications, deep-owns every request projection, and places them in
//! heap-stable coordinate slots. `sealComplete` is the only transition to the
//! immutable session and fails atomically while any slot is absent.
//!
//! Arrival order is not authority. Parallel leaves may arrive out of order;
//! the authenticated campaign coordinate selects a unique slot and sealing
//! emits the canonical coordinate order. No builder, owned JSON tree, or
//! process-local admission has a durable codec.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const inventory =
    @import("recursive_pipeline_worker_campaign_stage102_inventory_v4.zig");
const inventory_opener =
    @import("recursive_pipeline_worker_campaign_real_leaf_inventory_opener_v4.zig");
const campaign_store =
    @import("recursive_campaign_node_artifact_store_v2.zig");
const campaign_cas =
    @import("recursive_pipeline_worker_campaign_cas_v2.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const REQUEST_PROJECTIONS_DEEP_OWNED = true;
pub const POINTER_STABLE_COORDINATE_SLOTS = true;
pub const OUT_OF_ORDER_ARRIVAL_CANONICALIZED = true;
pub const SEAL_COMPLETE_IS_ATOMIC = true;

pub const Admission = inventory.Admission;
pub const EntryV4 = inventory.EntryV4;
pub const FinalRemint = inventory.FinalRemint;
pub const Policy = inventory.Policy;

pub const Error = error{
    CampaignStage102BuilderClosedV4,
    CampaignStage102BuilderDuplicateV4,
    CampaignStage102BuilderIncompleteV4,
    CampaignStage102BuilderMismatchV4,
    CampaignStage102BuilderPublicationDriftV4,
};

const StateV4 = enum {
    building,
    sealed,
    destroyed,
};

/// `Authority` is the exact campaign role-0 backend authority. A Builder may
/// be installed through `campaign_session_provider_v4.ProviderFor` while the
/// Stage-102 worker is alive. The provider installation and every live worker
/// lease must be destroyed before `sealComplete` moves ownership into the
/// returned immutable session.
pub fn BuilderFor(comptime Authority: type) type {
    const ImmutableSession = inventory.SessionFor(Authority);

    return struct {
        pub const AuthorityV4 = Authority;
        pub const ImmutableSessionV4 = ImmutableSession;

        store: *artifact_store.Store,
        authority: *const Authority,
        policy: *const Policy,
        shared: *SharedV4,

        const Self = @This();

        const SharedV4 = struct {
            allocator: std.mem.Allocator,
            mutex: std.Thread.Mutex = .{},
            state: StateV4 = .building,
            adopted_count: usize = 0,
            slots: []?*OwnedEntryV4,
        };

        /// Heap-stable owner returned by the one-way seal transition. The
        /// session pointer may be installed in a replay/final worker and stays
        /// valid until that worker and all leases are destroyed, after which
        /// this owner may be deinitialized.
        pub const OwnedSealedSessionV4 = struct {
            shared: *SharedV4,
            entries: []EntryV4,
            session: *ImmutableSession,

            pub fn sessionView(
                self: *const OwnedSealedSessionV4,
            ) !*const ImmutableSession {
                self.shared.mutex.lock();
                defer self.shared.mutex.unlock();
                if (self.shared.state != .sealed)
                    return error.CampaignStage102BuilderClosedV4;
                return self.session;
            }

            pub fn validate(
                self: *const OwnedSealedSessionV4,
                scratch_allocator: std.mem.Allocator,
            ) !void {
                _ = try self.sessionView();
                try self.session.validate(scratch_allocator);
            }

            pub fn deinit(self: *OwnedSealedSessionV4) void {
                const shared = self.shared;
                shared.mutex.lock();
                std.debug.assert(shared.state == .sealed);
                shared.state = .destroyed;
                shared.mutex.unlock();

                shared.allocator.destroy(self.session);
                shared.allocator.free(self.entries);
                destroySlots(shared);
                self.* = undefined;
            }

            comptime {
                rejectCodec(OwnedSealedSessionV4);
            }
        };

        pub fn init(
            owner_allocator: std.mem.Allocator,
            scratch_allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            authority: *const Authority,
            policy: *const Policy,
        ) !Self {
            try validateBase(
                scratch_allocator,
                store,
                authority,
                policy,
            );
            const count = try expectedCount(authority);
            const slots = try owner_allocator.alloc(?*OwnedEntryV4, count);
            errdefer owner_allocator.free(slots);
            @memset(slots, null);
            const shared = try owner_allocator.create(SharedV4);
            shared.* = .{
                .allocator = owner_allocator,
                .slots = slots,
            };
            return .{
                .store = store,
                .authority = authority,
                .policy = policy,
                .shared = shared,
            };
        }

        /// Validates the admitted prefix without requiring completion. Every
        /// occupied slot is independently reopened and exact-checked.
        pub fn validate(
            self: *const Self,
            scratch_allocator: std.mem.Allocator,
        ) !void {
            try validateBase(
                scratch_allocator,
                self.store,
                self.authority,
                self.policy,
            );
            const shared = self.shared;
            shared.mutex.lock();
            defer shared.mutex.unlock();
            try requireBuilding(shared);
            if (shared.slots.len != try expectedCount(self.authority))
                return error.CampaignStage102BuilderMismatchV4;
            var observed_count: usize = 0;
            for (shared.slots, 0..) |maybe_entry, index| {
                const entry = maybe_entry orelse continue;
                observed_count += 1;
                try validateOwnedEntry(
                    scratch_allocator,
                    self.store,
                    self.authority,
                    self.policy,
                    entry,
                    index,
                );
                try rejectCollisionWithEarlier(shared.slots, index, entry);
            }
            if (observed_count != shared.adopted_count)
                return error.CampaignStage102BuilderMismatchV4;
        }

        pub fn authorityForCampaign(
            self: *const Self,
            namespace: artifact_store.Digest,
        ) !*const Authority {
            try validateNamespace(self.authority.final_remint, namespace);
            return self.authority;
        }

        /// Only an already-adopted, heap-stable row is visible. The caller
        /// must keep the builder/provider installed for the returned borrow.
        pub fn stage102AdmissionForOutput(
            self: *const Self,
            namespace: artifact_store.Digest,
            output_ref: artifact_store.BlobRefV1,
        ) !*const Admission {
            try validateNamespace(self.authority.final_remint, namespace);
            try campaign_cas.validate(output_ref, .recursion_node);
            const shared = self.shared;
            shared.mutex.lock();
            defer shared.mutex.unlock();
            try requireBuilding(shared);
            for (shared.slots) |maybe_entry| {
                const entry = maybe_entry orelse continue;
                if (artifact_store.BlobRefV1.eql(
                    entry.output_ref,
                    output_ref,
                )) return &entry.admission;
            }
            return error.CampaignStage102BuilderMismatchV4;
        }

        pub fn finalRemintForCampaign(
            self: *const Self,
            namespace: artifact_store.Digest,
        ) !*const FinalRemint {
            try validateNamespace(self.authority.final_remint, namespace);
            return self.authority.final_remint;
        }

        pub fn policyForExecution(
            self: *const Self,
            execution: artifact_store.ExecutionKeyV1,
        ) !Policy {
            try self.policy.validateAgainstExecution(execution);
            return self.policy.*;
        }

        /// Deep-adopts one already cold-opened and seal-last-published row.
        /// `scratch_allocator` belongs to the worker request and is never used
        /// for retained state; `shared.allocator` owns every stored byte.
        pub fn adoptStage102ColdPublication(
            self: *const Self,
            scratch_allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            output_ref: artifact_store.BlobRefV1,
            stage_manifest_ref: artifact_store.BlobRefV1,
            dependency_stage_manifest_refs: []const artifact_store.BlobRefV1,
        ) !void {
            try validateBase(
                scratch_allocator,
                self.store,
                self.authority,
                self.policy,
            );
            const index = try validateTransientPublication(
                scratch_allocator,
                self.store,
                self.authority,
                self.policy,
                node,
                semantic,
                execution,
                ordered_inputs,
                output_ref,
                stage_manifest_ref,
                dependency_stage_manifest_refs,
            );
            var ordered_copy = [_]artifact_store.InputRefV1{
                ordered_inputs[0],
            };
            const observed = Admission{
                .node = &node,
                .semantic = &semantic,
                .execution = &execution,
                .ordered_inputs = &ordered_copy,
                .stage_manifest_ref = stage_manifest_ref,
                .dependency_stage_manifest_ref = dependency_stage_manifest_refs[0],
            };

            {
                self.shared.mutex.lock();
                defer self.shared.mutex.unlock();
                try requireBuilding(self.shared);
                if (self.shared.slots[index]) |existing| {
                    const existing_view = existing.entry();
                    if (try inventory.exactEntryMatchV4(
                        scratch_allocator,
                        &existing_view,
                        output_ref,
                        observed,
                    )) return;
                    return error.CampaignStage102BuilderPublicationDriftV4;
                }
                try rejectCandidateCollision(
                    self.shared.slots,
                    index,
                    output_ref,
                    observed,
                );
            }

            const owned = try OwnedEntryV4.init(
                self.shared.allocator,
                scratch_allocator,
                node,
                semantic,
                execution,
                ordered_inputs[0],
                output_ref,
                stage_manifest_ref,
                dependency_stage_manifest_refs[0],
            );
            var keep_owned = false;
            defer if (!keep_owned) owned.deinit(self.shared.allocator);
            try validateOwnedEntry(
                scratch_allocator,
                self.store,
                self.authority,
                self.policy,
                owned,
                index,
            );

            self.shared.mutex.lock();
            defer self.shared.mutex.unlock();
            try requireBuilding(self.shared);
            if (self.shared.slots[index]) |existing| {
                const existing_view = existing.entry();
                const owned_view = owned.entry();
                if (try inventory.exactEntryMatchV4(
                    scratch_allocator,
                    &existing_view,
                    owned.output_ref,
                    owned_view.admission,
                )) return;
                return error.CampaignStage102BuilderPublicationDriftV4;
            }
            try rejectCandidateCollision(
                self.shared.slots,
                index,
                owned.output_ref,
                owned.admission,
            );
            self.shared.slots[index] = owned;
            self.shared.adopted_count += 1;
            keep_owned = true;
        }

        /// Atomically transfers a complete coordinate-ordered inventory into
        /// the existing immutable SessionFor. On any error the builder remains
        /// open and owns the unchanged admitted prefix.
        pub fn sealComplete(
            self: *Self,
            scratch_allocator: std.mem.Allocator,
        ) !OwnedSealedSessionV4 {
            try validateBase(
                scratch_allocator,
                self.store,
                self.authority,
                self.policy,
            );
            const shared = self.shared;
            var sealed: OwnedSealedSessionV4 = undefined;
            {
                shared.mutex.lock();
                defer shared.mutex.unlock();
                try requireBuilding(shared);
                if (shared.adopted_count != shared.slots.len)
                    return error.CampaignStage102BuilderIncompleteV4;
                for (shared.slots, 0..) |maybe_entry, index| {
                    const entry = maybe_entry orelse
                        return error.CampaignStage102BuilderIncompleteV4;
                    try validateOwnedEntry(
                        scratch_allocator,
                        self.store,
                        self.authority,
                        self.policy,
                        entry,
                        index,
                    );
                    try rejectCollisionWithEarlier(
                        shared.slots,
                        index,
                        entry,
                    );
                }

                const entries = try shared.allocator.alloc(
                    EntryV4,
                    shared.slots.len,
                );
                errdefer shared.allocator.free(entries);
                for (shared.slots, entries) |maybe_entry, *entry| {
                    entry.* = (maybe_entry orelse
                        return error.CampaignStage102BuilderIncompleteV4).entry();
                }
                const session = try shared.allocator.create(ImmutableSession);
                errdefer shared.allocator.destroy(session);
                session.* = .{
                    .store = self.store,
                    .authority = self.authority,
                    .entries = entries,
                    .policy = self.policy,
                };
                try session.validate(scratch_allocator);
                sealed = .{
                    .shared = shared,
                    .entries = entries,
                    .session = session,
                };
                shared.state = .sealed;
            }
            self.* = undefined;
            return sealed;
        }

        pub fn adoptedCount(self: *const Self) !usize {
            self.shared.mutex.lock();
            defer self.shared.mutex.unlock();
            try requireBuilding(self.shared);
            return self.shared.adopted_count;
        }

        pub fn deinit(self: *Self) void {
            const shared = self.shared;
            shared.mutex.lock();
            std.debug.assert(shared.state == .building);
            shared.state = .destroyed;
            shared.mutex.unlock();
            destroySlots(shared);
            self.* = undefined;
        }

        comptime {
            rejectCodec(Self);
        }
    };
}

/// Heap-stable deep owner for one transient worker request projection.
const OwnedEntryV4 = struct {
    output_ref: artifact_store.BlobRefV1,
    stage_manifest_ref: artifact_store.BlobRefV1,
    dependency_stage_manifest_ref: artifact_store.BlobRefV1,
    node_id: []u8,
    adapter: []u8,
    dependencies: []protocol.Dependency,
    external_inputs: []artifact_store.InputRefV1,
    semantic_options: std.json.Parsed(protocol.Json),
    node: protocol.Node,
    semantic: artifact_store.OwnedSemanticKeyV1,
    execution: artifact_store.ExecutionKeyV1,
    ordered_inputs: [inventory_opener.STAGE102_DEPENDENCY_COUNT]artifact_store.InputRefV1,
    admission: Admission,

    fn init(
        owner_allocator: std.mem.Allocator,
        scratch_allocator: std.mem.Allocator,
        source_node: protocol.Node,
        source_semantic: artifact_store.SemanticKeyV1,
        execution: artifact_store.ExecutionKeyV1,
        input: artifact_store.InputRefV1,
        output_ref: artifact_store.BlobRefV1,
        stage_manifest_ref: artifact_store.BlobRefV1,
        dependency_stage_manifest_ref: artifact_store.BlobRefV1,
    ) !*OwnedEntryV4 {
        const node_id = try owner_allocator.dupe(u8, source_node.node_id);
        errdefer owner_allocator.free(node_id);
        const adapter = try owner_allocator.dupe(u8, source_node.adapter);
        errdefer owner_allocator.free(adapter);
        const dependencies = try owner_allocator.alloc(
            protocol.Dependency,
            source_node.dependencies.len,
        );
        var dependency_count: usize = 0;
        errdefer {
            for (dependencies[0..dependency_count]) |dependency|
                owner_allocator.free(dependency.node_id);
            owner_allocator.free(dependencies);
        }
        for (source_node.dependencies, dependencies) |source, *destination| {
            destination.* = .{
                .node_id = try owner_allocator.dupe(u8, source.node_id),
                .role = source.role,
                .ordinal = source.ordinal,
            };
            dependency_count += 1;
        }
        const external_inputs = try owner_allocator.dupe(
            artifact_store.InputRefV1,
            source_node.external_inputs,
        );
        errdefer owner_allocator.free(external_inputs);

        const options_bytes = try protocol.canonicalAlloc(
            scratch_allocator,
            source_node.semantic_options,
            false,
        );
        defer scratch_allocator.free(options_bytes);
        var semantic_options = try std.json.parseFromSlice(
            protocol.Json,
            owner_allocator,
            options_bytes,
            .{ .parse_numbers = true },
        );
        errdefer semantic_options.deinit();

        const semantic_bytes = try source_semantic.canonicalBytesAlloc(
            scratch_allocator,
        );
        defer scratch_allocator.free(semantic_bytes);
        var semantic = try artifact_store.decodeSemanticKeyAlloc(
            owner_allocator,
            semantic_bytes,
        );
        errdefer semantic.deinit(owner_allocator);

        const owned = try owner_allocator.create(OwnedEntryV4);
        owned.* = .{
            .output_ref = output_ref,
            .stage_manifest_ref = stage_manifest_ref,
            .dependency_stage_manifest_ref = dependency_stage_manifest_ref,
            .node_id = node_id,
            .adapter = adapter,
            .dependencies = dependencies,
            .external_inputs = external_inputs,
            .semantic_options = semantic_options,
            .node = undefined,
            .semantic = semantic,
            .execution = execution,
            .ordered_inputs = .{input},
            .admission = undefined,
        };
        owned.node = .{
            .node_id = owned.node_id,
            .stage_kind = source_node.stage_kind,
            .stage_schema_version = source_node.stage_schema_version,
            .adapter = owned.adapter,
            .dependencies = owned.dependencies,
            .external_inputs = owned.external_inputs,
            .local_task_identity_sha256 = source_node.local_task_identity_sha256,
            .semantic_authorities = source_node.semantic_authorities,
            .semantic_options = owned.semantic_options.value,
            .cpu_tokens = source_node.cpu_tokens,
            .rss_tokens = source_node.rss_tokens,
            .output_kind = source_node.output_kind,
            .output_schema_version = source_node.output_schema_version,
        };
        owned.admission = .{
            .node = &owned.node,
            .semantic = &owned.semantic.value,
            .execution = &owned.execution,
            .ordered_inputs = &owned.ordered_inputs,
            .stage_manifest_ref = owned.stage_manifest_ref,
            .dependency_stage_manifest_ref = owned.dependency_stage_manifest_ref,
        };
        return owned;
    }

    fn entry(self: *const OwnedEntryV4) EntryV4 {
        return .{
            .output_ref = self.output_ref,
            .admission = self.admission,
        };
    }

    fn deinit(
        self: *OwnedEntryV4,
        owner_allocator: std.mem.Allocator,
    ) void {
        self.semantic.deinit(owner_allocator);
        self.semantic_options.deinit();
        owner_allocator.free(self.external_inputs);
        for (self.dependencies) |dependency|
            owner_allocator.free(dependency.node_id);
        owner_allocator.free(self.dependencies);
        owner_allocator.free(self.adapter);
        owner_allocator.free(self.node_id);
        owner_allocator.destroy(self);
    }
};

fn validateBase(
    scratch_allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    authority: anytype,
    policy: *const Policy,
) !void {
    _ = store;
    try policy.validate();
    const final_remint = authority.final_remint;
    const namespace = final_remint.shape.campaign_namespace_sha256;
    try authority.validate(scratch_allocator, namespace);
    try final_remint.validateAgainstCampaign(namespace);
    if (!std.mem.eql(
        u8,
        &authority.padding_target.shape.identity_sha256,
        &final_remint.shape.identity_sha256,
    ) or authority.stage101_admissions.len != try expectedCount(authority)) {
        return error.CampaignStage102BuilderMismatchV4;
    }
}

fn expectedCount(authority: anytype) !usize {
    return std.math.cast(
        usize,
        authority.final_remint.shape.real_leaf_count,
    ) orelse return error.CampaignStage102BuilderMismatchV4;
}

fn validateNamespace(
    final_remint: *const FinalRemint,
    namespace: artifact_store.Digest,
) !void {
    try final_remint.validateAgainstCampaign(namespace);
    if (!std.mem.eql(
        u8,
        &namespace,
        &final_remint.shape.campaign_namespace_sha256,
    )) return error.CampaignStage102BuilderMismatchV4;
}

fn validateTransientPublication(
    scratch_allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    authority: anytype,
    policy: *const Policy,
    node: protocol.Node,
    semantic: artifact_store.SemanticKeyV1,
    execution: artifact_store.ExecutionKeyV1,
    ordered_inputs: []const artifact_store.InputRefV1,
    output_ref: artifact_store.BlobRefV1,
    stage_manifest_ref: artifact_store.BlobRefV1,
    dependency_stage_manifest_refs: []const artifact_store.BlobRefV1,
) !usize {
    if (ordered_inputs.len != inventory_opener.STAGE102_DEPENDENCY_COUNT or
        dependency_stage_manifest_refs.len !=
            inventory_opener.STAGE102_DEPENDENCY_COUNT)
    {
        return error.CampaignStage102BuilderMismatchV4;
    }
    try policy.validateAgainstExecution(execution);
    if (node.cpu_tokens != @as(u64, policy.cpu_tokens_per_node) or
        node.rss_tokens != policy.rss_bytes_per_node)
    {
        return error.CampaignStage102BuilderMismatchV4;
    }
    try campaign_cas.validate(output_ref, .recursion_node);
    try campaign_cas.validate(stage_manifest_ref, .stage_manifest);
    try campaign_cas.validate(
        dependency_stage_manifest_refs[0],
        .stage_manifest,
    );
    const shape = authority.final_remint.shape;
    const artifact = try campaign_store.coldOpenRecursiveNodeTransport(
        store,
        shape,
        output_ref,
    );
    if (artifact.stage_kind != .leaf_wrapper or
        artifact.node_kind != .real or artifact.child_count != 1 or
        artifact.coordinate.height != 0)
    {
        return error.CampaignStage102BuilderMismatchV4;
    }
    const index = std.math.cast(
        usize,
        artifact.coordinate.index,
    ) orelse return error.CampaignStage102BuilderMismatchV4;
    if (index >= try expectedCount(authority))
        return error.CampaignStage102BuilderMismatchV4;
    var ordered_copy = [_]artifact_store.InputRefV1{ordered_inputs[0]};
    const observed = Admission{
        .node = &node,
        .semantic = &semantic,
        .execution = &execution,
        .ordered_inputs = &ordered_copy,
        .stage_manifest_ref = stage_manifest_ref,
        .dependency_stage_manifest_ref = dependency_stage_manifest_refs[0],
    };
    try observed.validate(
        scratch_allocator,
        store,
        authority,
        authority.final_remint,
        output_ref,
        &artifact,
    );
    return index;
}

fn validateOwnedEntry(
    scratch_allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    authority: anytype,
    policy: *const Policy,
    entry: *const OwnedEntryV4,
    index: usize,
) !void {
    try policy.validateAgainstExecution(entry.execution);
    if (entry.node.cpu_tokens != @as(u64, policy.cpu_tokens_per_node) or
        entry.node.rss_tokens != policy.rss_bytes_per_node)
    {
        return error.CampaignStage102BuilderMismatchV4;
    }
    try campaign_cas.validate(entry.output_ref, .recursion_node);
    const artifact = try campaign_store.coldOpenRecursiveNodeTransport(
        store,
        authority.final_remint.shape,
        entry.output_ref,
    );
    if (artifact.stage_kind != .leaf_wrapper or
        artifact.node_kind != .real or artifact.child_count != 1 or
        artifact.coordinate.height != 0 or
        artifact.coordinate.index != @as(u32, @intCast(index)))
    {
        return error.CampaignStage102BuilderMismatchV4;
    }
    try entry.admission.validate(
        scratch_allocator,
        store,
        authority,
        authority.final_remint,
        entry.output_ref,
        &artifact,
    );
}

fn rejectCandidateCollision(
    slots: []const ?*OwnedEntryV4,
    candidate_index: usize,
    output_ref: artifact_store.BlobRefV1,
    admission: Admission,
) !void {
    for (slots, 0..) |maybe_entry, index| {
        if (index == candidate_index) continue;
        const entry = maybe_entry orelse continue;
        if (artifact_store.BlobRefV1.eql(entry.output_ref, output_ref) or
            artifact_store.BlobRefV1.eql(
                entry.stage_manifest_ref,
                admission.stage_manifest_ref,
            ) or artifact_store.BlobRefV1.eql(
            entry.dependency_stage_manifest_ref,
            admission.dependency_stage_manifest_ref,
        ) or std.mem.eql(
            u8,
            &entry.semantic.value.identity,
            &admission.semantic.identity,
        ) or std.mem.eql(
            u8,
            &entry.execution.identity,
            &admission.execution.identity,
        ) or std.mem.eql(
            u8,
            &entry.node.local_task_identity_sha256,
            &admission.node.local_task_identity_sha256,
        ) or std.mem.eql(u8, entry.node.node_id, admission.node.node_id)) {
            return error.CampaignStage102BuilderDuplicateV4;
        }
    }
}

fn rejectCollisionWithEarlier(
    slots: []const ?*OwnedEntryV4,
    index: usize,
    entry: *const OwnedEntryV4,
) !void {
    const view = entry.entry();
    try rejectCandidateCollision(
        slots[0..index],
        index,
        entry.output_ref,
        view.admission,
    );
}

fn requireBuilding(shared: anytype) !void {
    if (shared.state != .building)
        return error.CampaignStage102BuilderClosedV4;
}

fn destroySlots(shared: anytype) void {
    for (shared.slots) |maybe_entry| if (maybe_entry) |entry|
        entry.deinit(shared.allocator);
    shared.allocator.free(shared.slots);
    shared.allocator.destroy(shared);
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("campaign Stage102 inventory builder gained a codec");
}

pub const testing = struct {
    pub const OwnedEntry = OwnedEntryV4;

    pub fn deepOwnEntry(
        owner_allocator: std.mem.Allocator,
        scratch_allocator: std.mem.Allocator,
        output_ref: artifact_store.BlobRefV1,
        admission: Admission,
    ) !*OwnedEntryV4 {
        return OwnedEntryV4.init(
            owner_allocator,
            scratch_allocator,
            admission.node.*,
            admission.semantic.*,
            admission.execution.*,
            admission.ordered_inputs[0],
            output_ref,
            admission.stage_manifest_ref,
            admission.dependency_stage_manifest_ref,
        );
    }

    pub fn entry(value: *const OwnedEntryV4) EntryV4 {
        return value.entry();
    }

    pub fn deinitEntry(
        value: *OwnedEntryV4,
        owner_allocator: std.mem.Allocator,
    ) void {
        value.deinit(owner_allocator);
    }
};

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or
        !REQUEST_PROJECTIONS_DEEP_OWNED or
        !POINTER_STABLE_COORDINATE_SLOTS or
        !OUT_OF_ORDER_ARRIVAL_CANONICALIZED or
        !SEAL_COMPLETE_IS_ATOMIC)
    {
        @compileError("campaign Stage102 inventory builder contract drifted");
    }
    rejectCodec(OwnedEntryV4);
}
