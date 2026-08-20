//! Internal shard of binary_fri_outer_bundle.zig; use the public facade.

const dependency_0 = @import("binary_fri_outer_bundle_adapters_for_manifest.zig");
const dependency_2 = @import("binary_fri_outer_bundle_bind_owned_columns.zig");

const std = dependency_0.std;
const component_init = dependency_0.component_init;
const bundle_init = dependency_0.bundle_init;
const main_fill = dependency_0.main_fill;
const generated_audit = dependency_0.generated_audit;
const M31 = dependency_0.M31;
const source_mod = dependency_0.source_mod;
const fixed_wire = dependency_0.fixed_wire;
const digest = dependency_0.digest;
const logup = dependency_0.logup;
const poseidon_air = dependency_0.poseidon_air;
const poseidon_authority_mod = dependency_0.poseidon_authority_mod;
const poseidon_identity = dependency_0.poseidon_identity;
const relation_interaction = dependency_0.relation_interaction;
const shared_provider = dependency_0.shared_provider;
const universal = dependency_0.universal;
const AdaptersForManifest = dependency_0.AdaptersForManifest;
const GENERATED_FORMAT_VERSION = dependency_0.GENERATED_FORMAT_VERSION;
const ProviderCustody = dependency_0.ProviderCustody;
const ROW_COUNT = dependency_0.ROW_COUNT;
const PREPROCESSED_COLUMNS_PER_ROW = dependency_0.PREPROCESSED_COLUMNS_PER_ROW;
const MAIN_COLUMNS_PER_ROW = dependency_0.MAIN_COLUMNS_PER_ROW;
const INTERACTION_COLUMNS_PER_ROW = dependency_0.INTERACTION_COLUMNS_PER_ROW;
const PREPROCESSED_COLUMN_COUNT = dependency_0.PREPROCESSED_COLUMN_COUNT;
const MAIN_COLUMN_COUNT = dependency_0.MAIN_COLUMN_COUNT;
const INTERACTION_COLUMN_COUNT = dependency_0.INTERACTION_COLUMN_COUNT;
const Claims = dependency_0.Claims;
const DomainAudits = dependency_0.DomainAudits;
const GeneratedInteractionsV1 = dependency_0.GeneratedInteractionsV1;
const AuditedInteractionsV1 = dependency_0.AuditedInteractionsV1;
const ComponentsForManifest = dependency_0.ComponentsForManifest;
const generatedIdentity = dependency_0.generatedIdentity;
const auditedIdentity = dependency_0.auditedIdentity;
const bindOwnedColumns = dependency_2.bindOwnedColumns;
const preflightFreshColumns = dependency_2.preflightFreshColumns;
const clearColumns = dependency_2.clearColumns;
const parametersFromRows = dependency_2.parametersFromRows;
const providerScratchByteCount = dependency_2.providerScratchByteCount;
const traceLogSize = dependency_2.traceLogSize;
const committedRow = dependency_2.committedRow;
const validateClaims = dependency_2.validateClaims;
const validateAudits = dependency_2.validateAudits;
const bundleIdentity = dependency_2.bundleIdentity;
const allZero = dependency_2.allZero;
const poseidonCallSlicesEqual = dependency_2.poseidonCallSlicesEqual;

/// Schedule-parametric form used by authenticated proof kinds whose prefix
/// call ranges differ from frozen SegmentV2. The schedule contract is resolved
/// entirely at comptime, preserving the same direct hot loops as V2.
pub fn BundleForSourceScheduleAndManifest(
    comptime dimensions: fixed_wire.Dimensions,
    comptime Source: type,
    comptime ScheduleContract: type,
    comptime manifest_contract: type,
) type {
    dimensions.validate();
    const Adapters = AdaptersForManifest(manifest_contract);
    const ManifestComponents = ComponentsForManifest(manifest_contract);
    const SharedLayout = ScheduleContract.Layout;
    const SharedCall = ScheduleContract.Call;

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        source: *const Source,
        source_authority: Source.PreparedAuthority,
        composition_workspace: Source.CompositionWorkspace,
        fri_workspace: Source.Workspace,
        arithmetic_workspace: Source.ArithmeticWorkspace,
        merkle_workspace: Source.MerkleWorkspace,
        relation_rows: Source.RelationRows,
        interaction_workspace: Source.RelationInteractionWorkspace,
        poseidon_authority: poseidon_authority_mod.Authority,
        poseidon_program_id: poseidon_identity.ProgramIdentity,
        provider_scratch: []align(@alignOf(logup.RowPair)) u8,
        provider_custody: ProviderCustody,
        provider_log_size: u32,
        shared_layout: ?SharedLayout,
        shared_calls: []const SharedCall,
        owned_shared_calls: []SharedCall,
        shared_boundary_call_count: u32,
        shared_outputs: [][poseidon_air.WIDTH]u32,
        shared_outputs_ready: bool,
        main_prepared: bool,
        authority_seal: digest.Digest,

        pub fn init(
            allocator: std.mem.Allocator,
            source: *const Source,
        ) !Self {
            return bundle_init.init(
                allocator,
                source,
                Self,
                Source,
                providerScratchByteCount,
                bundleIdentity,
                validate,
            );
        }

        /// Validate and select the complete V2 row-34 provider schedule.
        pub fn initWithSharedSchedule(
            allocator: std.mem.Allocator,
            source: *const Source,
            layout: *const SharedLayout,
            calls: []const SharedCall,
        ) !Self {
            try layout.validate(calls);
            if (!layout.call_set_complete or
                !layout.verifier_core_range_populated)
            {
                return error.ProviderIdentityMismatch;
            }
            const provider_log_size = try traceLogSize(calls.len);
            var result = try Self.init(allocator, source);
            const scheduled_core_count = layout.verifier_core.count() catch {
                result.deinit();
                return error.ProviderIdentityMismatch;
            };
            // A binary parent and a native segment leaf share the AIR rows but
            // not their witness schedule. Reject that profile confusion before
            // allocating the complete-provider scratch or touching Tree 1.
            if (scheduled_core_count != result.merkle_workspace.poseidon_calls.len) {
                result.deinit();
                return error.ProviderIdentityMismatch;
            }
            const scratch_len = providerScratchByteCount(provider_log_size) catch |err| {
                result.deinit();
                return err;
            };
            const provider_scratch = allocator.alignedAlloc(
                u8,
                .fromByteUnits(@alignOf(logup.RowPair)),
                scratch_len,
            ) catch |err| {
                result.deinit();
                return err;
            };
            const shared_outputs = allocator.alloc(
                [poseidon_air.WIDTH]u32,
                calls.len,
            ) catch |err| {
                allocator.free(provider_scratch);
                result.deinit();
                return err;
            };
            allocator.free(result.provider_scratch);
            result.provider_scratch = provider_scratch;
            result.provider_custody = .complete_shared_schedule_v2;
            result.provider_log_size = provider_log_size;
            result.shared_layout = layout.*;
            result.shared_calls = calls;
            result.shared_boundary_call_count = layout.boundary_prefix_call_count;
            result.shared_outputs = shared_outputs;
            result.shared_outputs_ready = false;
            result.authority_seal = bundleIdentity(&result);
            result.validate() catch |err| {
                result.deinit();
                return err;
            };
            return result;
        }

        /// Install an authenticated prefix; Tree 1 seals its verifier suffix.
        pub fn initWithBoundarySchedule(
            allocator: std.mem.Allocator,
            source: *const Source,
            layout: *const SharedLayout,
            boundary_calls: []const SharedCall,
        ) !Self {
            try layout.validate(boundary_calls);
            if (layout.call_set_complete or
                layout.verifier_core_range_populated or
                layout.boundary_prefix_call_count != boundary_calls.len)
            {
                return error.ProviderIdentityMismatch;
            }
            var result = try Self.init(allocator, source);
            const core_count = result.merkle_workspace.poseidon_calls.len;
            if (core_count == 0) {
                result.deinit();
                return error.ProviderIdentityMismatch;
            }
            const total = std.math.add(
                usize,
                boundary_calls.len,
                core_count,
            ) catch {
                result.deinit();
                return error.ArithmeticOverflow;
            };
            const provider_log_size = traceLogSize(total) catch |err| {
                result.deinit();
                return err;
            };
            const calls = allocator.alloc(SharedCall, total) catch |err| {
                result.deinit();
                return err;
            };
            @memcpy(calls[0..boundary_calls.len], boundary_calls);
            @memset(std.mem.sliceAsBytes(calls[boundary_calls.len..]), 0);
            const scratch_len = providerScratchByteCount(provider_log_size) catch |err| {
                allocator.free(calls);
                result.deinit();
                return err;
            };
            const provider_scratch = allocator.alignedAlloc(
                u8,
                .fromByteUnits(@alignOf(logup.RowPair)),
                scratch_len,
            ) catch |err| {
                allocator.free(calls);
                result.deinit();
                return err;
            };
            const shared_outputs = allocator.alloc(
                [poseidon_air.WIDTH]u32,
                total,
            ) catch |err| {
                allocator.free(provider_scratch);
                allocator.free(calls);
                result.deinit();
                return err;
            };
            allocator.free(result.provider_scratch);
            result.provider_scratch = provider_scratch;
            result.provider_custody = .pending_shared_schedule;
            result.provider_log_size = provider_log_size;
            result.shared_layout = layout.*;
            result.shared_calls = calls[0..boundary_calls.len];
            result.owned_shared_calls = calls;
            result.shared_boundary_call_count = @intCast(boundary_calls.len);
            result.shared_outputs = shared_outputs;
            result.shared_outputs_ready = false;
            result.authority_seal = bundleIdentity(&result);
            result.validate() catch |err| {
                result.deinit();
                return err;
            };
            return result;
        }

        /// Frozen spelling retained byte-for-byte at existing call sites.
        pub fn initWithSharedScheduleV2(
            allocator: std.mem.Allocator,
            source: *const Source,
            layout: *const SharedLayout,
            calls: []const SharedCall,
        ) !Self {
            return initWithSharedSchedule(allocator, source, layout, calls);
        }

        pub fn deinit(self: *Self) void {
            if (self.shared_outputs.len != 0)
                self.allocator.free(self.shared_outputs);
            if (self.owned_shared_calls.len != 0)
                self.allocator.free(self.owned_shared_calls);
            self.allocator.free(self.provider_scratch);
            self.poseidon_authority.deinit();
            self.interaction_workspace.deinit();
            self.relation_rows.deinit();
            self.merkle_workspace.deinit();
            self.arithmetic_workspace.deinit();
            self.fri_workspace.deinit();
            self.composition_workspace.deinit();
            self.* = undefined;
        }

        /// Constant-size validation for immutable-capability hot tree writers.
        pub fn validate(self: *const Self) !void {
            try self.source_authority.validateFor(self.source);
            try self.composition_workspace.validateFor(self.source);
            try self.fri_workspace.validateFor(self.source);
            try self.arithmetic_workspace.validateFor(self.source);
            if (!self.poseidon_program_id.isCanonical() or
                !std.meta.eql(
                    self.poseidon_program_id,
                    self.poseidon_authority.program_identity,
                ) or self.provider_scratch.len != try providerScratchByteCount(
                self.provider_log_size,
            ) or !std.mem.eql(
                u8,
                &self.authority_seal,
                &bundleIdentity(self),
            )) return error.BundleIdentityMismatch;
            switch (self.provider_custody) {
                .local_core => if (self.shared_layout != null or
                    self.shared_calls.len != 0 or self.shared_outputs.len != 0 or
                    self.shared_outputs_ready or self.provider_log_size !=
                    self.merkle_workspace.provider_log_size)
                {
                    return error.ProviderIdentityMismatch;
                },
                .complete_shared_schedule_v2 => {
                    const layout = self.shared_layout orelse
                        return error.ProviderIdentityMismatch;
                    layout.validateReceipt() catch
                        return error.ProviderIdentityMismatch;
                    if (!layout.call_set_complete or
                        !layout.verifier_core_range_populated or
                        self.shared_calls.len != layout.total_call_count or
                        self.shared_outputs.len != self.shared_calls.len or
                        self.provider_log_size != try traceLogSize(
                            self.shared_calls.len,
                        ) or self.shared_outputs_ready != self.main_prepared)
                    {
                        return error.ProviderIdentityMismatch;
                    }
                },
                .pending_shared_schedule => {
                    const layout = self.shared_layout orelse
                        return error.ProviderIdentityMismatch;
                    layout.validate(self.shared_calls) catch
                        return error.ProviderIdentityMismatch;
                    if (layout.call_set_complete or
                        layout.verifier_core_range_populated or
                        self.shared_boundary_call_count != self.shared_calls.len or
                        self.owned_shared_calls.len <= self.shared_calls.len or
                        self.shared_calls.ptr != self.owned_shared_calls.ptr or
                        self.shared_outputs.len != self.owned_shared_calls.len or
                        self.provider_log_size != try traceLogSize(
                            self.owned_shared_calls.len,
                        ) or self.shared_outputs_ready or self.main_prepared)
                    {
                        return error.ProviderIdentityMismatch;
                    }
                },
            }
            if (self.main_prepared) {
                _ = try self.source.merklePoseidonCallsPrepared(
                    &self.source_authority,
                    &self.fri_workspace,
                    &self.merkle_workspace,
                );
                _ = try self.source.retainedRelationRowsPrepared(
                    &self.source_authority,
                    &self.relation_rows,
                );
                try self.interaction_workspace.validateFor(
                    self.source,
                    &self.relation_rows,
                );
            }
        }

        /// Full cold revalidation of every borrowed graph, capture, schedule,
        /// and seal. This is intentionally absent from repeated fill/receipt
        /// validation; it is the explicit boundary for hostile backing data.
        pub fn validateAgainstAuthority(self: *const Self) !void {
            try self.source.validateAgainstAuthority();
            if (self.shared_layout) |layout|
                layout.validate(self.shared_calls) catch
                    return error.ProviderIdentityMismatch;
            try self.validate();
        }

        fn bundleLogSizes(self: *const Self) [ROW_COUNT]u32 {
            var result = self.source_authority.bundle_log_sizes;
            result[ROW_COUNT - 1] = self.provider_log_size;
            return result;
        }

        pub fn componentLogSizes(self: *const Self) ![ROW_COUNT]u32 {
            try self.validate();
            return self.bundleLogSizes();
        }

        pub fn providerCustody(self: *const Self) ProviderCustody {
            return self.provider_custody;
        }

        pub fn sharedScheduleReceipt(
            self: *const Self,
        ) ?SharedLayout {
            return self.shared_layout;
        }

        pub fn verifierCoreCallsPrepared(
            self: *const Self,
        ) ![]const poseidon_air.Call {
            try self.requirePrepared();
            return self.source.merklePoseidonCallsPrepared(
                &self.source_authority,
                &self.fri_workspace,
                &self.merkle_workspace,
            );
        }

        pub fn completeProviderCallsPrepared(
            self: *const Self,
        ) ![]const poseidon_air.Call {
            try self.requirePrepared();
            return self.providerCallsPrepared();
        }

        fn providerBatchId(self: *const Self) digest.Digest {
            return if (self.shared_layout) |layout|
                layout.identity
            else
                self.merkle_workspace.authority_digest;
        }

        pub fn providerCallCount(self: *const Self) usize {
            return switch (self.provider_custody) {
                .local_core => self.merkle_workspace.poseidon_calls.len,
                .complete_shared_schedule_v2 => self.shared_calls.len,
                .pending_shared_schedule => self.owned_shared_calls.len,
            };
        }

        fn providerCallsPrepared(
            self: *const Self,
        ) ![]const poseidon_air.Call {
            const core_calls = try self.source.merklePoseidonCallsPrepared(
                &self.source_authority,
                &self.fri_workspace,
                &self.merkle_workspace,
            );
            if (self.provider_custody == .local_core) return core_calls;
            if (self.provider_custody == .pending_shared_schedule)
                return error.RowsNotPrepared;
            const layout = self.shared_layout orelse
                return error.ProviderIdentityMismatch;
            layout.validate(self.shared_calls) catch
                return error.ProviderIdentityMismatch;
            const start: usize = layout.verifier_core.start;
            const end: usize = layout.verifier_core.end;
            if (end < start or end > self.shared_calls.len or
                !poseidonCallSlicesEqual(
                    core_calls,
                    self.shared_calls[start..end],
                ))
            {
                return error.ProviderIdentityMismatch;
            }
            return self.shared_calls;
        }

        fn providerOutputsPrepared(
            self: *const Self,
        ) ![]const [poseidon_air.WIDTH]u32 {
            if (self.provider_custody == .local_core) {
                return self.source.merklePoseidonOutputsPrepared(
                    &self.source_authority,
                    &self.fri_workspace,
                    &self.merkle_workspace,
                );
            }
            if (!self.shared_outputs_ready or
                self.shared_outputs.len != self.shared_calls.len)
            {
                return error.RowsNotPrepared;
            }
            return self.shared_outputs;
        }

        fn captureSharedProviderOutputs(
            self: *Self,
            columns: *const [poseidon_air.N_MAIN_COLUMNS][]M31,
        ) !void {
            if (self.provider_custody != .complete_shared_schedule_v2) return;
            if (self.shared_outputs_ready or
                self.shared_outputs.len != self.shared_calls.len)
            {
                return error.ProviderIdentityMismatch;
            }
            for (self.shared_outputs, 0..) |*output, logical_row| {
                const committed = committedRow(logical_row, self.provider_log_size);
                if (!columns.*[0][committed].eql(M31.one()))
                    return error.ProviderIdentityMismatch;
                for (output, 0..) |*word, lane| word.* = columns.*[
                    shared_provider.POSEIDON_OUTPUT_COLUMN_START + lane
                ][committed].toU32();
            }
            self.shared_outputs_ready = true;
        }

        fn finalizePendingSharedSchedule(
            self: *Self,
            core_calls: []const SharedCall,
        ) !void {
            if (self.provider_custody != .pending_shared_schedule) return;
            const boundary = self.shared_layout orelse
                return error.ProviderIdentityMismatch;
            try boundary.validate(self.shared_calls);
            const prefix_count: usize = self.shared_boundary_call_count;
            if (prefix_count != self.shared_calls.len or
                self.owned_shared_calls.len - prefix_count != core_calls.len)
            {
                return error.ProviderIdentityMismatch;
            }
            @memcpy(self.owned_shared_calls[prefix_count..], core_calls);
            const complete = try SharedLayout.initComplete(
                try boundary.transcript.count(),
                try boundary.statement_authority.count(),
                core_calls.len,
                self.owned_shared_calls,
            );
            self.shared_layout = complete;
            self.shared_calls = self.owned_shared_calls;
            self.provider_custody = .complete_shared_schedule_v2;
            self.authority_seal = bundleIdentity(self);
            try self.validate();
        }

        /// Adds exactly rows 18--34 to an existing manifest builder. It is
        /// neutral with respect to parent child-role semantics.
        pub fn appendManifestGeometries(
            self: *const Self,
            builder: anytype,
        ) !void {
            try self.validate();
            const logs = self.bundleLogSizes();
            _ = try builder.append(Adapters.CompositionInput.manifestGeometry(
                .vm_air_composition_input,
                logs[0],
            ));
            _ = try builder.append(Adapters.CompositionControl.manifestGeometry(
                .vm_air_composition_control,
                logs[1],
            ));
            _ = try builder.append(Adapters.QueryBits.manifestGeometry(.query_bits, logs[2]));
            _ = try builder.append(Adapters.QueryMapping.manifestGeometry(.query_mapping, logs[3]));
            _ = try builder.append(Adapters.MerkleRoot.manifestGeometry(.merkle_root, logs[4]));
            _ = try builder.append(Adapters.TraceMerkle.manifestGeometry(.trace_merkle, logs[5]));
            _ = try builder.append(Adapters.Pcs.manifestGeometry(.pcs_deep_input, logs[6]));
            _ = try builder.append(Adapters.FriLeaf.manifestGeometry(.fri_merkle_leaf, logs[7]));
            _ = try builder.append(Adapters.FriNode.manifestGeometry(.fri_merkle_node, logs[8]));
            _ = try builder.append(Adapters.FriAnchor.manifestGeometry(.fri_merkle_anchor, logs[9]));
            _ = try builder.append(Adapters.FriControl.manifestGeometry(.fri_verifier_control, logs[10]));
            _ = try builder.append(Adapters.FriInput.manifestGeometry(.fri_verifier_input, logs[11]));
            _ = try builder.append(Adapters.Multiply.manifestGeometry(.qm31_mul, logs[12]));
            _ = try builder.append(Adapters.Inverse.manifestGeometry(.qm31_inv, logs[13]));
            _ = try builder.append(Adapters.Linear.manifestGeometry(.linear_ops, logs[14]));
            _ = try builder.append(Adapters.MerklePath.manifestGeometry(.merkle_path, logs[15]));
            _ = try builder.append(Adapters.Poseidon2.manifestGeometry(logs[16]));
        }

        /// Full Tree-0 writer for rows 18--34. Only this cohort's columns must
        /// be fresh, allowing rows 0--17 and 35 to be assembled independently.
        pub fn fillPreprocessedInto(
            self: *Self,
            manifest: *const manifest_contract.Manifest,
            destination: [][]M31,
        ) !void {
            try self.validate();
            const logs = self.bundleLogSizes();
            var columns = try bindOwnedColumns(
                manifest_contract,
                manifest_contract.PREPROCESSED_TREE_INDEX,
                PREPROCESSED_COLUMN_COUNT,
                PREPROCESSED_COLUMNS_PER_ROW,
                logs,
                manifest,
                destination,
            );
            try preflightFreshColumns(&columns);
            errdefer clearColumns(&columns);

            const composition_end = source_mod.COMPOSITION_PREPROCESSED_COLUMN_COUNT;
            const fri_end = composition_end + source_mod.PREPROCESSED_COLUMN_COUNT;
            const arithmetic_end = fri_end + source_mod.ARITHMETIC_PREPROCESSED_COLUMN_COUNT;
            try self.source.fillCompositionPreprocessedPreparedInto(
                &self.source_authority,
                &self.composition_workspace,
                columns[0..composition_end],
            );
            try self.source.fillFriPreprocessedPreparedInto(
                &self.source_authority,
                &self.fri_workspace,
                columns[composition_end..fri_end],
            );
            try self.source.fillArithmeticPreprocessedPreparedInto(
                &self.source_authority,
                &self.arithmetic_workspace,
                columns[fri_end..arithmetic_end],
            );
            const provider = columns[arithmetic_end..][0..1];
            @memset(provider[0], M31.zero());
            provider[0][committedRow(0, logs[16])] = M31.one();
        }

        /// Full Tree-1 writer. It also seals the retained relation rows and
        /// binds the cold interaction workspace; subsequent Tree-2 fills are
        /// heap-allocation-free.
        pub fn fillMainInto(
            self: *Self,
            manifest: *const manifest_contract.Manifest,
            destination: [][]M31,
        ) !void {
            return main_fill.fill(
                self,
                manifest,
                destination,
                manifest_contract,
                MAIN_COLUMN_COUNT,
                MAIN_COLUMNS_PER_ROW,
                bundleLogSizes,
                bindOwnedColumns,
                preflightFreshColumns,
                clearColumns,
                finalizePendingSharedSchedule,
                providerCallsPrepared,
                captureSharedProviderOutputs,
                validate,
            );
        }

        /// Full Tree-2 writer and generated receipt. Row 34 consumes retained
        /// outputs, avoiding the old second scalar Poseidon replay.
        pub fn fillInteractionInto(
            self: *Self,
            manifest: *const manifest_contract.Manifest,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
            destination: [][]M31,
        ) !GeneratedInteractionsV1 {
            try self.requirePrepared();
            try relations.validate();
            try provider_relations.validateAgainst(relations);
            const logs = self.bundleLogSizes();
            var columns = try bindOwnedColumns(
                manifest_contract,
                manifest_contract.INTERACTION_TREE_INDEX,
                INTERACTION_COLUMN_COUNT,
                INTERACTION_COLUMNS_PER_ROW,
                logs,
                manifest,
                destination,
            );
            try preflightFreshColumns(&columns);
            errdefer clearColumns(&columns);

            const typed_claims = try self.source.fillTypedInteractionsPreparedInto(
                &self.source_authority,
                &self.relation_rows,
                &self.interaction_workspace,
                relations,
                columns[0..source_mod.TYPED_INTERACTION_COLUMN_COUNT],
            );
            var provider_columns: [poseidon_air.N_INTERACTION_COLUMNS][]M31 = undefined;
            @memcpy(
                &provider_columns,
                columns[source_mod.TYPED_INTERACTION_COLUMN_COUNT..][0..poseidon_air.N_INTERACTION_COLUMNS],
            );
            const provider_claims = try self.generateProviderInteraction(
                provider_relations,
                &provider_columns,
            );
            const claims = Claims{
                .typed_rows = typed_claims,
                .poseidon2_partials = provider_claims.sums,
            };
            var result = GeneratedInteractionsV1{
                .bundle_id = self.authority_seal,
                .relation_registry_id = relations.registry_order_digest,
                .provider_relation_id = try provider_relations.identityDigest(),
                .provider_program_id = self.poseidon_program_id.combined_digest,
                .retained_rows_id = self.relation_rows.authority_digest,
                .merkle_provider_batch_id = self.providerBatchId(),
                .claims = claims,
                .identity = undefined,
            };
            result.identity = generatedIdentity(&result);
            try self.validateGeneratedInteractions(&result, relations, provider_relations);
            return result;
        }

        pub fn validateGeneratedInteractions(
            self: *const Self,
            generated: *const GeneratedInteractionsV1,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
        ) !void {
            try self.requirePrepared();
            try relations.validate();
            try provider_relations.validateAgainst(relations);
            if (generated.format_version != GENERATED_FORMAT_VERSION or
                !allZero(&generated.padding) or
                !std.mem.eql(u8, &generated.bundle_id, &self.authority_seal) or
                !std.mem.eql(
                    u8,
                    &generated.relation_registry_id,
                    &relations.registry_order_digest,
                ) or !std.mem.eql(
                u8,
                &generated.provider_relation_id,
                &(try provider_relations.identityDigest()),
            ) or !std.mem.eql(
                u8,
                &generated.provider_program_id,
                &self.poseidon_program_id.combined_digest,
            ) or !std.mem.eql(
                u8,
                &generated.retained_rows_id,
                &self.relation_rows.authority_digest,
            ) or !std.mem.eql(
                u8,
                &generated.merkle_provider_batch_id,
                &self.providerBatchId(),
            )) return error.GeneratedIdentityMismatch;
            try validateClaims(generated.claims);
            if (!std.mem.eql(u8, &generated.identity, &generatedIdentity(generated)))
                return error.GeneratedIdentityMismatch;
        }

        /// Replays all 16 typed relation domains and both native Poseidon
        /// recurrence claims from retained authority, independently of the
        /// generated interaction columns.
        pub fn auditGeneratedInteractions(
            self: *Self,
            allocator: std.mem.Allocator,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
            generated: *const GeneratedInteractionsV1,
        ) !AuditedInteractionsV1 {
            return self.auditGeneratedInteractionsAssumeLedger(
                allocator,
                relations,
                provider_relations,
                generated,
                null,
            );
        }

        /// Replays the exact generated claims while retaining signed tuples
        /// for a cold, failure-only global-closure diagnostic.  This is kept
        /// separate from the ordinary verifier audit so successful proofs do
        /// not inherit diagnostic hashing or allocation work.
        pub fn auditGeneratedInteractionsWithTupleLedger(
            self: *Self,
            allocator: std.mem.Allocator,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
            generated: *const GeneratedInteractionsV1,
            tuple_ledger: *relation_interaction.TupleLedger,
        ) !AuditedInteractionsV1 {
            return self.auditGeneratedInteractionsAssumeLedger(
                allocator,
                relations,
                provider_relations,
                generated,
                tuple_ledger,
            );
        }

        fn auditGeneratedInteractionsAssumeLedger(
            self: *Self,
            allocator: std.mem.Allocator,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
            generated: *const GeneratedInteractionsV1,
            tuple_ledger: ?*relation_interaction.TupleLedger,
        ) !AuditedInteractionsV1 {
            return generated_audit.audit(
                self,
                allocator,
                relations,
                provider_relations,
                generated,
                tuple_ledger,
                DomainAudits,
                AuditedInteractionsV1,
                validateGeneratedInteractions,
                providerCallsPrepared,
                providerOutputsPrepared,
                validateAudits,
                auditedIdentity,
            );
        }

        pub fn independentlyRebuildAndValidate(
            self: *Self,
            allocator: std.mem.Allocator,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
            generated: *const GeneratedInteractionsV1,
        ) !AuditedInteractionsV1 {
            return self.auditGeneratedInteractions(
                allocator,
                relations,
                provider_relations,
                generated,
            );
        }

        pub fn initComponents(
            self: *const Self,
            manifest: *const manifest_contract.Manifest,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
            generated: *const GeneratedInteractionsV1,
        ) !ManifestComponents {
            return component_init.init(
                self,
                manifest,
                relations,
                provider_relations,
                generated,
                ManifestComponents,
                Adapters,
                parametersFromRows,
                validateGeneratedInteractions,
                bundleLogSizes,
                providerCallCount,
            );
        }

        fn requirePrepared(self: *const Self) !void {
            try self.validate();
            if (!self.main_prepared) return error.RowsNotPrepared;
        }

        fn generateProviderInteraction(
            self: *Self,
            provider_relations: *const shared_provider.SharedProviderRelations,
            destination: ?*[poseidon_air.N_INTERACTION_COLUMNS][]M31,
        ) !poseidon_air.Claims {
            const calls = try self.providerCallsPrepared();
            const outputs = try self.providerOutputsPrepared();
            var fixed = std.heap.FixedBufferAllocator.init(self.provider_scratch);
            var interaction = poseidon_air.generateIoInteractionFromOutputs(
                fixed.allocator(),
                calls,
                outputs,
                self.provider_log_size,
                &provider_relations.native,
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.ProviderScratchExhausted,
                else => return err,
            };
            defer interaction.deinit(fixed.allocator());
            if (destination) |columns| {
                for (columns, interaction.columns) |target, values|
                    @memcpy(target, values);
            }
            return interaction.claims;
        }
    };
}
