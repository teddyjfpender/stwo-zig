//! Generic support operations for split PCS source planning and transcript custody.

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

pub fn Ops(comptime Owner: type) type {
    const Digest = Owner.Digest;
    const CancellationTokenV1 = Owner.CancellationTokenV1;
    const SharedChallengeBindingV1 = Owner.SharedChallengeBindingV1;
    const RoleAuthority = Owner.RoleAuthority;
    const leafIndex = Owner.leafIndex;
    const declarationDomain = Owner.declarationDomain;
    const preTreeDomainWords = Owner.preTreeDomainWords;
    const postBarrierDomainWords = Owner.postBarrierDomainWords;
    const pcs_commitment_profile = Owner.pcs_commitment_profile;
    const format_version = Owner.format_version;
    const tree_count = Owner.tree_count;
    const tree0_index = Owner.tree0_index;
    const tree1_index = Owner.tree1_index;

    return struct {
        pub fn copyProjectedColumn(
            destination: []M31,
            domain_size: usize,
            destination_column: usize,
            source: []const M31,
        ) void {
            std.debug.assert(source.len == domain_size);
            @memcpy(
                destination[destination_column * domain_size ..][0..domain_size],
                source,
            );
        }

        pub fn validateRoleAllocator(allocator: std.mem.Allocator, shadow: anytype) !void {
            if (!std.meta.eql(allocator, shadow.selectors.allocator) or
                !std.meta.eql(allocator, shadow.main.allocator))
            {
                return error.SplitPcsAllocatorMismatch;
            }
        }

        pub fn checkCancellation(cancellation: ?*const CancellationTokenV1) !void {
            if (cancellation) |token| {
                if (token.isRequested()) return error.SplitPcsPreparationCancelled;
            }
        }

        pub fn mixPreTreePrefixV1(
            comptime role: aggregation_types.LeafRole,
            pcs_config: pcs_core.PcsConfig,
            channel: anytype,
            core: *const base_statement.RiscVStatement,
            authority: RoleAuthority(role),
            profile_statement_digest: Digest,
            guest_call_commitment: Digest,
            guest_call_count: u64,
        ) void {
            pcs_config.mixInto(channel);
            if (role == .core_request) core.public_data.mixInto(channel);
            channel.mixU32s(preTreeDomainWords(role));
            mixDigest(channel, profile_statement_digest);
            mixDigest(channel, authority.accepted_protocol.proof_protocol_digest);
            mixDigest(channel, authority.accepted_protocol.relation_registry_digest);
            mixDigest(channel, authority.job_digest);
            mixDigest(channel, authority.air_artifact_digest);
            mixDigest(channel, guest_call_commitment);
            channel.mixU64(guest_call_count);
            channel.mixU32s(&.{
                @intFromEnum(authority.component.slot),
                @intFromEnum(authority.component.kind),
                authority.component.version,
                authority.component.n_rows,
                authority.component.log_size,
                authority.component.preprocessed_columns,
                authority.component.main_columns,
                authority.component.interaction_columns,
            });
        }

        /// Canonical verifier/prover replay of the first post-manifest transcript
        /// transition. All encoding and authority checks finish before the channel is
        /// changed; the shared pair is copied from the prepared manifest, never drawn
        /// from this role-local transcript.
        pub fn mixPostBarrierBindingV1(
            comptime role: aggregation_types.LeafRole,
            channel: anytype,
            session: *const aggregation_manifest.PreparedSessionV1,
            identities: *const split_leaf_statement.VerifierOwnedLeafIdentitiesV1,
        ) !SharedChallengeBindingV1 {
            const words = if (role == .core_request) blk: {
                const statement = try split_leaf_statement.CallerLeafStatementV1.init(
                    session,
                    leafIndex(role),
                    identities,
                );
                break :blk try statement.canonicalWords(session, identities);
            } else blk: {
                const statement = try split_leaf_statement.ProviderLeafStatementV1.init(
                    session,
                    leafIndex(role),
                    identities,
                );
                break :blk try statement.canonicalWords(session, identities);
            };
            channel.mixU32s(postBarrierDomainWords(role));
            channel.mixU32s(&words);
            return .{
                .session_digest = session.session_digest,
                .challenge_context_digest = session.challenge.challenge_context_digest,
                .guest_z = session.challenge.z,
                .guest_alpha = session.challenge.alpha,
            };
        }

        fn mixDigest(channel: anytype, digest: Digest) void {
            var words: [@sizeOf(Digest) / @sizeOf(u32)]u32 = undefined;
            for (&words, 0..) |*word, index| {
                const start = index * @sizeOf(u32);
                word.* = std.mem.readInt(
                    u32,
                    digest[start..][0..@sizeOf(u32)],
                    .little,
                );
            }
            channel.mixU32s(&words);
        }

        fn writeComponent(sink: anytype, component: component_registry.Descriptor) !void {
            try aggregation_hash.writeU32(sink, @intFromEnum(component.slot));
            try aggregation_hash.writeU32(sink, @intFromEnum(component.kind));
            try aggregation_hash.writeU16(sink, component.version);
            try aggregation_hash.writeU32(sink, component.n_rows);
            try aggregation_hash.writeU32(sink, component.log_size);
            try aggregation_hash.writeU16(sink, component.preprocessed_columns);
            try aggregation_hash.writeU16(sink, component.main_columns);
            try aggregation_hash.writeU16(sink, component.interaction_columns);
        }

        pub fn preSessionDeclarationDigest(
            comptime role: aggregation_types.LeafRole,
            descriptor: aggregation_types.LeafDescriptorV1,
            component: component_registry.Descriptor,
            profile_statement_digest: Digest,
        ) !Digest {
            if (descriptor.role != role or descriptor.leaf_index != leafIndex(role) or
                descriptor.pair_index != 0)
            {
                return error.NonCanonicalLeafPosition;
            }
            if (aggregation_hash.isZero(profile_statement_digest))
                return error.InvalidPreparedPcsIdentity;
            var sink = aggregation_hash.HashSink.init(declarationDomain(role));
            try sink.writeAll(pcs_commitment_profile);
            try aggregation_hash.writeU32(&sink, format_version);
            try sink.writeAll(&profile_statement_digest);
            try aggregation_hash.writeU32(&sink, descriptor.leaf_index);
            try aggregation_hash.writeU32(&sink, descriptor.pair_index);
            try sink.writeAll(&.{@intFromEnum(descriptor.role)});
            try sink.writeAll(&.{descriptor.flags});
            try aggregation_hash.writeU16(&sink, descriptor.reserved);
            try sink.writeAll(&descriptor.job_digest);
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

        pub fn canonicalDescriptor(
            comptime role: aggregation_types.LeafRole,
            authority: RoleAuthority(role),
            profile_statement_digest: Digest,
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
                .leaf_statement_digest = .{0} ** @sizeOf(Digest),
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
                profile_statement_digest,
            );
            if (aggregation_hash.isZero(descriptor.leaf_statement_digest))
                return error.ZeroStatementDigest;
            return descriptor;
        }

        pub fn validatePair(
            accepted: aggregation_types.AcceptedProtocolV1,
            caller: anytype,
            provider: anytype,
        ) !void {
            if (!std.meta.eql(caller.authority.accepted_protocol, accepted) or
                !std.meta.eql(provider.authority.accepted_protocol, accepted))
            {
                return error.PairProtocolMismatch;
            }
            if (!aggregation_hash.eql(caller.authority.job_digest, provider.authority.job_digest))
                return error.PairJobMismatch;
            if (!aggregation_hash.eql(
                caller.profile_statement_digest,
                provider.profile_statement_digest,
            )) return error.PairStatementMismatch;
            if (!aggregation_hash.eql(
                caller.guest_call_commitment,
                provider.guest_call_commitment,
            )) return error.PairCallCommitmentMismatch;
            if (caller.guest_call_count != provider.guest_call_count)
                return error.PairCallCountMismatch;
        }

        pub fn readExactRoots(
            comptime Engine: type,
            allocator: std.mem.Allocator,
            scheme: *Engine.Scheme,
        ) ![tree_count]Digest {
            var roots = try scheme.roots(allocator);
            defer roots.deinit(allocator);
            if (roots.items.len != tree_count) return error.InvalidSplitPcsTreeCount;
            return .{ roots.items[tree0_index], roots.items[tree1_index] };
        }

        pub fn validateSchemeRoots(
            comptime Engine: type,
            allocator: std.mem.Allocator,
            scheme: *Engine.Scheme,
            expected: [tree_count]Digest,
        ) !void {
            const actual = try readExactRoots(Engine, allocator, scheme);
            if (!std.meta.eql(actual, expected)) return error.PreparedPcsRootMismatch;
        }

        pub fn commitSource(
            comptime Engine: type,
            allocator: std.mem.Allocator,
            scheme: *Engine.Scheme,
            channel: *Engine.Channel,
            source: *SourcePlan,
        ) !void {
            if (!source.owns_buffers) return error.SplitPcsSourceNotOwned;
            const columns = source.columns;
            const backings = source.backing_buffers;
            source.disarm();
            try Engine.commitWithBacking(
                scheme,
                allocator,
                columns,
                backings,
                null,
                channel,
            );
        }

        pub const SourcePlan = struct {
            allocator: std.mem.Allocator,
            columns: []ColumnEvaluation,
            backing_buffers: [][]M31,
            owns_buffers: bool = false,
            expected_role_storage: []M31,

            pub fn initRoleOnly(
                allocator: std.mem.Allocator,
                log_size: u32,
                storage: []M31,
                column_count: usize,
            ) !SourcePlan {
                const domain_size = try domainSize(log_size);
                if (column_count == 0 or
                    storage.len != try checkedMul(column_count, domain_size))
                {
                    return error.InvalidSplitPcsSourceShape;
                }
                const columns = try allocator.alloc(ColumnEvaluation, column_count);
                errdefer allocator.free(columns);
                const backings = try allocator.alloc([]M31, 1);
                errdefer allocator.free(backings);
                for (columns, 0..) |*column, index| {
                    const start = index * domain_size;
                    column.* = .{
                        .log_size = log_size,
                        .values = storage[start..][0..domain_size],
                    };
                }
                backings[0] = storage;
                var result = SourcePlan{
                    .allocator = allocator,
                    .columns = columns,
                    .backing_buffers = backings,
                    .expected_role_storage = storage,
                };
                try result.validateCoverage();
                return result;
            }

            pub fn initCallerTree0(
                allocator: std.mem.Allocator,
                base: []const ColumnEvaluation,
                role_log_size: u32,
                role_storage: []M31,
            ) !SourcePlan {
                const role_domain = try domainSize(role_log_size);
                if (role_storage.len !=
                    try checkedMul(split_leaf_prepare.selector_column_count, role_domain))
                {
                    return error.InvalidSplitPcsSourceShape;
                }
                const total_columns = try checkedAdd(
                    base.len,
                    split_leaf_prepare.selector_column_count,
                );
                const columns = try allocator.alloc(ColumnEvaluation, total_columns);
                errdefer allocator.free(columns);
                const backings = try allocator.alloc([]M31, try checkedAdd(base.len, 1));
                errdefer allocator.free(backings);
                @memcpy(columns[0..base.len], base);
                for (base, 0..) |column, index| {
                    backings[index] = @constCast(column.values);
                }
                for (0..split_leaf_prepare.selector_column_count) |index| {
                    const start = index * role_domain;
                    columns[base.len + index] = .{
                        .log_size = role_log_size,
                        .values = role_storage[start..][0..role_domain],
                    };
                }
                backings[base.len] = role_storage;
                var result = SourcePlan{
                    .allocator = allocator,
                    .columns = columns,
                    .backing_buffers = backings,
                    .expected_role_storage = role_storage,
                };
                try result.validateCoverage();
                return result;
            }

            pub fn initCallerTree1(
                allocator: std.mem.Allocator,
                base: *const production.MainCommitment,
                role_log_size: u32,
                role_storage: []M31,
            ) !SourcePlan {
                const role_columns: usize = component_registry.caller_layout.main_columns;
                const role_domain = try domainSize(role_log_size);
                if (role_storage.len != try checkedMul(role_columns, role_domain))
                    return error.InvalidSplitPcsSourceShape;
                const total_columns = try checkedAdd(base.columns.len, role_columns);
                const base_backing_count: usize = if (base.backing != null)
                    1
                else
                    base.columns.len;
                const columns = try allocator.alloc(ColumnEvaluation, total_columns);
                errdefer allocator.free(columns);
                const backings = try allocator.alloc(
                    []M31,
                    try checkedAdd(base_backing_count, 1),
                );
                errdefer allocator.free(backings);
                @memcpy(columns[0..base.columns.len], base.columns);
                if (base.backing) |backing| {
                    backings[0] = backing.payload;
                } else {
                    for (base.columns, 0..) |column, index| {
                        backings[index] = @constCast(column.values);
                    }
                }
                for (0..role_columns) |index| {
                    const start = index * role_domain;
                    columns[base.columns.len + index] = .{
                        .log_size = role_log_size,
                        .values = role_storage[start..][0..role_domain],
                    };
                }
                backings[base_backing_count] = role_storage;
                var result = SourcePlan{
                    .allocator = allocator,
                    .columns = columns,
                    .backing_buffers = backings,
                    .expected_role_storage = role_storage,
                };
                try result.validateCoverage();
                return result;
            }

            pub fn deinit(self: *SourcePlan) void {
                if (self.columns.len == 0) return;
                if (self.owns_buffers) {
                    for (self.backing_buffers) |buffer| self.allocator.free(buffer);
                }
                self.allocator.free(self.backing_buffers);
                self.allocator.free(self.columns);
                self.* = undefined;
            }

            fn disarm(self: *SourcePlan) void {
                self.columns = &.{};
                self.backing_buffers = &.{};
                self.owns_buffers = false;
                self.expected_role_storage = &.{};
            }

            pub fn activateRoleStorage(self: *SourcePlan, actual: []M31) void {
                std.debug.assert(!self.owns_buffers);
                std.debug.assert(actual.ptr == self.expected_role_storage.ptr);
                std.debug.assert(actual.len == self.expected_role_storage.len);
                self.owns_buffers = true;
            }

            pub fn activateBaseMain(
                self: *SourcePlan,
                allocator: std.mem.Allocator,
                base: *production.MainCommitment,
            ) void {
                std.debug.assert(self.owns_buffers);
                if (base.backing) |backing| allocator.free(backing.buffers);
                allocator.free(base.columns);
                base.columns = &.{};
                base.backing = null;
            }

            fn validateCoverage(self: *const SourcePlan) !void {
                if (self.columns.len == 0 or self.backing_buffers.len == 0)
                    return error.InvalidSplitPcsSourceShape;
                const total = try checkedAdd(self.columns.len, self.backing_buffers.len);
                const ranges = try self.allocator.alloc(AddressRange, total);
                defer self.allocator.free(ranges);
                const column_ranges = ranges[0..self.columns.len];
                const backing_ranges = ranges[self.columns.len..];
                for (self.columns, column_ranges) |column, *range| {
                    const expected = try domainSize(column.log_size);
                    if (column.values.len != expected)
                        return error.InvalidSplitPcsSourceShape;
                    range.* = try addressRange(column.values);
                }
                for (self.backing_buffers, backing_ranges) |buffer, *range| {
                    if (buffer.len == 0) return error.InvalidSplitPcsSourceShape;
                    range.* = try addressRange(buffer);
                }
                std.mem.sortUnstable(AddressRange, column_ranges, {}, rangeLessThan);
                std.mem.sortUnstable(AddressRange, backing_ranges, {}, rangeLessThan);
                try requireDisjoint(column_ranges);
                try requireDisjoint(backing_ranges);

                var backing_index: usize = 0;
                for (column_ranges) |column| {
                    while (backing_index < backing_ranges.len and
                        backing_ranges[backing_index].end <= column.start)
                    {
                        backing_index += 1;
                    }
                    if (backing_index >= backing_ranges.len or
                        column.start < backing_ranges[backing_index].start or
                        column.end > backing_ranges[backing_index].end)
                    {
                        return error.SplitPcsColumnOutsideOwnedBacking;
                    }
                }
            }
        };

        const AddressRange = struct { start: usize, end: usize };

        fn addressRange(values: []const M31) !AddressRange {
            const bytes = try checkedMul(values.len, @sizeOf(M31));
            const start = @intFromPtr(values.ptr);
            return .{
                .start = start,
                .end = std.math.add(usize, start, bytes) catch
                    return error.SplitPcsResourceOverflow,
            };
        }

        fn rangeLessThan(_: void, left: AddressRange, right: AddressRange) bool {
            return if (left.start == right.start)
                left.end < right.end
            else
                left.start < right.start;
        }

        fn requireDisjoint(ranges: []const AddressRange) !void {
            if (ranges.len < 2) return;
            for (ranges[1..], ranges[0 .. ranges.len - 1]) |current, previous| {
                if (current.start < previous.end)
                    return error.OverlappingSplitPcsOwnership;
            }
        }

        pub fn validateBaseMain(
            core: *const base_statement.RiscVStatement,
            base: *const production.MainCommitment,
        ) !void {
            try base.validatePolicy();
            if (base.columns.len != core.nMainColumns())
                return error.IncompleteCallerBaseMainCommitment;
            var cursor: usize = 0;
            for (core.component_descs[0..core.n_components]) |descriptor| {
                try validateLogRun(
                    base.columns,
                    &cursor,
                    descriptor.log_size,
                    descriptor.n_columns,
                );
            }
            for (core.infra_descs[0..core.n_infra]) |descriptor| {
                try validateLogRun(
                    base.columns,
                    &cursor,
                    descriptor.log_size,
                    descriptor.n_columns,
                );
            }
            if (cursor != base.columns.len)
                return error.IncompleteCallerBaseMainCommitment;
        }

        fn validateLogRun(
            columns: []const ColumnEvaluation,
            cursor: *usize,
            log_size: u32,
            count_u32: u32,
        ) !void {
            const count: usize = count_u32;
            if (cursor.* > columns.len or count > columns.len - cursor.*)
                return error.IncompleteCallerBaseMainCommitment;
            const domain = try domainSize(log_size);
            for (columns[cursor.* .. cursor.* + count]) |column| {
                if (column.log_size != log_size or column.values.len != domain)
                    return error.InvalidCallerBaseMainGeometry;
            }
            cursor.* += count;
        }

        pub fn countCells(columns: []const ColumnEvaluation) !usize {
            var result: usize = 0;
            for (columns) |column| {
                result = try checkedAdd(result, column.values.len);
            }
            return result;
        }

        pub fn domainSize(log_size: u32) !usize {
            if (log_size >= @bitSizeOf(usize)) return error.SplitPcsResourceOverflow;
            return @as(usize, 1) << @intCast(log_size);
        }

        pub fn checkedAdd(left: usize, right: usize) !usize {
            return std.math.add(usize, left, right) catch
                return error.SplitPcsResourceOverflow;
        }

        pub fn checkedMul(left: usize, right: usize) !usize {
            return std.math.mul(usize, left, right) catch
                return error.SplitPcsResourceOverflow;
        }

        pub fn freeIndependentColumns(
            allocator: std.mem.Allocator,
            columns: []ColumnEvaluation,
        ) void {
            for (columns) |column| allocator.free(@constCast(column.values));
            allocator.free(columns);
        }
    };
}
