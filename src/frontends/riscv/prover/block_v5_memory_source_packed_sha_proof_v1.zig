//! Genuine page-level original packed SHA/core/table/connector proof lifecycle.
//! A fresh KernelVerified proves only this SHA kernel. It is NOT complete source
//! authentication: indexed records, fold roots and Source9 arithmetic must also
//! be proved and joined before any source receipt/global closure is possible.
//! Every wire requester aliases original raw/capture mains, so this dedicated
//! page-local wire challenge follows commitments on both sides of every wire.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Schema = @import("block_v5_memory_source_batch_raw_schema_v1.zig");
const Operand = @import("block_v5_memory_source_packed_sha_replay_v1.zig");
const Columns = @import("block_v5_memory_source_packed_sha_columns_v1.zig");
const TreeMap = @import("block_v5_memory_source_component_trees_v1.zig");
const ConnectorAir = @import("block_v5_memory_source_sha_connector_air_v1.zig");
const Connector = @import("block_v5_memory_source_sha_connector_component_v1.zig").ForSourceFixed(Schema.FIXED_COUNT);
const ConnectorInteraction = @import("block_v5_memory_source_sha_connector_interaction_v1.zig");
const Universal = @import("../recursion/air/universal_challenges.zig");
const Providers = @import("../recursion/air/universal_provider_relations.zig");
const Binding = @import("../recursion/air/universal_relation_binding.zig");
const Framework = @import("../recursion/air/framework_interaction.zig");
const CoreGeometry = @import("../recursion/air/roster_composition_geometry.zig").ForAirs(Columns.Airs);
const Roster = @import("../recursion/air/universal_component_roster.zig").ForAirs(Columns.Airs, &.{ "source", "schedule", "round", "feed_forward" });
const CoreOwner = @import("../recursion/air/universal_component_owner.zig").ForRoster(Roster);
const Tables = @import("../air/lookups/tables/schema.zig");
const Table = @import("../air/lookups/tables/component.zig").LookupTableComponent;
const TableInteraction = @import("../air/lookups/tables/interaction.zig");
const RowColumns = @import("../recursion/air/blake3_row_columns.zig");
const Preprocessed = @import("../air/guest_precompile/sha256_preprocessed.zig");
const Raw = @import("block_v5_memory_source_batch_raw_v1.zig");
const PLACE = @import("../air/block/memory_component_trace.zig");
const KINDS = [_]Tables.Kind{ .bitwise, .range_check_8_8 };
pub const TAG: u32 = 0x4235534b; // B5SK, kernel proof; not complete SOURCE
pub const VERSION: u32 = 1;
pub const TREE_COUNT = 7;
pub const COMPONENT_COUNT = 7; // four original AIRs, two tables, connector
pub const Limits = struct { operands: Operand.Limits = .{}, max_interaction_cells: usize = 1 << 28 };
pub const Proof = struct {
    pin: Operand.Pin,
    core_claims: [6]Q,
    connector_claim: ConnectorInteraction.Claim,
    stark: suite.Proof,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        self.* = undefined;
    }
};
pub const KernelVerified = struct {
    admission_id: [32]u8,
    page_identity: [32]u8,
    kernel_abi: [32]u8,
    compressions: u32,
    wire_requests: u64,
    final_channel: [32]u8,
};
pub fn abiId() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/source-packed-sha-kernel/v1\x00");
    hash.update(&Operand.abiId());
    hash.update(&Universal.registryOrderDigest());
    hash.update("same-raw-capture-main;dedicated-post-six-root-wire;original-four-AIRs;exact-two-tables;one-page-interaction-composition-FRI;not-full-source\x00");
    return hash.finalResult();
}
fn mixKernel(channel: *suite.Channel) void {
    channel.mixU32s(&.{ TAG, VERSION });
    channel.mixRoot(abiId());
}
fn mixClaims(channel: *suite.Channel, claims: [6]Q, connector: ConnectorInteraction.Claim) void {
    channel.mixU32s(&.{ TAG, VERSION, 0x434c414d });
    channel.mixFelts(&claims);
    channel.mixFelts(&connector.sums);
    channel.mixU64(connector.wire_requests);
}
pub fn requireClaims(pin: Operand.Pin, claims: [6]Q, connector: ConnectorInteraction.Claim, limits: Limits) !void {
    if (pin.raw.page.row_log < 1 or pin.raw.page.row_log > 12) return error.InvalidSourceShaKernelGeometry;
    for (pin.geometry.logs) |log| if (log >= core.circle.M31_CIRCLE_LOG_ORDER or log >= @bitSizeOf(usize)) return error.InvalidSourceShaKernelGeometry;
    const requests = try std.math.mul(u64, pin.geometry.compressions, 32);
    _ = try ConnectorInteraction.normalize(connector, @as(usize, 1) << @intCast(pin.raw.page.row_log), requests);
    var total = Q.zero();
    for (claims) |claim| total = total.add(claim);
    for (connector.sums) |sum| total = total.add(sum);
    if (!total.isZero()) return error.UnclosedSourceShaKernel;
    var cells: usize = 0;
    inline for (Columns.Airs, 0..) |Air, i| cells = try std.math.add(usize, cells, try std.math.mul(usize, @as(usize, 1) << @intCast(pin.geometry.logs[i]), Air.INTERACTION_COLUMN_COUNT));
    for (KINDS) |kind| cells = try std.math.add(usize, cells, try std.math.mul(usize, Tables.size(kind), TableInteraction.N_COLUMNS));
    cells = try std.math.add(usize, cells, try std.math.mul(usize, @as(usize, 1) << @intCast(pin.raw.page.row_log), ConnectorAir.INTERACTION_COUNT));
    if (cells > limits.max_interaction_cells) return error.SourcePackedPageResourceLimit;
}
fn coreInteractionCount() usize {
    var count: usize = 2 * TableInteraction.N_COLUMNS;
    inline for (Columns.Airs) |Air| count += Air.INTERACTION_COLUMN_COUNT;
    return count;
}
fn coreMainCount() usize {
    var count: usize = 2;
    inline for (Columns.Airs) |Air| count += Air.PHYSICAL_MAIN_COLUMN_COUNT;
    return count;
}
fn coreFixedCount() usize {
    var count: usize = 0;
    inline for (Columns.Airs) |Air| count += Air.PREPROCESSED_COLUMN_COUNT;
    for (KINDS) |kind| count += Tables.arity(kind) + 1;
    return count;
}
const CoreComponents = blk: {
    var types: [Columns.Airs.len]type = undefined;
    for (Columns.Airs, &types) |Air, *T| T.* = TreeMap.For(Roster.Component(Air), TREE_COUNT, 3);
    break :blk std.meta.Tuple(&types);
};
pub const COMPOSITION_SPLIT = @max(2, CoreGeometry.quotient_log_blowup);
const TargetSplit = COMPOSITION_SPLIT;
pub const ComponentOwner = struct {
    a: std.mem.Allocator,
    core: *CoreOwner,
    providers: Providers.SharedProviderRelations,
    mapped_core: CoreComponents = undefined,
    tables: [2]TreeMap.For(Table, TREE_COUNT, 3) = undefined,
    connector: TreeMap.For(Connector, TREE_COUNT, 5) = undefined,
    pub fn deinit(self: *@This()) void {
        self.core.deinit();
        const a = self.a;
        a.destroy(self);
    }
    pub fn init(a: std.mem.Allocator, pin: Operand.Pin, relations: Universal.UniversalRelations, claims: [6]Q, connector: ConnectorInteraction.Claim, limits: Limits) !*@This() {
        return initUsing(a, pin, relations, claims, connector, limits, null);
    }
    /// Exact checked scalar programs are copied during construction. The
    /// component owner does not borrow the page's ASTs after this call.
    pub fn initPrepared(a: std.mem.Allocator, pin: Operand.Pin, relations: Universal.UniversalRelations, claims: [6]Q, connector: ConnectorInteraction.Claim, limits: Limits, columns: *const Columns.Columns) !*@This() {
        if (!std.meta.eql(columns.geometry, pin.geometry)) return error.UntrustedSourceShaCoreRecipe;
        return initUsing(a, pin, relations, claims, connector, limits, .{ .definitions = &columns.definitions, .plans = &columns.plans });
    }
    pub fn initWithSetup(a: std.mem.Allocator, pin: Operand.Pin, relations: Universal.UniversalRelations, claims: [6]Q, connector: ConnectorInteraction.Claim, limits: Limits, setup: *const Columns.Setup) !*@This() {
        var lease = try setup.lease();
        defer lease.deinit();
        return initUsing(a, pin, relations, claims, connector, limits, .{ .definitions = &setup.definitions, .plans = &setup.plans });
    }
    const PreparedSetup = struct {
        definitions: *const Roster.Tuple(.definition),
        plans: *const Roster.Tuple(.plan),
    };
    fn initUsing(a: std.mem.Allocator, pin: Operand.Pin, relations: Universal.UniversalRelations, claims: [6]Q, connector: ConnectorInteraction.Claim, limits: Limits, setup: ?PreparedSetup) !*@This() {
        try requireClaims(pin, claims, connector, limits);
        const result = try a.create(@This());
        errdefer a.destroy(result);
        const manifest = Roster.Manifest{ .log_sizes = pin.geometry.logs };
        const core_owner = if (setup) |shared|
            try CoreOwner.initPrepared(a, &manifest, shared.definitions, shared.plans, @as([4][0]core.fields.m31.M31, @splat(.{})), relations, claims[0..4].*)
        else
            try CoreOwner.init(a, &manifest, @as([4][0]core.fields.m31.M31, @splat(.{})), relations, claims[0..4].*);
        errdefer core_owner.deinit();
        result.* = .{ .a = a, .core = core_owner, .providers = try Providers.SharedProviderRelations.init(&relations) };
        const mappings = [_]TreeMap.Binding{ .{ .tree = 2, .count = coreFixedCount() }, .{ .tree = 3, .count = coreMainCount() }, .{ .tree = 6, .count = coreInteractionCount() } };
        inline for (Columns.Airs, 0..) |Air, i| result.mapped_core[i] = try TreeMap.For(Roster.Component(Air), TREE_COUNT, 3).init(core_owner.components[i], mappings);
        var fixed_offset: usize = 0;
        inline for (Columns.Airs) |Air| fixed_offset += Air.PREPROCESSED_COLUMN_COUNT;
        var main_offset = coreMainCount() - 2;
        var interaction_offset = coreInteractionCount() - 2 * TableInteraction.N_COLUMNS;
        for (KINDS, 0..) |kind, i| {
            var tuple_indices: [Tables.MAX_ARITY]usize = undefined;
            for (tuple_indices[0..Tables.arity(kind)], 0..) |*index, ordinal| index.* = fixed_offset + 1 + ordinal;
            const table = try Table.initProver(kind, fixed_offset, tuple_indices[0..Tables.arity(kind)], main_offset, interaction_offset, &result.providers.native, claims[4 + i]);
            result.tables[i] = try TreeMap.For(Table, TREE_COUNT, 3).init(table, mappings);
            fixed_offset += Tables.arity(kind) + 1;
            main_offset += 1;
            interaction_offset += TableInteraction.N_COLUMNS;
        }
        const wire = relations.get(.recursion_wire);
        const original = try Connector.init(pin.raw.page.row_log, connector.wire_requests, connector, .{ .z = wire.z, .powers = wire.alpha_powers[0..6].* });
        result.connector = try TreeMap.For(Connector, TREE_COUNT, 5).init(original, .{
            .{ .tree = 0, .count = Schema.FIXED_COUNT },                                               .{ .tree = 1, .count = Schema.MAIN_COUNT },
            .{ .tree = 4, .count = ConnectorAir.EXPANDED_FIXED_COUNT },                                .{ .tree = 5, .count = ConnectorAir.CAPTURE_MAIN_COUNT },
            .{ .tree = 6, .offset = coreInteractionCount(), .count = ConnectorAir.INTERACTION_COUNT },
        });
        return result;
    }
    fn normalize(comptime intrinsic: u32, handle: anytype) !@TypeOf(handle) {
        if (intrinsic > TargetSplit) return error.InvalidSourceShaKernelDegree;
        return handle.withCompositionGeometryOverrideV1(.{ .max_constraint_log_degree_bound_delta = TargetSplit - intrinsic, .composition_log_split = TargetSplit });
    }
    pub fn provers(self: *const @This()) ![COMPONENT_COUNT]engine.air.component_prover.ComponentProver {
        var out: [COMPONENT_COUNT]engine.air.component_prover.ComponentProver = undefined;
        inline for (Columns.Airs, 0..) |Air, i| out[i] = try normalize(CoreGeometry.quotient_log_blowup, try CoreGeometry.component(Air, self.mapped_core[i].asProverComponent()));
        for (&self.tables, 4..) |*table, i| out[i] = try normalize(CoreGeometry.quotient_log_blowup, try CoreGeometry.table(table.asProverComponent()));
        out[6] = try normalize(2, self.connector.asProverComponent());
        return out;
    }
    pub fn verifiers(self: *const @This()) ![COMPONENT_COUNT]core.air.components.Component {
        var out: [COMPONENT_COUNT]core.air.components.Component = undefined;
        inline for (Columns.Airs, 0..) |Air, i| out[i] = try normalize(CoreGeometry.quotient_log_blowup, try CoreGeometry.component(Air, self.mapped_core[i].asVerifierComponent()));
        for (&self.tables, 4..) |*table, i| out[i] = try normalize(CoreGeometry.quotient_log_blowup, try CoreGeometry.table(table.asVerifierComponent()));
        out[6] = try normalize(2, self.connector.asVerifierComponent());
        return out;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Stage = Operand.ForBackend(Backend);
        pub const Proved = struct {
            owner: *Stage.Owner,
            proof: Proof,
            /// Proof vectors remain in the same bounded allocator that consumed
            /// the scheme. Keep this real owner alive until export/deinit.
            pub fn deinit(self: *Proved) void {
                self.proof.deinit(self.owner.allocator());
                std.debug.assert(self.owner.active_leases > 0);
                self.owner.active_leases -= 1;
                self.* = undefined;
            }
        };
        pub fn prove(owner: *Stage.Owner, admitted: *const Source.Admitted, plan: Schema.Protocol.Plan, expected: Operand.Pin, limits: Limits) !Proved {
            try owner.require(admitted, plan, expected, limits.operands);
            const a = owner.allocator();
            // Resource admission precedes any interaction allocation.
            const empty = ConnectorInteraction.Claim{ .sums = @splat(Q.zero()), .wire_requests = @as(u64, expected.geometry.compressions) * 32 };
            try requireClaims(expected, @splat(Q.zero()), empty, limits);
            var channel: suite.Channel = undefined;
            var lease = try Stage.lease(owner, admitted, plan, expected, limits.operands, &channel);
            defer lease.deinit();
            mixKernel(&channel);
            const relations = try Universal.UniversalRelations.draw(a, &channel);
            const providers = try Providers.SharedProviderRelations.init(&relations);
            var interaction: std.ArrayList(engine.pcs.ColumnEvaluation) = .empty;
            defer {
                for (interaction.items) |column| a.free(column.values);
                interaction.deinit(a);
            }
            var claims: [6]Q = undefined;
            const columns = &owner.cores.?;
            inline for (Columns.Airs, 0..) |Air, i| {
                const fixed = std.mem.sliceAsBytes(columns.owners[i].fixed); // borrowed compact fixed tail
                const metadata: []const core.fields.m31.M31 = @alignCast(std.mem.bytesAsSlice(core.fields.m31.M31, fixed));
                const view = try RowColumns.compactColumnView(Air, columns.owners[i].main, metadata, columns.owners[i].fixed.len, columns.owners[i].log);
                var generated = try Framework.Runtime(Binding.Binding(Air).Runtime).generatePreparedFromColumns(a, &columns.plans[i], view, columns.owners[i].log, &relations, @splat(core.fields.m31.M31.zero()));
                defer generated.deinit(a);
                claims[i] = generated.claimed_sum;
                // Framework storage is one slab: duplicate only final columns so
                // ArrayList has uniform independent ownership on every failure.
                for (generated.columns) |values| {
                    const owned = try a.dupe(core.fields.m31.M31, values);
                    interaction.append(a, .{ .log_size = columns.owners[i].log, .values = owned }) catch |err| {
                        a.free(owned);
                        return err;
                    };
                }
            }
            for (&columns.counters, 4..) |*counter, i| {
                var generated = try TableInteraction.generate(a, counter, &providers.native);
                defer generated.deinit(a);
                claims[i] = generated.claim;
                for (&generated.columns) |*values| {
                    try interaction.append(a, .{ .log_size = Tables.logSize(counter.kind), .values = values.* });
                    values.* = &.{};
                }
            }
            var fixed: [ConnectorAir.EXPANDED_FIXED_COUNT][]const core.fields.m31.M31 = undefined;
            var raw: [Schema.MAIN_COUNT][]const core.fields.m31.M31 = undefined;
            var captures: [ConnectorAir.CAPTURE_MAIN_COUNT][]const core.fields.m31.M31 = undefined;
            for (&fixed, columns.connector_fixed.columns) |*out, column| out.* = column.values;
            for (&captures, columns.captures.columns) |*out, column| out.* = column.values;
            for (&raw, 0..) |*out, column| out.* = owner.raw.?.columns.?.mainColumn(column);
            const wire = relations.get(.recursion_wire);
            var generated = try ConnectorInteraction.generate(a, .{ .fixed = &fixed, .original = &raw, .captures = &captures, .row_log = expected.raw.page.row_log, .logical_rows = expected.raw.page.chunks }, .{ .z = wire.z, .powers = wire.alpha_powers[0..6].* }, empty.wire_requests, limits.max_interaction_cells);
            defer generated.deinit();
            const rows = @as(usize, 1) << @intCast(expected.raw.page.row_log);
            for (0..ConnectorAir.INTERACTION_COUNT) |i| {
                const owned = try a.dupe(core.fields.m31.M31, generated.cells[i * rows ..][0..rows]);
                interaction.append(a, .{ .log_size = expected.raw.page.row_log, .values = owned }) catch |err| {
                    a.free(owned);
                    return err;
                };
            }
            try requireClaims(expected, claims, generated.claim, limits);
            mixClaims(&channel, claims, generated.claim);
            try lease.scheme.commitBorrowedStreaming(owner.allocator(), interaction.items, 16, &channel);
            const component_owner = try ComponentOwner.initPrepared(a, expected, relations, claims, generated.claim, limits, columns);
            defer component_owner.deinit();
            const components = try component_owner.provers();
            const scheme = try lease.takeScheme();
            const stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, owner.allocator(), &components, &channel, scheme);
            // The original lease remains live while proof storage is published;
            // add the returned storage lease before its deferred release.
            owner.active_leases += 1;
            return .{ .owner = owner, .proof = .{ .pin = expected, .core_claims = claims, .connector_claim = generated.claim, .stark = stark } };
        }
    };
}

/// Independently derive every tree inventory, including fixed masks and exact
/// original table geometry. No array length from proof bytes selects an AIR.
pub fn columnLogs(a: std.mem.Allocator, pin: Operand.Pin, tree: usize) ![]u32 {
    const raw_log = pin.raw.page.row_log;
    const count: usize = switch (tree) {
        0 => Schema.FIXED_COUNT,
        1 => Schema.MAIN_COUNT,
        2 => coreFixedCount(),
        3 => coreMainCount(),
        4 => ConnectorAir.EXPANDED_FIXED_COUNT,
        5 => ConnectorAir.CAPTURE_MAIN_COUNT,
        6 => coreInteractionCount() + ConnectorAir.INTERACTION_COUNT,
        else => return error.InvalidSourceShaKernelTree,
    };
    const logs = try a.alloc(u32, count);
    errdefer a.free(logs);
    @memset(logs, raw_log);
    if (tree == 2 or tree == 3 or tree == 6) {
        var offset: usize = 0;
        inline for (Columns.Airs, 0..) |Air, i| {
            const width: usize = if (tree == 2) Air.PREPROCESSED_COLUMN_COUNT else if (tree == 3) Air.PHYSICAL_MAIN_COLUMN_COUNT else Air.INTERACTION_COLUMN_COUNT;
            @memset(logs[offset..][0..width], pin.geometry.logs[i]);
            offset += width;
        }
        for (KINDS) |kind| {
            const width: usize = if (tree == 2) Tables.arity(kind) + 1 else if (tree == 3) 1 else TableInteraction.N_COLUMNS;
            @memset(logs[offset..][0..width], Tables.logSize(kind));
            offset += width;
        }
    }
    return logs;
}
/// Real CPU fixed-root reconstruction. The raw image/root/public input source
/// pins themselves still require the separate complete source authentication.
pub fn verifyFixedRoots(a: std.mem.Allocator, admitted: *const Source.Admitted, plan: Schema.Protocol.Plan, expected: Operand.Pin, limits: Limits) !void {
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, suite.Hasher, suite.MerkleChannel);
    try expected.require(admitted, plan, limits.operands);
    try Schema.Round.ForBackend(Cpu).verifyFixedRoot(a, admitted, plan, expected.raw, limits.operands.first);
    var budget = engine.host_budget_allocator.HostBudgetAllocator.init(a, limits.operands.max_page_heap_bytes);
    const bounded = budget.allocator();
    var fixed: std.ArrayList(engine.pcs.ColumnEvaluation) = .empty;
    defer {
        for (fixed.items) |column| bounded.free(column.values);
        fixed.deinit(bounded);
    }
    try Preprocessed.append(bounded, expected.geometry.compressions, false, &fixed);
    for (KINDS) |kind| try RowColumns.tablePreprocessed(bounded, kind, &fixed);
    var connector = try Columns.Matrix.init(bounded, ConnectorAir.EXPANDED_FIXED_COUNT, expected.raw.page.row_log);
    defer connector.deinit();
    for (0..expected.raw.page.chunks) |i| try connector.put(i, &(try ConnectorAir.expandedFixedRow(admitted, try Raw.kindAt(admitted, expected.raw.page.first_chunk + i))));
    var scheme = try Scheme.init(bounded, plan.config);
    defer scheme.deinit(bounded);
    scheme.setCoefficientRetentionPolicy(.never);
    var channel = suite.Channel{};
    try scheme.commitBorrowedStreaming(bounded, fixed.items, 16, &channel);
    try scheme.commitBorrowedStreaming(bounded, connector.columns, 16, &channel);
    var roots = try scheme.roots(bounded);
    defer roots.deinit(bounded);
    if (roots.items.len != 2 or !std.meta.eql(roots.items[0], expected.roots[2]) or !std.meta.eql(roots.items[1], expected.roots[4])) return error.UntrustedSourceShaKernelFixedRoots;
}
/// Pure admission before any component graph or received proof allocation.
pub fn admit(proof: *const Proof, admitted: *const Source.Admitted, plan: Schema.Protocol.Plan, expected: Operand.Pin, limits: Limits) !void {
    try expected.require(admitted, plan, limits.operands);
    try requireClaims(expected, proof.core_claims, proof.connector_claim, limits);
    const commitments = proof.stark.commitment_scheme_proof.commitments.items;
    if (!std.meta.eql(proof.pin, expected) or !std.meta.eql(proof.stark.commitment_scheme_proof.config, plan.config) or commitments.len != TREE_COUNT + 1) return error.UntrustedSourceShaKernelProof;
    if (!std.meta.eql(commitments[0..6].*, expected.roots)) return error.UntrustedSourceShaKernelProof;
}
/// Fresh original typed CPU verification consumes proof on every path. The
/// distinct return value intentionally cannot discharge a full source family.
pub fn verifyOwned(a: std.mem.Allocator, proof: Proof, admitted: *const Source.Admitted, plan: Schema.Protocol.Plan, expected: Operand.Pin, limits: Limits) !KernelVerified {
    return verifyOwnedUsing(a, proof, admitted, plan, expected, limits, null);
}
pub fn verifyOwnedWithSetup(a: std.mem.Allocator, proof: Proof, admitted: *const Source.Admitted, plan: Schema.Protocol.Plan, expected: Operand.Pin, limits: Limits, setup: *const Columns.Setup) !KernelVerified {
    return verifyOwnedUsing(a, proof, admitted, plan, expected, limits, setup);
}
fn verifyOwnedUsing(a: std.mem.Allocator, proof: Proof, admitted: *const Source.Admitted, plan: Schema.Protocol.Plan, expected: Operand.Pin, limits: Limits, setup: ?*const Columns.Setup) !KernelVerified {
    var owned = proof;
    var owns = true;
    defer if (owns) owned.deinit(a);
    try admit(&owned, admitted, plan, expected, limits);
    try verifyFixedRoots(a, admitted, plan, expected, limits);
    const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
    var verifier = try Verifier.init(a, plan.config);
    defer verifier.deinit(a);
    var channel = Operand.firstChannel(plan, expected.raw.page, expected.geometry);
    for (expected.roots, 0..) |root, i| {
        if (i == 2) {
            channel.mixRoot(Operand.abiId());
            channel.mixU32s(&(.{ Operand.TAG, 1, expected.geometry.compressions, expected.geometry.connector_log } ++ expected.geometry.logs));
        }
        const logs = try columnLogs(a, expected, i);
        defer a.free(logs);
        try verifier.commit(a, root, logs, &channel);
    }
    mixKernel(&channel);
    const relations = try Universal.UniversalRelations.draw(a, &channel);
    const component_owner = if (setup) |shared|
        try ComponentOwner.initWithSetup(a, expected, relations, owned.core_claims, owned.connector_claim, limits, shared)
    else
        try ComponentOwner.init(a, expected, relations, owned.core_claims, owned.connector_claim, limits);
    defer component_owner.deinit();
    const components = try component_owner.verifiers();
    mixClaims(&channel, owned.core_claims, owned.connector_claim);
    const interaction = try columnLogs(a, expected, 6);
    defer a.free(interaction);
    try verifier.commit(a, owned.stark.commitment_scheme_proof.commitments.items[6], interaction, &channel);
    owns = false; // Original CPU receiver consumes all proof vectors on errors too.
    try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, &components, &channel, &verifier, owned.stark);
    return .{ .admission_id = admitted.identity, .page_identity = try expected.identity(admitted, plan, limits.operands), .kernel_abi = abiId(), .compressions = expected.geometry.compressions, .wire_requests = owned.connector_claim.wire_requests, .final_channel = channel.digestBytes() };
}
