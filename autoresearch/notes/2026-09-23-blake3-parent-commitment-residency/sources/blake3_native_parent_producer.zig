//! Backend-injected standalone parent proving with immutable per-key preparation.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = @import("blake3_engine_protocol.zig");
const native_protocol = @import("blake3_native_parent_protocol.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
const native = @import("air/blake3_native_parent_rows.zig");
const Roster = @import("air/blake3_native_parent_roster.zig").Roster;
const row_columns = @import("air/blake3_row_columns.zig");
const binding = @import("air/universal_relation_binding.zig");
const framework = @import("air/framework_interaction.zig");
const universal = @import("air/universal_challenges.zig");
const schema = @import("../air/lookups/tables/schema.zig");
const Counter = @import("../air/lookups/tables/counter.zig").Counter;
const Table = @import("../air/lookups/tables/component.zig").LookupTableComponent;
const M = core.fields.m31.M31;
const Column = engine.pcs.ColumnEvaluation;
pub const Workspace = @import("blake3_native_parent_workspace.zig").Workspace;
const KINDS = [_]schema.Kind{ .bitwise, .range_check_8_8 };
pub fn Plan(comptime Backend: type) type {
    return PlanForProtocol(Backend, native_protocol);
}
/// Shared typed roster and persistent commitments with explicit protocol authority.
pub fn PlanForProtocol(comptime Backend: type, comptime protocol: type) type {
    return struct {
        const Self = @This();
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        allocator: std.mem.Allocator,
        arena: std.heap.ArenaAllocator,
        admission: protocol.Admission,
        definitions: Roster.Tuple(.definition),
        plans: Roster.Tuple(.plan),
        fixed: [Roster.Airs.len][]M,
        fixed_rows: [Roster.Airs.len]usize,
        templates: Roster.Tuple(.component),
        dummy_relations: universal.UniversalRelations,
        fixed_commitment: Scheme.CommittedTree,
        table_pp: [2]usize,
        pub fn init(a: std.mem.Allocator, prepared: *const native.Prepared, admission: protocol.Admission) !*Self {
            try admission.validate();
            const self = try a.create(Self);
            errdefer a.destroy(self);
            self.* = undefined;
            self.allocator = a;
            self.arena = std.heap.ArenaAllocator.init(a);
            errdefer self.arena.deinit();
            self.admission = admission;
            const temp = self.arena.allocator();
            var pp: std.ArrayList(Column) = .empty;
            defer {
                for (pp.items) |column| a.free(column.values);
                pp.deinit(a);
            }
            inline for (Roster.Airs, 0..) |Air, i| {
                const log = admission.key.log_sizes[i];
                if (log != rowLog(prepared.fixed[i].len)) return error.InvalidBlake3ParentRows;
                self.definitions[i] = if (@hasDecl(Air, "Location")) try Air.build(temp, .generated) else try Air.build(temp);
                self.plans[i] = try binding.Binding(Air).authenticate(&self.definitions[i]);
                const width = @typeInfo(Air.Row).array.len - Air.PHYSICAL_MAIN_COLUMN_COUNT;
                self.fixed_rows[i] = prepared.fixed[i].len;
                self.fixed[i] = try temp.alloc(M, try std.math.mul(usize, self.fixed_rows[i], width));
                for (prepared.fixed[i], 0..) |row, index| @memcpy(self.fixed[i][index * width ..][0..width], row[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
                try row_columns.project(Air, a, prepared.fixed[i], log, 0, &pp);
            }
            for (KINDS, &self.table_pp) |kind, *offset| {
                offset.* = pp.items.len;
                try row_columns.tablePreprocessed(a, kind, &pp);
            }
            self.dummy_relations = universal.UniversalRelations.dummy();
            const manifest = Roster.Manifest{ .log_sizes = admission.key.log_sizes };
            inline for (Roster.Airs, 0..) |Air, i| {
                const parameters = if (@hasDecl(Air, "PROOF_KIND_PARAMETER_COUNT")) native.selectors else [0]M{};
                self.templates[i] = try Roster.Component(Air).init(&self.definitions[i], self.plans[i], &manifest, @enumFromInt(i), admission.key.log_sizes[i], parameters, &self.dummy_relations, core.fields.qm31.QM31.zero());
            }

            var scheme = try Scheme.init(a, admission.key.config);
            defer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(.never);
            var channel = suite.Channel{};
            // Transfers projection storage on success and on failure.
            try scheme.commitOwned(a, try pp.toOwnedSlice(a), &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            try admission.admitRoot(roots.items[0]);
            try self.validateRows(prepared);
            try scheme.trees.items[0].share(a);
            self.fixed_commitment = scheme.trees.pop().?;
            return self;
        }
        pub fn deinit(self: *Self) void {
            const a = self.allocator;
            self.fixed_commitment.deinit(a);
            self.arena.deinit();
            a.destroy(self);
        }
        pub fn metadataBytes(self: *const Self) !usize {
            var total: usize = 0;
            for (self.fixed) |words| total = try std.math.add(usize, total, try std.math.mul(usize, words.len, @sizeOf(M)));
            return total;
        }
        pub fn validateRows(self: *const Self, prepared: *const native.Prepared) !void {
            try self.admission.validate();
            inline for (Roster.Airs, 0..) |Air, i| {
                if (prepared.fixed[i].len != self.fixed_rows[i]) return error.InvalidBlake3ParentRows;
                if (prepared.main[i].len != Air.PHYSICAL_MAIN_COLUMN_COUNT) return error.InvalidBlake3ParentRows;
                const log = self.admission.key.log_sizes[i];
                const size = @as(usize, 1) << @intCast(log);
                for (prepared.main[i]) |column| if (column.log_size != log or column.values.len != size) return error.InvalidBlake3ParentRows;
                const width = @typeInfo(Air.Row).array.len - Air.PHYSICAL_MAIN_COLUMN_COUNT;
                if (self.fixed[i].len != try std.math.mul(usize, self.fixed_rows[i], width)) return error.InvalidBlake3ParentRows;
                for (prepared.fixed[i], 0..) |row, index| {
                    for (row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], self.fixed[i][index * width ..][0..width]) |actual, expected| if (!actual.eql(expected)) return error.InvalidBlake3ParentRows;
                }
            }
        }
        /// Output owns its proof through `a` and does not borrow the plan or rows.
        pub fn prove(self: *const Self, a: std.mem.Allocator, prepared: *const native.Prepared) !artifact.Owned {
            var workspace = Workspace.init(a, 0);
            defer workspace.deinit();
            return self.proveWithWorkspace(a, prepared, &workspace);
        }
        /// One exclusive workspace per active worker. The output allocator must
        /// not be this workspace's arena; output survives reset and destruction.
        /// Plan, input rows and workspace must outlive this synchronous call.
        pub fn proveWithWorkspace(self: *const Self, a: std.mem.Allocator, prepared: *const native.Prepared, workspace: *Workspace) !artifact.Owned {
            try self.validateRows(prepared);
            const temp = try workspace.begin();
            defer workspace.end();
            if (workspace.outputAliasesScratch(a)) return error.ParentOutputAllocatorAliasesScratch;
            const rows = prepared.fixed;
            var padding: std.meta.Tuple(&blk: {
                var types: [Roster.Airs.len]type = undefined;
                for (Roster.Airs, &types) |Air, *T| T.* = Air.Row;
                break :blk types;
            }) = undefined;
            var main: std.ArrayList(Column) = .empty;
            var main_starts: [Roster.Airs.len]usize = undefined;
            const interaction_count = comptime blk: {
                var count: usize = 2 * @import("../air/lookups/tables/interaction.zig").N_COLUMNS;
                for (Roster.Airs) |Air| count += Air.INTERACTION_COLUMN_COUNT;
                break :blk count;
            };
            var interaction = try std.ArrayList(Column).initCapacity(a, interaction_count);
            defer {
                for (interaction.items) |column| a.free(column.values);
                interaction.deinit(a);
            }
            var counters = [2]Counter{ try Counter.init(temp, .bitwise), try Counter.init(temp, .range_check_8_8) };
            inline for (Roster.Airs, 0..) |Air, i| {
                const log = self.admission.key.log_sizes[i];
                padding[i] = @splat(M.zero());
                if (@hasDecl(Air, "PROOF_KIND_PARAMETER_COUNT")) padding[i][Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT ..].* = native.selectors;
                main_starts[i] = main.items.len;
                try main.appendSlice(temp, prepared.main[i]);
                const view = try row_columns.compactColumnView(Air, main.items[main_starts[i]..][0..Air.PHYSICAL_MAIN_COLUMN_COUNT], self.fixed[i], rows[i].len, log);
                try row_columns.registerColumns(Air, &self.plans[i], view, log, &counters);
                const size = @as(usize, 1) << @intCast(log);
                try row_columns.registerRepeated(Air, &self.plans[i], padding[i], size - rows[i].len, &counters);
            }
            const table_main = main.items.len;
            for (KINDS, &counters) |kind, *counter| try main.append(temp, .{ .log_size = schema.logSize(kind), .values = try counter.committedColumn(temp) });
            var channel = suite.Channel{};
            try self.admission.mix(&channel);
            var scheme = try Scheme.init(a, try self.admission.config());
            // Extended-domain columns already suffice for opening. Retaining
            // another coefficient copy exhausts canonical parent worker budgets.
            scheme.setCoefficientRetentionPolicy(.never);
            var owns_scheme = true;
            defer if (owns_scheme) scheme.deinit(a);
            {
                var fixed = self.fixed_commitment.retainShared();
                errdefer fixed.deinit(a);
                try scheme.appendCommittedTree(a, fixed, &channel);
            }
            workspace.phase = .main_commitment;
            try scheme.commit(a, main.items, &channel);
            const relations = try universal.UniversalRelations.draw(temp, &channel);
            const providers = try @import("air/universal_provider_relations.zig").SharedProviderRelations.init(&relations);
            workspace.phase = .interaction_generation;
            var claims: artifact.Claims = undefined;
            {
                // Cohorts execute serially: inversion scratch has no cross-cohort
                // consumers and must not accumulate with committed output staging.
                var scratch_count: usize = 0;
                inline for (Roster.Airs, 0..) |Air, i| {
                    const Runtime = framework.Runtime(binding.Binding(Air).Runtime);
                    scratch_count = @max(scratch_count, try Runtime.requiredScratchElementCount(@min(self.admission.key.log_sizes[i], framework.OWNED_TILE_LOG_SIZE)));
                }
                const scratch = try a.alloc(core.fields.qm31.QM31, scratch_count);
                defer a.free(scratch);
                inline for (Roster.Airs, 0..) |Air, i| {
                    const Runtime = framework.Runtime(binding.Binding(Air).Runtime);
                    const view = try row_columns.compactColumnView(Air, main.items[main_starts[i]..][0..Air.PHYSICAL_MAIN_COLUMN_COUNT], self.fixed[i], rows[i].len, self.admission.key.log_sizes[i]);
                    const log = self.admission.key.log_sizes[i];
                    const tile_log = @min(log, framework.OWNED_TILE_LOG_SIZE);
                    var inversion = Runtime.Workspace{ .allocator = a, .capacity_log_size = tile_log, .scratch = scratch[0..try Runtime.requiredScratchElementCount(tile_log)] };
                    const generated = try Runtime.generatePreparedOwnedColumnsTiledWithWorkspace(a, &inversion, &self.plans[i], view, log, &relations, padding[i]);
                    claims[i] = generated.claimed_sum;
                    for (generated.columns) |column| interaction.appendAssumeCapacity(.{ .log_size = self.admission.key.log_sizes[i], .values = column });
                }
            }
            const table_interaction = interaction.items.len;
            for (&counters, KINDS, Roster.Airs.len..) |*counter, kind, i| {
                const generated = try @import("../air/lookups/tables/interaction.zig").generate(a, counter, &providers.native);
                claims[i] = generated.claim;
                for (generated.columns) |column| interaction.appendAssumeCapacity(.{ .log_size = schema.logSize(kind), .values = column });
            }
            try artifact.validateClaims(claims);
            try self.admission.mixClaims(&channel, &claims);
            if (interaction.items.len != interaction_count) return error.InvalidBlake3ParentRows;
            // commitOwned consumes columns on every path. toOwnedSlice clears
            // the local list, so failure cleanup cannot free transferred values.
            workspace.phase = .interaction_commitment;
            // Bound preparation even for backends preferring monolithic commits.
            // The streaming PCS preserves original column indices and tree roots.
            try scheme.commitOwnedStreaming(a, try interaction.toOwnedSlice(a), 8, &channel);
            // Both commitments own their columns. Relations/providers are inline
            // values; only offsets and claims survive from staging into the core.
            workspace.releaseScratch();
            var components = self.templates;
            var provers: [artifact.CLAIM_COUNT]engine.air.component_prover.ComponentProver = undefined;
            inline for (Roster.Airs, 0..) |Air, i| {
                _ = Air;
                components[i].relations = &relations;
                components[i].claimed_sum = claims[i];
                components[i].claimed_sum_shift = try claims[i].divM31(M.fromU64(@as(u64, 1) << @intCast(self.admission.key.log_sizes[i])));
                provers[i] = components[i].asProverComponent();
            }
            var tables: [2]Table = undefined;
            for (&tables, KINDS, self.table_pp, 0..) |*table, kind, offset, i| {
                var tuple: [schema.MAX_ARITY]usize = undefined;
                for (tuple[0..schema.arity(kind)], 0..) |*column, j| column.* = offset + 1 + j;
                table.* = try Table.initProver(kind, offset, tuple[0..schema.arity(kind)], table_main + i, table_interaction + 4 * i, &providers.native, claims[Roster.Airs.len + i]);
                provers[Roster.Airs.len + i] = table.asProverComponent();
            }
            workspace.phase = .core_proof;
            owns_scheme = false; // Core proving consumes the scheme on all paths.
            var extended = try engine.prove.proveExWithExecutionDiagnosed(Backend, suite.Hasher, suite.MerkleChannel, a, &provers, &channel, scheme, false, null, null, null, &workspace.core_diagnostic);
            extended.aux.deinit(a);
            var owned = artifact.Owned.init(a, extended.proof, self.admission.expected_id, claims);
            errdefer owned.deinit();
            try owned.validate(&self.admission);
            workspace.phase = .complete;
            return owned;
        }
    };
}
fn rowLog(count: usize) u32 {
    return if (count <= 1) 1 else std.math.log2_int_ceil(usize, count);
}
