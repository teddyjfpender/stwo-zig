//! Backend-injected standalone parent proving with immutable per-key preparation.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const stage_profile = engine.stage_profile;
const suite = @import("blake3_engine_protocol.zig");
const native_protocol = @import("blake3_native_parent_protocol.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
const native = @import("air/blake3_native_parent_rows.zig");
const Roster = @import("air/blake3_native_parent_roster.zig").Roster;
const row_columns = @import("air/blake3_row_columns.zig");
const binding = @import("air/universal_relation_binding.zig");
const framework = @import("air/framework_interaction.zig");
const device = @import("blake3_native_parent_device_interactions.zig");
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
        device_programs: [Roster.Airs.len]?device.Program,
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
            self.device_programs = @splat(null);
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
                self.device_programs[i] = try device.prepare(Backend, Air, temp, &self.definitions[i], &self.plans[i]);
                const width = @typeInfo(Air.Row).array.len - Air.PHYSICAL_MAIN_COLUMN_COUNT;
                self.fixed_rows[i] = prepared.fixed[i].len;
                self.fixed[i] = try temp.alloc(M, try std.math.mul(usize, self.fixed_rows[i], width));
                for (prepared.fixed[i], 0..) |row, index| @memcpy(self.fixed[i][index * width ..][0..width], &row);
                try row_columns.projectFixed(Air, a, prepared.fixed[i], log, &pp);
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
        /// Called only under the worker's exclusive lease. Reuse structural
        /// custody, never transcript state: the next proof mixes the new key.
        /// A failed comparison leaves the existing admission unchanged.
        pub fn tryRebindAdmission(self: *Self, prepared: *const native.Prepared, admission: protocol.Admission) !bool {
            try admission.validate();
            var previous_config = self.admission.key.config;
            var next_config = admission.key.config;
            // These affect transcript/FRI sampling, not committed fixed columns.
            previous_config.pow_bits = 0;
            next_config.pow_bits = 0;
            previous_config.fri_config.n_queries = 0;
            next_config.fri_config.n_queries = 0;
            if (!std.meta.eql(previous_config, next_config) or
                !std.meta.eql(self.admission.key.log_sizes, admission.key.log_sizes) or
                !std.mem.eql(u8, &self.admission.key.preprocessed_root, &admission.key.preprocessed_root)) return false;
            self.validateRows(prepared) catch |err| switch (err) {
                error.InvalidBlake3ParentRows => return false,
                else => return err,
            };
            self.admission = admission;
            return true;
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
                    for (row, self.fixed[i][index * width ..][0..width]) |actual, expected| if (!actual.eql(expected)) return error.InvalidBlake3ParentRows;
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
            var recorder = stage_profile.Recorder.initWithOptions(a, "native", "blake3-recursive-parent", .{ .capture_tasks = false });
            defer recorder.deinit();
            const diagnostic: ?*stage_profile.Recorder = if (std.process.hasEnvVarConstant("STWO_RISCV_RECURSIVE_PARENT_PROFILE")) &recorder else null;
            var phase = try stage_profile.StageScope.begin(diagnostic, "parent.validation", "Authenticated row validation");
            defer phase.end();
            try self.validateRows(prepared);
            phase.end();
            phase = try stage_profile.StageScope.begin(diagnostic, "parent.main_setup", "Main columns and lookup counts");
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
                try @import("air/blake3_parallel_lookup_counts.zig").register(Air, a, &self.plans[i], view, log, &counters);
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
            phase.end();
            phase = try stage_profile.StageScope.begin(diagnostic, "parent.main_commit", "Main commitment");
            workspace.phase = .main_commitment;
            // Keep the admitted source columns alive for interactions, while
            // bounding preparation and reusing lifted Merkle prefixes.
            if (std.process.hasEnvVarConstant("STWO_RISCV_PARENT_MONOLITHIC_MAIN")) {
                try scheme.commit(a, main.items, &channel);
            } else {
                try scheme.commitBorrowedStreaming(a, main.items, @import("../prover/blake3_coefficient_retention.zig").streamingBatchColumns(), &channel);
            }
            phase.end();
            phase = try stage_profile.StageScope.begin(diagnostic, "parent.interaction_generation", "Interaction generation");
            const relations = try universal.UniversalRelations.draw(temp, &channel);
            const providers = try @import("air/universal_provider_relations.zig").SharedProviderRelations.init(&relations);
            workspace.phase = .interaction_generation;
            var claims: artifact.Claims = undefined;
            {
                // Cohorts execute serially: inversion scratch has no cross-cohort
                // consumers and must not accumulate with committed output staging.
                const allow_device = !std.process.hasEnvVarConstant("STWO_RISCV_CPU_PARENT_INTERACTIONS");
                var scratch_count: usize = 0;
                inline for (Roster.Airs, 0..) |Air, i| {
                    const Runtime = framework.Runtime(binding.Binding(Air).Runtime);
                    if (!allow_device or self.device_programs[i] == null) scratch_count = @max(scratch_count, try Runtime.requiredScratchElementCount(@min(self.admission.key.log_sizes[i], framework.OWNED_TILE_LOG_SIZE)));
                }
                const scratch = try a.alloc(core.fields.qm31.QM31, scratch_count);
                defer a.free(scratch);
                inline for (Roster.Airs, 0..) |Air, i| {
                    const view = try row_columns.compactColumnView(Air, main.items[main_starts[i]..][0..Air.PHYSICAL_MAIN_COLUMN_COUNT], self.fixed[i], rows[i].len, self.admission.key.log_sizes[i]);
                    const log = self.admission.key.log_sizes[i];
                    const program: ?*const device.Program = if (allow_device) if (self.device_programs[i]) |*program| program else null else null;
                    const generated = try device.generate(Backend, Air, a, program, &self.plans[i], view, prepared.fixed[i], log, &relations, padding[i], scratch);
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
            phase.end();
            phase = try stage_profile.StageScope.begin(diagnostic, "parent.interaction_commit", "Interaction commitment");
            workspace.phase = .interaction_commitment;
            // Bound preparation even for backends preferring monolithic commits.
            // The streaming PCS preserves original column indices and tree roots.
            try scheme.commitOwnedStreaming(a, try interaction.toOwnedSlice(a), @import("../prover/blake3_coefficient_retention.zig").streamingBatchColumns(), &channel);
            // Both commitments own their columns. Relations/providers are inline
            // values; only offsets and claims survive from staging into the core.
            phase.end();
            phase = try stage_profile.StageScope.begin(diagnostic, "parent.core", "Core STARK proof");
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
            var extended = try engine.prove.proveExWithExecutionDiagnosed(Backend, suite.Hasher, suite.MerkleChannel, a, &provers, &channel, scheme, false, diagnostic, null, null, &workspace.core_diagnostic);
            extended.aux.deinit(a);
            var owned = artifact.Owned.init(a, extended.proof, self.admission.expected_id, claims);
            errdefer owned.deinit();
            try owned.validate(&self.admission);
            workspace.phase = .complete;
            phase.end();
            if (diagnostic != null) {
                var snapshot = try recorder.snapshot(a);
                defer snapshot.deinit(a);
                const json = try std.json.Stringify.valueAlloc(a, snapshot, .{});
                defer a.free(json);
                std.debug.print("BLAKE3_PARENT_STAGE_PROFILE {s}\n", .{json});
            }
            return owned;
        }
    };
}
fn rowLog(count: usize) u32 {
    return if (count <= 1) 1 else std.math.log2_int_ceil(usize, count);
}
