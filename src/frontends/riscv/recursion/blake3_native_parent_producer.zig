//! Backend-injected standalone parent proving with immutable per-key preparation.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const stage_profile = engine.stage_profile;
const suite = @import("blake3_engine_protocol.zig");
const native_protocol = @import("blake3_native_parent_protocol.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
const native = @import("air/blake3_native_parent_rows.zig");
const FixedGuard = @import("blake3_parent_fixed_row_guard_v1.zig");
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
    return PlanKernel(Backend, protocol, false);
}
/// Persistent workers must explicitly bind each request's original admission.
/// Current public values/schedules are synchronous borrows, never setup data.
/// The default plan retains its existing borrowing API and field type.
pub fn PlanForProtocolScopedAdmission(comptime Backend: type, comptime protocol: type) type {
    return PlanKernel(Backend, protocol, true);
}
fn PlanKernel(comptime Backend: type, comptime protocol: type, comptime scoped_admission: bool) type {
    const Borrow = @import("blake3_parent_admission_borrow_v1.zig").For(protocol.Admission);
    return struct {
        const Self = @This();
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        allocator: std.mem.Allocator,
        arena: std.heap.ArenaAllocator,
        admission: if (scoped_admission) Borrow else protocol.Admission,
        template_key: protocol.Key,
        definitions: Roster.Tuple(.definition),
        plans: Roster.Tuple(.plan),
        device_programs: [Roster.Airs.len]?device.Program,
        fixed_digests: [Roster.Airs.len][32]u8,
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
            if (scoped_admission) {
                self.admission = .{};
                self.admission.bind(admission);
            } else self.admission = admission;
            self.template_key = admission.key;
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
                self.fixed_rows[i] = prepared.fixed[i].len;
                self.fixed_digests[i] = fixedDigest(prepared.fixed[i]);
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
            if (Backend.MerkleTree(suite.Hasher) == engine.vcs_lifted.prover.MerkleProverLifted(suite.Hasher) and !std.process.hasEnvVarConstant("STWO_RISCV_MATERIALIZED_POLYNOMIALS"))
                scheme.setCompactPolynomialStorage(20)
            else
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
            self.releaseAdmission(); // Scoped constructor exports no dynamic borrow.
            return self;
        }
        pub fn deinit(self: *Self) void {
            const a = self.allocator;
            self.fixed_commitment.deinit(a);
            self.arena.deinit();
            a.destroy(self);
        }
        pub fn metadataBytes(self: *const Self) !usize {
            return @sizeOf(@TypeOf(self.fixed_digests)) + @sizeOf(@TypeOf(self.fixed_rows));
        }
        fn currentAdmission(self: *const Self) !*const protocol.Admission {
            if (scoped_admission) return self.admission.require() else return &self.admission;
        }
        /// Called under the exclusive worker lease on every return, including
        /// rejected preflight and proof errors. Default plans retain old API.
        pub fn releaseAdmission(self: *Self) void {
            if (scoped_admission) self.admission.release();
        }
        fn compatibleFixedKey(self: *const Self, key: protocol.Key) bool {
            var previous_config = self.template_key.config;
            var next_config = key.config;
            // Original same-fixed policy: these affect transcript/FRI sampling.
            previous_config.pow_bits = 0;
            next_config.pow_bits = 0;
            previous_config.fri_config.n_queries = 0;
            next_config.fri_config.n_queries = 0;
            return std.meta.eql(previous_config, next_config) and
                std.meta.eql(self.template_key.log_sizes, key.log_sizes) and
                std.mem.eql(u8, &self.template_key.preprocessed_root, &key.preprocessed_root);
        }
        /// Called only under the worker's exclusive lease. Reuse structural
        /// custody, never prior request values. Authenticate supplied current
        /// admission and exact fixed rows before replacing the borrow.
        pub fn tryRebindAdmission(self: *Self, prepared: *const native.Prepared, admission: protocol.Admission) !bool {
            try admission.validate();
            if (!self.compatibleFixedKey(admission.key)) return false;
            self.validateRowsForAdmission(prepared, admission) catch |err| switch (err) {
                error.InvalidBlake3ParentRows => return false,
                else => return err,
            };
            if (scoped_admission) self.admission.bind(admission) else self.admission = admission;
            self.template_key = admission.key;
            return true;
        }
        pub fn validateRows(self: *const Self, prepared: *const native.Prepared) !void {
            return self.validateRowsForAdmission(prepared, (try self.currentAdmission()).*);
        }
        /// Full original public admission + fixed digest/row/column/log guards,
        /// using this request's values. Never reads an earlier dynamic borrow.
        pub fn validateRowsForAdmission(self: *const Self, prepared: *const native.Prepared, admission: protocol.Admission) !void {
            try admission.validate();
            if (!self.compatibleFixedKey(admission.key)) return error.InvalidBlake3ParentRows;
            try FixedGuard.ForAirs(Roster.Airs).require(prepared, &admission.key.log_sizes, &self.fixed_rows, &self.fixed_digests);
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
            return self.proveWithWorkspaceMode(a, prepared, workspace, null);
        }
        /// Consume one-shot source rows on success or error. Their last reader
        /// is interaction generation, before interaction commitment and FRI.
        pub fn proveConsumingWithWorkspace(self: *const Self, a: std.mem.Allocator, prepared: *native.Prepared, workspace: *Workspace) !artifact.Owned {
            defer prepared.releaseRows();
            return self.proveWithWorkspaceMode(a, prepared, workspace, prepared);
        }
        fn proveWithWorkspaceMode(self: *const Self, a: std.mem.Allocator, prepared: *const native.Prepared, workspace: *Workspace, consumed: ?*native.Prepared) !artifact.Owned {
            const admission = try self.currentAdmission();
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
                const log = admission.key.log_sizes[i];
                padding[i] = @splat(M.zero());
                if (@hasDecl(Air, "PROOF_KIND_PARAMETER_COUNT")) padding[i][Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT ..].* = native.selectors;
                main_starts[i] = main.items.len;
                try main.appendSlice(temp, prepared.main[i]);
                const view = try row_columns.compactColumnView(Air, main.items[main_starts[i]..][0..Air.PHYSICAL_MAIN_COLUMN_COUNT], std.mem.bytesAsSlice(M, std.mem.sliceAsBytes(prepared.fixed[i])), rows[i].len, log);
                try @import("air/blake3_parallel_lookup_counts.zig").register(Air, a, &self.plans[i], view, log, &counters);
                const size = @as(usize, 1) << @intCast(log);
                try row_columns.registerRepeated(Air, &self.plans[i], padding[i], size - rows[i].len, &counters);
            }
            const table_main = main.items.len;
            for (KINDS, &counters) |kind, *counter| try main.append(temp, .{ .log_size = schema.logSize(kind), .values = try counter.committedColumn(temp) });
            var channel = suite.Channel{};
            try admission.mix(&channel);
            var scheme = try Scheme.init(a, try admission.config());
            // Extended-domain columns already suffice for opening. Retaining
            // another coefficient copy exhausts canonical parent worker budgets.
            if (Backend.MerkleTree(suite.Hasher) == engine.vcs_lifted.prover.MerkleProverLifted(suite.Hasher) and !std.process.hasEnvVarConstant("STWO_RISCV_MATERIALIZED_POLYNOMIALS"))
                scheme.setCompactPolynomialStorage(20)
            else
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
            engine.host_budget_allocator.SharedHostBudget.reportStage(a, "parent.main_commitment");
            // Keep the admitted source columns alive for interactions, while
            // bounding preparation and reusing lifted Merkle prefixes.
            if (std.process.hasEnvVarConstant("STWO_RISCV_PARENT_MONOLITHIC_MAIN")) {
                try scheme.commit(a, main.items, &channel);
            } else {
                try scheme.commitBorrowedStreamingWithRecorder(a, main.items, @import("../prover/blake3_coefficient_retention.zig").streamingBatchColumns(), diagnostic, &channel);
            }
            phase.end();
            phase = try stage_profile.StageScope.begin(diagnostic, "parent.interaction_generation", "Interaction generation");
            const relations = try universal.UniversalRelations.draw(temp, &channel);
            const providers = try @import("air/universal_provider_relations.zig").SharedProviderRelations.init(&relations);
            workspace.phase = .interaction_generation;
            engine.host_budget_allocator.SharedHostBudget.reportStage(a, "parent.interaction_generation");
            var claims: artifact.Claims = undefined;
            {
                // Cohorts execute serially: inversion scratch has no cross-cohort
                // consumers and must not accumulate with committed output staging.
                const allow_device = !std.process.hasEnvVarConstant("STWO_RISCV_CPU_PARENT_INTERACTIONS");
                var scratch_count: usize = 0;
                inline for (Roster.Airs, 0..) |Air, i| {
                    const Runtime = framework.Runtime(binding.Binding(Air).Runtime);
                    if (!allow_device or self.device_programs[i] == null) scratch_count = @max(scratch_count, try Runtime.requiredScratchElementCount(@min(admission.key.log_sizes[i], framework.OWNED_TILE_LOG_SIZE)));
                }
                const scratch = try a.alloc(core.fields.qm31.QM31, scratch_count);
                defer a.free(scratch);
                inline for (Roster.Airs, 0..) |Air, i| {
                    const view = try row_columns.compactColumnView(Air, main.items[main_starts[i]..][0..Air.PHYSICAL_MAIN_COLUMN_COUNT], std.mem.bytesAsSlice(M, std.mem.sliceAsBytes(prepared.fixed[i])), rows[i].len, admission.key.log_sizes[i]);
                    const log = admission.key.log_sizes[i];
                    const program: ?*const device.Program = if (allow_device) if (self.device_programs[i]) |*program| program else null else null;
                    const generated = try device.generate(Backend, Air, a, program, &self.plans[i], view, prepared.fixed[i], log, &relations, padding[i], scratch);
                    claims[i] = generated.claimed_sum;
                    for (generated.columns) |column| interaction.appendAssumeCapacity(.{ .log_size = admission.key.log_sizes[i], .values = column });
                    // The committed main tree owns its extended evaluations.
                    // This cohort's final source reader has completed; retaining
                    // it until later cohorts finish needlessly overlaps buffers.
                    if (consumed) |source| source.releaseCohort(i);
                }
            }
            // Commitments own extended-domain values; all source-row readers
            // above have finished. The plan separately owns fixed metadata.
            if (consumed) |source| source.releaseRows();
            const table_interaction = interaction.items.len;
            for (&counters, KINDS, Roster.Airs.len..) |*counter, kind, i| {
                const generated = try @import("../air/lookups/tables/interaction.zig").generate(a, counter, &providers.native);
                claims[i] = generated.claim;
                for (generated.columns) |column| interaction.appendAssumeCapacity(.{ .log_size = schema.logSize(kind), .values = column });
            }
            try artifact.validateClosure(claims, admission, relations);
            try admission.mixClaims(&channel, &claims);
            if (interaction.items.len != interaction_count) return error.InvalidBlake3ParentRows;
            // commitOwned consumes columns on every path. toOwnedSlice clears
            // the local list, so failure cleanup cannot free transferred values.
            phase.end();
            phase = try stage_profile.StageScope.begin(diagnostic, "parent.interaction_commit", "Interaction commitment");
            workspace.phase = .interaction_commitment;
            engine.host_budget_allocator.SharedHostBudget.reportStage(a, "parent.interaction_commitment");
            // Bound preparation even for backends preferring monolithic commits.
            // The streaming PCS preserves original column indices and tree roots.
            try scheme.commitOwnedStreamingWithRecorder(a, try interaction.toOwnedSlice(a), @import("../prover/blake3_coefficient_retention.zig").streamingBatchColumns(), diagnostic, &channel);
            // Both commitments own their columns. Relations/providers are inline
            // values; only offsets and claims survive from staging into the core.
            phase.end();
            phase = try stage_profile.StageScope.begin(diagnostic, "parent.core", "Core STARK proof");
            workspace.releaseScratch();
            var components = self.templates;
            var provers: [artifact.CLAIM_COUNT]engine.air.component_prover.ComponentProver = undefined;
            inline for (Roster.Airs, 0..) |Air, i| {
                components[i].relations = &relations;
                components[i].claimed_sum = claims[i];
                components[i].claimed_sum_shift = try claims[i].divM31(M.fromU64(@as(u64, 1) << @intCast(admission.key.log_sizes[i])));
                provers[i] = try @import("air/roster_composition_geometry.zig").ForAirs(Roster.Airs).component(Air, components[i].asProverComponent());
            }
            var tables: [2]Table = undefined;
            for (&tables, KINDS, self.table_pp, 0..) |*table, kind, offset, i| {
                var tuple: [schema.MAX_ARITY]usize = undefined;
                for (tuple[0..schema.arity(kind)], 0..) |*column, j| column.* = offset + 1 + j;
                table.* = try Table.initProver(kind, offset, tuple[0..schema.arity(kind)], table_main + i, table_interaction + 4 * i, &providers.native, claims[Roster.Airs.len + i]);
                provers[Roster.Airs.len + i] = try @import("air/roster_composition_geometry.zig").ForAirs(Roster.Airs).table(table.asProverComponent());
            }
            workspace.phase = .core_proof;
            engine.host_budget_allocator.SharedHostBudget.reportStage(a, "parent.core_proof");
            owns_scheme = false; // Core proving consumes the scheme on all paths.
            var extended = try engine.prove.proveExWithExecutionDiagnosed(Backend, suite.Hasher, suite.MerkleChannel, a, &provers, &channel, scheme, false, diagnostic, null, .{
                .worker_count = if (engine.work_pool.getGlobalPool()) |pool| pool.workerCount() else 1,
                .host_byte_budget = std.math.maxInt(usize),
                .contention_policy = .compatibility,
                .preparation = .streamed,
            }, &workspace.core_diagnostic);
            extended.aux.deinit(a);
            var owned = artifact.Owned.init(a, extended.proof, admission.expected_id, claims);
            errdefer owned.deinit();
            try owned.validate(admission);
            workspace.phase = .complete;
            engine.host_budget_allocator.SharedHostBudget.reportStage(a, "parent.complete");
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

/// Internal content identity for metadata whose fixed commitment was independently
/// admitted at plan construction. Rows remain owned by the current preparation;
/// the persistent plan retains no second copy. Length/roster/log are checked
/// separately before digest comparison. This is not a caller-supplied receipt.
fn fixedDigest(rows: anytype) [32]u8 {
    return FixedGuard.fixedDigest(rows);
}
