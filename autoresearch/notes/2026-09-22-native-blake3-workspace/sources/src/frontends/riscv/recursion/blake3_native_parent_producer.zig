//! Backend-injected standalone parent proving with immutable per-key preparation.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = @import("blake3_engine_protocol.zig");
const protocol = @import("blake3_native_parent_protocol.zig");
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
const Rows = @FieldType(native.Prepared, "rows");
pub const Workspace = @import("blake3_native_parent_workspace.zig").Workspace;
const KINDS = [_]schema.Kind{ .bitwise, .range_check_8_8 };
pub fn Plan(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        allocator: std.mem.Allocator,
        arena: std.heap.ArenaAllocator,
        admission: protocol.Admission,
        definitions: Roster.Tuple(.definition),
        plans: Roster.Tuple(.plan),
        fixed: Rows,
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
            var pp_arena = std.heap.ArenaAllocator.init(a);
            defer pp_arena.deinit();
            const pp_allocator = pp_arena.allocator();
            var pp: std.ArrayList(Column) = .empty;
            inline for (Roster.Airs, 0..) |Air, i| {
                const log = admission.key.log_sizes[i];
                if (log != rowLog(prepared.fixed[i].len)) return error.InvalidBlake3ParentRows;
                self.definitions[i] = if (@hasDecl(Air, "Location")) try Air.build(temp, .generated) else try Air.build(temp);
                self.plans[i] = try binding.Binding(Air).authenticate(&self.definitions[i]);
                self.fixed[i] = try temp.dupe(Air.Row, prepared.fixed[i]);
                for (self.fixed[i]) |*row| @memset(row[0..Air.PHYSICAL_MAIN_COLUMN_COUNT], M.zero());
                try row_columns.project(Air, pp_allocator, self.fixed[i], log, 0, &pp);
            }
            for (KINDS, &self.table_pp) |kind, *offset| {
                offset.* = pp.items.len;
                try row_columns.tablePreprocessed(pp_allocator, kind, &pp);
            }
            const preprocessed = pp.items;
            self.dummy_relations = universal.UniversalRelations.dummy();
            const manifest = Roster.Manifest{ .log_sizes = admission.key.log_sizes };
            inline for (Roster.Airs, 0..) |Air, i| {
                const parameters = if (i >= 3 and i <= 5) native.selectors else [0]M{};
                self.templates[i] = try Roster.Component(Air).init(&self.definitions[i], self.plans[i], &manifest, @enumFromInt(i), admission.key.log_sizes[i], parameters, &self.dummy_relations, core.fields.qm31.QM31.zero());
            }

            var scheme = try Scheme.init(a, admission.key.config);
            defer scheme.deinit(a);
            var channel = suite.Channel{};
            try scheme.commit(a, preprocessed, &channel);
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
        pub fn validateRows(self: *const Self, prepared: *const native.Prepared) !void {
            try self.admission.validate();
            inline for (Roster.Airs, 0..) |Air, i| {
                if (prepared.rows[i].len != self.fixed[i].len) return error.InvalidBlake3ParentRows;
                for (prepared.rows[i], self.fixed[i]) |row, fixed| {
                    for (row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], fixed[Air.PHYSICAL_MAIN_COLUMN_COUNT..]) |actual, expected| if (!actual.eql(expected)) return error.InvalidBlake3ParentRows;
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
            if (a.ptr == temp.ptr and a.vtable == temp.vtable) return error.ParentOutputAllocatorAliasesScratch;
            var rows: Rows = undefined;
            var main: std.ArrayList(Column) = .empty;
            var interaction: std.ArrayList(Column) = .empty;
            var counters = [2]Counter{ try Counter.init(temp, .bitwise), try Counter.init(temp, .range_check_8_8) };
            inline for (Roster.Airs, 0..) |Air, i| {
                const log = self.admission.key.log_sizes[i];
                rows[i] = try row_columns.padded(Air, temp, prepared.rows[i], log);
                if (i >= 3 and i <= 5) for (rows[i]) |*row| {
                    row[Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT ..].* = native.selectors;
                };
                try row_columns.project(Air, temp, rows[i], log, 1, &main);
                try row_columns.register(Air, &self.plans[i], rows[i], &counters);
            }
            const table_main = main.items.len;
            for (KINDS, &counters) |kind, *counter| try main.append(temp, .{ .log_size = schema.logSize(kind), .values = try counter.committedColumn(temp) });
            var channel = suite.Channel{};
            try self.admission.mix(&channel);
            var scheme = try Scheme.init(a, try self.admission.config());
            var owns_scheme = true;
            defer if (owns_scheme) scheme.deinit(a);
            {
                var fixed = self.fixed_commitment.retainShared();
                errdefer fixed.deinit(a);
                try scheme.appendCommittedTree(a, fixed, &channel);
            }
            try scheme.commit(a, main.items, &channel);
            const relations = try universal.UniversalRelations.draw(temp, &channel);
            const providers = try @import("air/universal_provider_relations.zig").SharedProviderRelations.init(&relations);
            var claims: artifact.Claims = undefined;
            inline for (Roster.Airs, 0..) |Air, i| {
                const generated = try framework.Runtime(binding.Binding(Air).Runtime).generatePrepared(temp, &self.plans[i], rows[i], self.admission.key.log_sizes[i], &relations);
                claims[i] = generated.claimed_sum;
                for (generated.columns) |column| try interaction.append(temp, .{ .log_size = self.admission.key.log_sizes[i], .values = column });
            }
            const table_interaction = interaction.items.len;
            for (&counters, KINDS, Roster.Airs.len..) |*counter, kind, i| {
                const generated = try @import("../air/lookups/tables/interaction.zig").generate(temp, counter, &providers.native);
                claims[i] = generated.claim;
                for (generated.columns) |column| try interaction.append(temp, .{ .log_size = schema.logSize(kind), .values = column });
            }
            try artifact.validateClaims(claims);
            try self.admission.mixClaims(&channel, &claims);
            try scheme.commit(a, interaction.items, &channel);
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
            owns_scheme = false; // Core proving consumes the scheme on all paths.
            const proof = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, &provers, &channel, scheme);
            var owned = artifact.Owned.init(a, proof, self.admission.expected_id, claims);
            errdefer owned.deinit();
            try owned.validate(&self.admission);
            return owned;
        }
    };
}
fn rowLog(count: usize) u32 {
    return if (count <= 1) 1 else std.math.log2_int_ceil(usize, count);
}
