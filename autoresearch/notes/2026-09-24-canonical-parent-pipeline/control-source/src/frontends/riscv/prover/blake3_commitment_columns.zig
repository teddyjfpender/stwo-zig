//! Persistent final-layout columns for admitted BLAKE3 commitment components.
//! Fixed columns and authenticated typed definitions are prepared once. Each
//! witness overwrites the same main-column buffers through bounded word emission.
const std = @import("std");
const core = @import("stwo_core");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const M = core.fields.m31.M31;
const components = @import("blake3_commitment_components.zig");
const admission_mod = @import("blake3_commitment_plan.zig");
const Witness = @import("blake3_commitment_witness.zig").Witness;
const binding = @import("../recursion/air/universal_relation_binding.zig");
const framework = @import("../recursion/air/framework_interaction.zig");
const writer = @import("../recursion/air/framework_device_interaction.zig");
const roster = components.Roster;
const N = components.Airs.len;
const Universal = @import("../recursion/air/universal_challenges.zig").UniversalRelations;
const DeviceProgram = @import("stwo_prover_engine").air.component_prover.OwnedFrameworkPolynomialProgramV1;
fn Workspaces() type {
    var types: [N]type = undefined;
    for (components.Airs, &types) |Air, *T| T.* = framework.Runtime(binding.Binding(Air).Runtime).Workspace;
    return std.meta.Tuple(&types);
}
pub const InteractionColumns = struct {
    allocator: std.mem.Allocator,
    columns: std.ArrayList(Column) = .empty,
    claims: [N]core.fields.qm31.QM31 = undefined,
    pub fn deinit(self: *InteractionColumns) void {
        for (self.columns.items) |column| self.allocator.free(column.values);
        self.columns.deinit(self.allocator);
        self.* = undefined;
    }
};
pub const Counts = [N]usize;
/// Admission geometry without allocating fixed/main columns or typed plans.
pub fn traceLogs(a: std.mem.Allocator, admission: admission_mod.Admission) ![N]u32 {
    return logsForCounts(try rowCounts(a, admission));
}
/// Shared topology depends on the admitted address set, not merely word count.
pub fn rowCounts(a: std.mem.Allocator, admission: admission_mod.Admission) !Counts {
    var census = Census{};
    try components.emitTrusted(a, admission, &census);
    return census.counts;
}

fn logsForCounts(counts: Counts) ![N]u32 {
    var logs: [N]u32 = undefined;
    for (counts, &logs) |count, *log| {
        log.* = @max(1, std.math.log2_int_ceil(usize, @max(1, count)));
        if (log.* > 24) return error.CommitmentTraceTooLarge;
    }
    return logs;
}

pub const Owner = struct {
    allocator: std.mem.Allocator,
    plan_id: [32]u8,
    counts: Counts,
    logs: [N]u32,
    columns: [2]std.ArrayList(Column) = @splat(.empty),
    offsets: [2][N]usize = @splat(@splat(0)),
    definitions: roster.Tuple(.definition) = undefined,
    plans: roster.Tuple(.plan) = undefined,
    initialized_definitions: usize = 0,
    workspaces: Workspaces() = undefined,
    initialized_workspaces: [N]bool = @splat(false),
    device_programs: [N]?DeviceProgram = @splat(null),
    typed_components: roster.Tuple(.component) = undefined,
    relations: Universal = undefined,
    bound: bool = false,
    origin: roster.Origin = .{},
    main_ready: bool = false,
    verifier_only: bool = false,
    pub fn init(a: std.mem.Allocator, admission: admission_mod.Admission) !*Owner {
        return initMode(a, admission, false);
    }
    pub fn initVerifier(a: std.mem.Allocator, admission: admission_mod.Admission) !*Owner {
        return initMode(a, admission, true);
    }
    fn initMode(a: std.mem.Allocator, admission: admission_mod.Admission, comptime verifier_only: bool) !*Owner {
        const counts = try rowCounts(a, admission);
        const logs = try logsForCounts(counts);
        const self = try a.create(Owner);
        self.* = .{ .allocator = a, .plan_id = admission.expected_id, .counts = counts, .logs = logs, .verifier_only = verifier_only };
        errdefer self.deinit();
        inline for (components.Airs, 0..) |Air, i| {
            self.definitions[i] = try Air.build(a);
            self.initialized_definitions += 1;
            self.plans[i] = try binding.Binding(Air).authenticate(&self.definitions[i]);
            inline for (.{ Air.PREPROCESSED_COLUMN_COUNT, Air.PHYSICAL_MAIN_COLUMN_COUNT }, 0..) |count, tree| {
                if (tree == 1 and verifier_only) continue;
                self.offsets[tree][i] = self.columns[tree].items.len;
                for (0..count) |_| {
                    const values = try a.alloc(M, @as(usize, 1) << @intCast(self.logs[i]));
                    @memset(values, M.zero());
                    self.columns[tree].append(a, .{ .log_size = self.logs[i], .values = values }) catch |err| {
                        a.free(values);
                        return err;
                    };
                }
            }
        }
        var fixed = Sink(0){ .owner = self };
        try components.emitTrusted(a, admission, &fixed);
        try fixed.finish();
        return self;
    }
    pub fn deinit(self: *Owner) void {
        const a = self.allocator;
        inline for (components.Airs, 0..) |_, i| {
            if (self.device_programs[i]) |*program| program.deinit();
            if (self.initialized_workspaces[i]) self.workspaces[i].deinit();
            if (i < self.initialized_definitions) self.definitions[i].deinit();
        }
        for (&self.columns) |*columns| {
            for (columns.items) |column| a.free(column.values);
            columns.deinit(a);
        }
        a.destroy(self);
    }
    /// A failed emission invalidates the main view until a full retry succeeds.
    /// Once its root/logs are retained, verification needs only typed plans.
    pub fn releaseVerifierColumns(self: *Owner) !void {
        if (!self.verifier_only) return error.NotVerifierOnly;
        for (self.columns[0].items) |column| self.allocator.free(column.values);
        self.columns[0].clearRetainingCapacity();
    }
    pub fn prepareMain(self: *Owner, source: *const Witness) !void {
        if (self.verifier_only) return error.VerifierHasNoWitnessStorage;
        self.main_ready = false;
        self.bound = false;
        var candidate = try source.plan(self.allocator);
        defer candidate.deinit();
        const admission = try admission_mod.Admission.init(&candidate, self.plan_id);
        var destination = Sink(1){ .owner = self };
        // Reuse this source-derived, caller-admitted plan through emission.
        // The shared emitter revalidates admission before writing any rows.
        try @import("blake3_commitment_shared_emit.zig").emit(self.allocator, admission, source, &destination);
        try destination.finish();
        self.main_ready = true;
    }
    pub fn preprocessed(self: *const Owner) []const Column {
        return self.columns[0].items;
    }
    pub fn main(self: *const Owner) ![]const Column {
        if (!self.main_ready) return error.CommitmentMainNotReady;
        return self.columns[1].items;
    }
    pub fn manifest(self: *const Owner) roster.Manifest {
        return .{ .log_sizes = self.logs, .origin = self.origin };
    }
    pub fn view(self: *const Owner, comptime Air: type) !framework.Runtime(binding.Binding(Air).Runtime).ColumnRows {
        if (!self.main_ready) return error.CommitmentMainNotReady;
        const i = indexOf(Air);
        const Runtime = framework.Runtime(binding.Binding(Air).Runtime);
        var result = Runtime.ColumnRows{ .columns = @splat(&.{}), .count = self.counts[i] };
        for (result.columns[0..Air.PHYSICAL_MAIN_COLUMN_COUNT], self.columns[1].items[self.offsets[1][i]..][0..Air.PHYSICAL_MAIN_COLUMN_COUNT]) |*values, column| values.* = column.values;
        for (result.columns[Air.PHYSICAL_MAIN_COLUMN_COUNT..], self.columns[0].items[self.offsets[0][i]..][0..Air.PREPROCESSED_COLUMN_COUNT]) |*values, column| values.* = column.values;
        try result.validate(self.logs[i]);
        return result;
    }
    pub fn registerLookups(self: *const Owner, counters: anytype) !void {
        inline for (components.Airs, 0..) |Air, i| {
            const registration = @import("../recursion/air/blake3_row_columns.zig");
            try @import("../recursion/air/blake3_parallel_lookup_counts.zig").register(Air, self.allocator, &self.plans[i], try self.view(Air), self.logs[i], counters);
            // Zero-padded G/XOR rows still request valid zero table tuples.
            // Their interaction rows are active algebraically even though the
            // fixed wire weights are zero. Census must cover the full domain.
            const size = @as(usize, 1) << @intCast(self.logs[i]);
            try registration.registerRepeated(Air, &self.plans[i], @as(Air.Row, @splat(M.zero())), size - self.counts[i], counters);
        }
    }
    pub fn interactions(self: *Owner, a: std.mem.Allocator, relations: *const Universal) !InteractionColumns {
        return self.interactionsForBackend(struct {}, a, relations);
    }
    pub fn interactionsForBackend(self: *Owner, comptime Backend: type, a: std.mem.Allocator, relations: *const Universal) !InteractionColumns {
        if (!self.main_ready) return error.CommitmentMainNotReady;
        var result = InteractionColumns{ .allocator = a };
        errdefer result.deinit();
        inline for (components.Airs, 0..) |Air, i| {
            const Runtime = framework.Runtime(binding.Binding(Air).Runtime);
            const device = if (comptime @hasDecl(Backend, "supportsFrameworkInteractionProgram"))
                !std.process.hasEnvVarConstant("STWO_RISCV_CPU_HASH_INTERACTIONS") and try self.deviceAvailable(Backend, Air, i)
            else
                false;
            if (device) {
                try result.columns.ensureUnusedCapacity(a, Runtime.INTERACTION_COLUMN_COUNT);
                var destination: [Runtime.INTERACTION_COLUMN_COUNT][]M = undefined;
                var initialized: usize = 0;
                errdefer for (destination[0..initialized]) |column| a.free(column);
                for (&destination) |*column| {
                    column.* = try a.alloc(M, @as(usize, 1) << @intCast(self.logs[i]));
                    initialized += 1;
                }
                const view_columns = (try self.view(Air)).columns;
                result.claims[i] = try writer.generateColumnsInto(Backend, Air, a, &self.device_programs[i].?, &self.plans[i], .{
                    view_columns[Air.PHYSICAL_MAIN_COLUMN_COUNT..], view_columns[0..Air.PHYSICAL_MAIN_COLUMN_COUNT],
                }, &.{}, self.logs[i], relations, &destination);
                for (destination) |values| result.columns.appendAssumeCapacity(.{ .log_size = self.logs[i], .values = values });
                // Ownership has transferred; a later component failure is
                // handled by result.deinit, not this component's local guard.
                initialized = 0;
            } else {
                if (!self.initialized_workspaces[i]) {
                    self.workspaces[i] = try Runtime.Workspace.init(self.allocator, @min(self.logs[i], framework.OWNED_TILE_LOG_SIZE));
                    self.initialized_workspaces[i] = true;
                }
                // Reserve descriptors before generating owned columns, making their
                // transfer infallible and keeping rollback local to the result.
                try result.columns.ensureUnusedCapacity(a, Runtime.INTERACTION_COLUMN_COUNT);
                const generated = try @import("../recursion/air/framework_parallel_interaction.zig").generate(Runtime, a, &self.workspaces[i], &self.plans[i], try self.view(Air), self.logs[i], relations, @as(Air.Row, @splat(M.zero())));
                result.claims[i] = generated.claimed_sum;
                for (generated.columns) |values| result.columns.appendAssumeCapacity(.{ .log_size = self.logs[i], .values = values });
            }
        }
        return result;
    }
    fn deviceAvailable(self: *Owner, comptime Backend: type, comptime Air: type, comptime i: usize) !bool {
        if (self.device_programs[i] == null) {
            const direct = try @import("../recursion/air/direct_constraint_program.zig").authenticate(&self.definitions[i].arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
            self.device_programs[i] = try @import("../recursion/air/framework_polynomial_export_v1.zig").exportLocalPrepared(Air, self.allocator, &direct, &self.plans[i]);
        }
        return Backend.supportsFrameworkInteractionProgram(self.allocator, &self.device_programs[i].?, &.{ Air.PREPROCESSED_COLUMN_COUNT, Air.PHYSICAL_MAIN_COLUMN_COUNT, Air.INTERACTION_COLUMN_COUNT });
    }
    /// This binds only commitment components. The complete proof must also
    /// close execution/program/memory relations and include lookup tables.
    pub fn bind(self: *Owner, relations: Universal, claims: [N]core.fields.qm31.QM31) !void {
        return self.bindAt(relations, claims, .{});
    }
    pub fn bindAt(self: *Owner, relations: Universal, claims: [N]core.fields.qm31.QM31, origin: roster.Origin) !void {
        self.bound = false;
        self.relations = relations;
        self.origin = origin;
        const placement = self.manifest();
        inline for (components.Airs, 0..) |Air, i| {
            self.typed_components[i] = try roster.Component(Air).init(&self.definitions[i], self.plans[i], &placement, @enumFromInt(i), self.logs[i], .{}, &self.relations, claims[i]);
        }
        self.bound = true;
    }
    pub fn provers(self: *Owner) ![N]@import("stwo_prover_engine").air.component_prover.ComponentProver {
        if (!self.bound or !self.main_ready) return error.CommitmentComponentsNotBound;
        var result: [N]@import("stwo_prover_engine").air.component_prover.ComponentProver = undefined;
        inline for (components.Airs, 0..) |_, i| result[i] = self.typed_components[i].asProverComponent();
        return result;
    }
    pub fn verifiers(self: *Owner) ![N]core.air.components.Component {
        if (!self.bound) return error.CommitmentComponentsNotBound;
        var result: [N]core.air.components.Component = undefined;
        inline for (components.Airs, 0..) |_, i| result[i] = self.typed_components[i].asVerifierComponent();
        return result;
    }
    fn Sink(comptime tree: usize) type {
        return struct {
            owner: *Owner,
            written: Counts = @splat(0),
            pub fn append(self: *@This(), comptime Air: type, rows: []const Air.Row) !void {
                const i = indexOf(Air);
                if (rows.len > self.owner.counts[i] - self.written[i]) return error.CommitmentRowCountMismatch;
                const count = if (tree == 0) Air.PREPROCESSED_COLUMN_COUNT else Air.PHYSICAL_MAIN_COLUMN_COUNT;
                var values: [count][]M = undefined;
                for (&values, self.owner.columns[tree].items[self.owner.offsets[tree][i]..][0..count]) |*target, column| target.* = @constCast(column.values);
                if (rows.len != 0) writer.writeColumnsAt(Air, rows, self.owner.logs[i], tree, &values, self.written[i]);
                self.written[i] += rows.len;
            }
            fn finish(self: *const @This()) !void {
                if (!std.mem.eql(usize, &self.written, &self.owner.counts)) return error.CommitmentRowCountMismatch;
            }
        };
    }
};
pub fn indexOf(comptime Air: type) usize {
    inline for (components.Airs, 0..) |Candidate, i| if (Candidate == Air) return i;
    @compileError("unregistered BLAKE3 commitment component");
}
const Census = struct {
    counts: Counts = @splat(0),
    pub fn appendCount(self: *Census, comptime Air: type, count: usize) !void {
        const i = indexOf(Air);
        self.counts[i] = try std.math.add(usize, self.counts[i], count);
    }
    pub fn append(self: *Census, comptime Air: type, rows: []const Air.Row) !void {
        try self.appendCount(Air, rows.len);
    }
};
