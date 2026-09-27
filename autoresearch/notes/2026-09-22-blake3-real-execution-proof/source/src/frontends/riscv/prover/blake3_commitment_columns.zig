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
fn Workspaces() type {
    var types: [N]type = undefined;
    for (components.Airs, &types) |Air, *T| T.* = framework.Runtime(binding.Binding(Air).Runtime).Workspace;
    return std.meta.Tuple(&types);
}
pub const InteractionColumns = struct {
    allocator: std.mem.Allocator,
    columns: std.ArrayList(Column) = .empty,
    storage: [N][]M = @splat(&.{}),
    claims: [N]core.fields.qm31.QM31 = undefined,
    pub fn deinit(self: *InteractionColumns) void {
        for (self.storage) |storage| self.allocator.free(storage);
        self.columns.deinit(self.allocator);
        self.* = undefined;
    }
};
pub const Counts = [N]usize;
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
    initialized_workspaces: usize = 0,
    typed_components: roster.Tuple(.component) = undefined,
    relations: Universal = undefined,
    bound: bool = false,
    origin: roster.Origin = .{},
    main_ready: bool = false,
    pub fn init(a: std.mem.Allocator, admission: admission_mod.Admission) !*Owner {
        try admission.validate();
        var census = Census{};
        try components.emitTrusted(a, admission, &census);
        const self = try a.create(Owner);
        self.* = .{ .allocator = a, .plan_id = admission.expected_id, .counts = census.counts, .logs = undefined };
        errdefer self.deinit();
        inline for (components.Airs, 0..) |Air, i| {
            self.logs[i] = @max(1, std.math.log2_int_ceil(usize, @max(1, self.counts[i])));
            if (self.logs[i] > 24) return error.CommitmentTraceTooLarge;
            self.definitions[i] = try Air.build(a);
            self.initialized_definitions += 1;
            self.plans[i] = try binding.Binding(Air).authenticate(&self.definitions[i]);
            inline for (.{ Air.PREPROCESSED_COLUMN_COUNT, Air.PHYSICAL_MAIN_COLUMN_COUNT }, 0..) |count, tree| {
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
            if (i < self.initialized_workspaces) self.workspaces[i].deinit();
            if (i < self.initialized_definitions) self.definitions[i].deinit();
        }
        for (&self.columns) |*columns| {
            for (columns.items) |column| a.free(column.values);
            columns.deinit(a);
        }
        a.destroy(self);
    }
    /// A failed emission invalidates the main view until a full retry succeeds.
    pub fn prepareMain(self: *Owner, source: *const Witness) !void {
        self.main_ready = false;
        self.bound = false;
        var candidate = try source.plan(self.allocator);
        defer candidate.deinit();
        _ = try admission_mod.Admission.init(&candidate, self.plan_id);
        var destination = Sink(1){ .owner = self };
        try components.emit(self.allocator, source, &destination);
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
            try registration.registerColumns(Air, &self.plans[i], try self.view(Air), self.logs[i], counters);
            // Zero-padded G/XOR rows still request valid zero table tuples.
            // Their interaction rows are active algebraically even though the
            // fixed wire weights are zero. Census must cover the full domain.
            const size = @as(usize, 1) << @intCast(self.logs[i]);
            try registration.registerRepeated(Air, &self.plans[i], @as(Air.Row, @splat(M.zero())), size - self.counts[i], counters);
        }
    }
    pub fn interactions(self: *Owner, a: std.mem.Allocator, relations: *const Universal) !InteractionColumns {
        if (!self.main_ready) return error.CommitmentMainNotReady;
        var result = InteractionColumns{ .allocator = a };
        errdefer result.deinit();
        inline for (components.Airs, 0..) |Air, i| {
            const Runtime = framework.Runtime(binding.Binding(Air).Runtime);
            if (self.initialized_workspaces <= i) {
                self.workspaces[i] = try Runtime.Workspace.init(self.allocator, self.logs[i]);
                self.initialized_workspaces += 1;
            }
            const generated = try Runtime.generatePreparedFromColumnsWithWorkspace(a, &self.workspaces[i], &self.plans[i], try self.view(Air), self.logs[i], relations, @as(Air.Row, @splat(M.zero())));
            result.storage[i] = generated.storage;
            result.claims[i] = generated.claimed_sum;
            for (generated.columns) |values| try result.columns.append(a, .{ .log_size = self.logs[i], .values = values });
        }
        return result;
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
    pub fn append(self: *Census, comptime Air: type, rows: []const Air.Row) !void {
        const i = indexOf(Air);
        self.counts[i] = try std.math.add(usize, self.counts[i], rows.len);
    }
};
