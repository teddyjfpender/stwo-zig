//! Authenticated resident lookup jobs shared by V1 and selected-layout V2.
//!
//! Both versions use the same Metal dispatch ABI. This owner keeps their
//! program validation and kernel identity separate while projecting only the
//! physical columns and parameters needed by the batch dispatcher.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const metal_runtime = @import("../runtime.zig");
const v1_codegen = @import("lookup_polynomial_codegen.zig");
const v2_owner = @import("lookup_polynomial_v2_owner.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Component = prover.air.component_prover.ComponentProver;
const Trace = prover.air.component_prover.Trace;
const Poly = prover.air.component_prover.Poly;
const V1 = prover.air.component_prover.LookupPolynomialCapabilityV1;
const V2 = prover.air.component_prover.LookupPolynomialCapabilityV2;

pub const Capability = union(enum) {
    v1: V1,
    v2: V2,
};

pub const Job = struct {
    component: Component,
    power_start: usize,
    constraint_count: usize,
    row_count: usize,
    eval_log_size: u32,
    trace_log_size: u32,
    main_columns: []const Poly,
    interaction_columns: []const Poly,
    selector: [*]const M31,
    parameters: []QM31,
    program_index: usize,

    pub fn deinit(self: *Job, allocator: std.mem.Allocator) void {
        allocator.free(self.parameters);
        self.* = undefined;
    }
};

const V1Program = struct {
    program_id: u64,
    program: prover.air.component_prover.OwnedLookupPolynomialProgram,
    plan: ?metal_runtime.LookupPolynomialPlan = null,
};

const V2Program = struct {
    owner: v2_owner.ProgramOwner,
    plan: ?metal_runtime.LookupPolynomialPlan = null,
};

const Program = union(enum) {
    v1: V1Program,
    v2: V2Program,

    fn deinit(self: *Program) void {
        switch (self.*) {
            .v1 => |*entry| {
                if (entry.plan) |*plan| plan.deinit();
                entry.program.deinit();
            },
            .v2 => |*entry| {
                if (entry.plan) |*plan| plan.deinit();
                entry.owner.deinit();
            },
        }
        self.* = undefined;
    }

    fn matches(self: *const Program, capability_value: Capability) bool {
        return switch (self.*) {
            .v1 => |entry| switch (capability_value) {
                .v1 => |candidate| entry.program_id == candidate.program_id,
                .v2 => false,
            },
            .v2 => |entry| switch (capability_value) {
                .v1 => false,
                .v2 => |candidate| std.meta.eql(
                    entry.owner.authority,
                    candidate.authority.*,
                ),
            },
        };
    }

    fn prepare(self: *Program, allocator: std.mem.Allocator, runtime: *metal_runtime.Runtime) !void {
        switch (self.*) {
            .v1 => |*entry| {
                const name = try v1_codegen.kernelName(allocator, entry.program);
                defer allocator.free(name);
                entry.plan = try runtime.prepareLookupPolynomialAot(name);
            },
            .v2 => |*entry| {
                const name = try entry.owner.kernelName(allocator);
                defer allocator.free(name);
                entry.plan = try runtime.prepareLookupPolynomialAot(name);
            },
        }
    }

    fn planHandle(self: *const Program) *anyopaque {
        return switch (self.*) {
            .v1 => |entry| entry.plan.?.handle,
            .v2 => |entry| entry.plan.?.handle,
        };
    }
};

pub const Catalog = struct {
    allocator: std.mem.Allocator,
    programs: std.ArrayList(Program) = .empty,

    pub fn init(allocator: std.mem.Allocator) Catalog {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Catalog) void {
        for (self.programs.items) |*program| program.deinit();
        self.programs.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn appendJob(
        self: *Catalog,
        component: Component,
        capability_value: Capability,
        trace: *const Trace,
        residency_handles: []const ?*anyopaque,
        power_start: usize,
        constraint_count: usize,
    ) !Job {
        const geometry = physicalGeometry(capability_value);
        const resolved = try resolveJob(component, geometry, trace, residency_handles);
        const program_index = try self.ensureProgram(
            component,
            capability_value,
            constraint_count,
        );
        const parameters = try exportParameters(component, capability_value, self.allocator);
        errdefer self.allocator.free(parameters);
        const expected_parameters = switch (self.programs.items[program_index]) {
            .v1 => |entry| entry.program.parameterCount(),
            .v2 => |entry| try entry.owner.program.parameterCount(),
        };
        if (parameters.len != expected_parameters)
            return error.InvalidLookupPolynomialProgram;
        return .{
            .component = component,
            .power_start = power_start,
            .constraint_count = constraint_count,
            .row_count = resolved.row_count,
            .eval_log_size = resolved.eval_log_size,
            .trace_log_size = geometry.trace_log_size,
            .main_columns = resolved.main_columns,
            .interaction_columns = resolved.interaction_columns,
            .selector = resolved.selector,
            .parameters = parameters,
            .program_index = program_index,
        };
    }

    pub fn prepareAll(self: *Catalog, runtime: *metal_runtime.Runtime) !void {
        for (self.programs.items) |*program|
            try program.prepare(self.allocator, runtime);
    }

    pub fn planHandle(self: *const Catalog, index: usize) *anyopaque {
        return self.programs.items[index].planHandle();
    }

    fn ensureProgram(
        self: *Catalog,
        component: Component,
        capability_value: Capability,
        constraint_count: usize,
    ) !usize {
        for (self.programs.items, 0..) |*program, index| {
            if (!program.matches(capability_value)) continue;
            try validateExisting(
                program,
                capability_value,
                constraint_count,
            );
            return index;
        }
        const index = self.programs.items.len;
        switch (capability_value) {
            .v1 => |capability_v1| {
                var program = try capability_v1.export_program(component.ctx, self.allocator);
                errdefer program.deinit();
                try validateV1(program, capability_v1, constraint_count);
                try self.programs.append(self.allocator, .{ .v1 = .{
                    .program_id = capability_v1.program_id,
                    .program = program,
                } });
            },
            .v2 => |capability_v2| {
                var program = try capability_v2.export_program(component.ctx, self.allocator);
                errdefer program.deinit();
                var owner = try v2_owner.ProgramOwner.init(&program, capability_v2.authority);
                errdefer owner.deinit();
                _ = try v2_owner.JobIdentity.init(
                    capability_v2,
                    &owner,
                    constraint_count,
                );
                try self.programs.append(self.allocator, .{ .v2 = .{ .owner = owner } });
            },
        }
        return index;
    }
};

pub fn capability(component: Component) ?Capability {
    const value = component.backend_composition_capability orelse return null;
    return switch (value) {
        .lookup_polynomial_v1 => |selected| .{ .v1 = selected },
        .lookup_polynomial_v2 => |selected| .{ .v2 = selected },
        else => null,
    };
}

pub fn hasResidency(
    capability_value: Capability,
    handles: []const ?*anyopaque,
) bool {
    const geometry = physicalGeometry(capability_value);
    for ([_]usize{
        geometry.selector_tree_index,
        geometry.main_tree_index,
        geometry.interaction_tree_index,
    }) |index| if (index >= handles.len or handles[index] == null) return false;
    return true;
}

pub const PhysicalGeometry = struct {
    trace_log_size: u32,
    selector_tree_index: usize,
    selector_column: usize,
    main_tree_index: usize,
    first_main_column: usize,
    main_column_count: usize,
    interaction_tree_index: usize,
    first_interaction_column: usize,
    interaction_column_count: usize,
};

pub fn physicalGeometry(capability_value: Capability) PhysicalGeometry {
    return switch (capability_value) {
        inline else => |value| .{
            .trace_log_size = value.trace_log_size,
            .selector_tree_index = value.selector_tree_index,
            .selector_column = value.selector_column,
            .main_tree_index = value.main_tree_index,
            .first_main_column = value.first_main_column,
            .main_column_count = value.main_column_count,
            .interaction_tree_index = value.interaction_tree_index,
            .first_interaction_column = value.first_interaction_column,
            .interaction_column_count = value.interaction_column_count,
        },
    };
}

fn exportParameters(
    component: Component,
    capability_value: Capability,
    allocator: std.mem.Allocator,
) ![]QM31 {
    return switch (capability_value) {
        inline else => |value| value.export_parameters(component.ctx, allocator),
    };
}

fn validateExisting(
    program: *const Program,
    capability_value: Capability,
    constraint_count: usize,
) !void {
    switch (program.*) {
        .v1 => |entry| try validateV1(
            entry.program,
            capability_value.v1,
            constraint_count,
        ),
        .v2 => |entry| {
            const selected = capability_value.v2;
            _ = try v2_owner.JobIdentity.init(
                selected,
                &entry.owner,
                constraint_count,
            );
        },
    }
}

fn validateV1(
    program: prover.air.component_prover.OwnedLookupPolynomialProgram,
    capability_v1: V1,
    constraint_count: usize,
) !void {
    try program.validate();
    if (program.column_count != capability_v1.main_column_count or
        program.batchCount() != constraint_count or
        capability_v1.interaction_column_count != program.batchCount() * 4)
    {
        return error.InvalidLookupPolynomialProgram;
    }
}

const ResolvedJob = struct {
    row_count: usize,
    eval_log_size: u32,
    main_columns: []const Poly,
    interaction_columns: []const Poly,
    selector: [*]const M31,
};

fn resolveJob(
    component: Component,
    geometry: PhysicalGeometry,
    trace: *const Trace,
    residency_handles: []const ?*anyopaque,
) !ResolvedJob {
    if (!hasGeometryResidency(geometry, trace, residency_handles))
        return error.MissingLookupPolynomialResidency;
    const eval_log_size = component.maxConstraintLogDegreeBound();
    if (eval_log_size <= geometry.trace_log_size or
        eval_log_size - geometry.trace_log_size > 3 or
        eval_log_size >= @bitSizeOf(usize))
    {
        return error.InvalidLookupPolynomialProgram;
    }
    const row_count = @as(usize, 1) << @intCast(eval_log_size);
    const selector_tree = trace.polys.items[geometry.selector_tree_index];
    const main_tree = trace.polys.items[geometry.main_tree_index];
    const interaction_tree = trace.polys.items[geometry.interaction_tree_index];
    if (geometry.selector_column >= selector_tree.len or
        geometry.first_main_column > main_tree.len or
        geometry.main_column_count > main_tree.len - geometry.first_main_column or
        geometry.first_interaction_column > interaction_tree.len or
        geometry.interaction_column_count >
            interaction_tree.len - geometry.first_interaction_column)
    {
        return error.InvalidLookupPolynomialProgram;
    }
    const selector = selector_tree[geometry.selector_column];
    if (selector.log_size != eval_log_size or selector.values.len != row_count)
        return error.InvalidLookupPolynomialProgram;
    const main = main_tree[geometry.first_main_column..][0..geometry.main_column_count];
    const interaction = interaction_tree[geometry.first_interaction_column..][0..geometry.interaction_column_count];
    for (main) |column| if (column.log_size != eval_log_size or
        column.values.len != row_count) return error.InvalidLookupPolynomialProgram;
    for (interaction) |column| if (column.log_size != eval_log_size or
        column.values.len != row_count) return error.InvalidLookupPolynomialProgram;
    return .{
        .row_count = row_count,
        .eval_log_size = eval_log_size,
        .main_columns = main,
        .interaction_columns = interaction,
        .selector = selector.values.ptr,
    };
}

fn hasGeometryResidency(
    geometry: PhysicalGeometry,
    trace: *const Trace,
    handles: []const ?*anyopaque,
) bool {
    for ([_]usize{
        geometry.selector_tree_index,
        geometry.main_tree_index,
        geometry.interaction_tree_index,
    }) |index| {
        if (index >= trace.polys.items.len or
            index >= handles.len or handles[index] == null) return false;
    }
    return true;
}
