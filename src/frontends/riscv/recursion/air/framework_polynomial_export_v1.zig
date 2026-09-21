//! Backend export of already admitted immutable recursive component plans.
//! No AIR is reconstructed here. Inputs retain explicit PCS/profile bindings;
//! both direct roots and signed relation entries use the existing plan ops.
const std = @import("std");
const core = @import("stwo_core");
const backend = @import("stwo_prover_engine").air.component_prover;
const direct_mod = @import("direct_constraint_program.zig");
const relation_mod = @import("relation_interaction.zig");
const binding_mod = @import("universal_relation_binding.zig");
const universal = @import("universal_challenges.zig");
const lang = @import("../../air/lang/definition.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const NO_NODE = std.math.maxInt(u32);
const SLOT_COUNT = direct_mod.MAX_NODES + relation_mod.MAX_COMPILED_NODES;

/// Cold export from component-owned plans. Callers must have authenticated the
/// definition and exact plans at component construction. This function does
/// shape/seal checks, not another upstream arena audit on a routine read.
pub fn exportPrepared(
    comptime Air: type,
    allocator: std.mem.Allocator,
    direct: *const direct_mod.Program,
    relations: *const binding_mod.Binding(Air).Plan,
    inputs: []const backend.TypedPolynomialInputV1,
    interaction_columns: []const backend.TypedPolynomialColumnV1,
    profile_parameter_count: u32,
    tree_column_counts: []const usize,
) !backend.OwnedFrameworkPolynomialProgramV1 {
    return exportPreparedLayout(Air, allocator, direct, relations, inputs, interaction_columns, profile_parameter_count, tree_column_counts, null);
}

/// Canonical component-local bindings for interaction production and AOT
/// generation. Both paths use the same physical columns and profile slots.
pub fn exportLocalPrepared(
    comptime Air: type,
    allocator: std.mem.Allocator,
    direct: *const direct_mod.Program,
    relations: *const binding_mod.Binding(Air).Plan,
) !backend.OwnedFrameworkPolynomialProgramV1 {
    const parameter_start = Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT;
    const parameter_count = Air.LOGICAL_INPUT_COUNT - parameter_start;
    var inputs: [Air.LOGICAL_INPUT_COUNT]backend.TypedPolynomialInputV1 = undefined;
    for (&inputs, 0..) |*input, index| input.* = if (index < Air.PHYSICAL_MAIN_COLUMN_COUNT)
        .{ .trace_column = .{ .tree_index = 1, .column_index = @intCast(index) } }
    else if (index < parameter_start)
        .{ .trace_column = .{ .tree_index = 0, .column_index = @intCast(index - Air.PHYSICAL_MAIN_COLUMN_COUNT) } }
    else
        .{ .profile_parameter = @intCast(index - parameter_start) };
    var interaction: [Air.INTERACTION_COLUMN_COUNT]backend.TypedPolynomialColumnV1 = undefined;
    for (&interaction, 0..) |*column, index| column.* = .{ .tree_index = 2, .column_index = @intCast(index) };
    const counts = [_]usize{ Air.PREPROCESSED_COLUMN_COUNT, Air.PHYSICAL_MAIN_COLUMN_COUNT, Air.INTERACTION_COLUMN_COUNT };
    return exportPrepared(Air, allocator, direct, relations, &inputs, &interaction, parameter_count, &counts);
}

/// The extra committed selector belongs to the framework, not the typed
/// relation arena. Keep the arena's input-slot numbering unchanged when
/// lowering intermediate expressions.
pub fn exportIndependentPrepared(
    comptime Air: type,
    allocator: std.mem.Allocator,
    direct: *const direct_mod.Program,
    relations: *const binding_mod.Binding(Air).Plan,
    inputs: []const backend.TypedPolynomialInputV1,
    interaction_columns: []const backend.TypedPolynomialColumnV1,
    tree_column_counts: []const usize,
) !backend.OwnedFrameworkPolynomialProgramV1 {
    return exportPreparedLayout(Air, allocator, direct, relations, inputs, interaction_columns, 0, tree_column_counts, Air.LOGICAL_INPUT_COUNT);
}

fn exportPreparedLayout(
    comptime Air: type,
    allocator: std.mem.Allocator,
    direct: *const direct_mod.Program,
    relations: *const binding_mod.Binding(Air).Plan,
    inputs: []const backend.TypedPolynomialInputV1,
    interaction_columns: []const backend.TypedPolynomialColumnV1,
    profile_parameter_count: u32,
    tree_column_counts: []const usize,
    is_first_input: ?u32,
) !backend.OwnedFrameworkPolynomialProgramV1 {
    if (direct.input_count != Air.LOGICAL_INPUT_COUNT or direct.constraint_count != Air.DIRECT_CONSTRAINT_COUNT or
        direct.evaluation_node_count > direct.evaluation_nodes.len or direct.constraint_count > direct.constraints.len or
        relations.compiled_node_count > relations.compiled_nodes.len or relations.format_version != relation_mod.FORMAT_VERSION or
        direct.semantic_format_version != lang.digest.typed_effect_format_version or
        relations.semantic_format_version != lang.digest.typed_effect_format_version or
        !std.mem.eql(u8, &direct.semantic_digest, &Air.SEMANTIC_DIGEST) or
        !std.mem.eql(u8, &relations.semantic_digest, &Air.SEMANTIC_DIGEST) or
        !std.mem.eql(u8, &relations.registry_order_digest, &universal.registryOrderDigest()) or
        inputs.len != Air.LOGICAL_INPUT_COUNT + @as(usize, @intFromBool(is_first_input != null)) or interaction_columns.len != Air.INTERACTION_COLUMN_COUNT)
        return error.InvalidPreparedFrameworkProgram;
    var direct_lowerer = try Lowerer.init(allocator, Air.LOGICAL_INPUT_COUNT);
    defer direct_lowerer.deinit();
    for (direct.evaluation_nodes[0..direct.evaluation_node_count]) |node| try direct_lowerer.lower(node.destination, node.op);
    const roots = try allocator.alloc(u32, direct.constraint_count);
    errdefer allocator.free(roots);
    for (direct.constraints[0..direct.constraint_count], roots) |constraint, *root| {
        root.* = try direct_lowerer.slot(constraint.root);
        if (constraint.gate != std.math.maxInt(u16)) root.* = try direct_lowerer.append(.{
            .op = .mul,
            .lhs = root.*,
            .rhs = try direct_lowerer.slot(constraint.gate),
        });
    }
    // A relation-only component has no direct graph: do not invent a zero
    // constraint or retain unreferenced input nodes to fit the base ABI.
    if (direct.constraint_count == 0) direct_lowerer.nodes.clearRetainingCapacity();
    const direct_nodes = try direct_lowerer.nodes.toOwnedSlice(allocator);
    errdefer allocator.free(direct_nodes);
    var lookup_lowerer = try Lowerer.init(allocator, Air.LOGICAL_INPUT_COUNT);
    defer lookup_lowerer.deinit();
    for (relations.compiled_nodes[0..relations.compiled_node_count]) |node| try lookup_lowerer.lower(node.destination, node.op);
    const entries = try allocator.alloc(backend.FrameworkLookupEntryV1, relations.events.len);
    errdefer allocator.free(entries);
    for (relations.events, entries, 0..) |event, *entry, index| {
        if (event.ordinal != index or event.arity == 0 or event.arity > backend.FRAMEWORK_LOOKUP_MAX_ARITY_V1) return error.InvalidPreparedFrameworkProgram;
        var numerator = try lookup_lowerer.slot(event.numerator_slot);
        switch (event.role) {
            .emit => {},
            .consume, .request => numerator = try lookup_lowerer.append(.{ .op = .neg, .lhs = numerator }),
        }
        entry.* = .{ .domain = @intFromEnum(event.domain), .schema_version = event.schema_version, .numerator = numerator, .arity = event.arity };
        for (event.value_slots[0..event.arity], entry.values[0..event.arity]) |source, *target| target.* = try lookup_lowerer.slot(source);
    }
    const lookup_nodes = try lookup_lowerer.nodes.toOwnedSlice(allocator);
    errdefer allocator.free(lookup_nodes);
    const batches = try allocator.alloc(backend.FrameworkLookupBatchV1, relations.batches.len);
    errdefer allocator.free(batches);
    for (relations.batches, batches, 0..) |source, *target, index| {
        if (source.ordinal != index or (source.second != null and source.second.? != @as(usize, source.first) + 1)) return error.InvalidPreparedFrameworkProgram;
        target.* = .{ .first_entry = source.first, .entry_count = if (source.second == null) 1 else 2, .interaction_column_start = source.interaction_column_start };
    }
    const owned_inputs = try allocator.dupe(backend.TypedPolynomialInputV1, inputs);
    errdefer allocator.free(owned_inputs);
    const owned_interaction = try allocator.dupe(backend.TypedPolynomialColumnV1, interaction_columns);
    errdefer allocator.free(owned_interaction);
    var result = backend.OwnedFrameworkPolynomialProgramV1{
        .allocator = allocator,
        .semantic_digest = Air.SEMANTIC_DIGEST,
        .registry_order_digest = relations.registry_order_digest,
        .direct = .{ .allocator = allocator, .nodes = direct_nodes, .roots = roots, .column_count = inputs.len },
        .lookup_nodes = lookup_nodes,
        .entries = entries,
        .batches = batches,
        .inputs = owned_inputs,
        .interaction_columns = owned_interaction,
        .profile_parameter_count = profile_parameter_count,
        .layout = if (is_first_input != null) .independent_prefix_v1 else .same_row_prefix_v1,
        .is_first_input = is_first_input,
        .identity = @splat(0),
    };
    result.identity = result.identityDigest();
    try result.validate(tree_column_counts);
    return result;
}

/// Equation-free projection of an admitted universal typed component's source
/// layout. Backend code consumes these coordinates without assuming a main slab.
pub fn exportComponentPrepared(comptime Air: type, allocator: std.mem.Allocator, component: anytype, tree_column_counts: []const usize) !backend.OwnedFrameworkPolynomialProgramV1 {
    var inputs: [Air.LOGICAL_INPUT_COUNT]backend.TypedPolynomialInputV1 = undefined;
    for (inputs[0..Air.PHYSICAL_MAIN_COLUMN_COUNT], 0..) |*input, column| input.* = .{ .trace_column = .{ .tree_index = 1, .column_index = try columnIndex(component.placement.main_offset, column) } };
    const pp_start = Air.PHYSICAL_MAIN_COLUMN_COUNT;
    const parameter_start = pp_start + Air.PREPROCESSED_COLUMN_COUNT;
    for (inputs[pp_start..parameter_start], 0..) |*input, column| input.* = .{ .trace_column = .{ .tree_index = 0, .column_index = try columnIndex(component.placement.preprocessed_offset, column) } };
    if (inputs.len - parameter_start != component.parameters.len) return error.InvalidPreparedFrameworkProgram;
    for (inputs[parameter_start..], component.parameters, 0..) |*input, parameter, index| {
        if (parameter.toU32() >= core.fields.m31.Modulus) return error.InvalidPreparedFrameworkProgram;
        input.* = .{ .profile_parameter = @intCast(index) };
    }
    var interaction: [Air.INTERACTION_COLUMN_COUNT]backend.TypedPolynomialColumnV1 = undefined;
    for (&interaction, 0..) |*column, index| column.* = .{ .tree_index = 2, .column_index = try columnIndex(component.placement.interaction_offset, index) };
    return exportPrepared(Air, allocator, &component.direct, &component.relation_plan, &inputs, &interaction, @intCast(component.parameters.len), tree_column_counts);
}

/// A cold callback boundary. The component already owns authenticated plans;
/// the backend owns the exported program and invocation for the whole job.
/// Neither export reads or revalidates the upstream circuit/manifest hierarchy.
pub fn capability(comptime Air: type, comptime Component: type, trace_log_size: u32) backend.FrameworkPolynomialCapabilityV1 {
    const Callbacks = struct {
        fn program(ctx: *const anyopaque, allocator: std.mem.Allocator, tree_column_counts: []const usize) !backend.OwnedFrameworkPolynomialProgramV1 {
            const component: *const Component = @ptrCast(@alignCast(ctx));
            return exportComponentPrepared(Air, allocator, component, tree_column_counts);
        }
        fn parameters(ctx: *const anyopaque, allocator: std.mem.Allocator) !backend.OwnedFrameworkPolynomialParametersV1 {
            const component: *const Component = @ptrCast(@alignCast(ctx));
            const profile_values = try allocator.dupe(M31, &component.parameters);
            errdefer allocator.free(profile_values);
            const relation_values = try exportRelationParameters(allocator, &component.relation_plan, component.relations);
            errdefer allocator.free(relation_values);
            return .{ .allocator = allocator, .values = .{
                .profile_values = profile_values,
                .relation_values = relation_values,
                .trace_log_size = component.log_size,
                .claimed_sum = component.claimed_sum,
            } };
        }
    };
    return .{ .trace_log_size = trace_log_size, .export_program = Callbacks.program, .export_parameters = Callbacks.parameters };
}

pub fn exportRelationParameters(allocator: std.mem.Allocator, plan: anytype, relations: *const universal.UniversalRelations) ![]QM31 {
    if (!std.mem.eql(u8, &plan.registry_order_digest, &universal.registryOrderDigest())) return error.InvalidPreparedFrameworkProgram;
    try relations.validate();
    var result: std.ArrayList(QM31) = .empty;
    errdefer result.deinit(allocator);
    for (plan.events) |event| {
        const challenge = try relations.getExact(event.domain);
        if (challenge.arity != event.arity) return error.InvalidPreparedFrameworkProgram;
        try result.append(allocator, challenge.z);
        try result.appendSlice(allocator, challenge.alpha_powers[0..event.arity]);
    }
    return result.toOwnedSlice(allocator);
}
fn columnIndex(offset: u32, column: usize) !u32 {
    return std.math.add(u32, offset, std.math.cast(u32, column) orelse return error.InvalidPreparedFrameworkProgram) catch error.InvalidPreparedFrameworkProgram;
}

const Lowerer = struct {
    allocator: std.mem.Allocator,
    nodes: std.ArrayList(backend.BasePolynomialNode) = .empty,
    slots: [SLOT_COUNT]u32 = @splat(NO_NODE),
    fn init(allocator: std.mem.Allocator, count: usize) !Lowerer {
        if (count > SLOT_COUNT) return error.InvalidPreparedFrameworkProgram;
        var result = Lowerer{ .allocator = allocator };
        errdefer result.deinit();
        for (0..count) |index| result.slots[index] = try result.append(.{ .op = .column, .value = @intCast(index) });
        return result;
    }
    fn deinit(self: *Lowerer) void {
        self.nodes.deinit(self.allocator);
    }
    fn slot(self: *const Lowerer, source: usize) !u32 {
        if (source >= self.slots.len or self.slots[source] == NO_NODE) return error.InvalidPreparedFrameworkProgram;
        return self.slots[source];
    }
    fn append(self: *Lowerer, node: backend.BasePolynomialNode) !u32 {
        const index = std.math.cast(u32, self.nodes.items.len) orelse return error.InvalidPreparedFrameworkProgram;
        try self.nodes.append(self.allocator, node);
        return index;
    }
    fn lower(self: *Lowerer, destination: usize, op: anytype) !void {
        if (destination >= self.slots.len or self.slots[destination] != NO_NODE) return error.InvalidPreparedFrameworkProgram;
        const lowered: backend.BasePolynomialNode = switch (op) {
            .constant => |value| .{ .op = .constant, .value = value },
            .add, .sub, .mul => |pair| .{ .op = switch (op) {
                .add => .add,
                .sub => .sub,
                .mul => .mul,
                else => unreachable,
            }, .lhs = try self.slot(pair.lhs), .rhs = try self.slot(pair.rhs) },
            .neg => |value| .{ .op = .neg, .lhs = try self.slot(value) },
            .select => |selection| blk: {
                const difference = try self.append(.{ .op = .sub, .lhs = try self.slot(selection.when_true), .rhs = try self.slot(selection.when_false) });
                const selected = try self.append(.{ .op = .mul, .lhs = try self.slot(selection.selector), .rhs = difference });
                break :blk .{ .op = .add, .lhs = try self.slot(selection.when_false), .rhs = selected };
            },
        };
        self.slots[destination] = try self.append(lowered);
    }
};
