//! Validates and owns the frontend contracts admitted by CPU RISC-V composition.
//!
//! This module is the fail-closed boundary between typed frontend polynomial
//! programs and the packed backend evaluator. It accepts a semantic/lookup
//! pair only when their trace geometry, exported programs, and parameter shape
//! agree exactly; rejected pairs remain on the generic prover path.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");

const m31 = core.fields.m31;
const qm31 = core.fields.qm31;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const Component = prover.air.component_prover.ComponentProver;
const BaseCapability = prover.air.component_prover.BasePolynomialCapabilityV1;
const LookupCapability = prover.air.component_prover.LookupPolynomialCapabilityV1;
const LookupCapabilityV2 = prover.air.component_prover.LookupPolynomialCapabilityV2;
const BaseProgram = prover.air.component_prover.OwnedBasePolynomialProgram;
const LookupProgram = prover.air.component_prover.OwnedLookupPolynomialProgram;
const LookupProgramV2 = prover.air.component_prover.OwnedLookupPolynomialProgramV2;
const LookupAuthorityV2 = prover.air.component_prover.LookupPolynomialAuthorityV2;
const Poly = prover.air.component_prover.Poly;
const Trace = prover.air.component_prover.Trace;

const MAX_MAIN_COLUMNS: usize = 128;
const MAX_PROGRAM_NODES: usize = 8192;
const MAX_LOOKUP_ENTRIES: usize = 64;

/// A V2 capability is inert unless the caller has already authenticated the
/// versioned statement that owns its physical lookup partition. This token is
/// intentionally not inferred from the capability itself.
pub const LookupV2Activation = enum {
    disabled,
    authenticated_statement_v2,
};

pub const LookupVersion = enum(u1) {
    v1,
    v2,
};

pub const BaseProgramEntry = struct {
    program_id: u64,
    exporter: *const fn (*const anyopaque, std.mem.Allocator) anyerror!BaseProgram,
    program: BaseProgram,
    reachable: []bool,

    pub fn deinit(self: *BaseProgramEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.reachable);
        self.program.deinit();
        self.* = undefined;
    }
};

pub const LookupProgramEntry = struct {
    program_id: u64,
    exporter: *const fn (*const anyopaque, std.mem.Allocator) anyerror!LookupProgram,
    program: LookupProgram,
    reachable: []bool,

    pub fn deinit(self: *LookupProgramEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.reachable);
        self.program.deinit();
        self.* = undefined;
    }
};

pub const LookupProgramV2Entry = struct {
    authority: LookupAuthorityV2,
    exporter: *const fn (*const anyopaque, std.mem.Allocator) anyerror!LookupProgramV2,
    program: LookupProgramV2,
    reachable: []bool,

    pub fn deinit(self: *LookupProgramV2Entry, allocator: std.mem.Allocator) void {
        allocator.free(self.reachable);
        self.program.deinit();
        self.* = undefined;
    }
};

pub const PairJob = struct {
    semantic_registry_index: u32 = 0,
    lookup_registry_index: u32 = 0,
    base_program_index: usize,
    lookup_program_index: usize,
    lookup_version: LookupVersion = .v1,
    eval_log_size: u32,
    row_count: usize,
    main_columns: []const Poly,
    semantic_selector: []const M31,
    lookup_selector: []const M31,
    interaction_columns: []const Poly,
    parameters: []QM31,
    semantic_power_start: usize = 0,
    lookup_power_start: usize = 0,

    pub fn deinit(self: *PairJob, allocator: std.mem.Allocator) void {
        allocator.free(self.parameters);
        self.* = undefined;
    }
};

pub fn hasCandidatePair(
    components: []const Component,
    activation: LookupV2Activation,
) bool {
    if (components.len < 2) return false;
    for (components[0 .. components.len - 1], components[1..]) |left, right| {
        if (baseCapability(left) == null) continue;
        if (lookupCapability(right) != null) return true;
        if (activation == .authenticated_statement_v2 and
            lookupCapabilityV2(right) != null)
        {
            return true;
        }
    }
    return false;
}

pub fn resolvePair(
    allocator: std.mem.Allocator,
    semantic_component: Component,
    lookup_component: Component,
    trace: *const Trace,
    base_programs: *std.ArrayList(BaseProgramEntry),
    lookup_programs: *std.ArrayList(LookupProgramEntry),
    lookup_programs_v2: *std.ArrayList(LookupProgramV2Entry),
    activation: LookupV2Activation,
) !?PairJob {
    const base = baseCapability(semantic_component) orelse return null;
    if (lookupCapability(lookup_component)) |lookup| {
        return resolvePairV1(
            allocator,
            semantic_component,
            lookup_component,
            trace,
            base_programs,
            lookup_programs,
            base,
            lookup,
        );
    }
    if (activation != .authenticated_statement_v2) return null;
    const lookup = lookupCapabilityV2(lookup_component) orelse return null;
    return resolvePairV2(
        allocator,
        semantic_component,
        lookup_component,
        trace,
        base_programs,
        lookup_programs_v2,
        base,
        lookup,
    );
}

fn resolvePairV1(
    allocator: std.mem.Allocator,
    semantic_component: Component,
    lookup_component: Component,
    trace: *const Trace,
    base_programs: *std.ArrayList(BaseProgramEntry),
    lookup_programs: *std.ArrayList(LookupProgramEntry),
    base: BaseCapability,
    lookup: LookupCapability,
) !?PairJob {
    const resolved = resolveTracePair(
        semantic_component,
        lookup_component,
        base,
        lookup,
        trace,
    ) orelse return null;

    const base_program_index = try findOrAddBaseProgram(
        allocator,
        base_programs,
        semantic_component,
        base,
    ) orelse return null;
    const lookup_program_index = try findOrAddLookupProgram(
        allocator,
        lookup_programs,
        lookup_component,
        lookup,
    ) orelse return null;
    const base_program = base_programs.items[base_program_index].program;
    const lookup_program = lookup_programs.items[lookup_program_index].program;
    if (base_program.column_count != base.main_column_count + 1 or
        base_program.roots.len != semantic_component.nConstraints() or
        lookup_program.column_count != lookup.main_column_count or
        lookup_program.batchCount() != lookup_component.nConstraints() or
        lookup.interaction_column_count != lookup_program.batchCount() *
            qm31.SECURE_EXTENSION_DEGREE)
    {
        return null;
    }

    const parameters = lookup.export_parameters(
        lookup_component.ctx,
        allocator,
    ) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return null,
    };
    errdefer allocator.free(parameters);
    if (parameters.len != lookup_program.parameterCount()) {
        allocator.free(parameters);
        return null;
    }

    return .{
        .base_program_index = base_program_index,
        .lookup_program_index = lookup_program_index,
        .lookup_version = .v1,
        .eval_log_size = resolved.eval_log_size,
        .row_count = resolved.row_count,
        .main_columns = resolved.main_columns,
        .semantic_selector = resolved.semantic_selector,
        .lookup_selector = resolved.lookup_selector,
        .interaction_columns = resolved.interaction_columns,
        .parameters = parameters,
    };
}

fn resolvePairV2(
    allocator: std.mem.Allocator,
    semantic_component: Component,
    lookup_component: Component,
    trace: *const Trace,
    base_programs: *std.ArrayList(BaseProgramEntry),
    lookup_programs: *std.ArrayList(LookupProgramV2Entry),
    base: BaseCapability,
    lookup: LookupCapabilityV2,
) !?PairJob {
    lookup.authority.validate() catch return null;
    const resolved = resolveTracePair(
        semantic_component,
        lookup_component,
        base,
        lookup,
        trace,
    ) orelse return null;

    const base_program_index = try findOrAddBaseProgram(
        allocator,
        base_programs,
        semantic_component,
        base,
    ) orelse return null;
    const lookup_program_index = try findOrAddLookupProgramV2(
        allocator,
        lookup_programs,
        lookup_component,
        lookup,
    ) orelse return null;
    const base_program = base_programs.items[base_program_index].program;
    const lookup_program = &lookup_programs.items[lookup_program_index].program;
    if (base_program.column_count != base.main_column_count + 1 or
        base_program.roots.len != semantic_component.nConstraints() or
        @as(usize, lookup_program.layout.column_count) !=
            lookup.main_column_count or
        lookup_program.batchCount() != lookup_component.nConstraints() or
        lookup.interaction_column_count !=
            lookup_program.interactionColumnCount())
    {
        return null;
    }

    const parameters = lookup.export_parameters(
        lookup_component.ctx,
        allocator,
    ) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return null,
    };
    errdefer allocator.free(parameters);
    if (parameters.len != (lookup_program.parameterCount() catch return null)) {
        allocator.free(parameters);
        return null;
    }

    return .{
        .base_program_index = base_program_index,
        .lookup_program_index = lookup_program_index,
        .lookup_version = .v2,
        .eval_log_size = resolved.eval_log_size,
        .row_count = resolved.row_count,
        .main_columns = resolved.main_columns,
        .semantic_selector = resolved.semantic_selector,
        .lookup_selector = resolved.lookup_selector,
        .interaction_columns = resolved.interaction_columns,
        .parameters = parameters,
    };
}

const ResolvedPair = struct {
    eval_log_size: u32,
    row_count: usize,
    main_columns: []const Poly,
    semantic_selector: []const M31,
    lookup_selector: []const M31,
    interaction_columns: []const Poly,
};

fn resolveTracePair(
    semantic_component: Component,
    lookup_component: Component,
    base: BaseCapability,
    lookup: anytype,
    trace: *const Trace,
) ?ResolvedPair {
    if (base.trace_log_size != lookup.trace_log_size or
        base.selector_tree_index != lookup.selector_tree_index or
        base.main_tree_index != lookup.main_tree_index or
        base.first_main_column != lookup.first_main_column or
        base.main_column_count != lookup.main_column_count or
        base.main_column_count == 0 or base.main_column_count > MAX_MAIN_COLUMNS or
        lookup.interaction_column_count == 0)
    {
        return null;
    }
    const eval_log_size = semantic_component.maxConstraintLogDegreeBound();
    if (eval_log_size != lookup_component.maxConstraintLogDegreeBound() or
        eval_log_size == 0 or eval_log_size >= @bitSizeOf(usize) or
        base.trace_log_size != eval_log_size - 1)
    {
        return null;
    }
    const row_count = @as(usize, 1) << @intCast(eval_log_size);
    if (row_count < 2 * m31.PACK_WIDTH or row_count % m31.PACK_WIDTH != 0) return null;
    if (base.selector_tree_index >= trace.polys.items.len or
        base.main_tree_index >= trace.polys.items.len or
        lookup.interaction_tree_index >= trace.polys.items.len)
    {
        return null;
    }

    const selector_tree = trace.polys.items[base.selector_tree_index];
    const main_tree = trace.polys.items[base.main_tree_index];
    const interaction_tree = trace.polys.items[lookup.interaction_tree_index];
    if (base.selector_column >= selector_tree.len or
        lookup.selector_column >= selector_tree.len or
        base.first_main_column > main_tree.len or
        base.main_column_count > main_tree.len - base.first_main_column or
        lookup.first_interaction_column > interaction_tree.len or
        lookup.interaction_column_count >
            interaction_tree.len - lookup.first_interaction_column)
    {
        return null;
    }
    const semantic_selector = selector_tree[base.selector_column];
    const lookup_selector = selector_tree[lookup.selector_column];
    if (!validPoly(semantic_selector, eval_log_size, row_count) or
        !validPoly(lookup_selector, eval_log_size, row_count))
    {
        return null;
    }
    const main_columns = main_tree[base.first_main_column..][0..base.main_column_count];
    const interaction_columns = interaction_tree[lookup.first_interaction_column..][0..lookup.interaction_column_count];
    for (main_columns) |column| if (!validPoly(column, eval_log_size, row_count)) return null;
    for (interaction_columns) |column| if (!validPoly(column, eval_log_size, row_count)) return null;
    return .{
        .eval_log_size = eval_log_size,
        .row_count = row_count,
        .main_columns = main_columns,
        .semantic_selector = semantic_selector.values,
        .lookup_selector = lookup_selector.values,
        .interaction_columns = interaction_columns,
    };
}

fn validPoly(poly: Poly, log_size: u32, row_count: usize) bool {
    return poly.log_size == log_size and poly.values.len == row_count;
}

fn baseCapability(component: Component) ?BaseCapability {
    const capability = component.backend_composition_capability orelse return null;
    return switch (capability) {
        .base_polynomial_v1 => |value| value,
        else => null,
    };
}

fn lookupCapability(component: Component) ?LookupCapability {
    const capability = component.backend_composition_capability orelse return null;
    return switch (capability) {
        .lookup_polynomial_v1 => |value| value,
        else => null,
    };
}

fn lookupCapabilityV2(component: Component) ?LookupCapabilityV2 {
    const capability = component.backend_composition_capability orelse return null;
    return switch (capability) {
        .lookup_polynomial_v2 => |value| value,
        else => null,
    };
}

fn findOrAddBaseProgram(
    allocator: std.mem.Allocator,
    entries: *std.ArrayList(BaseProgramEntry),
    component: Component,
    capability: BaseCapability,
) !?usize {
    for (entries.items, 0..) |entry, index| {
        if (entry.program_id != capability.program_id) continue;
        if (entry.exporter != capability.export_program) return null;
        return index;
    }
    var program = capability.export_program(component.ctx, allocator) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return null,
    };
    var retained = false;
    defer if (!retained) program.deinit();
    program.validate() catch return null;
    if (!boundedNodes(program.nodes)) return null;
    const reachable = try baseReachable(allocator, program);
    errdefer allocator.free(reachable);
    try entries.append(allocator, .{
        .program_id = capability.program_id,
        .exporter = capability.export_program,
        .program = program,
        .reachable = reachable,
    });
    retained = true;
    return entries.items.len - 1;
}

fn findOrAddLookupProgram(
    allocator: std.mem.Allocator,
    entries: *std.ArrayList(LookupProgramEntry),
    component: Component,
    capability: LookupCapability,
) !?usize {
    for (entries.items, 0..) |entry, index| {
        if (entry.program_id != capability.program_id) continue;
        if (entry.exporter != capability.export_program) return null;
        return index;
    }
    var program = capability.export_program(component.ctx, allocator) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return null,
    };
    var retained = false;
    defer if (!retained) program.deinit();
    program.validate() catch return null;
    if (!boundedNodes(program.nodes) or program.entries.len > MAX_LOOKUP_ENTRIES) return null;
    const reachable = try lookupReachable(allocator, program);
    errdefer allocator.free(reachable);
    try entries.append(allocator, .{
        .program_id = capability.program_id,
        .exporter = capability.export_program,
        .program = program,
        .reachable = reachable,
    });
    retained = true;
    return entries.items.len - 1;
}

fn findOrAddLookupProgramV2(
    allocator: std.mem.Allocator,
    entries: *std.ArrayList(LookupProgramV2Entry),
    component: Component,
    capability: LookupCapabilityV2,
) !?usize {
    capability.authority.validate() catch return null;
    for (entries.items, 0..) |entry, index| {
        if (!std.mem.eql(
            u8,
            &entry.authority.program_identity,
            &capability.authority.program_identity,
        )) continue;
        if (entry.exporter != capability.export_program or
            !authorityEqualV2(entry.authority, capability.authority.*))
        {
            return null;
        }
        return index;
    }
    var program = capability.export_program(component.ctx, allocator) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return null,
    };
    var retained = false;
    defer if (!retained) program.deinit();
    program.validateAgainst(capability.authority) catch return null;
    if (!boundedNodes(program.nodes) or
        program.entries.len > prover.air.lookup_polynomial_v2.MAX_LOOKUP_ENTRIES or
        program.batches.len > prover.air.lookup_polynomial_v2.MAX_LOOKUP_BATCHES or
        @as(usize, program.layout.column_count) >
            prover.air.lookup_polynomial_v2.MAX_MAIN_COLUMNS)
    {
        return null;
    }
    const reachable = try lookupReachableV2(allocator, &program);
    errdefer allocator.free(reachable);
    try entries.append(allocator, .{
        .authority = capability.authority.*,
        .exporter = capability.export_program,
        .program = program,
        .reachable = reachable,
    });
    retained = true;
    return entries.items.len - 1;
}

fn authorityEqualV2(lhs: LookupAuthorityV2, rhs: LookupAuthorityV2) bool {
    return lhs.format_version == rhs.format_version and
        lhs.entry_count == rhs.entry_count and
        lhs.batch_count == rhs.batch_count and
        lhs.interaction_column_count == rhs.interaction_column_count and
        lhs.maximum_interaction_degree == rhs.maximum_interaction_degree and
        std.mem.eql(u8, &lhs.component_identity, &rhs.component_identity) and
        std.mem.eql(u8, &lhs.partition_identity, &rhs.partition_identity) and
        std.mem.eql(u8, &lhs.layout_identity, &rhs.layout_identity) and
        std.mem.eql(u8, &lhs.program_identity, &rhs.program_identity);
}

fn boundedNodes(nodes: []const prover.air.component_prover.BasePolynomialNode) bool {
    if (nodes.len == 0 or nodes.len > MAX_PROGRAM_NODES) return false;
    for (nodes) |node| {
        if (node.op == .constant and node.value >= m31.Modulus) return false;
    }
    return true;
}

fn baseReachable(allocator: std.mem.Allocator, program: BaseProgram) ![]bool {
    const reachable = try allocator.alloc(bool, program.nodes.len);
    @memset(reachable, false);
    for (program.roots) |root| reachable[root] = true;
    markAncestors(program.nodes, reachable);
    return reachable;
}

fn lookupReachable(allocator: std.mem.Allocator, program: LookupProgram) ![]bool {
    const reachable = try allocator.alloc(bool, program.nodes.len);
    @memset(reachable, false);
    for (program.entries) |entry| {
        reachable[entry.numerator] = true;
        for (entry.values[0..entry.arity]) |value| reachable[value] = true;
    }
    markAncestors(program.nodes, reachable);
    return reachable;
}

fn lookupReachableV2(
    allocator: std.mem.Allocator,
    program: *const LookupProgramV2,
) ![]bool {
    const reachable = try allocator.alloc(bool, program.nodes.len);
    @memset(reachable, false);
    for (program.entries) |entry| {
        reachable[entry.numerator] = true;
        for (entry.values[0..entry.arity]) |value| reachable[value] = true;
    }
    markAncestors(program.nodes, reachable);
    return reachable;
}

fn markAncestors(
    nodes: []const prover.air.component_prover.BasePolynomialNode,
    reachable: []bool,
) void {
    var cursor = nodes.len;
    while (cursor != 0) {
        cursor -= 1;
        if (!reachable[cursor]) continue;
        const node = nodes[cursor];
        switch (node.op) {
            .constant, .column => {},
            .add, .sub, .mul => {
                reachable[node.lhs] = true;
                reachable[node.rhs] = true;
            },
            .neg => reachable[node.lhs] = true,
        }
    }
}
