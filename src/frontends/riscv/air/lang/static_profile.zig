//! Deterministic static profiling for validated typed AIR programs.
//!
//! This pass reports logical structure, not elapsed time, backend memory, proof
//! size, or proving speed. Intrinsic facts are derived from the canonical AIR
//! arena. Physical main-column geometry, LogUp batching, and pre-canonical CSE
//! counts are accepted only as explicit caller context because the logical IR
//! does not own those decisions.
//!
//! Without a materialization plan, `collect` is a cold, allocation-explicit
//! O(nodes + expression edges + constraints + effects) pass. Supplying a plan
//! intentionally invokes that authority's complete validation, whose cost is
//! additional and policy-dependent. The returned record owns no memory.
//! Digest validation and both canonical writers allocate nothing.

const std = @import("std");
const degree = @import("degree.zig");
const digest = @import("digest.zig");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const protocol_degree = @import("protocol_degree.zig");
const types = @import("types.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const SCHEMA = "stwo.typed-air.static-profile.v1";
pub const SCHEMA_VERSION: u16 = 1;
pub const DIGEST_DOMAIN = "stwo-zig/typed-air/static-profile/v1\x00";
pub const Digest = [32]u8;

/// Exact current interaction layout supplied by an integration boundary.
/// Batch sizes larger than two are deliberately rejected because the modeled
/// recurrence is the current singleton/pair LogUp equation.
pub const LookupLayout = struct {
    batch_size: u8,
    interaction_coordinates_per_batch: u8,

    pub fn validate(self: LookupLayout) error{InvalidLookupLayout}!void {
        if ((self.batch_size != 1 and self.batch_size != 2) or
            self.interaction_coordinates_per_batch == 0)
        {
            return error.InvalidLookupLayout;
        }
    }
};

/// Facts not intrinsically encoded by `ir.Arena`.
pub const Context = struct {
    /// Final physical main-column count. No relationship to input-node count is
    /// inferred: selectors, materializations, and compatibility layouts are
    /// owned by separate authorities.
    physical_main_columns: ?u32 = null,
    /// Current relation batching and interaction-coordinate width.
    lookup_layout: ?LookupLayout = null,
    /// Number of expression nodes before canonical interning, when an importer
    /// retained that provenance. Native authoring normally leaves this null.
    source_expression_nodes: ?u32 = null,
    /// Optional authenticated degree-bounded materialization plan.
    materialization_plan: ?*const materializer.Plan = null,
};

pub const ValidationError = error{InvalidProfile};

/// Fixed-shape canonical record. Every nullable field means "not available
/// from this authority", never zero. The digest binds every field except
/// `profile_digest` itself in declaration order.
pub const Profile = struct {
    schema_version: u16 = SCHEMA_VERSION,
    program_digest_format: u16,
    program_digest: Digest,

    physical_main_columns: ?u32,
    logical_input_nodes: u32,
    constraint_roots: u32,
    unique_constraint_root_values: u32,
    duplicate_constraint_root_references: u32,
    effects: u32,
    lookup_events: u32,
    non_lookup_effects: u32,

    lookup_batch_size: ?u8,
    lookup_batches: ?u32,
    interaction_coordinates_per_batch: ?u8,
    interaction_columns: ?u32,

    maximum_logical_value_degree: degree.Degree,
    maximum_logical_constraint_degree: degree.Degree,
    maximum_lookup_numerator_degree: ?degree.Degree,
    maximum_lookup_denominator_degree: ?degree.Degree,
    maximum_modeled_interaction_degree: ?degree.Degree,

    materializations: ?u32,
    materialization_outputs: ?u32,
    materialization_dependency_edges: ?u32,
    materializations_with_structural_reuse: ?u32,
    maximum_materialization_body_degree: ?degree.Degree,
    maximum_materialization_constraint_degree: ?degree.Degree,

    expression_dag_nodes: u32,
    expression_dag_edges: u32,
    expression_dag_shared_nodes: u32,
    expression_dag_max_fanout: u32,
    constraint_effect_reachable_nodes: u32,
    nodes_outside_constraint_effect_closure: u32,

    source_expression_nodes: ?u32,
    cse_merges: ?u32,

    profile_digest: Digest,

    /// Allocation-free structural and digest validation.
    pub fn validate(self: *const Profile) ValidationError!void {
        const reconstructed_roots = addU32(
            self.unique_constraint_root_values,
            self.duplicate_constraint_root_references,
        ) catch return error.InvalidProfile;
        const reconstructed_effects = addU32(
            self.lookup_events,
            self.non_lookup_effects,
        ) catch return error.InvalidProfile;
        const reconstructed_nodes = addU32(
            self.constraint_effect_reachable_nodes,
            self.nodes_outside_constraint_effect_closure,
        ) catch return error.InvalidProfile;
        if (self.schema_version != SCHEMA_VERSION or
            self.program_digest_format == 0 or
            (self.physical_main_columns != null and
                self.physical_main_columns.? == 0) or
            self.logical_input_nodes > self.expression_dag_nodes or
            reconstructed_roots != self.constraint_roots or
            reconstructed_effects != self.effects or
            reconstructed_nodes != self.expression_dag_nodes or
            self.unique_constraint_root_values > self.expression_dag_nodes or
            self.expression_dag_shared_nodes > self.expression_dag_nodes or
            self.expression_dag_max_fanout > self.expression_dag_edges)
        {
            return error.InvalidProfile;
        }

        const has_lookup_layout = self.lookup_batch_size != null;
        if ((self.lookup_batches != null) != has_lookup_layout or
            (self.interaction_coordinates_per_batch != null) != has_lookup_layout or
            (self.interaction_columns != null) != has_lookup_layout or
            (self.maximum_modeled_interaction_degree != null) != has_lookup_layout)
        {
            return error.InvalidProfile;
        }
        if (has_lookup_layout) {
            const layout = LookupLayout{
                .batch_size = self.lookup_batch_size.?,
                .interaction_coordinates_per_batch = self.interaction_coordinates_per_batch.?,
            };
            layout.validate() catch return error.InvalidProfile;
            const expected_batches = batchCount(
                self.lookup_events,
                layout.batch_size,
            ) catch return error.InvalidProfile;
            const expected_columns = std.math.mul(
                u32,
                expected_batches,
                layout.interaction_coordinates_per_batch,
            ) catch return error.InvalidProfile;
            if (self.lookup_batches.? != expected_batches or
                self.interaction_columns.? != expected_columns)
            {
                return error.InvalidProfile;
            }
        }

        const has_lookups = self.lookup_events != 0;
        if ((self.maximum_lookup_numerator_degree != null) != has_lookups or
            (self.maximum_lookup_denominator_degree != null) != has_lookups)
        {
            return error.InvalidProfile;
        }

        const has_materializations = self.materializations != null;
        inline for (.{
            self.materialization_outputs,
            self.materialization_dependency_edges,
            self.materializations_with_structural_reuse,
            self.maximum_materialization_body_degree,
            self.maximum_materialization_constraint_degree,
        }) |field| {
            if ((field != null) != has_materializations)
                return error.InvalidProfile;
        }
        if (has_materializations and
            self.materializations_with_structural_reuse.? > self.materializations.?)
        {
            return error.InvalidProfile;
        }

        if ((self.source_expression_nodes != null) != (self.cse_merges != null))
            return error.InvalidProfile;
        if (self.source_expression_nodes) |source_nodes| {
            const reconstructed = addU32(
                self.expression_dag_nodes,
                self.cse_merges.?,
            ) catch return error.InvalidProfile;
            if (source_nodes != reconstructed) return error.InvalidProfile;
        }

        const expected_digest = computeDigest(self);
        if (!std.mem.eql(u8, &expected_digest, &self.profile_digest))
            return error.InvalidProfile;
    }
};

pub const Error = degree.Error || materializer.Error || error{
    CountOverflow,
    InvalidLookupLayout,
    InvalidProfileInput,
};

const NodeScratch = struct {
    reachable: bool = false,
    root_seen: bool = false,
    fanout: u32 = 0,
};

const MaterializationFacts = struct {
    count: u32,
    outputs: u32,
    dependency_edges: u32,
    reused: u32,
    maximum_body_degree: degree.Degree,
    maximum_constraint_degree: degree.Degree,
};

/// Collects a fixed-size profile. Temporary allocation is explicit through
/// `allocator`; the result borrows neither `arena`, `context`, nor a plan.
pub fn collect(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    context: Context,
) Error!Profile {
    if (context.physical_main_columns != null and
        context.physical_main_columns.? == 0)
    {
        return error.InvalidProfileInput;
    }
    if (context.lookup_layout) |layout| try layout.validate();

    var degrees = try degree.analyze(allocator, arena);
    defer degrees.deinit();
    const identity = try digest.computeIdentity(arena);

    const node_count = try count(arena.nodeCount());
    const constraint_count = try count(arena.constraintsView().len);
    const effect_count = try count(arena.effectsView().len);
    if (context.source_expression_nodes) |source_nodes| {
        if (source_nodes < node_count) return error.InvalidProfileInput;
    }

    const scratch = try allocator.alloc(NodeScratch, arena.nodeCount());
    defer allocator.free(scratch);
    @memset(scratch, .{});

    var logical_inputs: u32 = 0;
    var expression_edges: u32 = 0;
    for (arena.nodesView()) |node| {
        switch (node.key.op) {
            .input => logical_inputs = try addU32(logical_inputs, 1),
            else => {},
        }
        for (operands(node.key.op)) |optional_operand| {
            const operand = optional_operand orelse continue;
            const index = types.idIndex(operand);
            if (index >= scratch.len) return error.InvalidProfileInput;
            scratch[index].fanout = try addU32(scratch[index].fanout, 1);
            expression_edges = try addU32(expression_edges, 1);
        }
    }

    var unique_roots: u32 = 0;
    var duplicate_roots: u32 = 0;
    for (arena.constraintsView()) |constraint| {
        const root_index = types.idIndex(constraint.root);
        if (root_index >= scratch.len) return error.InvalidProfileInput;
        scratch[root_index].reachable = true;
        if (scratch[root_index].root_seen) {
            duplicate_roots = try addU32(duplicate_roots, 1);
        } else {
            scratch[root_index].root_seen = true;
            unique_roots = try addU32(unique_roots, 1);
        }
        if (constraint.gate) |gate| try markReachable(scratch, gate);
    }
    for (arena.effectsView()) |effect| {
        const values = effect.values.slice(arena.effectValuesView()) orelse
            return error.InvalidProfileInput;
        for (values) |value| try markReachable(scratch, value);
        if (effect.liveness) |liveness| try markReachable(scratch, liveness);
    }

    var reverse = arena.nodeCount();
    while (reverse > 0) {
        reverse -= 1;
        if (!scratch[reverse].reachable) continue;
        for (operands(arena.nodesView()[reverse].key.op)) |optional_operand| {
            const operand = optional_operand orelse continue;
            try markReachable(scratch, operand);
        }
    }

    var shared_nodes: u32 = 0;
    var maximum_fanout: u32 = 0;
    var reachable_nodes: u32 = 0;
    for (scratch) |item| {
        if (item.fanout > 1) shared_nodes = try addU32(shared_nodes, 1);
        maximum_fanout = @max(maximum_fanout, item.fanout);
        if (item.reachable) reachable_nodes = try addU32(reachable_nodes, 1);
    }

    var lookup_events: u32 = 0;
    var maximum_numerator: degree.Degree = 0;
    var maximum_denominator: degree.Degree = 0;
    var maximum_interaction: degree.Degree = 0;
    var pending_fraction: ?protocol_degree.FractionDegree = null;
    for (arena.effectsView()) |effect| {
        if (effect.binding == null) continue;
        const liveness = effect.liveness orelse return error.InvalidProfileInput;
        const numerator = degrees.value(liveness) orelse
            return error.InvalidProfileInput;
        const values = effect.values.slice(arena.effectValuesView()) orelse
            return error.InvalidProfileInput;
        var denominator: degree.Degree = 0;
        for (values) |value| {
            denominator = @max(
                denominator,
                degrees.value(value) orelse return error.InvalidProfileInput,
            );
        }
        maximum_numerator = @max(maximum_numerator, numerator);
        maximum_denominator = @max(maximum_denominator, denominator);
        lookup_events = try addU32(lookup_events, 1);

        if (context.lookup_layout) |layout| {
            const current = protocol_degree.FractionDegree{
                .numerator = numerator,
                .denominator = denominator,
            };
            if (layout.batch_size == 1) {
                const terms = try protocol_degree.interactionTerms(current, null);
                maximum_interaction = @max(maximum_interaction, terms.final);
            } else if (pending_fraction) |first| {
                const terms = try protocol_degree.interactionTerms(first, current);
                maximum_interaction = @max(maximum_interaction, terms.final);
                pending_fraction = null;
            } else {
                pending_fraction = current;
            }
        }
    }
    if (pending_fraction) |first| {
        const terms = try protocol_degree.interactionTerms(first, null);
        maximum_interaction = @max(maximum_interaction, terms.final);
    }

    const layout_batches: ?u32 = if (context.lookup_layout) |layout|
        try batchCount(lookup_events, layout.batch_size)
    else
        null;
    const interaction_columns: ?u32 = if (context.lookup_layout) |layout|
        std.math.mul(
            u32,
            layout_batches.?,
            layout.interaction_coordinates_per_batch,
        ) catch return error.CountOverflow
    else
        null;

    const materialization_facts: ?MaterializationFacts =
        if (context.materialization_plan) |plan| blk: {
            try plan.validate(allocator, arena);
            var reused: u32 = 0;
            var maximum_body: degree.Degree = 0;
            var maximum_constraint: degree.Degree = 0;
            for (plan.materializations) |item| {
                if (item.structural_use_count > 1)
                    reused = try addU32(reused, 1);
                const body_degree = std.math.cast(
                    degree.Degree,
                    item.body_degree,
                ) orelse return error.CountOverflow;
                const constraint_degree = std.math.cast(
                    degree.Degree,
                    item.constraint_degree,
                ) orelse return error.CountOverflow;
                maximum_body = @max(maximum_body, body_degree);
                maximum_constraint = @max(
                    maximum_constraint,
                    constraint_degree,
                );
            }
            break :blk .{
                .count = try count(plan.materializations.len),
                .outputs = try count(plan.outputs.len),
                .dependency_edges = try count(plan.dependencies.len),
                .reused = reused,
                .maximum_body_degree = maximum_body,
                .maximum_constraint_degree = maximum_constraint,
            };
        } else null;

    var profile = Profile{
        .program_digest_format = identity.format_version,
        .program_digest = identity.bytes,
        .physical_main_columns = context.physical_main_columns,
        .logical_input_nodes = logical_inputs,
        .constraint_roots = constraint_count,
        .unique_constraint_root_values = unique_roots,
        .duplicate_constraint_root_references = duplicate_roots,
        .effects = effect_count,
        .lookup_events = lookup_events,
        .non_lookup_effects = effect_count - lookup_events,
        .lookup_batch_size = if (context.lookup_layout) |layout|
            layout.batch_size
        else
            null,
        .lookup_batches = layout_batches,
        .interaction_coordinates_per_batch = if (context.lookup_layout) |layout|
            layout.interaction_coordinates_per_batch
        else
            null,
        .interaction_columns = interaction_columns,
        .maximum_logical_value_degree = degrees.maximumValueDegree(),
        .maximum_logical_constraint_degree = degrees.maximumConstraintDegree(),
        .maximum_lookup_numerator_degree = if (lookup_events == 0)
            null
        else
            maximum_numerator,
        .maximum_lookup_denominator_degree = if (lookup_events == 0)
            null
        else
            maximum_denominator,
        .maximum_modeled_interaction_degree = if (context.lookup_layout != null)
            maximum_interaction
        else
            null,
        .materializations = if (materialization_facts) |facts| facts.count else null,
        .materialization_outputs = if (materialization_facts) |facts| facts.outputs else null,
        .materialization_dependency_edges = if (materialization_facts) |facts|
            facts.dependency_edges
        else
            null,
        .materializations_with_structural_reuse = if (materialization_facts) |facts|
            facts.reused
        else
            null,
        .maximum_materialization_body_degree = if (materialization_facts) |facts|
            facts.maximum_body_degree
        else
            null,
        .maximum_materialization_constraint_degree = if (materialization_facts) |facts|
            facts.maximum_constraint_degree
        else
            null,
        .expression_dag_nodes = node_count,
        .expression_dag_edges = expression_edges,
        .expression_dag_shared_nodes = shared_nodes,
        .expression_dag_max_fanout = maximum_fanout,
        .constraint_effect_reachable_nodes = reachable_nodes,
        .nodes_outside_constraint_effect_closure = node_count - reachable_nodes,
        .source_expression_nodes = context.source_expression_nodes,
        .cse_merges = if (context.source_expression_nodes) |source_nodes|
            source_nodes - node_count
        else
            null,
        .profile_digest = undefined,
    };
    profile.profile_digest = computeDigest(&profile);
    profile.validate() catch return error.InvalidProfileInput;
    return profile;
}

/// Canonical single-line JSON. Field order is schema, not declaration, order;
/// nullable integer fields are emitted as JSON `null`.
pub fn writeJson(
    writer: *std.Io.Writer,
    profile: *const Profile,
) (ValidationError || std.Io.Writer.Error)!void {
    try profile.validate();
    try writer.writeAll("{\"schema\":\"" ++ SCHEMA ++ "\",\"schema_version\":");
    try writer.print("{d}", .{profile.schema_version});
    try writer.writeAll(",\"profile_sha256\":\"");
    try writeHex(writer, profile.profile_digest);
    try writer.writeAll("\",\"program_digest_format\":");
    try writer.print("{d}", .{profile.program_digest_format});
    try writer.writeAll(",\"program_sha256\":\"");
    try writeHex(writer, profile.program_digest);
    try writer.writeAll("\",\"physical_main_columns\":");
    try writeOptional(writer, profile.physical_main_columns);
    try writer.print(
        ",\"logical_input_nodes\":{d}" ++
            ",\"constraint_roots\":{d}" ++
            ",\"unique_constraint_root_values\":{d}" ++
            ",\"duplicate_constraint_root_references\":{d}" ++
            ",\"effects\":{d},\"lookup_events\":{d}" ++
            ",\"non_lookup_effects\":{d}",
        .{
            profile.logical_input_nodes,
            profile.constraint_roots,
            profile.unique_constraint_root_values,
            profile.duplicate_constraint_root_references,
            profile.effects,
            profile.lookup_events,
            profile.non_lookup_effects,
        },
    );
    try writer.writeAll(",\"lookup_batch_size\":");
    try writeOptional(writer, profile.lookup_batch_size);
    try writer.writeAll(",\"lookup_batches\":");
    try writeOptional(writer, profile.lookup_batches);
    try writer.writeAll(",\"interaction_coordinates_per_batch\":");
    try writeOptional(writer, profile.interaction_coordinates_per_batch);
    try writer.writeAll(",\"interaction_columns\":");
    try writeOptional(writer, profile.interaction_columns);
    try writer.print(
        ",\"maximum_logical_value_degree\":{d}" ++
            ",\"maximum_logical_constraint_degree\":{d}",
        .{
            profile.maximum_logical_value_degree,
            profile.maximum_logical_constraint_degree,
        },
    );
    try writer.writeAll(",\"maximum_lookup_numerator_degree\":");
    try writeOptional(writer, profile.maximum_lookup_numerator_degree);
    try writer.writeAll(",\"maximum_lookup_denominator_degree\":");
    try writeOptional(writer, profile.maximum_lookup_denominator_degree);
    try writer.writeAll(",\"maximum_modeled_interaction_degree\":");
    try writeOptional(writer, profile.maximum_modeled_interaction_degree);
    try writer.writeAll(",\"materializations\":");
    try writeOptional(writer, profile.materializations);
    try writer.writeAll(",\"materialization_outputs\":");
    try writeOptional(writer, profile.materialization_outputs);
    try writer.writeAll(",\"materialization_dependency_edges\":");
    try writeOptional(writer, profile.materialization_dependency_edges);
    try writer.writeAll(",\"materializations_with_structural_reuse\":");
    try writeOptional(writer, profile.materializations_with_structural_reuse);
    try writer.writeAll(",\"maximum_materialization_body_degree\":");
    try writeOptional(writer, profile.maximum_materialization_body_degree);
    try writer.writeAll(",\"maximum_materialization_constraint_degree\":");
    try writeOptional(writer, profile.maximum_materialization_constraint_degree);
    try writer.print(
        ",\"expression_dag_nodes\":{d}" ++
            ",\"expression_dag_edges\":{d}" ++
            ",\"expression_dag_shared_nodes\":{d}" ++
            ",\"expression_dag_max_fanout\":{d}" ++
            ",\"constraint_effect_reachable_nodes\":{d}" ++
            ",\"nodes_outside_constraint_effect_closure\":{d}",
        .{
            profile.expression_dag_nodes,
            profile.expression_dag_edges,
            profile.expression_dag_shared_nodes,
            profile.expression_dag_max_fanout,
            profile.constraint_effect_reachable_nodes,
            profile.nodes_outside_constraint_effect_closure,
        },
    );
    try writer.writeAll(",\"source_expression_nodes\":");
    try writeOptional(writer, profile.source_expression_nodes);
    try writer.writeAll(",\"cse_merges\":");
    try writeOptional(writer, profile.cse_merges);
    try writer.writeAll("}\n");
}

pub const TSV_COLUMNS =
    "schema\tschema_version\tprofile_sha256\tprogram_digest_format" ++
    "\tprogram_sha256\tphysical_main_columns\tlogical_input_nodes" ++
    "\tconstraint_roots\tunique_constraint_root_values" ++
    "\tduplicate_constraint_root_references\teffects\tlookup_events" ++
    "\tnon_lookup_effects\tlookup_batch_size\tlookup_batches" ++
    "\tinteraction_coordinates_per_batch\tinteraction_columns" ++
    "\tmaximum_logical_value_degree\tmaximum_logical_constraint_degree" ++
    "\tmaximum_lookup_numerator_degree\tmaximum_lookup_denominator_degree" ++
    "\tmaximum_modeled_interaction_degree\tmaterializations" ++
    "\tmaterialization_outputs\tmaterialization_dependency_edges" ++
    "\tmaterializations_with_structural_reuse" ++
    "\tmaximum_materialization_body_degree" ++
    "\tmaximum_materialization_constraint_degree\texpression_dag_nodes" ++
    "\texpression_dag_edges\texpression_dag_shared_nodes" ++
    "\texpression_dag_max_fanout\tconstraint_effect_reachable_nodes" ++
    "\tnodes_outside_constraint_effect_closure\tsource_expression_nodes" ++
    "\tcse_merges";

pub fn writeTsvHeader(writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try writer.writeAll(TSV_COLUMNS);
    try writer.writeByte('\n');
}

/// Canonical TSV row using `null` for unavailable integer facts.
pub fn writeTsvRecord(
    writer: *std.Io.Writer,
    profile: *const Profile,
) (ValidationError || std.Io.Writer.Error)!void {
    try profile.validate();
    try writer.writeAll(SCHEMA);
    try writer.print("\t{d}\t", .{profile.schema_version});
    try writeHex(writer, profile.profile_digest);
    try writer.print("\t{d}\t", .{profile.program_digest_format});
    try writeHex(writer, profile.program_digest);
    try writer.writeByte('\t');
    try writeOptional(writer, profile.physical_main_columns);
    inline for (.{
        profile.logical_input_nodes,
        profile.constraint_roots,
        profile.unique_constraint_root_values,
        profile.duplicate_constraint_root_references,
        profile.effects,
        profile.lookup_events,
        profile.non_lookup_effects,
    }) |value| try writer.print("\t{d}", .{value});
    try writer.writeByte('\t');
    try writeOptional(writer, profile.lookup_batch_size);
    try writer.writeByte('\t');
    try writeOptional(writer, profile.lookup_batches);
    try writer.writeByte('\t');
    try writeOptional(writer, profile.interaction_coordinates_per_batch);
    try writer.writeByte('\t');
    try writeOptional(writer, profile.interaction_columns);
    try writer.print(
        "\t{d}\t{d}\t",
        .{
            profile.maximum_logical_value_degree,
            profile.maximum_logical_constraint_degree,
        },
    );
    try writeOptional(writer, profile.maximum_lookup_numerator_degree);
    try writer.writeByte('\t');
    try writeOptional(writer, profile.maximum_lookup_denominator_degree);
    try writer.writeByte('\t');
    try writeOptional(writer, profile.maximum_modeled_interaction_degree);
    inline for (.{
        profile.materializations,
        profile.materialization_outputs,
        profile.materialization_dependency_edges,
        profile.materializations_with_structural_reuse,
        profile.maximum_materialization_body_degree,
        profile.maximum_materialization_constraint_degree,
    }) |value| {
        try writer.writeByte('\t');
        try writeOptional(writer, value);
    }
    inline for (.{
        profile.expression_dag_nodes,
        profile.expression_dag_edges,
        profile.expression_dag_shared_nodes,
        profile.expression_dag_max_fanout,
        profile.constraint_effect_reachable_nodes,
        profile.nodes_outside_constraint_effect_closure,
    }) |value| try writer.print("\t{d}", .{value});
    try writer.writeByte('\t');
    try writeOptional(writer, profile.source_expression_nodes);
    try writer.writeByte('\t');
    try writeOptional(writer, profile.cse_merges);
    try writer.writeByte('\n');
}

fn computeDigest(profile: *const Profile) Digest {
    var hash = Sha256.init(.{});
    hash.update(DIGEST_DOMAIN);
    hashInt(&hash, u16, profile.schema_version);
    hashInt(&hash, u16, profile.program_digest_format);
    hash.update(&profile.program_digest);
    hashOptionalInt(&hash, u32, profile.physical_main_columns);
    inline for (.{
        profile.logical_input_nodes,
        profile.constraint_roots,
        profile.unique_constraint_root_values,
        profile.duplicate_constraint_root_references,
        profile.effects,
        profile.lookup_events,
        profile.non_lookup_effects,
    }) |value| hashInt(&hash, u32, value);
    hashOptionalInt(&hash, u8, profile.lookup_batch_size);
    hashOptionalInt(&hash, u32, profile.lookup_batches);
    hashOptionalInt(&hash, u8, profile.interaction_coordinates_per_batch);
    hashOptionalInt(&hash, u32, profile.interaction_columns);
    hashInt(&hash, u32, profile.maximum_logical_value_degree);
    hashInt(&hash, u32, profile.maximum_logical_constraint_degree);
    hashOptionalInt(&hash, u32, profile.maximum_lookup_numerator_degree);
    hashOptionalInt(&hash, u32, profile.maximum_lookup_denominator_degree);
    hashOptionalInt(&hash, u32, profile.maximum_modeled_interaction_degree);
    hashOptionalInt(&hash, u32, profile.materializations);
    hashOptionalInt(&hash, u32, profile.materialization_outputs);
    hashOptionalInt(&hash, u32, profile.materialization_dependency_edges);
    hashOptionalInt(&hash, u32, profile.materializations_with_structural_reuse);
    hashOptionalInt(&hash, u32, profile.maximum_materialization_body_degree);
    hashOptionalInt(&hash, u32, profile.maximum_materialization_constraint_degree);
    inline for (.{
        profile.expression_dag_nodes,
        profile.expression_dag_edges,
        profile.expression_dag_shared_nodes,
        profile.expression_dag_max_fanout,
        profile.constraint_effect_reachable_nodes,
        profile.nodes_outside_constraint_effect_closure,
    }) |value| hashInt(&hash, u32, value);
    hashOptionalInt(&hash, u32, profile.source_expression_nodes);
    hashOptionalInt(&hash, u32, profile.cse_merges);
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn hashOptionalInt(
    hash: *Sha256,
    comptime T: type,
    value: ?T,
) void {
    if (value) |present| {
        hashInt(hash, u8, 1);
        hashInt(hash, T, present);
    } else {
        hashInt(hash, u8, 0);
    }
}

fn writeHex(writer: *std.Io.Writer, value: Digest) std.Io.Writer.Error!void {
    const rendered = std.fmt.bytesToHex(value, .lower);
    try writer.writeAll(&rendered);
}

fn writeOptional(writer: *std.Io.Writer, value: anytype) std.Io.Writer.Error!void {
    if (value) |present| {
        try writer.print("{d}", .{present});
    } else {
        try writer.writeAll("null");
    }
}

fn markReachable(scratch: []NodeScratch, value: types.ValueId) Error!void {
    const index = types.idIndex(value);
    if (index >= scratch.len) return error.InvalidProfileInput;
    scratch[index].reachable = true;
}

fn operands(op: expr.Op) [3]?types.ValueId {
    return switch (op) {
        .constant, .input, .hint_output, .call_output => .{ null, null, null },
        .add, .sub, .mul => |binary| .{ binary.lhs, binary.rhs, null },
        .neg => |value| .{ value, null, null },
        .select => |selection| .{
            selection.selector,
            selection.when_true,
            selection.when_false,
        },
        .machine_derived => |derived| switch (derived) {
            .register_address => |address| .{ address.index, null, null },
            .aligned_word_address => |address| .{ address.word_index, null, null },
            .access_clock => |clock| .{ clock.instruction_clock, null, null },
            // The active selector constrains admissible machine use but is not
            // an operand of the derived clock-gap polynomial, matching the
            // materializer's canonical expression-DAG projection.
            .strict_clock_gap => |gap| .{
                gap.current_clock,
                gap.previous_clock,
                null,
            },
            .instruction_next_pc => |next| .{ next.current, null, null },
            .instruction_next_clock => |next| .{ next.current, null, null },
        },
    };
}

fn batchCount(lookups: u32, batch_size: u8) error{CountOverflow}!u32 {
    if (lookups == 0) return 0;
    const rounded = std.math.add(u32, lookups, batch_size - 1) catch
        return error.CountOverflow;
    return rounded / batch_size;
}

fn count(value: usize) error{CountOverflow}!u32 {
    return std.math.cast(u32, value) orelse error.CountOverflow;
}

fn addU32(lhs: u32, rhs: u32) error{CountOverflow}!u32 {
    return std.math.add(u32, lhs, rhs) catch error.CountOverflow;
}
