//! Cold-path static profiles for the complete native opcode-family inventory.
//!
//! Every family is bound at comptime to one concrete native typed definition;
//! `base_alu_imm` deliberately binds `typed_addi`, whose program covers that
//! production family. Collection builds and validates those definitions
//! directly, then runs the allocation-explicit static profiler. There is no
//! source-name factory, runtime string dispatch, witness execution, telemetry,
//! or timing measurement on this path.
//!
//! Native program facts and integration facts are intentionally separate. The
//! program digest, direct roots, effects, expression DAG, and physical width
//! come from each typed definition. LogUp batching is labeled as current
//! audited protocol geometry. Production activation is explicitly not assessed
//! here: whether a witness/prover path has cut over belongs to another report.

const std = @import("std");
const opcode_manifest = @import("../../opcode_manifest.zig");
const static_profile = @import("static_profile.zig");
const typed_addi = @import("typed_addi.zig");
const typed_auipc = @import("typed_auipc.zig");
const typed_base_alu_reg = @import("typed_base_alu_reg.zig");
const typed_branch_eq = @import("typed_branch_eq.zig");
const typed_branch_lt = @import("typed_branch_lt.zig");
const typed_div = @import("typed_div.zig");
const typed_fence = @import("typed_fence.zig");
const typed_jal = @import("typed_jal.zig");
const typed_jalr = @import("typed_jalr.zig");
const typed_load_store = @import("typed_load_store.zig");
const typed_lt_imm = @import("typed_lt_imm.zig");
const typed_lt_reg = @import("typed_lt_reg.zig");
const typed_lui = @import("typed_lui.zig");
const typed_mul = @import("typed_mul.zig");
const typed_mulh = @import("typed_mulh.zig");
const typed_shifts_imm = @import("typed_shifts_imm.zig");
const typed_shifts_reg = @import("typed_shifts_reg.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const SCHEMA = "stwo.typed-air.native-family-static-profile.v1";
pub const SCHEMA_VERSION: u16 = 1;
pub const DIGEST_DOMAIN =
    "stwo-zig/typed-air/native-family-static-profile/v1\x00";
pub const INTERACTION_COORDINATES_PER_BATCH: u8 = 4;

pub const Family = opcode_manifest.Family;
pub const FAMILY_COUNT: usize = @typeInfo(Family).@"enum".fields.len;
pub const Digest = static_profile.Digest;

/// Stable order inherited from the proof-family protocol enum.
pub const FAMILY_ORDER = [_]Family{
    .base_alu_reg,
    .base_alu_imm,
    .shifts_reg,
    .shifts_imm,
    .lt_reg,
    .lt_imm,
    .branch_eq,
    .branch_lt,
    .lui,
    .auipc,
    .jalr,
    .jal,
    .load_store,
    .mul,
    .mulh,
    .div,
    .fence,
};

pub const ProgramAuthority = enum(u8) {
    native_typed_definition = 1,
};

/// This cold report does not inspect witness/prover dispatch.
pub const ProductionActivation = enum(u8) {
    not_assessed = 0,
};

/// Batching is integration context, not an intrinsic `ir.Arena` fact.
pub const LookupGeometryAuthority = enum(u8) {
    current_audited_protocol = 1,
};

/// Compile-time binding between one proof family and one native definition.
pub const Descriptor = struct {
    family: Family,
    native_definition: []const u8,
    physical_main_columns: u32,
    authored_constraint_roots: u32,
    authored_lookup_events: u32,
    audited_lookup_batch_size: u8,
    semantic_program_digest: Digest,
};

pub const DESCRIPTORS: [FAMILY_COUNT]Descriptor = blk: {
    var descriptors: [FAMILY_COUNT]Descriptor = undefined;
    for (FAMILY_ORDER, 0..) |family, index|
        descriptors[index] = descriptorFor(family);
    break :blk descriptors;
};

comptime {
    if (FAMILY_ORDER.len != FAMILY_COUNT)
        @compileError("native typed family inventory is incomplete");
    for (FAMILY_ORDER, 0..) |family, index| {
        if (@intFromEnum(family) != index)
            @compileError("native typed family inventory is not protocol ordered");
    }
}

pub const FamilyProfile = struct {
    family: Family,
    program_authority: ProgramAuthority,
    production_activation: ProductionActivation,
    lookup_geometry_authority: LookupGeometryAuthority,
    profile: static_profile.Profile,
};

pub const Totals = struct {
    physical_main_columns: u64 = 0,
    logical_input_nodes: u64 = 0,
    constraint_roots: u64 = 0,
    effects: u64 = 0,
    lookup_events: u64 = 0,
    lookup_batches: u64 = 0,
    interaction_columns: u64 = 0,
    expression_dag_nodes: u64 = 0,
    expression_dag_edges: u64 = 0,
    expression_dag_shared_nodes: u64 = 0,
    constraint_effect_reachable_nodes: u64 = 0,
    nodes_outside_constraint_effect_closure: u64 = 0,
    maximum_logical_constraint_degree: u32 = 0,
    maximum_lookup_numerator_degree: u32 = 0,
    maximum_lookup_denominator_degree: u32 = 0,
    maximum_modeled_interaction_degree: u32 = 0,
};

pub const ValidationError = error{InvalidReport};

pub const Report = struct {
    schema_version: u16 = SCHEMA_VERSION,
    families: [FAMILY_COUNT]FamilyProfile,
    totals: Totals,
    report_digest: Digest,

    /// Allocation-free validation of order, authorities, native program facts,
    /// aggregate geometry, every child digest, and the report digest.
    pub fn validate(self: *const Report) ValidationError!void {
        if (self.schema_version != SCHEMA_VERSION)
            return error.InvalidReport;

        for (self.families, 0..) |family_profile, index| {
            const descriptor = DESCRIPTORS[index];
            family_profile.profile.validate() catch return error.InvalidReport;
            if (@intFromEnum(family_profile.family) != index or
                family_profile.family != descriptor.family or
                family_profile.program_authority != .native_typed_definition or
                family_profile.production_activation != .not_assessed or
                family_profile.lookup_geometry_authority != .current_audited_protocol or
                family_profile.profile.physical_main_columns !=
                    descriptor.physical_main_columns or
                family_profile.profile.constraint_roots !=
                    descriptor.authored_constraint_roots or
                family_profile.profile.effects != descriptor.authored_lookup_events or
                family_profile.profile.lookup_events !=
                    descriptor.authored_lookup_events or
                family_profile.profile.non_lookup_effects != 0 or
                family_profile.profile.lookup_batch_size !=
                    descriptor.audited_lookup_batch_size or
                family_profile.profile.interaction_coordinates_per_batch !=
                    INTERACTION_COORDINATES_PER_BATCH or
                !std.mem.eql(
                    u8,
                    &family_profile.profile.program_digest,
                    &descriptor.semantic_program_digest,
                ) or
                family_profile.profile.materializations != null or
                family_profile.profile.source_expression_nodes != null or
                family_profile.profile.cse_merges != null)
            {
                return error.InvalidReport;
            }
        }

        const expected_totals = totalsFor(&self.families) catch
            return error.InvalidReport;
        if (!std.meta.eql(expected_totals, self.totals) or
            !std.mem.eql(u8, &computeDigest(self), &self.report_digest))
        {
            return error.InvalidReport;
        }
    }
};

/// Builds all seventeen native definitions in protocol order and returns a
/// fixed-shape report which owns no memory. This is intentionally a cold path.
pub fn collect(allocator: std.mem.Allocator) !Report {
    var report: Report = undefined;
    report.schema_version = SCHEMA_VERSION;
    inline for (FAMILY_ORDER, 0..) |family, index|
        report.families[index] = try collectFamily(allocator, family);
    report.totals = try totalsFor(&report.families);
    report.report_digest = computeDigest(&report);
    try report.validate();
    return report;
}

pub const TSV_COLUMNS =
    "report_schema\treport_schema_version\treport_sha256\tfamily_index\tfamily" ++
    "\tnative_definition\tprogram_authority\tproduction_activation" ++
    "\tlookup_geometry_authority\t" ++ static_profile.TSV_COLUMNS;

/// Canonical family-ordered TSV. Every row carries the complete P-001 profile
/// schema after its inventory metadata. The report and child profile digests
/// make the projection independently checkable without serializing telemetry.
pub fn writeTsv(
    writer: *std.Io.Writer,
    report: *const Report,
) (ValidationError || std.Io.Writer.Error)!void {
    try report.validate();
    try writer.writeAll(TSV_COLUMNS);
    try writer.writeByte('\n');

    const report_hex = std.fmt.bytesToHex(report.report_digest, .lower);
    for (report.families, 0..) |family_profile, index| {
        const descriptor = DESCRIPTORS[index];
        try writer.print(
            "{s}\t{d}\t{s}\t{d}\t{s}\t{s}\t{s}\t{s}\t{s}\t",
            .{
                SCHEMA,
                report.schema_version,
                &report_hex,
                index,
                @tagName(family_profile.family),
                descriptor.native_definition,
                @tagName(family_profile.program_authority),
                @tagName(family_profile.production_activation),
                @tagName(family_profile.lookup_geometry_authority),
            },
        );
        static_profile.writeTsvRecord(writer, &family_profile.profile) catch |err|
            switch (err) {
                error.InvalidProfile => return error.InvalidReport,
                error.WriteFailed => return error.WriteFailed,
            };
    }
}

/// Deterministic human review view of the authenticated machine report.
pub fn writeMarkdown(
    writer: *std.Io.Writer,
    report: *const Report,
) (ValidationError || std.Io.Writer.Error)!void {
    try report.validate();
    const report_hex = std.fmt.bytesToHex(report.report_digest, .lower);
    try writer.writeAll(
        "# P-002 native typed-family static profiles\n\n" ++
            "> Shadow/profile evidence only. This report does not activate a " ++
            "typed definition in the production prover, alter a proof statement, " ++
            "or contain runtime performance telemetry.\n\n" ++
            "## Identity and authority\n\n" ++
            "| Field | Value |\n| --- | --- |\n",
    );
    try writer.print(
        "| Schema | `{s}` v{d} |\n" ++
            "| Report SHA-256 | `{s}` |\n" ++
            "| Families | {d}, in production protocol enum order |\n" ++
            "| Native program authority | `{s}` |\n" ++
            "| Production activation | `{s}` |\n" ++
            "| Lookup geometry authority | `{s}` |\n\n",
        .{
            SCHEMA,
            report.schema_version,
            &report_hex,
            report.families.len,
            @tagName(ProgramAuthority.native_typed_definition),
            @tagName(ProductionActivation.not_assessed),
            @tagName(LookupGeometryAuthority.current_audited_protocol),
        },
    );

    try writer.writeAll(
        "## Aggregate static facts\n\n" ++
            "| Coordinate | Sum or maximum |\n| --- | ---: |\n",
    );
    try writer.print(
        "| Physical main columns | {d} |\n" ++
            "| Logical input nodes | {d} |\n" ++
            "| Direct constraint roots | {d} |\n" ++
            "| Typed effects / lookup events | {d} / {d} |\n" ++
            "| Lookup batches / interaction coordinates | {d} / {d} |\n" ++
            "| Expression DAG nodes / edges / shared nodes | {d} / {d} / {d} |\n" ++
            "| Reachable / outside-closure nodes | {d} / {d} |\n" ++
            "| Maximum degree: direct / numerator / denominator / interaction | " ++
            "{d} / {d} / {d} / {d} |\n\n",
        .{
            report.totals.physical_main_columns,
            report.totals.logical_input_nodes,
            report.totals.constraint_roots,
            report.totals.effects,
            report.totals.lookup_events,
            report.totals.lookup_batches,
            report.totals.interaction_columns,
            report.totals.expression_dag_nodes,
            report.totals.expression_dag_edges,
            report.totals.expression_dag_shared_nodes,
            report.totals.constraint_effect_reachable_nodes,
            report.totals.nodes_outside_constraint_effect_closure,
            report.totals.maximum_logical_constraint_degree,
            report.totals.maximum_lookup_numerator_degree,
            report.totals.maximum_lookup_denominator_degree,
            report.totals.maximum_modeled_interaction_degree,
        },
    );

    try writer.writeAll(
        "## Family profiles\n\n" ++
            "Degree columns are logical value, direct constraint, lookup numerator, " ++
            "lookup denominator, and modeled interaction degree. DAG columns are " ++
            "nodes, edges, structurally shared nodes, and nodes outside the " ++
            "constraint/effect closure.\n\n" ++
            "| # | Family | Native definition | Program SHA-256 | Main / inputs | " ++
            "Roots | Lookups / batch / batches / interaction | Degrees V/C/N/Den/I | " ++
            "DAG N/E/S/O |\n" ++
            "| ---: | --- | --- | --- | ---: | ---: | ---: | ---: | ---: |\n",
    );
    for (report.families, 0..) |family_profile, index| {
        const descriptor = DESCRIPTORS[index];
        const profile = family_profile.profile;
        const program_hex = std.fmt.bytesToHex(profile.program_digest, .lower);
        try writer.print(
            "| {d} | `{s}` | `{s}` | `{s}` | {d} / {d} | {d} | " ++
                "{d} / {d} / {d} / {d} | {d}/{d}/{d}/{d}/{d} | " ++
                "{d}/{d}/{d}/{d} |\n",
            .{
                index,
                @tagName(family_profile.family),
                descriptor.native_definition,
                &program_hex,
                profile.physical_main_columns.?,
                profile.logical_input_nodes,
                profile.constraint_roots,
                profile.lookup_events,
                profile.lookup_batch_size.?,
                profile.lookup_batches.?,
                profile.interaction_columns.?,
                profile.maximum_logical_value_degree,
                profile.maximum_logical_constraint_degree,
                profile.maximum_lookup_numerator_degree.?,
                profile.maximum_lookup_denominator_degree.?,
                profile.maximum_modeled_interaction_degree.?,
                profile.expression_dag_nodes,
                profile.expression_dag_edges,
                profile.expression_dag_shared_nodes,
                profile.nodes_outside_constraint_effect_closure,
            },
        );
    }
    try writer.writeAll(
        "\nThe machine TSV carries every field in the complete P-001 static-profile " ++
            "schema. `null` materialization and source-CSE coordinates mean that no " ++
            "materialization plan or pre-interning provenance was supplied; they do " ++
            "not mean zero work. Layout, batching, batch count, interaction-column " ++
            "count, and degree coordinates are regenerated against the audited " ++
            "production shadow report before reviewed artifact bytes are admitted.\n",
    );
}

fn collectFamily(
    allocator: std.mem.Allocator,
    comptime family: Family,
) !FamilyProfile {
    const Module = moduleFor(family);
    const descriptor = descriptorFor(family);
    var definition = try Module.build(allocator, .generated);
    defer definition.deinit();
    try definition.validate();

    const profile = try static_profile.collect(
        allocator,
        &definition.arena,
        .{
            .physical_main_columns = descriptor.physical_main_columns,
            .lookup_layout = .{
                .batch_size = descriptor.audited_lookup_batch_size,
                .interaction_coordinates_per_batch = INTERACTION_COORDINATES_PER_BATCH,
            },
        },
    );
    return .{
        .family = family,
        .program_authority = .native_typed_definition,
        .production_activation = .not_assessed,
        .lookup_geometry_authority = .current_audited_protocol,
        .profile = profile,
    };
}

fn descriptorFor(comptime family: Family) Descriptor {
    const Module = moduleFor(family);
    return .{
        .family = family,
        .native_definition = definitionName(family),
        .physical_main_columns = comptimeCount(Module.MAIN_COLUMN_COUNT),
        .authored_constraint_roots = comptimeCount(Module.DIRECT_CONSTRAINT_COUNT),
        .authored_lookup_events = comptimeCount(lookupCount(Module)),
        .audited_lookup_batch_size = batchSize(Module, family),
        .semantic_program_digest = Module.SEMANTIC_DIGEST,
    };
}

fn moduleFor(comptime family: Family) type {
    return switch (family) {
        .base_alu_reg => typed_base_alu_reg,
        .base_alu_imm => typed_addi,
        .shifts_reg => typed_shifts_reg,
        .shifts_imm => typed_shifts_imm,
        .lt_reg => typed_lt_reg,
        .lt_imm => typed_lt_imm,
        .branch_eq => typed_branch_eq,
        .branch_lt => typed_branch_lt,
        .lui => typed_lui,
        .auipc => typed_auipc,
        .jalr => typed_jalr,
        .jal => typed_jal,
        .load_store => typed_load_store,
        .mul => typed_mul,
        .mulh => typed_mulh,
        .div => typed_div,
        .fence => typed_fence,
    };
}

fn definitionName(comptime family: Family) []const u8 {
    return switch (family) {
        .base_alu_reg => "typed_base_alu_reg",
        .base_alu_imm => "typed_addi",
        .shifts_reg => "typed_shifts_reg",
        .shifts_imm => "typed_shifts_imm",
        .lt_reg => "typed_lt_reg",
        .lt_imm => "typed_lt_imm",
        .branch_eq => "typed_branch_eq",
        .branch_lt => "typed_branch_lt",
        .lui => "typed_lui",
        .auipc => "typed_auipc",
        .jalr => "typed_jalr",
        .jal => "typed_jal",
        .load_store => "typed_load_store",
        .mul => "typed_mul",
        .mulh => "typed_mulh",
        .div => "typed_div",
        .fence => "typed_fence",
    };
}

fn lookupCount(comptime Module: type) usize {
    if (@hasDecl(Module, "LOOKUP_COUNT")) return Module.LOOKUP_COUNT;
    if (@hasDecl(Module, "RELATION_EVENT_COUNT"))
        return Module.RELATION_EVENT_COUNT;
    @compileError("native typed definition does not publish its lookup count");
}

fn batchSize(comptime Module: type, comptime family: Family) u8 {
    const audited = comptime auditedBatchSize(family);
    if (@hasDecl(Module, "LOOKUP_BATCH_SIZE")) {
        const declared = comptime Module.LOOKUP_BATCH_SIZE;
        if (comptime declared != audited)
            @compileError("native batch declaration disagrees with audited protocol");
    } else if (@hasDecl(Module, "RELATION_BATCH_SIZE")) {
        const declared = comptime Module.RELATION_BATCH_SIZE;
        if (comptime declared != audited)
            @compileError("native batch declaration disagrees with audited protocol");
    }
    return audited;
}

fn auditedBatchSize(comptime family: Family) u8 {
    return switch (family) {
        .mul, .mulh, .div => 1,
        else => 2,
    };
}

fn comptimeCount(comptime value: usize) u32 {
    return @intCast(value);
}

fn totalsFor(families: *const [FAMILY_COUNT]FamilyProfile) !Totals {
    var totals = Totals{};
    for (families) |family_profile| {
        const profile = family_profile.profile;
        const physical = profile.physical_main_columns orelse
            return error.InvalidReport;
        const batches = profile.lookup_batches orelse return error.InvalidReport;
        const interaction_columns = profile.interaction_columns orelse
            return error.InvalidReport;
        const numerator = profile.maximum_lookup_numerator_degree orelse
            return error.InvalidReport;
        const denominator = profile.maximum_lookup_denominator_degree orelse
            return error.InvalidReport;
        const interaction = profile.maximum_modeled_interaction_degree orelse
            return error.InvalidReport;

        totals.physical_main_columns += physical;
        totals.logical_input_nodes += profile.logical_input_nodes;
        totals.constraint_roots += profile.constraint_roots;
        totals.effects += profile.effects;
        totals.lookup_events += profile.lookup_events;
        totals.lookup_batches += batches;
        totals.interaction_columns += interaction_columns;
        totals.expression_dag_nodes += profile.expression_dag_nodes;
        totals.expression_dag_edges += profile.expression_dag_edges;
        totals.expression_dag_shared_nodes += profile.expression_dag_shared_nodes;
        totals.constraint_effect_reachable_nodes +=
            profile.constraint_effect_reachable_nodes;
        totals.nodes_outside_constraint_effect_closure +=
            profile.nodes_outside_constraint_effect_closure;
        totals.maximum_logical_constraint_degree = @max(
            totals.maximum_logical_constraint_degree,
            profile.maximum_logical_constraint_degree,
        );
        totals.maximum_lookup_numerator_degree = @max(
            totals.maximum_lookup_numerator_degree,
            numerator,
        );
        totals.maximum_lookup_denominator_degree = @max(
            totals.maximum_lookup_denominator_degree,
            denominator,
        );
        totals.maximum_modeled_interaction_degree = @max(
            totals.maximum_modeled_interaction_degree,
            interaction,
        );
    }
    return totals;
}

fn computeDigest(report: *const Report) Digest {
    var hash = Sha256.init(.{});
    hash.update(DIGEST_DOMAIN);
    hashInt(&hash, u16, report.schema_version);
    hashInt(&hash, u16, @intCast(FAMILY_COUNT));
    for (report.families, 0..) |family_profile, index| {
        const descriptor = DESCRIPTORS[index];
        hashInt(&hash, u8, @intFromEnum(family_profile.family));
        hashBytes(&hash, descriptor.native_definition);
        hashInt(&hash, u8, @intFromEnum(family_profile.program_authority));
        hashInt(&hash, u8, @intFromEnum(family_profile.production_activation));
        hashInt(&hash, u8, @intFromEnum(family_profile.lookup_geometry_authority));
        hash.update(&family_profile.profile.profile_digest);
    }
    inline for (.{
        report.totals.physical_main_columns,
        report.totals.logical_input_nodes,
        report.totals.constraint_roots,
        report.totals.effects,
        report.totals.lookup_events,
        report.totals.lookup_batches,
        report.totals.interaction_columns,
        report.totals.expression_dag_nodes,
        report.totals.expression_dag_edges,
        report.totals.expression_dag_shared_nodes,
        report.totals.constraint_effect_reachable_nodes,
        report.totals.nodes_outside_constraint_effect_closure,
    }) |value| hashInt(&hash, u64, value);
    inline for (.{
        report.totals.maximum_logical_constraint_degree,
        report.totals.maximum_lookup_numerator_degree,
        report.totals.maximum_lookup_denominator_degree,
        report.totals.maximum_modeled_interaction_degree,
    }) |value| hashInt(&hash, u32, value);
    return hash.finalResult();
}

fn hashBytes(hash: *Sha256, bytes: []const u8) void {
    hashInt(hash, u32, std.math.cast(u32, bytes.len) orelse unreachable);
    hash.update(bytes);
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}
