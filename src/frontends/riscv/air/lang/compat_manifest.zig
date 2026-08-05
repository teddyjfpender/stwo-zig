//! Canonical `compat-v1` identity and round-trip receipt for one opcode family.
//!
//! The artifact is generated only after the production shadow, physical
//! mapping, direct and lookup lowerings, runtime owners, degree analysis, and
//! every AIR IR v2 opcode projection have validated. It is a section-framed
//! binary encoding: integer widths, tags, ordering, and string lengths are
//! explicit, while a readable aggregate index carries the review surface.

const std = @import("std");
const prover_component = @import("stwo_prover_engine").air.component_prover;
const program_json = @import("../extract/program_json.zig");
const opcode_manifest = @import("../../opcode_manifest.zig");
const trace = @import("../../runner/trace.zig");
const witness_layout = @import("../../witness_layout.zig");
const compat_layout = @import("compat_layout.zig");
const digest = @import("digest.zig");
const hint_recipe = @import("hint_recipe.zig");
const hints = @import("hints.zig");
const lower_air_ir = @import("lower_air_ir.zig");
const lower_constraint = @import("lower_constraint.zig");
const lower_lookup = @import("lower_lookup.zig");
const lower_runtime = @import("lower_runtime.zig");
const logical_manifest = @import("manifest.zig");
const protocol_degree = @import("protocol_degree.zig");
const relation = @import("relation.zig");
const shadow_import = @import("shadow_import.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");
const types = @import("types.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const magic = "STWAIRC\x00";
pub const format_version: u16 = 1;
pub const component_kind = "stwo.riscv.opcode-family";
pub const direct_capability_id = "stwo.prover.base-polynomial-v1";
pub const lookup_capability_id = "stwo.prover.lookup-polynomial-v1";
pub const runtime_capability_version: u16 = 1;
pub const layout_digest_domain = "stwo-zig/typed-air/compat-layout-v1";
pub const direct_digest_domain = "stwo-zig/typed-air/compat-direct-runtime-v1";
pub const lookup_digest_domain = "stwo-zig/typed-air/compat-lookup-runtime-v1";
pub const degree_digest_domain = "stwo-zig/typed-air/compat-degree-v1";
pub const hint_digest_domain = "stwo-zig/typed-air/compat-hints-v1";
pub const formal_digest_domain = "stwo-zig/typed-air/compat-air-ir-v2";
pub const index_filename = "index-v1.tsv";

const section_count: u8 = 7;
const no_node = std.math.maxInt(u32);

const Section = enum(u8) {
    identity = 1,
    layout = 2,
    direct = 3,
    lookup = 4,
    degree = 5,
    hints = 6,
    formal = 7,
};

pub const ManifestError = error{
    CountOverflow,
    FormalExportMismatch,
    InvalidFamilyOrder,
    InvalidManifestState,
    RuntimeExportMismatch,
};

pub const Summary = struct {
    family: trace.OpcodeFamily,
    byte_len: u32,
    manifest_digest: [32]u8,
    source_schedule_digest: [32]u8,
    semantic_digest: [32]u8,
    layout_digest: [32]u8,
    direct_runtime_digest: [32]u8,
    lookup_runtime_digest: [32]u8,
    degree_digest: [32]u8,
    formal_digest: [32]u8,
    main_columns: u32,
    direct_constraints: u32,
    lookup_events: u32,
    interaction_batches: u32,
    formal_exports: u32,
    maximum_direct_degree: u32,
    maximum_interaction_degree: u32,
};

pub const Artifact = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    summary: Summary,

    pub fn deinit(self: *Artifact) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub fn artifactFilename(family: trace.OpcodeFamily) []const u8 {
    return switch (family) {
        .base_alu_reg => "base_alu_reg.stwairc",
        .base_alu_imm => "base_alu_imm.stwairc",
        .shifts_reg => "shifts_reg.stwairc",
        .shifts_imm => "shifts_imm.stwairc",
        .lt_reg => "lt_reg.stwairc",
        .lt_imm => "lt_imm.stwairc",
        .branch_eq => "branch_eq.stwairc",
        .branch_lt => "branch_lt.stwairc",
        .lui => "lui.stwairc",
        .auipc => "auipc.stwairc",
        .jalr => "jalr.stwairc",
        .jal => "jal.stwairc",
        .load_store => "load_store.stwairc",
        .mul => "mul.stwairc",
        .mulh => "mulh.stwairc",
        .div => "div.stwairc",
        .fence => "fence.stwairc",
    };
}

/// Generates one complete family receipt. No process-global symbolic state is
/// retained, and every owned intermediate is released on failure.
pub fn generate(
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
) !Artifact {
    return generateWithScratch(allocator, allocator, family);
}

/// Separates fallible receipt encoding from the legacy production symbolic
/// builder, whose allocation contract is panic-on-OOM. Normal callers use one
/// allocator; adversarial tests supply a stable scratch allocator and exhaust
/// every allocation owned by the new encoding boundary.
pub fn generateWithScratch(
    result_allocator: std.mem.Allocator,
    scratch_allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
) !Artifact {
    var imported = try shadow_program.buildProduction(
        scratch_allocator,
        family,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);
    var direct = try lower_constraint.lower(scratch_allocator, &imported, &layout);
    defer direct.deinit();
    var lookups = try lower_lookup.lower(scratch_allocator, &imported, &layout);
    defer lookups.deinit();
    var degrees = try protocol_degree.analyze(scratch_allocator, &imported, 0);
    defer degrees.deinit();

    var runtime_direct = try lower_runtime.exportDirect(result_allocator, &direct);
    defer runtime_direct.deinit();
    var runtime_lookups = try lower_runtime.exportLookups(result_allocator, &lookups);
    defer runtime_lookups.deinit();
    try verifyRuntimeBinding(&direct, &lookups, &runtime_direct, &runtime_lookups);

    var layout_payload: std.ArrayList(u8) = .empty;
    defer layout_payload.deinit(result_allocator);
    try writeLayout(layout_payload.writer(result_allocator), &layout);

    var direct_runtime: std.ArrayList(u8) = .empty;
    defer direct_runtime.deinit(result_allocator);
    try writeDirectRuntime(direct_runtime.writer(result_allocator), &runtime_direct);
    const direct_runtime_digest = hashDomain(
        direct_digest_domain,
        direct_runtime.items,
    );
    var direct_payload: std.ArrayList(u8) = .empty;
    defer direct_payload.deinit(result_allocator);
    try writeDirect(
        direct_payload.writer(result_allocator),
        &imported,
        &direct,
        direct_runtime_digest,
        direct_runtime.items,
    );

    var lookup_runtime: std.ArrayList(u8) = .empty;
    defer lookup_runtime.deinit(result_allocator);
    try writeLookupRuntime(lookup_runtime.writer(result_allocator), &runtime_lookups);
    const lookup_runtime_digest = hashDomain(
        lookup_digest_domain,
        lookup_runtime.items,
    );
    var lookup_payload: std.ArrayList(u8) = .empty;
    defer lookup_payload.deinit(result_allocator);
    try writeLookups(
        lookup_payload.writer(result_allocator),
        &lookups,
        lookup_runtime_digest,
        lookup_runtime.items,
    );

    var degree_payload: std.ArrayList(u8) = .empty;
    defer degree_payload.deinit(result_allocator);
    try writeDegrees(degree_payload.writer(result_allocator), &degrees);

    var hint_payload: std.ArrayList(u8) = .empty;
    defer hint_payload.deinit(result_allocator);
    try writeHints(hint_payload.writer(result_allocator), &imported);

    var formal_payload: std.ArrayList(u8) = .empty;
    defer formal_payload.deinit(result_allocator);
    const formal_exports = try writeFormalExports(
        scratch_allocator,
        formal_payload.writer(result_allocator),
        &imported,
        &layout,
    );

    const semantic_digest = try digest.compute(&imported.imported.arena);
    const layout_digest = hashDomain(layout_digest_domain, layout_payload.items);
    const degree_digest = hashDomain(degree_digest_domain, degree_payload.items);
    const hint_digest = hashDomain(hint_digest_domain, hint_payload.items);
    const formal_digest = hashDomain(formal_digest_domain, formal_payload.items);

    var identity_payload: std.ArrayList(u8) = .empty;
    defer identity_payload.deinit(result_allocator);
    try writeIdentity(
        identity_payload.writer(result_allocator),
        family,
        imported.imported.source_schedule_digest,
        semantic_digest,
        layout_digest,
        direct_runtime_digest,
        lookup_runtime_digest,
        degree_digest,
        hint_digest,
        formal_digest,
    );

    var manifest_bytes: std.ArrayList(u8) = .empty;
    defer manifest_bytes.deinit(result_allocator);
    const writer = manifest_bytes.writer(result_allocator);
    try writer.writeAll(magic);
    try writeInt(writer, u16, format_version);
    try writeInt(writer, u8, familyTag(family));
    try writeInt(writer, u8, section_count);
    try writeSection(writer, .identity, identity_payload.items);
    try writeSection(writer, .layout, layout_payload.items);
    try writeSection(writer, .direct, direct_payload.items);
    try writeSection(writer, .lookup, lookup_payload.items);
    try writeSection(writer, .degree, degree_payload.items);
    try writeSection(writer, .hints, hint_payload.items);
    try writeSection(writer, .formal, formal_payload.items);

    const owned = try manifest_bytes.toOwnedSlice(result_allocator);
    errdefer result_allocator.free(owned);
    return .{
        .allocator = result_allocator,
        .bytes = owned,
        .summary = .{
            .family = family,
            .byte_len = try count(owned.len),
            .manifest_digest = hashRaw(owned),
            .source_schedule_digest = imported.imported.source_schedule_digest,
            .semantic_digest = semantic_digest,
            .layout_digest = layout_digest,
            .direct_runtime_digest = direct_runtime_digest,
            .lookup_runtime_digest = lookup_runtime_digest,
            .degree_digest = degree_digest,
            .formal_digest = formal_digest,
            .main_columns = try count(layout.main().len),
            .direct_constraints = try count(direct.roots.len),
            .lookup_events = try count(lookups.events.len),
            .interaction_batches = try count(lookups.batches.len),
            .formal_exports = formal_exports,
            .maximum_direct_degree = degrees.maximum_direct_degree,
            .maximum_interaction_degree = degrees.maximum_interaction_degree,
        },
    };
}

pub fn writeIndex(writer: anytype, summaries: []const Summary) !void {
    if (summaries.len != trace.N_FAMILIES) return error.InvalidFamilyOrder;
    try writer.print(
        "# stwo-zig typed-air compat-v1 family manifests v{d}\n",
        .{format_version},
    );
    try writer.writeAll(
        "family\tbytes\tmanifest_sha256\tsource_schedule_sha256" ++
            "\tsemantic_sha256\tlayout_sha256\tdirect_runtime_sha256" ++
            "\tlookup_runtime_sha256\tdegree_sha256\tformal_sha256" ++
            "\tmain_columns\tdirect_constraints\tlookup_events" ++
            "\tinteraction_batches\tformal_exports\tmax_direct_degree" ++
            "\tmax_interaction_degree\n",
    );
    for (summaries, 0..) |summary, family_index| {
        if (@intFromEnum(summary.family) != family_index)
            return error.InvalidFamilyOrder;
        const manifest_hex = std.fmt.bytesToHex(summary.manifest_digest, .lower);
        const source_hex = std.fmt.bytesToHex(summary.source_schedule_digest, .lower);
        const semantic_hex = std.fmt.bytesToHex(summary.semantic_digest, .lower);
        const layout_hex = std.fmt.bytesToHex(summary.layout_digest, .lower);
        const direct_hex = std.fmt.bytesToHex(summary.direct_runtime_digest, .lower);
        const lookup_hex = std.fmt.bytesToHex(summary.lookup_runtime_digest, .lower);
        const degree_hex = std.fmt.bytesToHex(summary.degree_digest, .lower);
        const formal_hex = std.fmt.bytesToHex(summary.formal_digest, .lower);
        try writer.print(
            "{s}\t{d}\t{s}\t{s}\t{s}\t{s}\t{s}\t{s}\t{s}\t{s}" ++
                "\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\n",
            .{
                @tagName(summary.family),
                summary.byte_len,
                &manifest_hex,
                &source_hex,
                &semantic_hex,
                &layout_hex,
                &direct_hex,
                &lookup_hex,
                &degree_hex,
                &formal_hex,
                summary.main_columns,
                summary.direct_constraints,
                summary.lookup_events,
                summary.interaction_batches,
                summary.formal_exports,
                summary.maximum_direct_degree,
                summary.maximum_interaction_degree,
            },
        );
    }
}

fn writeIdentity(
    writer: anytype,
    family: trace.OpcodeFamily,
    source_schedule_digest: [32]u8,
    semantic_digest: [32]u8,
    layout_digest: [32]u8,
    direct_runtime_digest: [32]u8,
    lookup_runtime_digest: [32]u8,
    degree_digest: [32]u8,
    hint_digest: [32]u8,
    formal_digest: [32]u8,
) !void {
    try writeString(writer, component_kind);
    try writeInt(writer, u8, familyTag(family));
    try writeString(writer, @tagName(family));
    try writeInt(writer, u32, opcode_manifest.schema_version);
    try writeString(writer, opcode_manifest.semantic_authority_revision);
    try writeString(writer, opcode_manifest.legacy_layout_revision);
    try writeInt(writer, u16, logical_manifest.logical_schema_version);
    try writeInt(writer, u16, digest.format_version);
    try writeString(writer, digest.domain_separator);
    try writeInt(writer, u16, shadow_import.source_schedule_digest_version);
    try writeString(writer, shadow_import.source_schedule_digest_domain);
    try writeString(writer, compat_layout.policy_id);
    try writeInt(writer, u16, compat_layout.policy_version);
    try writeString(writer, direct_capability_id);
    try writeString(writer, lookup_capability_id);
    try writeInt(writer, u16, runtime_capability_version);
    try writeInt(writer, u32, program_json.SCHEMA_VERSION);
    try writeString(writer, program_json.KIND);
    try writer.writeAll(&witness_layout.digest());
    try writer.writeAll(&source_schedule_digest);
    try writer.writeAll(&semantic_digest);
    try writer.writeAll(&layout_digest);
    try writer.writeAll(&direct_runtime_digest);
    try writer.writeAll(&lookup_runtime_digest);
    try writer.writeAll(&degree_digest);
    try writer.writeAll(&hint_digest);
    try writer.writeAll(&formal_digest);
}

fn writeLayout(writer: anytype, layout: *const compat_layout.Layout) !void {
    try writeCount(writer, layout.preprocessed.len);
    for (layout.preprocessed) |column| {
        try writeColumnRef(writer, column.reference);
        try writeInt(writer, u8, preprocessedKindTag(column.kind));
        try writeString(writer, column.name);
        try writeOptionalValue(writer, column.value);
        try writeInt(writer, u8, windowTag(column.window));
    }
    try writeCount(writer, layout.main().len);
    for (layout.main()) |column| {
        try writeColumnRef(writer, column.reference);
        try writeValue(writer, column.value);
        try writeString(writer, column.logical_name);
        try writeString(writer, column.physical_name);
        try writeInt(writer, u8, windowTag(column.window));
    }
    try writeCount(writer, layout.interactions().len);
    for (layout.interactions()) |column| {
        try writeColumnRef(writer, column.reference);
        try writeInt(writer, u32, column.batch);
        try writeInt(writer, u8, secureCoordinateTag(column.coordinate));
        try writeInt(writer, u32, column.first_lookup);
        try writeInt(writer, u8, column.entry_count);
        try writeInt(writer, u8, windowTag(column.window));
    }
}

fn writeDirectRuntime(
    writer: anytype,
    runtime: *const prover_component.OwnedBasePolynomialProgram,
) !void {
    try writer.writeAll("STWBASE\x01");
    try writeCount(writer, runtime.column_count);
    try writeCount(writer, runtime.nodes.len);
    for (runtime.nodes) |node| try writePolynomialNode(writer, node);
    try writeCount(writer, runtime.roots.len);
    for (runtime.roots) |root| try writeInt(writer, u32, root);
}

fn writeDirect(
    writer: anytype,
    imported: *const shadow_program.ImportedProgram,
    direct: *const lower_constraint.Program,
    runtime_digest: [32]u8,
    runtime_bytes: []const u8,
) !void {
    try writer.writeAll(&runtime_digest);
    try writeBytes(writer, runtime_bytes);
    try writeCount(writer, imported.direct_constraints.len);
    for (
        imported.direct_constraints,
        imported.direct_source_roots,
        direct.roots,
    ) |constraint_id, source_root, lowered_root| {
        const constraint = imported.imported.arena.constraint(constraint_id) orelse
            return error.InvalidManifestState;
        const name = imported.imported.arena.name(constraint.name) orelse
            return error.InvalidManifestState;
        try writeInt(writer, u32, @intFromEnum(constraint_id));
        try writeString(writer, name);
        try writeValue(writer, constraint.root);
        try writeInt(writer, u32, source_root);
        try writeInt(writer, u32, lowered_root);
    }
}

fn writeLookupRuntime(
    writer: anytype,
    runtime: *const prover_component.OwnedLookupPolynomialProgram,
) !void {
    try writer.writeAll("STWLOOK\x01");
    try writeCount(writer, runtime.column_count);
    try writeCount(writer, runtime.batch_size);
    try writeCount(writer, runtime.nodes.len);
    for (runtime.nodes) |node| try writePolynomialNode(writer, node);
    try writeCount(writer, runtime.entries.len);
    for (runtime.entries) |entry| {
        try writeInt(writer, u32, entry.numerator);
        try writeInt(writer, u8, entry.arity);
        for (entry.values) |value| try writeInt(writer, u32, value);
    }
}

fn writeLookups(
    writer: anytype,
    lookups: *const lower_lookup.Program,
    runtime_digest: [32]u8,
    runtime_bytes: []const u8,
) !void {
    try writer.writeAll(&runtime_digest);
    try writeBytes(writer, runtime_bytes);
    try writeCount(writer, lookups.events.len);
    for (lookups.events) |event| {
        const schema = relation.getById(event.schema) orelse
            return error.InvalidManifestState;
        try writeInt(writer, u16, @intFromEnum(event.schema));
        try writeInt(writer, u8, relationDomainTag(schema.domain));
        try writeInt(writer, u16, schema.version);
        try writeString(writer, schema.name);
        try writeInt(writer, u8, relationRoleTag(event.role));
        try writeInt(writer, u32, event.liveness);
        try writeInt(writer, u32, event.numerator);
        try writeInt(writer, u8, event.arity);
        try writeOptionalInt(writer, u8, event.access_ordinal);
        const values = event.valueSlice() orelse
            return error.InvalidManifestState;
        for (values) |value| try writeInt(writer, u32, value);
    }
    try writeCount(writer, lookups.batches.len);
    for (lookups.batches) |batch| {
        try writeInt(writer, u32, batch.first_event);
        try writeInt(writer, u8, batch.event_count);
        for (batch.interaction_columns) |column|
            try writeColumnRef(writer, column);
    }
}

fn writeDegrees(
    writer: anytype,
    degrees: *const protocol_degree.Analysis,
) !void {
    try writeInt(writer, u32, degrees.trace_log_size);
    try writeInt(writer, u32, degrees.maximum_direct_degree);
    try writeInt(writer, u32, degrees.maximum_lookup_numerator_degree);
    try writeInt(writer, u32, degrees.maximum_lookup_denominator_degree);
    try writeInt(writer, u32, degrees.maximum_interaction_degree);
    try writeInt(writer, u32, degrees.required_direct_log_degree_bound);
    try writeInt(writer, u32, degrees.required_interaction_log_degree_bound);
    try writeCount(writer, degrees.direct.len);
    for (degrees.direct) |item| {
        try writeInt(writer, u32, @intFromEnum(item.constraint));
        try writeInt(writer, u32, item.expression);
        try writeOptionalInt(writer, u32, item.explicit_gate);
        try writeInt(writer, u32, item.external_row_mask);
        try writeInt(writer, u32, item.final);
        try writeInt(writer, u8, item.quotient_expansion_bits);
        try writeInt(writer, u32, item.required_log_degree_bound);
    }
    try writeCount(writer, degrees.lookups.len);
    for (degrees.lookups) |item| {
        try writeInt(writer, u32, item.index);
        try writeInt(writer, u32, item.numerator);
        try writeInt(writer, u32, item.denominator);
        try writeInt(writer, u32, item.maximum_field);
    }
    try writeCount(writer, degrees.interactions.len);
    for (degrees.interactions) |item| {
        try writeInt(writer, u32, item.batch);
        try writeInt(writer, u32, item.first_lookup);
        try writeInt(writer, u8, item.entry_count);
        try writeInt(writer, u32, item.row_window);
        try writeInt(writer, u32, item.boundary_selector);
        try writeInt(writer, u32, item.boundary_claim);
        try writeInt(writer, u32, item.delta);
        try writeInt(writer, u32, item.denominator_product);
        try writeInt(writer, u32, item.combined_numerator);
        try writeInt(writer, u32, item.final);
        try writeInt(writer, u8, item.quotient_expansion_bits);
        try writeInt(writer, u32, item.required_log_degree_bound);
    }
}

fn writeHints(
    writer: anytype,
    imported: *const shadow_program.ImportedProgram,
) !void {
    const invocations = hints.view(&imported.imported.arena);
    try writeCount(writer, invocations.len);
    for (invocations) |invocation| {
        const recipe = hint_recipe.getById(invocation.recipe) orelse
            return error.InvalidManifestState;
        try writeInt(writer, u16, @intFromEnum(recipe.id));
        try writeInt(writer, u16, recipe.version);
        try writeString(writer, recipe.name);
    }
}

fn writeFormalExports(
    allocator: std.mem.Allocator,
    writer: anytype,
    imported: *const shadow_program.ImportedProgram,
    layout: *const compat_layout.Layout,
) !u32 {
    try writeInt(writer, u32, program_json.SCHEMA_VERSION);
    try writeString(writer, program_json.KIND);
    const export_count = opcodeCount(imported.family);
    try writeCount(writer, export_count);
    for (opcode_manifest.entries) |opcode| {
        if (opcode.family != imported.family) continue;
        var lowered = std.Io.Writer.Allocating.init(allocator);
        defer lowered.deinit();
        try lower_air_ir.emitOpcode(
            allocator,
            &lowered.writer,
            imported,
            layout,
            opcode,
        );
        var production = std.Io.Writer.Allocating.init(allocator);
        defer production.deinit();
        try program_json.emitOpcode(allocator, &production.writer, opcode);
        if (!std.mem.eql(u8, lowered.written(), production.written()))
            return error.FormalExportMismatch;
        const body = lowered.written();
        try writeInt(writer, u32, opcode.opcode.protocolId());
        try writeString(writer, opcode.mnemonic);
        try writeCount(writer, body.len);
        try writer.writeAll(&hashRaw(body));
    }
    return count(export_count);
}

fn verifyRuntimeBinding(
    direct: *const lower_constraint.Program,
    lookups: *const lower_lookup.Program,
    runtime_direct: *const prover_component.OwnedBasePolynomialProgram,
    runtime_lookups: *const prover_component.OwnedLookupPolynomialProgram,
) !void {
    try runtime_direct.validate();
    try runtime_lookups.validate();
    if (runtime_direct.column_count != direct.columnCount() or
        runtime_direct.nodes.len != direct.nodes.len or
        !std.mem.eql(u32, runtime_direct.roots, direct.roots) or
        runtime_lookups.column_count != lookups.polynomials.columnCount() or
        runtime_lookups.batch_size != lookups.batch_size or
        runtime_lookups.nodes.len != lookups.polynomials.nodes.len or
        runtime_lookups.entries.len != lookups.events.len)
    {
        return error.RuntimeExportMismatch;
    }
    for (runtime_direct.nodes, direct.nodes) |actual, expected|
        if (!polynomialNodeEqual(actual, expected))
            return error.RuntimeExportMismatch;
    for (runtime_lookups.nodes, lookups.polynomials.nodes) |actual, expected|
        if (!polynomialNodeEqual(actual, expected))
            return error.RuntimeExportMismatch;
    for (runtime_lookups.entries, lookups.events) |actual, expected| {
        const values = expected.valueSlice() orelse
            return error.RuntimeExportMismatch;
        if (actual.numerator != expected.numerator or actual.arity != expected.arity or
            !std.mem.eql(u32, actual.values[0..actual.arity], values))
        {
            return error.RuntimeExportMismatch;
        }
        for (actual.values[actual.arity..]) |unused|
            if (unused != no_node) return error.RuntimeExportMismatch;
    }
}

fn polynomialNodeEqual(actual: anytype, expected: anytype) bool {
    return @intFromEnum(actual.op) == @intFromEnum(expected.op) and
        actual.lhs == expected.lhs and actual.rhs == expected.rhs and
        actual.value == expected.value;
}

fn writePolynomialNode(writer: anytype, node: anytype) !void {
    try writeInt(writer, u8, polynomialOpTag(node.op));
    try writeInt(writer, u32, node.lhs);
    try writeInt(writer, u32, node.rhs);
    try writeInt(writer, u32, node.value);
}

fn writeColumnRef(writer: anytype, reference: compat_layout.ColumnRef) !void {
    try writeInt(writer, u8, treeTag(reference.tree));
    try writeInt(writer, u32, reference.local_index);
}

fn writeSection(writer: anytype, section: Section, payload: []const u8) !void {
    try writeInt(writer, u8, @intFromEnum(section));
    try writeBytes(writer, payload);
}

fn writeBytes(writer: anytype, bytes: []const u8) !void {
    try writeCount(writer, bytes.len);
    try writer.writeAll(bytes);
}

fn writeString(writer: anytype, value: []const u8) !void {
    try writeBytes(writer, value);
}

fn writeValue(writer: anytype, value: types.ValueId) !void {
    try writeInt(writer, u32, @intFromEnum(value));
}

fn writeOptionalValue(writer: anytype, value: ?types.ValueId) !void {
    if (value) |present| {
        try writeInt(writer, u8, 1);
        try writeValue(writer, present);
    } else {
        try writeInt(writer, u8, 0);
    }
}

fn writeOptionalInt(
    writer: anytype,
    comptime T: type,
    value: ?T,
) !void {
    if (value) |present| {
        try writeInt(writer, u8, 1);
        try writeInt(writer, T, present);
    } else {
        try writeInt(writer, u8, 0);
    }
}

fn writeCount(writer: anytype, value: usize) !void {
    try writeInt(writer, u32, try count(value));
}

fn writeInt(writer: anytype, comptime T: type, value: T) !void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    try writer.writeAll(&encoded);
}

fn count(value: usize) ManifestError!u32 {
    return std.math.cast(u32, value) orelse error.CountOverflow;
}

fn opcodeCount(family: trace.OpcodeFamily) usize {
    var result: usize = 0;
    for (opcode_manifest.entries) |opcode| {
        if (opcode.family == family) result += 1;
    }
    return result;
}

fn hashRaw(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(bytes, &result, .{});
    return result;
}

fn hashDomain(domain: []const u8, bytes: []const u8) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(domain);
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, bytes.len, .little);
    hash.update(&length);
    hash.update(bytes);
    return hash.finalResult();
}

fn familyTag(value: trace.OpcodeFamily) u8 {
    return switch (value) {
        .base_alu_reg => 0,
        .base_alu_imm => 1,
        .shifts_reg => 2,
        .shifts_imm => 3,
        .lt_reg => 4,
        .lt_imm => 5,
        .branch_eq => 6,
        .branch_lt => 7,
        .lui => 8,
        .auipc => 9,
        .jalr => 10,
        .jal => 11,
        .load_store => 12,
        .mul => 13,
        .mulh => 14,
        .div => 15,
        .fence => 16,
    };
}

fn treeTag(value: compat_layout.Tree) u8 {
    return switch (value) {
        .preprocessed => 0,
        .main => 1,
        .interaction => 2,
    };
}

fn windowTag(value: compat_layout.Window) u8 {
    return switch (value) {
        .current => 0,
        .current_and_previous => 1,
    };
}

fn preprocessedKindTag(value: compat_layout.PreprocessedKind) u8 {
    return switch (value) {
        .is_first => 0,
        .is_active => 1,
    };
}

fn secureCoordinateTag(value: compat_layout.SecureCoordinate) u8 {
    return switch (value) {
        .c0_a => 0,
        .c0_b => 1,
        .c1_a => 2,
        .c1_b => 3,
    };
}

fn polynomialOpTag(value: anytype) u8 {
    return switch (value) {
        .constant => 0,
        .column => 1,
        .add => 2,
        .sub => 3,
        .mul => 4,
        .neg => 5,
    };
}

fn relationDomainTag(value: relation.Domain) u8 {
    return switch (value) {
        .registers_state => 0,
        .memory_access => 1,
        .program_access => 2,
        .merkle => 3,
        .poseidon2 => 4,
        .poseidon2_io => 5,
        .bitwise => 6,
        .range_check_20 => 7,
        .range_check_8_11 => 8,
        .range_check_8_8_4 => 9,
        .range_check_8_8 => 10,
        .range_check_m31 => 11,
    };
}

fn relationRoleTag(value: relation.Role) u8 {
    return switch (value) {
        .request => 0,
        .consume => 1,
        .emit => 2,
    };
}

comptime {
    if (magic.len != 8) @compileError("compatibility manifest magic must be 8 bytes");
    if (program_json.SCHEMA_VERSION != 2)
        @compileError("compat-v1 manifest pins AIR IR v2");
    if (@typeInfo(trace.OpcodeFamily).@"enum".fields.len != trace.N_FAMILIES or
        trace.N_FAMILIES != 17)
    {
        @compileError("compat-v1 manifest requires the pinned 17-family set");
    }
}
