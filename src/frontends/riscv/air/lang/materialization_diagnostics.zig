//! Authenticated source-to-storage diagnostics for typed Poseidon2 AIR.
//!
//! The machine form is an append-only, canonical ASCII key/value stream. All
//! unbounded source text is lowercase-hex encoded, numeric identities are
//! decimal, field order is fixed, and no allocation or pointer identity enters
//! the projection. Version 1 explicitly distinguishes H-003's generic,
//! dependency-topological plan IDs from H-004's legacy lane-major ordinals.
//!
//! Both renderers authenticate the complete plan and binding before emitting a
//! byte. A malformed owner therefore cannot leave a plausible partial report.

const std = @import("std");
const compat = @import("typed_poseidon2_compat.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const poseidon = @import("typed_poseidon2.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA = "stwo.typed-air.poseidon2.materialization-report-v1";
pub const SELECTION_SCOPE = "root_closure";
pub const IDENTITY_SCOPE = "whole_program_digest";
pub const PLAN_ORDER = "generic_dependency_topological";
pub const PLACEMENT_ORDER = "legacy_lane_major";
pub const RECORD_FIELDS =
    "legacy_ordinal,generic_plan_id,value_id,compatibility_policy," ++
    "compatibility_version,materializer_policy,materializer_version," ++
    "selection_scope,identity_scope,program_sha256,gate_value_id," ++
    "semantic_path,source_id,source_path_hex,span_start_byte," ++
    "span_start_line,span_start_column,span_end_byte,span_end_line," ++
    "span_end_column,source_op,reason,structural_use_count,stable_name," ++
    "fingerprint_sha256,generic_dependency_plan_ids,body_degree," ++
    "equality_degree,context_degree,constraint_degree,phase,round,lane," ++
    "role,constraint_ordinal,column_index,column_name";

pub const Error = materializer.Error || compat.BindingError || error{
    InvalidPlanMaterialization,
    InvalidSourceIdentity,
};

/// Writes the versioned canonical machine projection. Validation and its
/// temporary allocations finish before the first byte is passed to `writer`.
pub fn writeMachine(
    allocator: std.mem.Allocator,
    writer: *std.Io.Writer,
    arena: *const ir.Arena,
    definition: poseidon.Definition,
    spans: poseidon.DefinitionSpans,
    plan: *const materializer.Plan,
    binding: *const compat.OwnedBinding,
) (Error || std.Io.Writer.Error)!void {
    try authenticate(allocator, arena, definition, spans, plan, binding);

    try writer.print("schema={s}\n", .{SCHEMA});
    try writer.print(
        "format_version={d} record_count={d}\n",
        .{ FORMAT_VERSION, compat.N_MATERIALIZATIONS },
    );
    try writer.print(
        "scope selection={s} identity={s} plan_order={s} placement_order={s}\n",
        .{ SELECTION_SCOPE, IDENTITY_SCOPE, PLAN_ORDER, PLACEMENT_ORDER },
    );
    try writer.print(
        "binding compatibility_policy={s} compatibility_version={d} " ++
            "materializer_policy={s} materializer_version={d} " ++
            "gate_value_id={d} maximum_constraint_degree={d} row_mask_degree={d} " ++
            "program_sha256=",
        .{
            compat.POLICY_NAME,
            compat.POLICY_VERSION,
            materializer.policy_id,
            materializer.policy_version,
            @intFromEnum(binding.gate),
            binding.policy.maximum_constraint_degree,
            binding.policy.row_mask_degree,
        },
    );
    try writeHex(writer, &binding.program_digest);
    try writer.writeByte('\n');
    try writer.print("fields={s}\n", .{RECORD_FIELDS});

    for (binding.entries) |entry| {
        try writeMachineRecord(writer, arena, plan, binding, entry);
    }
}

/// Writes one compact review line per legacy physical slot after applying the
/// same all-or-nothing authentication boundary as `writeMachine`.
pub fn writeHuman(
    allocator: std.mem.Allocator,
    writer: *std.Io.Writer,
    arena: *const ir.Arena,
    definition: poseidon.Definition,
    spans: poseidon.DefinitionSpans,
    plan: *const materializer.Plan,
    binding: *const compat.OwnedBinding,
) (Error || std.Io.Writer.Error)!void {
    try authenticate(allocator, arena, definition, spans, plan, binding);

    try writer.print(
        "Poseidon2 materializations ({d} slots; {s} plan -> {s} placement)\n",
        .{ compat.N_MATERIALIZATIONS, PLAN_ORDER, PLACEMENT_ORDER },
    );
    try writer.print(
        "selection: {s}; identity: {s}; {s} v{d}; {s} v{d}\n",
        .{
            SELECTION_SCOPE,
            IDENTITY_SCOPE,
            materializer.policy_id,
            materializer.policy_version,
            compat.POLICY_NAME,
            compat.POLICY_VERSION,
        },
    );
    for (binding.entries) |entry| {
        const plan_id = entry.plan_materialization;
        const planned = plannedAt(plan, plan_id) orelse
            return error.InvalidPlanMaterialization;
        try writer.print(
            "legacy[{d}] column[{d}] ",
            .{ entry.materialization.ordinal, entry.materialization.column },
        );
        try compat.writeColumnName(writer, entry.materialization.column);
        try writer.print(
            " <- plan[{d}] value[{d}] ",
            .{ @intFromEnum(plan_id), @intFromEnum(entry.value) },
        );
        try compat.writeSemanticPath(writer, entry.materialization);
        try writer.writeAll(" @ ");
        try writeHumanSource(writer, arena, entry.source_span);
        try writer.writeAll("; deps=");
        try writeDependencies(writer, plan, plan_id);
        try writer.print(
            "; degree={d}+{d}->{d}; {s}",
            .{
                planned.equality_degree,
                planned.context_degree,
                planned.constraint_degree,
                @tagName(entry.materialization.phase),
            },
        );
        if (entry.materialization.round == compat.NO_ROUND) {
            try writer.writeAll(" round=-");
        } else {
            try writer.print(" round={d}", .{entry.materialization.round});
        }
        try writer.print(
            " lane={d} role={s} constraint[{d}]\n",
            .{
                entry.materialization.lane,
                @tagName(entry.materialization.role),
                entry.materialization.constraint,
            },
        );
    }
}

fn authenticate(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    definition: poseidon.Definition,
    spans: poseidon.DefinitionSpans,
    plan: *const materializer.Plan,
    binding: *const compat.OwnedBinding,
) Error!void {
    try binding.validateAgainst(allocator, arena, definition, spans, plan);
}

fn writeMachineRecord(
    writer: *std.Io.Writer,
    arena: *const ir.Arena,
    plan: *const materializer.Plan,
    binding: *const compat.OwnedBinding,
    entry: compat.Binding,
) (Error || std.Io.Writer.Error)!void {
    const plan_id = entry.plan_materialization;
    const planned = plannedAt(plan, plan_id) orelse
        return error.InvalidPlanMaterialization;
    try writer.print(
        "record legacy_ordinal={d} generic_plan_id={d} value_id={d} " ++
            "compatibility_policy={s} compatibility_version={d} " ++
            "materializer_policy={s} materializer_version={d} " ++
            "selection_scope={s} identity_scope={s} program_sha256=",
        .{
            entry.materialization.ordinal,
            @intFromEnum(plan_id),
            @intFromEnum(entry.value),
            compat.POLICY_NAME,
            compat.POLICY_VERSION,
            materializer.policy_id,
            materializer.policy_version,
            SELECTION_SCOPE,
            IDENTITY_SCOPE,
        },
    );
    try writeHex(writer, &binding.program_digest);
    try writer.print(" gate_value_id={d} semantic_path=", .{@intFromEnum(binding.gate)});
    try compat.writeSemanticPath(writer, entry.materialization);
    try writeMachineSource(writer, arena, entry.source_span);
    try writer.print(
        " source_op={s} reason={s} structural_use_count={d} stable_name={s} " ++
            "fingerprint_sha256=",
        .{
            @tagName(planned.source_op),
            @tagName(planned.reason),
            planned.structural_use_count,
            planned.stable_name.slice(),
        },
    );
    try writeHex(writer, &planned.fingerprint);
    try writer.writeAll(" generic_dependency_plan_ids=");
    try writeDependencies(writer, plan, plan_id);
    try writer.print(
        " body_degree={d} equality_degree={d} context_degree={d} " ++
            "constraint_degree={d} phase={s} round=",
        .{
            planned.body_degree,
            planned.equality_degree,
            planned.context_degree,
            planned.constraint_degree,
            @tagName(entry.materialization.phase),
        },
    );
    if (entry.materialization.round == compat.NO_ROUND) {
        try writer.writeAll("none");
    } else {
        try writer.print("{d}", .{entry.materialization.round});
    }
    try writer.print(
        " lane={d} role={s} constraint_ordinal={d} column_index={d} column_name=",
        .{
            entry.materialization.lane,
            @tagName(entry.materialization.role),
            entry.materialization.constraint,
            entry.materialization.column,
        },
    );
    try compat.writeColumnName(writer, entry.materialization.column);
    try writer.writeByte('\n');
}

fn writeMachineSource(
    writer: *std.Io.Writer,
    arena: *const ir.Arena,
    span: source.SourceSpan,
) (Error || std.Io.Writer.Error)!void {
    if (span.source) |source_id| {
        const path = arena.sourcePath(source_id) orelse
            return error.InvalidSourceIdentity;
        try writer.print(" source_id={d} source_path_hex=", .{@intFromEnum(source_id)});
        try writeHex(writer, path);
    } else {
        try writer.writeAll(" source_id=none source_path_hex=none");
    }
    try writer.print(
        " span_start_byte={d} span_start_line={d} span_start_column={d} " ++
            "span_end_byte={d} span_end_line={d} span_end_column={d}",
        .{
            span.start.byte_offset,
            span.start.line,
            span.start.column,
            span.end.byte_offset,
            span.end.line,
            span.end.column,
        },
    );
}

fn writeHumanSource(
    writer: *std.Io.Writer,
    arena: *const ir.Arena,
    span: source.SourceSpan,
) (Error || std.Io.Writer.Error)!void {
    if (span.source) |source_id| {
        const path = arena.sourcePath(source_id) orelse
            return error.InvalidSourceIdentity;
        try writer.print(
            "{s}:{d}:{d}-{d}:{d}",
            .{ path, span.start.line, span.start.column, span.end.line, span.end.column },
        );
    } else {
        try writer.writeAll("<generated>");
    }
}

fn writeDependencies(
    writer: *std.Io.Writer,
    plan: *const materializer.Plan,
    plan_id: materializer.MaterializationId,
) (Error || std.Io.Writer.Error)!void {
    const dependencies = plan.dependenciesFor(plan_id) orelse
        return error.InvalidPlanMaterialization;
    if (dependencies.len == 0) {
        try writer.writeAll("none");
        return;
    }
    for (dependencies, 0..) |dependency, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.print("{d}", .{@intFromEnum(dependency)});
    }
}

fn plannedAt(
    plan: *const materializer.Plan,
    id: materializer.MaterializationId,
) ?*const materializer.Materialization {
    const index = types.idIndex(id);
    if (index >= plan.materializations.len) return null;
    return &plan.materializations[index];
}

fn writeHex(writer: *std.Io.Writer, bytes: []const u8) std.Io.Writer.Error!void {
    const alphabet = "0123456789abcdef";
    for (bytes) |byte| {
        try writer.writeByte(alphabet[byte >> 4]);
        try writer.writeByte(alphabet[byte & 0x0f]);
    }
}

comptime {
    if (FORMAT_VERSION != 1 or compat.FORMAT_VERSION != 1 or
        compat.POLICY_VERSION != 1 or materializer.policy_version != 1)
    {
        @compileError("materialization diagnostic format authority drifted");
    }
}
