//! Versioned compatibility oracle for the shipped Poseidon2-M31 main layout.
//!
//! This module describes placement only. It does not evaluate the permutation,
//! choose degree cuts, or allocate witness storage. H-003 remains responsible
//! for deriving materializations from the typed semantic graph; this oracle
//! checks that those choices reproduce Stark-V's existing order before H-004
//! may call the result compatible.

const std = @import("std");
const digest = @import("digest.zig");
const binding_check = @import("typed_poseidon2_binding_check.zig");
const candidate = @import("typed_poseidon2_candidate.zig");
const materializer = @import("degree3_materializer.zig");
const ir = @import("ir.zig");
const production = @import("../memory_commitment/poseidon2_air.zig");
const constants = @import("../memory_commitment/poseidon2_constants.zig");
const source = @import("source.zig");
const poseidon = @import("typed_poseidon2.zig");
const poseidon_shell = @import("typed_poseidon2_shell.zig");
const types = @import("types.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const POLICY_NAME = "stark-v.poseidon2.compatibility";
pub const POLICY_VERSION: u16 = 1;
pub const MATERIALIZER_POLICY_NAME = materializer.policy_id;
pub const MATERIALIZER_POLICY_VERSION = materializer.policy_version;
pub const ENABLER_NAME = "riscv.poseidon2_m31.enabled";
pub const MAXIMUM_CONSTRAINT_DEGREE: u8 = 3;
pub const WIDTH: usize = 16;
pub const N_ENABLER_COLUMNS: usize = 1;
pub const N_INPUT_COLUMNS: usize = WIDTH;
pub const N_MATERIALIZATIONS: usize = 426;
pub const N_MODE_COLUMNS: usize = 2;
pub const N_MAIN_COLUMNS: usize =
    N_ENABLER_COLUMNS + N_INPUT_COLUMNS + N_MATERIALIZATIONS + N_MODE_COLUMNS;

pub const ENABLER_COLUMN: usize = 0;
pub const INPUT_START: usize = 1;
pub const TEMPORARY_START: usize = INPUT_START + WIDTH;
pub const WIDE_COLUMN: usize = TEMPORARY_START + N_MATERIALIZATIONS;
pub const IO_COLUMN: usize = WIDE_COLUMN + 1;
pub const FIRST_MATERIALIZATION_CONSTRAINT: usize = 1;

pub const FIRST_EXTERNAL_END: usize = 32;
pub const INTERNAL_START: usize = 176;
pub const LAST_EXTERNAL_START: usize = 218;
pub const OUTPUT_START: usize = 410;

/// Stable numeric identity for the placement rule. The open enum makes policy
/// drift representable at artifact boundaries and therefore rejectable.
pub const PolicyId = enum(u32) {
    stark_v_poseidon2_compatibility = 0x5032_4331,
    _,
};

pub const Identity = struct {
    format_version: u16,
    policy: PolicyId,
    policy_version: u16,
    maximum_constraint_degree: u8,
    width: u16,
    materializations: u16,
    main_columns: u16,

    pub fn canonical() Identity {
        return .{
            .format_version = FORMAT_VERSION,
            .policy = .stark_v_poseidon2_compatibility,
            .policy_version = POLICY_VERSION,
            .maximum_constraint_degree = MAXIMUM_CONSTRAINT_DEGREE,
            .width = WIDTH,
            .materializations = N_MATERIALIZATIONS,
            .main_columns = N_MAIN_COLUMNS,
        };
    }

    pub fn validate(self: Identity) ValidationError!void {
        const canonical_identity = canonical();
        if (self.format_version != canonical_identity.format_version)
            return error.FormatVersionMismatch;
        if (self.policy != canonical_identity.policy) return error.PolicyMismatch;
        if (self.policy_version != canonical_identity.policy_version)
            return error.PolicyVersionMismatch;
        if (self.maximum_constraint_degree != canonical_identity.maximum_constraint_degree)
            return error.DegreeBudgetMismatch;
        if (self.width != canonical_identity.width or
            self.materializations != canonical_identity.materializations or
            self.main_columns != canonical_identity.main_columns)
        {
            return error.GeometryMismatch;
        }
    }
};

pub const Phase = enum(u8) {
    external_round,
    internal_round,
    output,
};

pub const Role = enum(u8) {
    /// `x = state + round_constant`; omitted only in external round zero.
    shifted,
    /// `x2 = x * x`.
    square,
    /// `x4 = x2 * x2`.
    fourth_power,
    /// Final permutation lane copied into a committed column.
    output,
};

pub const NO_ROUND: u8 = std.math.maxInt(u8);

/// One current temporary and its matching materialization constraint.
/// `ordinal`, column, and constraint are all stored deliberately: generated or
/// decoded schedules cannot silently infer one field after another has drifted.
pub const Materialization = struct {
    ordinal: u16,
    column: u16,
    constraint: u16,
    phase: Phase,
    round: u8,
    lane: u8,
    role: Role,
};

pub const ValidationError = error{
    ColumnOutOfRange,
    ConstraintMismatch,
    DegreeBudgetMismatch,
    EntryCountMismatch,
    FormatVersionMismatch,
    GeometryMismatch,
    LaneMismatch,
    OrdinalMismatch,
    PhaseMismatch,
    PolicyMismatch,
    PolicyVersionMismatch,
    RoleMismatch,
    RoundMismatch,
};

pub const BindingError = ValidationError || error{
    BindingIdentityMismatch,
    CandidateAmbiguous,
    CandidateCountMismatch,
    CandidateMissing,
    CanonicalDefinitionMismatch,
    DependencyMismatch,
    EnablerMismatch,
    MaterializerDegreeMismatch,
    MaterializerPolicyMismatch,
    MissingEnabler,
    NonFeltCandidate,
    OutputMismatch,
    PlanBindingMismatch,
    ProgramDigestMismatch,
    SemanticShapeMismatch,
    SourceSpanMismatch,
    UnmappedCandidate,
    UnknownCandidate,
};

pub const OwnedSchedule = struct {
    identity: Identity,
    materializations: []Materialization,

    pub fn deinit(self: *OwnedSchedule, allocator: std.mem.Allocator) void {
        allocator.free(self.materializations);
        self.* = undefined;
    }

    pub fn validate(self: OwnedSchedule) ValidationError!void {
        try self.identity.validate();
        try validateMaterializations(self.materializations);
    }
};

pub fn generate(allocator: std.mem.Allocator) std.mem.Allocator.Error!OwnedSchedule {
    const materializations = try allocator.alloc(Materialization, N_MATERIALIZATIONS);
    for (materializations, 0..) |*entry, ordinal| entry.* = expected(ordinal) catch unreachable;
    return .{
        .identity = Identity.canonical(),
        .materializations = materializations,
    };
}

/// Returns the unique canonical descriptor for one temporary ordinal.
pub fn expected(ordinal: usize) ValidationError!Materialization {
    if (ordinal >= N_MATERIALIZATIONS) return error.OrdinalMismatch;

    if (ordinal < FIRST_EXTERNAL_END) {
        return make(
            ordinal,
            .external_round,
            0,
            ordinal / 2,
            if (ordinal % 2 == 0) .square else .fourth_power,
        );
    }
    if (ordinal < INTERNAL_START) {
        const relative = ordinal - FIRST_EXTERNAL_END;
        return make(
            ordinal,
            .external_round,
            1 + relative / (3 * WIDTH),
            (relative % (3 * WIDTH)) / 3,
            tripleRole(relative % 3),
        );
    }
    if (ordinal < LAST_EXTERNAL_START) {
        const relative = ordinal - INTERNAL_START;
        return make(
            ordinal,
            .internal_round,
            relative / 3,
            0,
            tripleRole(relative % 3),
        );
    }
    if (ordinal < OUTPUT_START) {
        const relative = ordinal - LAST_EXTERNAL_START;
        return make(
            ordinal,
            .external_round,
            4 + relative / (3 * WIDTH),
            (relative % (3 * WIDTH)) / 3,
            tripleRole(relative % 3),
        );
    }
    return make(ordinal, .output, NO_ROUND, ordinal - OUTPUT_START, .output);
}

pub fn validateMaterializations(entries: []const Materialization) ValidationError!void {
    if (entries.len != N_MATERIALIZATIONS) return error.EntryCountMismatch;
    for (entries, 0..) |actual, ordinal| {
        const wanted = try expected(ordinal);
        if (actual.ordinal != wanted.ordinal) return error.OrdinalMismatch;
        if (actual.column != wanted.column) return error.ColumnOutOfRange;
        if (actual.constraint != wanted.constraint) return error.ConstraintMismatch;
        if (actual.phase != wanted.phase) return error.PhaseMismatch;
        if (actual.round != wanted.round) return error.RoundMismatch;
        if (actual.lane != wanted.lane) return error.LaneMismatch;
        if (actual.role != wanted.role) return error.RoleMismatch;
    }
}

pub const Column = union(enum) {
    enabler,
    input: u8,
    materialization: Materialization,
    wide,
    io,
};

/// Total, checked projection from the current physical index to its role.
pub fn column(index: usize) ValidationError!Column {
    if (index >= N_MAIN_COLUMNS) return error.ColumnOutOfRange;
    if (index == ENABLER_COLUMN) return .enabler;
    if (index < TEMPORARY_START) return .{ .input = @intCast(index - INPUT_START) };
    if (index < WIDE_COLUMN) return .{
        .materialization = try expected(index - TEMPORARY_START),
    };
    if (index == WIDE_COLUMN) return .wide;
    return .io;
}

/// Stable logical source path. This is separate from the physical column name
/// so diagnostics preserve meaning even while reproducing a legacy layout.
pub fn writeSemanticPath(writer: anytype, entry: Materialization) !void {
    const wanted = try expected(entry.ordinal);
    if (!std.meta.eql(entry, wanted)) return mismatch(entry, wanted);
    switch (entry.phase) {
        .external_round => try writer.print(
            "riscv.poseidon2_m31.external_round[{d}].lane[{d}].{s}",
            .{ entry.round, entry.lane, roleName(entry.role) },
        ),
        .internal_round => try writer.print(
            "riscv.poseidon2_m31.internal_round[{d}].lane[0].{s}",
            .{ entry.round, roleName(entry.role) },
        ),
        .output => try writer.print(
            "riscv.poseidon2_m31.output[{d}]",
            .{entry.lane},
        ),
    }
}

pub fn writeColumnName(writer: anytype, index: usize) !void {
    switch (try column(index)) {
        .enabler => try writer.writeAll("poseidon2.enabler"),
        .input => |lane| try writer.print("poseidon2.input[{d}]", .{lane}),
        .materialization => |entry| try writer.print(
            "poseidon2.temporary[{d}]",
            .{entry.ordinal},
        ),
        .wide => try writer.writeAll("poseidon2.wide"),
        .io => try writer.writeAll("poseidon2.io"),
    }
}

/// Deterministic, review-oriented machine view of the complete placement.
pub fn writeSchedule(writer: anytype, schedule: OwnedSchedule) !void {
    try schedule.validate();
    try writer.print(
        "# stwo-zig typed-air poseidon2-compatibility-schedule v{d}\n",
        .{schedule.identity.format_version},
    );
    try writer.print(
        "# policy {s} v{d}; materializer {s} v{d}; maximum-degree {d}; width {d}; " ++
            "materializations {d}; main-columns {d}\n",
        .{
            policyName(schedule.identity.policy),
            schedule.identity.policy_version,
            MATERIALIZER_POLICY_NAME,
            MATERIALIZER_POLICY_VERSION,
            schedule.identity.maximum_constraint_degree,
            schedule.identity.width,
            schedule.identity.materializations,
            schedule.identity.main_columns,
        },
    );
    try writer.writeAll("ordinal\tcolumn\tconstraint\tphase\tround\tlane\trole\tsemantic_path\n");
    for (schedule.materializations) |entry| {
        try writer.print(
            "{d}\t{d}\t{d}\t{s}\t",
            .{ entry.ordinal, entry.column, entry.constraint, @tagName(entry.phase) },
        );
        if (entry.round == NO_ROUND) try writer.writeByte('-') else try writer.print(
            "{d}",
            .{entry.round},
        );
        try writer.print("\t{d}\t{s}\t", .{ entry.lane, roleName(entry.role) });
        try writeSemanticPath(writer, entry);
        try writer.writeByte('\n');
    }
}

/// One typed node associated with a legacy compatibility slot. The source span
/// is retained for diagnostic rendering; the semantic path remains canonical
/// schedule data rather than an allocated string.
pub const Binding = struct {
    materialization: Materialization,
    plan_materialization: materializer.MaterializationId,
    value: types.ValueId,
    source_span: source.SourceSpan,
};

pub const OwnedBinding = struct {
    identity: Identity,
    materializer_policy_version: u16,
    program_digest: digest.Digest,
    gate: types.ValueId,
    policy: materializer.Policy,
    entries: []Binding,

    pub fn deinit(self: *OwnedBinding, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
        self.* = undefined;
    }

    /// Reconstructs the canonical mapping and authenticates the plan, function
    /// shell, local semantic chain, and every physical-slot correspondence.
    /// H-005 must call this after an ownership boundary.
    pub fn validateAgainst(
        self: *const OwnedBinding,
        allocator: std.mem.Allocator,
        arena: *const ir.Arena,
        definition: poseidon.Definition,
        spans: poseidon.DefinitionSpans,
        plan_value: *const materializer.Plan,
    ) (materializer.Error || BindingError)!void {
        const gate = try validatePlanEnvelope(
            allocator,
            arena,
            definition,
            plan_value,
        );
        try self.identity.validate();
        if (!std.meta.eql(self.identity, Identity.canonical()) or
            self.materializer_policy_version != materializer.policy_version or
            self.gate != gate)
        {
            return error.BindingIdentityMismatch;
        }
        try binding_check.validate(
            N_MATERIALIZATIONS,
            self.program_digest,
            self.gate,
            self.policy,
            self.entries,
            plan_value,
        );
        var placements: [N_MATERIALIZATIONS]Materialization = undefined;
        for (self.entries, 0..) |entry, ordinal| {
            if (!std.meta.eql(entry.materialization, try expected(ordinal)))
                return error.PlanBindingMismatch;
            placements[ordinal] = entry.materialization;
        }
        const schedule = OwnedSchedule{
            .identity = self.identity,
            .materializations = &placements,
        };
        var expected_values: [N_MATERIALIZATIONS]types.ValueId = undefined;
        var expected_ids: [N_MATERIALIZATIONS]materializer.MaterializationId = undefined;
        try mapPlanOrder(
            arena,
            definition,
            spans,
            schedule,
            plan_value,
            &expected_values,
            &expected_ids,
        );
        try validateInOrder(arena, definition, spans, schedule, &expected_values);
        for (self.entries, expected_values, expected_ids) |entry, value, plan_id| {
            if (entry.value != value or entry.plan_materialization != plan_id or
                !std.meta.eql(entry.source_span, arena.node(value).?.primary_source))
            {
                return error.PlanBindingMismatch;
            }
        }
    }
};

/// Admits an H-003 plan produced for the canonical `typed_poseidon2.define`
/// shell only when its complete policy and component shape match the legacy
/// layout. This is an adapter over that trusted constructor, not a universal
/// verifier for arbitrary graphs carrying a `Definition` value.
pub fn bindPlan(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    definition: poseidon.Definition,
    spans: poseidon.DefinitionSpans,
    schedule: OwnedSchedule,
    plan_value: *const materializer.Plan,
) (materializer.Error || BindingError)!OwnedBinding {
    try schedule.validate();
    const gate = try validatePlanEnvelope(allocator, arena, definition, plan_value);
    var source_values: [N_MATERIALIZATIONS]types.ValueId = undefined;
    var plan_ids: [N_MATERIALIZATIONS]materializer.MaterializationId = undefined;
    try mapPlanOrder(
        arena,
        definition,
        spans,
        schedule,
        plan_value,
        &source_values,
        &plan_ids,
    );
    try validateInOrder(
        arena,
        definition,
        spans,
        schedule,
        &source_values,
    );
    const entries = try allocator.alloc(Binding, N_MATERIALIZATIONS);
    for (entries, schedule.materializations, source_values, plan_ids) |
        *entry,
        placement,
        value,
        plan_id,
    | {
        entry.* = .{
            .materialization = placement,
            .plan_materialization = plan_id,
            .value = value,
            .source_span = arena.node(value).?.primary_source,
        };
    }
    var result = OwnedBinding{
        .identity = schedule.identity,
        .materializer_policy_version = materializer.policy_version,
        .program_digest = plan_value.program_digest,
        .gate = gate,
        .policy = plan_value.policy,
        .entries = entries,
    };
    errdefer result.deinit(allocator);
    try result.validateAgainst(allocator, arena, definition, spans, plan_value);
    return result;
}

fn validatePlanEnvelope(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    definition: poseidon.Definition,
    plan_value: *const materializer.Plan,
) (materializer.Error || BindingError)!types.ValueId {
    if (plan_value.policy.maximum_constraint_degree != MAXIMUM_CONSTRAINT_DEGREE or
        plan_value.policy.row_mask_degree != 0)
    {
        return error.MaterializerPolicyMismatch;
    }
    const gate = plan_value.gate orelse return error.MissingEnabler;
    if (plan_value.materializations.len != N_MATERIALIZATIONS or
        plan_value.outputs.len != WIDTH)
    {
        return error.CandidateCountMismatch;
    }
    try poseidon_shell.validate(arena, definition);
    try plan_value.validate(allocator, arena);
    const gate_node = arena.node(gate) orelse return error.EnablerMismatch;
    const gate_name = switch (gate_node.key.op) {
        .input => |name| arena.name(name) orelse return error.EnablerMismatch,
        else => return error.EnablerMismatch,
    };
    if (!std.mem.eql(u8, gate_name, ENABLER_NAME))
        return error.EnablerMismatch;
    for (plan_value.materializations) |item| {
        if (item.context_degree != 1 or
            item.body_degree > 2 or
            item.equality_degree > 2 or
            item.constraint_degree != MAXIMUM_CONSTRAINT_DEGREE)
        {
            return error.MaterializerDegreeMismatch;
        }
    }
    for (plan_value.outputs, definition.outputs.items) |output, expected_output| {
        if (output.root != expected_output.value) return error.OutputMismatch;
    }
    return gate;
}

/// Converts H-003's generic dependency-topological order into the frozen
/// lane-major compatibility order. H-002 creates all shifted lanes before its
/// sbox map, so raw `ValueId` order is intentionally not a layout authority.
fn mapPlanOrder(
    arena: *const ir.Arena,
    definition: poseidon.Definition,
    spans: poseidon.DefinitionSpans,
    schedule: OwnedSchedule,
    plan_value: *const materializer.Plan,
    ordered: *[N_MATERIALIZATIONS]types.ValueId,
    ordered_ids: *[N_MATERIALIZATIONS]materializer.MaterializationId,
) BindingError!void {
    var used = [_]bool{false} ** N_MATERIALIZATIONS;
    for (schedule.materializations) |entry| {
        const shape: candidate.Shape = switch (entry.role) {
            .shifted => .{ .shifted = roundConstant(entry) },
            .square => if (entry.phase == .external_round and entry.round == 0)
                .{ .first_square = roundConstant(entry) }
            else
                .{ .square_of = ordered[entry.ordinal - 1] },
            .fourth_power => .{ .square_of = ordered[entry.ordinal - 1] },
            .output => .{
                .exact = definition.outputs.items[entry.lane].value,
            },
        };
        const index = try candidate.find(
            arena,
            plan_value,
            &used,
            sourceSpan(definition, spans, entry),
            shape,
        );
        used[index] = true;
        ordered[entry.ordinal] = plan_value.materializations[index].source_value;
        ordered_ids[entry.ordinal] = @enumFromInt(index);
    }
    for (used) |consumed| if (!consumed) return error.UnmappedCandidate;
}

fn roundConstant(entry: Materialization) u32 {
    return switch (entry.phase) {
        .external_round => constants.EXTERNAL_ROUND[entry.round][entry.lane],
        .internal_round => constants.INTERNAL_ROUND[entry.round],
        .output => unreachable,
    };
}

/// Test seam for callers that already hold legacy slot order. It validates but
/// intentionally returns no owner: only `bindPlan` may create an authenticated
/// layout carrying plan identity and materialization IDs.
pub fn validateInOrder(
    arena: *const ir.Arena,
    definition: poseidon.Definition,
    spans: poseidon.DefinitionSpans,
    schedule: OwnedSchedule,
    source_values: []const types.ValueId,
) BindingError!void {
    try schedule.validate();
    if (source_values.len != N_MATERIALIZATIONS)
        return error.CandidateCountMismatch;

    for (schedule.materializations, source_values, 0..) |materialization, value, index| {
        const node = arena.node(value) orelse return error.UnknownCandidate;
        if (!std.meta.eql(node.key.ty, types.Type.felt))
            return error.NonFeltCandidate;
        const expected_span = sourceSpan(definition, spans, materialization);
        if (!std.meta.eql(node.primary_source, expected_span))
            return error.SourceSpanMismatch;
        try validateSemanticShape(
            arena,
            definition,
            materialization,
            value,
            if (index == 0) null else source_values[index - 1],
        );
    }
}

fn validateSemanticShape(
    arena: *const ir.Arena,
    definition: poseidon.Definition,
    entry: Materialization,
    value: types.ValueId,
    previous: ?types.ValueId,
) BindingError!void {
    const node = arena.node(value) orelse return error.UnknownCandidate;
    switch (entry.role) {
        .shifted => if (!candidate.addHasFieldConstant(arena, node, roundConstant(entry)))
            return error.SemanticShapeMismatch,
        .square => {
            const operand = candidate.squareOperand(node) orelse
                return error.SemanticShapeMismatch;
            if (entry.ordinal < FIRST_EXTERNAL_END) {
                const input_node = arena.node(operand) orelse
                    return error.UnknownCandidate;
                if (!candidate.addHasFieldConstant(arena, input_node, roundConstant(entry)))
                    return error.DependencyMismatch;
            } else if (previous == null or operand != previous.?) {
                return error.DependencyMismatch;
            }
        },
        .fourth_power => {
            const operand = candidate.squareOperand(node) orelse
                return error.SemanticShapeMismatch;
            if (previous == null or operand != previous.?)
                return error.DependencyMismatch;
        },
        .output => {
            if (value != definition.outputs.items[entry.lane].value)
                return error.OutputMismatch;
        },
    }
}

fn sourceSpan(
    definition: poseidon.Definition,
    spans: poseidon.DefinitionSpans,
    entry: Materialization,
) source.SourceSpan {
    return switch (entry.phase) {
        .external_round => switch (entry.role) {
            .shifted => spans.body.external_rounds[entry.round].constants,
            .square, .fourth_power => spans.body.external_rounds[entry.round].sbox,
            .output => unreachable,
        },
        .internal_round => switch (entry.role) {
            .shifted => spans.body.internal_rounds[entry.round].constant,
            .square, .fourth_power => spans.body.internal_rounds[entry.round].sbox,
            .output => unreachable,
        },
        .output => definition.outputs.items[entry.lane].source_span,
    };
}

fn make(
    ordinal: usize,
    phase: Phase,
    round: usize,
    lane: usize,
    role: Role,
) Materialization {
    return .{
        .ordinal = @intCast(ordinal),
        .column = @intCast(TEMPORARY_START + ordinal),
        .constraint = @intCast(FIRST_MATERIALIZATION_CONSTRAINT + ordinal),
        .phase = phase,
        .round = @intCast(round),
        .lane = @intCast(lane),
        .role = role,
    };
}

fn tripleRole(index: usize) Role {
    return switch (index) {
        0 => .shifted,
        1 => .square,
        2 => .fourth_power,
        else => unreachable,
    };
}

fn roleName(role: Role) []const u8 {
    return switch (role) {
        .shifted => "shifted",
        .square => "square",
        .fourth_power => "fourth_power",
        .output => "output",
    };
}

fn policyName(policy: PolicyId) []const u8 {
    return switch (policy) {
        .stark_v_poseidon2_compatibility => POLICY_NAME,
        _ => "unknown",
    };
}

fn mismatch(actual: Materialization, wanted: Materialization) ValidationError {
    if (actual.ordinal != wanted.ordinal) return error.OrdinalMismatch;
    if (actual.column != wanted.column) return error.ColumnOutOfRange;
    if (actual.constraint != wanted.constraint) return error.ConstraintMismatch;
    if (actual.phase != wanted.phase) return error.PhaseMismatch;
    if (actual.round != wanted.round) return error.RoundMismatch;
    if (actual.lane != wanted.lane) return error.LaneMismatch;
    return error.RoleMismatch;
}

comptime {
    if (materializer.policy_version != 1 or
        !std.mem.eql(
            u8,
            materializer.policy_id,
            "stwo.typed-air.materialize.degree-bounded-v1",
        ))
    {
        @compileError("Poseidon2 compatibility materializer policy drifted");
    }
    if (WIDTH != poseidon.WIDTH or WIDTH != production.WIDTH)
        @compileError("Poseidon2 width authority drifted");
    if (N_MATERIALIZATIONS != production.N_TEMPORARIES)
        @compileError("Poseidon2 compatibility materialization count drifted");
    if (N_MAIN_COLUMNS != production.N_MAIN_COLUMNS)
        @compileError("Poseidon2 compatibility main geometry drifted");
    if (production.N_MATERIALIZATION_CONSTRAINTS != N_MATERIALIZATIONS)
        @compileError("Poseidon2 materialization constraint count drifted");
    if (production.N_PERMUTATION_CONSTRAINTS !=
        FIRST_MATERIALIZATION_CONSTRAINT + N_MATERIALIZATIONS)
    {
        @compileError("Poseidon2 enabler/materialization constraint order drifted");
    }
    if (production.N_FLAG_CONSTRAINTS != 3 or
        production.N_CONSTRAINTS !=
            production.N_PERMUTATION_CONSTRAINTS + production.N_FLAG_CONSTRAINTS)
    {
        @compileError("Poseidon2 wide/io constraint tail drifted");
    }
    if (OUTPUT_START + WIDTH != N_MATERIALIZATIONS)
        @compileError("Poseidon2 output schedule no longer closes the layout");
}
