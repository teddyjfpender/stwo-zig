//! Signature-checked prover transaction contract.

const std = @import("std");
const pcs = @import("stwo_core").pcs;
const column = @import("column.zig");
const device_composition = @import("device_composition.zig");
const stage_profile = @import("stage_profile.zig");

/// Admission behavior when a CPU composition request cannot obtain its exact
/// worker count or would require an unprepared coordinator fallback.
pub const CpuCompositionContentionPolicy = enum {
    strict,
    compatibility,
};

/// Per-proof CPU composition resources used after an optional device stage
/// declines. The prover resolves the worker count to its private shared pool
/// and passes the request through execution-aware CPU backends and prepared
/// fallback paths; no executor implementation type crosses this stable API
/// boundary.
pub const CpuCompositionExecutionRequest = struct {
    worker_count: usize,
    host_byte_budget: usize,
    contention_policy: CpuCompositionContentionPolicy = .strict,
};

/// First failing phase of one complete prover transaction.
///
/// This diagnostic is an observability side channel only. It never replaces
/// the original error and is not mixed into the proof transcript.
pub const ProvePhase = enum {
    execution_authority,
    statement_admission,
    base_witness,
    extension_witness,
    tree0,
    tree1,
    tree2,
    composition,
    fri,
    openings,
    finalize,
    capture,
};

pub const CompositionSubphase = enum {
    assembly,
    geometry,
    evaluation,
    interpolation_split,
    commitment,
};

pub const EvaluationStage = enum {
    residency,
    trace_shape,
    plan,
    component_evaluation,
    lift_accumulation,
    final_length,
};

pub const EvaluationDiagnostic = struct {
    stage: EvaluationStage,
    cause: anyerror,
    component_index: ?u32 = null,
    tree_index: ?u32 = null,
    column_index: ?u32 = null,
    actual: ?usize = null,
    expected: ?usize = null,

    pub fn recordFirst(
        output: ?*?EvaluationDiagnostic,
        value: EvaluationDiagnostic,
    ) void {
        const retained = output orelse return;
        if (retained.* == null) retained.* = value;
    }
};

pub const ProveDiagnostic = struct {
    phase: ProvePhase,
    cause: anyerror,
    composition_subphase: ?CompositionSubphase = null,
    evaluation: ?EvaluationDiagnostic = null,

    pub fn recordFirst(
        output: ?*?ProveDiagnostic,
        phase: ProvePhase,
        cause: anyerror,
    ) void {
        recordFirstAt(output, phase, null, cause);
    }

    pub fn recordFirstAt(
        output: ?*?ProveDiagnostic,
        phase: ProvePhase,
        composition_subphase: ?CompositionSubphase,
        cause: anyerror,
    ) void {
        recordFirstDetailed(output, phase, composition_subphase, null, cause);
    }

    pub fn recordFirstDetailed(
        output: ?*?ProveDiagnostic,
        phase: ProvePhase,
        composition_subphase: ?CompositionSubphase,
        evaluation: ?EvaluationDiagnostic,
        cause: anyerror,
    ) void {
        const retained = output orelse return;
        if (retained.* == null) retained.* = .{
            .phase = phase,
            .cause = cause,
            .composition_subphase = composition_subphase,
            .evaluation = evaluation,
        };
    }
};

pub const ProveOptions = struct {
    include_all_preprocessed_columns: bool = false,
    recorder: ?*stage_profile.Recorder = null,
    /// Optional whole-stage device evaluator scoped to this prove call.
    composition_stage: ?device_composition.Stage = null,
    /// Optional exact CPU composition scheduling request for this prove call.
    cpu_composition_execution: ?CpuCompositionExecutionRequest = null,
};

test "CPU composition execution is a value-only public request" {
    const request = CpuCompositionExecutionRequest{
        .worker_count = 4,
        .host_byte_budget = 8 * 1024 * 1024,
        .contention_policy = .compatibility,
    };
    try std.testing.expectEqual(@as(usize, 4), request.worker_count);
    try std.testing.expectEqual(
        CpuCompositionContentionPolicy.compatibility,
        request.contention_policy,
    );
}

test "prove diagnostic retains the first error across every typed phase" {
    inline for (std.meta.fields(ProvePhase)) |field| {
        const phase: ProvePhase = @enumFromInt(field.value);
        var diagnostic: ?ProveDiagnostic = null;
        ProveDiagnostic.recordFirst(
            &diagnostic,
            phase,
            error.InvalidProofShape,
        );
        ProveDiagnostic.recordFirst(
            &diagnostic,
            .capture,
            error.InvalidStructure,
        );
        const retained = diagnostic orelse return error.MissingDiagnostic;
        try std.testing.expectEqual(phase, retained.phase);
        try std.testing.expectEqual(error.InvalidProofShape, retained.cause);
        try std.testing.expect(retained.composition_subphase == null);
        try std.testing.expect(retained.evaluation == null);
    }
}

test "evaluation diagnostic retains the first existing predicate" {
    inline for (std.meta.fields(EvaluationStage)) |field| {
        const stage: EvaluationStage = @enumFromInt(field.value);
        var diagnostic: ?EvaluationDiagnostic = null;
        EvaluationDiagnostic.recordFirst(&diagnostic, .{
            .stage = stage,
            .cause = error.InvalidProofShape,
            .component_index = 7,
            .tree_index = 2,
            .column_index = 11,
            .actual = 16,
            .expected = 32,
        });
        EvaluationDiagnostic.recordFirst(&diagnostic, .{
            .stage = .final_length,
            .cause = error.InvalidStructure,
        });
        const retained = diagnostic orelse return error.MissingDiagnostic;
        try std.testing.expectEqual(stage, retained.stage);
        try std.testing.expectEqual(@as(u32, 7), retained.component_index.?);
        try std.testing.expectEqual(@as(usize, 16), retained.actual.?);
        try std.testing.expectEqual(error.InvalidProofShape, retained.cause);
    }
}

test "prove diagnostic retains the first composition subphase" {
    inline for (std.meta.fields(CompositionSubphase)) |field| {
        const subphase: CompositionSubphase = @enumFromInt(field.value);
        var diagnostic: ?ProveDiagnostic = null;
        ProveDiagnostic.recordFirstAt(
            &diagnostic,
            .composition,
            subphase,
            error.InvalidProofShape,
        );
        ProveDiagnostic.recordFirstAt(
            &diagnostic,
            .composition,
            .commitment,
            error.InvalidStructure,
        );
        const retained = diagnostic orelse return error.MissingDiagnostic;
        try std.testing.expectEqual(ProvePhase.composition, retained.phase);
        try std.testing.expectEqual(subphase, retained.composition_subphase.?);
        try std.testing.expectEqual(error.InvalidProofShape, retained.cause);
    }
}

/// Checks the complete transaction-level surface expected by frontends.
///
/// Engines expose the concrete component and proof types as associated types,
/// allowing this package to validate signatures without importing the engine
/// implementation that defines those types.
pub fn assertProverEngine(comptime Engine: type) void {
    comptime {
        for ([_][]const u8{
            "Scheme",
            "Channel",
            "Component",
            "ExtendedProof",
            "init",
            "deinit",
            "commit",
            "prove",
        }) |name| {
            if (!@hasDecl(Engine, name)) {
                @compileError("prover engine is missing required declaration `" ++ name ++ "`");
            }
        }

        assertErrorUnionPayload(
            @TypeOf(Engine.init(
                @as(std.mem.Allocator, undefined),
                @as(pcs.PcsConfig, undefined),
            )),
            Engine.Scheme,
            "`Engine.init` must return `!Engine.Scheme`.",
        );
        if (@TypeOf(Engine.deinit(
            @as(*Engine.Scheme, undefined),
            @as(std.mem.Allocator, undefined),
        )) != void) {
            @compileError("`Engine.deinit` must return `void`.");
        }
        assertErrorUnionPayload(
            @TypeOf(Engine.commit(
                @as(*Engine.Scheme, undefined),
                @as(std.mem.Allocator, undefined),
                @as([]column.ColumnEvaluation, undefined),
                @as(?*stage_profile.Recorder, undefined),
                @as(*Engine.Channel, undefined),
            )),
            void,
            "`Engine.commit` does not match the stable transaction signature.",
        );
        assertErrorUnionPayload(
            @TypeOf(Engine.prove(
                @as(std.mem.Allocator, undefined),
                @as([]const Engine.Component, undefined),
                @as(*Engine.Channel, undefined),
                @as(Engine.Scheme, undefined),
                @as(ProveOptions, undefined),
            )),
            Engine.ExtendedProof,
            "`Engine.prove` does not match the stable transaction signature.",
        );
    }
}

fn assertErrorUnionPayload(
    comptime Actual: type,
    comptime Expected: type,
    comptime message: []const u8,
) void {
    const info = @typeInfo(Actual);
    if (info != .error_union or info.error_union.payload != Expected) {
        @compileError(message);
    }
}
