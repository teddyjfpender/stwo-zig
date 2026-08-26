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
