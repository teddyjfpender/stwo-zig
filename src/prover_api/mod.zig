//! Stable frontend/backend contracts for the prover engine.
//!
//! This package owns transaction types and observability schemas that callers
//! may depend on without importing commitment, quotient, FRI, or orchestration
//! implementations.

const std = @import("std");

pub const column = @import("column.zig");
pub const device_composition = @import("device_composition.zig");
pub const engine = @import("engine.zig");
pub const stage_profile = @import("stage_profile.zig");

pub const ColumnEvaluation = column.ColumnEvaluation;
pub const ColumnSource = column.ColumnSource;
pub const DeviceCompositionStage = device_composition.Stage;
pub const QuotientOpsError = column.QuotientOpsError;
pub const CpuCompositionContentionPolicy = engine.CpuCompositionContentionPolicy;
pub const CpuCompositionExecutionRequest = engine.CpuCompositionExecutionRequest;
pub const ProveOptions = engine.ProveOptions;
pub const assertProverEngine = engine.assertProverEngine;

test "api signature: prover engine transaction is structurally checked" {
    const core = @import("stwo_core");
    const FakeEngine = struct {
        pub const Scheme = struct {};
        pub const Channel = struct {};
        pub const Component = struct {};
        pub const ExtendedProof = struct {};

        pub fn init(
            allocator: std.mem.Allocator,
            config: core.pcs.PcsConfig,
        ) !Scheme {
            _ = allocator;
            _ = config;
            return .{};
        }

        pub fn deinit(scheme: *Scheme, allocator: std.mem.Allocator) void {
            _ = scheme;
            _ = allocator;
        }

        pub fn commit(
            scheme: *Scheme,
            allocator: std.mem.Allocator,
            columns: []ColumnEvaluation,
            recorder: ?*stage_profile.Recorder,
            channel: *Channel,
        ) !void {
            _ = scheme;
            _ = allocator;
            _ = columns;
            _ = recorder;
            _ = channel;
        }

        pub fn prove(
            allocator: std.mem.Allocator,
            components: []const Component,
            channel: *Channel,
            scheme: Scheme,
            options: ProveOptions,
        ) !ExtendedProof {
            _ = allocator;
            _ = components;
            _ = channel;
            _ = scheme;
            _ = options;
            return .{};
        }
    };
    comptime assertProverEngine(FakeEngine);
}

test {
    std.testing.refAllDecls(@This());
}
