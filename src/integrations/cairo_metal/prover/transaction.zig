//! Metal binding for the backend-neutral official Cairo transaction.

const std = @import("std");
const metal = @import("stwo_metal_backend");
const prover = @import("stwo_prover_impl");
const adapter = @import("stwo_cairo_frontend").adapter;
const generic = @import("stwo_cairo_frontend").proving.transaction;
const preprocessed = @import("stwo_cairo_frontend").preprocessed;

pub const Engine = metal.PlainMetalProverEngine;
pub const Fixture = generic.Fixture;
pub const Result = generic.Result(Engine);
pub const TelemetrySnapshot = Engine.TelemetrySnapshot;
pub const TelemetryDelta = Engine.Backend.TelemetryDelta;
pub const RuntimeInitializationPolicy = Engine.RuntimeInitializationPolicy;
pub const RuntimeLifecycleSnapshot = Engine.RuntimeLifecycleSnapshot;
pub const official_pcs_config = generic.official_pcs_config;

pub fn initializeRuntime(
    allocator: std.mem.Allocator,
    policy: RuntimeInitializationPolicy,
) !void {
    try Engine.initializeRuntime(allocator, policy);
}

pub fn telemetrySnapshot() Engine.TelemetryError!TelemetrySnapshot {
    return Engine.telemetrySnapshot();
}

pub fn runtimeLifecycleSnapshot() RuntimeLifecycleSnapshot {
    return Engine.runtimeLifecycleSnapshot();
}

pub fn shutdown() Engine.Backend.ShutdownError!void {
    try Engine.Backend.shutdown();
}

pub fn proveFixture(
    allocator: std.mem.Allocator,
    fixture: Fixture,
    variant: preprocessed.trace.Variant,
) !Result {
    return generic.proveFixture(Engine, allocator, fixture, variant);
}

pub fn proveFixtureWithRecorder(
    allocator: std.mem.Allocator,
    fixture: Fixture,
    variant: preprocessed.trace.Variant,
    recorder: ?*prover.stage_profile.Recorder,
) !Result {
    return generic.proveFixtureWithRecorder(
        Engine,
        allocator,
        fixture,
        variant,
        recorder,
    );
}

pub fn verifyAndConsume(
    input: *const adapter.ProverInput,
    result: *Result,
) !void {
    return generic.verifyAndConsume(Engine, input, result);
}

test "Metal binding uses the official plain Blake2s protocol" {
    try std.testing.expectEqual(@as(u32, 26), official_pcs_config.pow_bits);
    try std.testing.expect(Engine.Backend == metal.MetalCommitBackend);
}
