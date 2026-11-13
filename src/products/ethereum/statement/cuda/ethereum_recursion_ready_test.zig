//! Ethereum combined-lane admission, retaining the actual negative contract cases.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Execution = @import("stwo_riscv_cpu_integration").rv64_om31_execution_wrap;

test "combined ready admission binds exact physical lanes and refuses dual selections" {
    const Main = @import("ethereum_cpu_component").rv64_ethereum_gkr_main;
    const Factory = @import("stwo_circuit_cpu_integration").om31.device_prove.Factory;
    const Fake = struct {
        fn fixed(_: *anyopaque, _: std.mem.Allocator, _: *const @import("stwo_circuit_frontend").common.preprocessed.PreprocessedCircuit, _: u32) !@import("stwo_circuit_cpu_integration").om31.device_prove.PrecommittedFixed {
            return error.NotInvoked;
        }
        fn prepare(_: *anyopaque, _: std.mem.Allocator, _: *const @import("stwo_circuit_cpu_integration").om31.prove.Authority, _: []const @import("stwo_circuit_cpu_integration").om31.protocol.Q, _: @import("stwo_riscv_cpu_integration").rv64_device_pcs.Scope) !@import("stwo_circuit_cpu_integration").om31.device_prove.Source {
            return error.NotInvoked;
        }
        fn graph(_: *anyopaque, _: std.mem.Allocator, _: *const @import("stwo_circuit_cpu_integration").om31.prove.Authority, _: *const @import("stwo_circuit_frontend").builder.Context(@import("stwo_circuit_cpu_integration").om31.protocol.Q), _: @import("stwo_riscv_cpu_integration").rv64_device_pcs.Scope) !@import("stwo_circuit_cpu_integration").om31.device_prove.Source {
            return error.NotInvoked;
        }
    };
    var storage: u8 = 0;
    const factory = Factory{ .context = &storage, .prepare = Fake.prepare, .prepare_from_circuit = Fake.graph };
    var pool: Engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 1 });
    defer pool.deinit();
    const lanes = [_]Execution.Lane{.{ .physical_device = 3, .factory = factory, .pool = &pool }};
    const ready = Execution.ParallelOptions{ .lanes = &lanes, .pool_worker_budget = 1 };
    try (Main.CombinedRecursion{ .ready = ready, .physical_devices = &.{3} }).validate();
    try (Main.CombinedRecursion{ .factory = factory, .physical_devices = &.{3} }).validate();
    try std.testing.expectError(error.InvalidCombinedRecursionSelection, (Main.CombinedRecursion{ .ready = ready, .physical_devices = &.{0} }).validate());
    try std.testing.expectError(error.InvalidCombinedRecursionSelection, (Main.CombinedRecursion{ .ready = ready, .factory = factory, .physical_devices = &.{3} }).validate());
    try std.testing.expectError(error.InvalidCombinedRecursionSelection, (Main.CombinedRecursion{ .factory = factory, .physical_devices = &.{ 0, 1 } }).validate());
    try std.testing.expectError(error.InvalidCombinedRecursionSelection, (Main.CombinedRecursion{}).validate());
    try std.testing.expect(!try (Main.CombinedRecursion{ .ready = ready }).usesDeviceFixed());
    var device_factory = factory;
    device_factory.precommit_fixed = Fake.fixed;
    var other_pool: Engine.work_pool.WorkPool = .{};
    try other_pool.initInPlaceWithOptions(.{ .worker_count = 1 });
    defer other_pool.deinit();
    var other_storage: u8 = 0;
    var other_factory = device_factory;
    other_factory.context = &other_storage;
    const device_lanes = [_]Execution.Lane{
        .{ .physical_device = 0, .factory = device_factory, .pool = &pool },
        .{ .physical_device = 1, .factory = other_factory, .pool = &other_pool },
    };
    const device_ready = Execution.ParallelOptions{ .lanes = &device_lanes, .pool_worker_budget = 2 };
    try (Main.CombinedRecursion{ .ready = device_ready, .physical_devices = &.{ 0, 1 } }).validate();
    try std.testing.expect(try (Main.CombinedRecursion{ .ready = device_ready }).usesDeviceFixed());
    try std.testing.expect(try (Main.CombinedRecursion{ .factory = device_factory }).usesDeviceFixed());
    var mixed = device_lanes;
    mixed[1].factory.precommit_fixed = null;
    try std.testing.expectError(error.MixedCombinedFixedBackends, (Main.CombinedRecursion{
        .ready = .{ .lanes = &mixed, .pool_worker_budget = 2 },
    }).usesDeviceFixed());
    try std.testing.expectError(error.MixedCombinedFixedBackends, (Main.CombinedRecursion{
        .ready = .{ .lanes = &mixed, .pool_worker_budget = 2 },
        .physical_devices = &.{ 0, 1 },
    }).validate());
}
