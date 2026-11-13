const std = @import("std");
const native = @import("stwo_riscv_cpu_integration").rv64_gkr_coordinator;

test "coordinator boundary: native operations cannot select product early owners" {
    const N = native.ForEarlySources(void, void);
    const options = N.Options{};
    try std.testing.expect(@TypeOf(options.early_cpu0) == @TypeOf(null));
    try std.testing.expect(@TypeOf(options.early_segments) == @TypeOf(null));
    try std.testing.expect(N.Bundle == native.Bundle);
    try std.testing.expect(N.WorkerTiming == native.WorkerTiming);
    try std.testing.expect(N.Stream == native.Stream);
    try std.testing.expect(N.NativeStageTwo == native.NativeStageTwo);
    try std.testing.expect(N.Store == native.Store);
    const invalid = N.Options{ .max_workers = 0 };
    try std.testing.expectError(error.BoundedWideCoordinatorLimit, invalid.validate(1));
}

test "coordinator boundary: product operations retain concrete owners and canonical records" {
    const product = @import("ethereum_cpu_component").rv64_gkr_coordinator;
    const Cpu0 = product.EarlySourceOwners.Cpu0;
    const Segments = product.EarlySourceOwners.Segments;
    try std.testing.expect(Cpu0 != void and Segments != void);
    try std.testing.expect(product == native.ForEarlySources(Cpu0, Segments));
    try std.testing.expect(@FieldType(product.Options, "early_cpu0") == ?*Cpu0);
    try std.testing.expect(@FieldType(product.Options, "early_segments") == ?*Segments);
    try std.testing.expect(product.Bundle == native.Bundle);
    try std.testing.expect(product.WorkerTiming == native.WorkerTiming);
    try std.testing.expect(product.Stream == native.Stream);
    try std.testing.expect(product.NativeStageTwo == native.NativeStageTwo);
    try std.testing.expect(product.Store == native.Store);
    const options = product.Options{};
    try std.testing.expect(options.early_cpu0 == null);
    try std.testing.expect(options.early_segments == null);
}
