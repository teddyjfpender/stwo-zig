const std = @import("std");
const core = @import("stwo_core");
const C = @import("component.zig");
const P = @import("protocol.zig");
const Air = @import("../air.zig");
test "om31 outer component vtables derive full physical masks from original authority" {
    const a = std.testing.allocator;
    const bytes = try std.fs.cwd().readFileAlloc(a, Air.bundle_path, 64 << 20);
    defer a.free(bytes);
    var bundle = try Air.parse(a, bytes);
    defer bundle.deinit();
    const logs = [_]u32{23} ** 45;
    const point = try core.circle.secureFieldPointFromRandomSeedCheckedFor(P.O, P.O{ .c0 = P.Q.fromU32Unchecked(3, 5, 7, 11), .c1 = P.Q.fromU32Unchecked(13, 17, 19, 23) });
    for (bundle.components) |*captured| {
        var component = C.Component{ .allocator = a, .captured = captured, .preprocessed_logs = &logs, .z = P.O.one(), .alpha = P.O.basis(), .claim = P.O.zero() };
        try component.validate();
        const prover = component.asProverComponent();
        const verifier = component.asVerifierComponent();
        try std.testing.expectEqual(prover.nConstraints(), verifier.nConstraints());
        var bounds = try prover.traceLogDegreeBounds(a);
        defer bounds.deinitDeep(a);
        var masks = try verifier.maskPoints(a, point, bundle.max_evaluation_log_size - 1);
        defer masks.deinitDeep(a);
        const span = try @import("geometry.zig").span(captured.*, 2);
        try std.testing.expectEqual(span.end - span.start, masks.items[2].len);
        try std.testing.expectEqual(bounds.items[2].len, masks.items[2].len);
    }
}

test "om31 outer receiver rejects modified original AIR before binding" {
    const a = std.testing.allocator;
    const bytes = try std.fs.cwd().readFileAlloc(a, Air.bundle_path, 64 << 20);
    defer a.free(bytes);
    var parsed = try @import("prove.zig").parsePinnedAir(a, bytes);
    parsed.deinit();
    bytes[bytes.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidOm31CircuitAirAuthority, @import("prove.zig").parsePinnedAir(a, bytes));
}
test "om31 outer gather mass stays strictly below base characteristic" {
    const List = @import("stwo_circuit_frontend").common.component_list;
    const Native = @import("prove.zig");
    var logs = List.PerComponent(u32).fromArray([_]u32{4} ** List.N_COMPONENTS);
    const baseline = try Native.validateGatherMass(logs, 0);
    const prime = core.fields.m31.Modulus;
    try std.testing.expectEqual(prime - 1, try Native.validateGatherMass(logs, @intCast(prime - baseline - 1)));
    try std.testing.expectError(error.Om31CircuitCharacteristicBound, Native.validateGatherMass(logs, @intCast(prime - baseline)));
    logs.eq = 31;
    try std.testing.expectError(error.Om31CircuitCharacteristicBound, Native.validateGatherMass(logs, 8));
    logs.eq = 30;
    try std.testing.expectError(error.Om31CircuitCharacteristicBound, Native.validateGatherMass(logs, 8));
}
