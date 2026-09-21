const std = @import("std");

pub const Result = struct {
    prove_checkpoints: *std.Build.Step,
};

pub fn addGates(b: *std.Build, zig_optimize_arg: []const u8) Result {
    const deep = b.addSystemCommand(&.{ "python3", "scripts/zig_protocol_test.py" });
    // The serial launcher already owns the scheduling lock for this build.
    if (b.graph.env_map.get("STWO_ZIG_BUILD_HELD_LOCK") != null) deep.addArg("--no-lock");
    deep.addArgs(&.{ "src/stwo_deep.zig", zig_optimize_arg });
    b.step("deep-gate", "Run expanded deep graph coverage").dependOn(&deep.step);

    const fields = b.addSystemCommand(&.{ "python3", "scripts/parity_fields.py", "--skip-zig" });
    const constraints = b.addSystemCommand(&.{
        "python3", "scripts/parity_constraint_expr.py", "--skip-zig",
    });
    constraints.step.dependOn(&fields.step);
    const air = b.addSystemCommand(&.{
        "python3", "scripts/parity_air_derive.py", "--skip-zig",
    });
    air.step.dependOn(&constraints.step);
    b.step("vectors", "Validate committed parity vectors").dependOn(&air.step);

    const interop = b.addSystemCommand(&.{ "python3", "scripts/e2e_interop.py" });
    b.step(
        "interop",
        "Run interoperability harness (Rust <-> Zig proof exchange)",
    ).dependOn(&interop.step);

    const checkpoints = b.addSystemCommand(&.{ "python3", "scripts/prove_checkpoints.py" });
    b.step(
        "prove-checkpoints",
        "Run prove/prove_ex checkpoint harness (Rust -> Zig/Rust verification)",
    ).dependOn(&checkpoints.step);

    return .{ .prove_checkpoints = &checkpoints.step };
}
