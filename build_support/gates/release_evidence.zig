const std = @import("std");

pub fn addGates(b: *std.Build, prove_checkpoints: *std.Build.Step) void {
    const compile = b.addSystemCommand(&.{
        "zig",
        "build-lib",
        "src/support/shims/freestanding.zig",
        "-target",
        "wasm32-freestanding",
        "-O",
        "ReleaseSmall",
        "-femit-bin=/tmp/stwo-zig-std-shims-verifier.wasm",
    });
    b.step(
        "std-shims-smoke",
        "Build freestanding verifier profile shim (wasm32-freestanding)",
    ).dependOn(&compile.step);

    const behavior = b.addSystemCommand(&.{ "python3", "scripts/std_shims_behavior.py" });
    behavior.step.dependOn(prove_checkpoints);
    b.step(
        "std-shims-behavior",
        "Validate std-shims verifier behavior parity against standard verifier",
    ).dependOn(&behavior.step);

    const evidence = b.addSystemCommand(&.{
        "python3", "scripts/release_evidence.py", "--gate-mode", "strict",
    });
    b.step(
        "release-evidence",
        "Generate canonical release evidence manifest (vectors/reports/release_evidence.json)",
    ).dependOn(&evidence.step);
}
