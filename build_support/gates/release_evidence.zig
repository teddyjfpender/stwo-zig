const std = @import("std");

pub fn addGates(b: *std.Build, prove_checkpoints: *std.Build.Step) void {
    const directory = b.addSystemCommand(&.{ "mkdir", "-p", "zig-out/release-evidence/native" });
    const compile = b.addSystemCommand(&.{
        "zig",
        "build-lib",
        "src/std_shims_freestanding.zig",
        "-target",
        "wasm32-freestanding",
        "-O",
        "ReleaseSmall",
        "-femit-bin=zig-out/release-evidence/native/std-shims-verifier.wasm",
    });
    compile.step.dependOn(&directory.step);
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
