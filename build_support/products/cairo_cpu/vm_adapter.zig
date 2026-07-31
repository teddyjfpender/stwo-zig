//! Build and installation boundary for the pinned Cairo VM sidecar.

const std = @import("std");

pub const executable_name = "stwo-cairo-vm-adapter";
pub const manifest =
    "tools/stwo-cairo-vm-adapter-rs/Cargo.toml";

// Both the product build and the cairo-zkvm-fixtures step install the
// adapter. One graph must carry ONE cargo-build/install pair — duplicate
// pairs write the same installed path from concurrent steps — so the step is
// memoized per builder.
var cached_builder: ?*std.Build = null;
var cached_step: ?*std.Build.Step = null;

pub fn addInstall(b: *std.Build) *std.Build.Step {
    if (cached_builder == b) return cached_step.?;
    const cargo = b.addSystemCommand(&.{
        "cargo",
        "build",
        "--release",
        "--locked",
        "--offline",
        "--manifest-path",
        b.pathFromRoot(manifest),
    });
    // Cargo honors CARGO_TARGET_DIR (the focused CI lanes point it into the
    // lane cache), so the produced binary is only at the manifest-relative
    // default when that override is absent. Install from wherever cargo
    // actually wrote it.
    const source: std.Build.LazyPath = if (b.graph.env_map.get("CARGO_TARGET_DIR")) |dir|
        .{ .cwd_relative = b.fmt("{s}/release/{s}", .{ dir, executable_name }) }
    else
        b.path("tools/stwo-cairo-vm-adapter-rs/target/release/" ++ executable_name);
    const install = b.addInstallFile(source, "bin/" ++ executable_name);
    install.step.dependOn(&cargo.step);
    cached_builder = b;
    cached_step = &install.step;
    return &install.step;
}
