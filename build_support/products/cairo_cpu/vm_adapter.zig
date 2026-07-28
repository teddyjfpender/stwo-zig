//! Build and installation boundary for the pinned Cairo VM sidecar.

const std = @import("std");

pub const executable_name = "stwo-cairo-vm-adapter";
pub const manifest =
    "tools/stwo-cairo-vm-adapter-rs/Cargo.toml";

pub fn addInstall(b: *std.Build) *std.Build.Step {
    const cargo = b.addSystemCommand(&.{
        "cargo",
        "build",
        "--release",
        "--locked",
        "--offline",
        "--manifest-path",
        b.pathFromRoot(manifest),
    });
    const install = b.addInstallFile(
        b.path("tools/stwo-cairo-vm-adapter-rs/target/release/" ++
            executable_name),
        "bin/" ++ executable_name,
    );
    install.step.dependOn(&cargo.step);
    return &install.step;
}
