//! BG-15 host-receipt production and trusted aggregate verification owners.

const std = @import("std");

pub fn addGates(b: *std.Build) void {
    const producer = b.addSystemCommand(&.{
        "python3",
        "scripts/architecture/build_architecture_receipt.py",
        "produce",
    });
    if (b.args) |args| producer.addArgs(args);
    const producer_step = b.step(
        "architecture-gate",
        "Produce one host-local BG-15 architecture receipt",
    );
    producer_step.dependOn(&producer.step);

    const verifier = b.addSystemCommand(&.{
        "python3",
        "scripts/architecture/build_architecture_receipt.py",
        "verify",
    });
    if (b.args) |args| verifier.addArgs(args);
    const verifier_step = b.step(
        "architecture-verify",
        "Verify Linux and macOS BG-15 receipts in the trusted workflow",
    );
    verifier_step.dependOn(&verifier.step);
}
