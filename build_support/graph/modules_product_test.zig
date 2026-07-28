//! Product-identity tests for the package-aware module graph.

const std = @import("std");
const graph = @import("modules.zig");

test "executable products require explicit capabilities" {
    try std.testing.expectError(error.IncompleteProductCapabilities, (graph.Product{
        .name = "invalid",
        .frontend = .native,
        .backend = .none,
        .role = .cli,
    }).validate());
    try (graph.Product{
        .name = "stwo-native-cpu",
        .frontend = .native,
        .backend = .cpu,
        .role = .cli,
    }).validate();
}

test "capability manifests have stable public names" {
    const riscv = graph.Product{
        .name = "stwo-riscv-cpu",
        .frontend = .riscv,
        .backend = .cpu,
        .role = .gate,
    };
    try std.testing.expectEqualStrings(
        "sail-rv32im-zkvm",
        riscv.frontendManifest(),
    );
    try std.testing.expectEqualStrings("cpu", riscv.backendManifest());
}

test "generic prover identifies backend contracts without a concrete backend" {
    const prover = graph.proverProduct(.library);
    try prover.validate();
    try std.testing.expectEqualStrings("contracts", prover.backendManifest());
}

test "aggregate SDK facade has an explicit library identity" {
    const facade = graph.Product{
        .name = "stwo",
        .frontend = .aggregate,
        .backend = .contracts,
        .role = .library,
        .protocol_features = "aggregate-sdk-v1",
    };
    try facade.validate();
}
