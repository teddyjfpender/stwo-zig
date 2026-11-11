//! Registration owner for the existing experimental OP source/proof gates.
//! Keeps minimum discovery counts and environment-gated probes together.
const std = @import("std");
const tests = @import("riscv_cpu_tests.zig");
const test_filter = @import("riscv_test_filter.zig");

pub fn add(context: tests.Context) void {
    inline for (.{
        .{ "op-runtime", "src/frontends/riscv/rv64_op_runtime_test_root.zig", 3 },
        .{ "op-tower", "src/frontends/riscv/rv64_op_tower_test_root.zig", 3 },
        .{ "op-g2-source", "src/frontends/riscv/rv64_bn254_g2_test_root.zig", 18 },
        .{ "op-g2-preparation-source", "src/frontends/riscv/rv64_bn254_g2_preparation_test_root.zig", 14 },
        .{ "op-g2-subgroup-source", "src/frontends/riscv/rv64_bn254_g2_subgroup_test_root.zig", 16 },
        .{ "op-hint-source", "src/frontends/riscv/rv64_bn254_hint_test_root.zig", 3 },
        .{ "op-residue-source", "src/frontends/riscv/rv64_bn254_residue_test_root.zig", 16 },
        .{ "op-miller-source", "src/frontends/riscv/rv64_bn254_miller_test_root.zig", 16 },
        .{ "op-pairing-source", "src/frontends/riscv/rv64_bn254_pairing_test_root.zig", 16 },
        .{ "op-mac-source", "src/frontends/riscv/rv64_bn254_mac6_test_root.zig", 8 },
        .{ "op-mac12-source", "src/frontends/riscv/rv64_bn254_mac12_test_root.zig", 7 },
        .{ "op-pairing-lowering", "src/frontends/riscv/rv64_bn254_pairing_lowering_test_root.zig", 15 },
        .{ "op-mac12-proof", "src/integrations/riscv_cpu/rv64_op_mac12_test_root.zig", 2 },
        .{ "op-pairing-proof", "src/integrations/riscv_cpu/rv64_op_pairing_mac12_test_root.zig", 9 },
        .{ "op-pairing-horner", "src/integrations/riscv_cpu/rv64_op_pairing_horner_test_root.zig", 5 },
        .{ "op-pairing-r7-projection", "src/integrations/riscv_cpu/rv64_op_pairing_r7_projection_test_root.zig", 5 },
        .{ "op-mac12-padding-audit", "src/frontends/riscv/rv64_bn254_mac12_padding_audit_test_root.zig", 2 },
        .{ "op-pairing-fixture", "src/frontends/riscv/rv64_bn254_pairing_fixture_test_root.zig", 11 },
        .{ "op-segmented-lane", "src/integrations/riscv_cpu/rv64_op_segmented_lane_test_root.zig", 3 },
        .{ "op-g2-subgroup-proof", "src/integrations/riscv_cpu/rv64_op_g2_subgroup_test_root.zig", 4 },
        .{ "op-residue-proof", "src/integrations/riscv_cpu/rv64_op_residue_test_root.zig", 4 },
        .{ "op-dense-local-gkr", "src/integrations/riscv_cpu/rv64_op_dense_local_gkr_test_root.zig", 2 },
        .{ "op-dense-proof", "src/integrations/riscv_cpu/rv64_op_dense_physical_test_root.zig", 1 },
        .{ "op-tower-proof", "src/integrations/riscv_cpu/rv64_op_tower_physical_test_root.zig", 1 },
        .{ "op-native-join", "src/integrations/riscv_cpu/rv64_op_native_join_test_root.zig", 1 },
        .{ "op-native-truth", "src/integrations/riscv_cpu/rv64_op_native_truth_test_root.zig", 1 },
    }) |suite| {
        context.b.step("test-riscv64-" ++ suite[0], "Test OP source and physical proof gates").dependOn(test_filter.addSuites(context.b, &.{.{
            .tests = tests.addFocusedTestRoot(context, suite[1], &.{}),
            .minimum = suite[2],
        }}));
    }
    inline for (.{
        .{ "fill", "src/frontends/riscv/rv64_bn254_pairing_fill_bench_test_root.zig" },
        .{ "plan", "src/frontends/riscv/rv64_bn254_pairing_plan_bench_test_root.zig" },
    }) |bench| {
        context.b.step("bench-riscv64-op-pairing-" ++ bench[0], "Environment-gated bounded pairing witness benchmark").dependOn(test_filter.addSuites(context.b, &.{.{
            .tests = tests.addFocusedTestRoot(context, bench[1], &.{}),
            .minimum = 1,
        }}));
    }
    const pairing_check = tests.addFocusedTestRoot(
        context,
        "src/integrations/riscv_cpu/rv64_op_pairing_mac12_test_root.zig",
        &.{},
    );
    context.b.step("check-riscv64-op-pairing", "Type-check complete pairing experiment without LLVM output").dependOn(&pairing_check.step);
}

pub fn addNativeCheck(b: *std.Build, module: *std.Build.Module) void {
    // No install/getEmittedBin: this lazy artifact performs semantic analysis only.
    const check = b.addExecutable(.{ .name = "rv64-op-native-check", .root_module = module });
    b.step("check-rv64-op-native", "Fast semantic check of explicit OP native runtime").dependOn(&check.step);
}
