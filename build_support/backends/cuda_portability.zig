//! Optional Apple-Silicon portability floor for maintained CUDA device code.

const std = @import("std");

const audited_cumetal_version = "0.1.3";

const Compatibility = enum {
    translated,
    translated_host_parity_bitreverse,
    blocked_bitreverse,
    blocked_funnel_shift,
    blocked_shared_atomic,
    blocked_cub,
    blocked_u64_atomic_min,
    blocked_runtime_api,

    fn isFloor(self: Compatibility) bool {
        return switch (self) {
            .translated, .translated_host_parity_bitreverse => true,
            else => false,
        };
    }
};

const Probe = struct {
    label: []const u8,
    source: []const u8,
    compatibility: Compatibility,

    fn definitions(self: Probe) []const []const u8 {
        return switch (self.compatibility) {
            .translated_host_parity_bitreverse => &.{"STWO_CUDA_HOST_TEST=1"},
            else => &.{},
        };
    }
};

// Complete maintained translation-unit audit against CuMetal 0.1.3. Blocked
// entries remain visible so the positive floor cannot hide compatibility gaps.
const probes = [_]Probe{
    .{ .label = "cairo-casm-input", .source = "src/backends/cuda/native/cairo/casm_input.cu", .compatibility = .translated },
    .{ .label = "cairo-eval-params", .source = "src/backends/cuda/native/cairo/eval_params.cu", .compatibility = .translated },
    .{ .label = "cairo-memory-base", .source = "src/backends/cuda/native/cairo/memory_base.cu", .compatibility = .translated },
    .{ .label = "cairo-memory-execution", .source = "src/backends/cuda/native/cairo/memory_execution.cu", .compatibility = .translated },
    .{ .label = "cairo-witness-compact-v2", .source = "src/backends/cuda/native/cairo/witness_compact_v2.cu", .compatibility = .blocked_cub },
    .{ .label = "cairo-witness-edge", .source = "src/backends/cuda/native/cairo/witness_edge.cu", .compatibility = .translated },
    .{ .label = "cairo-witness-multi-edge", .source = "src/backends/cuda/native/cairo/witness_multi_edge.cu", .compatibility = .translated },
    .{ .label = "cairo-witness-seed", .source = "src/backends/cuda/native/cairo/witness_seed.cu", .compatibility = .translated },
    .{ .label = "commitment-merkle", .source = "src/backends/cuda/native/commitment/merkle.cu", .compatibility = .blocked_funnel_shift },
    .{ .label = "commitment-progressive", .source = "src/backends/cuda/native/commitment/progressive.cu", .compatibility = .blocked_funnel_shift },
    .{ .label = "constraint-powers", .source = "src/backends/cuda/native/constraints/powers.cu", .compatibility = .translated },
    .{ .label = "decommit-fri", .source = "src/backends/cuda/native/decommit/fri.cu", .compatibility = .blocked_shared_atomic },
    .{ .label = "decommit-query-planning", .source = "src/backends/cuda/native/decommit/query_planning.cu", .compatibility = .translated },
    .{ .label = "decommit-sparse-parents", .source = "src/backends/cuda/native/decommit/sparse_parents.cu", .compatibility = .blocked_funnel_shift },
    .{ .label = "decommit-trace", .source = "src/backends/cuda/native/decommit/trace.cu", .compatibility = .blocked_shared_atomic },
    .{ .label = "fri-final", .source = "src/backends/cuda/native/fri/final.cu", .compatibility = .translated },
    .{ .label = "fri-fold", .source = "src/backends/cuda/native/fri/fold.cu", .compatibility = .translated },
    .{
        .label = "trace-wide-fibonacci",
        .source = "src/backends/cuda/native/kernels/wide_fibonacci_trace.cu",
        .compatibility = .translated_host_parity_bitreverse,
    },
    .{
        .label = "trace-xor",
        .source = "src/backends/cuda/native/kernels/xor_trace.cu",
        .compatibility = .translated_host_parity_bitreverse,
    },
    .{ .label = "oods-barycentric", .source = "src/backends/cuda/native/oods/barycentric.cu", .compatibility = .translated },
    .{ .label = "oods-evaluate", .source = "src/backends/cuda/native/oods/evaluate.cu", .compatibility = .translated },
    .{ .label = "pow-search", .source = "src/backends/cuda/native/pow/search.cu", .compatibility = .blocked_u64_atomic_min },
    .{ .label = "quotient-combine", .source = "src/backends/cuda/native/quotient/combine.cu", .compatibility = .blocked_bitreverse },
    .{ .label = "quotient-numerator", .source = "src/backends/cuda/native/quotient/numerator.cu", .compatibility = .translated },
    .{ .label = "quotient-prepare", .source = "src/backends/cuda/native/quotient/prepare.cu", .compatibility = .translated },
    .{ .label = "relation-batch-inverse", .source = "src/backends/cuda/native/relation/batch_inverse.cu", .compatibility = .translated },
    .{ .label = "relation-graph", .source = "src/backends/cuda/native/relation/graph.cu", .compatibility = .translated },
    .{ .label = "runtime-context", .source = "src/backends/cuda/native/runtime/context.cu", .compatibility = .blocked_runtime_api },
    .{ .label = "transcript", .source = "src/backends/cuda/native/transcript/transcript.cu", .compatibility = .blocked_funnel_shift },
    .{ .label = "transform-b2n-retained", .source = "src/backends/cuda/native/transform/b2n_retained.cu", .compatibility = .blocked_runtime_api },
    .{ .label = "transform-composition-split", .source = "src/backends/cuda/native/transform/composition_split.cu", .compatibility = .blocked_runtime_api },
    .{ .label = "transform-lde", .source = "src/backends/cuda/native/transform/lde.cu", .compatibility = .blocked_runtime_api },
    .{ .label = "transform-n2b", .source = "src/backends/cuda/native/transform/n2b.cu", .compatibility = .blocked_runtime_api },
};

pub fn addStep(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
) void {
    const step = b.step(
        "cuda-cumetal-portability",
        "Translate the maintained CUDA device-code portability floor with CuMetal",
    );
    const compiler = b.option(
        []const u8,
        "cuda-cumetalc",
        "Explicit CuMetal compiler used only by the optional macOS portability lane",
    ) orelse {
        step.dependOn(&b.addFail(
            "cuda-cumetal-portability requires -Dcuda-cumetalc=/absolute/path/to/cumetalc",
        ).step);
        return;
    };
    if (target.result.os.tag != .macos) {
        step.dependOn(&b.addFail(
            "cuda-cumetal-portability is an Apple Metal development lane and requires macOS",
        ).step);
        return;
    }

    const version = b.addSystemCommand(&.{ compiler, "--version" });
    for (probes) |probe| {
        if (!probe.compatibility.isFloor()) continue;
        const command = b.addSystemCommand(&.{compiler});
        command.addFileArg(b.path(probe.source));
        command.addArg("-o");
        _ = command.addOutputFileArg(b.fmt("{s}.metallib", .{probe.label}));
        command.addArgs(&.{
            "--cuda-device",
            "--ptx-strict",
            "--overwrite",
        });
        for (probe.definitions()) |definition| command.addArg(
            b.fmt("-D{s}", .{definition}),
        );
        command.step.dependOn(&version.step);
        step.dependOn(&command.step);
    }
}

test "CuMetal portability floor remains maintained device code only" {
    try std.testing.expectEqualStrings("0.1.3", audited_cumetal_version);
    try std.testing.expectEqual(@as(usize, 33), probes.len);
    var floor_count: usize = 0;
    var strict_count: usize = 0;
    for (probes, 0..) |probe, index| {
        try std.testing.expect(std.mem.startsWith(
            u8,
            probe.source,
            "src/backends/cuda/native/",
        ));
        try std.testing.expect(std.mem.endsWith(u8, probe.source, ".cu"));
        for (probes[0..index]) |previous| {
            try std.testing.expect(!std.mem.eql(
                u8,
                previous.source,
                probe.source,
            ));
        }
        if (probe.compatibility.isFloor()) floor_count += 1;
        if (probe.compatibility == .translated) strict_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 19), floor_count);
    try std.testing.expectEqual(@as(usize, 17), strict_count);
}
