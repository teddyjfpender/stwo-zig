//! Zig-owned, cache-resident CUDA AOT source generation.

const std = @import("std");

pub const GeneratedSet = struct {
    directory: std.Build.LazyPath,
    run: *std.Build.Step.Run,
};

pub fn addCairoEval(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    stwo: *std.Build.Module,
) GeneratedSet {
    const root = b.createModule(.{
        .root_source_file = b.path(
            "src/tools/cairo_cuda_eval_aot/main.zig",
        ),
        .target = target,
        .optimize = .ReleaseFast,
    });
    root.addImport("stwo", stwo);
    const executable = b.addExecutable(.{
        .name = "cairo-cuda-eval-aot",
        .root_module = root,
    });
    const run = b.addRunArtifact(executable);
    run.addFileArg(b.path(
        "vectors/cairo/sn_pie_2_composition.bin",
    ));
    return .{
        .directory = run.addOutputDirectoryArg(
            "cairo-cuda-eval-aot",
        ),
        .run = run,
    };
}

pub fn addCairoEvalToolStep(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    stwo: *std.Build.Module,
) void {
    const generated = addCairoEval(b, target, stwo);
    b.step(
        "cuda-cairo-eval-aot",
        "Generate authenticated Cairo CUDA eval sources in Zig's build cache",
    ).dependOn(&generated.run.step);
}
