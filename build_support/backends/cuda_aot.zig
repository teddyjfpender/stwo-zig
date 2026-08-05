//! Zig-owned, cache-resident CUDA AOT source generation.

const std = @import("std");

pub const GeneratedSet = struct {
    directory: std.Build.LazyPath,
    run: *std.Build.Step.Run,
};

pub fn addNative(b: *std.Build) GeneratedSet {
    const root = b.createModule(.{
        .root_source_file = b.path(
            "src/tools/cairo_cuda_witness_aot/main.zig",
        ),
        .target = b.graph.host,
        .optimize = .ReleaseFast,
    });
    root.addImport(
        "cairo_witness_model",
        b.createModule(.{
            .root_source_file = b.path(
                "src/tools/cairo_witness_cpu_codegen/model.zig",
            ),
            .target = b.graph.host,
            .optimize = .ReleaseFast,
        }),
    );
    const executable = b.addExecutable(.{
        .name = "cairo-cuda-witness-aot",
        .root_module = root,
    });
    const run = b.addRunArtifact(executable);
    run.addFileArg(b.path(
        "vectors/cairo/sn_pie_2_witness_programs.bin",
    ));
    run.addDirectoryArg(b.path("src/backends/cuda/aot/native"));
    addDirectoryInputs(b, run, "src/backends/cuda/aot/native");
    run.addDirectoryArg(b.path(
        "src/backends/cuda/authority/active",
    ));
    addDirectoryInputs(b, run, "src/backends/cuda/authority/active");
    run.addDirectoryArg(b.path("src/backends/cuda/native"));
    addDirectoryInputs(b, run, "src/backends/cuda/native");
    const product_root = run.addOutputDirectoryArg(
        "native-cuda-product",
    );
    return .{
        .directory = product_root.path(b, "aot/native"),
        .run = run,
    };
}

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

pub fn addNativeToolStep(b: *std.Build) void {
    const generated = addNative(b);
    b.step(
        "cuda-native-aot",
        "Generate authenticated Native CUDA AOT sources in Zig's build cache",
    ).dependOn(&generated.run.step);
}

fn addDirectoryInputs(
    b: *std.Build,
    run: *std.Build.Step.Run,
    relative_root: []const u8,
) void {
    var directory = b.build_root.handle.openDir(
        relative_root,
        .{ .iterate = true },
    ) catch |err| std.debug.panic(
        "cannot open CUDA AOT input directory {s}: {s}",
        .{ relative_root, @errorName(err) },
    );
    defer directory.close();

    var walker = directory.walk(b.allocator) catch @panic("OOM");
    defer walker.deinit();
    var files: std.ArrayList([]const u8) = .empty;
    defer files.deinit(b.allocator);

    while (walker.next() catch |err| std.debug.panic(
        "cannot enumerate CUDA AOT input directory {s}: {s}",
        .{ relative_root, @errorName(err) },
    )) |entry| {
        if (entry.kind != .file) continue;
        files.append(b.allocator, b.dupe(entry.path)) catch @panic("OOM");
    }
    std.mem.sort([]const u8, files.items, {}, struct {
        fn lessThan(_: void, left: []const u8, right: []const u8) bool {
            return std.mem.lessThan(u8, left, right);
        }
    }.lessThan);

    for (files.items) |relative_path| {
        run.addFileInput(b.path(b.pathJoin(&.{
            relative_root,
            relative_path,
        })));
    }
}
