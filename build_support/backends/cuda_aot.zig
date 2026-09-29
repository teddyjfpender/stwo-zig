//! Zig-owned, cache-resident CUDA AOT source generation.

const std = @import("std");

pub const GeneratedSet = struct {
    directory: std.Build.LazyPath,
    run: *std.Build.Step.Run,
    canonical_eval: ?std.Build.LazyPath = null,
    canonical_witness: ?std.Build.LazyPath = null,
};

fn witnessGenerator(b: *std.Build, name: []const u8) *std.Build.Step.Compile {
    const root = b.createModule(.{
        .root_source_file = b.path(
            "src/tools/cairo_cuda_witness_aot/main.zig",
        ),
        .target = b.graph.host,
        .optimize = .ReleaseFast,
    });
    const model = b.createModule(.{
        .root_source_file = b.path("src/tools/cairo_witness_cpu_codegen/model.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseFast,
    });
    model.addImport("cairo_deduction_contract", b.createModule(.{
        .root_source_file = b.path("src/frontends/cairo/witness/deduction_contract.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseFast,
    }));
    root.addImport("cairo_witness_model", model);
    return b.addExecutable(.{
        .name = name,
        .root_module = root,
    });
}

pub fn addNative(b: *std.Build) GeneratedSet {
    const executable = witnessGenerator(b, "cairo-cuda-witness-aot");
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
    const canonical = addCanonicalCairoEval(b, target, stwo);
    const witnesses = addCanonicalWitness(b);
    return .{
        .directory = run.addOutputDirectoryArg(
            "cairo-cuda-eval-aot",
        ),
        .run = run,
        .canonical_eval = canonical.directory,
        .canonical_witness = witnesses.directory,
    };
}

pub fn addCairoEvalToolStep(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    stwo: *std.Build.Module,
) void {
    const generated = addCairoEval(b, target, stwo);
    const step = b.step(
        "cuda-cairo-eval-aot",
        "Generate authenticated Cairo CUDA eval sources in Zig's build cache",
    );
    step.dependOn(&generated.run.step);
    generated.canonical_eval.?.addStepDependencies(step);
    generated.canonical_witness.?.addStepDependencies(step);
    // Register local tools once in the tools product. Production construction
    // requests multiple canonical source sets when CUDA is enabled.
    const parity_root = b.createModule(.{ .root_source_file = b.path("src/tools/cairo_cuda_eval_aot/main.zig"), .target = target, .optimize = .ReleaseFast });
    parity_root.addImport("stwo", stwo);
    const parity_executable = b.addExecutable(.{ .name = "cairo-cuda-parametric-parity-aot", .root_module = parity_root });
    const parity = b.addRunArtifact(parity_executable);
    parity.addArg("--parametric-parity");
    _ = parity.addOutputDirectoryArg("cairo-cuda-parametric-parity");
    b.step("cuda-cairo-local-parity", "Generate the CUDA scalar and register-rewrite differential").dependOn(&parity.step);
}

pub fn addCanonicalCairoEval(b: *std.Build, target: std.Build.ResolvedTarget, stwo: *std.Build.Module) GeneratedSet {
    const root = b.createModule(.{ .root_source_file = b.path("src/tools/cairo_cuda_eval_aot/main.zig"), .target = target, .optimize = .ReleaseFast });
    root.addImport("stwo", stwo);
    const executable = b.addExecutable(.{ .name = "cairo-cuda-canonical-eval-aot", .root_module = root });
    const run = b.addRunArtifact(executable);
    run.addArg("--canonical");
    run.addFileArg(b.path("vectors/cairo/official/air_template_library_v1.json"));
    addDirectoryInputs(b, run, "vectors/cairo/official");
    return .{ .directory = run.addOutputDirectoryArg("cairo-canonical-cuda-eval"), .run = run };
}

pub fn addNativeToolStep(b: *std.Build) void {
    const generated = addNative(b);
    b.step(
        "cuda-native-aot",
        "Generate authenticated Native CUDA AOT sources in Zig's build cache",
    ).dependOn(&generated.run.step);
    const canonical = addCanonicalWitness(b);
    b.step("cuda-cairo-witness-aot", "Generate all current upstream Cairo CUDA witness programs").dependOn(&canonical.run.step);
    const generator = witnessGenerator(b, "cairo-cuda-canonical-witness-aot");
    const parity = b.addRunArtifact(generator);
    parity.addArg("--row-parity");
    _ = parity.addOutputDirectoryArg("cairo-cuda-row-parity");
    b.step("cuda-cairo-witness-parity", "Generate the long deduction-chain CUDA differential").dependOn(&parity.step);
}

pub fn addCanonicalWitness(b: *std.Build) GeneratedSet {
    const generator = witnessGenerator(b, "cairo-cuda-canonical-witness-aot");
    const run = b.addRunArtifact(generator);
    run.addArg("--canonical");
    run.addFileArg(b.path("vectors/cairo/official/witness_programs_v1.bin"));
    run.addDirectoryArg(b.path("src/backends/cuda/authority/active"));
    addDirectoryInputs(b, run, "src/backends/cuda/authority/active");
    run.addFileArg(b.path("vectors/cairo/official/witness_programs_v1.provenance.json"));
    return .{ .directory = run.addOutputDirectoryArg("cairo-canonical-cuda-witness"), .run = run };
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
