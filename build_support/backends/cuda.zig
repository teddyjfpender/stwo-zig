//! Explicit, isolated build and link ownership for the native CUDA archive.

const std = @import("std");
const cuda_aot = @import("cuda_aot.zig");

pub const source_root =
    "src/backends/cuda/authority/active";
pub const source_manifest = "src/backends/cuda/active_source_manifest.json";
pub const product_manifest = "src/backends/cuda/product_manifest.json";
pub const native_root = "src/backends/cuda/native";
pub const native_aot_root = "src/backends/cuda/aot/native";
pub const archive_name = "stwo_cuda_kernels";
const build_script = "scripts/cuda_build.py";
const build_script_root = "scripts/cuda_build_lib";

pub const AotProduct = enum {
    native,
    cairo,
    circuit,
};

pub const Toolchain = struct {
    nvcc: []const u8 = "",
    host_cxx: []const u8 = "",
    host_runtime: []const u8 = "",
    host_unwind_runtime: []const u8 = "",
    archiver: []const u8 = "",
    cuda_home: []const u8 = "",
    library_dir: []const u8 = "",
    architectures: []const u8 = "",
    jobs: u16 = 1,

    pub fn validate(self: Toolchain) !void {
        if (self.nvcc.len == 0) return error.MissingCudaCompiler;
        if (self.host_cxx.len == 0) return error.MissingCudaHostCompiler;
        if (self.archiver.len == 0) return error.MissingCudaArchiver;
        if (self.cuda_home.len == 0) return error.MissingCudaToolkitDirectory;
        if (self.library_dir.len == 0) return error.MissingCudaLibraryDirectory;
        if (self.architectures.len == 0) return error.MissingCudaArchitecture;
        if (self.jobs == 0) return error.InvalidCudaBuildJobs;
    }

    pub fn validateRuntime(self: Toolchain) !void {
        try self.validate();
        if (self.host_runtime.len == 0) return error.MissingCudaHostRuntime;
        if (!std.fs.path.isAbsolute(self.host_runtime))
            return error.InvalidCudaHostRuntime;
        if (self.host_unwind_runtime.len == 0)
            return error.MissingCudaHostUnwindRuntime;
        if (!std.fs.path.isAbsolute(self.host_unwind_runtime))
            return error.InvalidCudaHostUnwindRuntime;
    }
};

pub const Archive = struct {
    directory: std.Build.LazyPath,
    build: *std.Build.Step.Run,
};

pub fn addArchive(
    b: *std.Build,
    toolchain: Toolchain,
    product: AotProduct,
    cairo_eval_root: ?cuda_aot.GeneratedSet,
) Archive {
    require(toolchain);
    if (product == .circuit) @panic("Circuit CUDA archive requires addCircuitArchive with both AOT source sets");
    const command = buildCommand(
        b,
        toolchain,
        false,
        product,
        cairo_eval_root,
        null,
    );
    return .{
        .directory = command.addOutputDirectoryArg("stwo-native-cuda-runtime"),
        .build = command,
    };
}

pub fn addCircuitArchive(b: *std.Build, toolchain: Toolchain, cairo_generated: cuda_aot.GeneratedSet, generated_circuit_eval: std.Build.LazyPath) Archive {
    require(toolchain);
    const command = buildCommand(b, toolchain, false, .circuit, cairo_generated, generated_circuit_eval);
    return .{
        .directory = command.addOutputDirectoryArg("stwo-circuit-cuda-runtime"),
        .build = command,
    };
}

pub fn addPlan(b: *std.Build, toolchain: Toolchain) *std.Build.Step.Run {
    require(toolchain);
    const command = buildCommand(
        b,
        toolchain,
        true,
        .native,
        null,
        null,
    );
    _ = command.addOutputDirectoryArg("stwo-native-cuda-plan");
    return command;
}

/// Exercise the exact Cairo archive selection and generator arguments locally.
/// Plan-only mode deliberately does not discover or execute NVIDIA tools.
pub fn addCairoPlan(b: *std.Build, generated: cuda_aot.GeneratedSet) *std.Build.Step.Run {
    const command = buildCommand(b, .{
        .nvcc = "/cuda-plan-only/bin/nvcc",
        .host_cxx = "/cuda-plan-only/bin/c++",
        .archiver = "/cuda-plan-only/bin/ar",
        .cuda_home = "/cuda-plan-only",
        .library_dir = "/cuda-plan-only/lib64",
        .architectures = "sm_90",
    }, true, .cairo, generated, null);
    _ = command.addOutputDirectoryArg("cairo-cuda-local-plan");
    _ = command.captureStdOut();
    return command;
}

pub fn addCircuitPlan(b: *std.Build, cairo_generated: cuda_aot.GeneratedSet, generated: std.Build.LazyPath) *std.Build.Step.Run {
    const command = buildCommand(b, .{
        .nvcc = "/cuda-plan-only/bin/nvcc",
        .host_cxx = "/cuda-plan-only/bin/c++",
        .archiver = "/cuda-plan-only/bin/ar",
        .cuda_home = "/cuda-plan-only",
        .library_dir = "/cuda-plan-only/lib64",
        .architectures = "sm_90",
    }, true, .circuit, cairo_generated, generated);
    _ = command.addOutputDirectoryArg("circuit-cuda-local-plan");
    _ = command.captureStdOut();
    return command;
}

pub fn addSourceClosureGate(b: *std.Build) *std.Build.Step.Run {
    const command = b.addSystemCommand(&.{
        "python3",
        "scripts/cuda_source_closure.py",
    });
    const product = b.addSystemCommand(&.{
        "python3",
        "scripts/cuda_product_closure.py",
    });
    product.step.dependOn(&command.step);
    return product;
}

pub fn linkRuntime(
    artifact: *std.Build.Step.Compile,
    toolchain: Toolchain,
    archive: Archive,
) void {
    requireRuntime(toolchain);
    artifact.step.dependOn(&archive.build.step);
    artifact.addLibraryPath(archive.directory);
    artifact.addLibraryPath(.{ .cwd_relative = toolchain.library_dir });
    artifact.linkSystemLibrary(archive_name);
    artifact.linkSystemLibrary("cudart");
    artifact.linkSystemLibrary("cuda");
    artifact.addObjectFile(.{ .cwd_relative = toolchain.host_runtime });
    artifact.addObjectFile(.{ .cwd_relative = toolchain.host_unwind_runtime });
    artifact.linkLibC();
}

fn buildCommand(
    b: *std.Build,
    toolchain: Toolchain,
    plan_only: bool,
    product: AotProduct,
    cairo_eval_root: ?cuda_aot.GeneratedSet,
    circuit_eval_root: ?std.Build.LazyPath,
) *std.Build.Step.Run {
    const native_aot = cuda_aot.addNative(b);
    const command = b.addSystemCommand(&.{"python3"});
    command.addFileArg(b.path(build_script));
    addDirectoryInputs(b, command, build_script_root);
    if (b.graph.env_map.get("STWO_CUDA_AOT_CUBIN_IMPORT_ROOT")) |import_root| {
        const absolute_root = b.pathFromRoot(import_root);
        command.addArg("--aot-cubin-import-root");
        command.addDirectoryArg(.{ .cwd_relative = absolute_root });
        addImportedCubinInputs(b, command, absolute_root);
    }
    command.addArg("--source-root");
    command.addDirectoryArg(b.path(source_root));
    addDirectoryInputs(b, command, source_root);
    command.addArg("--source-manifest");
    command.addFileArg(b.path(source_manifest));
    command.addArg("--product-manifest");
    command.addFileArg(b.path(product_manifest));
    command.addArg("--native-root");
    command.addDirectoryArg(b.path(native_root));
    addDirectoryInputs(b, command, native_root);
    command.addArg("--native-aot-root");
    command.addDirectoryArg(b.path(native_aot_root));
    addDirectoryInputs(b, command, native_aot_root);
    command.addArgs(&.{ "--aot-set", "." });
    command.addArgs(&.{ "--frontend", @tagName(product) });
    command.addArgs(&.{ "--aot-set-root", "." });
    command.addDirectoryArg(native_aot.directory);
    if (product == .cairo or product == .circuit) {
        const generated = cairo_eval_root orelse @panic(
            "Cairo CUDA archive requires generated eval AOT sources",
        );
        command.addArgs(&.{ "--aot-set", "cairo_canonical_eval" });
        command.addArgs(&.{ "--aot-set-root", "cairo_canonical_eval" });
        command.addDirectoryArg(generated.canonical_eval orelse @panic("Current Cairo AIR product is absent"));
        command.addArgs(&.{ "--aot-set", "cairo_witness", "--aot-set-root", "cairo_witness" });
        command.addDirectoryArg(generated.canonical_witness orelse @panic("Current Cairo witness product is absent"));
    }
    if (product == .circuit) {
        const generated = circuit_eval_root orelse @panic("Circuit CUDA archive requires generated circuit AIR AOT sources");
        command.addArgs(&.{ "--aot-set", "circuit_eval", "--aot-set-root", "circuit_eval" });
        command.addDirectoryArg(generated);
    } else if (product == .native and (cairo_eval_root != null or circuit_eval_root != null)) {
        @panic("Native CUDA archive cannot consume Cairo AOT sources");
    }
    command.addArgs(&.{ "--nvcc", toolchain.nvcc });
    command.addArgs(&.{ "--host-cxx", toolchain.host_cxx });
    command.addArgs(&.{ "--ar", toolchain.archiver });
    command.addArgs(&.{ "--cuda-home", toolchain.cuda_home });
    command.addArgs(&.{ "--cuda-library-dir", toolchain.library_dir });
    command.addArgs(&.{ "--arch", toolchain.architectures });
    command.addArgs(&.{ "--jobs", b.fmt("{d}", .{toolchain.jobs}) });
    if (plan_only) command.addArg("--plan-only");
    command.addArg("--out-dir");
    return command;
}

fn addDirectoryInputs(
    b: *std.Build,
    command: *std.Build.Step.Run,
    relative_root: []const u8,
) void {
    var directory = b.build_root.handle.openDir(
        relative_root,
        .{ .iterate = true },
    ) catch |err| std.debug.panic(
        "cannot open CUDA build input directory {s}: {s}",
        .{ relative_root, @errorName(err) },
    );
    defer directory.close();

    var walker = directory.walk(b.allocator) catch @panic("OOM");
    defer walker.deinit();
    var files: std.ArrayList([]const u8) = .empty;
    defer files.deinit(b.allocator);

    while (walker.next() catch |err| std.debug.panic(
        "cannot enumerate CUDA build input directory {s}: {s}",
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
        command.addFileInput(b.path(b.pathJoin(&.{
            relative_root,
            relative_path,
        })));
    }
}

/// The outer Zig cache must bind imported artifacts as well as the Python
/// archive identity. An inherited environment variable alone is not an input.
fn addImportedCubinInputs(b: *std.Build, command: *std.Build.Step.Run, root: []const u8) void {
    const manifest = b.pathJoin(&.{ root, "manifest.json" });
    command.addFileInput(.{ .cwd_relative = manifest });
    const bytes = std.fs.cwd().readFileAlloc(b.allocator, manifest, 8 << 20) catch |err|
        std.debug.panic("cannot read imported CUDA manifest: {s}", .{@errorName(err)});
    defer b.allocator.free(bytes);
    const parsed = std.json.parseFromSlice(std.json.Value, b.allocator, bytes, .{}) catch
        @panic("invalid imported CUDA manifest");
    defer parsed.deinit();
    if (parsed.value != .object) @panic("invalid imported CUDA manifest");
    const entries = parsed.value.object.get("entries") orelse @panic("missing imported CUDA entries");
    if (entries != .array) @panic("invalid imported CUDA entries");
    for (entries.array.items) |entry| {
        if (entry != .object) @panic("invalid imported CUDA entry");
        const file = entry.object.get("file") orelse @panic("missing imported CUDA artifact");
        if (file != .string or !std.mem.eql(u8, file.string, std.fs.path.basename(file.string)) or
            std.mem.eql(u8, file.string, ".") or std.mem.eql(u8, file.string, ".."))
            @panic("invalid imported CUDA artifact path");
        command.addFileInput(.{ .cwd_relative = b.pathJoin(&.{ root, file.string }) });
    }
}

fn require(toolchain: Toolchain) void {
    toolchain.validate() catch |err| std.debug.panic(
        "invalid explicit CUDA toolchain: {s}",
        .{@errorName(err)},
    );
}

fn requireRuntime(toolchain: Toolchain) void {
    toolchain.validateRuntime() catch |err| std.debug.panic(
        "invalid explicit CUDA runtime toolchain: {s}",
        .{@errorName(err)},
    );
}

test "CUDA toolchain has no implicit compiler, path, or architecture" {
    try std.testing.expectError(error.MissingCudaCompiler, (Toolchain{}).validate());
    try std.testing.expectError(error.MissingCudaHostCompiler, (Toolchain{
        .nvcc = "/cuda/bin/nvcc",
    }).validate());
    try std.testing.expectError(error.MissingCudaArchiver, (Toolchain{
        .nvcc = "/cuda/bin/nvcc",
        .host_cxx = "/usr/bin/c++",
    }).validate());
    try std.testing.expectError(error.MissingCudaToolkitDirectory, (Toolchain{
        .nvcc = "/cuda/bin/nvcc",
        .host_cxx = "/usr/bin/c++",
        .archiver = "/usr/bin/ar",
    }).validate());
    try std.testing.expectError(error.MissingCudaLibraryDirectory, (Toolchain{
        .nvcc = "/cuda/bin/nvcc",
        .host_cxx = "/usr/bin/c++",
        .archiver = "/usr/bin/ar",
        .cuda_home = "/cuda",
    }).validate());
    try std.testing.expectError(error.MissingCudaArchitecture, (Toolchain{
        .nvcc = "/cuda/bin/nvcc",
        .host_cxx = "/usr/bin/c++",
        .archiver = "/usr/bin/ar",
        .cuda_home = "/cuda",
        .library_dir = "/cuda/lib64",
    }).validate());
    try (Toolchain{
        .nvcc = "/cuda/bin/nvcc",
        .host_cxx = "/usr/bin/c++",
        .archiver = "/usr/bin/ar",
        .cuda_home = "/cuda",
        .library_dir = "/cuda/lib64",
        .architectures = "sm_86,sm_90",
        .jobs = 8,
    }).validate();
    try std.testing.expectError(
        error.MissingCudaHostRuntime,
        (Toolchain{
            .nvcc = "/cuda/bin/nvcc",
            .host_cxx = "/usr/bin/c++",
            .archiver = "/usr/bin/ar",
            .cuda_home = "/cuda",
            .library_dir = "/cuda/lib64",
            .architectures = "sm_89",
        }).validateRuntime(),
    );
    try std.testing.expectError(
        error.MissingCudaHostUnwindRuntime,
        (Toolchain{
            .nvcc = "/cuda/bin/nvcc",
            .host_cxx = "/usr/bin/c++",
            .host_runtime = "/usr/lib/libstdc++.so.6",
            .archiver = "/usr/bin/ar",
            .cuda_home = "/cuda",
            .library_dir = "/cuda/lib64",
            .architectures = "sm_89",
        }).validateRuntime(),
    );
    try (Toolchain{
        .nvcc = "/cuda/bin/nvcc",
        .host_cxx = "/usr/bin/c++",
        .host_runtime = "/usr/lib/libstdc++.so.6",
        .host_unwind_runtime = "/usr/lib/libgcc_s.so.1",
        .archiver = "/usr/bin/ar",
        .cuda_home = "/cuda",
        .library_dir = "/cuda/lib64",
        .architectures = "sm_89",
    }).validateRuntime();
}
