const std = @import("std");

/// The kernel source: `backends/cuda/native/pow/candidate.cuh` plus the
/// circuit lane's M31 output policy and host-supplied prefix.
const kernel_source = "native/circuit_grind.cu";

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const filter = b.option([]const u8, "test-filter", "Run only matching circuit CUDA tests");
    const filters: []const []const u8 = if (filter) |value| &.{value} else &.{};
    // GPU host (all three, or none): the nvcc that builds the kernel, the
    // directory holding libcudart, and the SM targets.
    const nvcc = b.option([]const u8, "cuda-nvcc", "nvcc for the circuit grind kernel (GPU hosts)");
    const cuda_library_dir = b.option([]const u8, "cuda-library-dir", "Directory holding libcudart (GPU hosts)");
    const cuda_arch = b.option([]const u8, "cuda-arch", "Comma-separated numeric SM targets for nvcc (default 90: H100)") orelse "90";
    // Any host: an NVPTX-capable Clang for the compile check (Apple Clang
    // has no NVPTX target; Homebrew LLVM does).
    const cuda_clang = b.option([]const u8, "cuda-clang", "NVPTX-capable Clang for circuit-cuda-compile-check");
    const dependency_options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const prover = b.dependency("stwo_prover_engine", dependency_options).module("stwo_prover_engine");
    const prover_api = b.dependency("stwo_prover_api", dependency_options).module("stwo_prover_api");
    const circuit_dependency = b.dependency("stwo_circuit_frontend", dependency_options);
    const circuit = circuit_dependency.module("stwo_circuit_frontend");
    const circuit_testing = circuit_dependency.module("circuit_testing");
    const cairo = b.dependency("stwo_cairo_frontend", dependency_options).module("stwo_cairo_frontend");
    const cairo_cpu = b.dependency("stwo_cairo_cpu_integration", dependency_options).module("stwo_cairo_cpu_integration");
    const cairo_cuda = b.dependency("stwo_cairo_cuda_integration", dependency_options).module("stwo_cairo_cuda_integration");
    const cuda_backend = cairo_cuda.import_table.get("stwo_cuda_backend") orelse
        @panic("Cairo CUDA integration is missing stwo_cuda_backend");
    const native_cuda = cairo_cuda.import_table.get("stwo_native_cuda_integration") orelse
        @panic("Cairo CUDA integration is missing stwo_native_cuda_integration");
    const cpu_dependency = b.dependency("stwo_circuit_cpu_integration", dependency_options);
    const circuit_cpu = cpu_dependency.module("stwo_circuit_cpu_integration");
    // The CPU integration's own module instances (one module per file per
    // compilation): the wire package and the CPU backend it proves on.
    const wire = circuit_cpu.import_table.get("stwo_circuit_recursion_wire") orelse
        @panic("circuit CPU integration is missing stwo_circuit_recursion_wire");
    const cpu_backend = circuit_cpu.import_table.get("stwo_cpu_backend") orelse
        @panic("circuit CPU integration is missing stwo_cpu_backend");

    const integration = b.addModule("stwo_circuit_cuda_integration", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration.addImport("stwo_core", core);
    integration.addImport("stwo_prover_api", prover_api);
    integration.addImport("stwo_prover_engine", prover);
    integration.addImport("stwo_cpu_backend", cpu_backend);
    integration.addImport("stwo_circuit_frontend", circuit);
    integration.addImport("stwo_circuit_cpu_integration", circuit_cpu);
    integration.addImport("stwo_cairo_cuda_integration", cairo_cuda);
    integration.addImport("stwo_cuda_backend", cuda_backend);
    integration.addImport("stwo_native_cuda_integration", native_cuda);

    // Fixture tests read `vectors/circuit` from the repository root.
    const repository_root: std.Build.LazyPath = .{ .cwd_relative = b.pathFromRoot("../../..") };

    const test_step = b.step("test", "Test the stwo_circuit_cuda_integration package on any host (the kernel's search emulated on the CPU)");
    const aot_step = b.step("circuit-cuda-air-aot", "Generate authenticated circuit AIR CUDA kernels in the build cache");
    const aot_root = b.createModule(.{
        .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../tools/circuit_cuda_air_aot/main.zig") },
        .target = b.graph.host,
        .optimize = .ReleaseFast,
    });
    aot_root.addImport("stwo_circuit_cuda_integration", integration);
    const aot_exe = b.addExecutable(.{ .name = "circuit-cuda-air-aot", .root_module = aot_root });
    const aot_run = b.addRunArtifact(aot_exe);
    aot_run.addFileArg(.{ .cwd_relative = b.pathFromRoot("../../../vectors/circuit/official/circuit_air.air_programs_v1.bin") });
    const aot_directory = aot_run.addOutputDirectoryArg("circuit-cuda-air-aot");
    aot_step.dependOn(&aot_run.step);
    const aot_ptx_step = b.step("circuit-cuda-air-ptx-check", "Authenticate and lower all eleven circuit AIR kernels to sm_80 and sm_90 PTX");
    if (cuda_clang) |clang| {
        const ptx_check = b.addSystemCommand(&.{ "python3", b.pathFromRoot("../../tools/circuit_cuda_air_aot/check_ptx.py"), "--clang", clang, "--generated" });
        ptx_check.addDirectoryArg(aot_directory);
        ptx_check.addArg("--stub");
        ptx_check.addDirectoryArg(b.path("native/compile_check/include"));
        aot_ptx_step.dependOn(&ptx_check.step);
    } else {
        aot_ptx_step.dependOn(&b.addFail("circuit-cuda-air-ptx-check requires -Dcuda-clang=<NVPTX-capable clang>").step);
    }
    const r7_emulated_step = b.step(
        "circuit-parity-r7-cuda-emulated",
        "Rung R7 with both grinds on the CUDA kernel's host emulation, byte for byte against the CPU oracle's fixture (any host)",
    );
    const compile_check_step = b.step(
        "circuit-cuda-compile-check",
        "Type-check the circuit grind kernel's host code and lower its kernels to PTX (sm_80, sm_90) without a CUDA toolkit (-Dcuda-clang)",
    );
    const device_test_step = b.step("test-cuda-device", "The circuit grind kernel on the device against the CPU grind and Rust known answers (GPU host)");
    const r7_step = b.step(
        "circuit-parity-r7-cuda",
        "Rung R7 with both grinds on the CUDA device, byte for byte against the CPU oracle's fixture (GPU host)",
    );
    const r9_step = b.step(
        "circuit-parity-r9-cuda",
        "Rung R9 with every reduction's grinds on the CUDA device, byte for byte against upstream (GPU host, large)",
    );
    const bench_step = b.step("circuit-cuda-grind-bench", "Time the circuit grinds on the CPU and on the CUDA device (GPU host)");
    const hybrid_step = b.step("circuit-recursion-cuda-hybrid", "Install the PIE-to-root CLI with CUDA circuit grinds and CPU Cairo/PCS (GPU host)");

    const app = b.createModule(.{
        .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../products/circuit_recursion_cpu/app.zig") },
        .target = target,
        .optimize = optimize,
    });
    app.addImport("stwo_cairo_frontend", cairo);
    app.addImport("stwo_cairo_cpu_integration", cairo_cpu);
    app.addImport("stwo_circuit_frontend", circuit);
    app.addImport("stwo_circuit_cpu_integration", circuit_cpu);
    app.addImport("stwo_circuit_recursion_wire", wire);
    app.addImport("stwo_prover_engine", prover);
    app.addAnonymousImport("circuit_air_projection", .{
        .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../../vectors/circuit/official/compiled_air_constraints_v1.bin") },
    });
    app.addAnonymousImport("circuit_air_programs", .{
        .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../../vectors/circuit/official/circuit_air.air_programs_v1.bin") },
    });
    const cairo_cuda_backend = cuda_backend;
    const cairo_facade = b.createModule(.{
        .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../cairo_cuda.zig") },
        .target = target,
        .optimize = optimize,
    });
    cairo_facade.addImport("stwo_cuda_backend", cairo_cuda_backend);
    cairo_facade.addImport("stwo_cairo_frontend", cairo);
    cairo_facade.addImport("stwo_cairo_cuda_integration", cairo_cuda);
    const cairo_app = b.createModule(.{
        .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../products/cairo_cuda/app.zig") },
        .target = target,
        .optimize = optimize,
    });
    cairo_app.addImport("stwo_cairo_cuda", cairo_facade);
    cairo_app.addImport("stwo_circuit_recursion_wire", wire);
    const architectures = b.addOptions();
    architectures.addOption([]const u8, "architectures", cuda_arch);
    cairo_app.addImport("cuda_architectures", architectures.createModule());
    const handoff_root = b.createModule(.{
        .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../products/circuit_recursion_cuda/verified_sink.zig") },
        .target = target,
        .optimize = optimize,
    });
    handoff_root.addImport("cairo_cuda_app", cairo_app);
    handoff_root.addImport("circuit_recursion_app", app);
    handoff_root.addImport("stwo_circuit_cpu_integration", circuit_cpu);
    handoff_root.addImport("stwo_cairo_cuda_integration", cairo_cuda);
    handoff_root.addImport("stwo_cairo_frontend", cairo);
    const handoff_test = b.addTest(.{ .root_module = handoff_root });
    const run_handoff_test = b.addRunArtifact(handoff_test);
    run_handoff_test.setCwd(repository_root);
    b.step("circuit-cuda-leaf-handoff-check", "Compile the verified CUDA Cairo proof-to-recursion leaf handoff without a GPU").dependOn(&run_handoff_test.step);
    test_step.dependOn(&run_handoff_test.step);
    const product_root = b.createModule(.{
        .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../products/circuit_recursion_cuda/main.zig") },
        .target = target,
        .optimize = optimize,
    });
    product_root.addImport("circuit_recursion_app", app);
    product_root.addImport("stwo_cairo_cpu_integration", cairo_cpu);
    product_root.addImport("stwo_circuit_cuda_integration", integration);

    // Host emulation: the kernel's own search code as host C++.
    // The unit tests get their own instance of `mod.zig`, so the emulation
    // object never rides along with the public module.
    const unit_root = b.createModule(.{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    for (integration.import_table.keys(), integration.import_table.values()) |name, module| unit_root.addImport(name, module);
    const unit_tests = b.addTest(.{ .root_module = unit_root, .filters = filters });
    addEmulation(b, unit_tests);
    unit_tests.root_module.addCSourceFile(.{
        .file = b.path("tests/resident_link_stubs.c"),
        .flags = &.{ "-std=c11", "-Wno-strict-prototypes" },
    });
    const run_unit = b.addRunArtifact(unit_tests);
    run_unit.setCwd(repository_root);
    test_step.dependOn(&run_unit.step);

    const r7_imports = R7Imports{
        .core = core,
        .prover = prover,
        .circuit = circuit,
        .cairo = cairo,
        .circuit_cpu = circuit_cpu,
        .wire = wire,
        .circuit_testing = circuit_testing,
    };
    const emulated_provers = proversModule(b, "tests/emulated_provers.zig", integration, target, optimize);
    const r7_emulated = b.addTest(.{
        .root_module = r7Module(b, cpu_dependency, r7_imports, emulated_provers, "tests/r7_prove_small_test.zig", target, optimize),
        .filters = filters,
    });
    // The emulation object belongs to the rung binary, not to the module.
    addEmulation(b, r7_emulated);
    const run_r7_emulated = b.addRunArtifact(r7_emulated);
    run_r7_emulated.setCwd(repository_root);
    r7_emulated_step.dependOn(&run_r7_emulated.step);

    // Compile check (no toolkit, no device).
    if (cuda_clang) |clang| {
        inline for (.{ "sm_80", "sm_90" }) |arch| {
            const ptx = b.addSystemCommand(&.{
                clang,                "-x",                       "cuda",
                "--cuda-device-only", "--cuda-gpu-arch=" ++ arch, "-Xclang",
                "-target-feature",    "-Xclang",                  "+ptx78",
                "-nocudainc",         "-nocudalib",               "-std=c++17",
                "-O3",                "-Wall",                    "-Wextra",
                "-Werror",            "-S",
            });
            ptx.addPrefixedDirectoryArg("-I", b.path("native/compile_check/include"));
            ptx.addFileArg(b.path(kernel_source));
            ptx.addArg("-o");
            _ = ptx.addOutputFileArg("circuit_grind_" ++ arch ++ ".ptx");
            compile_check_step.dependOn(&ptx.step);
        }
        const host = b.addSystemCommand(&.{
            clang,        "-x",         "cuda",          "--cuda-host-only", "--cuda-gpu-arch=sm_90",
            "-nocudainc", "-nocudalib", "-std=c++17",    "-O2",              "-Wall",
            "-Wextra",    "-Werror",    "-fsyntax-only",
        });
        host.addPrefixedDirectoryArg("-I", b.path("native/compile_check/include"));
        host.addFileArg(b.path(kernel_source));
        compile_check_step.dependOn(&host.step);
    } else {
        compile_check_step.dependOn(&b.addFail("circuit-cuda-compile-check requires -Dcuda-clang=<NVPTX-capable clang>, e.g. /opt/homebrew/opt/llvm/bin/clang").step);
    }

    // The device artifacts link either the kernel (GPU host) or the
    // no-device stand-in (any host: compile check and fail-closed tests).
    const stub = DeviceLink{ .stub = b.path("native/compile_check/no_device.c") };
    const fail_closed = b.addTest(.{
        .root_module = testModule(b, "tests/fail_closed_test.zig", integration, core, prover, target, optimize),
        .filters = filters,
    });
    stub.link(fail_closed);
    test_step.dependOn(&b.addRunArtifact(fail_closed).step);

    const device_artifacts = DeviceArtifacts{
        .b = b,
        .integration = integration,
        .core = core,
        .prover = prover,
        .cpu_dependency = cpu_dependency,
        .r7_imports = r7_imports,
        .target = target,
        .optimize = optimize,
        .filters = filters,
    };
    const stubbed = device_artifacts.add(stub);
    for (stubbed.all()) |compile| compile_check_step.dependOn(&compile.step);
    // Link inputs are attached to the root module in Zig 0.15. A separate
    // module is required here: sharing it would put both the compile-check
    // stub and the real NVCC object in the GPU binary.
    const stubbed_product_root = b.createModule(.{
        .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../products/circuit_recursion_cuda/main.zig") },
        .target = target,
        .optimize = optimize,
    });
    stubbed_product_root.addImport("circuit_recursion_app", app);
    stubbed_product_root.addImport("stwo_cairo_cpu_integration", cairo_cpu);
    stubbed_product_root.addImport("stwo_circuit_cuda_integration", integration);
    const stubbed_product = b.addExecutable(.{ .name = "stwo-circuit-recursion-cuda-hybrid", .root_module = stubbed_product_root });
    stub.link(stubbed_product);
    compile_check_step.dependOn(&stubbed_product.step);

    // GPU host: nvcc builds the kernel; the artifacts link libcudart.
    const device_steps = [_]*std.Build.Step{ device_test_step, r7_step, r9_step, bench_step, hybrid_step };
    if (nvcc == null or cuda_library_dir == null) {
        const missing = b.addFail("the CUDA device steps require -Dcuda-nvcc and -Dcuda-library-dir (a Linux host with an NVIDIA GPU; see README.md)");
        for (device_steps) |step| step.dependOn(&missing.step);
        return;
    }
    const device = device_artifacts.add(.{ .cuda = .{
        .object = nvccObject(b, nvcc.?, cuda_arch),
        .library_dir = cuda_library_dir.?,
    } });
    const product = b.addExecutable(.{ .name = "stwo-circuit-recursion-cuda-hybrid", .root_module = product_root });
    (DeviceLink{ .cuda = .{ .object = nvccObject(b, nvcc.?, cuda_arch), .library_dir = cuda_library_dir.? } }).link(product);
    hybrid_step.dependOn(&b.addInstallArtifact(product, .{}).step);
    inline for (.{
        .{ device.device_tests, device_test_step },
        .{ device.r7_tests, r7_step },
        .{ device.r9_tests, r9_step },
    }) |pair| {
        const run = b.addRunArtifact(pair[0]);
        run.setCwd(repository_root);
        pair[1].dependOn(&run.step);
    }
    const run_bench = b.addRunArtifact(device.bench);
    if (b.args) |args| run_bench.addArgs(args);
    bench_step.dependOn(&run_bench.step);
}

const DeviceArtifacts = struct {
    b: *std.Build,
    integration: *std.Build.Module,
    core: *std.Build.Module,
    prover: *std.Build.Module,
    cpu_dependency: *std.Build.Dependency,
    r7_imports: R7Imports,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    filters: []const []const u8,

    const Set = struct {
        device_tests: *std.Build.Step.Compile,
        r7_tests: *std.Build.Step.Compile,
        r9_tests: *std.Build.Step.Compile,
        bench: *std.Build.Step.Compile,

        fn all(self: Set) [4]*std.Build.Step.Compile {
            return .{ self.device_tests, self.r7_tests, self.r9_tests, self.bench };
        }
    };

    fn add(self: DeviceArtifacts, link: DeviceLink) Set {
        const b = self.b;
        const device_tests = b.addTest(.{
            .root_module = testModule(b, "tests/device_grind_test.zig", self.integration, self.core, self.prover, self.target, self.optimize),
            .filters = self.filters,
        });
        // R7 and R9 (large: every reduction is a 2^23-row multiverifier):
        // the CPU integration's rung tests, proving with the CUDA provers.
        const cuda_provers = proversModule(b, "tests/cuda_provers.zig", self.integration, self.target, self.optimize);
        const r7_tests = b.addTest(.{
            .root_module = r7Module(b, self.cpu_dependency, self.r7_imports, cuda_provers, "tests/r7_prove_small_test.zig", self.target, self.optimize),
            .filters = self.filters,
        });
        const r9_tests = b.addTest(.{
            .root_module = r7Module(b, self.cpu_dependency, self.r7_imports, cuda_provers, "tests/r9_fold_tree_test.zig", self.target, self.optimize),
            .filters = self.filters,
        });
        const bench = b.addExecutable(.{
            .name = "circuit-cuda-grind-bench",
            .root_module = testModule(b, "tests/grind_bench.zig", self.integration, self.core, self.prover, self.target, .ReleaseFast),
        });
        const set = Set{ .device_tests = device_tests, .r7_tests = r7_tests, .r9_tests = r9_tests, .bench = bench };
        for (set.all()) |compile| link.link(compile);
        return set;
    }
};

fn addEmulation(b: *std.Build, compile: *std.Build.Step.Compile) void {
    compile.root_module.addIncludePath(b.path("native/emulation/include"));
    compile.root_module.addCSourceFile(.{
        .file = b.path(kernel_source),
        .flags = &.{ "-std=c++17", "-O3", "-DSTWO_CIRCUIT_GRIND_HOST_EMULATION", "-Wall", "-Wextra", "-Werror" },
        .language = .cpp,
    });
    compile.linkLibCpp();
}

fn nvccObject(b: *std.Build, nvcc: []const u8, arches: []const u8) std.Build.LazyPath {
    const command = b.addSystemCommand(&.{ nvcc, "-c", "-O3", "-std=c++17", "-Xcompiler", "-fPIC", "--expt-relaxed-constexpr" });
    var iterator = std.mem.tokenizeScalar(u8, arches, ',');
    while (iterator.next()) |arch| {
        command.addArg("-gencode");
        command.addArg(b.fmt("arch=compute_{s},code=[sm_{s},compute_{s}]", .{ arch, arch, arch }));
    }
    command.addFileArg(b.path(kernel_source));
    command.addArg("-o");
    return command.addOutputFileArg("circuit_grind.o");
}

const DeviceLink = union(enum) {
    /// The kernel built by nvcc, and the directory holding libcudart.
    cuda: struct { object: std.Build.LazyPath, library_dir: []const u8 },
    /// `native/compile_check/no_device.c`.
    stub: std.Build.LazyPath,

    fn link(self: DeviceLink, compile: *std.Build.Step.Compile) void {
        switch (self) {
            .cuda => |cuda| {
                compile.root_module.addObjectFile(cuda.object);
                compile.root_module.addLibraryPath(.{ .cwd_relative = cuda.library_dir });
                compile.root_module.addRPath(.{ .cwd_relative = cuda.library_dir });
                compile.linkSystemLibrary("cudart");
                compile.linkLibCpp();
            },
            .stub => |source| {
                compile.root_module.addCSourceFile(.{ .file = source, .flags = &.{ "-std=c11", "-Wall", "-Wextra", "-Werror" } });
                compile.linkLibC();
            },
        }
    }
};

fn proversModule(
    b: *std.Build,
    path: []const u8,
    integration: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const module = b.createModule(.{ .root_source_file = b.path(path), .target = target, .optimize = optimize });
    module.addImport("stwo_circuit_cuda_integration", integration);
    return module;
}

fn testModule(
    b: *std.Build,
    path: []const u8,
    integration: *std.Build.Module,
    core: *std.Build.Module,
    prover: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const module = proversModule(b, path, integration, target, optimize);
    module.addImport("stwo_core", core);
    module.addImport("stwo_prover_engine", prover);
    return module;
}

const R7Imports = struct {
    core: *std.Build.Module,
    prover: *std.Build.Module,
    circuit: *std.Build.Module,
    cairo: *std.Build.Module,
    circuit_cpu: *std.Build.Module,
    wire: *std.Build.Module,
    circuit_testing: *std.Build.Module,
};

/// The CPU integration's rung test (`circuit_cpu/tests/…`), proving with
/// `provers` instead of the CPU oracle.
fn r7Module(
    b: *std.Build,
    cpu_dependency: *std.Build.Dependency,
    imports: R7Imports,
    provers: *std.Build.Module,
    path: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = cpu_dependency.path(path),
        .target = target,
        .optimize = optimize,
    });
    module.addImport("stwo_circuit_cpu_integration", imports.circuit_cpu);
    module.addImport("stwo_core", imports.core);
    module.addImport("stwo_prover_engine", imports.prover);
    module.addImport("stwo_circuit_frontend", imports.circuit);
    module.addImport("stwo_cairo_frontend", imports.cairo);
    module.addImport("stwo_circuit_recursion_wire", imports.wire);
    module.addImport("circuit_testing", imports.circuit_testing);
    module.addImport("circuit_provers_under_test", provers);
    return module;
}
