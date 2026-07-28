//! Host-independent source/build-plan gates and explicit CUDA archive build.

const std = @import("std");
const cuda = @import("cuda.zig");
const construction_observer = @import("../graph/construction_observer.zig");
const graph = @import("../graph/modules.zig");
const integration_graph = @import("../graph/integrations.zig");

pub const Options = struct {
    nvcc: ?[]const u8,
    host_cxx: ?[]const u8,
    host_runtime: ?[]const u8,
    host_unwind_runtime: ?[]const u8,
    archiver: ?[]const u8,
    cuda_home: ?[]const u8,
    library_dir: ?[]const u8,
    architectures: ?[]const u8,
    jobs: u16,

    pub fn read(b: *std.Build) Options {
        return .{
            .nvcc = b.option([]const u8, "cuda-nvcc", "Explicit nvcc executable"),
            .host_cxx = b.option([]const u8, "cuda-host-cxx", "Explicit nvcc host C++ compiler"),
            .host_runtime = b.option([]const u8, "cuda-host-runtime", "Absolute GNU C++ runtime shared-library path"),
            .host_unwind_runtime = b.option([]const u8, "cuda-host-unwind-runtime", "Absolute GNU C++ unwind runtime shared-library path"),
            .archiver = b.option([]const u8, "cuda-ar", "Explicit static archiver"),
            .cuda_home = b.option([]const u8, "cuda-home", "Explicit CUDA toolkit root"),
            .library_dir = b.option([]const u8, "cuda-library-dir", "Explicit CUDA library directory"),
            .architectures = b.option([]const u8, "cuda-arch", "Comma-separated numeric CUDA SM targets"),
            .jobs = b.option(u16, "cuda-build-jobs", "Maximum parallel nvcc processes") orelse 8,
        };
    }

    pub fn complete(self: Options) bool {
        return self.nvcc != null and
            self.host_cxx != null and
            self.archiver != null and
            self.cuda_home != null and
            self.library_dir != null and
            self.architectures != null;
    }

    pub fn runtimeComplete(self: Options) bool {
        return self.complete() and
            self.host_runtime != null and
            self.host_unwind_runtime != null;
    }

    pub fn toolchain(self: Options) cuda.Toolchain {
        if (!self.complete()) @panic(
            "cuda-native-archive requires -Dcuda-nvcc, -Dcuda-host-cxx, " ++
                "-Dcuda-ar, -Dcuda-home, -Dcuda-library-dir, and -Dcuda-arch",
        );
        return .{
            .nvcc = self.nvcc.?,
            .host_cxx = self.host_cxx.?,
            .host_runtime = self.host_runtime orelse "",
            .host_unwind_runtime = self.host_unwind_runtime orelse "",
            .archiver = self.archiver.?,
            .cuda_home = self.cuda_home.?,
            .library_dir = self.library_dir.?,
            .architectures = self.architectures.?,
            .jobs = self.jobs,
        };
    }

    pub fn planningToolchain(self: Options) cuda.Toolchain {
        return .{
            .nvcc = self.nvcc orelse "/opt/cuda/bin/nvcc",
            .host_cxx = self.host_cxx orelse "/usr/bin/c++",
            .host_runtime = self.host_runtime orelse "/usr/lib/libstdc++.so.6",
            .host_unwind_runtime = self.host_unwind_runtime orelse "/usr/lib/libgcc_s.so.1",
            .archiver = self.archiver orelse "/usr/bin/ar",
            .cuda_home = self.cuda_home orelse "/opt/cuda",
            .library_dir = self.library_dir orelse "/opt/cuda/lib64",
            .architectures = self.architectures orelse "sm_90",
            .jobs = self.jobs,
        };
    }
};

pub fn addProducts(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const options = Options.read(b);
    const source = cuda.addSourceClosureGate(b);
    b.step(
        "cuda-source-closure",
        "Verify the exact pinned CUDA/C++ source authority",
    ).dependOn(&source.step);

    const plan = cuda.addPlan(b, options.planningToolchain());
    b.step(
        "cuda-build-plan",
        "Validate and print the isolated native CUDA archive build plan",
    ).dependOn(&plan.step);

    const tests = b.addSystemCommand(&.{
        "python3",
        "-m",
        "unittest",
        "scripts.tests.test_cuda_build",
        "scripts.tests.test_cuda_aot_identity",
        "scripts.tests.test_cuda_build_cache",
        "scripts.tests.test_cuda_source_closure",
        "scripts.tests.test_cuda_product_closure",
        "scripts.tests.test_cuda_aot_authentication",
        "scripts.tests.test_cuda_blake_aot",
        "scripts.tests.test_cuda_blake_exact_interaction_oracle",
        "scripts.tests.test_cuda_blake_exact_trace_aot",
        "scripts.tests.test_cuda_compact_b2n",
        "scripts.tests.test_cuda_blake_exact_interaction_aot",
        "scripts.tests.test_cuda_plonk_logup_aot",
        "scripts.tests.test_cuda_poseidon_aot",
        "scripts.tests.test_cuda_xor_logup_aot",
        "scripts.tests.test_cuda_xor_logup_trace_aot",
        "scripts.tests.test_cuda_proof_parity_gate",
        "scripts.tests.test_cuda_activation",
    });
    tests.step.dependOn(&source.step);
    b.step(
        "test-cuda-build-plan",
        "Test CUDA source, AOT, toolchain, and build-plan contracts without a GPU",
    ).dependOn(&tests.step);

    const runtime_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = graph.source(
                b,
                "src/backends/cuda/mod.zig",
                target,
                optimize,
            ),
            .target = target,
            .optimize = optimize,
        }),
    });
    runtime_tests.root_module.addImport(
        "stwo_backend_contracts",
        b.createModule(.{
            .root_source_file = graph.source(
                b,
                "src/backend/mod.zig",
                target,
                optimize,
            ),
            .target = target,
            .optimize = optimize,
        }),
    );
    runtime_tests.addCSourceFile(.{
        .file = b.path("src/backends/cuda/runtime/stages/test_stubs.c"),
        .flags = &.{ "-std=c11", "-Wno-strict-prototypes" },
    });
    runtime_tests.linkLibC();
    b.step(
        "test-cuda-runtime-contract",
        "Test proof-owned CUDA context, residency, and strict-AOT contracts",
    ).dependOn(&b.addRunArtifact(runtime_tests).step);

    const protocol = graph.createPrivateProtocolModules(
        b,
        target,
        optimize,
    );
    const tool_product = graph.Product{
        .name = "stwo-native-cuda-tools",
        .frontend = .native,
        .backend = .cuda,
        .role = .library,
    };
    const stwo = b.createModule(.{
        .root_source_file = b.path("src/stwo.zig"),
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(stwo);
    const metal_session = graph.addMetalSessionImport(
        b,
        tool_product,
        target,
        optimize,
        stwo,
    );
    const cpu_backend = graph.addCpuBackendImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        stwo,
    );
    const metal_backend = graph.addMetalBackendImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        cpu_backend,
        stwo,
    );
    _ = graph.addCudaBackendImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        stwo,
    );
    const riscv_frontend = graph.addRiscVFrontendImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        stwo,
    );
    _ = integration_graph.addRiscVCpuImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        cpu_backend,
        riscv_frontend,
        stwo,
    );
    const cairo_frontend = graph.addCairoFrontendImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        stwo,
    );
    _ = integration_graph.addCairoCpuImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        cpu_backend,
        cairo_frontend,
        stwo,
    );
    _ = integration_graph.addCairoMetalImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        metal_backend,
        cairo_frontend,
        metal_session,
        stwo,
    );
    const ec_oracle_root = b.createModule(.{
        .root_source_file = b.path(
            "src/tools/cuda_native_ec_composite_oracle/main.zig",
        ),
        .target = target,
        .optimize = .ReleaseFast,
    });
    ec_oracle_root.addImport("stwo_under_test", stwo);
    ec_oracle_root.addImport("stwo_cairo_frontend", cairo_frontend);
    const ec_oracle = b.addExecutable(.{
        .name = "cuda-native-ec-composite-oracle",
        .root_module = ec_oracle_root,
    });
    b.step(
        "cuda-native-ec-composite-oracle",
        "Emit the canonical Zig SIMD receipt for the native EC consumer",
    ).dependOn(&b.addRunArtifact(ec_oracle).step);
    const plonk_logup_root = b.createModule(.{
        .root_source_file = b.path("tests/native_cuda_plonk_logup.zig"),
        .target = target,
        .optimize = optimize,
    });
    plonk_logup_root.addImport("stwo_under_test", stwo);
    const plonk_logup_tests = b.addTest(.{
        .root_module = plonk_logup_root,
    });
    b.step(
        "test-cuda-plonk-logup-contract",
        "Test activation-disabled exact Plonk/LogUp CUDA contracts",
    ).dependOn(&b.addRunArtifact(plonk_logup_tests).step);

    const xor_logup_root = b.createModule(.{
        .root_source_file = b.path("tests/native_cuda_xor_logup.zig"),
        .target = target,
        .optimize = optimize,
    });
    xor_logup_root.addImport("stwo_under_test", stwo);
    const xor_logup_tests = b.addTest(.{
        .root_module = xor_logup_root,
    });
    b.step(
        "test-cuda-xor-logup-contract",
        "Test exact XOR/LogUp CUDA contracts without a GPU",
    ).dependOn(&b.addRunArtifact(xor_logup_tests).step);

    const state_machine_root = b.createModule(.{
        .root_source_file = b.path("tests/native_cuda_state_machine.zig"),
        .target = target,
        .optimize = optimize,
    });
    state_machine_root.addImport("stwo_under_test", stwo);
    const state_machine_tests = b.addTest(.{
        .root_module = state_machine_root,
    });
    b.step(
        "test-cuda-state-machine-contract",
        "Test activation-disabled exact State Machine v2 CUDA contracts",
    ).dependOn(&b.addRunArtifact(state_machine_tests).step);

    const poseidon_arena_root = b.createModule(.{
        .root_source_file = b.path(
            "tests/native_cuda_poseidon_arena.zig",
        ),
        .target = target,
        .optimize = optimize,
    });
    poseidon_arena_root.addImport("stwo_under_test", stwo);
    const poseidon_arena_tests = b.addTest(.{
        .root_module = poseidon_arena_root,
    });
    b.step(
        "test-cuda-poseidon-arena-contract",
        "Test exact Poseidon CUDA arena contracts without a GPU",
    ).dependOn(&b.addRunArtifact(poseidon_arena_tests).step);

    const blake_exact_root = b.createModule(.{
        .root_source_file = b.path(
            "tests/native_cuda_blake_exact_structure.zig",
        ),
        .target = target,
        .optimize = optimize,
    });
    blake_exact_root.addImport("stwo_under_test", stwo);
    const blake_exact_tests = b.addTest(.{
        .root_module = blake_exact_root,
    });
    const blake_exact_step = b.step(
        "test-cuda-blake-exact-structure",
        "Test exact mixed-height Blake CUDA contracts without a GPU",
    );
    blake_exact_step.dependOn(&b.addRunArtifact(blake_exact_tests).step);

    const blake_route_root = b.createModule(.{
        .root_source_file = b.path(
            "src/products/native_cuda/blake_route.zig",
        ),
        .target = target,
        .optimize = optimize,
    });
    blake_route_root.addImport("stwo_native_cuda", stwo);
    const blake_route_tests = b.addTest(.{
        .root_module = blake_route_root,
    });
    blake_exact_step.dependOn(&b.addRunArtifact(blake_route_tests).step);

    const adapter_tests = b.addSystemCommand(&.{
        "cargo",
        "+nightly-2025-07-14",
        "test",
        "--locked",
        "--manifest-path",
        "tools/stwo-cuda-adapter-rs/Cargo.toml",
    });
    adapter_tests.step.dependOn(&source.step);
    b.step(
        "test-cuda-adapter",
        "Compile and test the isolated copied-backend Native proof adapter",
    ).dependOn(&adapter_tests.step);

    if (options.complete()) {
        const archive = cuda.addArchive(b, options.toolchain());
        b.step(
            "cuda-native-archive",
            "Build the exact static CUDA runtime and copied AOT pack",
        ).dependOn(&archive.build.step);

        const adapter = b.addSystemCommand(&.{
            "cargo",
            "+nightly-2025-07-14",
            "build",
            "--release",
            "--locked",
            "--manifest-path",
            "tools/stwo-cuda-adapter-rs/Cargo.toml",
        });
        adapter.setEnvironmentVariable("STWO_CUDA_NVCC", options.nvcc.?);
        adapter.setEnvironmentVariable("STWO_CUDA_HOST_COMPILER", options.host_cxx.?);
        adapter.setEnvironmentVariable("STWO_CUDA_ARCH", options.architectures.?);
        adapter.setEnvironmentVariable(
            "STWO_CUDA_BUILD_JOBS",
            b.fmt("{d}", .{options.jobs}),
        );
        adapter.step.dependOn(&source.step);
        b.step(
            "cuda-native-adapter",
            "Build the copied-backend Native CUDA proof adapter",
        ).dependOn(&adapter.step);
    } else {
        const unavailable = b.addFail(
            "cuda-native-archive requires explicit compiler, toolkit, library, " ++
                "archiver, and SM options; run `zig build cuda-build-plan` for " ++
                "the host-independent contract",
        );
        b.step(
            "cuda-native-archive",
            "Build the exact static CUDA runtime and copied AOT pack",
        ).dependOn(&unavailable.step);

        const adapter_unavailable = b.addFail(
            "cuda-native-adapter requires -Dcuda-nvcc, -Dcuda-host-cxx, " ++
                "-Dcuda-ar, -Dcuda-home, -Dcuda-library-dir, and -Dcuda-arch",
        );
        b.step(
            "cuda-native-adapter",
            "Build the copied-backend Native CUDA proof adapter",
        ).dependOn(&adapter_unavailable.step);
    }
    construction_observer.recordConstructor(b, "backends/cuda_tools.addProducts");
}

test "CUDA archive options are all-or-nothing" {
    const absent = Options{
        .nvcc = null,
        .host_cxx = null,
        .host_runtime = null,
        .host_unwind_runtime = null,
        .archiver = null,
        .cuda_home = null,
        .library_dir = null,
        .architectures = null,
        .jobs = 8,
    };
    try std.testing.expect(!absent.complete());
    var complete = absent;
    complete.nvcc = "nvcc";
    complete.host_cxx = "c++";
    complete.archiver = "ar";
    complete.cuda_home = "/cuda";
    complete.library_dir = "/cuda/lib64";
    complete.architectures = "sm_90";
    try std.testing.expect(complete.complete());
    try std.testing.expect(!complete.runtimeComplete());
    complete.host_runtime = "/usr/lib/libstdc++.so.6";
    try std.testing.expect(!complete.runtimeComplete());
    complete.host_unwind_runtime = "/usr/lib/libgcc_s.so.1";
    try std.testing.expect(complete.runtimeComplete());
}
