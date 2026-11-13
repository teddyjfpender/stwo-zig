const std = @import("std");

/// Public BUILD-only constructors; runtime module keys stay unchanged.
pub const Construction = @import("build_components.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const options = .{ .target = target, .optimize = optimize };
    const neutral_frontend = b.dependency("stwo_riscv_frontend", options).module("stwo_riscv_frontend");
    const neutral_cpu = b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration");
    const neutral_cuda = b.dependency("stwo_riscv_cuda_integration", options).module("stwo_riscv_cuda_integration");
    // Declare the full published dependency closure; concrete instances come
    // from the native owners and are never rebuilt against another protocol.
    _ = b.dependency("stwo_circuit_cpu_integration", options);
    _ = b.dependency("stwo_circuit_frontend", options);
    _ = b.dependency("stwo_cpu_backend", options);
    _ = b.dependency("stwo_core", options);
    _ = b.dependency("stwo_proof_wire", options);
    _ = b.dependency("stwo_prover_api", options);
    _ = b.dependency("stwo_prover_engine", options);
    _ = b.dependency("stwo_riscv_air_lang", options);
    _ = b.dependency("stwo_riscv_isa", options);
    _ = b.dependency("stwo_riscv_memory", options);
    _ = b.dependency("stwo_riscv_precompiles", options);
    _ = b.dependency("stwo_riscv_recursion", options);
    _ = b.dependency("stwo_riscv_recursion_air", options);
    _ = b.dependency("stwo_riscv_rv32", options);
    _ = b.dependency("stwo_riscv_rv64", options);
    _ = b.dependency("stwo_riscv_testing", options);
    const frontend_component = b.createModule(.{ .root_source_file = b.path("frontend.zig"), .target = target, .optimize = optimize });
    Construction.bindFrontend(frontend_component, neutral_frontend);
    const cpu_component = b.createModule(.{ .root_source_file = b.path("cpu.zig"), .target = target, .optimize = optimize });
    Construction.bindCpu(cpu_component, frontend_component, neutral_cpu);
    const cuda_component = b.createModule(.{ .root_source_file = b.path("cuda.zig"), .target = target, .optimize = optimize });
    Construction.bindCuda(cuda_component, frontend_component, cpu_component, neutral_cuda);
    const product = b.createModule(.{ .root_source_file = b.path("mod.zig"), .target = target, .optimize = optimize });
    Construction.bindPrimary(product, frontend_component, cpu_component, cuda_component);
    b.modules.put("stwo_ethereum_statement", product) catch @panic("OOM");
    b.modules.put("legacy_riscv_frontend", frontend_component) catch @panic("OOM");
    b.modules.put("legacy_riscv_cpu_integration", cpu_component) catch @panic("OOM");
    addMetalCsp(b, target, optimize, frontend_component);
    const owner = b.step("test", "Run Ethereum product contracts and owned component suites");
    var runs: [4]*std.Build.Step.Run = undefined;
    for ([_]*std.Build.Module{ product, frontend_component, cpu_component, cuda_component }, &runs) |component, *run| {
        const tests = b.addTest(.{ .root_module = component });
        // Host-only CUDA tests analyse real builders without linking a device
        // library. Zig ELF debug metadata retains unused extern references.
        if (component == cuda_component) tests.root_module.strip = true;
        run.* = b.addRunArtifact(tests);
        run.*.has_side_effects = true;
        owner.dependOn(&run.*.step);
    }
    owner.dependOn(@import("stwo_riscv_frontend").TestCountFloor.addMany(b, &runs, 478));
    const build_tests = b.addRunArtifact(b.addTest(.{ .root_module = b.createModule(.{ .root_source_file = b.path("build_components_test.zig"), .target = b.graph.host, .optimize = optimize }) }));
    build_tests.has_side_effects = true;
    const build_floor = @import("stwo_riscv_frontend").TestCountFloor.addMany(b, &.{build_tests}, 1);
    owner.dependOn(&build_tests.step);
    owner.dependOn(build_floor);
    const build_step = b.step("test-build-components", "Check caller-selected module identity and native owner isolation");
    build_step.dependOn(&build_tests.step);
    build_step.dependOn(build_floor);
    // Product-owned focused roots borrow the actual component's dependency
    // pointers; they never construct a second frontend/Core module graph.
    inline for (.{
        .{ .component = cpu_component, .step = "test-receiver-boundaries", .description = "Test real receipt, image and independently configured receiver rejection boundaries", .root = "cpu/rv64_ethereum_receiver_boundary_test_root.zig", .filters = &[_][]const u8{ "serialized Ethereum receipt", "Ethereum cursor rejects", "serialized physical receipt", "merged RAM BYTE mass rejects" }, .minimum = 5 },
        .{ .component = cpu_component, .step = "test-receiver-boundaries", .description = "Test real receipt, image and independently configured receiver rejection boundaries", .root = "cpu/rv64_ethereum_image_admission_test_root.zig", .filters = &[_][]const u8{ "pristine expected image retains", "pristine image pin terminal", "new execution packet path reads", "execution receiver binds independently", "execution memory count preflight", "resident pinned image program cache" }, .minimum = 7 },
        .{ .component = cpu_component, .step = "test-gkr-resources", .description = "Test operational schema, immutable security and receiver setup authority", .root = "cpu/rv64_gkr_resources_test_root.zig", .filters = &[_][]const u8{}, .minimum = 10 },
        .{ .component = cpu_component, .step = "test-capture-prefetch", .description = "Test real native packet capture, speculative joins and admission", .root = "cpu/rv64_capture_prefetch_test_root.zig", .filters = &[_][]const u8{}, .minimum = 20 },
        .{ .component = cpu_component, .step = "test-setup-cache", .description = "Test setup artifact integrity and prover/verifier ownership", .root = "cpu/rv64_setup_cache_test_root.zig", .filters = &[_][]const u8{}, .minimum = 4 },
        .{ .component = cpu_component, .step = "test-services-gkr-policy", .description = "Test product-owned service execution policy", .root = "cpu/rv64_services_gkr_policy_test_root.zig", .filters = &[_][]const u8{}, .minimum = 6 },
        .{ .component = cpu_component, .step = "test-word16-services", .description = "Test product-owned service execution policy", .root = "cpu/rv64_word16_services_test_root.zig", .filters = &[_][]const u8{}, .minimum = 11 },
        .{ .component = cpu_component, .step = "test-word16-zbb-services", .description = "Test product-owned service execution policy", .root = "cpu/rv64_word16_zbb_services_test_root.zig", .filters = &[_][]const u8{}, .minimum = 4 },
        .{ .component = cpu_component, .step = "test-word16-sponge-services", .description = "Test product-owned service execution policy", .root = "cpu/rv64_word16_sponge_services_test_root.zig", .filters = &[_][]const u8{}, .minimum = 11 },
        .{ .component = cpu_component, .step = "test-word16-ls-dword-services", .description = "Test product-owned service execution policy", .root = "cpu/rv64_word16_ls_dword_services_test_root.zig", .filters = &[_][]const u8{}, .minimum = 6 },
        .{ .component = cpu_component, .step = "test-services-recursion", .description = "Test product-owned service execution policy", .root = "cpu/rv64_services_recursion_test_root.zig", .filters = &[_][]const u8{}, .minimum = 8 },
        .{ .component = frontend_component, .step = "test-vm-leaf-context-v2", .description = "Test SegmentV2 verifier-instance and capture authority", .root = "frontend.zig", .filters = &[_][]const u8{ "SegmentV2 VM leaf ContextV2", "Ethereum selected base claim admission" }, .minimum = 16 },
        .{ .component = frontend_component, .step = "test-vm-air-profile-authority-v2", .description = "Check VM profile identity and authority without composition-program or provider-shard tests", .root = "frontend.zig", .filters = &[_][]const u8{ "authenticated VM AIR ProfileV2 binds fixed program", "authenticated VM AIR ProfileV2 binds selected physical", "authenticated VM AIR ProfileV2 rejects authority and vtable", "authenticated VM AIR ProfileV2 focused inventory compiles" }, .minimum = 17 },
        .{ .component = cpu_component, .step = "test-csp-ecdsa-proof", .description = "Prove both canonical CSP ECDSA suites on CPU", .root = "cpu/csp_ecdsa_proof_test.zig", .filters = &[_][]const u8{ "CSP ECDSA guest proves caller memory", "BLAKE3 CSP ECDSA guest proves" }, .minimum = 2 },
        .{ .component = frontend_component, .step = "test-composition-custody", .description = "Check ownership, OOM, mutation and Initial38 policy", .root = "frontend.zig", .filters = &[_][]const u8{ "composition ownership", "composition finalization", "composition borrowed", "Initial38 composition descriptor" }, .minimum = 17 },
        .{ .component = product, .step = "test-component-boundaries", .description = "Check canonical components, coordinator owners and read capabilities", .root = "mod.zig", .filters = &[_][]const u8{ "api signature: Ethereum product", "api invariant: legacy exports", "coordinator boundary:", "composition boundary:" }, .minimum = 7 },
        .{ .component = frontend_component, .step = "test-ethereum-composition-program", .description = "Run every moved composition-program case", .root = "frontend_composition_program_test_root.zig", .filters = &[_][]const u8{}, .minimum = 8 },
    }) |spec| {
        const root = b.createModule(.{ .root_source_file = b.path(spec.root), .target = target, .optimize = optimize });
        for (spec.component.import_table.keys(), spec.component.import_table.values()) |name, dependency| root.addImport(name, dependency);
        const tests = b.addTest(.{ .root_module = root, .filters = spec.filters });
        const run = b.addRunArtifact(tests);
        run.has_side_effects = true;
        // Shared names compose independent images, each with its own floor.
        const step = if (b.top_level_steps.get(spec.step)) |existing| &existing.step else b.step(spec.step, spec.description);
        step.dependOn(&run.step);
        step.dependOn(@import("stwo_riscv_frontend").TestCountFloor.addMany(b, &.{run}, spec.minimum));
    }
}

fn addMetalCsp(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, frontend: *std.Build.Module) void {
    const jit_step = b.step("test-blake3-csp-ecdsa-jit", "Prove canonical CSP ECDSA on Metal source-JIT");
    const aot_step = b.step("test-blake3-csp-ecdsa-aot", "Prove canonical CSP ECDSA on authenticated AOT Metal");
    if (target.result.os.tag != .macos) {
        const failure = b.addFail("Metal CSP qualification requires macOS and the Metal SDK");
        jit_step.dependOn(&failure.step);
        aot_step.dependOn(&failure.step);
        return;
    }
    const metal = b.dependency("stwo_metal_backend", .{ .target = target, .optimize = optimize }).module("stwo_metal_backend");
    const root = b.createModule(.{ .root_source_file = b.path("compat/metal/blake3_csp_test.zig"), .target = target, .optimize = optimize });
    for (frontend.import_table.keys(), frontend.import_table.values()) |name, dependency| root.addImport(name, dependency);
    root.addImport("ethereum_frontend_component", frontend);
    root.addImport("stwo_metal_backend", metal);
    const tests = b.addTest(.{ .root_module = root, .filters = &.{"Metal BLAKE3 canonical CSP ECDSA proves and independently verifies"} });
    tests.root_module.linkFramework("Metal", .{});
    tests.root_module.linkFramework("Foundation", .{});
    tests.linkLibC();
    tests.linkSystemLibrary("objc");
    const jit = b.addRunArtifact(tests);
    jit.setEnvironmentVariable("STWO_BLAKE3_CSP_RUNTIME", "source_jit");
    jit_step.dependOn(&jit.step);
    jit_step.dependOn(@import("stwo_riscv_frontend").TestCountFloor.addMany(b, &.{jit}, 1));
    if (b.option([]const u8, "metal-core-aot-bundle", "Absolute authenticated core AOT bundle for real-device acceptance")) |bundle| {
        const aot = b.addRunArtifact(tests);
        aot.setEnvironmentVariable("STWO_BLAKE3_CSP_RUNTIME", "authenticated_aot");
        aot.setEnvironmentVariable("STWO_RISCV_METAL_AOT_BUNDLE", bundle);
        aot_step.dependOn(&aot.step);
        aot_step.dependOn(@import("stwo_riscv_frontend").TestCountFloor.addMany(b, &.{aot}, 1));
    } else aot_step.dependOn(&b.addFail("test-blake3-csp-ecdsa-aot requires -Dmetal-core-aot-bundle=<absolute-path>").step);
}
