//! Focused sub-build command construction and product-scoped cache policy.

const std = @import("std");
const build_identity = @import("../build_identity.zig");

pub const Options = struct {
    aggregate_metal: bool,
    riscv_release_phase: []const u8,
    riscv_evidence_dir: []const u8,
    riscv_refinement_ir_dir: ?[]const u8,
    riscv_air_program_ir_dir: ?[]const u8,
    cuda_nvcc: ?[]const u8,
    cuda_host_cxx: ?[]const u8,
    cuda_host_runtime: ?[]const u8,
    cuda_host_unwind_runtime: ?[]const u8,
    cuda_archiver: ?[]const u8,
    cuda_home: ?[]const u8,
    cuda_library_dir: ?[]const u8,
    cuda_architectures: ?[]const u8,
    cuda_build_jobs: ?u16,
    metal_core_aot_bundle: ?[]const u8,
    cairo_test_filter: ?[]const u8,
    riscv_test_filter: ?[]const u8,
    identity: ?build_identity.Identity,

    pub fn read(b: *std.Build) Options {
        const implementation_commit = b.option(
            []const u8,
            "implementation-commit",
            "Exact lowercase 40-hex source commit embedded in the production CLI",
        );
        const implementation_dirty = b.option(
            bool,
            "implementation-dirty",
            "Whether the source embedded in the production CLI has local modifications",
        );
        const implementation_tree = b.option(
            []const u8,
            "implementation-tree",
            "Exact lowercase 40-hex source tree for an identity override",
        );
        const dirty_content_sha256 = b.option(
            []const u8,
            "implementation-dirty-content-sha256",
            "Canonical dirty-content digest required for a diagnostic dirty override",
        );
        return .{
            .aggregate_metal = b.option(bool, "aggregate-metal", "Explicitly link Metal into aggregate test roots") orelse false,
            .riscv_release_phase = b.option([]const u8, "riscv-release-phase", "RISC-V release phase: candidate or promoted") orelse "candidate",
            .riscv_evidence_dir = b.option([]const u8, "riscv-evidence-dir", "Fresh RISC-V release evidence directory") orelse "zig-out/release-evidence/riscv",
            .riscv_refinement_ir_dir = b.option(
                []const u8,
                "riscv-refinement-ir-dir",
                "Fresh output directory for the RISC-V symbolic AIR extractor",
            ),
            .riscv_air_program_ir_dir = b.option(
                []const u8,
                "riscv-air-program-ir-dir",
                "Fresh output directory for production AIR IR v2",
            ),
            .cuda_nvcc = b.option([]const u8, "cuda-nvcc", "Explicit nvcc executable"),
            .cuda_host_cxx = b.option([]const u8, "cuda-host-cxx", "Explicit nvcc host C++ compiler"),
            .cuda_host_runtime = b.option([]const u8, "cuda-host-runtime", "Absolute GNU C++ runtime shared-library path"),
            .cuda_host_unwind_runtime = b.option([]const u8, "cuda-host-unwind-runtime", "Absolute GNU C++ unwind runtime shared-library path"),
            .cuda_archiver = b.option([]const u8, "cuda-ar", "Explicit static archiver"),
            .cuda_home = b.option([]const u8, "cuda-home", "Explicit CUDA toolkit root"),
            .cuda_library_dir = b.option([]const u8, "cuda-library-dir", "Explicit CUDA library directory"),
            .cuda_architectures = b.option([]const u8, "cuda-arch", "Comma-separated numeric CUDA SM targets"),
            .cuda_build_jobs = b.option(u16, "cuda-build-jobs", "Maximum parallel nvcc processes"),
            .metal_core_aot_bundle = b.option(
                []const u8,
                "metal-core-aot-bundle",
                "Authenticated core Metal AOT bundle consumed by production Metal products",
            ),
            .cairo_test_filter = b.option(
                []const u8,
                "cairo-test-filter",
                "Compile and run Cairo tests whose names contain this text",
            ),
            .riscv_test_filter = b.option(
                []const u8,
                "riscv-test-filter",
                "Run RISC-V tests whose names contain this text",
            ),
            .identity = resolveIdentity(b, .{
                .commit = implementation_commit,
                .dirty = implementation_dirty,
                .tree = implementation_tree,
                .dirty_content_sha256 = dirty_content_sha256,
            }),
        };
    }
};

const IdentityOptions = struct {
    commit: ?[]const u8,
    dirty: ?bool,
    tree: ?[]const u8,
    dirty_content_sha256: ?[]const u8,
};

pub fn addProxy(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    options: Options,
    name: []const u8,
    description: []const u8,
    scope: []const u8,
) void {
    const command = commandFor(b, target, optimize, options, scope, name);
    // The CSP harness authenticates a frontend-only trace diagnostic in
    // addition to the selected prover. Keep that CPU-owned tool in its focused
    // graph, but make the public Metal matrix step self-contained and ordered.
    if (requiresRiscvTracePrerequisite(name)) {
        const trace = commandFor(
            b,
            target,
            optimize,
            options,
            "riscv_cpu",
            "riscv-trace-dump",
        );
        command.step.dependOn(&trace.step);
    }
    b.step(name, description).dependOn(&command.step);
}

fn requiresRiscvTracePrerequisite(step_name: []const u8) bool {
    return std.mem.eql(u8, step_name, "riscv-csp-bench-metal");
}

pub fn addInstallProxy(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    options: Options,
) void {
    const command = commandFor(b, target, optimize, options, "aggregate", "stwo-zig");
    b.getInstallStep().dependOn(&command.step);
}

fn commandFor(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    options: Options,
    scope: []const u8,
    step_name: []const u8,
) *std.Build.Step.Run {
    const triple = target.result.zigTriple(b.allocator) catch @panic("cannot format build target");
    const command = b.addSystemCommand(&.{
        b.graph.zig_exe,
        "build",
        step_name,
        "--build-file",
        b.pathFromRoot("build_support/internal_build.zig"),
        "--cache-dir",
        productCacheDir(b, scope),
        "-p",
        b.install_path,
        b.fmt("-Drepository-root={s}", .{b.pathFromRoot(".")}),
        b.fmt("-Dproduct-scope={s}", .{scope}),
        b.fmt("-Doptimize={s}", .{@tagName(optimize)}),
    });
    if (std.mem.eql(u8, scope, "aggregate"))
        command.addArg(b.fmt("-Daggregate-metal={s}", .{if (options.aggregate_metal) "true" else "false"}));
    if (std.mem.eql(u8, scope, "verification")) {
        command.addArg(b.fmt("-Driscv-release-phase={s}", .{options.riscv_release_phase}));
        command.addArg(b.fmt("-Driscv-evidence-dir={s}", .{options.riscv_evidence_dir}));
    }
    if (std.mem.eql(u8, scope, "riscv_cpu")) {
        if (options.riscv_refinement_ir_dir) |dir| command.addArg(b.fmt(
            "-Driscv-refinement-ir-dir={s}",
            .{dir},
        ));
        if (options.riscv_air_program_ir_dir) |dir| command.addArg(b.fmt(
            "-Driscv-air-program-ir-dir={s}",
            .{dir},
        ));
    }
    if (std.mem.eql(u8, scope, "cuda_tools") or
        std.mem.eql(u8, scope, "native_cuda") or
        std.mem.eql(u8, scope, "cairo_cuda"))
        addCudaArguments(b, command, options);
    if (requiresAuthenticatedCoreAot(scope)) {
        const bundle = if (options.metal_core_aot_bundle) |configured|
            if (std.fs.path.isAbsolute(configured))
                configured
            else
                b.pathFromRoot(configured)
        else blk: {
            const producer = commandFor(
                b,
                target,
                optimize,
                options,
                "metal_tools",
                "metal-core-aot-acceptance",
            );
            command.step.dependOn(&producer.step);
            break :blk b.getInstallPath(
                .prefix,
                "share/stwo-zig/metal/core",
            );
        };
        command.addArg(b.fmt(
            "-Dmetal-core-aot-bundle={s}",
            .{bundle},
        ));
    }
    if (std.mem.eql(u8, scope, "compatibility_tools")) {
        if (options.cairo_test_filter) |filter| command.addArg(b.fmt(
            "-Dcairo-test-filter={s}",
            .{filter},
        ));
    }
    if (std.mem.eql(u8, scope, "riscv_cpu") or std.mem.eql(u8, scope, "riscv_cpu_compat")) {
        if (options.riscv_test_filter) |filter| command.addArg(b.fmt(
            "-Driscv-test-filter={s}",
            .{filter},
        ));
    }
    if (b.user_input_options.get("target") != null or b.user_input_options.get("cpu") != null)
        command.addArg(b.fmt("-Dtarget={s}", .{triple}));
    // `standardTargetOptions` resolves `-Dcpu`, but `zigTriple` intentionally
    // contains only the architecture/OS/ABI. Preserve the caller's CPU model
    // and feature expression across the focused sub-build boundary as well;
    // otherwise every delegated product silently falls back to the target's
    // baseline model (apple_m1 on aarch64-macos today).
    if (b.user_input_options.get("cpu")) |cpu_option| switch (cpu_option.value) {
        .scalar => |cpu| command.addArg(b.fmt("-Dcpu={s}", .{cpu})),
        else => @panic("standard -Dcpu option must be a scalar"),
    };
    if (options.identity) |identity| addIdentityArguments(b, command, identity);
    return command;
}

fn requiresAuthenticatedCoreAot(scope: []const u8) bool {
    return std.mem.eql(u8, scope, "cairo_metal") or
        std.mem.eql(u8, scope, "riscv_metal");
}

fn addCudaArguments(
    b: *std.Build,
    command: *std.Build.Step.Run,
    options: Options,
) void {
    const StringOption = struct { name: []const u8, value: ?[]const u8 };
    for ([_]StringOption{
        .{ .name = "cuda-nvcc", .value = options.cuda_nvcc },
        .{ .name = "cuda-host-cxx", .value = options.cuda_host_cxx },
        .{ .name = "cuda-host-runtime", .value = options.cuda_host_runtime },
        .{ .name = "cuda-host-unwind-runtime", .value = options.cuda_host_unwind_runtime },
        .{ .name = "cuda-ar", .value = options.cuda_archiver },
        .{ .name = "cuda-home", .value = options.cuda_home },
        .{ .name = "cuda-library-dir", .value = options.cuda_library_dir },
        .{ .name = "cuda-arch", .value = options.cuda_architectures },
    }) |option| if (option.value) |value| command.addArg(b.fmt(
        "-D{s}={s}",
        .{ option.name, value },
    ));
    if (options.cuda_build_jobs) |jobs| command.addArg(b.fmt(
        "-Dcuda-build-jobs={d}",
        .{jobs},
    ));
}

fn resolveIdentity(b: *std.Build, options: IdentityOptions) ?build_identity.Identity {
    if ((options.commit == null) != (options.dirty == null))
        @panic("incomplete implementation identity override");
    if (options.commit == null and
        (options.tree != null or options.dirty_content_sha256 != null))
        @panic("orphan implementation identity override");

    // Dependency consumers configure this dispatcher only to discover public
    // modules. Their package cache is not necessarily a Git checkout, and no
    // delegated product command is run from that graph.
    if (b.pkg_hash.len != 0 and options.commit == null) return null;
    return build_identity.resolveWithOverride(
        b.allocator,
        b.pathFromRoot("."),
        if (options.commit) |commit| .{
            .commit = commit,
            .tree = options.tree,
            .dirty = options.dirty.?,
            .dirty_content_sha256 = options.dirty_content_sha256,
        } else null,
    ) catch |err| std.debug.panic(
        "cannot resolve delegated product identity: {s}",
        .{@errorName(err)},
    );
}

fn addIdentityArguments(
    b: *std.Build,
    command: *std.Build.Step.Run,
    identity: build_identity.Identity,
) void {
    command.addArg(b.fmt(
        "-Dimplementation-commit={s}",
        .{&identity.implementation_commit},
    ));
    command.addArg(b.fmt(
        "-Dimplementation-dirty={s}",
        .{if (identity.implementation_dirty) "true" else "false"},
    ));
    if (identity.implementation_tree) |tree| command.addArg(b.fmt(
        "-Dimplementation-tree={s}",
        .{&tree},
    ));
    if (identity.dirty_content_sha256) |digest| {
        const encoded = std.fmt.bytesToHex(digest, .lower);
        command.addArg(b.fmt(
            "-Dimplementation-dirty-content-sha256={s}",
            .{&encoded},
        ));
    }
}

fn productCacheDir(b: *std.Build, scope: []const u8) []const u8 {
    if (b.graph.env_map.get("STWO_CI_CACHE_DIR")) |configured| {
        return if (std.fs.path.isAbsolute(configured)) configured else b.pathFromRoot(configured);
    }
    // A caller-provided `--cache-dir` is a lane boundary, not merely a cache
    // hint.  Delegated product builds must stay below that exact root; falling
    // back to the repository's shared `.zig-cache` makes otherwise isolated
    // agents invalidate and contend on the same product graph.
    return b.cache_root.join(
        b.allocator,
        &.{ "products", scope },
    ) catch @panic("cannot construct delegated product cache directory");
}

test "production Metal product scopes automatically consume authenticated core AOT" {
    try std.testing.expect(requiresAuthenticatedCoreAot("cairo_metal"));
    try std.testing.expect(requiresAuthenticatedCoreAot("riscv_metal"));
    try std.testing.expect(!requiresAuthenticatedCoreAot("native_metal"));
    try std.testing.expect(!requiresAuthenticatedCoreAot("metal_tools"));
}

test "the public Metal CSP step first builds the focused trace diagnostic" {
    try std.testing.expect(requiresRiscvTracePrerequisite("riscv-csp-bench-metal"));
    try std.testing.expect(!requiresRiscvTracePrerequisite("stwo-riscv-metal"));
    try std.testing.expect(!requiresRiscvTracePrerequisite("riscv-csp-bench"));
}
