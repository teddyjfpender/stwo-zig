const std = @import("std");

pub fn createHarnessModule(
    b: *std.Build,
    root_source_file: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    core: *std.Build.Module,
    cpu_backend: *std.Build.Module,
    frontend: *std.Build.Module,
    integration: *std.Build.Module,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path(root_source_file),
        .target = target,
        .optimize = optimize,
    });
    module.addImport("stwo_core", core);
    module.addImport("stwo_cpu_backend", cpu_backend);
    module.addImport("stwo_riscv_frontend", frontend);
    module.addImport("stwo_riscv_cpu_integration", integration);
    return module;
}

pub fn addImports(
    module: *std.Build.Module,
    core: *std.Build.Module,
    prover_api: *std.Build.Module,
    prover: *std.Build.Module,
    cpu_backend: *std.Build.Module,
    frontend: *std.Build.Module,
) void {
    module.addImport("stwo_core", core);
    module.addImport("stwo_prover_api", prover_api);
    module.addImport("stwo_prover_engine", prover);
    module.addImport("stwo_cpu_backend", cpu_backend);
    module.addImport("stwo_riscv_frontend", frontend);
}

/// Prevents the native recursion proof lane from becoming a successful empty
/// shell if any evidence-bearing `test` declaration is deleted or renamed.
pub const ProofTestGuard = struct {
    step: std.Build.Step,
    run: *std.Build.Step.Run,
    expected_names: []const []const u8,

    pub fn add(
        b: *std.Build,
        run: *std.Build.Step.Run,
        expected_names: []const []const u8,
        step_name: []const u8,
    ) *std.Build.Step {
        const guard = b.allocator.create(ProofTestGuard) catch @panic("out of memory");
        guard.* = .{
            .step = std.Build.Step.init(.{
                .id = .custom,
                .name = step_name,
                .owner = b,
                .makeFn = make,
            }),
            .run = run,
            .expected_names = expected_names,
        };
        guard.step.dependOn(&run.step);
        return &guard.step;
    }

    fn make(step: *std.Build.Step, _: std.Build.Step.MakeOptions) anyerror!void {
        const guard: *ProofTestGuard = @fieldParentPtr("step", step);
        const metadata = guard.run.cached_test_metadata orelse return step.fail(
            "the native recursion proof run reported no test names",
            .{},
        );
        if (metadata.names.len != guard.expected_names.len) return step.fail(
            "the native recursion proof root compiled {d} tests; expected exactly {d}",
            .{ metadata.names.len, guard.expected_names.len },
        );
        for (guard.expected_names) |expected_name| {
            var matches: usize = 0;
            for (0..metadata.names.len) |index| {
                if (std.mem.indexOf(
                    u8,
                    metadata.testName(@intCast(index)),
                    expected_name,
                ) != null)
                    matches += 1;
            }
            if (matches != 1) return step.fail(
                "the native recursion proof test identity drifted: expected one match for {s}, found {d}",
                .{ expected_name, matches },
            );
        }
    }
};
