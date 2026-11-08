const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const dependency_options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const api = b.addModule("stwo_prover_api", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    api.addImport("stwo_core", core);

    const repository_root = b.path("../..");
    const source_authority = b.addSystemCommand(&.{
        "python3",
        "-m",
        "unittest",
        "scripts.tests.test_typed_air_work_site_authority",
    });
    source_authority.setCwd(repository_root);
    const source_authority_step = b.step(
        "test-work-site-source-authority",
        "Test the comment-proof logical-work site source authority",
    );
    source_authority_step.dependOn(&source_authority.step);

    const completion_tests = b.addSystemCommand(&.{
        "python3",
        "-m",
        "unittest",
        "scripts.tests.test_typed_air_p003_completion",
    });
    completion_tests.setCwd(repository_root);
    const completion_matrix = b.addSystemCommand(&.{
        "python3",
        "scripts/typed_air_p003_completion.py",
        "validate-matrix",
        "--quiet",
    });
    completion_matrix.setCwd(repository_root);
    completion_matrix.step.dependOn(&completion_tests.step);
    const completion_receipt = b.addSystemCommand(&.{
        "python3",
        "scripts/typed_air_p003_completion.py",
        "validate-blocker",
        "design/typed-air/artifacts/p003-work-profile-closure-v1/scaling-blocker-v1.json",
    });
    completion_receipt.setCwd(repository_root);
    completion_receipt.step.dependOn(&completion_matrix.step);
    const completion_step = b.step(
        "test-work-profile-completion",
        "Validate the sixteen-family P-003 closure and fail-closed scaling gate",
    );
    completion_step.dependOn(&completion_receipt.step);

    const tests = b.addRunArtifact(b.addTest(.{ .root_module = api }));
    tests.step.dependOn(&source_authority.step);
    tests.step.dependOn(&completion_receipt.step);
    b.step(
        "test",
        "Compile and test the stable stwo_prover_api package",
    ).dependOn(&tests.step);
}
