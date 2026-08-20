const support = @import("build_support.zig");

pub fn add(ctx: anytype) void {
    const b = ctx.b;
    const target = ctx.target;
    const optimize = ctx.optimize;
    const core = ctx.core;
    const cpu_backend = ctx.cpu_backend;
    const frontend = ctx.frontend;
    const integration = ctx.integration;
    const producer = b.addExecutable(.{
        .name = "guest-precompile-artifact-producer",
        .root_module = support.createHarnessModule(
            b,
            "guest_precompile_artifact_producer.zig",
            target,
            optimize,
            core,
            cpu_backend,
            frontend,
            integration,
        ),
    });
    const verifier = b.addExecutable(.{
        .name = "guest-precompile-artifact-verifier",
        .root_module = support.createHarnessModule(
            b,
            "guest_precompile_artifact_verifier.zig",
            target,
            optimize,
            core,
            cpu_backend,
            frontend,
            integration,
        ),
    });
    const produce = b.addRunArtifact(producer);
    const artifact = produce.addOutputFileArg("guest-precompile-proof.stw");
    const verify = b.addRunArtifact(verifier);
    verify.addFileArg(artifact);

    const artifact_step = b.step(
        "test-guest-precompile-artifact-process",
        "Prove, serialize, and verify a guest-precompile proof in fresh processes",
    );
    artifact_step.dependOn(&verify.step);
    ctx.test_step.dependOn(artifact_step);
}
