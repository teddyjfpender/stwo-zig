const std = @import("std");
const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const support = @import("build_support.zig");

pub fn add(ctx: anytype) void {
    const b = ctx.b;
    const target = ctx.target;
    const optimize = ctx.optimize;
    const core = ctx.core;
    const cpu_backend = ctx.cpu_backend;
    const frontend = ctx.frontend;
    const integration = ctx.integration;
    const io_tests = b.addTest(.{
        .root_module = support.createHarnessModule(
            b,
            "ethereum_precompile_artifact_io.zig",
            target,
            optimize,
            core,
            cpu_backend,
            frontend,
            integration,
        ),
    });
    b.step(
        "test-ethereum-precompile-artifact-io",
        "Run create-only Ethereum artifact custody tests",
    ).dependOn(&b.addRunArtifact(io_tests).step);
    addIncrementalCapturePublication(ctx);
    addIncrementalCapturePublicationV3(ctx);
    addIncrementalCapturePublicationV4(ctx);
    addIncrementalPublicWirePublicationV4(ctx);
    addIncrementalCapturePostprocessV4(ctx);
    addIncrementalCapturePostprocessCommandV4(ctx);
    const block_leaf_tests = b.addTest(.{
        .root_module = support.createHarnessModule(
            b,
            "ethereum_block_leaf_test.zig",
            target,
            optimize,
            core,
            cpu_backend,
            frontend,
            integration,
        ),
    });
    const check_block_leaf = b.step(
        "check-ethereum-block-leaf-product",
        "Compile the streamed Ethereum leaf producer and fresh verifier",
    );
    check_block_leaf.dependOn(&block_leaf_tests.step);
    b.step(
        "test-ethereum-block-leaf-product",
        "Run streamed Ethereum leaf contract and entrypoint tests",
    ).dependOn(&b.addRunArtifact(block_leaf_tests).step);
    addPoseidonLeafComponentCheck(ctx);
    addPoseidonLeafProcessGate(ctx);
    addRecursivePipelineWorker(ctx);
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

    const ethereum_producer = b.addExecutable(.{
        .name = "ethereum-precompile-artifact-producer",
        .root_module = support.createHarnessModule(
            b,
            "ethereum_precompile_artifact_producer.zig",
            target,
            optimize,
            core,
            cpu_backend,
            frontend,
            integration,
        ),
    });
    const ethereum_verifier = b.addExecutable(.{
        .name = "ethereum-precompile-artifact-verifier",
        .root_module = support.createHarnessModule(
            b,
            "ethereum_precompile_artifact_verifier.zig",
            target,
            optimize,
            core,
            cpu_backend,
            frontend,
            integration,
        ),
    });
    const ethereum_mutator = b.addExecutable(.{
        .name = "ethereum-precompile-artifact-mutator",
        .root_module = support.createHarnessModule(
            b,
            "ethereum_precompile_artifact_mutator.zig",
            target,
            optimize,
            core,
            cpu_backend,
            frontend,
            integration,
        ),
    });
    const ethereum_produce = b.addRunArtifact(ethereum_producer);
    const ethereum_artifact = ethereum_produce.addOutputFileArg(
        "ethereum-precompile-proof-v2.stw",
    );
    const ethereum_verify = b.addRunArtifact(ethereum_verifier);
    ethereum_verify.addFileArg(ethereum_artifact);
    const ethereum_artifact_step = b.step(
        "test-ethereum-precompile-artifact-process",
        "Prove, serialize, and verify a joined Ethereum leaf in fresh processes",
    );
    ethereum_artifact_step.dependOn(&ethereum_verify.step);

    const mutate_version = b.addRunArtifact(ethereum_mutator);
    mutate_version.addArg("version");
    mutate_version.addFileArg(ethereum_artifact);
    const bad_version = mutate_version.addOutputFileArg(
        "ethereum-precompile-proof-bad-version.stw",
    );
    const reject_version = b.addRunArtifact(ethereum_verifier);
    reject_version.addFileArg(bad_version);
    reject_version.expectExitCode(1);
    const mutate_identity = b.addRunArtifact(ethereum_mutator);
    mutate_identity.addArg("identity");
    mutate_identity.addFileArg(ethereum_artifact);
    const bad_identity = mutate_identity.addOutputFileArg(
        "ethereum-precompile-proof-bad-identity.stw",
    );
    const reject_identity = b.addRunArtifact(ethereum_verifier);
    reject_identity.addFileArg(bad_identity);
    reject_identity.expectExitCode(1);
    const mutation_step = b.step(
        "test-ethereum-precompile-artifact-mutations",
        "Reject mutated Ethereum artifact version and identity in fresh processes",
    );
    mutation_step.dependOn(&reject_version.step);
    mutation_step.dependOn(&reject_identity.step);
}

fn addIncrementalCapturePostprocessCommandV4(ctx: anytype) void {
    const b = ctx.b;
    const test_names: []const []const u8 = &.{
        "fast V4 command distinguishes create and resumable unsealed custody",
        "fast V4 command rejects ambiguous roots and unbounded workers",
        "fast V4 command is raw-once then VM-free postprocess only",
        "parallel raw opens may complete out of order but mint order is exact",
        "parallel raw open cleanup releases each moved owner exactly once",
        "nonfinal role completion is exact admitted ELF CUSTOM-0 fetch",
        "program fetch authority rejects mutation missing PC and role drift",
        "path-free mint input rejects byte identity drift before decoding",
        "path-free mint input API has no filesystem parameter",
        "raw recovery manifest roundtrips exact ordered cold inventory",
        "resealed recovery manifest rejects lineage and order drift",
        "resealed recovery manifest rejects empty relabel and role drift",
        "raw recovery codec rejects mutation truncation and trailing bytes",
        "recovery contract requires real compact replay and remains inactive",
    };
    const tests = b.addTest(.{
        .root_module = support.createHarnessModule(
            b,
            "ethereum_incremental_capture_postprocess_command_v4_test.zig",
            ctx.target,
            ctx.optimize,
            ctx.core,
            ctx.cpu_backend,
            ctx.frontend,
            ctx.integration,
        ),
        .filters = test_names,
    });
    const run = b.addRunArtifact(tests);
    run.has_side_effects = true;

    // Compile the exact command root as an executable as well as compiling its
    // option/phase tests. This keeps product dispatch wiring out of the gate
    // while still type-checking every runtime branch used by the 210-segment
    // retained capture.
    const command = b.addExecutable(.{
        .name = "ethereum-incremental-capture-fast-v4",
        .root_module = support.createHarnessModule(
            b,
            "ethereum_incremental_capture_postprocess_command_v4.zig",
            ctx.target,
            ctx.optimize,
            ctx.core,
            ctx.cpu_backend,
            ctx.frontend,
            ctx.integration,
        ),
    });
    const step = b.step(
        "test-ethereum-incremental-capture-fast-v4",
        "Compile and test the raw-once, VM-free V4 capture command",
    );
    step.dependOn(support.ProofTestGuard.add(
        b,
        run,
        test_names,
        "incremental V4 fast command identity guard",
    ));
    step.dependOn(&command.step);
}

fn addIncrementalCapturePostprocessV4(ctx: anytype) void {
    const b = ctx.b;
    const root = support.createHarnessModule(
        b,
        "ethereum_incremental_capture_postprocess_v4_test_root.zig",
        ctx.target,
        ctx.optimize,
        ctx.core,
        ctx.cpu_backend,
        ctx.frontend,
        ctx.integration,
    );
    const test_names: []const []const u8 = &.{
        "early V4 owner publishes raw pair and cold-adopts exact restart",
        "early V4 owner rejects order boundary and byte drift",
        "VM-free V4 owner mints sequential jobs then cold-publishes independently",
        "sequential mint order failure poisons the process-local owner",
    };
    const compile = b.addTest(.{
        .root_module = root,
        .filters = test_names,
    });
    const run = b.addRunArtifact(compile);
    run.has_side_effects = true;
    b.step(
        "test-ethereum-incremental-capture-postprocess-v4",
        "Run VM-free V4 capture mint, cold publication, and resume gates",
    ).dependOn(support.ProofTestGuard.add(
        b,
        run,
        test_names,
        "incremental V4 VM-free postprocess identity guard",
    ));
}

fn addIncrementalCapturePublication(ctx: anytype) void {
    const b = ctx.b;
    const root = support.createHarnessModule(
        b,
        "ethereum_incremental_capture_publication_v1_test.zig",
        ctx.target,
        ctx.optimize,
        ctx.core,
        ctx.cpu_backend,
        ctx.frontend,
        ctx.integration,
    );
    const test_names: []const []const u8 = &.{
        "incremental publication resumes a committed STWIMT02 prefix without execution",
        "incremental publication manifest binds all 210 refs and authorities",
        "incremental segment ref codec rejects wrong magic and mutations",
    };
    const compile = b.addTest(.{
        .root_module = root,
        .filters = test_names,
    });
    const run = b.addRunArtifact(compile);
    run.has_side_effects = true;
    b.step(
        "test-ethereum-incremental-capture-publication-v1",
        "Run create-only incremental capture publication and recovery tests",
    ).dependOn(support.ProofTestGuard.add(
        b,
        run,
        test_names,
        "incremental capture publication test identity guard",
    ));
}

fn addIncrementalCapturePublicationV3(ctx: anytype) void {
    const b = ctx.b;
    const root = support.createHarnessModule(
        b,
        "ethereum_incremental_capture_publication_v3_test.zig",
        ctx.target,
        ctx.optimize,
        ctx.core,
        ctx.cpu_backend,
        ctx.frontend,
        ctx.integration,
    );
    const test_names: []const []const u8 = &.{
        "V3 publication reexecutes and cold-adopts a durable prefix",
        "V3 segment and manifest codecs reject mutations",
        "V3 command options distinguish create from full-VM resume",
    };
    const compile = b.addTest(.{
        .root_module = root,
        .filters = test_names,
    });
    const run = b.addRunArtifact(compile);
    run.has_side_effects = true;
    b.step(
        "test-ethereum-incremental-capture-publication-v3",
        "Run retained-authority V3 capture transaction tests",
    ).dependOn(support.ProofTestGuard.add(
        b,
        run,
        test_names,
        "incremental V3 capture publication test identity guard",
    ));
}

fn addIncrementalCapturePublicationV4(ctx: anytype) void {
    const b = ctx.b;
    const root = support.createHarnessModule(
        b,
        "ethereum_incremental_capture_publication_v4_test.zig",
        ctx.target,
        ctx.optimize,
        ctx.core,
        ctx.cpu_backend,
        ctx.frontend,
        ctx.integration,
    );
    const test_names: []const []const u8 = &.{
        "V4 publication reexecutes and cold-adopts a durable prefix",
        "V4 segment and manifest codecs reject mutations",
        "V4 command options distinguish create from full-VM resume",
    };
    const compile = b.addTest(.{
        .root_module = root,
        .filters = test_names,
    });
    const run = b.addRunArtifact(compile);
    run.has_side_effects = true;
    b.step(
        "test-ethereum-incremental-capture-publication-v4",
        "Run retained-authority V4 policy-2 capture transaction tests",
    ).dependOn(support.ProofTestGuard.add(
        b,
        run,
        test_names,
        "incremental V4 capture publication test identity guard",
    ));
}

fn addIncrementalPublicWirePublicationV4(ctx: anytype) void {
    const b = ctx.b;
    const root = support.createHarnessModule(
        b,
        "ethereum_incremental_public_wire_publication_v4_test.zig",
        ctx.target,
        ctx.optimize,
        ctx.core,
        ctx.cpu_backend,
        ctx.frontend,
        ctx.integration,
    );
    const test_names: []const []const u8 = &.{
        "V4 public-wire companion cold-adopts a crash prefix and seals last",
        "V4 public-wire codecs reject field ref and manifest mutations",
        "V4 role-aware public data is reconstructed from wire layout and raw IO",
    };
    const compile = b.addTest(.{
        .root_module = root,
        .filters = test_names,
    });
    const run = b.addRunArtifact(compile);
    run.has_side_effects = true;
    b.step(
        "test-ethereum-incremental-public-wire-publication-v4",
        "Run canonical SegmentV2 wire companion custody and reconstruction gates",
    ).dependOn(support.ProofTestGuard.add(
        b,
        run,
        test_names,
        "incremental public-wire V4 companion test identity guard",
    ));
}

fn addRecursivePipelineWorker(ctx: anytype) void {
    const b = ctx.b;
    const artifact_store = b.dependency(
        "stwo_artifact_store",
        .{ .target = ctx.target, .optimize = .Debug },
    ).module("stwo_artifact_store");
    const worker_module = b.createModule(.{
        .root_source_file = b.path("recursive_pipeline_worker_main_v1.zig"),
        .target = ctx.target,
        .optimize = ctx.optimize,
    });
    worker_module.addImport("stwo_artifact_store", b.dependency(
        "stwo_artifact_store",
        .{ .target = ctx.target, .optimize = ctx.optimize },
    ).module("stwo_artifact_store"));
    const worker = b.addExecutable(.{
        .name = "recursive-pipeline-worker-v1",
        .root_module = worker_module,
    });
    const unit_module = b.createModule(.{
        .root_source_file = b.path("recursive_pipeline_worker_test_root.zig"),
        .target = ctx.target,
        .optimize = .Debug,
    });
    unit_module.addImport("stwo_artifact_store", b.dependency(
        "stwo_artifact_store",
        .{ .target = ctx.target, .optimize = .Debug },
    ).module("stwo_artifact_store"));
    const unit_tests = b.addTest(.{ .root_module = unit_module });
    const canonical_empty_module = support.createHarnessModule(
        b,
        "recursive_pipeline_worker_canonical_empty_v2_test.zig",
        ctx.target,
        .Debug,
        ctx.core,
        ctx.cpu_backend,
        ctx.frontend,
        ctx.integration,
    );
    canonical_empty_module.addImport("stwo_artifact_store", artifact_store);
    canonical_empty_module.addImport("stwo_prover_api", ctx.prover_api);
    canonical_empty_module.addImport("stwo_prover_engine", ctx.prover);
    canonical_empty_module.addImport("interop_postcard", ctx.postcard);
    const canonical_empty_names: []const []const u8 = &.{
        "stage103 describes only the field canonical-empty wrapper",
        "stage103 requires a replayed three-role parity authority",
        "stage103 fold child requires verifier-rerecorded live graph",
        "stage103 worker surface typechecks behind the unavailable authority",
    };
    const canonical_empty_tests = b.addTest(.{
        .root_module = canonical_empty_module,
        .filters = canonical_empty_names,
    });
    b.step(
        "test-recursive-pipeline-worker-canonical-empty-v2",
        "Run stage103 cold graph and live fold-child adapter gates",
    ).dependOn(&b.addRunArtifact(canonical_empty_tests).step);
    const native_leaf_v4_module = support.createHarnessModule(
        b,
        "recursive_pipeline_worker_native_leaf_v4_test.zig",
        ctx.target,
        .Debug,
        ctx.core,
        ctx.cpu_backend,
        ctx.frontend,
        ctx.integration,
    );
    native_leaf_v4_module.addImport("stwo_artifact_store", artifact_store);
    native_leaf_v4_module.addImport("stwo_prover_api", ctx.prover_api);
    native_leaf_v4_module.addImport("stwo_prover_engine", ctx.prover);
    native_leaf_v4_module.addImport("interop_postcard", ctx.postcard);
    const native_leaf_v4_names: []const []const u8 = &.{
        "stage101 exposes the exact seven-input proof contract",
        "stage101 rejects role ordinal codec and order mutations",
        "stage101 Zig semantic projection binds coordinate and ordered refs",
        "stage101 store-less hooks cannot mint admission",
    };
    const native_leaf_v4_tests = b.addTest(.{
        .root_module = native_leaf_v4_module,
        .filters = native_leaf_v4_names,
    });
    b.step(
        "test-recursive-pipeline-worker-native-leaf-v4",
        "Run stage101 CAS custody and fresh native-leaf adapter gates",
    ).dependOn(&b.addRunArtifact(native_leaf_v4_tests).step);
    const campaign_importer_module = support.createHarnessModule(
        b,
        "recursive_pipeline_incremental_campaign_importer_v4_test.zig",
        ctx.target,
        .Debug,
        ctx.core,
        ctx.cpu_backend,
        ctx.frontend,
        ctx.integration,
    );
    campaign_importer_module.addImport("stwo_artifact_store", artifact_store);
    campaign_importer_module.addImport("stwo_prover_api", ctx.prover_api);
    campaign_importer_module.addImport("stwo_prover_engine", ctx.prover);
    campaign_importer_module.addImport("interop_postcard", ctx.postcard);
    const campaign_importer_names: []const []const u8 = &.{
        "two-leaf campaign table roundtrips exact path-free Stage101 refs",
        "two-leaf campaign table rejects order role codec and manifest substitution",
        "two-leaf journal payload extraction retains canonical payload bytes",
        "three and five leaf campaign tables derive exact binary topology",
    };
    const campaign_importer_tests = b.addTest(.{
        .root_module = campaign_importer_module,
        .filters = campaign_importer_names,
    });
    const campaign_importer_run = b.addRunArtifact(campaign_importer_tests);
    campaign_importer_run.has_side_effects = true;
    b.step(
        "test-recursive-pipeline-incremental-campaign-importer-v4",
        "Run sealed V4 campaign CAS importer and path-free table gates",
    ).dependOn(support.ProofTestGuard.add(
        b,
        campaign_importer_run,
        campaign_importer_names,
        "incremental campaign importer V4 test identity guard",
    ));
    const campaign_import_command_module = support.createHarnessModule(
        b,
        "recursive_pipeline_incremental_campaign_import_command_v4_test.zig",
        ctx.target,
        .Debug,
        ctx.core,
        ctx.cpu_backend,
        ctx.frontend,
        ctx.integration,
    );
    campaign_import_command_module.addImport(
        "stwo_artifact_store",
        artifact_store,
    );
    campaign_import_command_module.addImport(
        "stwo_prover_api",
        ctx.prover_api,
    );
    campaign_import_command_module.addImport(
        "stwo_prover_engine",
        ctx.prover,
    );
    campaign_import_command_module.addImport(
        "interop_postcard",
        ctx.postcard,
    );
    const campaign_import_command_names: []const []const u8 = &.{
        "campaign import receipt is canonical and path-free",
        "canonical Ethereum profile retains exact 210-count admission policy",
        "campaign import command resolves exact options and rejects drift",
        "campaign import command rejects publication CAS and receipt overlap",
    };
    const campaign_import_command_tests = b.addTest(.{
        .root_module = campaign_import_command_module,
        .filters = campaign_import_command_names,
    });
    const campaign_import_command_run = b.addRunArtifact(
        campaign_import_command_tests,
    );
    campaign_import_command_run.has_side_effects = true;
    const campaign_import_command_root = support.createHarnessModule(
        b,
        "recursive_pipeline_incremental_campaign_import_command_v4.zig",
        ctx.target,
        ctx.optimize,
        ctx.core,
        ctx.cpu_backend,
        ctx.frontend,
        ctx.integration,
    );
    campaign_import_command_root.addImport(
        "stwo_artifact_store",
        artifact_store,
    );
    campaign_import_command_root.addImport(
        "stwo_prover_api",
        ctx.prover_api,
    );
    campaign_import_command_root.addImport(
        "stwo_prover_engine",
        ctx.prover,
    );
    campaign_import_command_root.addImport(
        "interop_postcard",
        ctx.postcard,
    );
    const campaign_import_command = b.addExecutable(.{
        .name = "recursive-pipeline-incremental-campaign-import-v4",
        .root_module = campaign_import_command_root,
    });
    const campaign_import_command_install = b.addInstallArtifact(
        campaign_import_command,
        .{},
    );
    b.step(
        "build-recursive-pipeline-incremental-campaign-import-v4",
        "Build the sealed V4 campaign CAS importer command",
    ).dependOn(&campaign_import_command_install.step);
    const campaign_import_command_step = b.step(
        "test-recursive-pipeline-incremental-campaign-import-command-v4",
        "Compile and test the sealed V4 campaign CAS importer command",
    );
    campaign_import_command_step.dependOn(support.ProofTestGuard.add(
        b,
        campaign_import_command_run,
        campaign_import_command_names,
        "incremental campaign import command V4 test identity guard",
    ));
    campaign_import_command_step.dependOn(&campaign_import_command.step);
    const campaign_cold_describe_module = support.createHarnessModule(
        b,
        "recursive_pipeline_incremental_campaign_cold_describe_v4_test.zig",
        ctx.target,
        .Debug,
        ctx.core,
        ctx.cpu_backend,
        ctx.frontend,
        ctx.integration,
    );
    campaign_cold_describe_module.addImport(
        "stwo_artifact_store",
        artifact_store,
    );
    campaign_cold_describe_module.addImport(
        "stwo_prover_api",
        ctx.prover_api,
    );
    campaign_cold_describe_module.addImport(
        "stwo_prover_engine",
        ctx.prover,
    );
    campaign_cold_describe_module.addImport(
        "interop_postcard",
        ctx.postcard,
    );
    const campaign_cold_describe_names: []const []const u8 = &.{
        "cold campaign description is canonical path-free and topology-bound",
        "cold campaign description rejects receipt table and topology mutations",
        "cold describe command accepts only receipt and Zig CAS inputs",
        "cold describe rejects noncanonical STWCIR04 before CAS access",
    };
    const campaign_cold_describe_tests = b.addTest(.{
        .root_module = campaign_cold_describe_module,
        .filters = campaign_cold_describe_names,
    });
    const campaign_cold_describe_run = b.addRunArtifact(
        campaign_cold_describe_tests,
    );
    campaign_cold_describe_run.has_side_effects = true;
    const campaign_cold_describe_command_root = support.createHarnessModule(
        b,
        "recursive_pipeline_incremental_campaign_cold_describe_command_v4.zig",
        ctx.target,
        ctx.optimize,
        ctx.core,
        ctx.cpu_backend,
        ctx.frontend,
        ctx.integration,
    );
    campaign_cold_describe_command_root.addImport(
        "stwo_artifact_store",
        artifact_store,
    );
    campaign_cold_describe_command_root.addImport(
        "stwo_prover_api",
        ctx.prover_api,
    );
    campaign_cold_describe_command_root.addImport(
        "stwo_prover_engine",
        ctx.prover,
    );
    campaign_cold_describe_command_root.addImport(
        "interop_postcard",
        ctx.postcard,
    );
    const campaign_cold_describe_command = b.addExecutable(.{
        .name = "recursive-pipeline-incremental-campaign-cold-describe-v4",
        .root_module = campaign_cold_describe_command_root,
    });
    const campaign_cold_describe_command_install = b.addInstallArtifact(
        campaign_cold_describe_command,
        .{},
    );
    b.step(
        "build-recursive-pipeline-incremental-campaign-cold-describe-v4",
        "Build the cold-validated V4 campaign worker-description command",
    ).dependOn(&campaign_cold_describe_command_install.step);
    const campaign_cold_describe_step = b.step(
        "test-recursive-pipeline-incremental-campaign-cold-describe-v4",
        "Compile and test the cold-validated path-free campaign handoff",
    );
    campaign_cold_describe_step.dependOn(support.ProofTestGuard.add(
        b,
        campaign_cold_describe_run,
        campaign_cold_describe_names,
        "incremental campaign cold-describe V4 test identity guard",
    ));
    campaign_cold_describe_step.dependOn(
        &campaign_cold_describe_command.step,
    );
    const campaign_worker_description_module = support.createHarnessModule(
        b,
        "recursive_pipeline_incremental_campaign_worker_description_v4_test.zig",
        ctx.target,
        .Debug,
        ctx.core,
        ctx.cpu_backend,
        ctx.frontend,
        ctx.integration,
    );
    campaign_worker_description_module.addImport(
        "stwo_artifact_store",
        artifact_store,
    );
    campaign_worker_description_module.addImport(
        "stwo_prover_api",
        ctx.prover_api,
    );
    campaign_worker_description_module.addImport(
        "stwo_prover_engine",
        ctx.prover,
    );
    campaign_worker_description_module.addImport(
        "interop_postcard",
        ctx.postcard,
    );
    const campaign_worker_description_names: []const []const u8 = &.{
        "campaign worker description emits exact runtime-derived 2 3 and 5 leaf projections",
        "campaign worker description rejects row order count input and semantic drift",
        "campaign worker description codec is canonical path-free and size-bounded",
    };
    const campaign_worker_description_tests = b.addTest(.{
        .root_module = campaign_worker_description_module,
        .filters = campaign_worker_description_names,
    });
    const campaign_worker_description_run = b.addRunArtifact(
        campaign_worker_description_tests,
    );
    campaign_worker_description_run.has_side_effects = true;
    const campaign_worker_description_step = b.step(
        "test-recursive-pipeline-incremental-campaign-worker-description-v4",
        "Test the path-free authenticated Stage101 planner row projection",
    );
    campaign_worker_description_step.dependOn(support.ProofTestGuard.add(
        b,
        campaign_worker_description_run,
        campaign_worker_description_names,
        "incremental campaign worker-description V4 identity guard",
    ));
    campaign_worker_description_step.dependOn(
        &campaign_cold_describe_command.step,
    );
    const acceptance = b.addSystemCommand(&.{"python3"});
    acceptance.addFileArg(b.path(
        "recursive_pipeline_worker_acceptance_fixture_v1.py",
    ));
    acceptance.addArg("--worker");
    acceptance.addArtifactArg(worker);
    acceptance.setCwd(.{ .cwd_relative = b.pathFromRoot("../../..") });
    const check = b.step(
        "check-recursive-pipeline-worker-v1",
        "Compile the persistent recursive pipeline worker and protocol tests",
    );
    check.dependOn(&worker.step);
    check.dependOn(&unit_tests.step);
    const semantic = b.step(
        "test-recursive-pipeline-worker-v1",
        "Run protocol tests and real subprocess CAS/lease acceptance",
    );
    semantic.dependOn(&b.addRunArtifact(unit_tests).step);
    semantic.dependOn(&acceptance.step);
}

fn addPoseidonLeafComponentCheck(ctx: anytype) void {
    const b = ctx.b;
    const component = b.createModule(.{
        .root_source_file = b.path(
            "ethereum_poseidon_v4_leaf_component_test_root.zig",
        ),
        .target = ctx.target,
        .optimize = .Debug,
    });
    component.addImport("stwo_core", ctx.core);
    component.addImport("stwo_prover_api", ctx.prover_api);
    component.addImport("stwo_prover_engine", ctx.prover);
    component.addImport("stwo_cpu_backend", ctx.cpu_backend);
    component.addImport("stwo_riscv_frontend", ctx.frontend);
    component.addImport("interop_postcard", ctx.postcard);
    const tests = b.addTest(.{ .root_module = component });
    const context = b.createModule(.{
        .root_source_file = .{ .cwd_relative = b.pathFromRoot(
            "../../frontends/riscv/ethereum_leaf_context_v1_test_root.zig",
        ) },
        .target = ctx.target,
        .optimize = .Debug,
    });
    context.addImport("stwo_core", ctx.core);
    context.addImport("stwo_prover_engine", ctx.prover);
    const context_tests = b.addTest(.{
        .root_module = context,
        .filters = &.{
            "Ethereum leaf context preserves legacy placement and authenticates V2",
        },
    });
    const profile = b.createModule(.{
        .root_source_file = .{ .cwd_relative = b.pathFromRoot(
            "../../frontends/riscv/vm_air_profile_v2_test_root.zig",
        ) },
        .target = ctx.target,
        .optimize = .Debug,
    });
    profile.addImport("stwo_core", ctx.core);
    profile.addImport("stwo_prover_engine", ctx.prover);
    const profile_tests = b.addTest(.{
        .root_module = profile,
        .filters = &.{"authenticated VM AIR ProfileV2"},
    });
    const context_v2 = b.createModule(.{
        .root_source_file = .{ .cwd_relative = b.pathFromRoot(
            "../../frontends/riscv/vm_leaf_context_v2_test_root.zig",
        ) },
        .target = ctx.target,
        .optimize = .Debug,
    });
    context_v2.addImport("stwo_core", ctx.core);
    context_v2.addImport("stwo_prover_engine", ctx.prover);
    const context_v2_tests = b.addTest(.{
        .root_module = context_v2,
        .filters = &.{"SegmentV2 VM leaf ContextV2"},
    });
    const check = b.step(
        "check-ethereum-poseidon-v4-leaf-component",
        "Diagnostic-only Debug compile of the narrow Poseidon v4 leaf surface",
    );
    check.dependOn(&tests.step);
    check.dependOn(&context_tests.step);
    check.dependOn(&profile_tests.step);
    check.dependOn(&context_v2_tests.step);
    const semantic = b.step(
        "test-ethereum-poseidon-v4-leaf-component",
        "Run narrow Poseidon v4 product, placement, and context authority tests",
    );
    semantic.dependOn(&b.addRunArtifact(tests).step);
    semantic.dependOn(&b.addRunArtifact(context_tests).step);
    semantic.dependOn(&b.addRunArtifact(profile_tests).step);
    semantic.dependOn(&b.addRunArtifact(context_v2_tests).step);
}

fn addPoseidonLeafProcessGate(ctx: anytype) void {
    const b = ctx.b;
    const smoke_path = b.option(
        []const u8,
        "ethereum-poseidon-smoke-elf",
        "Absolute path to the retained Ethereum recovery ABI smoke ELF",
    ) orelse return;
    const product_module = b.createModule(.{
        .root_source_file = .{ .cwd_relative = b.pathFromRoot(
            "../../products/riscv_cpu/ethereum_block_proof_main.zig",
        ) },
        .target = ctx.target,
        .optimize = ctx.optimize,
    });
    product_module.addImport("stwo_riscv_cpu_integration", ctx.integration);
    const product = b.addExecutable(.{
        .name = "stwo-ethereum-block-proof",
        .root_module = product_module,
    });
    const mutator = b.addExecutable(.{
        .name = "ethereum-poseidon-v4-request-mutator",
        .root_module = support.createHarnessModule(
            b,
            "ethereum_poseidon_leaf_product_request_mutator.zig",
            ctx.target,
            ctx.optimize,
            ctx.core,
            ctx.cpu_backend,
            ctx.frontend,
            ctx.integration,
        ),
    });
    const check = b.step(
        "check-ethereum-poseidon-v4-leaf-process",
        "Compile the Poseidon v4 leaf multiplexer and mutation harness",
    );
    check.dependOn(&product.step);
    check.dependOn(&mutator.step);
    const fixture = b.addWriteFiles();
    const input = fixture.add("ethereum-smoke-input.bin", "");
    const expected_output = fixture.add(
        "ethereum-smoke-output.bin",
        &[_]u8{
            0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12, 0x5d, 0x5d,
            0xfc, 0xb7, 0xb8, 0xc2, 0x65, 0x90, 0x29, 0x39, 0x5b, 0xdf,
        },
    );
    const elf: std.Build.LazyPath = .{ .cwd_relative = if (std.fs.path.isAbsolute(smoke_path)) smoke_path else b.pathFromRoot(smoke_path) };

    const materialize = b.addRunArtifact(product);
    materialize.addArg("ethereum-block-leaf-materialize");
    materialize.addArg("--elf");
    materialize.addFileArg(elf);
    materialize.addArg("--expected-output");
    materialize.addFileArg(expected_output);
    materialize.addArg("--input");
    materialize.addFileArg(input);
    materialize.addArg("--journal");
    const journal = materialize.addOutputFileArg("execution-v3.ndjson");
    materialize.addArgs(&.{
        "--proof-profile",
        "stwo.ethereum-segment-v3-recursive-poseidon2-m31-v1",
        "--result",
    });
    _ = materialize.addOutputFileArg("materialization-v2.json");
    materialize.addArgs(&.{
        "--segment-count",
        "2",
        "--segment-step-budget",
        "628",
        "--source-request",
    });
    const source_request = materialize.addOutputFileArg("source-v2.json");
    materialize.addArg("--source-root-parent");
    const source_parent = materialize.addOutputDirectoryArg(
        "leaf-source-publication",
    );
    const source_root = source_parent.path(
        b,
        artifact_io.ethereum_leaf_source_basename,
    );
    materialize.expectStdOutEqual("");
    materialize.expectStdErrEqual("");

    const request = b.addRunArtifact(product);
    request.addArgs(&.{ "ethereum-poseidon-v4-leaf-request", "--producer" });
    request.addArtifactArg(product);
    request.addArgs(&.{"--result"});
    const request_path = request.addOutputFileArg("leaf-request.json");
    request.addArgs(&.{
        "--segment-index",
        "0",
        "--session-id",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "--source-request",
    });
    request.addFileArg(source_request);
    request.addArg("--source-segment");
    request.addFileArg(source_root.path(b, "segment-000000.stwesg31"));
    request.addArg("--verifier");
    request.addArtifactArg(product);
    request.expectStdOutEqual("");
    request.expectStdErrEqual("");

    const produce = b.addRunArtifact(product);
    produce.addArgs(&.{ "ethereum-poseidon-v4-leaf-producer", "--proof" });
    const proof = produce.addOutputFileArg("poseidon-v4-leaf.stw");
    produce.addArg("--request");
    produce.addFileArg(request_path);
    produce.addArg("--result");
    const producer_result = produce.addOutputFileArg("producer-result.json");
    produce.expectStdOutEqual("");
    produce.expectStdErrEqual("");

    const verify = b.addRunArtifact(product);
    verify.addArgs(&.{ "ethereum-poseidon-v4-leaf-verifier", "--proof" });
    verify.addFileArg(proof);
    verify.addArg("--request");
    verify.addFileArg(request_path);
    verify.addArg("--result");
    const verifier_result = verify.addOutputFileArg("verifier-result.json");
    verify.addArg("--timing-receipt");
    const verifier_timing_receipt = verify.addOutputFileArg(
        "verifier-timing-receipt.json",
    );
    verify.expectStdOutEqual("");
    verify.expectStdErrEqual("");

    const mutate = b.addRunArtifact(mutator);
    mutate.addFileArg(request_path);
    mutate.addFileArg(source_root.path(b, "segment-000001.stwesg31"));
    const bad_request = mutate.addOutputFileArg("unrelated-source-request.json");
    mutate.expectStdOutEqual("");
    mutate.expectStdErrEqual("");
    const reject = b.addRunArtifact(product);
    reject.addArgs(&.{ "ethereum-poseidon-v4-leaf-verifier", "--proof" });
    reject.addFileArg(proof);
    reject.addArg("--request");
    reject.addFileArg(bad_request);
    reject.addArg("--result");
    const forbidden_verifier_result = reject.addOutputFileArg(
        "forbidden-verifier-result.json",
    );
    reject.addArg("--timing-receipt");
    const forbidden_timing_receipt = reject.addOutputFileArg(
        "forbidden-verifier-timing-receipt.json",
    );
    reject.expectExitCode(1);
    reject.expectStdOutEqual("");
    reject.expectStdErrEqual("error: VerifiedPoseidonSourceMismatch\n");
    const reject_stdout = reject.captureStdOut();
    const reject_stderr = reject.captureStdErr();

    _ = journal;
    _ = producer_result;
    _ = verifier_result;
    _ = verifier_timing_receipt;
    _ = forbidden_verifier_result;
    _ = forbidden_timing_receipt;
    _ = reject_stdout;
    _ = reject_stderr;
    const step = b.step(
        "test-ethereum-poseidon-v4-leaf-process",
        "Materialize, prove, and fresh-verify one Poseidon v4 leaf",
    );
    step.dependOn(&verify.step);
    step.dependOn(&reject.step);
}
