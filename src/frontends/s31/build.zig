const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const opts = .{ .target = target, .optimize = optimize };
    const cpu = b.dependency("stwo_circuit_cpu_integration", opts).module("stwo_circuit_cpu_integration");
    const core = cpu.import_table.get("stwo_core") orelse @panic("circuit CPU module is missing core");
    const circuit = cpu.import_table.get("stwo_circuit_frontend") orelse @panic("circuit CPU module is missing frontend");
    const wire = cpu.import_table.get("stwo_circuit_recursion_wire") orelse @panic("circuit CPU module is missing wire");
    const source_asset: std.Build.LazyPath = if (b.option([]const u8, "s31-source", "Absolute path to a normalized S31 source file")) |path|
        .{ .cwd_relative = path }
    else
        b.path("examples/affine4.s31.json");
    const program_name = b.option([]const u8, "s31-name", "Build artifact name for the selected program") orelse "affine4";
    const source_version = b.option(u32, "s31-version", "Normalized source version (0 or 1)") orelse 0;
    const lowering = b.option([]const u8, "s31-lowering", "gate, chip, sparse-gate, sparse-chip, sparse-wide-gate, direct-gate, direct-chip, sha-joint, or sha-shift proof lowering") orelse "gate";
    if (!std.mem.eql(u8, lowering, "gate") and !std.mem.eql(u8, lowering, "chip") and
        !std.mem.eql(u8, lowering, "sparse-gate") and !std.mem.eql(u8, lowering, "sparse-chip") and
        !std.mem.eql(u8, lowering, "sparse-wide-gate") and
        !std.mem.eql(u8, lowering, "direct-gate") and !std.mem.eql(u8, lowering, "direct-chip") and
        !std.mem.eql(u8, lowering, "sha-joint") and !std.mem.eql(u8, lowering, "sha-shift"))
        @panic("invalid s31-lowering");
    const fri_fold_step = b.option(u32, "s31-fri-fold-step", "FRI folds per commitment for gate or sparse-wide-gate (1 or 4)") orelse 1;
    if ((fri_fold_step != 1 and fri_fold_step != 4) or
        (fri_fold_step != 1 and !std.mem.eql(u8, lowering, "gate") and !std.mem.eql(u8, lowering, "sparse-wide-gate")))
        @panic("FRI fold step 4 requires gate or sparse-wide-gate lowering; supported steps are 1 and 4");
    const s31_options = b.addOptions();
    s31_options.addOption(bool, "chip_mode", std.mem.eql(u8, lowering, "chip") or std.mem.eql(u8, lowering, "sparse-chip") or std.mem.eql(u8, lowering, "direct-chip"));
    s31_options.addOption(bool, "sparse_mode", std.mem.startsWith(u8, lowering, "sparse-"));
    s31_options.addOption(bool, "wide_mode", std.mem.eql(u8, lowering, "sparse-wide-gate"));
    s31_options.addOption(bool, "direct_mode", std.mem.startsWith(u8, lowering, "direct-"));
    s31_options.addOption(bool, "sha_joint_mode", std.mem.eql(u8, lowering, "sha-joint"));
    s31_options.addOption(bool, "sha_shift_mode", std.mem.eql(u8, lowering, "sha-shift"));
    s31_options.addOption(u32, "fri_fold_step", fri_fold_step);
    s31_options.addOption([]const u8, "stdlib_lock_sha256", b.option([]const u8, "s31-stdlib-sha256", "Pinned S31 standard library lock digest") orelse "");

    const sha_postcard = b.createModule(.{ .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../interop/postcard.zig") }, .target = target, .optimize = optimize });
    sha_postcard.addImport("stwo_core", core);
    const official_air = b.createModule(.{ .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../../vectors/circuit/official/circuit_air.air_programs_v1.bin") } });
    const frontend = b.addModule("stwo_s31_prototype", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    frontend.addImport("stwo_core", core);
    frontend.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("circuit CPU module is missing prover engine"));
    frontend.addImport("stwo_circuit_frontend", circuit);
    frontend.addImport("stwo_circuit_cpu_integration", cpu);
    frontend.addImport("stwo_cairo_frontend", cpu.import_table.get("stwo_cairo_frontend") orelse @panic("missing Cairo frontend"));
    frontend.addImport("interop_postcard", sha_postcard);
    frontend.addImport("s31_air_programs", official_air);
    const sha_provider = b.createModule(.{
        .root_source_file = b.path("../riscv/sha256_s31_provider.zig"),
        .target = target,
        .optimize = optimize,
    });
    sha_provider.addImport("stwo_core", core);
    sha_provider.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("missing prover engine"));
    frontend.addImport("s31_poseidon_ref", sha_provider);
    frontend.addImport("s31_sha_provider", sha_provider);

    const tests = b.addRunArtifact(b.addTest(.{ .root_module = frontend }));
    const test_step = b.step("test", "Test the S31 prototype parser, evaluator and circuit compiler");
    test_step.dependOn(&tests.step);
    const bitcoin_step_inspector_root = b.createModule(.{
        .root_source_file = b.path("inspect_bitcoin_fold_step.zig"),
        .target = target,
        .optimize = optimize,
    });
    bitcoin_step_inspector_root.addImport("stwo_s31_prototype", frontend);
    bitcoin_step_inspector_root.addImport("stwo_circuit_frontend", circuit);
    const bitcoin_step_inspector = b.addExecutable(.{
        .name = "s31-inspect-bitcoin-fold-step",
        .root_module = bitcoin_step_inspector_root,
    });
    b.step("inspect-bitcoin-fold-step", "Inspect witness-free Bitcoin fold-step circuit cost")
        .dependOn(&b.addRunArtifact(bitcoin_step_inspector).step);
    const bitcoin_fold_inspector_root = b.createModule(.{
        .root_source_file = b.path("inspect_bitcoin_chain_fold.zig"),
        .target = target,
        .optimize = optimize,
    });
    bitcoin_fold_inspector_root.addImport("stwo_s31_prototype", frontend);
    bitcoin_fold_inspector_root.addImport("stwo_core", core);
    bitcoin_fold_inspector_root.addImport("stwo_circuit_frontend", circuit);
    bitcoin_fold_inspector_root.addImport("stwo_circuit_cpu_integration", cpu);
    bitcoin_fold_inspector_root.addAnonymousImport("s31_air_projection", .{ .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../../vectors/circuit/official/compiled_air_constraints_v1.bin") } });
    bitcoin_fold_inspector_root.addAnonymousImport("s31_fold_reference", .{ .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../../design/s31/measurements/bitcoin-sparse-wide-fold-stages-v1-2026-10-07.json") } });
    const bitcoin_fold_inspector = b.addExecutable(.{
        .name = "s31-inspect-bitcoin-chain-fold",
        .root_module = bitcoin_fold_inspector_root,
    });
    b.step("inspect-bitcoin-chain-fold", "Inspect complete candidate Bitcoin chain-fold topology")
        .dependOn(&b.addRunArtifact(bitcoin_fold_inspector).step);
    const bitcoin_fold_test_root = b.createModule(.{
        .root_source_file = b.path("bitcoin_chain_fold.zig"),
        .target = target,
        .optimize = optimize,
    });
    bitcoin_fold_test_root.addImport("stwo_s31_prototype", frontend);
    bitcoin_fold_test_root.addImport("stwo_core", core);
    bitcoin_fold_test_root.addImport("stwo_circuit_frontend", circuit);
    bitcoin_fold_test_root.addImport("stwo_circuit_cpu_integration", cpu);
    const bitcoin_fold_tests = b.addRunArtifact(b.addTest(.{
        .root_module = bitcoin_fold_test_root,
        .filters = &.{"Bitcoin fold chooses a trusted base or the authenticated previous digest"},
    }));
    test_step.dependOn(&bitcoin_fold_tests.step);
    const bitcoin_anchor_test_root = b.createModule(.{
        .root_source_file = b.path("bitcoin_chain_anchor.zig"),
        .target = target,
        .optimize = optimize,
    });
    bitcoin_anchor_test_root.addImport("stwo_core", core);
    bitcoin_anchor_test_root.addImport("stwo_circuit_frontend", circuit);
    const bitcoin_anchor_tests = b.addRunArtifact(b.addTest(.{
        .root_module = bitcoin_anchor_test_root,
        .filters = &.{"Bitcoin checkpoint anchor has the same AIR in value and topology modes"},
    }));
    test_step.dependOn(&bitcoin_anchor_tests.step);
    const anchor_proof_test_root = b.createModule(.{
        .root_source_file = b.path("bitcoin_chain_anchor_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    anchor_proof_test_root.addImport("stwo_core", core);
    anchor_proof_test_root.addImport("stwo_circuit_frontend", circuit);
    anchor_proof_test_root.addImport("stwo_circuit_cpu_integration", cpu);
    anchor_proof_test_root.addImport("stwo_s31_prototype", frontend);
    anchor_proof_test_root.addImport("stwo_cairo_frontend", cpu.import_table.get("stwo_cairo_frontend") orelse @panic("missing Cairo frontend"));
    anchor_proof_test_root.addImport("interop_postcard", sha_postcard);
    anchor_proof_test_root.addImport("s31_air_programs", official_air);
    anchor_proof_test_root.addAnonymousImport("s31_air_projection", .{
        .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../../vectors/circuit/official/compiled_air_constraints_v1.bin") },
    });
    const private_bridge_test_root = b.createModule(.{
        .root_source_file = b.path("private_boundary_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    private_bridge_test_root.addImport("stwo_core", core);
    private_bridge_test_root.addImport("stwo_circuit_frontend", circuit);
    private_bridge_test_root.addImport("stwo_circuit_cpu_integration", cpu);
    private_bridge_test_root.addImport("stwo_cairo_frontend", cpu.import_table.get("stwo_cairo_frontend") orelse @panic("missing Cairo frontend"));
    private_bridge_test_root.addImport("interop_postcard", sha_postcard);
    private_bridge_test_root.addImport("s31_air_programs", official_air);
    const private_bridge_tests = b.addRunArtifact(b.addTest(.{ .root_module = private_bridge_test_root }));
    test_step.dependOn(&private_bridge_tests.step);
    const sha_joint_test_root = b.createModule(.{
        .root_source_file = b.path("sha_joint_prover_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    sha_joint_test_root.addImport("stwo_core", core);
    sha_joint_test_root.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("missing prover engine"));
    sha_joint_test_root.addImport("stwo_circuit_frontend", circuit);
    sha_joint_test_root.addImport("stwo_circuit_cpu_integration", cpu);
    sha_joint_test_root.addImport("stwo_cairo_frontend", cpu.import_table.get("stwo_cairo_frontend") orelse @panic("missing Cairo frontend"));
    sha_joint_test_root.addImport("s31_sha_provider", sha_provider);
    sha_joint_test_root.addImport("s31_poseidon_ref", sha_provider);
    sha_joint_test_root.addImport("interop_postcard", sha_postcard);
    sha_joint_test_root.addImport("s31_air_programs", official_air);
    const sha_joint_tests = b.addRunArtifact(b.addTest(.{ .root_module = sha_joint_test_root }));
    b.step("test-sha-joint", "Compile and test one-proof circuit plus packed SHA integration")
        .dependOn(&sha_joint_tests.step);
    const sha_joint_batch2_test_root = b.createModule(.{
        .root_source_file = b.path("sha_joint_batch2_prover_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    sha_joint_batch2_test_root.addImport("stwo_core", core);
    sha_joint_batch2_test_root.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("missing prover engine"));
    sha_joint_batch2_test_root.addImport("stwo_circuit_frontend", circuit);
    sha_joint_batch2_test_root.addImport("stwo_circuit_cpu_integration", cpu);
    sha_joint_batch2_test_root.addImport("stwo_cairo_frontend", cpu.import_table.get("stwo_cairo_frontend") orelse @panic("missing Cairo frontend"));
    sha_joint_batch2_test_root.addImport("s31_sha_provider", sha_provider);
    sha_joint_batch2_test_root.addImport("s31_poseidon_ref", sha_provider);
    sha_joint_batch2_test_root.addImport("interop_postcard", sha_postcard);
    sha_joint_batch2_test_root.addImport("s31_air_programs", official_air);
    const sha_joint_batch2_tests = b.addRunArtifact(b.addTest(.{ .root_module = sha_joint_batch2_test_root }));
    b.step("test-sha-joint-batch2", "Prove and verify two private Bitcoin headers with one SHA AIR proof")
        .dependOn(&sha_joint_batch2_tests.step);
    const sha_round_direct_test_root = b.createModule(.{
        .root_source_file = b.path("sha_round_direct_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    sha_round_direct_test_root.addImport("stwo_core", core);
    sha_round_direct_test_root.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("missing prover engine"));
    sha_round_direct_test_root.addImport("stwo_circuit_cpu_integration", cpu);
    sha_round_direct_test_root.addImport("s31_sha_provider", sha_provider);
    sha_round_direct_test_root.addImport("interop_postcard", sha_postcard);
    const sha_round_direct_tests = b.addRunArtifact(b.addTest(.{ .root_module = sha_round_direct_test_root }));
    b.step("test-sha-round-direct", "Prove and natively verify the table-free SHA-256 round AIR")
        .dependOn(&sha_round_direct_tests.step);
    const sha_schedule_direct_test_root = b.createModule(.{
        .root_source_file = b.path("sha_schedule_direct_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    sha_schedule_direct_test_root.addImport("stwo_core", core);
    sha_schedule_direct_test_root.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("missing prover engine"));
    sha_schedule_direct_test_root.addImport("stwo_circuit_cpu_integration", cpu);
    sha_schedule_direct_test_root.addImport("s31_sha_provider", sha_provider);
    sha_schedule_direct_test_root.addImport("interop_postcard", sha_postcard);
    const sha_schedule_direct_tests = b.addRunArtifact(b.addTest(.{ .root_module = sha_schedule_direct_test_root }));
    b.step("test-sha-schedule-direct", "Prove and natively verify the table-free SHA-256 schedule AIR")
        .dependOn(&sha_schedule_direct_tests.step);
    const sha_feed_direct_test_root = b.createModule(.{
        .root_source_file = b.path("sha_feed_direct_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    sha_feed_direct_test_root.addImport("stwo_core", core);
    sha_feed_direct_test_root.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("missing prover engine"));
    sha_feed_direct_test_root.addImport("stwo_circuit_cpu_integration", cpu);
    sha_feed_direct_test_root.addImport("s31_sha_provider", sha_provider);
    sha_feed_direct_test_root.addImport("interop_postcard", sha_postcard);
    const sha_feed_direct_tests = b.addRunArtifact(b.addTest(.{ .root_module = sha_feed_direct_test_root }));
    b.step("test-sha-feed-direct", "Prove and natively verify the table-free SHA-256 feed-forward AIR")
        .dependOn(&sha_feed_direct_tests.step);
    const sha_caller_stream_test_root = b.createModule(.{
        .root_source_file = b.path("sha_caller_stream_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    sha_caller_stream_test_root.addImport("stwo_core", core);
    sha_caller_stream_test_root.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("missing prover engine"));
    sha_caller_stream_test_root.addImport("stwo_circuit_cpu_integration", cpu);
    sha_caller_stream_test_root.addImport("s31_sha_provider", sha_provider);
    sha_caller_stream_test_root.addImport("interop_postcard", sha_postcard);
    const sha_caller_stream_tests = b.addRunArtifact(b.addTest(.{ .root_module = sha_caller_stream_test_root }));
    b.step("test-sha-caller-stream", "Prove and natively verify the streamed SHA256d caller AIR")
        .dependOn(&sha_caller_stream_tests.step);
    const sha_round_word_logup_test_root = b.createModule(.{
        .root_source_file = b.path("sha_round_direct_word_logup.zig"),
        .target = target,
        .optimize = optimize,
    });
    sha_round_word_logup_test_root.addImport("stwo_core", core);
    sha_round_word_logup_test_root.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("missing prover engine"));
    sha_round_word_logup_test_root.addImport("s31_sha_provider", sha_provider);
    const sha_round_word_logup_tests = b.addRunArtifact(b.addTest(.{ .root_module = sha_round_word_logup_test_root }));
    b.step("test-sha-round-word-logup", "Check committed direct SHA round word-bus interactions")
        .dependOn(&sha_round_word_logup_tests.step);
    const sha_round_word_proof_root = b.createModule(.{
        .root_source_file = b.path("sha_round_direct_word_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    sha_round_word_proof_root.addImport("stwo_core", core);
    sha_round_word_proof_root.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("missing prover engine"));
    sha_round_word_proof_root.addImport("stwo_circuit_cpu_integration", cpu);
    sha_round_word_proof_root.addImport("s31_sha_provider", sha_provider);
    sha_round_word_proof_root.addImport("interop_postcard", sha_postcard);
    const sha_round_word_proof_tests = b.addRunArtifact(b.addTest(.{ .root_module = sha_round_word_proof_root }));
    b.step("test-sha-round-word-proof", "Prove direct SHA rounds and their committed word lookup in one STARK")
        .dependOn(&sha_round_word_proof_tests.step);
    const sha_round_shift_word_proof_root = b.createModule(.{
        .root_source_file = b.path("sha_round_shift_word_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    sha_round_shift_word_proof_root.addImport("stwo_core", core);
    sha_round_shift_word_proof_root.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("missing prover engine"));
    sha_round_shift_word_proof_root.addImport("stwo_circuit_cpu_integration", cpu);
    sha_round_shift_word_proof_root.addImport("s31_sha_provider", sha_provider);
    sha_round_shift_word_proof_root.addImport("interop_postcard", sha_postcard);
    const sha_round_shift_word_proof_tests = b.addRunArtifact(b.addTest(.{ .root_module = sha_round_shift_word_proof_root }));
    b.step("test-sha-round-shift-word-proof", "Prove shift-register SHA rounds and committed word lookup in one STARK")
        .dependOn(&sha_round_shift_word_proof_tests.step);
    const sha_schedule_word_proof_root = b.createModule(.{
        .root_source_file = b.path("sha_schedule_direct_word_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    sha_schedule_word_proof_root.addImport("stwo_core", core);
    sha_schedule_word_proof_root.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("missing prover engine"));
    sha_schedule_word_proof_root.addImport("stwo_circuit_cpu_integration", cpu);
    sha_schedule_word_proof_root.addImport("s31_sha_provider", sha_provider);
    sha_schedule_word_proof_root.addImport("interop_postcard", sha_postcard);
    const sha_schedule_word_proof_tests = b.addRunArtifact(b.addTest(.{ .root_module = sha_schedule_word_proof_root }));
    b.step("test-sha-schedule-word", "Prove direct SHA schedule and its committed word lookup in one STARK")
        .dependOn(&sha_schedule_word_proof_tests.step);
    const sha_caller_bus_proof_root = b.createModule(.{
        .root_source_file = b.path("sha_caller_stream_bus_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    sha_caller_bus_proof_root.addImport("stwo_core", core);
    sha_caller_bus_proof_root.addImport("stwo_circuit_frontend", circuit);
    sha_caller_bus_proof_root.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("missing prover engine"));
    sha_caller_bus_proof_root.addImport("stwo_circuit_cpu_integration", cpu);
    sha_caller_bus_proof_root.addImport("s31_sha_provider", sha_provider);
    sha_caller_bus_proof_root.addImport("interop_postcard", sha_postcard);
    const sha_caller_bus_proof_tests = b.addRunArtifact(b.addTest(.{ .root_module = sha_caller_bus_proof_root }));
    b.step("test-sha-caller-stream-bus", "Prove the streamed SHA caller and its committed Gate/word lookups")
        .dependOn(&sha_caller_bus_proof_tests.step);
    const sha_direct_gate_closure_root = b.createModule(.{
        .root_source_file = b.path("sha_direct_gate_closure_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    sha_direct_gate_closure_root.addImport("stwo_core", core);
    sha_direct_gate_closure_root.addImport("stwo_circuit_frontend", circuit);
    sha_direct_gate_closure_root.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("missing prover engine"));
    sha_direct_gate_closure_root.addImport("stwo_circuit_cpu_integration", cpu);
    sha_direct_gate_closure_root.addImport("s31_sha_provider", sha_provider);
    sha_direct_gate_closure_root.addImport("s31_poseidon_ref", sha_provider);
    const sha_direct_gate_closure_tests = b.addRunArtifact(b.addTest(.{ .root_module = sha_direct_gate_closure_root }));
    b.step("test-sha-direct-gate-closure", "Check direct caller Gate lookup against the Bitcoin sparse-wide circuit")
        .dependOn(&sha_direct_gate_closure_tests.step);
    const sha_direct_private_join_root = b.createModule(.{
        .root_source_file = b.path("sha_direct_private_join_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    sha_direct_private_join_root.addImport("stwo_core", core);
    sha_direct_private_join_root.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("missing prover engine"));
    sha_direct_private_join_root.addImport("stwo_circuit_cpu_integration", cpu);
    sha_direct_private_join_root.addImport("stwo_circuit_frontend", circuit);
    sha_direct_private_join_root.addImport("s31_sha_provider", sha_provider);
    sha_direct_private_join_root.addImport("interop_postcard", sha_postcard);
    const sha_direct_private_join_tests = b.addRunArtifact(b.addTest(.{ .root_module = sha_direct_private_join_root }));
    b.step("test-sha-direct-private-join", "Prove one private SHA256d header with all direct AIRs and word closure")
        .dependOn(&sha_direct_private_join_tests.step);
    const sha_direct_circuit_root = b.createModule(.{
        .root_source_file = b.path("sha_direct_circuit_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    sha_direct_circuit_root.addImport("stwo_core", core);
    sha_direct_circuit_root.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("missing prover engine"));
    sha_direct_circuit_root.addImport("stwo_circuit_frontend", circuit);
    sha_direct_circuit_root.addImport("stwo_circuit_cpu_integration", cpu);
    sha_direct_circuit_root.addImport("stwo_cairo_frontend", cpu.import_table.get("stwo_cairo_frontend") orelse @panic("missing Cairo frontend"));
    sha_direct_circuit_root.addImport("interop_postcard", sha_postcard);
    sha_direct_circuit_root.addImport("s31_air_programs", official_air);
    sha_direct_circuit_root.addImport("s31_sha_provider", sha_provider);
    sha_direct_circuit_root.addImport("s31_poseidon_ref", sha_provider);
    const sha_direct_circuit_tests = b.addRunArtifact(b.addTest(.{ .root_module = sha_direct_circuit_root }));
    b.step("test-sha-direct-circuit", "Prove one Bitcoin circuit plus private direct SHA256d in one STARK")
        .dependOn(&sha_direct_circuit_tests.step);
    const sha_shift_private_join_root = b.createModule(.{
        .root_source_file = b.path("sha_shift_private_join_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    sha_shift_private_join_root.addImport("stwo_core", core);
    sha_shift_private_join_root.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("missing prover engine"));
    sha_shift_private_join_root.addImport("stwo_circuit_cpu_integration", cpu);
    sha_shift_private_join_root.addImport("stwo_circuit_frontend", circuit);
    sha_shift_private_join_root.addImport("s31_sha_provider", sha_provider);
    sha_shift_private_join_root.addImport("interop_postcard", sha_postcard);
    const sha_shift_private_join_tests = b.addRunArtifact(b.addTest(.{ .root_module = sha_shift_private_join_root }));
    b.step("test-sha-shift-private-join", "Prove one private SHA256d header with shift-register round AIRs")
        .dependOn(&sha_shift_private_join_tests.step);
    const sha_shift_circuit_root = b.createModule(.{
        .root_source_file = b.path("sha_shift_circuit_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    sha_shift_circuit_root.addImport("stwo_core", core);
    sha_shift_circuit_root.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("missing prover engine"));
    sha_shift_circuit_root.addImport("stwo_circuit_frontend", circuit);
    sha_shift_circuit_root.addImport("stwo_circuit_cpu_integration", cpu);
    sha_shift_circuit_root.addImport("stwo_cairo_frontend", cpu.import_table.get("stwo_cairo_frontend") orelse @panic("missing Cairo frontend"));
    sha_shift_circuit_root.addImport("interop_postcard", sha_postcard);
    sha_shift_circuit_root.addImport("s31_air_programs", official_air);
    sha_shift_circuit_root.addImport("s31_sha_provider", sha_provider);
    sha_shift_circuit_root.addImport("s31_poseidon_ref", sha_provider);
    const sha_shift_circuit_tests = b.addRunArtifact(b.addTest(.{ .root_module = sha_shift_circuit_root }));
    b.step("test-sha-shift-circuit", "Prove one Bitcoin circuit plus shift-register SHA256d in one STARK")
        .dependOn(&sha_shift_circuit_tests.step);
    const sha_feed_word_proof_root = b.createModule(.{
        .root_source_file = b.path("sha_feed_direct_word_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    sha_feed_word_proof_root.addImport("stwo_core", core);
    sha_feed_word_proof_root.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("missing prover engine"));
    sha_feed_word_proof_root.addImport("stwo_circuit_cpu_integration", cpu);
    sha_feed_word_proof_root.addImport("s31_sha_provider", sha_provider);
    sha_feed_word_proof_root.addImport("interop_postcard", sha_postcard);
    const sha_feed_word_proof_tests = b.addRunArtifact(b.addTest(.{ .root_module = sha_feed_word_proof_root }));
    b.step("test-sha-feed-word", "Prove SHA feed-forward and its committed word lookup in one STARK")
        .dependOn(&sha_feed_word_proof_tests.step);
    const retarget_proof_test_root = b.createModule(.{
        .root_source_file = b.path("bitcoin_retarget_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    retarget_proof_test_root.addImport("stwo_core", core);
    retarget_proof_test_root.addImport("stwo_circuit_frontend", circuit);
    retarget_proof_test_root.addImport("stwo_circuit_cpu_integration", cpu);
    retarget_proof_test_root.addImport("stwo_cairo_frontend", cpu.import_table.get("stwo_cairo_frontend") orelse @panic("missing Cairo frontend"));
    retarget_proof_test_root.addImport("interop_postcard", sha_postcard);
    retarget_proof_test_root.addImport("s31_air_programs", official_air);
    const retarget_proof_tests = b.addRunArtifact(b.addTest(.{ .root_module = retarget_proof_test_root }));
    b.step("test-bitcoin-retarget-proof", "Prove and natively verify the first Bitcoin retarget relation")
        .dependOn(&retarget_proof_tests.step);
    anchor_proof_test_root.addAnonymousImport("s31_bitcoin_fixture", .{
        .root_source_file = b.path("examples/bitcoin_header_link.valid.json"),
    });
    anchor_proof_test_root.addAnonymousImport("s31_bitcoin_block2_fixture", .{
        .root_source_file = b.path("examples/bitcoin_block2_header.valid.json"),
    });
    const anchor_proof_tests = b.addRunArtifact(b.addTest(.{
        .root_module = anchor_proof_test_root,
        .filters = &.{"Bitcoin checkpoint anchor proves and verifies under the fold child layout"},
    }));
    b.step("test-bitcoin-anchor-proof", "Prove and natively verify the full-layout Bitcoin checkpoint anchor")
        .dependOn(&anchor_proof_tests.step);
    const chain_fold_proof_tests = b.addRunArtifact(b.addTest(.{
        .root_module = anchor_proof_test_root,
        .filters = &.{"Bitcoin chain fold proves two changing headers over a verified checkpoint anchor"},
    }));
    b.step("test-bitcoin-chain-fold-proof", "Prove and natively verify a Bitcoin header update inside a recursive fold")
        .dependOn(&chain_fold_proof_tests.step);
    const retarget_chain_proof_tests = b.addRunArtifact(b.addTest(.{
        .root_module = anchor_proof_test_root,
        .filters = &.{"first-retarget fold profile proves and verifies a genesis-anchored header"},
    }));
    b.step("test-bitcoin-retarget-fold-proof", "Prove and natively verify the first-retarget fold profile at step zero")
        .dependOn(&retarget_chain_proof_tests.step);
    const retarget_chain_key_root = b.createModule(.{
        .root_source_file = b.path("bitcoin_chain_retarget_verifier.zig"),
        .target = target,
        .optimize = optimize,
    });
    retarget_chain_key_root.addImport("stwo_core", core);
    retarget_chain_key_root.addImport("stwo_circuit_frontend", circuit);
    retarget_chain_key_root.addImport("stwo_circuit_cpu_integration", cpu);
    retarget_chain_key_root.addImport("stwo_s31_prototype", frontend);
    retarget_chain_key_root.addImport("stwo_cairo_frontend", cpu.import_table.get("stwo_cairo_frontend") orelse @panic("missing Cairo frontend"));
    retarget_chain_key_root.addImport("interop_postcard", sha_postcard);
    retarget_chain_key_root.addImport("s31_air_programs", official_air);
    retarget_chain_key_root.addAnonymousImport("s31_air_projection", .{
        .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../../vectors/circuit/official/compiled_air_constraints_v1.bin") },
    });
    const retarget_chain_key_tests = b.addRunArtifact(b.addTest(.{ .root_module = retarget_chain_key_root }));
    b.step("test-bitcoin-retarget-fold-key", "Derive and validate the distinct first-retarget recursive fold key")
        .dependOn(&retarget_chain_key_tests.step);
    const bitcoin_cli_root = b.createModule(.{
        .root_source_file = b.path("bitcoin_chain_cli.zig"),
        .target = target,
        .optimize = optimize,
    });
    bitcoin_cli_root.addImport("stwo_core", core);
    bitcoin_cli_root.addImport("stwo_circuit_frontend", circuit);
    bitcoin_cli_root.addImport("stwo_circuit_cpu_integration", cpu);
    bitcoin_cli_root.addImport("stwo_s31_prototype", frontend);
    bitcoin_cli_root.addImport("stwo_cairo_frontend", cpu.import_table.get("stwo_cairo_frontend") orelse @panic("missing Cairo frontend"));
    bitcoin_cli_root.addImport("interop_postcard", sha_postcard);
    bitcoin_cli_root.addImport("s31_air_programs", official_air);
    bitcoin_cli_root.addAnonymousImport("s31_air_projection", .{
        .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../../vectors/circuit/official/compiled_air_constraints_v1.bin") },
    });
    const bitcoin_cli = b.addExecutable(.{ .name = "s31-bitcoin-chain", .root_module = bitcoin_cli_root });
    b.step("bitcoin-chain-cli", "Build the standalone Bitcoin chain key and native verifier CLI")
        .dependOn(&b.addInstallArtifact(bitcoin_cli, .{}).step);
    const fold_test_root = b.createModule(.{
        .root_source_file = b.path("state_fold.zig"),
        .target = target,
        .optimize = optimize,
    });
    fold_test_root.addImport("stwo_s31_prototype", frontend);
    fold_test_root.addImport("stwo_core", core);
    fold_test_root.addImport("stwo_circuit_frontend", circuit);
    fold_test_root.addImport("stwo_circuit_cpu_integration", cpu);
    const fold_tests = b.addRunArtifact(b.addTest(.{
        .root_module = fold_test_root,
        .filters = &.{ "state-fold counter spans u16 carry and u32 bounds", "state-fold source step body matches constrained circuit across mixed programs", "state-fold digest binds all 32 counter bits in circuit" },
    }));
    test_step.dependOn(&fold_tests.step);
    const fixed_fold_test_root = b.createModule(.{
        .root_source_file = b.path("fixed_fold.zig"),
        .target = target,
        .optimize = optimize,
    });
    fixed_fold_test_root.addImport("stwo_core", core);
    fixed_fold_test_root.addImport("stwo_circuit_frontend", circuit);
    fixed_fold_test_root.addImport("stwo_circuit_cpu_integration", cpu);
    const fixed_fold_tests = b.addRunArtifact(b.addTest(.{
        .root_module = fixed_fold_test_root,
        .filters = &.{"fixed-fold digest binds the full u32 counter"},
    }));
    test_step.dependOn(&fixed_fold_tests.step);

    const sha_batch_root = b.createModule(.{
        .root_source_file = b.path("../riscv/sha256_batch_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    sha_batch_root.addImport("stwo_core", core);
    sha_batch_root.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("missing prover engine"));
    sha_batch_root.addImport("stwo_cpu_backend", cpu.import_table.get("stwo_cpu_backend") orelse @panic("missing CPU backend"));
    const sha_batch_tests = b.addRunArtifact(b.addTest(.{
        .root_module = sha_batch_root,
        .filters = &.{ "SHA canonical compression STARK", "six linked SHA compression calls" },
    }));
    b.step("test-sha-batch", "Prove and verify a six-call SHA256d AIR batch").dependOn(&sha_batch_tests.step);

    if (source_version == 1) {
        const cairo = cpu.import_table.get("stwo_cairo_frontend") orelse @panic("circuit CPU module is missing Cairo AIR runtime");
        const key_asset: std.Build.LazyPath = if (b.option([]const u8, "s31-key", "Absolute path to the sealed verification key")) |path|
            .{ .cwd_relative = path }
        else
            b.path("examples/placeholder-verification-key.json");
        const recursive_key_asset: std.Build.LazyPath = if (b.option([]const u8, "s31-recursive-key", "Absolute path to the sealed recursive verification key")) |path|
            .{ .cwd_relative = path }
        else
            b.path("examples/placeholder-recursive-key.json");
        const recursive_next_key_asset: std.Build.LazyPath = if (b.option([]const u8, "s31-recursive-next-key", "Absolute path to the sealed second-level recursive verification key")) |path|
            .{ .cwd_relative = path }
        else
            b.path("examples/placeholder-recursive-key.json");
        const fold_key_asset: std.Build.LazyPath = if (b.option([]const u8, "s31-fold-key", "Absolute path to the sealed fixed-fold verification key")) |path|
            .{ .cwd_relative = path }
        else
            b.path("examples/placeholder-recursive-key.json");
        const state_fold_key_asset: std.Build.LazyPath = if (b.option([]const u8, "s31-state-fold-key", "Absolute path to the sealed state-transition fold verification key")) |path|
            .{ .cwd_relative = path }
        else
            b.path("examples/placeholder-recursive-key.json");
        const prover_root = b.createModule(.{
            .root_source_file = b.path("mvp_runtime.zig"),
            .target = target,
            .optimize = optimize,
        });
        prover_root.addImport("stwo_s31_prototype", frontend);
        prover_root.addImport("stwo_core", core);
        prover_root.addImport("stwo_circuit_frontend", circuit);
        prover_root.addImport("stwo_circuit_cpu_integration", cpu);
        prover_root.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("missing prover engine"));
        prover_root.addImport("s31_sha_provider", sha_provider);
        prover_root.addImport("stwo_cairo_frontend", cairo);
        prover_root.addImport("interop_postcard", sha_postcard);
        prover_root.addImport("stwo_circuit_recursion_wire", wire);
        prover_root.addOptions("s31_options", s31_options);
        prover_root.addAnonymousImport("s31_program_source", .{ .root_source_file = source_asset });
        const projection_asset: std.Build.LazyPath = .{ .cwd_relative = b.pathFromRoot("../../../vectors/circuit/official/compiled_air_constraints_v1.bin") };
        prover_root.addAnonymousImport("s31_air_projection", .{ .root_source_file = projection_asset });
        prover_root.addImport("s31_air_programs", official_air);
        prover_root.addAnonymousImport("s31_verification_key", .{ .root_source_file = key_asset });
        prover_root.addAnonymousImport("s31_recursive_key", .{ .root_source_file = recursive_key_asset });
        prover_root.addAnonymousImport("s31_recursive_next_key", .{ .root_source_file = recursive_next_key_asset });
        prover_root.addAnonymousImport("s31_fold_key", .{ .root_source_file = fold_key_asset });
        prover_root.addAnonymousImport("s31_state_fold_key", .{ .root_source_file = state_fold_key_asset });
        const prover_exe = b.addExecutable(.{ .name = b.fmt("s31-{s}-prover", .{program_name}), .root_module = prover_root });
        b.installArtifact(prover_exe);

        const native_root = b.createModule(.{
            .root_source_file = b.path("mvp_verifier_main.zig"),
            .target = target,
            .optimize = optimize,
        });
        native_root.addImport("stwo_s31_prototype", frontend);
        native_root.addImport("stwo_core", core);
        native_root.addImport("stwo_circuit_frontend", circuit);
        native_root.addImport("stwo_circuit_cpu_integration", cpu);
        native_root.addImport("stwo_prover_engine", cpu.import_table.get("stwo_prover_engine") orelse @panic("missing prover engine"));
        native_root.addImport("s31_sha_provider", sha_provider);
        native_root.addImport("stwo_cairo_frontend", cairo);
        native_root.addImport("interop_postcard", sha_postcard);
        native_root.addImport("stwo_circuit_recursion_wire", wire);
        native_root.addOptions("s31_options", s31_options);
        native_root.addAnonymousImport("s31_program_source", .{ .root_source_file = source_asset });
        native_root.addAnonymousImport("s31_air_projection", .{ .root_source_file = projection_asset });
        native_root.addImport("s31_air_programs", official_air);
        native_root.addAnonymousImport("s31_verification_key", .{ .root_source_file = key_asset });
        native_root.addAnonymousImport("s31_recursive_key", .{ .root_source_file = recursive_key_asset });
        native_root.addAnonymousImport("s31_recursive_next_key", .{ .root_source_file = recursive_next_key_asset });
        native_root.addAnonymousImport("s31_fold_key", .{ .root_source_file = fold_key_asset });
        native_root.addAnonymousImport("s31_state_fold_key", .{ .root_source_file = state_fold_key_asset });
        const native_exe = b.addExecutable(.{ .name = b.fmt("s31-{s}-native-verifier", .{program_name}), .root_module = native_root });
        b.installArtifact(native_exe);
        const run = b.addRunArtifact(prover_exe);
        if (b.args) |args| run.addArgs(args);
        b.step("program", "Run the S31 v1 program compiler/prover").dependOn(&run.step);
        return;
    }
    if (source_version != 0) @panic("unsupported S31 source version");

    const showcase_root = b.createModule(.{
        .root_source_file = b.path("showcase.zig"),
        .target = target,
        .optimize = optimize,
    });
    showcase_root.addImport("stwo_s31_prototype", frontend);
    showcase_root.addImport("stwo_core", core);
    showcase_root.addImport("stwo_circuit_frontend", circuit);
    showcase_root.addImport("stwo_circuit_cpu_integration", cpu);
    showcase_root.addImport("stwo_circuit_recursion_wire", wire);
    showcase_root.addAnonymousImport("s31_program_source", .{ .root_source_file = source_asset });
    const projection_asset: std.Build.LazyPath = .{ .cwd_relative = b.pathFromRoot("../../../vectors/circuit/official/compiled_air_constraints_v1.bin") };
    showcase_root.addAnonymousImport("s31_air_projection", .{ .root_source_file = projection_asset });
    showcase_root.addImport("s31_air_programs", official_air);
    const executable = b.addExecutable(.{ .name = "s31-showcase", .root_module = showcase_root });
    b.installArtifact(executable);

    const verifier_root = b.createModule(.{
        .root_source_file = b.path("verifier_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    verifier_root.addImport("stwo_s31_prototype", frontend);
    verifier_root.addImport("stwo_core", core);
    verifier_root.addImport("stwo_circuit_frontend", circuit);
    verifier_root.addImport("stwo_circuit_cpu_integration", cpu);
    verifier_root.addImport("stwo_circuit_recursion_wire", wire);
    verifier_root.addAnonymousImport("s31_program_source", .{ .root_source_file = source_asset });
    verifier_root.addAnonymousImport("s31_air_projection", .{ .root_source_file = projection_asset });
    verifier_root.addImport("s31_air_programs", official_air);
    const verifier = b.addExecutable(.{ .name = b.fmt("s31-{s}-verifier", .{program_name}), .root_module = verifier_root });
    b.installArtifact(verifier);

    const showcase = b.addRunArtifact(executable);
    showcase.setCwd(.{ .cwd_relative = b.pathFromRoot("../../..") });
    if (b.args) |args| showcase.addArgs(args);
    const showcase_step = b.step("showcase", "Prove and natively verify the S31 affine-four example");
    showcase_step.dependOn(&showcase.step);
    showcase_step.dependOn(b.getInstallStep());
}
