const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const dependency_options = .{ .target = target, .optimize = optimize };

    const artifact_store = b.dependency(
        "stwo_artifact_store",
        dependency_options,
    ).module("stwo_artifact_store");
    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const prover = b.dependency(
        "stwo_prover_engine",
        dependency_options,
    ).module("stwo_prover_engine");
    const prover_api = b.dependency(
        "stwo_prover_api",
        dependency_options,
    ).module("stwo_prover_api");
    const cpu_backend = b.dependency(
        "stwo_cpu_backend",
        dependency_options,
    ).module("stwo_cpu_backend");
    const frontend_dependency = b.dependency(
        "stwo_riscv_frontend",
        dependency_options,
    );
    const frontend = frontend_dependency.module("stwo_riscv_frontend");
    const postcard = frontend.import_table.get("interop_postcard") orelse
        @panic("canonical RISC-V frontend is missing interop_postcard");
    const integration = b.addModule("stwo_riscv_cpu_integration", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration.addImport("stwo_artifact_store", artifact_store);
    integration.addImport("stwo_core", core);
    integration.addImport("stwo_prover_api", prover_api);
    integration.addImport("stwo_prover_engine", prover);
    integration.addImport("stwo_cpu_backend", cpu_backend);
    integration.addImport("stwo_riscv_frontend", frontend);
    integration.addImport("interop_postcard", postcard);

    const tests = b.addTest(.{ .root_module = integration });
    b.step("test", "Test the focused RISC-V CPU integration")
        .dependOn(&b.addRunArtifact(tests).step);

    const secp_root = b.createModule(.{
        .root_source_file = b.path("secp256k1_precompile_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    secp_root.addImport("stwo_cpu_backend", cpu_backend);
    secp_root.addImport("stwo_riscv_frontend", frontend);
    secp_root.addImport("stwo_core", core);
    secp_root.addImport("stwo_prover_engine", prover);
    secp_root.addImport("secp256k1_proof_harness", frontend_dependency.module("secp256k1_proof_harness"));
    const secp_tests = b.addTest(.{ .root_module = secp_root });
    b.step("test-secp256k1-precompile-proof", "Prove and independently verify typed and canonical CSP ECDSA on CPU")
        .dependOn(&b.addRunArtifact(secp_tests).step);

    const keccak_root = b.createModule(.{
        .root_source_file = b.path("keccakf_precompile_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    keccak_root.addImport("stwo_cpu_backend", cpu_backend);
    keccak_root.addImport("stwo_riscv_frontend", frontend);
    keccak_root.addImport("stwo_core", core);
    keccak_root.addImport("stwo_prover_engine", prover);
    keccak_root.addImport("keccakf_proof_harness", frontend_dependency.module("keccakf_proof_harness"));
    const keccak_tests = b.addTest(.{
        .root_module = keccak_root,
        .filters = &.{"Keccak-f typed shard and lookup tables prove and independently verify"},
    });
    b.step("test-keccakf-precompile-proof", "Prove and independently verify typed Keccak-f on CPU")
        .dependOn(&b.addRunArtifact(keccak_tests).step);

    const segment_root = b.createModule(.{
        .root_source_file = b.path("segment_v2_native_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    segment_root.addImport("stwo_core", core);
    segment_root.addImport("stwo_artifact_store", artifact_store);
    segment_root.addImport("stwo_prover_engine", prover);
    segment_root.addImport("stwo_prover_api", prover_api);
    segment_root.addImport("stwo_cpu_backend", cpu_backend);
    segment_root.addImport("stwo_riscv_frontend", frontend);
    segment_root.addImport("interop_postcard", postcard);
    const segment_tests = b.addTest(.{
        .root_module = segment_root,
        .filters = &.{"native V2 proves and independently verifies real nonfinal and final segments"},
    });
    b.step("test-segment-v2-native-proof", "Prove and independently verify real nonfinal and final SegmentV2 shards")
        .dependOn(&b.addRunArtifact(segment_tests).step);

    const leaf_local_v3_tests = b.addTest(.{
        .root_module = segment_root,
        .filters = &.{"native V2 proves a rebased leaf-local V3 segment without widening the AIR"},
    });
    b.step("test-segment-v3-native-ingress", "Prove a leaf-local V3 segment and freshly verify its global link")
        .dependOn(&b.addRunArtifact(leaf_local_v3_tests).step);

    const v3_security_root = b.createModule(.{
        .root_source_file = b.path("native_v3_security_smoke_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    v3_security_root.addImport("stwo_core", core);
    v3_security_root.addImport("stwo_artifact_store", artifact_store);
    v3_security_root.addImport("stwo_prover_engine", prover);
    v3_security_root.addImport("stwo_prover_api", prover_api);
    v3_security_root.addImport("stwo_cpu_backend", cpu_backend);
    v3_security_root.addImport("stwo_riscv_frontend", frontend);
    v3_security_root.addImport("interop_postcard", postcard);
    const v3_security_tests = b.addTest(.{
        .root_module = v3_security_root,
        .filters = &.{"real SegmentV2 native proof verifies under V3 q193 security profile"},
    });
    b.step("test-segment-v3-native-security-smoke", "Prove and verify a real small SegmentV2 ELF under V3 q193 security")
        .dependOn(&b.addRunArtifact(v3_security_tests).step);

    const v3_pinned_root = b.createModule(.{
        .root_source_file = b.path("native_v3_pinned_ingress_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    v3_pinned_root.addImport("stwo_core", core);
    v3_pinned_root.addImport("stwo_artifact_store", artifact_store);
    v3_pinned_root.addImport("stwo_prover_engine", prover);
    v3_pinned_root.addImport("stwo_prover_api", prover_api);
    v3_pinned_root.addImport("stwo_cpu_backend", cpu_backend);
    v3_pinned_root.addImport("stwo_riscv_frontend", frontend);
    v3_pinned_root.addImport("interop_postcard", postcard);
    const v3_pinned_tests = b.addTest(.{
        .root_module = v3_pinned_root,
        .filters = &.{"real V3 native ingress accepts independently pinned q193 Tree0"},
    });
    b.step("test-segment-v3-pinned-native-ingress", "Prove and verify a real V3 local leaf under an independent q193 Tree0 pin")
        .dependOn(&b.addRunArtifact(v3_pinned_tests).step);
    const v3_strong_chain_root = b.createModule(.{
        .root_source_file = b.path("native_v3_strong_chain_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    v3_strong_chain_root.addImport("stwo_core", core);
    v3_strong_chain_root.addImport("stwo_artifact_store", artifact_store);
    v3_strong_chain_root.addImport("stwo_prover_engine", prover);
    v3_strong_chain_root.addImport("stwo_prover_api", prover_api);
    v3_strong_chain_root.addImport("stwo_cpu_backend", cpu_backend);
    v3_strong_chain_root.addImport("stwo_riscv_frontend", frontend);
    v3_strong_chain_root.addImport("interop_postcard", postcard);
    const v3_strong_chain_tests = b.addTest(.{
        .root_module = v3_strong_chain_root,
        .filters = &.{"real q193 native child feeds freshly verified q193 local outer"},
    });
    b.step("test-segment-v3-strong-chain", "Freshly verify pinned q193 native and strong q193 local outer proofs for one real V3 leaf")
        .dependOn(&b.addRunArtifact(v3_strong_chain_tests).step);
    const v3_rows_root = b.createModule(.{
        .root_source_file = b.path("../../frontends/riscv/segment_leaf_wrapper_source_projection_v3_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    v3_rows_root.addImport("stwo_core", core);
    v3_rows_root.addImport("stwo_prover_engine", prover);
    v3_rows_root.addImport("stwo_prover_api", prover_api);
    const v3_rows_tests = b.addTest(.{ .root_module = v3_rows_root });
    b.step("test-v3-source-projection-rows", "Check typed V3 leaf source and projection joins")
        .dependOn(&b.addRunArtifact(v3_rows_tests).step);
    const v6_template_tests = b.addTest(.{
        .root_module = v3_rows_root,
        .filters = &.{"V6 template geometry is rebuilt without either leaf V2 manifest seal"},
    });
    b.step("test-v6-fixed-key-template", "Check verifier-owned V6 template geometry and key separation")
        .dependOn(&b.addRunArtifact(v6_template_tests).step);
    const v7_template_protocol_tests = b.addTest(.{
        .root_module = v3_rows_root,
        .filters = &.{"VPR7 candidate is shape-only while VPK7 awaits a rebuilt template root"},
    });
    b.step("test-v7-template-protocol", "Check pinned V6 template identity in candidate VPR7/VPK7")
        .dependOn(&b.addRunArtifact(v7_template_protocol_tests).step);
    const v6_row4_tests = b.addTest(.{
        .root_module = v3_rows_root,
        .filters = &.{"V6 row4"},
    });
    b.step("test-v6-row4-template", "Check independently rebuilt fixed row-4 transcript columns")
        .dependOn(&b.addRunArtifact(v6_row4_tests).step);
    const v6_appended_tests = b.addTest(.{
        .root_module = v3_rows_root,
        .filters = &.{"V6 appended rows rebuild fixed columns"},
    });
    b.step("test-v6-appended-fixed-rows", "Check verifier-owned preprocessing for direct rows 39 through 49")
        .dependOn(&b.addRunArtifact(v6_appended_tests).step);
    const v6_base_fixed_tests = b.addTest(.{
        .root_module = v3_rows_root,
        .filters = &.{ "V6 base fixed", "V6 public rows 13", "V6 claim-hash fixed tail" },
    });
    b.step("test-v6-base-fixed-rows", "Check independent V6 control, public, provider and byte-table preprocessing")
        .dependOn(&b.addRunArtifact(v6_base_fixed_tests).step);
    const v7_roster_tests = b.addTest(.{
        .root_module = v3_rows_root,
        .filters = &.{"V7 roster pins wire-half AIR geometry"},
    });
    b.step("test-v7-wire-roster", "Check versioned native wire-half physical geometry and key seal")
        .dependOn(&b.addRunArtifact(v7_roster_tests).step);
    const v7_payload_fixed_tests = b.addTest(.{
        .root_module = v3_rows_root,
        .filters = &.{"V7 row5 fixed schedule comes from admitted transcript shape"},
    });
    b.step("test-v7-payload-fixed", "Check verifier-owned native half-word payload fixed columns")
        .dependOn(&b.addRunArtifact(v7_payload_fixed_tests).step);
    const v6_npv2_tests = b.addTest(.{
        .root_module = v3_rows_root,
        .filters = &.{"V6 local router exports exactly eight hash-bound authority words to NPV2"},
    });
    b.step("test-v6-local-npv2", "Check the versioned proof-visible authority-word bridge")
        .dependOn(&b.addRunArtifact(v6_npv2_tests).step);
    const v6_row5_identity_tests = b.addTest(.{
        .root_module = v3_rows_root,
        .filters = &.{"V6 direct row5 semantic identity"},
    });
    b.step("test-v6-row5-identity", "Pin the direct NPV2 native payload AIR identity")
        .dependOn(&b.addRunArtifact(v6_row5_identity_tests).step);
    const v6_row5_wire_tests = b.addTest(.{
        .root_module = v3_rows_root,
        .filters = &.{"V6 row5 exports exactly the eight transcript-bound wire IDs"},
    });
    b.step("test-v6-row5-wire", "Check exact native row5 NPV2 mask and wire-value custody")
        .dependOn(&b.addRunArtifact(v6_row5_wire_tests).step);
    const v6_local_witness_tests = b.addTest(.{
        .root_module = v3_rows_root,
        .filters = &.{"V6 authority export materializes a validated local witness"},
    });
    b.step("test-v6-local-witness", "Check schema-2 child schedule and witness compatibility")
        .dependOn(&b.addRunArtifact(v6_local_witness_tests).step);
    const v6_composition_control_fixed_tests = b.addTest(.{
        .root_module = v3_rows_root,
        .filters = &.{"V6 row19 physical columns"},
    });
    b.step("test-v6-composition-control-fixed", "Check verifier-owned V6 row-19 physical preprocessing")
        .dependOn(&b.addRunArtifact(v6_composition_control_fixed_tests).step);
    const v6_composition_input_fixed_tests = b.addTest(.{
        .root_module = v3_rows_root,
        .filters = &.{"V6 row18 physical columns"},
    });
    b.step("test-v6-composition-input-fixed", "Check verifier-owned V6 row-18 physical preprocessing")
        .dependOn(&b.addRunArtifact(v6_composition_input_fixed_tests).step);
    const v6_statement_row11_fixed_tests = b.addTest(.{
        .root_module = v3_rows_root,
        .filters = &.{"V6 row11 fixed columns"},
    });
    b.step("test-v6-statement-row11-fixed", "Check canonical-wire-shape V6 row-11 physical preprocessing")
        .dependOn(&b.addRunArtifact(v6_statement_row11_fixed_tests).step);
    const v6_transcript_fixed_tests = b.addTest(.{
        .root_module = v3_rows_root,
        .filters = &.{"V6 transcript fixed schedule matches executed V2"},
    });
    b.step("test-v6-transcript-fixed-schedule", "Check shape-only transcript call, frame, relation and randomness preprocessing")
        .dependOn(&b.addRunArtifact(v6_transcript_fixed_tests).step);

    const universal_root = b.createModule(.{
        .root_source_file = b.path("universal_typed_component_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    universal_root.addImport("stwo_core", core);
    universal_root.addImport("stwo_cpu_backend", cpu_backend);
    universal_root.addImport("stwo_riscv_frontend", frontend);
    universal_root.addImport("stwo_prover_engine", prover);
    const universal_tests = b.addTest(.{
        .root_module = universal_root,
        .filters = &.{"R-012 active FRI Merkle leaf adapter proves and independently verifies"},
    });
    b.step("test-universal-typed-proof", "Prove and independently verify the generic typed FRI adapter")
        .dependOn(&b.addRunArtifact(universal_tests).step);

    // Generic SegmentV2 detached tools remain available for the qualified
    // continuation path. Ethereum block assembly is an archived experiment.
    const leaf_verifier_root = b.createModule(.{
        .root_source_file = b.path("../../frontends/riscv/leaf_verifier.zig"),
        .target = target,
        .optimize = optimize,
    });
    leaf_verifier_root.addImport("stwo_core", core);
    leaf_verifier_root.addImport("interop_postcard", postcard);
    const leaf_verifier_runner = b.createModule(.{
        .root_source_file = b.path("recursive_segment_v2_detached_verifier_runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    leaf_verifier_runner.addImport("stwo_leaf_verifier", leaf_verifier_root);
    const leaf_verifier = b.addExecutable(.{
        .name = "recursive-segment-v2-detached-verify",
        .root_module = leaf_verifier_runner,
    });
    b.step("build-recursive-segment-v2-detached-verifier", "Build the detached SegmentV2 leaf verifier")
        .dependOn(&b.addInstallArtifact(leaf_verifier, .{}).step);

    const parent_verifier_root = b.createModule(.{
        .root_source_file = b.path("../../frontends/riscv/parent_verifier.zig"),
        .target = target,
        .optimize = optimize,
    });
    parent_verifier_root.addImport("stwo_core", core);
    parent_verifier_root.addImport("interop_postcard", postcard);
    const parent_verifier_runner = b.createModule(.{
        .root_source_file = b.path("recursive_segment_v2_detached_parent_verifier_runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    parent_verifier_runner.addImport("stwo_parent_verifier", parent_verifier_root);
    const parent_verifier = b.addExecutable(.{
        .name = "recursive-segment-v2-detached-parent-verify",
        .root_module = parent_verifier_runner,
    });
    b.step("build-recursive-segment-v2-detached-parent-verifier", "Build the detached SegmentV2 parent verifier")
        .dependOn(&b.addInstallArtifact(parent_verifier, .{}).step);

    const leaf_producer_root = b.addModule("stwo_riscv_detached_leaf_runner", .{
        .root_source_file = b.path("recursive_segment_v2_detached_leaf_runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    leaf_producer_root.addImport("stwo_core", core);
    leaf_producer_root.addImport("stwo_cpu_backend", cpu_backend);
    leaf_producer_root.addImport("stwo_riscv_frontend", frontend);
    leaf_producer_root.addImport("stwo_prover_api", prover_api);
    leaf_producer_root.addImport("stwo_prover_engine", prover);
    leaf_producer_root.addImport("interop_postcard", postcard);
    const leaf_producer = b.addExecutable(.{
        .name = "recursive-segment-v2-detached-leaf-prove",
        .root_module = leaf_producer_root,
    });
    b.step("build-recursive-segment-v2-detached-leaf-producer", "Build the detached SegmentV2 leaf producer")
        .dependOn(&b.addInstallArtifact(leaf_producer, .{}).step);

    const parent_producer_owner = b.addModule("stwo_riscv_detached_parent_producer", .{
        .root_source_file = b.path("recursive_segment_v2_detached_parent_producer.zig"),
        .target = target,
        .optimize = optimize,
    });
    parent_producer_owner.addImport("stwo_core", core);
    parent_producer_owner.addImport("stwo_cpu_backend", cpu_backend);
    parent_producer_owner.addImport("stwo_riscv_frontend", frontend);
    parent_producer_owner.addImport("stwo_prover_api", prover_api);
    parent_producer_owner.addImport("stwo_prover_engine", prover);
    parent_producer_owner.addImport("interop_postcard", postcard);
    const parent_producer_runner = b.createModule(.{
        .root_source_file = b.path("recursive_segment_v2_detached_parent_producer_runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    parent_producer_runner.addImport("stwo_riscv_detached_parent_producer", parent_producer_owner);
    const parent_producer = b.addExecutable(.{
        .name = "recursive-segment-v2-detached-parent-prove",
        .root_module = parent_producer_runner,
    });
    b.step("build-recursive-segment-v2-detached-parent-producer", "Build the detached SegmentV2 parent producer")
        .dependOn(&b.addInstallArtifact(parent_producer, .{}).step);
}
