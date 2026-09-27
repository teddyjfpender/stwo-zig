//! Focused BLAKE3 migration gates; intentionally independent of full prover suites.
const support = @import("build_support.zig");
pub fn add(ctx: anytype) void {
    const b = ctx.b;
    const target = ctx.target;
    const optimize = ctx.optimize;
    const core = ctx.core;
    const prover = ctx.prover;
    const cpu_backend = ctx.cpu_backend;
    const frontend = ctx.frontend;
    const integration = ctx.integration;
    const hash_root = support.createHarnessModule(b, "../../frontends/riscv/blake3_hash_test_root.zig", target, optimize, core, cpu_backend, frontend, integration);
    hash_root.addImport("stwo_prover_engine", prover);
    const pcs_capture_names: []const []const u8 = &.{"PCS arithmetic capture preserves ownership and rejects geometry encoding mutations"};
    const pcs_capture_tests = b.addTest(.{ .root_module = hash_root, .filters = pcs_capture_names });
    b.step("test-pcs-arithmetic-capture", "Check hash-independent DEEP capture admission and ownership")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(pcs_capture_tests), pcs_capture_names, "PCS arithmetic capture guard"));
    const scalar_names: []const []const u8 = &.{"Scalar wire sources pin base-field tuple shape and fixed identities"};
    const scalar_tests = b.addTest(.{ .root_module = hash_root, .filters = scalar_names });
    b.step("test-scalar-wire-source", "Check private scalar wire identities and literal zero extension coordinates")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(scalar_tests), scalar_names, "Scalar wire source guard"));
    const hash_names: []const []const u8 = &.{
        "BLAKE3 hash DAG matches standard hashing across blocks chunks and unbalanced trees",
        "BLAKE3 hash global wires reject chaining flags and digest substitutions",
        "BLAKE3 hash graph releases every partial allocation",
    };
    const hash_tests = b.addTest(.{ .root_module = hash_root, .filters = hash_names });
    b.step("test-blake3-hash", "Check canonical full-hash schedules and cross-compression typed wires")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(hash_tests), hash_names, "BLAKE3 hash graph guard"));
    const frame_witness_names: []const []const u8 = &.{"BLAKE3 routed frame witness hides digest bytes from fixed columns and owns allocations"};
    const frame_witness_tests = b.addTest(.{ .root_module = hash_root, .filters = frame_witness_names });
    b.step("test-blake3-frame-witness", "Check private digest frame preprocessing and allocation ownership")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(frame_witness_tests), frame_witness_names, "BLAKE3 frame witness guard"));
    const query_batch_names: []const []const u8 = &.{"BLAKE3 query batches preserve native partial blocks counters and private fixed columns"};
    const query_batch_tests = b.addTest(.{ .root_module = hash_root, .filters = query_batch_names });
    b.step("test-blake3-query-batch", "Check authenticated raw query batching and exact native counter consumption")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(query_batch_tests), query_batch_names, "BLAKE3 query batch guard"));
    const query_path_names: []const []const u8 = &.{"BLAKE3 query path admission preserves duplicates folding and exact path order"};
    const query_path_tests = b.addTest(.{ .root_module = hash_root, .filters = query_path_names });
    b.step("test-blake3-query-path-plan", "Check canonical raw-to-unique folded path admission")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(query_path_tests), query_path_names, "BLAKE3 query path plan guard"));
    const field_bytes_names: []const []const u8 = &.{"BLAKE3 field byte encoding pins canonical coordinates and rejects modular aliases"};
    const field_bytes_tests = b.addTest(.{ .root_module = hash_root, .filters = field_bytes_names });
    b.step("test-blake3-field-bytes", "Check canonical QM31 coordinate serialization through typed constraints")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(field_bytes_tests), field_bytes_names, "BLAKE3 field bytes guard"));
    const query_mask_names: []const []const u8 = &.{"BLAKE3 raw query masking pins semantics and preserves native u32 boundaries"};
    const query_mask_tests = b.addTest(.{ .root_module = hash_root, .filters = query_mask_names });
    b.step("test-blake3-query-mask", "Check typed raw-u32 query masks against canonical bitwise tables")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(query_mask_tests), query_mask_names, "BLAKE3 query mask guard"));
    const draw_names: []const []const u8 = &.{
        "BLAKE3 ordered draws match native outputs and independently rebuilt fixed columns",
        "BLAKE3 ordered draws reject skipped accepted attempts false outputs and counter wrap",
    };
    const draw_tests = b.addTest(.{ .root_module = hash_root, .filters = draw_names });
    b.step("test-blake3-draw", "Check contiguous native rejection-sampling attempt admission")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(draw_tests), draw_names, "BLAKE3 ordered draw guard"));
    const challenge_names: []const []const u8 = &.{
        "BLAKE3 challenge block pins typed reduction rejection and framework export",
        "BLAKE3 challenge block matches native boundaries and rejects unused half",
        "BLAKE3 challenge block rejects validity reduction and acceptance mutations",
    };
    const challenge_tests = b.addTest(.{ .root_module = hash_root, .filters = challenge_names });
    b.step("test-blake3-challenge", "Check exact whole-block rejection and field challenge reduction")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(challenge_tests), challenge_names, "BLAKE3 challenge guard"));
    const route_names: []const []const u8 = &.{
        "BLAKE3 byte route pins typed semantics and rejects selected byte mutations",
        "BLAKE3 symbolic Merkle routing matches canonical frame bytes",
        "BLAKE3 transcript digest routing matches frames and rejects missing role bindings",
    };
    const route_tests = b.addTest(.{ .root_module = hash_root, .filters = route_names });
    b.step("test-blake3-byte-route", "Check authenticated byte selection for canonical Merkle frames")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(route_tests), route_names, "BLAKE3 byte route guard"));
    const frame_names: []const []const u8 = &.{"BLAKE3 canonical frames match native operations and full hash witnesses"};
    const frame_tests = b.addTest(.{ .root_module = hash_root, .filters = frame_names });
    b.step("test-blake3-framing", "Check shared transcript and commitment byte encoding")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(frame_tests), frame_names, "BLAKE3 framing guard"));
    const private_names: []const []const u8 = &.{
        "BLAKE3 private input bridge pins typed semantics and enforces unused bytes",
        "BLAKE3 private hash preprocessing contains no message words",
        "BLAKE3 private input claims require exact caller and graph endpoints",
    };
    const private_tests = b.addTest(.{ .root_module = hash_root, .filters = private_names });
    b.step("test-blake3-private-input", "Check typed caller binding and private hash preprocessing")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(private_tests), private_names, "BLAKE3 private input guard"));
    const framework_root = support.createHarnessModule(b, "../../frontends/riscv/blake3_framework_test_root.zig", target, optimize, core, cpu_backend, frontend, integration);
    framework_root.addImport("stwo_prover_engine", prover);
    const combined_names: []const []const u8 = &.{"BLAKE3 private FRI values join all paths and canonical arithmetic in one proof"};
    const combined_tests = b.addTest(.{ .root_module = framework_root, .filters = combined_names });
    b.step("test-blake3-combined-fri", "Prove all FRI paths and canonical arithmetic with shared private values")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(combined_tests), combined_names, "BLAKE3 combined FRI guard"));
    const arithmetic_names: []const []const u8 = &.{"BLAKE3 captured FRI arithmetic verifies in a complete typed CPU proof"};
    const arithmetic_tests = b.addTest(.{ .root_module = framework_root, .filters = arithmetic_names });
    b.step("test-blake3-fri-arithmetic-proof", "Prove the existing canonical FRI arithmetic with captured BLAKE3 inputs")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(arithmetic_tests), arithmetic_names, "BLAKE3 FRI arithmetic guard"));
    const group_names: []const []const u8 = &.{"BLAKE3 complete FRI folding groups bind every field tuple in a typed proof"};
    const group_tests = b.addTest(.{ .root_module = framework_root, .filters = group_names });
    b.step("test-blake3-fri-group", "Prove complete captured FRI subtrees from canonical field wires")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(group_tests), group_names, "BLAKE3 FRI group guard"));
    const capture_names: []const []const u8 = &.{"BLAKE3 actual PCS captures feed typed trace and FRI paths"};
    const capture_tests = b.addTest(.{ .root_module = framework_root, .filters = capture_names });
    b.step("test-blake3-pcs-capture", "Qualify actual native PCS captures against typed trace and FRI paths")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(capture_tests), capture_names, "BLAKE3 PCS capture guard"));
    const private_draw_names: []const []const u8 = &.{"BLAKE3 absorption feeds private state into a complete ordered challenge proof"};
    const private_draw_tests = b.addTest(.{ .root_module = framework_root, .filters = private_draw_names });
    b.step("test-blake3-private-draw-proof", "Prove absorption into private state followed by an ordered challenge draw")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(private_draw_tests), private_draw_names, "BLAKE3 private draw guard"));
    const sequence_names: []const []const u8 = &.{
        "BLAKE3 transcript sequence derives native counters resets and private state links",
        "BLAKE3 native transcript sequence verifies in a complete CPU proof",
    };
    const sequence_tests = b.addTest(.{ .root_module = framework_root, .filters = sequence_names });
    b.step("test-blake3-transcript-sequence", "Check and prove native transcript operation ordering and counter resets")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(sequence_tests), sequence_names, "BLAKE3 transcript sequence guard"));
    const query_proof_names: []const []const u8 = &.{"BLAKE3 raw query indices verify in a complete CPU draw proof"};
    const query_proof_tests = b.addTest(.{ .root_module = framework_root, .filters = query_proof_names });
    b.step("test-blake3-query-proof", "Prove canonical raw query extraction through real bitwise providers")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(query_proof_tests), query_proof_names, "BLAKE3 raw query proof guard"));
    const query_path_proof_names: []const []const u8 = &.{"BLAKE3 raw queries admit exactly their canonical private sibling paths in one proof"};
    const query_path_proof_tests = b.addTest(.{ .root_module = framework_root, .filters = query_path_proof_names });
    b.step("test-blake3-query-path-proof", "Prove raw queries and exactly their deduplicated Merkle paths together")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(query_path_proof_tests), query_path_proof_names, "BLAKE3 query path proof guard"));
    const lifted_path_names: []const []const u8 = &.{"BLAKE3 lifted geometry matches native decommitments and a complete typed path proof"};
    const lifted_path_tests = b.addTest(.{ .root_module = framework_root, .filters = lifted_path_names });
    b.step("test-blake3-lifted-path", "Check native lifted leaf geometry and prove a captured path to its real root")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(lifted_path_tests), lifted_path_names, "BLAKE3 lifted path guard"));
    const field_bytes_proof_names: []const []const u8 = &.{"BLAKE3 canonical field bytes feed an authenticated complete hash proof"};
    const field_bytes_proof_tests = b.addTest(.{ .root_module = framework_root, .filters = field_bytes_proof_names });
    b.step("test-blake3-field-bytes-proof", "Prove canonical arithmetic-to-byte encoding through BLAKE3 hashing")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(field_bytes_proof_tests), field_bytes_proof_names, "BLAKE3 field bytes proof guard"));
    const transition_names: []const []const u8 = &.{"BLAKE3 transcript absorption proves with private intermediate state"};
    const transition_tests = b.addTest(.{ .root_module = framework_root, .filters = transition_names });
    b.step("test-blake3-transcript-proof", "Prove native absorption with authenticated private transcript state")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(transition_tests), transition_names, "BLAKE3 transcript transition guard"));
    const challenge_proof_names: []const []const u8 = &.{"BLAKE3 native draw produces constrained scalar challenges in a complete CPU proof"};
    const challenge_proof_tests = b.addTest(.{ .root_module = framework_root, .filters = challenge_proof_names });
    b.step("test-blake3-challenge-proof", "Prove native BLAKE3 draw hashing and scalar challenge extraction")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(challenge_proof_tests), challenge_proof_names, "BLAKE3 challenge proof guard"));
    const framework_names: []const []const u8 = &.{
        "BLAKE3 boundary pins semantics and exports committed framework programs",
        "BLAKE3 padded framework and production table interaction claims close",
    };
    const framework_tests = b.addTest(.{ .root_module = framework_root, .filters = framework_names });
    b.step("test-blake3-framework", "Check typed boundary exports and full padded interaction claim closure")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(framework_tests), framework_names, "BLAKE3 framework guard"));
    const proof_names: []const []const u8 = &.{
        "BLAKE3 compression committed proof verifies with trusted preprocessing",
        "BLAKE3 full hash committed proofs cover empty partial and unbalanced chunk trees",
        "BLAKE3 framed Merkle node proof matches the native commitment",
    };
    const proof_tests = b.addTest(.{ .root_module = framework_root, .filters = proof_names });
    b.step("test-blake3-proof", "Prove and verify the complete BLAKE3 compression circuit on CPU")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(proof_tests), proof_names, "BLAKE3 committed proof guard"));
    const private_proof_names: []const []const u8 = &.{"BLAKE3 private hash chain proves without exposing its intermediate digest"};
    const private_proof_tests = b.addTest(.{ .root_module = framework_root, .filters = private_proof_names });
    b.step("test-blake3-private-proof", "Prove an authenticated private digest between two hash graphs")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(private_proof_tests), private_proof_names, "BLAKE3 private proof guard"));
    const routed_proof_names: []const []const u8 = &.{"BLAKE3 routed Merkle proof authenticates both private child digests"};
    const routed_proof_tests = b.addTest(.{ .root_module = framework_root, .filters = routed_proof_names });
    b.step("test-blake3-routed-proof", "Prove a canonical Merkle parent of two authenticated child hashes")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(routed_proof_tests), routed_proof_names, "BLAKE3 routed proof guard"));
    const path_names: []const []const u8 = &.{
        "BLAKE3 private sibling word semantics pin and reject out of range bytes",
        "BLAKE3 path witnesses match every native direction and keep siblings private",
    };
    const path_tests = b.addTest(.{ .root_module = framework_root, .filters = path_names });
    b.step("test-blake3-path", "Check private-sibling path witness and source semantics")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(path_tests), path_names, "BLAKE3 path guard"));
    const path_proof_names: []const []const u8 = &.{"BLAKE3 private sibling paths verify in complete CPU proofs"};
    const path_proof_tests = b.addTest(.{ .root_module = framework_root, .filters = path_proof_names });
    b.step("test-blake3-path-proof", "Prove Merkle authentication paths with private siblings")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(path_proof_tests), path_proof_names, "BLAKE3 path proof guard"));
    const blake3_wiring_root = support.createHarnessModule(b, "../../frontends/riscv/blake3_wiring_test_root.zig", target, optimize, core, cpu_backend, frontend, integration);
    const blake3_wiring_names: []const []const u8 = &.{
        "BLAKE3 call components pin semantics and authenticate relation plans",
        "BLAKE3 fixed compression wire graph closes and rejects endpoint substitutions",
        "BLAKE3 ordered call construction releases partial allocations",
    };
    const blake3_wiring_tests = b.addTest(.{ .root_module = blake3_wiring_root, .filters = blake3_wiring_names });
    b.step("test-blake3-wiring", "Check typed BLAKE3 call bindings and exact compression wire closure")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(blake3_wiring_tests), blake3_wiring_names, "BLAKE3 wiring guard"));
    const blake3_packed_root = support.createHarnessModule(b, "../../frontends/riscv/blake3_packed_test_root.zig", target, optimize, core, cpu_backend, frontend, integration);
    const blake3_packed_names: []const []const u8 = &.{
        "BLAKE3 compact G matches typed bit reference and canonical lookup schemas",
        "BLAKE3 compact G rejects coordinate mutations and requires lookup bounds",
        "BLAKE3 compact G covers all seven rounds of a native compression trace",
    };
    const blake3_packed_tests = b.addTest(.{ .root_module = blake3_packed_root, .filters = blake3_packed_names });
    b.step("test-blake3-packed", "Check compact typed BLAKE3 arithmetic and exact lookup requests")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(blake3_packed_tests), blake3_packed_names, "BLAKE3 packed guard"));
    const blake3_compression_root = support.createHarnessModule(b, "../../frontends/riscv/blake3_compression_test_root.zig", target, optimize, core, cpu_backend, frontend, integration);
    const blake3_compression_names: []const []const u8 = &.{
        "BLAKE3 typed G has degree two and agrees with native arithmetic",
        "BLAKE3 typed G rejects every single-bit mutation and nonboolean witnesses",
        "BLAKE3 seven-round compression matches standard hash across chunks",
        "BLAKE3 typed arithmetic covers all scheduled compression calls",
    };
    const blake3_compression_test = b.addTest(.{ .root_module = blake3_compression_root, .filters = blake3_compression_names });
    b.step("test-blake3-compression", "Check canonical compression and typed degree-two G arithmetic")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(blake3_compression_test), blake3_compression_names, "BLAKE3 compression guard"));
    const blake3_benchmark_root = support.createHarnessModule(b, "blake3_hash_benchmark.zig", target, optimize, core, cpu_backend, frontend, integration);
    const blake3_benchmark = b.addExecutable(.{ .name = "blake3-hash-benchmark", .root_module = blake3_benchmark_root });
    b.step("benchmark-blake3-hash", "Measure native BLAKE3 and Poseidon hashing, excluding recursive constraints")
        .dependOn(&b.addRunArtifact(blake3_benchmark).step);
    const blake3_root = support.createHarnessModule(b, "blake3_test_root.zig", target, optimize, core, cpu_backend, frontend, integration);
    blake3_root.addImport("stwo_prover_engine", prover);
    const blake3_names: []const []const u8 = &.{
        "BLAKE3 official primitive vectors and streaming boundaries",
        "BLAKE3 independent protocol vectors retain full digest bits",
        "BLAKE3 field rejection and operation domains",
        "BLAKE3 CPU PCS and FRI roundtrip with core verifier",
        "BLAKE3 CPU commitments reject tampered roots and wrong hash family",
    };
    const blake3_tests = b.addTest(.{ .root_module = blake3_root, .filters = blake3_names });
    b.step("test-blake3-protocol", "Check BLAKE3 reference vectors, transcript, commitments and CPU PCS/FRI")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(blake3_tests), blake3_names, "BLAKE3 protocol test guard"));
}
