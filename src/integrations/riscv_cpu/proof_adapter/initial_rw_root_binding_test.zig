//! The staged verifier recomputes the initial RW-memory root from the ELF
//! image and rejects an artifact whose `initial_rw_root` disagrees.

const std = @import("std");
const stwo = @import("stwo");
const artifact_validation = @import("artifact_validation.zig");

const runner = stwo.frontends.riscv.runner;
const WordState = runner.memory_state.WordState;

fn layout() runner.memory_state.MemoryLayout {
    return .{
        .program_base = 0x0001_0000,
        .program_end = 0x0002_0000,
        .data_base = 0x0002_0000,
        .data_end = 0x0010_0000,
        .stack_bottom = 0x0010_0000,
        .stack_top = 0x0020_0000,
        .io_base = 0x0020_0000,
        .io_end = 0x0030_0000,
        .input_base = 0x0028_0000,
        .input_end = 0x0029_0000,
        .output_len_addr = 0x0020_0004,
        .output_data_addr = 0x0020_0008,
        .output_base = 0x0020_0008,
        .output_end = 0x0027_0000,
    };
}

fn captureImage(allocator: std.mem.Allocator, memory: *runner.Memory) !runner.memory_state.Snapshot {
    var tracker = runner.state_chain.StateChainTracker.init(allocator);
    defer tracker.deinit();
    return runner.memory_state.capture(
        allocator,
        memory,
        &tracker,
        layout(),
        runner.memory_state.SegmentRole.single(),
        0,
        null,
    );
}

test "initial RW root: recomputed from the loaded image and compared exactly" {
    const allocator = std.testing.allocator;
    var memory = runner.Memory.init(allocator);
    defer memory.deinit();
    memory.writeU32(0x0002_0000, 0xdead_beef); // .data
    memory.writeU32(0x0002_0010, 0); // zero-initialised .bss word
    memory.writeU32(0x0028_0000, 0x1234_5678); // public input placement
    var snapshot = try captureImage(allocator, &memory);
    defer snapshot.deinit(allocator);

    const expected = (try artifact_validation.expectedInitialRwRoot(allocator, snapshot.words)).?;

    // The honest prover's boundary witness commits the same root.
    const boundary = stwo.frontends.riscv.air.memory_commitment.boundary;
    var claims = try boundary.build(allocator, snapshot.words);
    defer claims.deinit(allocator);
    try std.testing.expectEqual(claims.initial_tree.?.root, expected);

    try artifact_validation.validateInitialRwRoot(expected, expected);
    try std.testing.expectError(error.InitialRwRootMismatch, artifact_validation.validateInitialRwRoot(expected, expected ^ 1));
    try std.testing.expectError(error.InitialRwRootMismatch, artifact_validation.validateInitialRwRoot(expected, null));
    try std.testing.expectError(error.InitialRwRootMismatch, artifact_validation.validateInitialRwRoot(null, expected));
    try artifact_validation.validateInitialRwRoot(null, null);

    // Public-input bytes never enter the initial tree, so the root the
    // verifier derives is independent of the input it was run with.
    memory.writeU32(0x0028_0000, 0x9999_9999);
    var with_other_input = try captureImage(allocator, &memory);
    defer with_other_input.deinit(allocator);
    try std.testing.expectEqual(expected, (try artifact_validation.expectedInitialRwRoot(allocator, with_other_input.words)).?);

    // A guest touching an unloaded word sees zero bytes: the default leaf.
    const touched = try allocator.alloc(WordState, snapshot.words.len + 1);
    defer allocator.free(touched);
    @memcpy(touched[0..snapshot.words.len], snapshot.words);
    touched[snapshot.words.len] = .{ .addr = 0x0010_0040, .initial_word = 0, .final_word = 42, .final_clock = 3 };
    try std.testing.expectEqual(expected, (try artifact_validation.expectedInitialRwRoot(allocator, touched)).?);

    // Altered `.data` contents move the root.
    memory.writeU32(0x0002_0000, 0xdead_bee0);
    var altered = try captureImage(allocator, &memory);
    defer altered.deinit(allocator);
    try std.testing.expect(expected != (try artifact_validation.expectedInitialRwRoot(allocator, altered.words)).?);
}

test "initial RW root: the artifact route rejects an altered initial_rw_root" {
    const allocator = std.testing.allocator;
    // The retained CSP guest is addressed from the repository root; package-
    // local test runs start a few directories below it.
    const candidates = [_][]const u8{
        "vectors/riscv_csp/guests/sha256.elf",
        "../../../vectors/riscv_csp/guests/sha256.elf",
    };
    var elf_path: []const u8 = undefined;
    var elf_bytes: []u8 = undefined;
    var found = false;
    for (candidates) |candidate| {
        elf_bytes = std.fs.cwd().readFileAlloc(allocator, candidate, 64 * 1024 * 1024) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        elf_path = candidate;
        found = true;
        break;
    }
    if (!found) return error.SkipZigTest;
    defer allocator.free(elf_bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(elf_bytes, &digest, .{});
    const digest_hex = std.fmt.bytesToHex(digest, .lower);

    var memory = runner.Memory.init(allocator);
    defer memory.deinit();
    const elf_info = try runner.elf_loader.loadElf(elf_bytes, &memory);
    var tracker = runner.state_chain.StateChainTracker.init(allocator);
    defer tracker.deinit();
    var snapshot = try runner.memory_state.capture(
        allocator,
        &memory,
        &tracker,
        elf_info.memory_layout,
        runner.memory_state.SegmentRole.single(),
        0,
        null,
    );
    defer snapshot.deinit(allocator);
    var program = try stwo.frontends.riscv.air.program.commitment.build(allocator, &.{}, snapshot.program_words);
    defer program.deinit(allocator);
    const initial_rw_root = try artifact_validation.expectedInitialRwRoot(allocator, snapshot.words);
    try std.testing.expect(initial_rw_root != null);

    const schema = stwo.interop.riscv_artifact;
    var artifact = schema.Artifact{
        .artifact_kind = "riscv-cpu-proof",
        .schema_version = 1,
        .exchange_mode = "test",
        .release_status = "test",
        .generator = "test",
        .air = "test",
        .backend = "test",
        .protocol = "functional",
        .source = .{ .elf_sha256 = &digest_hex, .input_sha256 = "00" ** 32 },
        .provenance = .{
            .oracle_repository = schema.ORACLE_REPOSITORY,
            .oracle_commit = schema.ORACLE_COMMIT,
            .implementation_repository = schema.IMPLEMENTATION_REPOSITORY,
            .implementation_commit = "00" ** 20,
            .implementation_dirty = false,
            .witness_layout_sha256 = "00" ** 32,
        },
        .pcs_config = .{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 1 } },
        .statement = .{
            .segment_ordinal = 0,
            .segment_count = 1,
            .initial_pc = elf_info.entry_point,
            .final_pc = elf_info.entry_point,
            .total_steps = 1,
            .components = &.{},
            .infrastructure = &.{},
            .public_data = .{
                .initial_pc = elf_info.entry_point,
                .final_pc = elf_info.entry_point,
                .clock = 1,
                .initial_regs = .{0} ** 32,
                .final_regs = .{0} ** 32,
                .reg_last_clock = .{0} ** 32,
                .program_root = program.tree.root,
                .initial_rw_root = initial_rw_root,
                .final_rw_root = null,
                .completion = .{ .kind = .halt_flag, .address = elf_info.halt_flag, .value = 1, .clock = 1 },
                .input_start = elf_info.input_start,
                .input_len = 0,
                .input_words = &.{},
                .output_len = 0,
                .output_len_addr = elf_info.output_len,
                .output_data_addr = elf_info.output_data,
                .output_words = &.{},
            },
        },
        .interaction_claim = .{ .interaction_pow = 0, .opcode_claims = &.{}, .infrastructure_claims = &.{} },
        .proof_bytes_hex = "",
    };
    try artifact_validation.validateElfBinding(allocator, artifact, elf_path);

    artifact.statement.public_data.initial_rw_root = initial_rw_root.? ^ 1;
    try std.testing.expectError(error.InitialRwRootMismatch, artifact_validation.validateElfBinding(allocator, artifact, elf_path));
    artifact.statement.public_data.initial_rw_root = null;
    try std.testing.expectError(error.InitialRwRootMismatch, artifact_validation.validateElfBinding(allocator, artifact, elf_path));
    artifact.statement.public_data.initial_rw_root = initial_rw_root;
    artifact.statement.public_data.program_root = program.tree.root ^ 1;
    try std.testing.expectError(error.ProgramRootMismatch, artifact_validation.validateElfBinding(allocator, artifact, elf_path));
}
