//! Local artifact bindings checked before the staged proof verifier runs.
//!
//! These checks bind a proof artifact to the selected ELF, this executable,
//! the local witness layout, and the exact PCS shape admitted by the wire.

const std = @import("std");
const stwo = @import("stwo");
const build_identity = @import("build_identity");

pub const ProcessIdentity = struct {
    executable_sha256: [32]u8,
};

pub fn validateElfBinding(
    allocator: std.mem.Allocator,
    artifact: stwo.interop.riscv_artifact.Artifact,
    elf_path: []const u8,
) !void {
    const runner = stwo.frontends.riscv.runner;
    const program_commitment = stwo.frontends.riscv.air.program.commitment;
    const elf_bytes = try std.fs.cwd().readFileAlloc(allocator, elf_path, 64 * 1024 * 1024);
    defer allocator.free(elf_bytes);
    try runner.elf_loader.validateReleaseAbi(elf_bytes);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(elf_bytes, &digest, .{});
    const digest_hex = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, artifact.source.elf_sha256, &digest_hex))
        return error.ElfDigestMismatch;

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
    var program = try program_commitment.build(allocator, &.{}, snapshot.program_words);
    defer program.deinit(allocator);
    if (artifact.statement.public_data.program_root.? != program.tree.root)
        return error.ProgramRootMismatch;

    const completion = artifact.statement.public_data.completion;
    switch (completion.kind) {
        .halt_flag => {
            if (completion.address != elf_info.halt_flag)
                return error.CompletionSymbolMismatch;
            if (memory.readU32(elf_info.halt_flag) != 0)
                return error.NonZeroInitialHaltFlag;
        },
        .unretired_self_loop => {
            if (memory.readU32(completion.address) != completion.value)
                return error.CompletionInstructionMismatch;
        },
    }
}

pub fn measureProcessIdentity(allocator: std.mem.Allocator) !ProcessIdentity {
    const executable_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(executable_path);
    const file = try std.fs.openFileAbsolute(executable_path, .{});
    defer file.close();
    const before = try file.stat();
    if (before.kind != .file or before.size == 0) return error.InvalidExecutable;

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [256 * 1024]u8 = undefined;
    var measured_bytes: u64 = 0;
    while (true) {
        const count = try file.read(&buffer);
        if (count == 0) break;
        hasher.update(buffer[0..count]);
        measured_bytes = std.math.add(u64, measured_bytes, count) catch
            return error.InvalidExecutable;
    }
    const after = try file.stat();
    if (measured_bytes != before.size or before.size != after.size or
        before.inode != after.inode or before.mtime != after.mtime)
        return error.ExecutableChangedDuringMeasurement;
    return .{ .executable_sha256 = hasher.finalResult() };
}

pub fn proofPreflightShape(
    artifact: stwo.interop.riscv_artifact.Artifact,
) !stwo.interop.postcard.proof_preflight.Shape {
    const protocol = stwo.interop.riscv_artifact.wire_protocol;
    const prover = stwo.frontends.riscv.prover_mod;

    var preprocessed_columns: u64 = std.math.mul(
        u64,
        artifact.statement.components.len,
        2,
    ) catch return error.InvalidArtifact;
    var main_columns: u64 = 0;
    var interaction_columns: u64 = 0;
    var max_log_size: u32 = 0;
    for (artifact.statement.components) |component| {
        main_columns = std.math.add(u64, main_columns, component.n_columns) catch
            return error.InvalidArtifact;
        const interaction = std.math.mul(
            u64,
            component.interaction_batch_count,
            4,
        ) catch return error.InvalidArtifact;
        interaction_columns = std.math.add(u64, interaction_columns, interaction) catch
            return error.InvalidArtifact;
        max_log_size = @max(max_log_size, component.log_size);
    }
    for (artifact.statement.infrastructure) |component| {
        const kind = std.meta.intToEnum(protocol.InfraKind, component.kind) catch
            return error.InvalidArtifact;
        preprocessed_columns = std.math.add(
            u64,
            preprocessed_columns,
            protocol.preprocessedColumns(kind),
        ) catch return error.InvalidArtifact;
        main_columns = std.math.add(u64, main_columns, component.n_columns) catch
            return error.InvalidArtifact;
        const interaction = std.math.mul(u64, component.claim_count, 4) catch
            return error.InvalidArtifact;
        interaction_columns = std.math.add(u64, interaction_columns, interaction) catch
            return error.InvalidArtifact;
        max_log_size = @max(max_log_size, component.log_size);
    }

    return .{
        .config = .{
            .pow_bits = artifact.pcs_config.pow_bits,
            .log_blowup_factor = artifact.pcs_config.fri_config.log_blowup_factor,
            .n_queries = artifact.pcs_config.fri_config.n_queries,
            .log_last_layer_degree_bound = artifact.pcs_config.fri_config.log_last_layer_degree_bound,
            .fold_step = artifact.pcs_config.fri_config.fold_step,
            .lifting_log_size = artifact.pcs_config.lifting_log_size,
        },
        .tree_columns = .{
            std.math.cast(u32, preprocessed_columns) orelse return error.InvalidArtifact,
            std.math.cast(u32, main_columns) orelse return error.InvalidArtifact,
            std.math.cast(u32, interaction_columns) orelse return error.InvalidArtifact,
            2 * stwo.core.fields.qm31.SECURE_EXTENSION_DEGREE,
        },
        .max_column_log_size = max_log_size,
        .hash_size = @sizeOf(prover.Hasher.Hash),
        .max_wire_bytes = stwo.interop.riscv_artifact.MAX_PROOF_BYTES,
    };
}

pub fn validateLocalProvenance(
    provenance: stwo.interop.riscv_artifact.ProvenanceWire,
) !void {
    if (!std.mem.eql(u8, provenance.implementation_commit, build_identity.implementation_commit) or
        provenance.implementation_dirty != build_identity.implementation_dirty)
        return error.ImplementationIdentityMismatch;
    const expected_layout = std.fmt.bytesToHex(
        stwo.frontends.riscv.witness_layout.digest(),
        .lower,
    );
    if (!std.mem.eql(u8, provenance.witness_layout_sha256, &expected_layout))
        return error.WitnessLayoutMismatch;
}

pub fn pcsConfigsEqual(expected: anytype, actual: @TypeOf(expected)) bool {
    return expected.pow_bits == actual.pow_bits and
        expected.fri_config.log_blowup_factor == actual.fri_config.log_blowup_factor and
        expected.fri_config.log_last_layer_degree_bound == actual.fri_config.log_last_layer_degree_bound and
        expected.fri_config.n_queries == actual.fri_config.n_queries and
        expected.fri_config.fold_step == actual.fri_config.fold_step and
        expected.lifting_log_size == actual.lifting_log_size;
}
