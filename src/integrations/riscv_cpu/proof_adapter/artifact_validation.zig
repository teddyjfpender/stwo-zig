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
    try validateInitialRwRoot(
        try expectedInitialRwRoot(allocator, snapshot.words),
        artifact.statement.public_data.initial_rw_root,
    );
    try validateIoBinding(artifact.statement.public_data, elf_info);

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

/// The initial RW-memory root an honest prover commits for this image.
///
/// The prover's tree spans the loaded RW words plus every word the guest
/// touched; touched-but-unloaded words enter with zero bytes, and a zero byte
/// is the sparse tree's default leaf, so the root is a pure function of the
/// loaded image.  Public-input words are excluded on both sides, so the root
/// is independent of the input bytes as well.  An image without loaded RW
/// words (no `.data`/`.bss`) yields the empty sparse-tree root
/// `DEFAULT_HASHES[0]`, which is what the prover commits once the guest
/// touches any word.
pub fn expectedInitialRwRoot(
    allocator: std.mem.Allocator,
    words: []const stwo.frontends.riscv.runner.memory_state.WordState,
) !u32 {
    const boundary = stwo.frontends.riscv.air.memory_commitment.boundary;
    return boundary.initialTreeRoot(allocator, words);
}

/// Root of the sparse tree with no leaves: the only initial root an image
/// without loaded RW words can honestly carry.
pub fn emptyInitialRwRoot() u32 {
    return stwo.frontends.riscv.air.memory_commitment.poseidon2.DEFAULT_HASHES[0];
}

/// A statement whose `initial_rw_root` is not the image's root would let the
/// prover start execution from `.data`/`.rodata` contents of its choosing
/// while `program_root` still matches the ELF.
///
/// An absent claim (`null`) means the prover committed no initial tree at
/// all: that is honest only when the image has no loaded RW words and the
/// guest touched none, so it is accepted exactly when the expected root is
/// the empty-tree root.  Any other absent or differing root is rejected.
pub fn validateInitialRwRoot(expected: u32, claimed: ?u32) error{InitialRwRootMismatch}!void {
    const claimed_root = claimed orelse {
        if (expected == emptyInitialRwRoot()) return;
        return error.InitialRwRootMismatch;
    };
    if (expected != claimed_root) return error.InitialRwRootMismatch;
}

/// Binds the public-I/O window of the statement to the ELF's guest ABI, as
/// the guest-profile verifier already does (`GuestAbiBindingMismatch`).
///
/// Without this a prover could relocate the public input to an RW address of
/// its choosing (overriding `.data` contents while `initial_rw_root` still
/// matches the image, since input words are excluded from that root) or
/// point the public output at any memory window.  The runner itself only
/// admits an input that fits `__input_start..__input_end` and an output that
/// fits `__output_data..__output_end`, so the bounds are honest-prover exact.
pub fn validateIoBinding(
    public: stwo.interop.riscv_artifact.PublicDataWire,
    elf: stwo.frontends.riscv.runner.elf_loader.ElfInfo,
) error{IoBindingMismatch}!void {
    if (public.input_start != elf.input_start or
        public.output_len_addr != elf.output_len or
        public.output_data_addr != elf.output_data)
        return error.IoBindingMismatch;
    if (elf.input_end < elf.input_start or public.input_len > elf.input_end - elf.input_start)
        return error.IoBindingMismatch;
    if (elf.output_end < elf.output_data or public.output_len > elf.output_end - elf.output_data)
        return error.IoBindingMismatch;
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
