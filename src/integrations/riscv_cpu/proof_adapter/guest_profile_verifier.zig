//! Fresh-process verification for the retained `STWGPF01` profile envelope.

const std = @import("std");
const stwo = @import("stwo");
const build_identity = @import("build_identity");
const capabilities = @import("riscv_cpu_capabilities");
const artifact_validation = @import("artifact_validation.zig");
const identity = @import("guest_profile_identity.zig");
const pcs_profile = @import("pcs_profile.zig");
const transcript_state = @import("transcript_state.zig");

const maximum_elf_bytes = 64 * 1024 * 1024;
const maximum_input_bytes = 16 * 1024 * 1024;
const artifact_limits: stwo.frontends.riscv.prover_mod.guest_precompile.proof_artifact.Limits = .{
    .max_artifact_bytes = 256 * 1024 * 1024,
    .max_proof_bytes = 128 * 1024 * 1024,
    .max_input_bytes = maximum_input_bytes,
    .max_output_bytes = 16 * 1024 * 1024,
    .max_queries = 1024,
    .max_pow_bits = 128,
};

pub fn hasMagic(bytes: []const u8) bool {
    return bytes.len >= identity.ARTIFACT_MAGIC.len and
        std.mem.eql(u8, bytes[0..identity.ARTIFACT_MAGIC.len], identity.ARTIFACT_MAGIC);
}

pub fn verifyPath(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    artifact_path: []const u8,
    requested_policy: pcs_profile.Protocol,
    expected_statement_digest: [32]u8,
    elf_path: []const u8,
    input_path: ?[]const u8,
) !void {
    comptime identity.assertProductCapability(capabilities, capabilities.backend);
    if (requested_policy == .smoke) return error.UnsupportedGuestProtocol;
    const encoded = try readFileBounded(
        allocator,
        artifact_path,
        artifact_limits.max_artifact_bytes,
    );
    defer allocator.free(encoded);
    if (!hasMagic(encoded)) return error.UnsupportedArtifactKind;

    const config = pcs_profile.select(requested_policy);
    const artifact_wire = stwo.frontends.riscv.prover_mod.guest_precompile.proof_artifact;
    var decoded = try artifact_wire.decodeAllocForConfig(
        allocator,
        encoded,
        config,
        artifact_limits,
    );
    var proof_moved = false;
    defer if (proof_moved)
        decoded.deinitAfterProofMoved(allocator)
    else
        decoded.deinit(allocator);

    const source = try validateSource(
        allocator,
        elf_path,
        input_path,
        &decoded.statement.public_data,
    );
    const statement_digest = identity.statementDigest(
        @tagName(requested_policy),
        config,
        source.elf_sha256,
        source.input_sha256,
        decoded.artifact.statement_digest,
    );
    if (!std.mem.eql(u8, &expected_statement_digest, &statement_digest))
        return error.StatementDigestMismatch;

    var verify_channel = Engine.Channel{};
    proof_moved = true;
    try stwo.frontends.riscv.prover_mod.verifyPoseidon2WithEngineUsingChannel(
        Engine,
        allocator,
        config,
        decoded.statement,
        decoded.extension,
        decoded.artifact,
        decoded.proof,
        decoded.interaction_claim,
        &verify_channel,
    );

    var artifact_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &artifact_digest, .{});
    const process_identity = try artifact_validation.measureProcessIdentity(allocator);
    const receipt = try encodeReceipt(allocator, .{
        .security_policy = @tagName(requested_policy),
        .statement_sha256 = statement_digest,
        .artifact_bytes = encoded.len,
        .artifact_sha256 = artifact_digest,
        .transcript_state_blake2s = transcript_state.receiptDigest(
            verify_channel.digestBytes(),
            verify_channel.n_draws,
        ),
        .executable_sha256 = process_identity.executable_sha256,
    });
    defer allocator.free(receipt);
    try std.fs.File.stdout().writeAll(receipt);
    try std.fs.File.stdout().writeAll("\n");
}

const SourceIdentity = struct {
    elf_sha256: [32]u8,
    input_sha256: [32]u8,
};

fn validateSource(
    allocator: std.mem.Allocator,
    elf_path: []const u8,
    input_path: ?[]const u8,
    public: *const stwo.frontends.riscv.air.public_data.PublicData,
) !SourceIdentity {
    const runner = stwo.frontends.riscv.runner;
    const elf = try readFileBounded(allocator, elf_path, maximum_elf_bytes);
    defer allocator.free(elf);
    try runner.elf_loader.validateReleaseAbiForProfile(
        elf,
        .rv32im_zkvm_poseidon2_v1,
    );
    const input = if (input_path) |path|
        try readFileBounded(allocator, path, maximum_input_bytes)
    else
        try allocator.alloc(u8, 0);
    defer allocator.free(input);
    try validateInputBinding(input, public);

    var memory = runner.Memory.init(allocator);
    defer memory.deinit();
    const elf_info = try runner.elf_loader.loadElfForProfile(
        elf,
        &memory,
        .rv32im_zkvm_poseidon2_v1,
    );
    if (public.io_entries.input_start != elf_info.input_start or
        public.io_entries.output_len_addr != elf_info.output_len or
        public.io_entries.output_data_addr != elf_info.output_data)
    {
        return error.GuestAbiBindingMismatch;
    }
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
    const no_base_fetches: []const runner.trace.TraceRow = &.{};
    const no_guest_fetches: []const runner.guest_precompile.poseidon2_v1.ExecutionRow = &.{};
    var program = try stwo.frontends.riscv.air.program.commitment.buildDeclaredForProfile(
        allocator,
        .rv32im_zkvm_poseidon2_v1,
        no_base_fetches,
        no_guest_fetches,
        snapshot.program_words,
        null,
    );
    defer program.deinit(allocator);
    if (public.program_root == null or public.program_root.? != program.tree.root)
        return error.ProgramRootMismatch;

    const completion = public.completion orelse return error.MissingCompletion;
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
        .unretired_program_fetch => return error.UnsupportedCompletion,
    }

    var result: SourceIdentity = undefined;
    std.crypto.hash.sha2.Sha256.hash(elf, &result.elf_sha256, .{});
    std.crypto.hash.sha2.Sha256.hash(input, &result.input_sha256, .{});
    return result;
}

fn validateInputBinding(
    input: []const u8,
    public: *const stwo.frontends.riscv.air.public_data.PublicData,
) !void {
    if (input.len != @as(usize, public.io_entries.input_len))
        return error.InputLengthMismatch;
    const words = public.io_entries.input_words;
    const expected_words = std.math.divCeil(usize, input.len, @sizeOf(u32)) catch
        return error.InputLengthMismatch;
    if (words.len != expected_words) return error.InputLengthMismatch;
    for (input, 0..) |byte, index| {
        const word = words[index / @sizeOf(u32)];
        const shift: u5 = @intCast((index % @sizeOf(u32)) * 8);
        if (byte != @as(u8, @truncate(word >> shift)))
            return error.InputDigestMismatch;
    }
    if (input.len % @sizeOf(u32) != 0 and words.len != 0) {
        const used_bits: u5 = @intCast((input.len % @sizeOf(u32)) * 8);
        if (words[words.len - 1] >> used_bits != 0)
            return error.NonCanonicalInputPadding;
    }
}

const ReceiptInput = struct {
    security_policy: []const u8,
    statement_sha256: [32]u8,
    artifact_bytes: usize,
    artifact_sha256: [32]u8,
    transcript_state_blake2s: [32]u8,
    executable_sha256: [32]u8,
};

fn encodeReceipt(allocator: std.mem.Allocator, input: ReceiptInput) ![]u8 {
    const statement_hex = std.fmt.bytesToHex(input.statement_sha256, .lower);
    const artifact_hex = std.fmt.bytesToHex(input.artifact_sha256, .lower);
    const transcript_hex = std.fmt.bytesToHex(input.transcript_state_blake2s, .lower);
    const executable_hex = std.fmt.bytesToHex(input.executable_sha256, .lower);
    return std.json.Stringify.valueAlloc(allocator, .{
        .schema = identity.RECEIPT_SCHEMA,
        .status = "verified",
        .artifact_kind = identity.ARTIFACT_KIND,
        .artifact_schema_version = identity.ARTIFACT_SCHEMA_VERSION,
        .artifact_magic = identity.ARTIFACT_MAGIC,
        .profile_identity = identity.PROFILE_IDENTITY,
        .profile_version = identity.PROFILE_VERSION,
        .profile_manifest_sha256 = identity.PROFILE_MANIFEST_SHA256,
        .release_status = stwo.interop.riscv_artifact.RELEASE_STATUS,
        .security_policy = input.security_policy,
        .statement_sha256 = &statement_hex,
        .artifact_bytes = input.artifact_bytes,
        .artifact_sha256 = &artifact_hex,
        .transcript_state_blake2s = &transcript_hex,
        .implementation_commit = build_identity.implementation_commit,
        .implementation_dirty = build_identity.implementation_dirty,
        .executable_sha256 = &executable_hex,
    }, .{});
}

fn readFileBounded(
    allocator: std.mem.Allocator,
    path: []const u8,
    maximum: usize,
) ![]u8 {
    var file = if (std.fs.path.isAbsolute(path))
        try std.fs.openFileAbsolute(path, .{})
    else
        try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.kind != .file or stat.size > maximum)
        return error.ArtifactResourceLimitExceeded;
    const length = std.math.cast(usize, stat.size) orelse
        return error.ArtifactResourceLimitExceeded;
    const bytes = try allocator.alloc(u8, length);
    errdefer allocator.free(bytes);
    if (try file.readAll(bytes) != bytes.len) return error.UnexpectedEndOfFile;
    var trailing: [1]u8 = undefined;
    if (try file.read(&trailing) != 0) return error.ArtifactChangedDuringRead;
    return bytes;
}

test "guest verifier routes only exact STWGPF01 magic" {
    try std.testing.expect(hasMagic("STWGPF01payload"));
    try std.testing.expect(!hasMagic("STWGPF00payload"));
    try std.testing.expect(!hasMagic("short"));
}

test "guest verification receipt keeps its canonical 17-field order" {
    const encoded = try encodeReceipt(std.testing.allocator, .{
        .security_policy = "secure",
        .statement_sha256 = [_]u8{0x11} ** 32,
        .artifact_bytes = 99,
        .artifact_sha256 = [_]u8{0x22} ** 32,
        .transcript_state_blake2s = [_]u8{0x33} ** 32,
        .executable_sha256 = [_]u8{0x44} ** 32,
    });
    defer std.testing.allocator.free(encoded);
    try std.testing.expect(std.mem.indexOfScalar(u8, encoded, '\n') == null);
    const fields = [_][]const u8{
        "\"schema\":",                "\"status\":",
        "\"artifact_kind\":",         "\"artifact_schema_version\":",
        "\"artifact_magic\":",        "\"profile_identity\":",
        "\"profile_version\":",       "\"profile_manifest_sha256\":",
        "\"release_status\":",        "\"security_policy\":",
        "\"statement_sha256\":",      "\"artifact_bytes\":",
        "\"artifact_sha256\":",       "\"transcript_state_blake2s\":",
        "\"implementation_commit\":", "\"implementation_dirty\":",
        "\"executable_sha256\":",
    };
    var cursor: usize = 0;
    for (fields) |field| {
        const relative = std.mem.indexOf(u8, encoded[cursor..], field) orelse
            return error.MissingReceiptField;
        cursor += relative + field.len;
    }
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, encoded, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(fields.len, parsed.value.object.count());
}
