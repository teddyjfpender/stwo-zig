//! Transaction-local admission capability for a candidate Ethereum session.
//!
//! The legacy receipt proves custody only for the SWAP-only guest fixture and
//! cannot promote it. A disjoint combined receipt can mint the final candidate
//! class only after cold reopening ELF bytes, source closure, program
//! commitment, and session construction. Neither class activates production.

const std = @import("std");

const registry_mod =
    @import("../../isa/ethereum_candidate_private_registry_v1.zig");
const combined_authority_mod =
    @import("../../isa/ethereum_candidate_combined_authority_v1.zig");
const swap_authority_mod =
    @import("../../isa/ethereum_stack_swap_candidate_v1.zig");
const combined_decode =
    @import("../../prover/guest_precompile/ethereum_stack_swap_candidate_decode_v1.zig");
const segment_session = @import("../segment_session.zig");
const receipt_mod =
    @import("ethereum_stack_swap_candidate_elf_receipt_v1.zig");
const combined_receipt_mod =
    @import("ethereum_candidate_combined_elf_receipt_v1.zig");

pub const Digest = [32]u8;
pub const production_active = false;
pub const proof_or_fresh_verification = false;
pub const format_version: u16 = 1;
pub const schema_version: u16 = 1;

const MintSeal = enum(u8) {
    transaction_verified = 0xa7,
};

pub const ExecutableClass = enum(u8) {
    /// Existing admitted ELF: registry reserves bulk, executable contains no
    /// bulk opcode. It is useful only for capability/journal regressions.
    stack_swap_fixture = 1,
    /// Receipt-admitted executable containing every ordered member of the
    /// combined candidate registry. It remains nonproduction.
    combined_candidate = 2,
};

pub const FixtureSession =
    segment_session.EthereumStackSwapCandidateExecutionSessionV1();
pub const CombinedSession =
    segment_session.EthereumCombinedCandidateExecutionSessionV1();

pub const Capability = struct {
    format: u16 = format_version,
    schema: u16 = schema_version,
    executable_class: ExecutableClass,
    final_candidate_executable: bool,
    registry: registry_mod.Registry,
    guest_elf_sha256: Digest,
    admission_receipt_identity: Digest,
    source_closure_identity: Digest,
    program_row_count: u64,
    program_root: u32,
    program_commitment_identity: Digest,
    session_authority_identity: Digest,
    stack_swap_fixture_authority: swap_authority_mod.Authority,
    combined_candidate_authority: ?combined_authority_mod.Authority,
    identity: Digest,
    mint_seal: MintSeal,

    pub fn validate(self: Capability) !void {
        if (production_active or proof_or_fresh_verification or
            self.format != format_version or self.schema != schema_version or
            self.mint_seal != .transaction_verified or
            isZero(self.guest_elf_sha256) or
            isZero(self.admission_receipt_identity) or
            isZero(self.source_closure_identity) or
            self.program_row_count == 0 or self.program_root == 0 or
            isZero(self.program_commitment_identity) or
            isZero(self.session_authority_identity))
        {
            return error.InvalidEthereumCandidateExecutionCapability;
        }
        try self.registry.validate();
        try self.stack_swap_fixture_authority.validate();
        const bulk = try self.registry.member(.bulk_memcpy_v1);
        const swap = try self.registry.member(.stack_swap_v1);
        if (bulk.funct7 != 4 or bulk.proof_opcode_id != 48 or
            swap.funct7 != self.stack_swap_fixture_authority.stack_swap.allocation.funct7 or
            swap.proof_opcode_id !=
                self.stack_swap_fixture_authority.stack_swap.allocation.proof_opcode_id or
            swap.fixed_word != self.stack_swap_fixture_authority.stack_swap.fixed_word or
            !std.mem.eql(
                u8,
                &swap.semantic_authority_identity,
                &self.stack_swap_fixture_authority.stack_swap.semantic_identity,
            ))
        {
            return error.InvalidEthereumCandidateExecutionRegistryBinding;
        }
        switch (self.executable_class) {
            .stack_swap_fixture => {
                if (self.final_candidate_executable or
                    self.combined_candidate_authority != null or
                    !std.mem.eql(
                        u8,
                        &self.guest_elf_sha256,
                        &self.stack_swap_fixture_authority.guest_elf_sha256,
                    ) or !std.mem.eql(
                    u8,
                    &self.session_authority_identity,
                    &self.stack_swap_fixture_authority.identity,
                ) or !std.mem.eql(
                    u8,
                    &self.registry.stack_swap_fixture_registry_identity,
                    &self.stack_swap_fixture_authority.stack_swap.allocation.registry_identity,
                )) {
                    return error.InvalidEthereumCandidateExecutionCapability;
                }
            },
            .combined_candidate => {
                const authority = self.combined_candidate_authority orelse
                    return error.InvalidEthereumCandidateExecutionCapability;
                try authority.validate();
                if (!self.final_candidate_executable or
                    !std.meta.eql(self.registry, authority.registry) or
                    !std.meta.eql(
                        self.stack_swap_fixture_authority,
                        authority.stack_swap,
                    ) or !std.mem.eql(
                    u8,
                    &self.guest_elf_sha256,
                    &authority.guest_elf_sha256,
                ) or !std.mem.eql(
                    u8,
                    &self.session_authority_identity,
                    &authority.identity,
                )) {
                    return error.InvalidEthereumCandidateExecutionCapability;
                }
            },
        }
        const expected = capabilityIdentity(self);
        if (!std.mem.eql(u8, &self.identity, &expected))
            return error.InvalidEthereumCandidateExecutionCapabilityIdentity;
    }

    /// Reopens the fixture bytes transaction-locally and constructs the only
    /// session type which can consume this capability. The default Ethereum
    /// session has no corresponding constructor.
    pub fn initFixtureSession(
        self: Capability,
        allocator: std.mem.Allocator,
        elf_bytes: []const u8,
        options: segment_session.SessionOptions,
    ) !FixtureSession {
        try self.validate();
        if (self.executable_class != .stack_swap_fixture)
            return error.EthereumStackSwapFixtureCapabilityRequired;
        const reopened_digest = receipt_mod.hashBytes(elf_bytes);
        if (!std.mem.eql(u8, &reopened_digest, &self.guest_elf_sha256))
            return error.EthereumCandidateExecutableIdentityMismatch;
        return FixtureSession.initCandidate(
            allocator,
            elf_bytes,
            options,
            self.stack_swap_fixture_authority,
        );
    }

    /// Reopen the final combined bytes before constructing the only session
    /// which can consume this authority. The receipt/source closure was
    /// already revalidated in `mintCombinedCandidate`.
    pub fn initCombinedSession(
        self: Capability,
        allocator: std.mem.Allocator,
        elf_bytes: []const u8,
        options: segment_session.SessionOptions,
    ) !CombinedSession {
        try self.validate();
        if (self.executable_class != .combined_candidate)
            return error.EthereumCombinedCandidateCapabilityRequired;
        const authority = self.combined_candidate_authority orelse
            return error.EthereumCombinedCandidateCapabilityRequired;
        const reopened_digest = combined_receipt_mod.hashBytes(elf_bytes);
        if (!std.mem.eql(u8, &reopened_digest, &self.guest_elf_sha256))
            return error.EthereumCandidateExecutableIdentityMismatch;
        try authority.validateElf(elf_bytes);
        return CombinedSession.initCandidate(
            allocator,
            elf_bytes,
            options,
            authority,
        );
    }
};

/// Mint only after receipt bytes, ELF bytes, and every source/Cargo file have
/// been reopened by the current transaction. No digest-only transport value
/// can call the candidate session constructor on its own.
pub fn mintStackSwapFixture(
    allocator: std.mem.Allocator,
    receipt: receipt_mod.Receipt,
    reopened_elf: []const u8,
    reopened_source_files: [receipt_mod.source_paths.len]receipt_mod.FileIdentity,
    registry: registry_mod.Registry,
) !Capability {
    try receipt.validate();
    try registry.validate();
    if (!receipt_mod.sameFiles(reopened_source_files, receipt.source_files) or
        !std.mem.eql(
            u8,
            &registry.stack_swap_fixture_registry_identity,
            &receipt.registry_identity,
        ))
    {
        return error.EthereumCandidateAdmissionCustodyMismatch;
    }
    const reopened_digest = receipt_mod.hashBytes(reopened_elf);
    if (reopened_elf.len != receipt.elf_bytes or
        !std.mem.eql(u8, &reopened_digest, &receipt.elf_sha256) or
        !std.mem.eql(
            u8,
            &reopened_digest,
            &receipt.externally_expected_elf_sha256,
        ))
    {
        return error.EthereumCandidateExecutableIdentityMismatch;
    }

    const authority = try swap_authority_mod.Authority.create(reopened_digest);
    try authority.validateElf(reopened_elf);
    const decoder = try combined_decode.DeclaredDecodeAuthority.init(authority);
    var inventory = try receipt_mod.inspectElf(allocator, reopened_elf, decoder);
    defer inventory.deinit(allocator);
    if (!receipt_mod.sameInventory(inventory.inventory, receipt.inventory))
        return error.EthereumCandidateExecutableInventoryMismatch;
    const program = try receipt_mod.buildProgramCommitment(
        allocator,
        decoder,
        &inventory,
        authority,
    );
    if (program.row_count != receipt.program_row_count or
        program.root != receipt.program_root or
        !std.mem.eql(
            u8,
            &program.identity,
            &receipt.program_commitment_identity,
        ))
    {
        return error.EthereumCandidateProgramCommitmentMismatch;
    }
    // This retained fixture predates the bulk guest overlay. Its executable
    // inventory must remain SWAP-only even though the registry reserves both.
    if (inventory.inventory.stack_swap_word_count == 0 or
        inventory.inventory.custom0_word_count !=
            inventory.inventory.keccak_word_count +
                inventory.inventory.recovery_word_count +
                inventory.inventory.stack_swap_word_count)
    {
        return error.InvalidStackSwapFixtureInventory;
    }
    try receipt_mod.constructAndDeinitSession(allocator, reopened_elf, authority);

    var result = Capability{
        .executable_class = .stack_swap_fixture,
        .final_candidate_executable = false,
        .registry = registry,
        .guest_elf_sha256 = reopened_digest,
        .admission_receipt_identity = receipt.receipt_identity,
        .source_closure_identity = receipt.source_closure_identity,
        .program_row_count = program.row_count,
        .program_root = program.root,
        .program_commitment_identity = program.identity,
        .session_authority_identity = authority.identity,
        .stack_swap_fixture_authority = authority,
        .combined_candidate_authority = null,
        .identity = undefined,
        .mint_seal = .transaction_verified,
    };
    result.identity = capabilityIdentity(result);
    try result.validate();
    return result;
}

/// Mint the final combined candidate only from Halley's cold-reopened receipt
/// and the exact source closure it names. `Authority.create(digest)` alone can
/// never enter this boundary.
pub fn mintCombinedCandidate(
    allocator: std.mem.Allocator,
    receipt: combined_receipt_mod.Receipt,
    reopened_elf: []const u8,
    reopened_source_closure: combined_receipt_mod.SourceClosure,
    registry: registry_mod.Registry,
) !Capability {
    try receipt.validate();
    try registry.validate();
    if (!receipt.final_candidate_executable)
        return error.FinalEthereumCombinedCandidateExecutableRequired;
    try combined_receipt_mod.validateReopened(
        allocator,
        receipt,
        reopened_elf,
        reopened_source_closure,
    );
    const authority = try combined_authority_mod.Authority.create(
        receipt.elf.sha256,
    );
    try authority.validateElf(reopened_elf);
    if (!std.meta.eql(registry, authority.registry) or
        !std.mem.eql(u8, &receipt.registry_identity, &registry.identity) or
        !std.mem.eql(u8, &receipt.authority_identity, &authority.identity))
    {
        return error.EthereumCandidateAdmissionCustodyMismatch;
    }

    var result = Capability{
        .executable_class = .combined_candidate,
        .final_candidate_executable = true,
        .registry = registry,
        .guest_elf_sha256 = receipt.elf.sha256,
        .admission_receipt_identity = receipt.identity,
        .source_closure_identity = receipt.source_closure.identity,
        .program_row_count = receipt.program_row_count,
        .program_root = receipt.program_root,
        .program_commitment_identity = receipt.program_commitment_identity,
        .session_authority_identity = authority.identity,
        .stack_swap_fixture_authority = authority.stack_swap,
        .combined_candidate_authority = authority,
        .identity = undefined,
        .mint_seal = .transaction_verified,
    };
    result.identity = capabilityIdentity(result);
    try result.validate();
    return result;
}

fn capabilityIdentity(value: Capability) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-candidate-execution-capability.v1\x00");
    putInt(&hash, u16, value.format);
    putInt(&hash, u16, value.schema);
    putInt(&hash, u8, @intFromEnum(value.executable_class));
    hash.update(&.{@intFromBool(value.final_candidate_executable)});
    hash.update(&value.registry.identity);
    hash.update(&value.guest_elf_sha256);
    hash.update(&value.admission_receipt_identity);
    hash.update(&value.source_closure_identity);
    putInt(&hash, u64, value.program_row_count);
    putInt(&hash, u32, value.program_root);
    hash.update(&value.program_commitment_identity);
    hash.update(&value.session_authority_identity);
    return hash.finalResult();
}

fn putInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn isZero(value: Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

comptime {
    if (production_active or proof_or_fresh_verification or
        format_version != 1 or schema_version != 1 or
        registry_mod.production_active or swap_authority_mod.production_active or
        combined_authority_mod.production_active or
        receipt_mod.production_active or receipt_mod.proof_or_fresh_verification or
        combined_receipt_mod.production_active or
        combined_receipt_mod.proof_or_fresh_verification)
    {
        @compileError("Ethereum candidate execution capability became active");
    }
}

test "combined candidate contract v1: capability cannot promote the SWAP fixture" {
    const elf_identity = patternedDigest(1);
    const registry = try registry_mod.Registry.canonical();
    const authority = try swap_authority_mod.Authority.create(elf_identity);
    var capability = Capability{
        .executable_class = .stack_swap_fixture,
        .final_candidate_executable = false,
        .registry = registry,
        .guest_elf_sha256 = elf_identity,
        .admission_receipt_identity = patternedDigest(2),
        .source_closure_identity = patternedDigest(3),
        .program_row_count = 7,
        .program_root = 11,
        .program_commitment_identity = patternedDigest(4),
        .session_authority_identity = authority.identity,
        .stack_swap_fixture_authority = authority,
        .combined_candidate_authority = null,
        .identity = undefined,
        .mint_seal = .transaction_verified,
    };
    capability.identity = capabilityIdentity(capability);
    try capability.validate();

    var promoted = capability;
    promoted.final_candidate_executable = true;
    promoted.identity = capabilityIdentity(promoted);
    try std.testing.expectError(
        error.InvalidEthereumCandidateExecutionCapability,
        promoted.validate(),
    );
    var changed_registry = capability;
    changed_registry.registry.identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidEthereumCandidateRegistryIdentity,
        changed_registry.validate(),
    );
}

test "combined candidate contract v1: final capability requires cold reopened receipt" {
    const test_elf = @import("test_elf.zig");
    const elf = test_elf.buildEthereumCombinedCandidate();
    const elf_identity = combined_receipt_mod.hashBytes(&elf);
    const source_files = [_]combined_receipt_mod.FileIdentity{
        .{
            .path = "candidate/guest.rs",
            .bytes = 17,
            .sha256 = patternedDigest(20),
        },
        .{
            .path = "candidate/Cargo.lock",
            .bytes = 19,
            .sha256 = patternedDigest(21),
        },
    };
    const source_closure = try combined_receipt_mod.SourceClosure.create(
        &source_files,
    );
    const checker = combined_receipt_mod.FileIdentity{
        .path = "/private/tmp/test-ethereum-combined-candidate-checker",
        .bytes = 23,
        .sha256 = patternedDigest(22),
    };
    const receipt = try combined_receipt_mod.createFromReopened(
        std.testing.allocator,
        "/private/tmp/test-ethereum-combined-candidate.elf",
        &elf,
        elf_identity,
        checker,
        "/private/tmp/test-ethereum-combined-source",
        source_closure,
        true,
    );
    const registry = try registry_mod.Registry.canonical();
    const capability = try mintCombinedCandidate(
        std.testing.allocator,
        receipt,
        &elf,
        source_closure,
        registry,
    );
    try capability.validate();
    try std.testing.expectEqual(
        ExecutableClass.combined_candidate,
        capability.executable_class,
    );
    try std.testing.expect(capability.final_candidate_executable);
    var session = try capability.initCombinedSession(
        std.testing.allocator,
        &elf,
        .{},
    );
    session.deinit();

    var mutated = capability;
    mutated.admission_receipt_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidEthereumCandidateExecutionCapabilityIdentity,
        mutated.validate(),
    );
}

fn patternedDigest(seed: u8) Digest {
    var result: Digest = undefined;
    for (&result, 0..) |*byte, index| byte.* = seed +% @as(u8, @truncate(index));
    return result;
}
