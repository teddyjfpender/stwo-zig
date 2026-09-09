//! Candidate-only admission receipt for the immutable Ethereum+SWAP guest.
//!
//! This is not proof evidence and cannot activate a production profile. The
//! caller supplies an external ELF digest, which is checked before the
//! candidate authority is constructed. Every executable PT_LOAD word is then
//! decoded through the closed Ethereum+SWAP decoder and committed with zero
//! multiplicity. Absolute paths are diagnostic; byte digests and identities
//! are the authority carried by the receipt.

const std = @import("std");

const program_commitment = @import("../../air/program/commitment.zig");
const custom0 = @import("../../isa/custom0.zig");
const authority_mod = @import("../../isa/ethereum_stack_swap_candidate_v1.zig");
const memory_state = @import("../memory_state.zig");
const segment_session = @import("../segment_session.zig");
const combined_decode =
    @import("../../prover/guest_precompile/ethereum_stack_swap_candidate_decode_v1.zig");

pub const Digest = [32]u8;
pub const schema = "stwo.riscv.ethereum-stack-swap-candidate-elf-check.v1";
pub const schema_version: u16 = 1;
pub const production_active = false;
pub const proof_or_fresh_verification = false;

pub const expected_elf_bytes: u64 = 3_709_216;
pub const expected_executable_pt_load_count: u32 = 1;
pub const expected_executable_file_bytes: u64 = 3_224_348;
pub const expected_executable_word_count: u64 = 806_087;
pub const expected_custom0_count: usize = 22;
pub const expected_keccak_word: u32 = 0x0402_800b;
pub const expected_recovery_word: u32 = 0x0602_800b;
pub const expected_stack_swap_word: u32 = 0x0ab5_000b;
pub const expected_keccak_count: u32 = 4;
pub const expected_recovery_count: u32 = 2;
pub const expected_stack_swap_count: u32 = 16;

pub const source_paths = [_][]const u8{
    "crates/stateless-validator-reth/src/guest/stack_swap_candidate_v1.rs",
    "crates/stateless-validator-reth/src/guest.rs",
    "crates/stateless-validator-reth/src/guest/convert.rs",
    "Cargo.toml",
    "Cargo.lock",
    "crates/stateless-validator-reth/Cargo.toml",
    "bin/stateless-validator-reth/stwo/Cargo.toml",
    "bin/stateless-validator-reth/stwo/.cargo/config.toml",
    "bin/stateless-validator-reth/stwo/riscv32imc-unknown-none-elf.json",
    "bin/stateless-validator-reth/stwo/linker.ld",
};
pub const guest_source_file_count: usize = 3;

pub const FileIdentity = struct {
    path: []const u8,
    bytes: u64,
    sha256: Digest,
};

pub const Custom0Occurrence = struct {
    address: u32,
    word: u32,
};

pub const Inventory = struct {
    executable_pt_load_count: u32,
    executable_file_bytes: u64,
    executable_memory_bytes: u64,
    executable_word_count: u64,
    nonzero_word_count: u64,
    custom0_word_count: u32,
    keccak_word_count: u32,
    recovery_word_count: u32,
    stack_swap_word_count: u32,
    custom0_occurrences: [expected_custom0_count]Custom0Occurrence,
    word_inventory_sha256: Digest,

    pub fn validate(self: Inventory) !void {
        if (self.executable_pt_load_count != expected_executable_pt_load_count or
            self.executable_file_bytes != expected_executable_file_bytes or
            self.executable_word_count != expected_executable_word_count or
            self.executable_memory_bytes < self.executable_file_bytes or
            self.nonzero_word_count == 0 or
            self.nonzero_word_count > self.executable_word_count or
            self.custom0_word_count != expected_custom0_count or
            self.keccak_word_count != expected_keccak_count or
            self.recovery_word_count != expected_recovery_count or
            self.stack_swap_word_count != expected_stack_swap_count or
            isZero(self.word_inventory_sha256))
        {
            return error.InvalidStackSwapElfInventory;
        }
        var previous_address: ?u32 = null;
        var keccak_count: u32 = 0;
        var recovery_count: u32 = 0;
        var swap_count: u32 = 0;
        for (self.custom0_occurrences) |occurrence| {
            if (previous_address) |address| if (occurrence.address <= address)
                return error.InvalidStackSwapElfInventory;
            previous_address = occurrence.address;
            switch (occurrence.word) {
                expected_keccak_word => keccak_count += 1,
                expected_recovery_word => recovery_count += 1,
                expected_stack_swap_word => swap_count += 1,
                else => return error.StrayCustom0Word,
            }
        }
        if (keccak_count != self.keccak_word_count or
            recovery_count != self.recovery_word_count or
            swap_count != self.stack_swap_word_count)
        {
            return error.InvalidStackSwapElfInventory;
        }
    }
};

pub const Receipt = struct {
    elf_path: []const u8,
    source_root: []const u8,
    elf_bytes: u64,
    elf_sha256: Digest,
    externally_expected_elf_sha256: Digest,
    checker_executable_bytes: u64,
    checker_executable_sha256: Digest,
    authority_identity: Digest,
    registry_identity: Digest,
    stack_swap_semantic_identity: Digest,
    inventory: Inventory,
    program_row_count: u64,
    program_root: u32,
    program_commitment_identity: Digest,
    source_files: [source_paths.len]FileIdentity,
    guest_source_identity: Digest,
    cargo_build_identity: Digest,
    source_closure_identity: Digest,
    session_constructed_and_deinitialized: bool,
    receipt_identity: Digest,

    pub fn validate(self: Receipt) !void {
        const authority = authority_mod.Authority.create(
            self.externally_expected_elf_sha256,
        ) catch return error.InvalidStackSwapElfReceipt;
        if (production_active or proof_or_fresh_verification or
            !std.fs.path.isAbsolute(self.elf_path) or
            !std.fs.path.isAbsolute(self.source_root) or
            self.elf_bytes != expected_elf_bytes or
            !std.mem.eql(u8, &self.elf_sha256, &self.externally_expected_elf_sha256) or
            self.checker_executable_bytes == 0 or
            isZero(self.checker_executable_sha256) or
            isZero(self.authority_identity) or
            isZero(self.registry_identity) or
            isZero(self.stack_swap_semantic_identity) or
            !std.mem.eql(u8, &self.authority_identity, &authority.identity) or
            !std.mem.eql(
                u8,
                &self.registry_identity,
                &authority.stack_swap.allocation.registry_identity,
            ) or
            !std.mem.eql(
                u8,
                &self.stack_swap_semantic_identity,
                &authority.stack_swap.semantic_identity,
            ) or
            self.program_row_count != self.inventory.nonzero_word_count or
            self.program_root == 0 or
            self.program_root >= 0x7fff_ffff or
            isZero(self.program_commitment_identity) or
            !self.session_constructed_and_deinitialized)
        {
            return error.InvalidStackSwapElfReceipt;
        }
        try self.inventory.validate();
        for (self.source_files, source_paths) |file, expected_path| {
            if (!std.mem.eql(u8, file.path, expected_path) or
                file.bytes == 0 or isZero(file.sha256))
            {
                return error.InvalidStackSwapSourceIdentity;
            }
        }
        const expected_guest_sources = fileSetIdentity(
            "stwo.riscv.ethereum-stack-swap-guest-sources.v1\x00",
            self.source_files[0..guest_source_file_count],
        );
        const expected_cargo_build = fileSetIdentity(
            "stwo.riscv.ethereum-stack-swap-cargo-build.v1\x00",
            self.source_files[guest_source_file_count..],
        );
        const expected_closure = fileSetIdentity(
            "stwo.riscv.ethereum-stack-swap-source-closure.v1\x00",
            &self.source_files,
        );
        const expected_program = programCommitmentIdentity(
            authority,
            self.inventory,
            self.program_row_count,
            self.program_root,
        );
        const expected_receipt = receiptIdentity(self);
        if (!std.mem.eql(u8, &self.guest_source_identity, &expected_guest_sources) or
            !std.mem.eql(u8, &self.cargo_build_identity, &expected_cargo_build) or
            !std.mem.eql(u8, &self.source_closure_identity, &expected_closure) or
            !std.mem.eql(u8, &self.program_commitment_identity, &expected_program) or
            !std.mem.eql(u8, &self.receipt_identity, &expected_receipt))
        {
            return error.InvalidStackSwapElfReceipt;
        }
    }
};

pub const OwnedInventory = struct {
    inventory: Inventory,
    program_words: []memory_state.WordState,

    pub fn deinit(self: *OwnedInventory, allocator: std.mem.Allocator) void {
        allocator.free(self.program_words);
        self.* = undefined;
    }
};

pub fn inspectElf(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    decoder: combined_decode.DeclaredDecodeAuthority,
) !OwnedInventory {
    if (elf_bytes.len != expected_elf_bytes or elf_bytes.len < 52 or
        !std.mem.eql(u8, elf_bytes[0..4], "\x7fELF") or
        elf_bytes[4] != 1 or elf_bytes[5] != 1 or
        readU16(elf_bytes[18..20]) != 243)
    {
        return error.InvalidStackSwapElf;
    }
    const program_header_offset: usize = readU32(elf_bytes[28..32]);
    const program_header_size: usize = readU16(elf_bytes[42..44]);
    const program_header_count: usize = readU16(elf_bytes[44..46]);
    if (program_header_size != 32 or program_header_count == 0)
        return error.InvalidStackSwapElf;
    const table_bytes = std.math.mul(
        usize,
        program_header_size,
        program_header_count,
    ) catch return error.InvalidStackSwapElf;
    _ = bounded(elf_bytes, program_header_offset, table_bytes) orelse
        return error.InvalidStackSwapElf;

    var words: std.ArrayList(memory_state.WordState) = .empty;
    errdefer words.deinit(allocator);
    var executable_pt_load_count: u32 = 0;
    var executable_file_bytes: u64 = 0;
    var executable_memory_bytes: u64 = 0;
    for (0..program_header_count) |index| {
        const header_offset = program_header_offset + index * program_header_size;
        const header = elf_bytes[header_offset .. header_offset + program_header_size];
        if (readU32(header[0..4]) != 1 or readU32(header[24..28]) & 1 == 0)
            continue;
        executable_pt_load_count = try add(u32, executable_pt_load_count, 1);
        const file_offset: usize = readU32(header[4..8]);
        const virtual_address: u32 = readU32(header[8..12]);
        const file_bytes: usize = readU32(header[16..20]);
        const memory_bytes: usize = readU32(header[20..24]);
        if (file_bytes > memory_bytes or file_bytes & 3 != 0 or
            virtual_address & 3 != 0)
        {
            return error.InvalidStackSwapExecutableSegment;
        }
        const segment = bounded(elf_bytes, file_offset, file_bytes) orelse
            return error.InvalidStackSwapExecutableSegment;
        executable_file_bytes = try add(u64, executable_file_bytes, file_bytes);
        executable_memory_bytes = try add(u64, executable_memory_bytes, memory_bytes);
        try words.ensureUnusedCapacity(allocator, file_bytes / 4);
        var offset: usize = 0;
        while (offset < segment.len) : (offset += 4) {
            const address = std.math.add(
                u32,
                virtual_address,
                @intCast(offset),
            ) catch return error.InvalidStackSwapExecutableSegment;
            const word = readU32(segment[offset..][0..4]);
            words.appendAssumeCapacity(.{
                .addr = address,
                .initial_word = word,
                .final_word = word,
                .final_clock = 0,
            });
        }
    }
    if (words.items.len == 0) return error.InvalidStackSwapElfInventory;
    std.mem.sort(memory_state.WordState, words.items, {}, lessWord);
    for (words.items[1..], words.items[0 .. words.items.len - 1]) |current, previous| {
        if (current.addr == previous.addr) return error.DuplicateExecutableWord;
    }

    var occurrences: [expected_custom0_count]Custom0Occurrence = undefined;
    var custom0_count: usize = 0;
    var nonzero_word_count: u64 = 0;
    var keccak_word_count: u32 = 0;
    var recovery_word_count: u32 = 0;
    var stack_swap_word_count: u32 = 0;
    var word_hash = std.crypto.hash.sha2.Sha256.init(.{});
    word_hash.update("stwo.riscv.ethereum-stack-swap-executable-words.v1\x00");
    for (words.items) |word_state| {
        hashInt(&word_hash, word_state.addr);
        hashInt(&word_hash, word_state.initial_word);
        if (word_state.initial_word == 0) continue;
        nonzero_word_count = try add(u64, nonzero_word_count, 1);
        if (@as(u7, @truncate(word_state.initial_word)) == custom0.major_opcode) {
            if (custom0_count == occurrences.len) return error.StrayCustom0Word;
            switch (word_state.initial_word) {
                expected_keccak_word => keccak_word_count += 1,
                expected_recovery_word => recovery_word_count += 1,
                expected_stack_swap_word => stack_swap_word_count += 1,
                else => return error.StrayCustom0Word,
            }
            occurrences[custom0_count] = .{
                .address = word_state.addr,
                .word = word_state.initial_word,
            };
            custom0_count += 1;
        }
        _ = try decoder.decodeDeclaredWord(word_state.initial_word);
    }
    if (custom0_count != occurrences.len) return error.InvalidStackSwapElfInventory;
    var word_inventory_sha256: Digest = undefined;
    word_hash.final(&word_inventory_sha256);
    const inventory = Inventory{
        .executable_pt_load_count = executable_pt_load_count,
        .executable_file_bytes = executable_file_bytes,
        .executable_memory_bytes = executable_memory_bytes,
        .executable_word_count = @intCast(words.items.len),
        .nonzero_word_count = nonzero_word_count,
        .custom0_word_count = @intCast(custom0_count),
        .keccak_word_count = keccak_word_count,
        .recovery_word_count = recovery_word_count,
        .stack_swap_word_count = stack_swap_word_count,
        .custom0_occurrences = occurrences,
        .word_inventory_sha256 = word_inventory_sha256,
    };
    try inventory.validate();
    return .{
        .inventory = inventory,
        .program_words = try words.toOwnedSlice(allocator),
    };
}

pub fn buildProgramCommitment(
    allocator: std.mem.Allocator,
    decoder: combined_decode.DeclaredDecodeAuthority,
    owned_inventory: *const OwnedInventory,
    authority: authority_mod.Authority,
) !struct { row_count: u64, root: u32, identity: Digest } {
    var commitment = try program_commitment.buildDeclaredWithDecodeAuthoritySources(
        allocator,
        decoder,
        .{},
        owned_inventory.program_words,
        null,
    );
    defer commitment.deinit(allocator);
    try commitment.validate(allocator);
    for (commitment.rows) |row| if (row.multiplicity != 0)
        return error.NonzeroCandidateProgramMultiplicity;
    if (commitment.rows.len != owned_inventory.inventory.nonzero_word_count)
        return error.InvalidStackSwapProgramCommitment;
    return .{
        .row_count = @intCast(commitment.rows.len),
        .root = commitment.tree.root,
        .identity = programCommitmentIdentity(
            authority,
            owned_inventory.inventory,
            commitment.rows.len,
            commitment.tree.root,
        ),
    };
}

fn programCommitmentIdentity(
    authority: authority_mod.Authority,
    inventory: Inventory,
    row_count: u64,
    root: u32,
) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-stack-swap-program-commitment.v1\x00");
    hash.update(&authority.identity);
    hash.update(&inventory.word_inventory_sha256);
    hashInt(&hash, row_count);
    hashInt(&hash, root);
    var identity: Digest = undefined;
    hash.final(&identity);
    return identity;
}

pub fn constructAndDeinitSession(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    authority: authority_mod.Authority,
) !void {
    const CandidateSession = segment_session.EthereumStackSwapCandidateExecutionSessionV1();
    var session = try CandidateSession.initCandidateLegacy(
        allocator,
        elf_bytes,
        .{},
        authority,
    );
    session.deinit();
}

pub fn collectSourceFiles(source_root: []const u8) ![source_paths.len]FileIdentity {
    if (!std.fs.path.isAbsolute(source_root)) return error.SourceRootMustBeAbsolute;
    var directory = try std.fs.openDirAbsolute(source_root, .{});
    defer directory.close();
    var result: [source_paths.len]FileIdentity = undefined;
    for (source_paths, 0..) |path, index| {
        var file = try directory.openFile(path, .{});
        defer file.close();
        const stat = try file.stat();
        if (stat.kind != .file or stat.size == 0)
            return error.InvalidStackSwapSourceIdentity;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        var buffer: [64 * 1024]u8 = undefined;
        while (true) {
            const count = try file.read(&buffer);
            if (count == 0) break;
            hash.update(buffer[0..count]);
        }
        var digest: Digest = undefined;
        hash.final(&digest);
        result[index] = .{
            .path = path,
            .bytes = stat.size,
            .sha256 = digest,
        };
    }
    return result;
}

pub fn bindReceiptIdentity(receipt: *Receipt) !void {
    receipt.guest_source_identity = fileSetIdentity(
        "stwo.riscv.ethereum-stack-swap-guest-sources.v1\x00",
        receipt.source_files[0..guest_source_file_count],
    );
    receipt.cargo_build_identity = fileSetIdentity(
        "stwo.riscv.ethereum-stack-swap-cargo-build.v1\x00",
        receipt.source_files[guest_source_file_count..],
    );
    receipt.source_closure_identity = fileSetIdentity(
        "stwo.riscv.ethereum-stack-swap-source-closure.v1\x00",
        &receipt.source_files,
    );
    receipt.receipt_identity = receiptIdentity(receipt.*);
    try receipt.validate();
}

pub const SourceFileWire = struct {
    path: []const u8,
    bytes: u64,
    sha256: []const u8,
};

pub const Custom0Wire = struct {
    address: u32,
    word_hex: []const u8,
};

pub const InventoryWire = struct {
    executable_pt_load_count: u32,
    executable_file_bytes: u64,
    executable_memory_bytes: u64,
    executable_word_count: u64,
    nonzero_word_count: u64,
    custom0_word_count: u32,
    keccak_word_count: u32,
    recovery_word_count: u32,
    stack_swap_word_count: u32,
    custom0_occurrences: [expected_custom0_count]Custom0Wire,
    word_inventory_sha256: []const u8,
};

pub const ReceiptWire = struct {
    schema: []const u8,
    schema_version: u16,
    status: []const u8,
    production_active: bool,
    proof_or_fresh_verification: bool,
    elf_path: []const u8,
    source_root: []const u8,
    elf_bytes: u64,
    elf_sha256: []const u8,
    externally_expected_elf_sha256: []const u8,
    checker_executable_bytes: u64,
    checker_executable_sha256: []const u8,
    authority_identity: []const u8,
    registry_identity: []const u8,
    stack_swap_semantic_identity: []const u8,
    inventory: InventoryWire,
    program_row_count: u64,
    program_root: u32,
    program_commitment_identity: []const u8,
    source_files: [source_paths.len]SourceFileWire,
    guest_source_identity: []const u8,
    cargo_build_identity: []const u8,
    source_closure_identity: []const u8,
    session_constructed_and_deinitialized: bool,
    receipt_identity: []const u8,
};

pub fn encodeAlloc(allocator: std.mem.Allocator, receipt: Receipt) ![]u8 {
    try receipt.validate();
    var source_hex: [source_paths.len][64]u8 = undefined;
    var source_wire: [source_paths.len]SourceFileWire = undefined;
    for (receipt.source_files, 0..) |file, index| {
        source_hex[index] = std.fmt.bytesToHex(file.sha256, .lower);
        source_wire[index] = .{
            .path = file.path,
            .bytes = file.bytes,
            .sha256 = &source_hex[index],
        };
    }
    var custom_hex: [expected_custom0_count][8]u8 = undefined;
    var custom_wire: [expected_custom0_count]Custom0Wire = undefined;
    for (receipt.inventory.custom0_occurrences, 0..) |occurrence, index| {
        custom_hex[index] = wordHex(occurrence.word);
        custom_wire[index] = .{
            .address = occurrence.address,
            .word_hex = &custom_hex[index],
        };
    }
    const elf_hex = std.fmt.bytesToHex(receipt.elf_sha256, .lower);
    const expected_hex = std.fmt.bytesToHex(receipt.externally_expected_elf_sha256, .lower);
    const checker_hex = std.fmt.bytesToHex(receipt.checker_executable_sha256, .lower);
    const authority_hex = std.fmt.bytesToHex(receipt.authority_identity, .lower);
    const registry_hex = std.fmt.bytesToHex(receipt.registry_identity, .lower);
    const semantic_hex = std.fmt.bytesToHex(receipt.stack_swap_semantic_identity, .lower);
    const inventory_hex = std.fmt.bytesToHex(receipt.inventory.word_inventory_sha256, .lower);
    const program_hex = std.fmt.bytesToHex(receipt.program_commitment_identity, .lower);
    const guest_source_hex = std.fmt.bytesToHex(receipt.guest_source_identity, .lower);
    const cargo_hex = std.fmt.bytesToHex(receipt.cargo_build_identity, .lower);
    const closure_hex = std.fmt.bytesToHex(receipt.source_closure_identity, .lower);
    const receipt_hex = std.fmt.bytesToHex(receipt.receipt_identity, .lower);
    return std.json.Stringify.valueAlloc(allocator, ReceiptWire{
        .schema = schema,
        .schema_version = schema_version,
        .status = "candidate-only-validated",
        .production_active = production_active,
        .proof_or_fresh_verification = proof_or_fresh_verification,
        .elf_path = receipt.elf_path,
        .source_root = receipt.source_root,
        .elf_bytes = receipt.elf_bytes,
        .elf_sha256 = &elf_hex,
        .externally_expected_elf_sha256 = &expected_hex,
        .checker_executable_bytes = receipt.checker_executable_bytes,
        .checker_executable_sha256 = &checker_hex,
        .authority_identity = &authority_hex,
        .registry_identity = &registry_hex,
        .stack_swap_semantic_identity = &semantic_hex,
        .inventory = .{
            .executable_pt_load_count = receipt.inventory.executable_pt_load_count,
            .executable_file_bytes = receipt.inventory.executable_file_bytes,
            .executable_memory_bytes = receipt.inventory.executable_memory_bytes,
            .executable_word_count = receipt.inventory.executable_word_count,
            .nonzero_word_count = receipt.inventory.nonzero_word_count,
            .custom0_word_count = receipt.inventory.custom0_word_count,
            .keccak_word_count = receipt.inventory.keccak_word_count,
            .recovery_word_count = receipt.inventory.recovery_word_count,
            .stack_swap_word_count = receipt.inventory.stack_swap_word_count,
            .custom0_occurrences = custom_wire,
            .word_inventory_sha256 = &inventory_hex,
        },
        .program_row_count = receipt.program_row_count,
        .program_root = receipt.program_root,
        .program_commitment_identity = &program_hex,
        .source_files = source_wire,
        .guest_source_identity = &guest_source_hex,
        .cargo_build_identity = &cargo_hex,
        .source_closure_identity = &closure_hex,
        .session_constructed_and_deinitialized = receipt.session_constructed_and_deinitialized,
        .receipt_identity = &receipt_hex,
    }, .{});
}

pub fn decodeAlloc(
    allocator: std.mem.Allocator,
    encoded: []const u8,
) !std.json.Parsed(ReceiptWire) {
    return std.json.parseFromSlice(ReceiptWire, allocator, encoded, .{});
}

pub fn fromWire(wire: ReceiptWire) !Receipt {
    if (!std.mem.eql(u8, wire.schema, schema) or
        wire.schema_version != schema_version or
        !std.mem.eql(u8, wire.status, "candidate-only-validated") or
        wire.production_active or wire.proof_or_fresh_verification)
    {
        return error.InvalidStackSwapElfReceipt;
    }
    var source_files: [source_paths.len]FileIdentity = undefined;
    for (wire.source_files, 0..) |file, index| source_files[index] = .{
        .path = file.path,
        .bytes = file.bytes,
        .sha256 = try parseDigest(file.sha256),
    };
    var occurrences: [expected_custom0_count]Custom0Occurrence = undefined;
    for (wire.inventory.custom0_occurrences, 0..) |occurrence, index| {
        occurrences[index] = .{
            .address = occurrence.address,
            .word = try parseWordHex(occurrence.word_hex),
        };
    }
    const result = Receipt{
        .elf_path = wire.elf_path,
        .source_root = wire.source_root,
        .elf_bytes = wire.elf_bytes,
        .elf_sha256 = try parseDigest(wire.elf_sha256),
        .externally_expected_elf_sha256 = try parseDigest(wire.externally_expected_elf_sha256),
        .checker_executable_bytes = wire.checker_executable_bytes,
        .checker_executable_sha256 = try parseDigest(wire.checker_executable_sha256),
        .authority_identity = try parseDigest(wire.authority_identity),
        .registry_identity = try parseDigest(wire.registry_identity),
        .stack_swap_semantic_identity = try parseDigest(wire.stack_swap_semantic_identity),
        .inventory = .{
            .executable_pt_load_count = wire.inventory.executable_pt_load_count,
            .executable_file_bytes = wire.inventory.executable_file_bytes,
            .executable_memory_bytes = wire.inventory.executable_memory_bytes,
            .executable_word_count = wire.inventory.executable_word_count,
            .nonzero_word_count = wire.inventory.nonzero_word_count,
            .custom0_word_count = wire.inventory.custom0_word_count,
            .keccak_word_count = wire.inventory.keccak_word_count,
            .recovery_word_count = wire.inventory.recovery_word_count,
            .stack_swap_word_count = wire.inventory.stack_swap_word_count,
            .custom0_occurrences = occurrences,
            .word_inventory_sha256 = try parseDigest(wire.inventory.word_inventory_sha256),
        },
        .program_row_count = wire.program_row_count,
        .program_root = wire.program_root,
        .program_commitment_identity = try parseDigest(wire.program_commitment_identity),
        .source_files = source_files,
        .guest_source_identity = try parseDigest(wire.guest_source_identity),
        .cargo_build_identity = try parseDigest(wire.cargo_build_identity),
        .source_closure_identity = try parseDigest(wire.source_closure_identity),
        .session_constructed_and_deinitialized = wire.session_constructed_and_deinitialized,
        .receipt_identity = try parseDigest(wire.receipt_identity),
    };
    try result.validate();
    return result;
}

pub fn parseDigest(encoded: []const u8) !Digest {
    if (encoded.len != 64) return error.InvalidSha256;
    var result: Digest = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch return error.InvalidSha256;
    const canonical = std.fmt.bytesToHex(result, .lower);
    if (!std.mem.eql(u8, encoded, &canonical) or isZero(result))
        return error.InvalidSha256;
    return result;
}

pub fn hashBytes(bytes: []const u8) Digest {
    var result: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

pub fn sameFiles(
    left: [source_paths.len]FileIdentity,
    right: [source_paths.len]FileIdentity,
) bool {
    for (left, right) |a, b| {
        if (!std.mem.eql(u8, a.path, b.path) or a.bytes != b.bytes or
            !std.mem.eql(u8, &a.sha256, &b.sha256)) return false;
    }
    return true;
}

pub fn sameInventory(left: Inventory, right: Inventory) bool {
    return std.meta.eql(left, right);
}

fn receiptIdentity(receipt: Receipt) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(schema ++ "\x00");
    hash.update(&receipt.elf_sha256);
    hash.update(&receipt.externally_expected_elf_sha256);
    hashInt(&hash, receipt.elf_bytes);
    hash.update(&receipt.checker_executable_sha256);
    hashInt(&hash, receipt.checker_executable_bytes);
    hash.update(&receipt.authority_identity);
    hash.update(&receipt.registry_identity);
    hash.update(&receipt.stack_swap_semantic_identity);
    hashInventory(&hash, receipt.inventory);
    hashInt(&hash, receipt.program_row_count);
    hashInt(&hash, receipt.program_root);
    hash.update(&receipt.program_commitment_identity);
    hash.update(&receipt.guest_source_identity);
    hash.update(&receipt.cargo_build_identity);
    hash.update(&receipt.source_closure_identity);
    hash.update(&.{@intFromBool(receipt.session_constructed_and_deinitialized)});
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

fn hashInventory(hash: anytype, inventory: Inventory) void {
    hashInt(hash, inventory.executable_pt_load_count);
    hashInt(hash, inventory.executable_file_bytes);
    hashInt(hash, inventory.executable_memory_bytes);
    hashInt(hash, inventory.executable_word_count);
    hashInt(hash, inventory.nonzero_word_count);
    hashInt(hash, inventory.custom0_word_count);
    hashInt(hash, inventory.keccak_word_count);
    hashInt(hash, inventory.recovery_word_count);
    hashInt(hash, inventory.stack_swap_word_count);
    for (inventory.custom0_occurrences) |occurrence| {
        hashInt(hash, occurrence.address);
        hashInt(hash, occurrence.word);
    }
    hash.update(&inventory.word_inventory_sha256);
}

fn fileSetIdentity(domain: []const u8, files: []const FileIdentity) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(domain);
    hashInt(&hash, files.len);
    for (files) |file| {
        hashInt(&hash, file.path.len);
        hash.update(file.path);
        hashInt(&hash, file.bytes);
        hash.update(&file.sha256);
    }
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

fn parseWordHex(encoded: []const u8) !u32 {
    if (encoded.len != 8) return error.InvalidInstructionWord;
    var bytes: [4]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, encoded) catch return error.InvalidInstructionWord;
    const result = std.mem.readInt(u32, &bytes, .big);
    const canonical = wordHex(result);
    if (!std.mem.eql(u8, encoded, &canonical)) return error.InvalidInstructionWord;
    return result;
}

fn wordHex(word: u32) [8]u8 {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, word, .big);
    return std.fmt.bytesToHex(bytes, .lower);
}

fn bounded(bytes: []const u8, offset: usize, length: usize) ?[]const u8 {
    const end = std.math.add(usize, offset, length) catch return null;
    if (end > bytes.len) return null;
    return bytes[offset..end];
}

fn readU16(bytes: *const [2]u8) u16 {
    return std.mem.readInt(u16, bytes, .little);
}

fn readU32(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .little);
}

fn lessWord(_: void, left: memory_state.WordState, right: memory_state.WordState) bool {
    return left.addr < right.addr;
}

fn hashInt(hash: anytype, value: anytype) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn add(comptime T: type, left: T, right: anytype) !T {
    const normalized: T = @intCast(right);
    return std.math.add(T, left, normalized) catch error.StackSwapElfCountOverflow;
}

fn isZero(value: Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

comptime {
    if (production_active or proof_or_fresh_verification or
        expected_executable_file_bytes / 4 != expected_executable_word_count or
        expected_custom0_count != expected_keccak_count + expected_recovery_count +
            expected_stack_swap_count or
        expected_keccak_word != custom0.encodeKeccakf(5) or
        expected_recovery_word != custom0.encodeSecp256k1Recover(5) or
        source_paths.len != 10 or guest_source_file_count != 3)
    {
        @compileError("Ethereum+SWAP candidate ELF receipt authority drifted");
    }
}
