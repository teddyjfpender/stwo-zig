//! Candidate-only custody receipt/checker for a combined Ethereum guest ELF.
//!
//! The externally supplied ELF digest is the executable selection authority.
//! This module reopens those exact bytes, decodes every nonzero executable word
//! through the closed combined decoder, rebuilds the program commitment,
//! reopens a bounded source closure, and constructs/deinitializes the combined
//! session. It is neither proof evidence nor production admission.

const std = @import("std");

const program_commitment = @import("../../air/program/commitment.zig");
const custom0 = @import("../../isa/custom0.zig");
const authority_mod =
    @import("../../isa/ethereum_candidate_combined_authority_v1.zig");
const registry_mod =
    @import("../../isa/ethereum_candidate_private_registry_v1.zig");
const combined_decode =
    @import("../../prover/guest_precompile/ethereum_candidate_combined_decode_v1.zig");
const memory_state = @import("../memory_state.zig");
const segment_session = @import("../segment_session.zig");

pub const Digest = [32]u8;
pub const schema = "stwo.riscv.ethereum-combined-candidate-elf-receipt.v1";
pub const production_active = false;
pub const proof_or_fresh_verification = false;
pub const schema_version: u16 = 1;
pub const source_file_capacity: usize = 32;

pub const FileIdentity = struct {
    path: []const u8,
    bytes: u64,
    sha256: Digest,

    pub fn validate(self: FileIdentity, absolute: bool) !void {
        if (self.path.len == 0 or self.bytes == 0 or isZero(self.sha256) or
            std.fs.path.isAbsolute(self.path) != absolute or
            (!absolute and !isCanonicalRelativePath(self.path)))
        {
            return error.InvalidCombinedCandidateFileIdentity;
        }
    }
};

pub const SourceClosure = struct {
    count: u16,
    files: [source_file_capacity]?FileIdentity,
    identity: Digest,

    pub fn create(files: []const FileIdentity) !SourceClosure {
        if (files.len == 0 or files.len > source_file_capacity)
            return error.InvalidCombinedCandidateSourceClosure;
        var stored: [source_file_capacity]?FileIdentity = .{null} ** source_file_capacity;
        for (files, 0..) |file, index| stored[index] = file;
        var result = SourceClosure{
            .count = @intCast(files.len),
            .files = stored,
            .identity = undefined,
        };
        result.identity = sourceClosureIdentity(result);
        try result.validate();
        return result;
    }

    pub fn validate(self: SourceClosure) !void {
        const count: usize = self.count;
        if (count == 0 or count > source_file_capacity)
            return error.InvalidCombinedCandidateSourceClosure;
        for (self.files[0..count], 0..) |maybe_file, index| {
            const file = maybe_file orelse
                return error.InvalidCombinedCandidateSourceClosure;
            try file.validate(false);
            for (self.files[0..index]) |maybe_previous| {
                const previous = maybe_previous.?;
                if (std.mem.eql(u8, file.path, previous.path))
                    return error.DuplicateCombinedCandidateSourcePath;
            }
        }
        for (self.files[count..]) |file| if (file != null)
            return error.InvalidCombinedCandidateSourceClosure;
        if (!std.mem.eql(u8, &self.identity, &sourceClosureIdentity(self)))
            return error.InvalidCombinedCandidateSourceClosureIdentity;
    }
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
    bulk_memcpy_word_count: u32,
    stack_swap_word_count: u32,
    executable_words_identity: Digest,
    custom0_sequence_identity: Digest,

    pub fn validate(self: Inventory) !void {
        if (self.executable_pt_load_count == 0 or
            self.executable_file_bytes == 0 or
            self.executable_memory_bytes < self.executable_file_bytes or
            self.executable_word_count == 0 or self.nonzero_word_count == 0 or
            self.nonzero_word_count > self.executable_word_count or
            self.bulk_memcpy_word_count == 0 or self.stack_swap_word_count == 0 or
            self.custom0_word_count != self.keccak_word_count +
                self.recovery_word_count + self.bulk_memcpy_word_count +
                self.stack_swap_word_count or
            isZero(self.executable_words_identity) or
            isZero(self.custom0_sequence_identity))
        {
            return error.InvalidCombinedCandidateElfInventory;
        }
    }
};

pub const Receipt = struct {
    format: u16 = schema_version,
    elf: FileIdentity,
    externally_expected_elf_sha256: Digest,
    checker: FileIdentity,
    source_root: []const u8,
    source_closure: SourceClosure,
    authority_identity: Digest,
    registry_identity: Digest,
    ordered_member_identities: [registry_mod.canonical_member_count]Digest,
    inventory: Inventory,
    program_row_count: u64,
    program_root: u32,
    program_commitment_identity: Digest,
    session_constructed_and_deinitialized: bool,
    final_candidate_executable: bool,
    production_eligible: bool = false,
    identity: Digest,

    pub fn validate(self: Receipt) !void {
        try self.elf.validate(true);
        try self.checker.validate(true);
        try self.source_closure.validate();
        if (production_active or proof_or_fresh_verification or
            self.format != schema_version or
            !std.fs.path.isAbsolute(self.source_root) or
            !std.mem.eql(
                u8,
                &self.elf.sha256,
                &self.externally_expected_elf_sha256,
            ) or self.program_row_count != self.inventory.nonzero_word_count or
            self.program_root == 0 or self.program_root >= 0x7fff_ffff or
            isZero(self.program_commitment_identity) or
            !self.session_constructed_and_deinitialized or
            self.production_eligible)
        {
            return error.InvalidCombinedCandidateElfReceipt;
        }
        try self.inventory.validate();
        const authority = try authority_mod.Authority.create(
            self.externally_expected_elf_sha256,
        );
        if (!std.mem.eql(u8, &self.authority_identity, &authority.identity) or
            !std.mem.eql(u8, &self.registry_identity, &authority.registry.identity))
        {
            return error.InvalidCombinedCandidateElfReceipt;
        }
        inline for (0..registry_mod.canonical_member_count) |index| {
            const member = authority.registry.members[index] orelse unreachable;
            if (!std.mem.eql(
                u8,
                &self.ordered_member_identities[index],
                &member.identity,
            )) return error.InvalidCombinedCandidateElfReceipt;
        }
        const expected_program = programCommitmentIdentity(
            authority,
            self.inventory,
            self.program_row_count,
            self.program_root,
        );
        if (!std.mem.eql(
            u8,
            &self.program_commitment_identity,
            &expected_program,
        ) or !std.mem.eql(u8, &self.identity, &receiptIdentity(self))) {
            return error.InvalidCombinedCandidateElfReceiptIdentity;
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

pub const ReceiptWire = struct {
    schema: []const u8,
    status: []const u8,
    production_active: bool,
    proof_or_fresh_verification: bool,
    receipt: Receipt,
};

pub fn encodeAlloc(allocator: std.mem.Allocator, receipt: Receipt) ![]u8 {
    try receipt.validate();
    return std.json.Stringify.valueAlloc(allocator, ReceiptWire{
        .schema = schema,
        .status = "candidate-only-validated",
        .production_active = production_active,
        .proof_or_fresh_verification = proof_or_fresh_verification,
        .receipt = receipt,
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
        !std.mem.eql(u8, wire.status, "candidate-only-validated") or
        wire.production_active or wire.proof_or_fresh_verification)
    {
        return error.InvalidCombinedCandidateElfReceipt;
    }
    try wire.receipt.validate();
    return wire.receipt;
}

pub fn collectSourceClosure(
    source_root: []const u8,
    relative_paths: []const []const u8,
) !SourceClosure {
    if (!std.fs.path.isAbsolute(source_root) or relative_paths.len == 0 or
        relative_paths.len > source_file_capacity)
    {
        return error.InvalidCombinedCandidateSourceClosure;
    }
    var directory = try std.fs.openDirAbsolute(source_root, .{});
    defer directory.close();
    var files: [source_file_capacity]FileIdentity = undefined;
    for (relative_paths, 0..) |path, index| {
        if (!isCanonicalRelativePath(path))
            return error.InvalidCombinedCandidateFileIdentity;
        var file = try directory.openFile(path, .{});
        defer file.close();
        const stat = try file.stat();
        if (stat.kind != .file or stat.size == 0)
            return error.InvalidCombinedCandidateFileIdentity;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        var buffer: [64 * 1024]u8 = undefined;
        while (true) {
            const count = try file.read(&buffer);
            if (count == 0) break;
            hash.update(buffer[0..count]);
        }
        files[index] = .{
            .path = path,
            .bytes = stat.size,
            .sha256 = hash.finalResult(),
        };
    }
    return SourceClosure.create(files[0..relative_paths.len]);
}

pub fn createFromReopened(
    allocator: std.mem.Allocator,
    elf_path: []const u8,
    elf_bytes: []const u8,
    externally_expected_elf_sha256: Digest,
    checker: FileIdentity,
    source_root: []const u8,
    source_closure: SourceClosure,
    final_candidate_executable: bool,
) !Receipt {
    const elf = FileIdentity{
        .path = elf_path,
        .bytes = @intCast(elf_bytes.len),
        .sha256 = hashBytes(elf_bytes),
    };
    try elf.validate(true);
    try checker.validate(true);
    try source_closure.validate();
    if (!std.fs.path.isAbsolute(source_root) or
        !std.mem.eql(u8, &elf.sha256, &externally_expected_elf_sha256))
    {
        return error.CombinedCandidateExecutableIdentityMismatch;
    }
    const authority = try authority_mod.Authority.create(externally_expected_elf_sha256);
    try authority.validateElf(elf_bytes);
    const decoder = try combined_decode.DeclaredDecodeAuthority.init(authority);
    var owned = try inspectElf(allocator, elf_bytes, decoder, authority);
    defer owned.deinit(allocator);
    const program = try buildProgramCommitment(allocator, decoder, &owned, authority);
    try constructAndDeinitSession(allocator, elf_bytes, authority);

    var member_identities: [registry_mod.canonical_member_count]Digest = undefined;
    inline for (0..registry_mod.canonical_member_count) |index|
        member_identities[index] = authority.registry.members[index].?.identity;
    var result = Receipt{
        .elf = elf,
        .externally_expected_elf_sha256 = externally_expected_elf_sha256,
        .checker = checker,
        .source_root = source_root,
        .source_closure = source_closure,
        .authority_identity = authority.identity,
        .registry_identity = authority.registry.identity,
        .ordered_member_identities = member_identities,
        .inventory = owned.inventory,
        .program_row_count = program.row_count,
        .program_root = program.root,
        .program_commitment_identity = program.identity,
        .session_constructed_and_deinitialized = true,
        .final_candidate_executable = final_candidate_executable,
        .identity = undefined,
    };
    result.identity = receiptIdentity(result);
    try result.validate();
    return result;
}

pub fn validateReopened(
    allocator: std.mem.Allocator,
    receipt: Receipt,
    elf_bytes: []const u8,
    reopened_source_closure: SourceClosure,
) !void {
    try receipt.validate();
    try reopened_source_closure.validate();
    const reopened_elf_sha256 = hashBytes(elf_bytes);
    if (elf_bytes.len != receipt.elf.bytes or
        !std.mem.eql(u8, &reopened_elf_sha256, &receipt.elf.sha256) or
        !sameSourceClosures(reopened_source_closure, receipt.source_closure))
    {
        return error.CombinedCandidateReopenMismatch;
    }
    const authority = try authority_mod.Authority.create(receipt.elf.sha256);
    try authority.validateElf(elf_bytes);
    const decoder = try combined_decode.DeclaredDecodeAuthority.init(authority);
    var owned = try inspectElf(allocator, elf_bytes, decoder, authority);
    defer owned.deinit(allocator);
    if (!std.meta.eql(owned.inventory, receipt.inventory))
        return error.CombinedCandidateReopenMismatch;
    const program = try buildProgramCommitment(allocator, decoder, &owned, authority);
    if (program.row_count != receipt.program_row_count or
        program.root != receipt.program_root or
        !std.mem.eql(u8, &program.identity, &receipt.program_commitment_identity))
    {
        return error.CombinedCandidateReopenMismatch;
    }
    try constructAndDeinitSession(allocator, elf_bytes, authority);
}

pub fn inspectElf(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    decoder: combined_decode.DeclaredDecodeAuthority,
    authority: authority_mod.Authority,
) !OwnedInventory {
    if (elf_bytes.len < 52 or !std.mem.eql(u8, elf_bytes[0..4], "\x7fELF") or
        elf_bytes[4] != 1 or elf_bytes[5] != 1 or readU16(elf_bytes[18..20]) != 243)
    {
        return error.InvalidCombinedCandidateElf;
    }
    const program_header_offset: usize = readU32(elf_bytes[28..32]);
    const program_header_size: usize = readU16(elf_bytes[42..44]);
    const program_header_count: usize = readU16(elf_bytes[44..46]);
    if (program_header_size != 32 or program_header_count == 0)
        return error.InvalidCombinedCandidateElf;
    _ = bounded(
        elf_bytes,
        program_header_offset,
        try std.math.mul(usize, program_header_size, program_header_count),
    ) orelse return error.InvalidCombinedCandidateElf;

    var words: std.ArrayList(memory_state.WordState) = .empty;
    errdefer words.deinit(allocator);
    var pt_load_count: u32 = 0;
    var file_bytes: u64 = 0;
    var memory_bytes: u64 = 0;
    for (0..program_header_count) |index| {
        const offset = program_header_offset + index * program_header_size;
        const header = elf_bytes[offset..][0..32];
        if (readU32(header[0..4]) != 1 or readU32(header[24..28]) & 1 == 0)
            continue;
        pt_load_count = try add(u32, pt_load_count, 1);
        const segment_file_offset: usize = readU32(header[4..8]);
        const virtual_address: u32 = readU32(header[8..12]);
        const segment_file_bytes: usize = readU32(header[16..20]);
        const segment_memory_bytes: usize = readU32(header[20..24]);
        if (segment_file_bytes > segment_memory_bytes or
            segment_file_bytes & 3 != 0 or virtual_address & 3 != 0)
        {
            return error.InvalidCombinedCandidateExecutableSegment;
        }
        const segment = bounded(
            elf_bytes,
            segment_file_offset,
            segment_file_bytes,
        ) orelse return error.InvalidCombinedCandidateExecutableSegment;
        file_bytes = try add(u64, file_bytes, segment_file_bytes);
        memory_bytes = try add(u64, memory_bytes, segment_memory_bytes);
        try words.ensureUnusedCapacity(allocator, segment.len / 4);
        var word_offset: usize = 0;
        while (word_offset < segment.len) : (word_offset += 4) {
            const address = try std.math.add(
                u32,
                virtual_address,
                @intCast(word_offset),
            );
            const word = readU32(segment[word_offset..][0..4]);
            words.appendAssumeCapacity(.{
                .addr = address,
                .initial_word = word,
                .final_word = word,
                .final_clock = 0,
            });
        }
    }
    if (words.items.len == 0) return error.InvalidCombinedCandidateElfInventory;
    std.mem.sort(memory_state.WordState, words.items, {}, lessWord);
    for (words.items[1..], words.items[0 .. words.items.len - 1]) |current, previous|
        if (current.addr == previous.addr) return error.DuplicateExecutableWord;

    const bulk_word = authority.bulk_memcpy.bulk_memcpy.fixed_word;
    const swap_word = authority.stack_swap.stack_swap.fixed_word;
    var executable_hash = std.crypto.hash.sha2.Sha256.init(.{});
    executable_hash.update("stwo.riscv.ethereum-combined-executable-words.v1\x00");
    var custom_hash = std.crypto.hash.sha2.Sha256.init(.{});
    custom_hash.update("stwo.riscv.ethereum-combined-custom0-sequence.v1\x00");
    var nonzero: u64 = 0;
    var custom_count: u32 = 0;
    var keccak_count: u32 = 0;
    var recovery_count: u32 = 0;
    var bulk_count: u32 = 0;
    var swap_count: u32 = 0;
    for (words.items) |word_state| {
        hashInt(&executable_hash, word_state.addr);
        hashInt(&executable_hash, word_state.initial_word);
        if (word_state.initial_word == 0) continue;
        nonzero = try add(u64, nonzero, 1);
        _ = try decoder.decodeDeclaredWord(word_state.initial_word);
        if (@as(u7, @truncate(word_state.initial_word)) != custom0.major_opcode)
            continue;
        custom_count = try add(u32, custom_count, 1);
        hashInt(&custom_hash, word_state.addr);
        hashInt(&custom_hash, word_state.initial_word);
        switch (word_state.initial_word) {
            custom0.encodeKeccakf(5) => keccak_count += 1,
            custom0.encodeSecp256k1Recover(5) => recovery_count += 1,
            else => {
                if (word_state.initial_word == bulk_word) {
                    bulk_count += 1;
                } else if (word_state.initial_word == swap_word) {
                    swap_count += 1;
                } else {
                    return error.StrayCombinedCandidateCustom0Word;
                }
            },
        }
    }
    var executable_identity: Digest = undefined;
    executable_hash.final(&executable_identity);
    var custom_identity: Digest = undefined;
    custom_hash.final(&custom_identity);
    const inventory = Inventory{
        .executable_pt_load_count = pt_load_count,
        .executable_file_bytes = file_bytes,
        .executable_memory_bytes = memory_bytes,
        .executable_word_count = @intCast(words.items.len),
        .nonzero_word_count = nonzero,
        .custom0_word_count = custom_count,
        .keccak_word_count = keccak_count,
        .recovery_word_count = recovery_count,
        .bulk_memcpy_word_count = bulk_count,
        .stack_swap_word_count = swap_count,
        .executable_words_identity = executable_identity,
        .custom0_sequence_identity = custom_identity,
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
    owned: *const OwnedInventory,
    authority: authority_mod.Authority,
) !struct { row_count: u64, root: u32, identity: Digest } {
    var commitment = try program_commitment.buildDeclaredWithDecodeAuthoritySources(
        allocator,
        decoder,
        .{},
        owned.program_words,
        null,
    );
    defer commitment.deinit(allocator);
    try commitment.validate(allocator);
    for (commitment.rows) |row| if (row.multiplicity != 0)
        return error.NonzeroCombinedCandidateProgramMultiplicity;
    if (commitment.rows.len != owned.inventory.nonzero_word_count)
        return error.InvalidCombinedCandidateProgramCommitment;
    return .{
        .row_count = @intCast(commitment.rows.len),
        .root = commitment.tree.root,
        .identity = programCommitmentIdentity(
            authority,
            owned.inventory,
            commitment.rows.len,
            commitment.tree.root,
        ),
    };
}

pub fn constructAndDeinitSession(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    authority: authority_mod.Authority,
) !void {
    const Session = segment_session.EthereumCombinedCandidateExecutionSessionV1();
    var session = try Session.initCandidateLegacy(allocator, elf_bytes, .{}, authority);
    session.deinit();
}

pub fn hashBytes(bytes: []const u8) Digest {
    var result: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
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

fn sourceClosureIdentity(value: SourceClosure) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-combined-source-closure.v1\x00");
    hashInt(&hash, value.count);
    const count: usize = value.count;
    for (value.files[0..count]) |maybe_file| {
        const file = maybe_file.?;
        hashInt(&hash, file.path.len);
        hash.update(file.path);
        hashInt(&hash, file.bytes);
        hash.update(&file.sha256);
    }
    return hash.finalResult();
}

fn sameSourceClosures(left: SourceClosure, right: SourceClosure) bool {
    if (left.count != right.count or
        !std.mem.eql(u8, &left.identity, &right.identity)) return false;
    const count: usize = left.count;
    for (left.files[0..count], right.files[0..count]) |maybe_left, maybe_right| {
        const left_file = maybe_left orelse return false;
        const right_file = maybe_right orelse return false;
        if (!std.mem.eql(u8, left_file.path, right_file.path) or
            left_file.bytes != right_file.bytes or
            !std.mem.eql(u8, &left_file.sha256, &right_file.sha256)) return false;
    }
    return true;
}

fn programCommitmentIdentity(
    authority: authority_mod.Authority,
    inventory: Inventory,
    row_count: u64,
    root: u32,
) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-combined-program-commitment.v1\x00");
    hash.update(&authority.identity);
    hash.update(&inventory.executable_words_identity);
    hash.update(&inventory.custom0_sequence_identity);
    hashInt(&hash, row_count);
    hashInt(&hash, root);
    return hash.finalResult();
}

fn receiptIdentity(value: Receipt) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-combined-elf-receipt.v1\x00");
    hashInt(&hash, value.format);
    hash.update(&value.elf.sha256);
    hashInt(&hash, value.elf.bytes);
    hash.update(&value.externally_expected_elf_sha256);
    hash.update(&value.checker.sha256);
    hashInt(&hash, value.checker.bytes);
    hash.update(&value.source_closure.identity);
    hash.update(&value.authority_identity);
    hash.update(&value.registry_identity);
    for (value.ordered_member_identities) |identity| hash.update(&identity);
    hashInventory(&hash, value.inventory);
    hashInt(&hash, value.program_row_count);
    hashInt(&hash, value.program_root);
    hash.update(&value.program_commitment_identity);
    hash.update(&.{
        @intFromBool(value.session_constructed_and_deinitialized),
        @intFromBool(value.final_candidate_executable),
        @intFromBool(value.production_eligible),
    });
    return hash.finalResult();
}

fn hashInventory(hash: anytype, value: Inventory) void {
    hashInt(hash, value.executable_pt_load_count);
    hashInt(hash, value.executable_file_bytes);
    hashInt(hash, value.executable_memory_bytes);
    hashInt(hash, value.executable_word_count);
    hashInt(hash, value.nonzero_word_count);
    hashInt(hash, value.custom0_word_count);
    hashInt(hash, value.keccak_word_count);
    hashInt(hash, value.recovery_word_count);
    hashInt(hash, value.bulk_memcpy_word_count);
    hashInt(hash, value.stack_swap_word_count);
    hash.update(&value.executable_words_identity);
    hash.update(&value.custom0_sequence_identity);
}

fn bounded(bytes: []const u8, offset: usize, length: usize) ?[]const u8 {
    const end = std.math.add(usize, offset, length) catch return null;
    if (end > bytes.len) return null;
    return bytes[offset..end];
}

fn isCanonicalRelativePath(path: []const u8) bool {
    return path.len != 0 and !std.fs.path.isAbsolute(path) and
        !std.mem.eql(u8, path, ".") and !std.mem.eql(u8, path, "..") and
        !std.mem.startsWith(u8, path, "./") and
        !std.mem.startsWith(u8, path, "../") and
        !std.mem.endsWith(u8, path, "/.") and
        !std.mem.endsWith(u8, path, "/..") and
        std.mem.indexOf(u8, path, "//") == null and
        std.mem.indexOf(u8, path, "/./") == null and
        std.mem.indexOf(u8, path, "/../") == null;
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
    return std.math.add(T, left, @intCast(right));
}

fn isZero(value: Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

comptime {
    if (production_active or proof_or_fresh_verification or
        schema_version != 1 or source_file_capacity < 3 or
        authority_mod.production_active or registry_mod.production_active)
    {
        @compileError("combined candidate ELF receipt became active");
    }
}
