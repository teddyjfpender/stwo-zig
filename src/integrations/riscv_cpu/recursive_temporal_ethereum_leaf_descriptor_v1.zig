//! Canonical transport for one freshly verified recursive Ethereum leaf.
//!
//! Decoding this value is never proof admission. The only production mint is
//! the direct success edge of `verifyPoseidonArtifactWithCapture`: that edge
//! cold-compiles ProgramV2, binds the exact verified Tree0 commitment, and
//! validates the full global/local link before projecting this pointer-free
//! descriptor. Re-admission must reopen both STWESG31 and the proof artifact.

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const proof_security = @import("recursive_temporal_proof_security_v1.zig");
const statement_plan = @import("recursive_temporal_statement_plan_v1.zig");

const recursion = frontend.recursion;
const program_desc = recursion.ethereum_vm_verified_program_descriptor_v1;
const source_wire = frontend.prover_mod.guest_precompile
    .ethereum_segment_source_wire;
const span = recursion.span_statement;
const verified_link_mod = recursion.segment_leaf_local_verified_link_v3;

const M31 = core.fields.m31.M31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const ENCODED_BYTE_COUNT: usize = 2728;
pub const PRODUCTION_RECURSIVE_ACTIVATION = false;

const SUBTREE_DOMAIN =
    "stwo-zig/typed-air/ethereum-leaf-descriptor-subtree/v1\x00";
const DESCRIPTOR_DOMAIN =
    "stwo-zig/typed-air/ethereum-leaf-descriptor/v1\x00";

pub const KindV1 = enum(u8) {
    ethereum_segment_v3_poseidon2 = 1,
};

pub const MintInputV1 = struct {
    program: program_desc.DescriptorV1,
    source: *const source_wire.Source,
    verified_link: verified_link_mod.VerifiedLinkV3,
    proof_artifact_byte_count: u64,
    proof_artifact_sha256: [32]u8,
    proof_root_sha256: [32]u8,
    transcript_state_sha256: [32]u8,
};

/// Pointer-free publication candidate. It carries exact compiler, source,
/// proof-capture, artifact, and global-position custody; it carries no witness
/// pointer and cannot choose a verifier program during replay.
pub const DescriptorV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    kind: KindV1 = .ethereum_segment_v3_poseidon2,
    height: u8 = 0,
    reserved: [2]u8 = .{ 0, 0 },
    program: program_desc.DescriptorV1,
    statement_words: span.StatementWords,
    source_authority_sha256: [32]u8,
    source_public_statement_sha256: [32]u8,
    recursive_statement_sha256: [32]u8,
    journal_record_sha256: [32]u8,
    global_metadata_id: recursion.poseidon2_channel.Digest,
    verified_link: verified_link_mod.VerifiedLinkV3,
    proof_artifact_byte_count: u64,
    proof_security_identity_sha256: [32]u8,
    proof_artifact_sha256: [32]u8,
    proof_root_sha256: [32]u8,
    transcript_state_sha256: [32]u8,
    subtree_sha256: [32]u8,
    descriptor_sha256: [32]u8,

    pub fn validate(self: *const DescriptorV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.kind != .ethereum_segment_v3_poseidon2 or
            self.height != 0 or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            self.proof_artifact_byte_count == 0)
        {
            return error.InvalidEthereumLeafDescriptor;
        }
        try self.program.validate();
        const statement = try span.SpanStatement.fromCanonicalWords(
            &self.statement_words,
        );
        if (statement.slots.height != 0 or
            statement.slots.first != self.verified_link.segment_index or
            statement.job.segment_count != self.verified_link.segment_count)
        {
            return error.InvalidEthereumLeafDescriptor;
        }
        switch (statement.body) {
            .executed => |executed| if (executed.first_segment !=
                self.verified_link.segment_index or
                executed.segment_count != 1 or
                executed.first_cycle != self.verified_link.global_cycle_start or
                executed.cycle_count != self.verified_link.local_cycle_count)
            {
                return error.InvalidEthereumLeafDescriptor;
            },
            .empty => return error.InvalidEthereumLeafDescriptor,
        }
        try self.verified_link.validateHeader();
        if (!std.meta.eql(
            self.global_metadata_id,
            self.verified_link.global_metadata_id,
        ) or !std.mem.eql(
            u8,
            &self.recursive_statement_sha256,
            &statement_plan.statementSha256(&self.statement_words),
        ) or !std.mem.eql(
            u8,
            &self.proof_security_identity_sha256,
            &productionSecurityIdentity(),
        )) return error.InvalidEthereumLeafDescriptor;
        inline for (.{
            self.source_authority_sha256,
            self.source_public_statement_sha256,
            self.recursive_statement_sha256,
            self.journal_record_sha256,
            self.proof_security_identity_sha256,
            self.proof_artifact_sha256,
            self.proof_root_sha256,
            self.transcript_state_sha256,
            self.subtree_sha256,
            self.descriptor_sha256,
        }) |value| try requireSha(value);
        if (!std.mem.eql(
            u8,
            &self.subtree_sha256,
            &subtreeIdentity(self),
        ) or !std.mem.eql(
            u8,
            &self.descriptor_sha256,
            &descriptorIdentity(self),
        )) return error.InvalidEthereumLeafDescriptor;
    }

    /// Cold transport re-admission. The caller must separately reopen and
    /// verify the proof artifact before this source/program comparison can be
    /// promoted to a verifier-owned leaf publication.
    pub fn validateAgainst(
        self: *const DescriptorV1,
        source: *const source_wire.Source,
        program: *const recursion.ethereum_vm_composition_program_v2
            .EthereumVmCompositionProgramV2,
    ) !void {
        try self.validate();
        try self.program.validateAgainstProgram(program);
        try self.validateAgainstSource(source);
    }

    /// Reopens the exact STWESG31 authority without claiming that the retained
    /// verifier program or proof artifact has been re-verified.
    pub fn validateAgainstSource(
        self: *const DescriptorV1,
        source: *const source_wire.Source,
    ) !void {
        try self.validate();
        const expected = try initFromFreshVerifier(.{
            .program = self.program,
            .source = source,
            .verified_link = self.verified_link,
            .proof_artifact_byte_count = self.proof_artifact_byte_count,
            .proof_artifact_sha256 = self.proof_artifact_sha256,
            .proof_root_sha256 = self.proof_root_sha256,
            .transcript_state_sha256 = self.transcript_state_sha256,
        });
        if (!std.meta.eql(self.*, expected))
            return error.EthereumLeafDescriptorMismatch;
    }

    pub fn encodeCanonical(self: *const DescriptorV1) ![ENCODED_BYTE_COUNT]u8 {
        try self.validate();
        var result: [ENCODED_BYTE_COUNT]u8 = undefined;
        var writer = Writer{ .bytes = &result };
        writer.u16Value(self.format_version);
        writer.u16Value(self.schema_version);
        writer.u8Value(@intFromEnum(self.kind));
        writer.u8Value(self.height);
        writer.bytesValue(&self.reserved);
        const program_bytes = try self.program.encodeCanonical();
        writer.bytesValue(&program_bytes);
        for (self.statement_words) |word| writer.u32Value(word.toU32());
        inline for (.{
            self.source_authority_sha256,
            self.source_public_statement_sha256,
            self.recursive_statement_sha256,
            self.journal_record_sha256,
        }) |value| writer.sha(value);
        writer.digest(self.global_metadata_id);
        writer.link(self.verified_link);
        writer.u64Value(self.proof_artifact_byte_count);
        inline for (.{
            self.proof_security_identity_sha256,
            self.proof_artifact_sha256,
            self.proof_root_sha256,
            self.transcript_state_sha256,
            self.subtree_sha256,
            self.descriptor_sha256,
        }) |value| writer.sha(value);
        std.debug.assert(writer.at == result.len);
        return result;
    }

    pub fn decodeCanonical(bytes: []const u8) !DescriptorV1 {
        if (bytes.len != ENCODED_BYTE_COUNT)
            return error.InvalidEthereumLeafDescriptor;
        var reader = Reader{ .bytes = bytes };
        var result = DescriptorV1{
            .format_version = reader.u16Value(),
            .schema_version = reader.u16Value(),
            .kind = std.meta.intToEnum(KindV1, reader.u8Value()) catch
                return error.InvalidEthereumLeafDescriptor,
            .height = reader.u8Value(),
            .reserved = reader.array(2),
            .program = try program_desc.DescriptorV1.decodeCanonical(
                reader.take(program_desc.ENCODED_BYTE_COUNT),
            ),
            .statement_words = undefined,
            .source_authority_sha256 = undefined,
            .source_public_statement_sha256 = undefined,
            .recursive_statement_sha256 = undefined,
            .journal_record_sha256 = undefined,
            .global_metadata_id = undefined,
            .verified_link = undefined,
            .proof_artifact_byte_count = undefined,
            .proof_security_identity_sha256 = undefined,
            .proof_artifact_sha256 = undefined,
            .proof_root_sha256 = undefined,
            .transcript_state_sha256 = undefined,
            .subtree_sha256 = undefined,
            .descriptor_sha256 = undefined,
        };
        for (&result.statement_words) |*word| {
            const value = reader.u32Value();
            if (value >= core.fields.m31.Modulus)
                return error.InvalidEthereumLeafDescriptor;
            word.* = M31.fromCanonical(value);
        }
        result.source_authority_sha256 = reader.sha();
        result.source_public_statement_sha256 = reader.sha();
        result.recursive_statement_sha256 = reader.sha();
        result.journal_record_sha256 = reader.sha();
        result.global_metadata_id = reader.digest();
        result.verified_link = reader.link();
        result.proof_artifact_byte_count = reader.u64Value();
        result.proof_security_identity_sha256 = reader.sha();
        result.proof_artifact_sha256 = reader.sha();
        result.proof_root_sha256 = reader.sha();
        result.transcript_state_sha256 = reader.sha();
        result.subtree_sha256 = reader.sha();
        result.descriptor_sha256 = reader.sha();
        if (reader.at != bytes.len)
            return error.InvalidEthereumLeafDescriptor;
        try result.validate();
        const canonical = try result.encodeCanonical();
        if (!std.mem.eql(u8, bytes, &canonical))
            return error.InvalidEthereumLeafDescriptor;
        return result;
    }
};

/// This constructor is intentionally structural. Production callers invoke it
/// only after the fresh verifier capability has revalidated the same source,
/// ProgramV2, proof capture, and VerifiedLinkV3 in one transaction.
pub fn initFromFreshVerifier(input: MintInputV1) !DescriptorV1 {
    try input.program.validate();
    try input.source.validate();
    try input.verified_link.validateHeader();
    try validateLinkAgainstSource(&input.verified_link, input.source);
    if (input.proof_artifact_byte_count == 0)
        return error.InvalidEthereumLeafDescriptor;
    const source_bytes = try source_wire.encodeValue(input.source);
    var result = DescriptorV1{
        .program = input.program,
        .statement_words = input.source.metadata.base_statement_words,
        .source_authority_sha256 = sha256(&source_bytes),
        .source_public_statement_sha256 = try input.source.statementSha256(),
        .recursive_statement_sha256 = statement_plan.statementSha256(
            &input.source.metadata.base_statement_words,
        ),
        .journal_record_sha256 = input.source.journal_record_sha256,
        .global_metadata_id = try input.source.metadata.identity(),
        .verified_link = input.verified_link,
        .proof_artifact_byte_count = input.proof_artifact_byte_count,
        .proof_security_identity_sha256 = productionSecurityIdentity(),
        .proof_artifact_sha256 = input.proof_artifact_sha256,
        .proof_root_sha256 = input.proof_root_sha256,
        .transcript_state_sha256 = input.transcript_state_sha256,
        .subtree_sha256 = undefined,
        .descriptor_sha256 = undefined,
    };
    result.subtree_sha256 = subtreeIdentity(&result);
    result.descriptor_sha256 = descriptorIdentity(&result);
    try result.validate();
    return result;
}

fn validateLinkAgainstSource(
    link: *const verified_link_mod.VerifiedLinkV3,
    source: *const source_wire.Source,
) !void {
    const metadata = &source.metadata;
    if (!std.meta.eql(link.global_metadata_id, try metadata.identity()) or
        link.segment_index != metadata.segment_index or
        link.segment_count != metadata.segment_count or
        link.global_cycle_start != metadata.global_cycle_start or
        link.global_cycle_end != metadata.global_cycle_end or
        link.local_cycle_count != metadata.local_cycle_count or
        link.entry_continuation_root != metadata.entry.continuation_root or
        link.exit_continuation_root != metadata.exit.continuation_root)
    {
        return error.EthereumLeafDescriptorMismatch;
    }
}

fn productionSecurityIdentity() [32]u8 {
    return proof_security.ProofSecurityV1.ethereumSegmentV3Poseidon2().identity;
}

fn subtreeIdentity(value: *const DescriptorV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(SUBTREE_DOMAIN);
    hash.update(&value.program.descriptor_sha256);
    hash.update(&value.source_authority_sha256);
    hash.update(&value.recursive_statement_sha256);
    hashDigest(&hash, value.global_metadata_id);
    hashDigest(&hash, value.verified_link.identity);
    hash.update(&value.proof_security_identity_sha256);
    hash.update(&value.proof_artifact_sha256);
    hash.update(&value.program.proof_capture_sha256);
    hash.update(&value.program.capture_identity);
    return hash.finalResult();
}

fn descriptorIdentity(value: *const DescriptorV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(DESCRIPTOR_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.kind));
    hashInt(&hash, u8, value.height);
    hash.update(&value.reserved);
    hash.update(&value.program.descriptor_sha256);
    for (value.statement_words) |word| hashInt(&hash, u32, word.toU32());
    inline for (.{
        value.source_authority_sha256,
        value.source_public_statement_sha256,
        value.recursive_statement_sha256,
        value.journal_record_sha256,
    }) |item| hash.update(&item);
    hashDigest(&hash, value.global_metadata_id);
    hashLink(&hash, value.verified_link);
    hashInt(&hash, u64, value.proof_artifact_byte_count);
    inline for (.{
        value.proof_security_identity_sha256,
        value.proof_artifact_sha256,
        value.proof_root_sha256,
        value.transcript_state_sha256,
        value.subtree_sha256,
    }) |item| hash.update(&item);
    return hash.finalResult();
}

fn hashLink(hash: *Sha256, link: verified_link_mod.VerifiedLinkV3) void {
    hashInt(hash, u16, link.format_version);
    hashInt(hash, u16, link.schema_version);
    inline for (.{
        link.global_metadata_id,
        link.local_authority_id,
        link.local_wire_id,
        link.local_receipt_id,
    }) |digest| hashDigest(hash, digest);
    hashInt(hash, u32, link.segment_index);
    hashInt(hash, u32, link.segment_count);
    hashInt(hash, u64, link.global_cycle_start);
    hashInt(hash, u64, link.global_cycle_end);
    hashInt(hash, u32, link.local_cycle_count);
    hashInt(hash, u32, link.entry_continuation_root);
    hashInt(hash, u32, link.exit_continuation_root);
    hashDigest(hash, link.identity);
}

fn sha256(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(bytes, &result, .{});
    return result;
}

fn requireSha(value: [32]u8) !void {
    if (std.mem.allEqual(u8, &value, 0))
        return error.InvalidEthereumLeafDescriptor;
}

fn hashDigest(hash: *Sha256, value: recursion.poseidon2_channel.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

const Writer = struct {
    bytes: []u8,
    at: usize = 0,

    fn take(self: *Writer, len: usize) []u8 {
        defer self.at += len;
        return self.bytes[self.at..][0..len];
    }
    fn bytesValue(self: *Writer, value: []const u8) void {
        @memcpy(self.take(value.len), value);
    }
    fn u8Value(self: *Writer, value: u8) void {
        self.take(1)[0] = value;
    }
    fn u16Value(self: *Writer, value: u16) void {
        std.mem.writeInt(u16, self.take(2)[0..2], value, .little);
    }
    fn u32Value(self: *Writer, value: u32) void {
        std.mem.writeInt(u32, self.take(4)[0..4], value, .little);
    }
    fn u64Value(self: *Writer, value: u64) void {
        std.mem.writeInt(u64, self.take(8)[0..8], value, .little);
    }
    fn sha(self: *Writer, value: [32]u8) void {
        self.bytesValue(&value);
    }
    fn digest(self: *Writer, value: recursion.poseidon2_channel.Digest) void {
        for (value) |word| self.u32Value(word);
    }
    fn link(self: *Writer, value: verified_link_mod.VerifiedLinkV3) void {
        self.u16Value(value.format_version);
        self.u16Value(value.schema_version);
        self.digest(value.global_metadata_id);
        self.digest(value.local_authority_id);
        self.digest(value.local_wire_id);
        self.digest(value.local_receipt_id);
        self.u32Value(value.segment_index);
        self.u32Value(value.segment_count);
        self.u64Value(value.global_cycle_start);
        self.u64Value(value.global_cycle_end);
        self.u32Value(value.local_cycle_count);
        self.u32Value(value.entry_continuation_root);
        self.u32Value(value.exit_continuation_root);
        self.digest(value.identity);
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,

    fn take(self: *Reader, len: usize) []const u8 {
        defer self.at += len;
        return self.bytes[self.at..][0..len];
    }
    fn array(self: *Reader, comptime len: usize) [len]u8 {
        return self.take(len)[0..len].*;
    }
    fn u8Value(self: *Reader) u8 {
        return self.take(1)[0];
    }
    fn u16Value(self: *Reader) u16 {
        return std.mem.readInt(u16, self.take(2)[0..2], .little);
    }
    fn u32Value(self: *Reader) u32 {
        return std.mem.readInt(u32, self.take(4)[0..4], .little);
    }
    fn u64Value(self: *Reader) u64 {
        return std.mem.readInt(u64, self.take(8)[0..8], .little);
    }
    fn sha(self: *Reader) [32]u8 {
        return self.array(32);
    }
    fn digest(self: *Reader) recursion.poseidon2_channel.Digest {
        var result: recursion.poseidon2_channel.Digest = undefined;
        for (&result) |*word| word.* = self.u32Value();
        return result;
    }
    fn link(self: *Reader) verified_link_mod.VerifiedLinkV3 {
        return .{
            .format_version = self.u16Value(),
            .schema_version = self.u16Value(),
            .global_metadata_id = self.digest(),
            .local_authority_id = self.digest(),
            .local_wire_id = self.digest(),
            .local_receipt_id = self.digest(),
            .segment_index = self.u32Value(),
            .segment_count = self.u32Value(),
            .global_cycle_start = self.u64Value(),
            .global_cycle_end = self.u64Value(),
            .local_cycle_count = self.u32Value(),
            .entry_continuation_root = self.u32Value(),
            .exit_continuation_root = self.u32Value(),
            .identity = self.digest(),
        };
    }
};

comptime {
    if (ENCODED_BYTE_COUNT != 2728 or FORMAT_VERSION != 1 or
        SCHEMA_VERSION != 1)
    {
        @compileError("Ethereum leaf descriptor wire drifted");
    }
}
