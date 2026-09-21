//! Canonical transport projection of one freshly verified Ethereum VM program.
//!
//! This value is not proof authority by itself.  A successful native verifier
//! first cold-compiles `EthereumVmCompositionProgramV2`, binds it to the exact
//! Tree0 preprocessed commitment and complete proof capture, and only then
//! publishes this pointer-free projection.  Re-admission must reopen the proof
//! and compare against `validateAgainstProgram`; decoding a self-consistent
//! byte string never selects a verifier program.

const std = @import("std");

const graph = @import("air/composition_circuit.zig");
const channel = @import("poseidon2_channel.zig");
const program_v2 = @import("ethereum_vm_composition_program_v2.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const ENCODED_BYTE_COUNT: usize = 512;

const INSTANCE_DOMAIN =
    "stwo-zig/riscv/ethereum-vm-fresh-verified-program/v1\x00";
const DESCRIPTOR_DOMAIN =
    "stwo-zig/riscv/ethereum-vm-verified-program-descriptor/v1\x00";

pub const Error = error{
    InvalidVerifiedProgramDescriptor,
    VerifiedProgramDescriptorMismatch,
};

pub const InstanceInputV1 = struct {
    air_program_identity: [32]u8,
    verifier_program_authority: [32]u8,
    preprocessed_commitment_root: channel.Digest,
    proof_capture_sha256: [32]u8,
    capture_identity: [32]u8,
};

/// Complete fixed-size projection of the proof-independent compiler result and
/// its verifier-owned proof-instance binding.  Every compiler subauthority is
/// retained explicitly; consumers never flatten this to one opaque selector.
pub const DescriptorV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    program_format_version: u16 = program_v2.FORMAT_VERSION,
    program_schema_version: u16 = program_v2.SCHEMA_VERSION,
    circuit_id: u32 = program_v2.CIRCUIT_ID,
    sampled_value_count: u32,
    claimed_sum_count: u32,
    relation_challenge_count: u32,
    transcript_claimed_sum_count: u32,
    public_wire_boundary_count: u32,
    base_profile_sha256: [32]u8,
    base_geometry_sha256: [32]u8,
    extension_geometry_sha256: [32]u8,
    selected_lookup_compiler_sha256: [32]u8,
    protocol_profile_sha256: [32]u8,
    graph_sha256: [32]u8,
    reference_sha256: [32]u8,
    schedule_sha256: [32]u8,
    air_program_identity: [32]u8,
    verifier_program_authority: [32]u8,
    preprocessed_commitment_root: channel.Digest,
    proof_capture_sha256: [32]u8,
    capture_identity: [32]u8,
    instance_sha256: [32]u8,
    descriptor_sha256: [32]u8,

    pub fn validate(self: *const DescriptorV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.program_format_version != program_v2.FORMAT_VERSION or
            self.program_schema_version != program_v2.SCHEMA_VERSION or
            self.circuit_id != program_v2.CIRCUIT_ID or
            self.sampled_value_count == 0 or
            self.claimed_sum_count == 0 or
            self.relation_challenge_count == 0 or
            self.transcript_claimed_sum_count == 0 or
            self.public_wire_boundary_count != 0)
        {
            return error.InvalidVerifiedProgramDescriptor;
        }
        inline for (.{
            self.base_profile_sha256,
            self.base_geometry_sha256,
            self.extension_geometry_sha256,
            self.selected_lookup_compiler_sha256,
            self.protocol_profile_sha256,
            self.graph_sha256,
            self.reference_sha256,
            self.schedule_sha256,
            self.air_program_identity,
            self.verifier_program_authority,
            self.proof_capture_sha256,
            self.capture_identity,
            self.instance_sha256,
            self.descriptor_sha256,
        }) |value| try requireSha(value);
        try requireNativeDigest(self.preprocessed_commitment_root);
        if (!std.mem.eql(
            u8,
            &self.instance_sha256,
            &instanceSha256(.{
                .air_program_identity = self.air_program_identity,
                .verifier_program_authority = self.verifier_program_authority,
                .preprocessed_commitment_root = self.preprocessed_commitment_root,
                .proof_capture_sha256 = self.proof_capture_sha256,
                .capture_identity = self.capture_identity,
            }),
        ) or !std.mem.eql(
            u8,
            &self.descriptor_sha256,
            &descriptorIdentity(self),
        )) return error.InvalidVerifiedProgramDescriptor;
    }

    pub fn validateAgainstProgram(
        self: *const DescriptorV1,
        program: *const program_v2.EthereumVmCompositionProgramV2,
    ) !void {
        try self.validate();
        try program.validate();
        const expected = project(
            program,
            self.preprocessed_commitment_root,
            self.proof_capture_sha256,
            self.capture_identity,
        );
        if (!std.meta.eql(self.*, expected))
            return error.VerifiedProgramDescriptorMismatch;
    }

    pub fn inputProfile(self: *const DescriptorV1) graph.InputProfile {
        return .{
            .sampled_value_count = self.sampled_value_count,
            .claimed_sum_count = self.claimed_sum_count,
            .relation_challenge_count = self.relation_challenge_count,
            .transcript_claimed_sum_count = self.transcript_claimed_sum_count,
            .public_wire_boundary_count = self.public_wire_boundary_count,
        };
    }

    pub fn encodeCanonical(self: *const DescriptorV1) ![ENCODED_BYTE_COUNT]u8 {
        try self.validate();
        var result: [ENCODED_BYTE_COUNT]u8 = undefined;
        var writer = Writer{ .bytes = &result };
        writer.u16Value(self.format_version);
        writer.u16Value(self.schema_version);
        writer.u16Value(self.program_format_version);
        writer.u16Value(self.program_schema_version);
        writer.u32Value(self.circuit_id);
        inline for (.{
            self.sampled_value_count,
            self.claimed_sum_count,
            self.relation_challenge_count,
            self.transcript_claimed_sum_count,
            self.public_wire_boundary_count,
        }) |value| writer.u32Value(value);
        inline for (.{
            self.base_profile_sha256,
            self.base_geometry_sha256,
            self.extension_geometry_sha256,
            self.selected_lookup_compiler_sha256,
            self.protocol_profile_sha256,
            self.graph_sha256,
            self.reference_sha256,
            self.schedule_sha256,
            self.air_program_identity,
            self.verifier_program_authority,
        }) |value| writer.sha(value);
        for (self.preprocessed_commitment_root) |word| writer.u32Value(word);
        inline for (.{
            self.proof_capture_sha256,
            self.capture_identity,
            self.instance_sha256,
            self.descriptor_sha256,
        }) |value| writer.sha(value);
        std.debug.assert(writer.at == result.len);
        return result;
    }

    pub fn decodeCanonical(bytes: []const u8) !DescriptorV1 {
        if (bytes.len != ENCODED_BYTE_COUNT)
            return error.InvalidVerifiedProgramDescriptor;
        var reader = Reader{ .bytes = bytes };
        var result = DescriptorV1{
            .format_version = reader.u16Value(),
            .schema_version = reader.u16Value(),
            .program_format_version = reader.u16Value(),
            .program_schema_version = reader.u16Value(),
            .circuit_id = reader.u32Value(),
            .sampled_value_count = reader.u32Value(),
            .claimed_sum_count = reader.u32Value(),
            .relation_challenge_count = reader.u32Value(),
            .transcript_claimed_sum_count = reader.u32Value(),
            .public_wire_boundary_count = reader.u32Value(),
            .base_profile_sha256 = reader.sha(),
            .base_geometry_sha256 = reader.sha(),
            .extension_geometry_sha256 = reader.sha(),
            .selected_lookup_compiler_sha256 = reader.sha(),
            .protocol_profile_sha256 = reader.sha(),
            .graph_sha256 = reader.sha(),
            .reference_sha256 = reader.sha(),
            .schedule_sha256 = reader.sha(),
            .air_program_identity = reader.sha(),
            .verifier_program_authority = reader.sha(),
            .preprocessed_commitment_root = undefined,
            .proof_capture_sha256 = undefined,
            .capture_identity = undefined,
            .instance_sha256 = undefined,
            .descriptor_sha256 = undefined,
        };
        for (&result.preprocessed_commitment_root) |*word|
            word.* = reader.u32Value();
        result.proof_capture_sha256 = reader.sha();
        result.capture_identity = reader.sha();
        result.instance_sha256 = reader.sha();
        result.descriptor_sha256 = reader.sha();
        if (reader.at != bytes.len)
            return error.InvalidVerifiedProgramDescriptor;
        try result.validate();
        const canonical = try result.encodeCanonical();
        if (!std.mem.eql(u8, bytes, &canonical))
            return error.InvalidVerifiedProgramDescriptor;
        return result;
    }
};

/// Projection used only on the direct success edge of the fresh verifier.
/// Callers that merely decode its output still need proof re-admission.
pub fn project(
    program: *const program_v2.EthereumVmCompositionProgramV2,
    preprocessed_commitment_root: channel.Digest,
    proof_capture_sha256: [32]u8,
    capture_identity: [32]u8,
) DescriptorV1 {
    const profile = program.input_profile;
    var result = DescriptorV1{
        .sampled_value_count = profile.sampled_value_count,
        .claimed_sum_count = profile.claimed_sum_count,
        .relation_challenge_count = profile.relation_challenge_count,
        .transcript_claimed_sum_count = profile.transcript_claimed_sum_count,
        .public_wire_boundary_count = profile.public_wire_boundary_count,
        .base_profile_sha256 = program.base_profile_sha256,
        .base_geometry_sha256 = program.base_geometry_sha256,
        .extension_geometry_sha256 = program.extension_geometry_sha256,
        .selected_lookup_compiler_sha256 = program.selected_lookup_compiler_sha256,
        .protocol_profile_sha256 = program.protocol_profile_sha256,
        .graph_sha256 = program.graph_sha256,
        .reference_sha256 = program.reference_sha256,
        .schedule_sha256 = program.schedule_sha256,
        .air_program_identity = program.air_program_identity,
        .verifier_program_authority = program.verifier_program_authority,
        .preprocessed_commitment_root = preprocessed_commitment_root,
        .proof_capture_sha256 = proof_capture_sha256,
        .capture_identity = capture_identity,
        .instance_sha256 = undefined,
        .descriptor_sha256 = undefined,
    };
    result.instance_sha256 = instanceSha256(.{
        .air_program_identity = result.air_program_identity,
        .verifier_program_authority = result.verifier_program_authority,
        .preprocessed_commitment_root = result.preprocessed_commitment_root,
        .proof_capture_sha256 = result.proof_capture_sha256,
        .capture_identity = result.capture_identity,
    });
    result.descriptor_sha256 = descriptorIdentity(&result);
    return result;
}

pub fn instanceSha256(input: InstanceInputV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(INSTANCE_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hash.update(&input.air_program_identity);
    hash.update(&input.verifier_program_authority);
    for (input.preprocessed_commitment_root) |word|
        hashInt(&hash, u32, word);
    hash.update(&input.proof_capture_sha256);
    hash.update(&input.capture_identity);
    return hash.finalResult();
}

fn descriptorIdentity(value: *const DescriptorV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(DESCRIPTOR_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u16, value.program_format_version);
    hashInt(&hash, u16, value.program_schema_version);
    hashInt(&hash, u32, value.circuit_id);
    inline for (.{
        value.sampled_value_count,
        value.claimed_sum_count,
        value.relation_challenge_count,
        value.transcript_claimed_sum_count,
        value.public_wire_boundary_count,
    }) |item| hashInt(&hash, u32, item);
    inline for (.{
        value.base_profile_sha256,
        value.base_geometry_sha256,
        value.extension_geometry_sha256,
        value.selected_lookup_compiler_sha256,
        value.protocol_profile_sha256,
        value.graph_sha256,
        value.reference_sha256,
        value.schedule_sha256,
        value.air_program_identity,
        value.verifier_program_authority,
    }) |item| hash.update(&item);
    for (value.preprocessed_commitment_root) |word|
        hashInt(&hash, u32, word);
    hash.update(&value.proof_capture_sha256);
    hash.update(&value.capture_identity);
    hash.update(&value.instance_sha256);
    return hash.finalResult();
}

fn requireSha(value: [32]u8) !void {
    if (std.mem.allEqual(u8, &value, 0))
        return error.InvalidVerifiedProgramDescriptor;
}

fn requireNativeDigest(value: channel.Digest) !void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= @import("stwo_core").fields.m31.Modulus)
            return error.InvalidVerifiedProgramDescriptor;
        aggregate |= word;
    }
    if (aggregate == 0) return error.InvalidVerifiedProgramDescriptor;
}

const Writer = struct {
    bytes: []u8,
    at: usize = 0,

    fn u16Value(self: *Writer, value: u16) void {
        std.mem.writeInt(u16, self.bytes[self.at..][0..2], value, .little);
        self.at += 2;
    }
    fn u32Value(self: *Writer, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.at..][0..4], value, .little);
        self.at += 4;
    }
    fn sha(self: *Writer, value: [32]u8) void {
        @memcpy(self.bytes[self.at..][0..32], &value);
        self.at += 32;
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,

    fn u16Value(self: *Reader) u16 {
        defer self.at += 2;
        return std.mem.readInt(u16, self.bytes[self.at..][0..2], .little);
    }
    fn u32Value(self: *Reader) u32 {
        defer self.at += 4;
        return std.mem.readInt(u32, self.bytes[self.at..][0..4], .little);
    }
    fn sha(self: *Reader) [32]u8 {
        defer self.at += 32;
        return self.bytes[self.at..][0..32].*;
    }
};

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub const testing = struct {
    pub fn reseal(value: *DescriptorV1) void {
        value.instance_sha256 = instanceSha256(.{
            .air_program_identity = value.air_program_identity,
            .verifier_program_authority = value.verifier_program_authority,
            .preprocessed_commitment_root = value.preprocessed_commitment_root,
            .proof_capture_sha256 = value.proof_capture_sha256,
            .capture_identity = value.capture_identity,
        });
        value.descriptor_sha256 = descriptorIdentity(value);
    }
};

comptime {
    if (ENCODED_BYTE_COUNT != 512 or FORMAT_VERSION != 1 or
        SCHEMA_VERSION != 1)
    {
        @compileError("verified Ethereum VM program descriptor drifted");
    }
}
