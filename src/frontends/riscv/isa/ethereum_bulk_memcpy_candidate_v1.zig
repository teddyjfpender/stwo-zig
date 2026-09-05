//! Nonproduction execution authority for Ethereum plus private bulk memcpy.
//!
//! The normal Ethereum admission profile is unchanged. A candidate session
//! must receive this sidecar from its caller, including the exact guest ELF
//! digest and the separately validated private registry authority.

const std = @import("std");

const bulk = @import("bulk_memcpy_candidate_v1.zig");
const execution_profile = @import("execution_profile.zig");
const private_registry = @import("bulk_memcpy_private_registry_v1.zig");

pub const production_active = false;
pub const schema_version: u16 = 1;
pub const base_profile = execution_profile.ExecutionProfile.rv32im_zkvm_ethereum_v1;

pub const Authority = struct {
    schema: u16,
    admitted_profile: execution_profile.ExecutionProfile,
    capability_bits: u64,
    ethereum_abi_version: u16,
    ethereum_semantic_digest: [32]u8,
    guest_elf_sha256: [32]u8,
    bulk_memcpy: private_registry.Authority,
    identity: [32]u8,

    pub fn create(guest_elf_sha256: [32]u8) !Authority {
        if (isZeroDigest(guest_elf_sha256))
            return error.InvalidEthereumBulkMemcpyGuestIdentity;
        const bulk_authority = try private_registry.authority();
        const result = Authority{
            .schema = schema_version,
            .admitted_profile = base_profile,
            .capability_bits = execution_profile.ethereum_capability_bits,
            .ethereum_abi_version = execution_profile.ethereum_abi_version,
            .ethereum_semantic_digest = execution_profile.ethereum_semantic_digest,
            .guest_elf_sha256 = guest_elf_sha256,
            .bulk_memcpy = bulk_authority,
            .identity = authorityIdentity(guest_elf_sha256, bulk_authority),
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: Authority) !void {
        if (production_active or self.schema != schema_version or
            self.admitted_profile != base_profile or
            self.capability_bits != execution_profile.ethereum_capability_bits or
            self.ethereum_abi_version != execution_profile.ethereum_abi_version or
            !std.mem.eql(
                u8,
                &self.ethereum_semantic_digest,
                &execution_profile.ethereum_semantic_digest,
            ) or
            isZeroDigest(self.guest_elf_sha256))
        {
            return error.InvalidEthereumBulkMemcpyAuthority;
        }
        try private_registry.validateAuthority(self.bulk_memcpy);
        const expected = authorityIdentity(self.guest_elf_sha256, self.bulk_memcpy);
        if (!std.mem.eql(u8, &self.identity, &expected))
            return error.InvalidEthereumBulkMemcpyAuthority;
    }

    pub fn validateElf(self: Authority, elf_bytes: []const u8) !void {
        try self.validate();
        var actual: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(elf_bytes, &actual, .{});
        if (!std.mem.eql(u8, &actual, &self.guest_elf_sha256))
            return error.EthereumBulkMemcpyGuestIdentityMismatch;
    }

    pub fn bindSessionTag(self: Authority, base: u64) !u64 {
        try self.validate();
        var result = base;
        for (self.identity) |byte|
            result = (result ^ byte) *% 0x0000_0100_0000_01b3;
        return result;
    }
};

fn authorityIdentity(
    guest_elf_sha256: [32]u8,
    bulk_authority: private_registry.Authority,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-bulk-memcpy-candidate-authority.v1\x00");
    hash.update(&u16Bytes(schema_version));
    hash.update(&u16Bytes(@intFromEnum(base_profile)));
    hash.update(&u64Bytes(execution_profile.ethereum_capability_bits));
    hash.update(&u16Bytes(execution_profile.ethereum_abi_version));
    hash.update(&execution_profile.ethereum_semantic_digest);
    hash.update(&guest_elf_sha256);
    hash.update(&bulk_authority.allocation.registry_identity);
    hash.update(&.{
        bulk.major_opcode,
        bulk_authority.allocation.funct7,
        bulk.destination_register,
        bulk.source_register,
        bulk.length_register,
    });
    hash.update(&u32Bytes(bulk_authority.fixed_word));
    hash.update(&u32Bytes(bulk_authority.allocation.proof_opcode_id));
    hash.update(&bulk_authority.semantic_identity);
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn isZeroDigest(value: [32]u8) bool {
    return std.mem.allEqual(u8, &value, 0);
}

fn u16Bytes(value: anytype) [2]u8 {
    var result: [2]u8 = undefined;
    std.mem.writeInt(u16, &result, @intCast(value), .little);
    return result;
}

fn u32Bytes(value: u32) [4]u8 {
    var result: [4]u8 = undefined;
    std.mem.writeInt(u32, &result, value, .little);
    return result;
}

fn u64Bytes(value: u64) [8]u8 {
    var result: [8]u8 = undefined;
    std.mem.writeInt(u64, &result, value, .little);
    return result;
}

comptime {
    if (production_active or schema_version != 1 or
        @intFromEnum(base_profile) != 3 or
        execution_profile.ethereum_capability_bits != 6 or
        private_registry.production_active or bulk.production_active)
    {
        @compileError("Ethereum+bulk-memcpy candidate authority became active");
    }
}

test "Ethereum bulk memcpy authority binds exact ELF and private member" {
    const elf = "candidate-elf";
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(elf, &digest, .{});
    const actual = try Authority.create(digest);
    try actual.validate();
    try actual.validateElf(elf);
    try std.testing.expectEqual(@as(u7, 4), actual.bulk_memcpy.allocation.funct7);
    try std.testing.expectEqual(
        @as(u32, 48),
        actual.bulk_memcpy.allocation.proof_opcode_id,
    );
    try std.testing.expectError(
        error.EthereumBulkMemcpyGuestIdentityMismatch,
        actual.validateElf("different"),
    );
}
