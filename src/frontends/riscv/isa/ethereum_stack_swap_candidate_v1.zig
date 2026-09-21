//! Nonproduction execution authority for Ethereum plus private U256 SWAP.
//!
//! The ordinary Ethereum admission-note profile remains unchanged. This
//! sidecar additionally binds one externally retained guest ELF digest and
//! the explicit private CUSTOM-0 registry allocation. The candidate session
//! receives this authority separately and never mints it from its ELF input.

const std = @import("std");

const execution_profile = @import("execution_profile.zig");
const private_registry = @import("stack_swap_private_registry_v1.zig");
const stack_swap = @import("stack_swap_candidate_v1.zig");

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
    stack_swap: stack_swap.Authority,
    identity: [32]u8,

    pub fn create(guest_elf_sha256: [32]u8) !Authority {
        if (isZeroDigest(guest_elf_sha256))
            return error.InvalidEthereumStackSwapGuestIdentity;
        const swap_authority = try private_registry.authority();
        const result = Authority{
            .schema = schema_version,
            .admitted_profile = base_profile,
            .capability_bits = execution_profile.ethereum_capability_bits,
            .ethereum_abi_version = execution_profile.ethereum_abi_version,
            .ethereum_semantic_digest = execution_profile.ethereum_semantic_digest,
            .guest_elf_sha256 = guest_elf_sha256,
            .stack_swap = swap_authority,
            .identity = authorityIdentity(guest_elf_sha256, swap_authority),
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
            return error.InvalidEthereumStackSwapAuthority;
        }
        try private_registry.validateAuthority(self.stack_swap);
        const expected = authorityIdentity(self.guest_elf_sha256, self.stack_swap);
        if (!std.mem.eql(u8, &self.identity, &expected))
            return error.InvalidEthereumStackSwapAuthority;
    }

    pub fn validateElf(self: Authority, elf_bytes: []const u8) !void {
        try self.validate();
        var actual: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(elf_bytes, &actual, .{});
        if (!std.mem.eql(u8, &actual, &self.guest_elf_sha256))
            return error.EthereumStackSwapGuestIdentityMismatch;
    }

    /// Extends the existing continuation tag without changing its default
    /// derivation. Only the candidate session calls this method.
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
    swap_authority: stack_swap.Authority,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-stack-swap-candidate-authority.v1\x00");
    hash.update(&u16Bytes(schema_version));
    hash.update(&u16Bytes(@intFromEnum(base_profile)));
    hash.update(&u64Bytes(execution_profile.ethereum_capability_bits));
    hash.update(&u16Bytes(execution_profile.ethereum_abi_version));
    hash.update(&execution_profile.ethereum_semantic_digest);
    hash.update(&guest_elf_sha256);
    hash.update(&swap_authority.allocation.registry_identity);
    hash.update(&.{
        stack_swap.major_opcode,
        swap_authority.allocation.funct7,
        stack_swap.destination_register,
        stack_swap.lhs_pointer_register,
        stack_swap.rhs_pointer_register,
    });
    hash.update(&u32Bytes(swap_authority.fixed_word));
    hash.update(&u32Bytes(swap_authority.allocation.proof_opcode_id));
    hash.update(&swap_authority.semantic_identity);
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn isZeroDigest(value: [32]u8) bool {
    for (value) |byte| if (byte != 0) return false;
    return true;
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
        private_registry.production_active or stack_swap.production_active)
    {
        @compileError("Ethereum+SWAP candidate authority became production-active");
    }
}
