//! Nonproduction authority for the final `{bulk memcpy, U256 SWAP}` guest.
//!
//! The combined registry owns ordering and allocation identity. The two
//! standalone authorities remain exact per-member runner custody and must bind
//! the same ELF bytes; neither may be substituted for the combined authority.

const std = @import("std");

const bulk_authority_mod = @import("ethereum_bulk_memcpy_candidate_v1.zig");
const bulk_registry = @import("bulk_memcpy_private_registry_v1.zig");
const execution_profile = @import("execution_profile.zig");
const registry_mod = @import("ethereum_candidate_private_registry_v1.zig");
const swap_authority_mod = @import("ethereum_stack_swap_candidate_v1.zig");

pub const Digest = [32]u8;
pub const production_active = false;
pub const schema_version: u16 = 1;
pub const base_profile = execution_profile.ExecutionProfile.rv32im_zkvm_ethereum_v1;

pub const Authority = struct {
    schema: u16 = schema_version,
    admitted_profile: execution_profile.ExecutionProfile = base_profile,
    registry: registry_mod.Registry,
    guest_elf_sha256: Digest,
    bulk_memcpy: bulk_authority_mod.Authority,
    stack_swap: swap_authority_mod.Authority,
    identity: Digest,

    pub fn create(guest_elf_sha256: Digest) !Authority {
        if (isZero(guest_elf_sha256))
            return error.InvalidEthereumCombinedCandidateGuestIdentity;
        var result = Authority{
            .registry = try .canonical(),
            .guest_elf_sha256 = guest_elf_sha256,
            .bulk_memcpy = try .create(guest_elf_sha256),
            .stack_swap = try .create(guest_elf_sha256),
            .identity = undefined,
        };
        result.identity = authorityIdentity(result);
        try result.validate();
        return result;
    }

    pub fn validate(self: Authority) !void {
        if (production_active or self.schema != schema_version or
            self.admitted_profile != base_profile or isZero(self.guest_elf_sha256))
        {
            return error.InvalidEthereumCombinedCandidateAuthority;
        }
        try self.registry.validate();
        try self.bulk_memcpy.validate();
        try self.stack_swap.validate();
        if (!std.mem.eql(
            u8,
            &self.guest_elf_sha256,
            &self.bulk_memcpy.guest_elf_sha256,
        ) or !std.mem.eql(
            u8,
            &self.guest_elf_sha256,
            &self.stack_swap.guest_elf_sha256,
        ) or !std.mem.eql(
            u8,
            &self.registry.bulk_memcpy_fixture_registry_identity,
            &self.bulk_memcpy.bulk_memcpy.allocation.registry_identity,
        ) or !std.mem.eql(
            u8,
            &self.registry.stack_swap_fixture_registry_identity,
            &self.stack_swap.stack_swap.allocation.registry_identity,
        )) {
            return error.InvalidEthereumCombinedCandidateAuthority;
        }

        const bulk_member = try self.registry.member(.bulk_memcpy_v1);
        const bulk_descriptor = bulk_registry.memberDescriptor();
        try bulk_descriptor.validate();
        const swap_member = try self.registry.member(.stack_swap_v1);
        if (bulk_member.funct7 != self.bulk_memcpy.bulk_memcpy.allocation.funct7 or
            bulk_member.proof_opcode_id !=
                self.bulk_memcpy.bulk_memcpy.allocation.proof_opcode_id or
            bulk_member.fixed_word != self.bulk_memcpy.bulk_memcpy.fixed_word or
            !std.mem.eql(
                u8,
                &bulk_member.semantic_authority_identity,
                &bulk_descriptor.semantic_identity,
            ) or swap_member.funct7 !=
            self.stack_swap.stack_swap.allocation.funct7 or
            swap_member.proof_opcode_id !=
                self.stack_swap.stack_swap.allocation.proof_opcode_id or
            swap_member.fixed_word != self.stack_swap.stack_swap.fixed_word or
            !std.mem.eql(
                u8,
                &swap_member.semantic_authority_identity,
                &self.stack_swap.stack_swap.semantic_identity,
            ) or !std.mem.eql(u8, &self.identity, &authorityIdentity(self)))
        {
            return error.InvalidEthereumCombinedCandidateAuthority;
        }
    }

    pub fn validateElf(self: Authority, elf_bytes: []const u8) !void {
        try self.validate();
        var actual: Digest = undefined;
        std.crypto.hash.sha2.Sha256.hash(elf_bytes, &actual, .{});
        if (!std.mem.eql(u8, &actual, &self.guest_elf_sha256))
            return error.EthereumCombinedCandidateGuestIdentityMismatch;
        try self.bulk_memcpy.validateElf(elf_bytes);
        try self.stack_swap.validateElf(elf_bytes);
    }

    pub fn bindSessionTag(self: Authority, base: u64) !u64 {
        try self.validate();
        var result = base;
        for (self.identity) |byte|
            result = (result ^ byte) *% 0x0000_0100_0000_01b3;
        return result;
    }
};

fn authorityIdentity(value: Authority) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-combined-candidate-authority.v1\x00");
    putInt(&hash, u16, value.schema);
    putInt(&hash, u16, @intFromEnum(value.admitted_profile));
    hash.update(&value.registry.identity);
    hash.update(&value.guest_elf_sha256);
    hash.update(&value.bulk_memcpy.identity);
    hash.update(&value.stack_swap.identity);
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
    if (production_active or schema_version != 1 or
        registry_mod.production_active or bulk_authority_mod.production_active or
        swap_authority_mod.production_active)
    {
        @compileError("combined Ethereum candidate authority became active");
    }
}

test "combined authority binds both ordered members to one ELF" {
    var digest = [_]u8{0} ** 32;
    digest[0] = 1;
    const authority = try Authority.create(digest);
    try authority.validate();
    try std.testing.expectEqual(
        @as(u7, 4),
        (try authority.registry.member(.bulk_memcpy_v1)).funct7,
    );
    try std.testing.expectEqual(
        @as(u7, 5),
        (try authority.registry.member(.stack_swap_v1)).funct7,
    );
}
