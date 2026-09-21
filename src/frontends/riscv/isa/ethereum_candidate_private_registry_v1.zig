//! Closed nonproduction registry authority for candidate-only Ethereum opcodes.
//!
//! The fixed-capacity member table is the journal ABI. New candidate members
//! occupy another ordered slot; they do not add fields to execution records.
//! The currently admitted executable is only a SWAP fixture, but its registry
//! already reserves bulk memcpy at funct7=4 and SWAP at funct7=5.

const std = @import("std");

const bulk = @import("bulk_memcpy_candidate_v1.zig");
const bulk_registry = @import("bulk_memcpy_private_registry_v1.zig");
const swap = @import("stack_swap_candidate_v1.zig");
const legacy_registry = @import("stack_swap_private_registry_v1.zig");

pub const Digest = [32]u8;
pub const production_active = false;
pub const schema_version: u16 = 1;
pub const max_members: usize = 8;
pub const canonical_member_count: usize = 2;

pub const MemberKind = enum(u16) {
    bulk_memcpy_v1 = 1,
    stack_swap_v1 = 2,
};

pub const Member = struct {
    kind: MemberKind,
    major_opcode: u7,
    funct7: u7,
    proof_opcode_id: u32,
    fixed_word: u32,
    argument_registers: [3]u5,
    semantic_authority_identity: Digest,
    identity: Digest,

    pub fn canonical(kind: MemberKind) !Member {
        return switch (kind) {
            .bulk_memcpy_v1 => blk: {
                const descriptor = bulk_registry.memberDescriptor();
                try descriptor.validate();
                break :blk init(
                    kind,
                    descriptor.major_opcode,
                    descriptor.funct7,
                    descriptor.proof_opcode_id,
                    descriptor.fixed_word,
                    .{
                        descriptor.destination_register,
                        descriptor.source_register,
                        descriptor.length_register,
                    },
                    descriptor.semantic_identity,
                );
            },
            .stack_swap_v1 => blk: {
                const authority = try legacy_registry.authority();
                break :blk init(
                    kind,
                    swap.major_opcode,
                    authority.allocation.funct7,
                    authority.allocation.proof_opcode_id,
                    authority.fixed_word,
                    .{
                        swap.destination_register,
                        swap.lhs_pointer_register,
                        swap.rhs_pointer_register,
                    },
                    authority.semantic_identity,
                );
            },
        };
    }

    pub fn validate(self: Member) !void {
        const expected = try canonical(self.kind);
        if (!std.meta.eql(self, expected))
            return error.InvalidEthereumCandidateRegistryMember;
    }
};

pub const Registry = struct {
    schema: u16 = schema_version,
    member_count: u16,
    members: [max_members]?Member,
    /// Identity of the allocator which owns the CUSTOM-0/proof-opcode pairs.
    allocation_registry_identity: Digest,
    stack_swap_fixture_registry_identity: Digest,
    bulk_memcpy_fixture_registry_identity: Digest,
    identity: Digest,

    pub fn canonical() !Registry {
        var members: [max_members]?Member = .{null} ** max_members;
        members[0] = try Member.canonical(.bulk_memcpy_v1);
        members[1] = try Member.canonical(.stack_swap_v1);
        var result = Registry{
            .member_count = canonical_member_count,
            .members = members,
            .allocation_registry_identity = combinedAllocationIdentity(&members),
            .stack_swap_fixture_registry_identity = legacy_registry.canonicalRegistryIdentity(),
            .bulk_memcpy_fixture_registry_identity = bulk_registry.canonicalRegistryIdentity(),
            .identity = undefined,
        };
        result.identity = registryIdentity(result);
        try result.validate();
        return result;
    }

    pub fn validate(self: Registry) !void {
        if (production_active or self.schema != schema_version or
            self.member_count != canonical_member_count or
            isZero(self.allocation_registry_identity) or
            !std.mem.eql(
                u8,
                &self.stack_swap_fixture_registry_identity,
                &legacy_registry.canonicalRegistryIdentity(),
            ) or !std.mem.eql(
            u8,
            &self.bulk_memcpy_fixture_registry_identity,
            &bulk_registry.canonicalRegistryIdentity(),
        )) {
            return error.InvalidEthereumCandidateRegistry;
        }
        const count: usize = self.member_count;
        var previous_funct7: ?u7 = null;
        for (self.members[0..count], 0..) |maybe_member, index| {
            const registry_member = maybe_member orelse
                return error.InvalidEthereumCandidateRegistry;
            try registry_member.validate();
            if (previous_funct7) |previous| if (registry_member.funct7 <= previous)
                return error.InvalidEthereumCandidateRegistryOrder;
            previous_funct7 = registry_member.funct7;
            const expected_kind: MemberKind = switch (index) {
                0 => .bulk_memcpy_v1,
                1 => .stack_swap_v1,
                else => unreachable,
            };
            if (registry_member.kind != expected_kind)
                return error.InvalidEthereumCandidateRegistryOrder;
            for (self.members[0..index]) |maybe_prior| {
                const prior = maybe_prior.?;
                if (prior.funct7 == registry_member.funct7 or
                    prior.proof_opcode_id == registry_member.proof_opcode_id or
                    prior.fixed_word == registry_member.fixed_word)
                {
                    return error.EthereumCandidateRegistryCollision;
                }
            }
        }
        for (self.members[count..]) |remaining_member| if (remaining_member != null)
            return error.InvalidEthereumCandidateRegistry;
        if (!std.mem.eql(
            u8,
            &self.allocation_registry_identity,
            &combinedAllocationIdentity(&self.members),
        )) return error.InvalidEthereumCandidateRegistryIdentity;
        const expected_identity = registryIdentity(self);
        if (!std.mem.eql(u8, &self.identity, &expected_identity))
            return error.InvalidEthereumCandidateRegistryIdentity;
    }

    pub fn member(self: Registry, kind: MemberKind) !Member {
        try self.validate();
        for (self.members[0..self.member_count]) |maybe_member| {
            const candidate = maybe_member.?;
            if (candidate.kind == kind) return candidate;
        }
        return error.EthereumCandidateRegistryMemberMissing;
    }
};

fn init(
    kind: MemberKind,
    major_opcode: u7,
    funct7: u7,
    proof_opcode_id: u32,
    fixed_word: u32,
    argument_registers: [3]u5,
    semantic_authority_identity: Digest,
) Member {
    var result = Member{
        .kind = kind,
        .major_opcode = major_opcode,
        .funct7 = funct7,
        .proof_opcode_id = proof_opcode_id,
        .fixed_word = fixed_word,
        .argument_registers = argument_registers,
        .semantic_authority_identity = semantic_authority_identity,
        .identity = undefined,
    };
    result.identity = memberIdentity(result);
    return result;
}

fn combinedAllocationIdentity(members: *const [max_members]?Member) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-candidate-combined-allocation.v1\x00");
    for (members) |maybe_member| {
        if (maybe_member) |member| {
            hash.update(&.{1});
            hash.update(&member.identity);
        } else hash.update(&.{0});
    }
    return hash.finalResult();
}

fn memberIdentity(value: Member) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-candidate-registry-member.v1\x00");
    putInt(&hash, u16, @intFromEnum(value.kind));
    putInt(&hash, u8, value.major_opcode);
    putInt(&hash, u8, value.funct7);
    putInt(&hash, u32, value.proof_opcode_id);
    putInt(&hash, u32, value.fixed_word);
    for (value.argument_registers) |register| putInt(&hash, u8, register);
    hash.update(&value.semantic_authority_identity);
    return hash.finalResult();
}

fn registryIdentity(value: Registry) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-candidate-private-registry.v1\x00");
    putInt(&hash, u16, value.schema);
    putInt(&hash, u16, value.member_count);
    hash.update(&value.allocation_registry_identity);
    hash.update(&value.stack_swap_fixture_registry_identity);
    hash.update(&value.bulk_memcpy_fixture_registry_identity);
    for (value.members) |maybe_member| {
        if (maybe_member) |member| {
            hash.update(&.{1});
            hash.update(&member.identity);
        } else {
            hash.update(&.{0});
        }
    }
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
    if (production_active or schema_version != 1 or max_members < 2 or
        canonical_member_count != 2 or bulk.production_active or
        swap.production_active or bulk_registry.production_active or
        legacy_registry.production_active or
        bulk.funct7 != 4 or legacy_registry.allocated_funct7 != 5 or
        bulk.proof_opcode_id != 48 or
        legacy_registry.allocated_proof_opcode_id != 49)
    {
        @compileError("Ethereum candidate registry authority drifted");
    }
}

test "combined candidate contract v1: registry fixes ordered bulk and SWAP members" {
    const registry = try Registry.canonical();
    try registry.validate();
    try std.testing.expectEqual(
        MemberKind.bulk_memcpy_v1,
        (try registry.member(.bulk_memcpy_v1)).kind,
    );
    try std.testing.expectEqual(
        MemberKind.stack_swap_v1,
        (try registry.member(.stack_swap_v1)).kind,
    );

    var changed_member = registry;
    changed_member.members[0].?.funct7 = 6;
    try std.testing.expectError(
        error.InvalidEthereumCandidateRegistryMember,
        changed_member.validate(),
    );
    var changed_allocation = registry;
    changed_allocation.allocation_registry_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidEthereumCandidateRegistryIdentity,
        changed_allocation.validate(),
    );
}
