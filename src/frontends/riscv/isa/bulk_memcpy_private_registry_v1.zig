//! Explicit private namespace authority for the nonproduction bulk memcpy.
//!
//! This registry is intentionally separate from both the production profile
//! and the SWAP-named registry.  `memberDescriptor` is the stable additive
//! input a future combined private registry may consume; this module's own
//! `Authority` admits only the one-member bulk profile.

const std = @import("std");

const bulk = @import("bulk_memcpy_candidate_v1.zig");
const custom0 = @import("custom0.zig");

pub const production_active = false;
pub const registry_schema_version: u16 = 1;
pub const member_schema_version: u16 = 1;
pub const private_scope: u16 = 0xff00;
pub const semantic_name = "stwo.riscv.bulk-memcpy.candidate-v1";

pub const EntryV1 = struct {
    scope: u16,
    semantic_name: []const u8,
    funct7: u7,
    proof_opcode_id: u32,
};

pub const MemberDescriptorV1 = struct {
    schema: u16,
    scope: u16,
    abi_version: u16,
    major_opcode: u7,
    funct7: u7,
    proof_opcode_id: u32,
    fixed_word: u32,
    destination_register: u5,
    source_register: u5,
    length_register: u5,
    semantic_identity: [32]u8,

    pub fn validate(self: MemberDescriptorV1) !void {
        const expected = memberDescriptor();
        if (!std.meta.eql(self, expected))
            return error.InvalidBulkMemcpyPrivateMemberDescriptor;
    }
};

pub const Allocation = struct {
    funct7: u7,
    proof_opcode_id: u32,
    registry_identity: [32]u8,

    pub fn validate(self: Allocation) !void {
        if (self.funct7 != bulk.funct7 or
            self.proof_opcode_id != bulk.proof_opcode_id or
            !std.mem.eql(
                u8,
                &self.registry_identity,
                &canonicalRegistryIdentity(),
            ))
        {
            return error.InvalidBulkMemcpyPrivateRegistryAllocation;
        }
    }
};

pub const Authority = struct {
    allocation: Allocation,
    fixed_word: u32,
    semantic_identity: [32]u8,

    pub fn canonical() !Authority {
        try validateRegistry();
        const allocation_value = allocation();
        const result = Authority{
            .allocation = allocation_value,
            .fixed_word = bulk.fixed_word,
            .semantic_identity = authorityIdentity(allocation_value),
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: Authority) !void {
        try self.allocation.validate();
        if (self.fixed_word != bulk.fixed_word or
            !std.mem.eql(
                u8,
                &self.semantic_identity,
                &authorityIdentity(self.allocation),
            ))
        {
            return error.InvalidBulkMemcpyPrivateRegistryAuthority;
        }
    }

    pub fn decode(self: Authority, word: u32) !bulk.Decoded {
        try self.validate();
        return bulk.decode(word);
    }

    pub fn programTuple(self: Authority, pc: u32) ![5]u32 {
        try self.validate();
        return bulk.programTuple(pc);
    }
};

const occupied_entries = [_]EntryV1{
    .{
        .scope = 1,
        .semantic_name = "stwo.poseidon2-m31.permute-in-place@1",
        .funct7 = custom0.poseidon2_funct7,
        .proof_opcode_id = 46,
    },
    .{
        .scope = 2,
        .semantic_name = "stwo.keccakf-1600.permute-in-place@1",
        .funct7 = custom0.keccakf_funct7,
        .proof_opcode_id = 46,
    },
    .{
        .scope = 3,
        .semantic_name = "stwo.secp256k1.recover-signer@1",
        .funct7 = custom0.secp256k1_recover_funct7,
        .proof_opcode_id = 47,
    },
    .{
        .scope = private_scope,
        .semantic_name = semantic_name,
        .funct7 = bulk.funct7,
        .proof_opcode_id = bulk.proof_opcode_id,
    },
};

pub fn memberDescriptor() MemberDescriptorV1 {
    return .{
        .schema = member_schema_version,
        .scope = private_scope,
        .abi_version = 1,
        .major_opcode = bulk.major_opcode,
        .funct7 = bulk.funct7,
        .proof_opcode_id = bulk.proof_opcode_id,
        .fixed_word = bulk.fixed_word,
        .destination_register = bulk.destination_register,
        .source_register = bulk.source_register,
        .length_register = bulk.length_register,
        .semantic_identity = memberIdentity(),
    };
}

pub fn allocation() Allocation {
    return .{
        .funct7 = bulk.funct7,
        .proof_opcode_id = bulk.proof_opcode_id,
        .registry_identity = canonicalRegistryIdentity(),
    };
}

pub fn authority() !Authority {
    return Authority.canonical();
}

pub fn validateAuthority(actual: Authority) !void {
    const expected = try authority();
    try actual.validate();
    if (!std.meta.eql(actual, expected))
        return error.BulkMemcpyPrivateRegistryAuthorityMismatch;
}

pub fn validateRegistry() !void {
    if (bulk.production_active or
        bulk.major_opcode != custom0.major_opcode or
        bulk.funct7 == custom0.poseidon2_funct7 or
        bulk.funct7 == custom0.keccakf_funct7 or
        bulk.funct7 == custom0.secp256k1_recover_funct7 or
        bulk.proof_opcode_id == 46 or
        bulk.proof_opcode_id == 47)
    {
        return error.BulkMemcpyPrivateRegistryCollision;
    }
    for (occupied_entries, 0..) |left, left_index| {
        for (occupied_entries[left_index + 1 ..]) |right| {
            if (left.funct7 == right.funct7)
                return error.BulkMemcpyPrivateRegistryCollision;
            if (left.scope == right.scope and
                left.proof_opcode_id == right.proof_opcode_id)
            {
                return error.BulkMemcpyPrivateRegistryCollision;
            }
        }
    }
    try memberDescriptor().validate();
    try allocation().validate();
}

pub fn canonicalRegistryIdentity() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.bulk-memcpy-private-custom0-registry.v1\x00");
    hash.update(&u16Bytes(registry_schema_version));
    hash.update(&u16Bytes(occupied_entries.len));
    for (occupied_entries) |entry| {
        hash.update(&u16Bytes(entry.scope));
        hash.update(&u16Bytes(entry.semantic_name.len));
        hash.update(entry.semantic_name);
        hash.update(&.{entry.funct7});
        hash.update(&u32Bytes(entry.proof_opcode_id));
    }
    hash.update(&memberIdentity());
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn memberIdentity() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.bulk-memcpy-private-member.v1\x00");
    hash.update(semantic_name);
    hash.update(&u16Bytes(member_schema_version));
    hash.update(&u16Bytes(private_scope));
    hash.update(&.{ bulk.major_opcode, bulk.funct7 });
    hash.update(&u32Bytes(bulk.proof_opcode_id));
    hash.update(&u32Bytes(bulk.fixed_word));
    hash.update(&.{
        bulk.destination_register,
        bulk.source_register,
        bulk.length_register,
    });
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn authorityIdentity(allocation_value: Allocation) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.bulk-memcpy-private-authority.v1\x00");
    hash.update(&allocation_value.registry_identity);
    hash.update(&memberIdentity());
    hash.update(&u32Bytes(bulk.fixed_word));
    hash.update(&u32Bytes(allocation_value.proof_opcode_id));
    hash.update(&.{allocation_value.funct7});
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
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

comptime {
    if (production_active or registry_schema_version != 1 or
        member_schema_version != 1 or bulk.funct7 != 4 or
        bulk.proof_opcode_id != 48 or bulk.fixed_word != 0x08c5_850b or
        occupied_entries.len != 4)
    {
        @compileError("bulk-memcpy private registry geometry drifted");
    }
}

test "bulk memcpy private member and authority pin the exact allocation" {
    try validateRegistry();
    const member = memberDescriptor();
    try member.validate();
    try std.testing.expectEqual(@as(u7, 4), member.funct7);
    try std.testing.expectEqual(@as(u32, 48), member.proof_opcode_id);
    try std.testing.expectEqual(@as(u32, 0x08c5_850b), member.fixed_word);

    const canonical = try authority();
    try validateAuthority(canonical);
    try std.testing.expectEqualDeep(
        [_]u32{ 0x1000, 48, 10, 11, 12 },
        try canonical.programTuple(0x1000),
    );

    var changed = canonical;
    changed.allocation.proof_opcode_id += 1;
    try std.testing.expectError(
        error.InvalidBulkMemcpyPrivateRegistryAllocation,
        validateAuthority(changed),
    );
}
