//! Explicit private namespace allocation for the nonproduction U256 SWAP.
//!
//! This registry is deliberately disjoint from the production execution-
//! profile enum.  It records every currently occupied CUSTOM-0 `funct7` and
//! program-relation opcode boundary before assigning the candidate pair.  A
//! consumer receives the existing semantic `Authority`; it never chooses an
//! opcode from the next apparent integer at the call site.

const std = @import("std");

const bulk = @import("bulk_memcpy_candidate_v1.zig");
const custom0 = @import("custom0.zig");
const swap = @import("stack_swap_candidate_v1.zig");

pub const production_active = false;
pub const registry_schema_version: u16 = 1;
pub const allocated_funct7: u7 = 5;
pub const allocated_proof_opcode_id: u32 = 49;

const Entry = struct {
    scope: u16,
    semantic_name: []const u8,
    funct7: u7,
    proof_opcode_id: u32,
};

/// Registry scopes distinguish intentionally separate program profiles.  The
/// Poseidon-only and Keccak-only profiles both use program opcode 46, but they
/// can never coexist in one admitted program.  The candidate scope is private
/// and has no production admission-note value.
const entries = [_]Entry{
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
        .scope = 0xff00,
        .semantic_name = "stwo.riscv.bulk-memcpy.candidate-v1",
        .funct7 = bulk.funct7,
        .proof_opcode_id = bulk.proof_opcode_id,
    },
    .{
        .scope = 0xff01,
        .semantic_name = "stwo.riscv.u256-swap.v1",
        .funct7 = allocated_funct7,
        .proof_opcode_id = allocated_proof_opcode_id,
    },
};

pub fn canonicalRegistryIdentity() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.private-custom0-registry.v1\x00");
    hash.update(&u16Bytes(registry_schema_version));
    hash.update(&u16Bytes(entries.len));
    for (entries) |entry| {
        hash.update(&u16Bytes(entry.scope));
        hash.update(&u16Bytes(entry.semantic_name.len));
        hash.update(entry.semantic_name);
        hash.update(&.{entry.funct7});
        hash.update(&u32Bytes(entry.proof_opcode_id));
    }
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

pub fn allocation() swap.Allocation {
    return .{
        .funct7 = allocated_funct7,
        .proof_opcode_id = allocated_proof_opcode_id,
        .registry_identity = canonicalRegistryIdentity(),
    };
}

pub fn authority() !swap.Authority {
    try validateRegistry();
    return swap.Authority.create(allocation());
}

pub fn validateAuthority(actual: swap.Authority) !void {
    const expected = try authority();
    try actual.validate();
    if (!std.meta.eql(actual, expected))
        return error.StackSwapPrivateRegistryAuthorityMismatch;
}

pub fn validateRegistry() !void {
    if (swap.registry_request.requested_funct7 != null or
        swap.registry_request.requested_proof_opcode_id != null or
        swap.registry_request.major_opcode != custom0.major_opcode or
        allocated_funct7 == custom0.poseidon2_funct7 or
        allocated_funct7 == custom0.keccakf_funct7 or
        allocated_funct7 == custom0.secp256k1_recover_funct7 or
        allocated_funct7 == bulk.funct7 or
        allocated_proof_opcode_id == 46 or
        allocated_proof_opcode_id == 47 or
        allocated_proof_opcode_id == bulk.proof_opcode_id)
    {
        return error.StackSwapPrivateRegistryCollision;
    }
    for (entries, 0..) |left, left_index| {
        for (entries[left_index + 1 ..]) |right| {
            if (left.funct7 == right.funct7)
                return error.StackSwapPrivateRegistryCollision;
            if (left.scope == right.scope and
                left.proof_opcode_id == right.proof_opcode_id)
            {
                return error.StackSwapPrivateRegistryCollision;
            }
        }
    }
    try allocation().validate();
}

fn u16Bytes(value: anytype) [2]u8 {
    const normalized: u16 = @intCast(value);
    var result: [2]u8 = undefined;
    std.mem.writeInt(u16, &result, normalized, .little);
    return result;
}

fn u32Bytes(value: u32) [4]u8 {
    var result: [4]u8 = undefined;
    std.mem.writeInt(u32, &result, value, .little);
    return result;
}

comptime {
    if (production_active or allocated_funct7 != 5 or
        allocated_proof_opcode_id != 49 or entries.len != 5)
    {
        @compileError("stack-swap private registry geometry drifted");
    }
}
