//! Registry-shaped ABI request for a non-production U256 stack swap.
//!
//! No CUSTOM-0 `funct7` or proof opcode is allocated here. A registry owner
//! must supply an authenticated `Allocation`; every consumer retains and cold
//! validates that allocation before deriving an instruction or AIR identity.

const std = @import("std");

pub const production_active = false;
pub const abi_version: u16 = 1;
pub const major_opcode: u7 = 0x0b;
pub const destination_register: u5 = 0; // x0: the instruction has no result.
pub const lhs_pointer_register: u5 = 10; // a0
pub const rhs_pointer_register: u5 = 11; // a1
pub const funct3: u3 = 0;
pub const u256_bytes: u32 = 32;
pub const word_bytes: u32 = 4;
pub const words_per_value: u32 = u256_bytes / word_bytes;
pub const data_address_limit: u32 = @as(u32, 1) << 30;

pub const revm_git_revision = "45f05bd88fd09e32ea43cf5e94190759ea6ace7c";
pub const revm_version = "42.0.1";
pub const revm_interpreter_version = "42.0.0";
pub const alloy_evm_version = "0.38.0";
pub const alloy_evm_git_revision = "065a125cde3a5c69990323aecab97ce4ed048237";
pub const reth_git_revision = "3d270d933daeeb90c5735d81ff7f80c00322d6de";
pub const guest_factory_hook =
    "EthEvmConfig::new_with_evm_factory/StwoStackSwapEvmFactory.v1";

pub const RegistryRequest = struct {
    semantic_name: []const u8,
    abi_version: u16,
    major_opcode: u7,
    destination_register: u5,
    lhs_pointer_register: u5,
    rhs_pointer_register: u5,
    requested_funct7: ?u7,
    requested_proof_opcode_id: ?u32,
};

/// This is a request, not an allocation. Both optionals deliberately remain
/// null so a candidate cannot silently claim a shared opcode namespace.
pub const registry_request = RegistryRequest{
    .semantic_name = "stwo.riscv.u256-swap.v1",
    .abi_version = abi_version,
    .major_opcode = major_opcode,
    .destination_register = destination_register,
    .lhs_pointer_register = lhs_pointer_register,
    .rhs_pointer_register = rhs_pointer_register,
    .requested_funct7 = null,
    .requested_proof_opcode_id = null,
};

pub const Allocation = struct {
    funct7: u7,
    proof_opcode_id: u32,
    registry_identity: [32]u8,

    pub fn validate(self: Allocation) !void {
        if (self.funct7 == 0 or
            self.proof_opcode_id == 0 or
            isZeroSha(self.registry_identity))
        {
            return error.InvalidStackSwapRegistryAllocation;
        }
    }

    pub fn fixedWord(self: Allocation) !u32 {
        try self.validate();
        return (@as(u32, self.funct7) << 25) |
            (@as(u32, rhs_pointer_register) << 20) |
            (@as(u32, lhs_pointer_register) << 15) |
            (@as(u32, funct3) << 12) |
            (@as(u32, destination_register) << 7) |
            @as(u32, major_opcode);
    }
};

pub const Authority = struct {
    allocation: Allocation,
    fixed_word: u32,
    semantic_identity: [32]u8,

    pub fn create(allocation: Allocation) !Authority {
        const fixed_word = try allocation.fixedWord();
        return .{
            .allocation = allocation,
            .fixed_word = fixed_word,
            .semantic_identity = semanticIdentity(allocation, fixed_word),
        };
    }

    pub fn validate(self: Authority) !void {
        try self.allocation.validate();
        const fixed_word = try self.allocation.fixedWord();
        if (self.fixed_word != fixed_word or
            !std.mem.eql(
                u8,
                &self.semantic_identity,
                &semanticIdentity(self.allocation, fixed_word),
            ))
        {
            return error.InvalidStackSwapProgramAuthority;
        }
    }

    pub fn decode(self: Authority, word: u32) !Decoded {
        try self.validate();
        if (word != self.fixed_word) return error.InvalidStackSwapEncoding;
        return .{
            .destination_register = destination_register,
            .lhs_pointer_register = lhs_pointer_register,
            .rhs_pointer_register = rhs_pointer_register,
        };
    }

    pub fn programTuple(self: Authority, pc: u32) ![5]u32 {
        try self.validate();
        return .{
            pc,
            self.allocation.proof_opcode_id,
            destination_register,
            lhs_pointer_register,
            rhs_pointer_register,
        };
    }
};

pub const Decoded = struct {
    destination_register: u5,
    lhs_pointer_register: u5,
    rhs_pointer_register: u5,
};

pub const DiagnosticScope = struct {
    calls: u64,
    retired_rv32_rows: u64,
    rows_per_call: u32,
    candidate_elf_sha256: [32]u8,
    membership_identity_sha256: [32]u8,
};

pub const RetainedSoftwareFamilyRows = struct {
    load_store: u16,
    base_alu_imm: u16,
    base_alu_reg: u16,
    branch_lt: u16,
    jalr: u16,
    shifts_imm: u16,

    pub fn total(self: RetainedSoftwareFamilyRows) u32 {
        return @as(u32, self.load_store) + self.base_alu_imm +
            self.base_alu_reg + self.branch_lt + self.jalr + self.shifts_imm;
    }
};

/// Retained V8 observation only. It is not candidate geometry or a savings
/// claim, and its ELF identity differs from every future candidate executable.
pub const retained_scope = DiagnosticScope{
    .calls = 43_456,
    .retired_rv32_rows = 5_953_472,
    .rows_per_call = 137,
    .candidate_elf_sha256 = .{
        0x69, 0x97, 0x0f, 0xcb, 0x4c, 0x45, 0x4d, 0x76,
        0x43, 0x50, 0xe3, 0x22, 0x7d, 0xe9, 0x7f, 0x3d,
        0xfa, 0x65, 0xdc, 0x5f, 0x1c, 0x97, 0x40, 0x03,
        0x26, 0x52, 0xf2, 0x68, 0x22, 0xcd, 0xa7, 0x50,
    },
    .membership_identity_sha256 = .{
        0x11, 0x8b, 0x12, 0x09, 0xf5, 0x5b, 0x52, 0x90,
        0x29, 0x8c, 0x9a, 0x0e, 0x2c, 0xa3, 0xeb, 0xcf,
        0x5f, 0x04, 0x02, 0x6e, 0xf1, 0x70, 0x6b, 0x3b,
        0xd8, 0x51, 0x2c, 0x8f, 0xf1, 0x6a, 0xc2, 0xb7,
    },
};

/// Exact PC+nm membership for the retained V8 candidate ELF's 137-row SWAP
/// template. This is diagnostic evidence under `retained_scope` identities,
/// not a future guest or proof-profile claim.
pub const retained_software_family_rows = RetainedSoftwareFamilyRows{
    .load_store = 130,
    .base_alu_imm = 3,
    .base_alu_reg = 1,
    .branch_lt = 1,
    .jalr = 1,
    .shifts_imm = 1,
};

fn semanticIdentity(allocation: Allocation, fixed_word: u32) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.u256-swap-program-authority.v1\x00");
    hash.update(revm_git_revision);
    hash.update(alloy_evm_git_revision);
    hash.update(reth_git_revision);
    hash.update(guest_factory_hook);
    hash.update(&allocation.registry_identity);
    hash.update(&u16Bytes(abi_version));
    hash.update(&u32Bytes(fixed_word));
    hash.update(&u32Bytes(allocation.proof_opcode_id));
    hash.update(&.{
        major_opcode,
        allocation.funct7,
        destination_register,
        lhs_pointer_register,
        rhs_pointer_register,
    });
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn u16Bytes(value: u16) [2]u8 {
    var result: [2]u8 = undefined;
    std.mem.writeInt(u16, &result, value, .little);
    return result;
}

fn u32Bytes(value: u32) [4]u8 {
    var result: [4]u8 = undefined;
    std.mem.writeInt(u32, &result, value, .little);
    return result;
}

fn isZeroSha(value: [32]u8) bool {
    return std.mem.allEqual(u8, &value, 0);
}

comptime {
    if (production_active or
        registry_request.requested_funct7 != null or
        registry_request.requested_proof_opcode_id != null or
        words_per_value != 8)
    {
        @compileError("stack-swap candidate authority drifted");
    }
}
