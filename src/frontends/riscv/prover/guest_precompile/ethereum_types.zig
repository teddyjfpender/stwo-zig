//! Verifier-visible interaction claims for the combined Ethereum profile.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const keccak_component = @import("../../air/guest_precompile/keccakf_component.zig");
const secp_bundle = @import("../../air/guest_precompile/secp256k1_component_bundle.zig");
const secp_component = @import("../../air/guest_precompile/secp256k1_component.zig");
const secp_config = @import("../../air/guest_precompile/secp256k1_component_config.zig");
const statement_mod = @import("../../air/guest_precompile/ethereum_statement.zig");
const base_types = @import("../types.zig");

pub const ExtensionClaim = struct {
    keccak_shard: keccak_component.Claim,
    keccak_chi_table: QM31,
    keccak_xor5_table: QM31,
    product_base: secp_component.Claim(secp_bundle.ProductBase),
    product_scalar: secp_component.Claim(secp_bundle.ProductScalar),
    linear_base: secp_component.Claim(secp_bundle.LinearBase),
    linear_scalar: secp_component.Claim(secp_bundle.LinearScalar),
    point: secp_component.Claim(secp_config.Point),
    split: secp_component.Claim(secp_config.Split),
    scalar: secp_component.Claim(secp_config.ScalarProgram),
    table: secp_component.Claim(secp_config.Table),
    recovery: secp_component.Claim(secp_config.Recovery),
    byte: secp_component.Claim(secp_config.ByteTable),
    recovery_caller: secp_component.Claim(secp_config.RecoveryCaller),

    pub fn validate(
        self: *const ExtensionClaim,
        statement: *const statement_mod.Statement,
    ) !void {
        if (self.keccak_shard.first_call_index != 0 or
            self.keccak_shard.call_count != statement.counts.keccak_calls)
        {
            return error.InvalidClaim;
        }
        try self.keccak_shard.validate();
        try expectDescriptor(
            self.keccak_shard.log_size,
            self.keccak_shard.n_rows,
            statement.components[0],
        );
        if (statement.counts.keccak_calls == 0 and
            (!allZero(&self.keccak_shard.batch_sums) or
                !self.keccak_shard.component_sum.eql(QM31.zero()) or
                !self.keccak_chi_table.eql(QM31.zero()) or
                !self.keccak_xor5_table.eql(QM31.zero())))
        {
            return error.InvalidClaim;
        }
        inline for (.{
            .{ self.product_base, statement.components[3] },
            .{ self.product_scalar, statement.components[4] },
            .{ self.linear_base, statement.components[5] },
            .{ self.linear_scalar, statement.components[6] },
            .{ self.point, statement.components[7] },
            .{ self.split, statement.components[8] },
            .{ self.scalar, statement.components[9] },
            .{ self.table, statement.components[10] },
            .{ self.recovery, statement.components[11] },
            .{ self.byte, statement.components[12] },
            .{ self.recovery_caller, statement.components[13] },
        }) |entry| {
            try entry[0].validate();
            try expectDescriptor(
                entry[0].log_size,
                entry[0].n_rows,
                entry[1],
            );
            if (statement.counts.signer_calls == 0 and
                (!allZero(&entry[0].batch_sums) or
                    !entry[0].component_sum.eql(QM31.zero())))
            {
                return error.InvalidClaim;
            }
        }
    }

    pub fn componentSum(self: *const ExtensionClaim) QM31 {
        var result = self.keccak_shard.component_sum
            .add(self.keccak_chi_table)
            .add(self.keccak_xor5_table);
        inline for (.{
            self.product_base.component_sum,
            self.product_scalar.component_sum,
            self.linear_base.component_sum,
            self.linear_scalar.component_sum,
            self.point.component_sum,
            self.split.component_sum,
            self.scalar.component_sum,
            self.table.component_sum,
            self.recovery.component_sum,
            self.byte.component_sum,
            self.recovery_caller.component_sum,
        }) |sum| result = result.add(sum);
        return result;
    }

    /// Mixes every component-local batch claim rather than only aggregates.
    /// Component adapters consume the detailed values, so they are part of the
    /// Fiat-Shamir statement even when the same total could be decomposed in
    /// several ways.
    pub fn mixInto(self: *const ExtensionClaim, channel: anytype) void {
        channel.mixU32s(&.{ 0x4757_5453, 0x3143_5445, statement_mod.component_count });
        mixComponent(channel, &self.keccak_shard.batch_sums, self.keccak_shard.component_sum);
        channel.mixFelts(&.{self.keccak_chi_table});
        channel.mixFelts(&.{self.keccak_xor5_table});
        inline for (.{
            self.product_base,
            self.product_scalar,
            self.linear_base,
            self.linear_scalar,
            self.point,
            self.split,
            self.scalar,
            self.table,
            self.recovery,
            self.byte,
            self.recovery_caller,
        }) |claim| mixComponent(channel, &claim.batch_sums, claim.component_sum);
    }
};

pub fn ProveOutputForEngine(comptime Engine: type) type {
    return struct {
        statement: base_types.RiscVStatement,
        extension: statement_mod.Statement,
        proof: base_types.ProofForEngine(Engine),
        base_claim: *base_types.RiscVInteractionClaim,
        extension_claim: ExtensionClaim,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            allocator.destroy(self.base_claim);
            self.* = undefined;
        }

        pub fn deinitAfterProofMoved(self: Self, allocator: std.mem.Allocator) void {
            allocator.destroy(self.base_claim);
        }
    };
}

pub fn SegmentProveOutputForEngine(comptime Engine: type) type {
    return struct {
        statement: base_types.RiscVStatementV2,
        extension: statement_mod.Statement,
        proof: base_types.ProofForEngine(Engine),
        base_claim: *base_types.RiscVInteractionClaim,
        extension_claim: ExtensionClaim,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            allocator.destroy(self.base_claim);
            self.* = undefined;
        }

        pub fn deinitAfterProofMoved(self: Self, allocator: std.mem.Allocator) void {
            allocator.destroy(self.base_claim);
        }
    };
}

fn allZero(values: []const QM31) bool {
    for (values) |value| if (!value.eql(QM31.zero())) return false;
    return true;
}

fn expectDescriptor(
    log_size: u32,
    n_rows: u32,
    descriptor: statement_mod.Descriptor,
) !void {
    if (log_size != descriptor.log_size or n_rows != descriptor.n_rows)
        return error.InvalidClaim;
}

fn mixComponent(
    channel: anytype,
    detailed: []const QM31,
    total: QM31,
) void {
    channel.mixU32s(&.{@intCast(detailed.len)});
    channel.mixFelts(detailed);
    channel.mixFelts(&.{total});
}
