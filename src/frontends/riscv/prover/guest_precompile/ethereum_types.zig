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
        try self.keccak_shard.validateWithMaximumLogSize(@import("../../air/guest_precompile/keccakf_trace.zig").ethereum_maximum_log_size);
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

    /// Borrowed immutable claim data in the statement's canonical component
    /// order. Native transcript framing and recursive input routing share this
    /// mapping; scalar claims have one frame, batch claims have count, detailed,
    /// and aggregate frames. The incremental bridge is a separate component.
    pub fn componentClaims(self: *const ExtensionClaim) [statement_mod.component_count]ComponentClaimView {
        var result: [statement_mod.component_count]ComponentClaimView = undefined;
        for (statement_mod.componentKinds(), &result) |kind, *view| {
            view.* = switch (kind) {
                .keccak_shard_v1 => batchClaim(kind, &self.keccak_shard),
                .keccak_chi_table_v2 => scalarClaim(kind, &self.keccak_chi_table),
                .keccak_xor5_table_v2 => scalarClaim(kind, &self.keccak_xor5_table),
                .secp_product_base_v1 => batchClaim(kind, &self.product_base),
                .secp_product_scalar_v1 => batchClaim(kind, &self.product_scalar),
                .secp_linear_base_v1 => batchClaim(kind, &self.linear_base),
                .secp_linear_scalar_v1 => batchClaim(kind, &self.linear_scalar),
                .secp_point_v1 => batchClaim(kind, &self.point),
                .secp_split_v1 => batchClaim(kind, &self.split),
                .secp_scalar_program_v1 => batchClaim(kind, &self.scalar),
                .secp_signed_table_v1 => batchClaim(kind, &self.table),
                .secp_recovery_v1 => batchClaim(kind, &self.recovery),
                .secp_byte_table_v1 => batchClaim(kind, &self.byte),
                .secp_recovery_caller_v1 => batchClaim(kind, &self.recovery_caller),
            };
        }
        return result;
    }

    pub fn componentSum(self: *const ExtensionClaim) QM31 {
        var result = QM31.zero();
        for (self.componentClaims()) |claim| result = result.add(claim.total);
        return result;
    }

    /// Mixes every component-local batch claim rather than only aggregates.
    /// Component adapters consume the detailed values, so they are part of the
    /// Fiat-Shamir statement even when the same total could be decomposed in
    /// several ways. Preserve native call boundaries as well as payload words.
    pub fn mixInto(self: *const ExtensionClaim, channel: anytype) void {
        channel.mixU32s(&.{ 0x4757_5453, 0x3143_5445, statement_mod.component_count });
        for (self.componentClaims()) |claim| {
            if (claim.has_batch_frame)
                mixComponent(channel, claim.detailed, claim.total)
            else
                channel.mixFelts(claim.detailed);
        }
    }
};

/// Slices borrow an ExtensionClaim and must not outlive it. No proof values
/// enter fixed circuit admission through this view.
pub const ComponentClaimView = struct {
    kind: statement_mod.Kind,
    detailed: []const QM31,
    total: QM31,
    has_batch_frame: bool,
};

fn batchClaim(kind: statement_mod.Kind, claim: anytype) ComponentClaimView {
    return .{ .kind = kind, .detailed = &claim.batch_sums, .total = claim.component_sum, .has_batch_frame = true };
}

fn scalarClaim(kind: statement_mod.Kind, claim: *const QM31) ComponentClaimView {
    return .{ .kind = kind, .detailed = @as(*const [1]QM31, @ptrCast(claim))[0..], .total = claim.*, .has_batch_frame = false };
}

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
