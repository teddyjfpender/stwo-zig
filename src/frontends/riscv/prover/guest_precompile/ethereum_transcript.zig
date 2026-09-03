//! Single-source Fiat-Shamir order for the combined Ethereum proof.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const transcript = @import("../../air/transcript/mod.zig");
const base_relations = @import("../../air/relation_challenges.zig");
const keccak_relations = @import("../../air/guest_precompile/keccakf_relations.zig");
const secp_relations = @import("../../air/guest_precompile/secp256k1_relations.zig");
const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const base_statement = @import("../../air/statement.zig");
const statement_mod = @import("../../air/guest_precompile/ethereum_statement.zig");
const types = @import("ethereum_types.zig");

pub const Relations = struct {
    base: base_relations.Relations,
    keccak: keccak_relations.Relations,
    secp: secp_relations.Relations,

    pub fn draw(allocator: std.mem.Allocator, channel: anytype) !Relations {
        const base = try base_relations.Relations.draw(allocator, channel);
        const values = try channel.drawSecureFelts(allocator, 26);
        defer allocator.free(values);
        if (values.len != 26) return error.InvalidChallengeDraw;
        return .{
            .base = base,
            .keccak = .{
                .base = base,
                .io = .init(values[0], values[1]),
                .chi = .init(values[2], values[3]),
                .xor5 = .init(values[4], values[5]),
            },
            .secp = .{
                .base = base,
                .product = .init(values[6], values[7]),
                .linear = .init(values[8], values[9]),
                .point = .init(values[10], values[11]),
                .split = .init(values[12], values[13]),
                .table = .init(values[14], values[15]),
                .program = .init(values[16], values[17]),
                .table_root = .init(values[18], values[19]),
                .ecdsa = .init(values[20], values[21]),
                .byte = .init(values[22], values[23]),
                .recovery = .init(values[24], values[25]),
            },
        };
    }
};

pub const Prefix = struct {
    interaction_pow: u64,
    relations: Relations,
};

pub fn proveToRelations(
    allocator: std.mem.Allocator,
    channel: anytype,
    core: *const base_statement.RiscVStatement,
) !Prefix {
    mixMainClaim(channel, core);
    const nonce = channel.grind(transcript.INTERACTION_POW_BITS);
    channel.mixU64(nonce);
    return .{
        .interaction_pow = nonce,
        .relations = try Relations.draw(allocator, channel),
    };
}

/// Additive joined-Ethereum Stage-A prefix. The extension is mixed after the
/// frozen base main claim/shard manifest and before the single interaction
/// PoW and complete base+Keccak+secp challenge draw.
pub fn proveToRelationsWithExtension(
    allocator: std.mem.Allocator,
    channel: anytype,
    core: *const base_statement.RiscVStatement,
    extension: anytype,
) !Prefix {
    mixMainClaim(channel, core);
    extension.mixInto(channel);
    const nonce = channel.grind(transcript.INTERACTION_POW_BITS);
    channel.mixU64(nonce);
    return .{
        .interaction_pow = nonce,
        .relations = try Relations.draw(allocator, channel),
    };
}

pub fn verifyToRelations(
    allocator: std.mem.Allocator,
    channel: anytype,
    core: *const base_statement.RiscVStatement,
    nonce: u64,
) !Relations {
    mixMainClaim(channel, core);
    if (!channel.verifyPowNonce(transcript.INTERACTION_POW_BITS, nonce))
        return transcript.PrefixError.InvalidInteractionProofOfWork;
    channel.mixU64(nonce);
    return Relations.draw(allocator, channel);
}

pub fn verifyToRelationsWithExtension(
    allocator: std.mem.Allocator,
    channel: anytype,
    core: *const base_statement.RiscVStatement,
    nonce: u64,
    extension: anytype,
) !Relations {
    mixMainClaim(channel, core);
    extension.mixInto(channel);
    if (!channel.verifyPowNonce(transcript.INTERACTION_POW_BITS, nonce))
        return transcript.PrefixError.InvalidInteractionProofOfWork;
    channel.mixU64(nonce);
    return Relations.draw(allocator, channel);
}

pub fn mixInteractionClaim(
    channel: anytype,
    core: *const base_statement.RiscVStatement,
    base: *const base_statement.RiscVInteractionClaim,
    extension: *const types.ExtensionClaim,
) !void {
    if (base.n_components != core.n_components or base.n_infra != core.n_infra)
        return error.InvalidInteractionClaim;
    channel.mixU32s(&.{ 0x4757_5453, 0x3149_5445, core.n_components, core.n_infra });
    for (core.component_descs[0..core.n_components], 0..) |descriptor, index| {
        channel.mixFelts(try base.opcodeClaims(descriptor.family, index));
    }
    for (core.infra_descs[0..core.n_infra], 0..) |descriptor, index| {
        channel.mixFelts(try base.infraClaims(descriptor.kind, index));
    }
    extension.mixInto(channel);
}

/// Append-only interaction-claim frame for authenticated SegmentV2 leaves.
/// The selected physical lookup projection owns the base claim; the Ethereum
/// extension remains the same fourteen-component detailed claim.
pub fn mixInteractionClaimV2(
    channel: anytype,
    core: *const base_statement.RiscVStatement,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    base: *const base_statement.RiscVInteractionClaim,
    extension: *const types.ExtensionClaim,
) !void {
    channel.mixU32s(&.{
        0x4757_5453, // "STWG"
        0x3249_5445, // "ETI2"
        lookup_physical_v2.FORMAT_VERSION,
        statement_mod.component_count,
    });
    try authenticated.mixInteractionClaim(channel, core, manifest, base);
    extension.mixInto(channel);
}

pub fn total(
    base: anytype,
    extension: *const types.ExtensionClaim,
) QM31 {
    return base.total().add(extension.componentSum());
}

fn mixMainClaim(channel: anytype, core: *const base_statement.RiscVStatement) void {
    const main_claim = core.canonicalMainClaim();
    main_claim.mixInto(channel);
    core.mixShardManifest(channel);
}
