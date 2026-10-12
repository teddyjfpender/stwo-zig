//! Exact 49-component proof-gate assembly for the V3 leaf wrapper.
//!
//! This gate only owns component order, geometry and committed claims. It
//! cannot emit a proof or publication: the verifier-owned source cohort,
//! shared Poseidon/range providers and all-domain closure must be attached
//! before an engine may use it. A partial 39/42/46/47-row gate never seals.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const manifest_mod = @import("segment_leaf_wrapper_roster_v3.zig");

const QM31 = core.fields.qm31.QM31;
const COMPONENT_COUNT = manifest_mod.COMPONENT_COUNT;
pub const CLAIM_DOMAIN = "stwo-zig/riscv-v3-leaf-wrapper-claims/v1\x00";
pub const ALL_COMPONENT_MASK: u64 = (@as(u64, 1) << COMPONENT_COUNT) - 1;
pub const PRODUCTION_PROOF_ACTIVATION = false;

pub const ClaimVector = struct {
    manifest_seal: [32]u8,
    bound_mask: u64 = 0,
    values: [COMPONENT_COUNT]QM31 = [_]QM31{QM31.zero()} ** COMPONENT_COUNT,
    seal: [32]u8 = .{0} ** 32,

    pub fn init(manifest: *const manifest_mod.Plan) !ClaimVector {
        try manifest.validate();
        return .{ .manifest_seal = manifest.seal };
    }

    pub fn bind(self: *ClaimVector, row: u8, value: QM31) !void {
        if (row >= COMPONENT_COUNT) return error.InvalidV3WrapperRow;
        const bit = @as(u64, 1) << @intCast(row);
        if ((self.bound_mask & bit) != 0) return error.DuplicateV3WrapperClaim;
        for (value.toM31Array()) |limb| if (limb.toU32() >= core.fields.m31.Modulus)
            return error.NonCanonicalV3WrapperClaim;
        self.values[row] = value;
        self.bound_mask |= bit;
    }

    pub fn sealClaims(self: *ClaimVector, manifest: *const manifest_mod.Plan) !void {
        try self.checkGeometry(manifest);
        if (self.bound_mask != ALL_COMPONENT_MASK) return error.IncompleteV3WrapperGate;
        self.seal = claimSeal(self, manifest);
    }

    pub fn validate(self: *const ClaimVector, manifest: *const manifest_mod.Plan) !void {
        try self.checkGeometry(manifest);
        if (self.bound_mask != ALL_COMPONENT_MASK or
            !std.mem.eql(u8, &self.seal, &claimSeal(self, manifest)))
            return error.InvalidV3WrapperClaims;
    }

    pub fn mixInteractionClaims(self: *const ClaimVector, manifest: *const manifest_mod.Plan, channel: anytype) !void {
        try self.validate(manifest);
        channel.mixU32s(&.{COMPONENT_COUNT});
        for (manifest.placements, 0..) |maybe_placement, index| {
            const placement = maybe_placement orelse return error.InvalidV3WrapperRoster;
            channel.mixU32s(&.{
                @as(u32, @intCast(index)),
                placement.geometry.log_size,
                placement.geometry.interaction_columns,
            });
            channel.mixFelts(&.{self.values[index]});
        }
        channel.mixU32s(&digestWords(self.seal));
    }

    fn checkGeometry(self: *const ClaimVector, manifest: *const manifest_mod.Plan) !void {
        try manifest.validate();
        if (!std.mem.eql(u8, &self.manifest_seal, &manifest.seal) or
            (self.bound_mask & ~ALL_COMPONENT_MASK) != 0)
            return error.InvalidV3WrapperClaims;
    }
};

pub const ProofGate = struct {
    manifest_seal: [32]u8,
    roster_rows: [COMPONENT_COUNT]u8 = .{0} ** COMPONENT_COUNT,
    verifier_components: [COMPONENT_COUNT]core.air.components.Component = undefined,
    prover_components: [COMPONENT_COUNT]prover.air.component_prover.ComponentProver = undefined,
    claims: ClaimVector,
    count: u8 = 0,
    sealed: bool = false,

    pub fn init(manifest: *const manifest_mod.Plan) !ProofGate {
        return .{
            .manifest_seal = manifest.seal,
            .claims = try ClaimVector.init(manifest),
        };
    }

    pub fn append(self: *ProofGate, manifest: *const manifest_mod.Plan, binding: manifest_mod.AdapterBinding) !void {
        if (self.sealed or self.count >= COMPONENT_COUNT)
            return error.IncompleteV3WrapperGate;
        try manifest.validate();
        if (!std.mem.eql(u8, &self.manifest_seal, &manifest.seal) or
            !std.mem.eql(u8, &binding.manifest_seal, &manifest.seal))
            return error.InvalidV3WrapperRoster;
        const row = self.count;
        const expected = manifest.placements[row] orelse return error.InvalidV3WrapperRoster;
        if (binding.placement.geometry.roster_row != row or
            !binding.placement.eql(expected) or
            binding.verifier.nConstraints() !=
                @as(usize, expected.geometry.direct_constraints) + expected.geometry.interaction_batches or
            binding.prover.nConstraints() != binding.verifier.nConstraints())
            return error.InvalidV3WrapperComponent;
        try self.claims.bind(row, binding.claimed_sum);
        self.roster_rows[row] = row;
        self.verifier_components[row] = binding.verifier;
        self.prover_components[row] = binding.prover;
        self.count += 1;
    }

    pub fn sealGate(self: *ProofGate, manifest: *const manifest_mod.Plan) !void {
        if (self.count != COMPONENT_COUNT) return error.IncompleteV3WrapperGate;
        try manifest.validate();
        if (!std.mem.eql(u8, &self.manifest_seal, &manifest.seal))
            return error.InvalidV3WrapperRoster;
        for (self.roster_rows, 0..) |row, index|
            if (row != index) return error.InvalidV3WrapperRoster;
        try self.claims.sealClaims(manifest);
        self.sealed = true;
    }

    pub fn validate(self: *const ProofGate, manifest: *const manifest_mod.Plan) !void {
        if (!self.sealed or self.count != COMPONENT_COUNT)
            return error.IncompleteV3WrapperGate;
        try self.claims.validate(manifest);
        if (!std.mem.eql(u8, &self.manifest_seal, &manifest.seal))
            return error.InvalidV3WrapperRoster;
        for (self.roster_rows, 0..) |row, index|
            if (row != index) return error.InvalidV3WrapperRoster;
    }

    pub fn verifierSlice(self: *const ProofGate, manifest: *const manifest_mod.Plan) ![]const core.air.components.Component {
        try self.validate(manifest);
        return &self.verifier_components;
    }

    pub fn proverSlice(self: *const ProofGate, manifest: *const manifest_mod.Plan) ![]const prover.air.component_prover.ComponentProver {
        try self.validate(manifest);
        return &self.prover_components;
    }
};

fn claimSeal(claims: *const ClaimVector, manifest: *const manifest_mod.Plan) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CLAIM_DOMAIN);
    hash.update(&manifest.seal);
    hashInt(&hash, u64, claims.bound_mask);
    for (claims.values, 0..) |value, index| {
        hashInt(&hash, u8, @intCast(index));
        for (value.toM31Array()) |limb| hashInt(&hash, u32, limb.toU32());
    }
    return hash.finalResult();
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn digestWords(value: [32]u8) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = std.mem.readInt(u32, value[index * 4 ..][0..4], .little);
    return result;
}
