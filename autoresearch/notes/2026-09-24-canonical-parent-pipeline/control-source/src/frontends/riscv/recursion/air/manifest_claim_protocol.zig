//! Ordered claim admission and transcript absorption shared by versioned manifests.
//! Component admission stays with each contract. This code does not choose AIRs,
//! geometry, transcript domains, or proof-dependent circuit structure.
const std = @import("std");
const core = @import("stwo_core");
const digest = @import("../../air/lang/digest.zig");
const QM31 = core.fields.qm31.QM31;

pub fn Types(comptime contract: type) type {
    return struct {
        const Manifest = contract.Manifest;
        const ComponentKey = contract.ComponentKey;
        const keyIndex = contract.keyIndex;
        const Error = contract.Error;
        pub const ClaimVector = struct {
            manifest_seal: digest.Digest,
            admitted_mask: u64,
            bound_mask: u64,
            values: [contract.COMPONENT_COUNT]QM31,
            seal: digest.Digest,

            pub fn init(manifest: *const Manifest) Error!ClaimVector {
                try manifest.validate();
                var mask: u64 = 0;
                for (manifest.roster_rows[0..manifest.roster_count]) |row|
                    mask |= rosterBit(row);
                return .{
                    .manifest_seal = manifest.seal,
                    .admitted_mask = mask,
                    .bound_mask = 0,
                    .values = [_]QM31{QM31.zero()} ** contract.COMPONENT_COUNT,
                    .seal = [_]u8{0} ** 32,
                };
            }

            pub fn bind(
                self: *ClaimVector,
                row: ComponentKey,
                value: QM31,
            ) Error!void {
                const index = keyIndex(row);
                const bit = rosterBit(index);
                if ((self.admitted_mask & bit) == 0) return error.ClaimNotAdmitted;
                if ((self.bound_mask & bit) != 0) return error.ClaimAlreadyBound;
                self.values[index] = value;
                self.bound_mask |= bit;
            }

            pub fn sealClaims(self: *ClaimVector, manifest: *const Manifest) Error!void {
                try validateClaimGeometry(self, manifest);
                if (self.bound_mask != self.admitted_mask) return error.ClaimMissing;
                self.seal = claimDigest(self, manifest);
            }

            pub fn validate(self: *const ClaimVector, manifest: *const Manifest) Error!void {
                try validateClaimGeometry(self, manifest);
                if (self.bound_mask != self.admitted_mask) return error.ClaimMissing;
                if (!std.mem.eql(u8, &self.seal, &claimDigest(self, manifest)))
                    return error.ClaimSealMismatch;
            }

            /// Claimed sums are absorbed in canonical roster order, before the
            /// interaction commitment, exactly where the generic outer prover expects
            /// the component claim vector.
            pub fn mixInteractionClaims(
                self: *const ClaimVector,
                manifest: *const Manifest,
                channel: anytype,
            ) Error!void {
                try self.mixInteractionClaimValues(manifest, channel);
                channel.mixU32s(&digestWords(self.seal));
            }

            /// Validated roster metadata and all claim values, without the transport
            /// seal. The caller's versioned protocol must select this transcript form.
            pub fn mixInteractionClaimValues(
                self: *const ClaimVector,
                manifest: *const Manifest,
                channel: anytype,
            ) Error!void {
                try self.validate(manifest);
                channel.mixU32s(&.{manifest.roster_count});
                for (manifest.roster_rows[0..manifest.roster_count]) |row| {
                    const placement_value = manifest.placements[row].?;
                    channel.mixU32s(&.{
                        row,
                        placement_value.geometry.log_size,
                        placement_value.geometry.interaction_columns,
                    });
                    channel.mixFelts(&.{self.values[row]});
                }
            }
        };

        fn claimDigest(claims: *const ClaimVector, manifest: *const Manifest) digest.Digest {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(contract.CLAIM_DOMAIN);
            hash.update(&manifest.seal);
            hashInt(&hash, u64, claims.admitted_mask);
            hashInt(&hash, u64, claims.bound_mask);
            for (manifest.roster_rows[0..manifest.roster_count]) |row| {
                hashInt(&hash, u8, row);
                for (claims.values[row].toM31Array()) |coordinate|
                    hashInt(&hash, u32, coordinate.toU32());
            }
            return hash.finalResult();
        }

        fn validateClaimGeometry(
            claims: *const ClaimVector,
            manifest: *const Manifest,
        ) Error!void {
            try manifest.validate();
            if (!std.mem.eql(u8, &claims.manifest_seal, &manifest.seal))
                return error.ManifestSealMismatch;
            var expected_mask: u64 = 0;
            for (manifest.roster_rows[0..manifest.roster_count]) |row|
                expected_mask |= rosterBit(row);
            if (claims.admitted_mask != expected_mask or
                (claims.bound_mask & ~expected_mask) != 0)
            {
                return error.ClaimSealMismatch;
            }
        }

        fn rosterBit(row: u8) u64 {
            std.debug.assert(row < 64);
            return @as(u64, 1) << @intCast(row);
        }

        fn digestWords(value: [32]u8) [8]u32 {
            var result: [8]u32 = undefined;
            for (&result, 0..) |*word, index| {
                word.* = std.mem.readInt(
                    u32,
                    value[index * @sizeOf(u32) ..][0..@sizeOf(u32)],
                    .little,
                );
            }
            return result;
        }

        fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
            var encoded: [@sizeOf(T)]u8 = undefined;
            std.mem.writeInt(T, &encoded, @intCast(value), .little);
            hash.update(&encoded);
        }
    };
}
