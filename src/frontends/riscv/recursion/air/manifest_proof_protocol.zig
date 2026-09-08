//! Ordered claim absorption and adapter handoff shared by versioned manifests.
//! Component admission stays with each contract. This code does not choose AIRs,
//! geometry, transcript domains, or proof-dependent circuit structure.
const std = @import("std");
const core = @import("stwo_core");
const digest = @import("../../air/lang/digest.zig");
const core_components = core.air.components;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const QM31 = core.fields.qm31.QM31;

pub fn Types(comptime contract: type) type {
    return struct {
        const Manifest = contract.Manifest;
        const ComponentKey = contract.ComponentKey;
        const keyIndex = contract.keyIndex;
        const AdapterBinding = contract.AdapterBinding;
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

        pub const ProofGate = struct {
            manifest_seal: digest.Digest,
            roster_rows: [contract.COMPONENT_COUNT]u8,
            verifier_components: [contract.COMPONENT_COUNT]core_components.Component,
            prover_components: [contract.COMPONENT_COUNT]prover_component.ComponentProver,
            claims: ClaimVector,
            count: u8,
            sealed: bool,

            pub fn init(manifest: *const Manifest) Error!ProofGate {
                try manifest.validate();
                return .{
                    .manifest_seal = manifest.seal,
                    .roster_rows = [_]u8{0} ** contract.COMPONENT_COUNT,
                    .verifier_components = undefined,
                    .prover_components = undefined,
                    .claims = try ClaimVector.init(manifest),
                    .count = 0,
                    .sealed = false,
                };
            }

            pub fn append(
                self: *ProofGate,
                manifest: *const Manifest,
                binding: AdapterBinding,
            ) Error!void {
                if (self.sealed) return error.AdapterCountMismatch;
                try manifest.validate();
                if (!std.mem.eql(u8, &self.manifest_seal, &manifest.seal) or
                    !std.mem.eql(u8, &binding.manifest_seal, &manifest.seal))
                {
                    return error.ManifestSealMismatch;
                }
                if (self.count >= manifest.roster_count)
                    return error.AdapterCountMismatch;
                const expected_row = manifest.roster_rows[self.count];
                if (binding.placement.geometry.roster_row != expected_row)
                    return error.AdapterOrderMismatch;
                const expected = manifest.placements[expected_row].?;
                if (!binding.placement.eql(expected) or
                    binding.verifier.nConstraints() !=
                        @as(usize, expected.geometry.direct_constraints) +
                            expected.geometry.interaction_batches or
                    binding.prover.nConstraints() != binding.verifier.nConstraints())
                {
                    return error.AdapterGeometryMismatch;
                }

                try self.claims.bind(@enumFromInt(expected_row), binding.claimed_sum);
                self.roster_rows[self.count] = expected_row;
                self.verifier_components[self.count] = binding.verifier;
                self.prover_components[self.count] = binding.prover;
                self.count += 1;
            }

            pub fn sealGate(self: *ProofGate, manifest: *const Manifest) Error!void {
                if (self.count != manifest.roster_count)
                    return error.AdapterCountMismatch;
                try self.claims.sealClaims(manifest);
                self.sealed = true;
            }

            pub fn validate(self: *const ProofGate, manifest: *const Manifest) Error!void {
                try manifest.validate();
                if (!self.sealed or self.count != manifest.roster_count or
                    !std.mem.eql(u8, &self.manifest_seal, &manifest.seal))
                {
                    return error.AdapterCountMismatch;
                }
                for (self.roster_rows[0..self.count], manifest.roster_rows[0..manifest.roster_count]) |
                    got,
                    expected,
                | if (got != expected) return error.AdapterOrderMismatch;
                try self.claims.validate(manifest);
            }

            pub fn verifierSlice(self: *const ProofGate) Error![]const core_components.Component {
                if (!self.sealed) return error.AdapterCountMismatch;
                return self.verifier_components[0..self.count];
            }

            pub fn proverSlice(self: *const ProofGate) Error![]const prover_component.ComponentProver {
                if (!self.sealed) return error.AdapterCountMismatch;
                return self.prover_components[0..self.count];
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
