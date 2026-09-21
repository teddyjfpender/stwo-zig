//! Ordered adapter handoff to proving and independent verification.
const std = @import("std");
const core = @import("stwo_core");
const digest = @import("../../air/lang/digest.zig");
const core_components = core.air.components;
const prover_component = @import("stwo_prover_engine").air.component_prover;

pub fn Types(comptime contract: type) type {
    return TypesWithClaims(contract, @import("manifest_claim_protocol.zig").Types(contract).ClaimVector);
}

/// The default manifest shares its claim type with its metadata-only contract.
pub fn TypesWithClaims(comptime contract: type, comptime Claims: type) type {
    return struct {
        const Manifest = contract.Manifest;
        const AdapterBinding = contract.AdapterBinding;
        const Error = contract.Error;
        pub const ClaimVector = Claims;
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
    };
}
