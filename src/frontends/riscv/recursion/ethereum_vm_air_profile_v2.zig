//! Original four-tag product profile authority; no selector is recovered from layout.
const std = @import("std");
const native = @import("vm_air_profile_v2.zig");
const circuit = @import("../prover/ethereum_circuit_profile.zig");
pub const CIRCUIT_SCHEMA_VERSION: u16 = 2;
pub const CIRCUIT_PROFILE_DOMAIN = "stwo-zig/riscv/recursion/vm-air-profile/ethereum-circuit/v1\x00";
const ProductOwner = struct {
    pub const Selector = circuit.CircuitProfileV1;
    pub const DEFAULT_SELECTOR: Selector = .legacy_v4;
    pub fn schemaVersion(selected: Selector) u16 {
        return if (selected == .legacy_v4) native.SCHEMA_VERSION else CIRCUIT_SCHEMA_VERSION;
    }
    pub fn circuitLayout(selected: Selector) @import("../air/program/circuit_layout.zig").CircuitLayout {
        return selected.layout();
    }
    pub fn hashIdentityPrefix(hash: *std.crypto.hash.sha2.Sha256, selected: Selector) void {
        if (selected == .legacy_v4) {
            hash.update(native.PROFILE_DOMAIN);
        } else {
            hash.update(CIRCUIT_PROFILE_DOMAIN);
            var bytes: [2]u8 = undefined;
            std.mem.writeInt(u16, &bytes, @intFromEnum(selected), .little);
            hash.update(&bytes);
        }
    }
};
const Product = native.ForOwner(ProductOwner);
pub const FORMAT_VERSION = native.FORMAT_VERSION;
pub const SCHEMA_VERSION = native.SCHEMA_VERSION;
pub const PROFILE_DOMAIN = native.PROFILE_DOMAIN;
pub const Error = native.Error;
pub const AdapterRoleV2 = native.AdapterRoleV2;
pub const TreeSpanV2 = native.TreeSpanV2;
pub const OpcodeSemanticKeyV2 = native.OpcodeSemanticKeyV2;
pub const OpcodeLookupKeyV2 = native.OpcodeLookupKeyV2;
pub const InfrastructureKeyV2 = native.InfrastructureKeyV2;
pub const RegistryKeyV2 = native.RegistryKeyV2;
pub const EntryV2 = native.EntryV2;
pub const InputProfileV2 = native.InputProfileV2;
pub const Facts = native.Facts;
pub const ProfileV2 = Product.ProfileV2;
pub const derive = Product.derive;
pub const deriveAuthority = Product.deriveAuthority;
pub const testing = Product.testing;
pub const deriveWithCircuitProfile = Product.deriveSelected;
pub const deriveAuthorityWithCircuitProfile = Product.deriveAuthoritySelected;
