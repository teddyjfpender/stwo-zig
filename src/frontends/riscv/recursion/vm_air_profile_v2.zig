//! Native legacy SegmentV2 authority; shared derivation is source-bound below.
const shared = @import("vm_air_profile_v2_authority.zig");
const NativeOwner = struct {
    pub const Selector = enum(u16) { legacy_v4 = 0 };
    pub const DEFAULT_SELECTOR: Selector = .legacy_v4;
    pub fn schemaVersion(_: Selector) u16 {
        return shared.SCHEMA_VERSION;
    }
    pub fn circuitLayout(_: Selector) @import("../air/program/circuit_layout.zig").CircuitLayout {
        return .ordinary_sparse;
    }
    pub fn hashIdentityPrefix(hash: *std.crypto.hash.sha2.Sha256, _: Selector) void {
        hash.update(shared.PROFILE_DOMAIN);
    }
};
const std = @import("std");
const Native = shared.ForOwner(NativeOwner);
pub const FORMAT_VERSION = shared.FORMAT_VERSION;
pub const SCHEMA_VERSION = shared.SCHEMA_VERSION;
pub const PROFILE_DOMAIN = shared.PROFILE_DOMAIN;
pub const Error = shared.Error;
pub const AdapterRoleV2 = shared.AdapterRoleV2;
pub const TreeSpanV2 = shared.TreeSpanV2;
pub const OpcodeSemanticKeyV2 = shared.OpcodeSemanticKeyV2;
pub const OpcodeLookupKeyV2 = shared.OpcodeLookupKeyV2;
pub const InfrastructureKeyV2 = shared.InfrastructureKeyV2;
pub const RegistryKeyV2 = shared.RegistryKeyV2;
pub const EntryV2 = shared.EntryV2;
pub const InputProfileV2 = shared.InputProfileV2;
pub const Facts = shared.Facts;
pub const ProfileV2 = Native.ProfileV2;
pub const derive = Native.derive;
pub const deriveAuthority = Native.deriveAuthority;
pub const testing = Native.testing;
pub const ForOwner = shared.ForOwner;
