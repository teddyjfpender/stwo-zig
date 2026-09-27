//! Compiler admission inputs for incremental Ethereum composition.
//! The statement-root profile accepts geometry separately from root values;
//! native and recursive callers use these types without importing a recorder.
const statement_mod = @import("../air/statement.zig");
const ethereum_statement = @import("../air/guest_precompile/ethereum_statement.zig");
const lookup_manifest = @import("../air/lang/lookup_physical_manifest_v2.zig");
const profile_mod = @import("vm_air_profile_v2.zig");
const bridge_external = @import("../prover/incremental_bridge_external_v3.zig");

pub const BridgeInputV4 = struct {
    geometry: bridge_external.GeometryV3,
    entry_root: u32,
    exit_root: u32,

    pub fn validateAfterPrefix(
        self: BridgeInputV4,
        prefix: bridge_external.PrefixColumnsV3,
    ) !void {
        try self.geometry.validateAfterPrefix(prefix);
        const modulus = @import("stwo_core").fields.m31.Modulus;
        if (self.entry_root >= modulus or self.exit_root >= modulus)
            return error.InvalidBridgeCompositionGeometry;
    }
};

pub const CompilerInputV4 = struct {
    core_statement: *const statement_mod.RiscVStatement,
    extension_statement: *const ethereum_statement.Statement,
    lookup_manifest: *const lookup_manifest.Manifest,
    authenticated_lookup: *const lookup_manifest.AuthenticatedStatement,
    base_profile: *const profile_mod.ProfileV2,
    bridge: BridgeInputV4,
};

/// Circuit shape for the Ethereum statement-root profile. Root VALUES cannot
/// enter this API. The caller must supply them through row-18 statement inputs.
/// Full provider closure is required before production activation.
pub const StatementRootCompilerInput = struct {
    core_statement: *const statement_mod.RiscVStatement,
    extension_statement: *const ethereum_statement.Statement,
    lookup_manifest: *const lookup_manifest.Manifest,
    authenticated_lookup: *const lookup_manifest.AuthenticatedStatement,
    base_profile: *const profile_mod.ProfileV2,
    bridge_geometry: bridge_external.GeometryV3,
    native_continuation_roots: bool = false,
};

/// Ethereum-only admission for the three native singleton claims. Native
/// transcript shape keeps the full logical sequence; the graph has no second
/// witness for a singleton already supplied by its canonical claim input.
/// This value contains fixed geometry only and is retained inside the compiled
/// immutable owner. Neither graph input types nor legacy profiles change.
pub const ClaimRoutingPlan = struct {
    /// One canonical consumer in VM composition and one in global cancellation.
    pub const CANONICAL_TRANSCRIPT_USE_COUNT: u32 = 2;
    pub const SCHEMA_VERSION: u32 = 1;
    pub const ALIAS_COUNT: u32 = 3;
    pub const BASE_CANONICAL_COUNT: u32 = @import("../air/transcript/claims.zig").COMPONENT_COUNT;
    pub const Error = error{ InvalidEthereumClaimRouting, ArithmeticOverflow };
    pub const Route = union(enum) { detailed: u32, canonical: u32 };
    pub const Alias = struct { logical: u32, canonical: u32 };

    base_count: u32,
    extension_counts: [ethereum_statement.component_count]u32,
    logical_count: u32,
    physical_count: u32,
    aliases: [ALIAS_COUNT]Alias,

    pub fn init(base_count: u32, counts: [ethereum_statement.component_count]u32) Error!ClaimRoutingPlan {
        const std = @import("std");
        var cursor = base_count;
        var aliases: [ALIAS_COUNT]Alias = undefined;
        var at: usize = 0;
        for (ethereum_statement.componentKinds(), counts, 0..) |kind, count, index| {
            if (count == 0) return error.InvalidEthereumClaimRouting;
            if (kind == .keccak_chi_table_v2 or kind == .keccak_xor5_table_v2) {
                if (count != 1) return error.InvalidEthereumClaimRouting;
                aliases[at] = .{ .logical = cursor, .canonical = BASE_CANONICAL_COUNT + @as(u32, @intCast(index)) };
                at += 1;
            }
            cursor = std.math.add(u32, cursor, count) catch return error.ArithmeticOverflow;
        }
        if (at != 2) return error.InvalidEthereumClaimRouting;
        aliases[2] = .{ .logical = cursor, .canonical = BASE_CANONICAL_COUNT + ethereum_statement.component_count };
        cursor = std.math.add(u32, cursor, 1) catch return error.ArithmeticOverflow;
        if (cursor >= @import("stwo_core").fields.m31.Modulus) return error.InvalidEthereumClaimRouting;
        return .{ .base_count = base_count, .extension_counts = counts, .logical_count = cursor, .physical_count = cursor - ALIAS_COUNT, .aliases = aliases };
    }

    pub fn validate(self: ClaimRoutingPlan) Error!void {
        const expected = try init(self.base_count, self.extension_counts);
        if (!@import("std").meta.eql(expected, self)) return error.InvalidEthereumClaimRouting;
    }

    pub fn route(self: ClaimRoutingPlan, logical: u32) Error!Route {
        if (logical >= self.logical_count) return error.InvalidEthereumClaimRouting;
        var removed: u32 = 0;
        for (self.aliases) |alias| {
            if (logical == alias.logical) return .{ .canonical = alias.canonical };
            removed += @intFromBool(alias.logical < logical);
        }
        return .{ .detailed = logical - removed };
    }

    pub fn logicalForPhysical(self: ClaimRoutingPlan, physical: u32) Error!u32 {
        if (physical >= self.physical_count) return error.InvalidEthereumClaimRouting;
        var logical = physical;
        for (self.aliases) |alias| if (logical >= alias.logical) {
            logical += 1;
        };
        return logical;
    }

    /// A separately mixed native batch must remain one contiguous physical
    /// input range; singleton alias frames cannot be retagged as batch inputs.
    pub fn physicalRange(self: ClaimRoutingPlan, first: u32, count: u32) Error!u32 {
        if (count == 0) return error.InvalidEthereumClaimRouting;
        const end = @import("std").math.add(u32, first, count) catch return error.ArithmeticOverflow;
        if (end > self.logical_count) return error.InvalidEthereumClaimRouting;
        for (self.aliases) |alias| if (alias.logical >= first and alias.logical < end)
            return error.InvalidEthereumClaimRouting;
        return switch (try self.route(first)) {
            .detailed => |item| item,
            .canonical => error.InvalidEthereumClaimRouting,
        };
    }

    pub fn sourceForWord(self: ClaimRoutingPlan, logical: u32, limb: u32) Error!@import("air/composition_circuit.zig").VmSource {
        if (limb >= 4) return error.InvalidEthereumClaimRouting;
        return switch (try self.route(logical)) {
            .detailed => |item| .{ .claimed_sum = .{ .item_index = item, .word_index = limb } },
            .canonical => |item| .{ .transcript_claimed_sum = .{ .item_index = item, .word_index = limb } },
        };
    }

    pub fn identity(self: ClaimRoutingPlan) [32]u8 {
        var hash = @import("std").crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/ethereum-singleton-claim-routing/v1\x00");
        hashWord(&hash, SCHEMA_VERSION);
        hashWord(&hash, self.base_count);
        for (self.extension_counts) |count| hashWord(&hash, count);
        hashWord(&hash, self.logical_count);
        hashWord(&hash, self.physical_count);
        for (self.aliases) |alias| {
            hashWord(&hash, alias.logical);
            hashWord(&hash, alias.canonical);
        }
        return hash.finalResult();
    }
};

/// Physical AIR selection paired with StatementRootCompilerInput. Native
/// adapters and recursive recorders consume the same selected component type.
/// This defines geometry, not a complete-proof admission capability: registry
/// log sizes, preprocessing commitments and all lookup closure remain required.
pub const StatementRootProvider = @import("air/statement_input_roots_v3.zig");
pub const StatementByteProvider = @import("air/statement_semantics_bytes_v2.zig");
pub const PublicLogupProvider = @import("air/ethereum_public_logup_input_v1.zig");
pub const TranscriptStateProvider = @import("air/ethereum_transcript_state_v1.zig");
pub const PublicationControlProvider = @import("air/ethereum_publication_control_v1.zig");
pub const PublicationHashProvider = @import("air/ethereum_publication_hash_v1.zig");
pub const ClaimInputProvider = @import("air/ethereum_vm_public_claim_input_v1.zig");
pub const ClockPayloadProvider = @import("air/ethereum_transcript_payload_raw_v1.zig");
pub const StatementRootOuterCatalog = struct {
    const base = @import("air/universal_catalog.zig");
    pub const LOGICAL_ROWS = blk: {
        var rows: [base.LOGICAL_COUNT]base.Entry = undefined;
        for (base.LOGICAL_ROWS, 0..) |entry, index| {
            rows[index] = entry;
            if (entry.row == .statement_input) rows[index].Air = StatementRootProvider;
        }
        break :blk rows;
    };
    pub const LOGICAL_COUNT = LOGICAL_ROWS.len;
};

/// Schema-11 Ethereum routing exposes range-checked statement bytes and
/// transcript-authenticated native clock words. The earlier root-only catalog remains a separate admitted profile.
pub const StatementRoutingOuterCatalog = struct {
    pub const LOGICAL_ROWS = blk: {
        var rows = StatementRootOuterCatalog.LOGICAL_ROWS;
        for (&rows) |*entry| {
            if (entry.row == .statement_semantics_input) entry.Air = StatementByteProvider;
            if (entry.row == .transcript_payload) entry.Air = ClockPayloadProvider;
            if (entry.row == .transcript_state) entry.Air = TranscriptStateProvider;
            if (entry.row == .vm_public_claim_input) entry.Air = ClaimInputProvider;
            if (entry.row == .vm_public_claim_hash) entry.Air = PublicationHashProvider;
            if (entry.row == .vm_public_logup_control) entry.Air = PublicationControlProvider;
            if (entry.row == .vm_public_logup_input) entry.Air = PublicLogupProvider;
        }
        break :blk rows;
    };
    pub const LOGICAL_COUNT = LOGICAL_ROWS.len;
};

/// One identity encoding for the legacy and statement-root input profiles.
/// Appending the opt-in marker leaves every zero-count legacy preimage intact.
pub fn hashInputProfile(hash: anytype, profile: @import("air/composition_circuit.zig").InputProfile) void {
    const words = [_]u32{ profile.sampled_value_count, profile.claimed_sum_count, profile.relation_challenge_count, profile.transcript_claimed_sum_count, profile.public_wire_boundary_count };
    for (words) |word| hashWord(hash, word);
    @import("air/vm_statement_roots.zig").hashProfileExtension(hash, profile.vm_statement_root_count);
    @import("air/vm_statement_roots.zig").hashNativeProfileExtension(hash, profile.vm_native_continuation_roots);
}

fn hashWord(hash: anytype, word: u32) void {
    var bytes: [4]u8 = undefined;
    @import("std").mem.writeInt(u32, &bytes, word, .little);
    hash.update(&bytes);
}
