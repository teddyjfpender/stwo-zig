const frontend = @import("stwo_riscv_frontend");
const prefix_runtime = @import("recursive_temporal_parent_prefix_runtime.zig");
const row18_source = @import("recursive_temporal_parent_row18_source_v3.zig");
const row35_mod = @import("recursive_temporal_parent_row35_owner_v1.zig");
const suffix_mod = @import("recursive_temporal_parent_suffix_v3.zig");
const temporal_nonfri = @import("recursive_temporal_nonfri_source_v2.zig");
const manifest_mod = @import("recursive_temporal_parent_manifest_v3.zig");

const recursion = frontend.recursion;
const global_closure = recursion.binary_global_closure_outer_source;
const PrefixComponents = temporal_nonfri.TemporalPrefixComponentsForManifest(manifest_mod);
const SuffixComponents = recursion.binary_fri_outer_bundle.ComponentsForManifest(
    manifest_mod,
);
const GENERATED_FORMAT_VERSION: u16 = 1;
const PREFIX_ROW_COUNT: usize = manifest_mod.PREFIX_ROW_COUNT;
const PROVIDER_ROW: usize = 35;
const COMPONENT_COUNT: usize = manifest_mod.COMPONENT_COUNT;

pub const AuthorityInputs = struct {
    runtime: prefix_runtime.RuntimeInputsV1,
    row18: *row18_source.Row18AuthorityV3,
};

pub const GeneratedInteractionsV1 = struct {
    format_version: u16 = GENERATED_FORMAT_VERSION,
    padding: [6]u8 = [_]u8{0} ** 6,
    cohort_id: [32]u8,
    manifest_seal: [32]u8,
    prefix: temporal_nonfri.TemporalPrefixInteractionsV3,
    suffix: recursion.binary_fri_outer_bundle.GeneratedInteractionsV1,
    row35: row35_mod.GeneratedV1,
    identity: [32]u8,
};

pub const AuditedInteractionsV2 = struct {
    prefix: temporal_nonfri.TemporalPrefixDomainAuditsV3,
    suffix: recursion.binary_fri_outer_bundle.AuditedInteractionsV1,
    row35: row35_mod.GeneratedV1,
    rows: [global_closure.PREFIX_ROW_COUNT]global_closure.RowClaimsV1,
    provider_claim: global_closure.ProviderClaimV1,
    wire_boundary: global_closure.BoundaryEvidenceV2,
    verifier_input_boundary: global_closure.BoundaryEvidenceV2,
    closure: global_closure.ClosureReceiptV2,
    context: suffix_mod.ContextReceiptV3,
    identity: [32]u8,
};

pub const Components = struct {
    prefix: PrefixComponents,
    suffix: SuffixComponents,
    row35: row35_mod.Adapter,

    pub fn deinit(self: *Components) void {
        self.* = undefined;
    }

    pub fn appendToGate(
        self: *const Components,
        active_manifest: *const manifest_mod.Manifest,
        gate: *manifest_mod.ProofGate,
    ) !void {
        if (gate.count != 0) return error.RosterOrderMismatch;
        try self.prefix.appendToGate(active_manifest, gate);
        if (gate.count != PREFIX_ROW_COUNT)
            return error.RosterOrderMismatch;
        try self.suffix.appendToGate(active_manifest, gate);
        if (gate.count != PROVIDER_ROW)
            return error.RosterOrderMismatch;
        try gate.append(
            active_manifest,
            try self.row35.binding(active_manifest),
        );
        if (gate.count != COMPONENT_COUNT)
            return error.RosterOrderMismatch;
    }
};
