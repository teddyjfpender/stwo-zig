//! Native Poseidon2 provider adapter for the compact Ethereum h1 manifest.
//!
//! `universal_shared_provider.Poseidon2AdapterForManifest` intentionally
//! retains frozen roster row 34 in its geometry.  The h1 proof reuses the same
//! reviewed HashComponent and relation storage at physical row 11, so this
//! narrow adapter changes only the manifest placement and never the provider
//! equations or transcript challenges.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const manifest_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_manifest_v1.zig");

const recursion = frontend.recursion;
const poseidon_air = frontend.air.memory_commitment.poseidon2_air;
const poseidon_component = frontend.air.memory_commitment.hash_component;
const shared_provider = recursion.air.universal_shared_provider;
const universal = recursion.air.universal_challenges;
const m31 = stwo_core.fields.m31;
const QM31 = stwo_core.fields.qm31.QM31;

pub const Adapter = struct {
    placement: manifest_mod.Placement,
    component: poseidon_component.HashComponent,
    provider_relations: *const shared_provider.SharedProviderRelations,
    challenge_binding_sha256: [32]u8,
    admitted_claims: [poseidon_air.N_SUMS]QM31,

    pub fn init(
        manifest: *const manifest_mod.Manifest,
        log_size: u32,
        active_rows: u32,
        provider_relations: *const shared_provider.SharedProviderRelations,
        relations: *const universal.UniversalRelations,
        claims: [poseidon_air.N_SUMS]QM31,
    ) !Adapter {
        try manifest.validate();
        try provider_relations.validateAgainst(relations);
        try shared_provider.PoseidonSourceAuthority.pinned().validate();
        if (log_size == 0 or
            log_size >= shared_provider.POSEIDON_LOG_SIZE_EXCLUSIVE_LIMIT or
            @as(u64, active_rows) > @as(u64, 1) << @intCast(log_size))
        {
            return error.ProviderTraceShapeMismatch;
        }
        for (claims) |claim| try requireCanonicalQm31(claim);
        const placement = try manifest.placement(.poseidon2);
        if (!std.meta.eql(
            placement.geometry,
            manifest_mod.providerGeometry(log_size),
        )) return error.ProviderGeometryMismatch;
        return .{
            .placement = placement,
            .provider_relations = provider_relations,
            .challenge_binding_sha256 = try provider_relations.identityDigest(),
            .admitted_claims = claims,
            .component = .{
                .kind = .poseidon2,
                .log_size = log_size,
                .n_rows = active_rows,
                .is_first_col_idx = placement.preprocessed_offset,
                .is_active_col_idx = placement.preprocessed_offset,
                .main_col_offset = placement.main_offset,
                .interaction_col_offset = placement.interaction_offset,
                .relations = &provider_relations.native,
                .poseidon_shell = .universal,
                .poseidon_claims = claims,
            },
        };
    }

    pub fn binding(
        self: *const Adapter,
        manifest: *const manifest_mod.Manifest,
    ) !manifest_mod.AdapterBinding {
        try manifest.validate();
        try shared_provider.PoseidonSourceAuthority.pinned().validate();
        const expected = try manifest.placement(.poseidon2);
        const current_binding = try self.provider_relations.identityDigest();
        if (!self.placement.eql(expected) or
            !std.meta.eql(
                self.placement.geometry,
                manifest_mod.providerGeometry(
                    self.placement.geometry.log_size,
                ),
            ) or !std.mem.eql(
            u8,
            &self.challenge_binding_sha256,
            &current_binding,
        ) or self.component.relations != &self.provider_relations.native)
        {
            return error.ProviderAuthorityMismatch;
        }
        for (self.component.poseidon_claims, self.admitted_claims) |
            actual,
            admitted,
        | {
            try requireCanonicalQm31(actual);
            if (!actual.eql(admitted))
                return error.ChallengeBindingMismatch;
        }
        if (self.component.kind != .poseidon2 or
            self.component.poseidon_shell != .universal or
            self.component.log_size != self.placement.geometry.log_size or
            self.component.n_rows >
                @as(u64, 1) << @intCast(self.component.log_size) or
            self.component.is_first_col_idx !=
                self.placement.preprocessed_offset or
            self.component.is_active_col_idx !=
                self.placement.preprocessed_offset or
            self.component.main_col_offset != self.placement.main_offset or
            self.component.interaction_col_offset !=
                self.placement.interaction_offset or
            self.component.nPreprocessedColumns() !=
                shared_provider.POSEIDON_PREPROCESSED_COLUMN_COUNT or
            self.component.nConstraints() !=
                shared_provider.POSEIDON_DIRECT_CONSTRAINT_COUNT +
                    shared_provider.POSEIDON_INTERACTION_BATCH_COUNT)
        {
            return error.ProviderAuthorityMismatch;
        }
        return .{
            .manifest_seal = manifest.seal,
            .placement = self.placement,
            .claimed_sum = self.admitted_claims[0].add(
                self.admitted_claims[1],
            ),
            .verifier = self.component.asVerifierComponent(),
            .prover = self.component.asProverComponent(),
        };
    }
};

fn requireCanonicalQm31(value: QM31) !void {
    for (value.toM31Array()) |word|
        if (word.toU32() >= m31.Modulus)
            return error.ChallengeBindingMismatch;
}

test "compact provider geometry uses h1 row eleven" {
    const geometry = manifest_mod.providerGeometry(9);
    try std.testing.expectEqual(
        manifest_mod.keyIndex(.poseidon2),
        geometry.roster_row,
    );
    try std.testing.expectEqual(
        @as(u16, poseidon_air.N_MAIN_COLUMNS),
        geometry.main_columns,
    );
}
