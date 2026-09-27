//! Narrow append-only access to the unchanged base Tree-2 generator.

const std = @import("std");
const stage_profile = @import("stwo_prover_api").stage_profile;
const relation_challenges = @import("../air/relation_challenges.zig");
const lookup_physical_v2 = @import("../air/lang/lookup_physical_manifest_v2.zig");
const commitment_witness = @import("commitment_witness.zig");
const lookup_sources = @import("lookup_sources.zig");
const proof_workspace = @import("proof_workspace.zig");
const statement_geometry = @import("statement_geometry.zig");
const tree2_main_source = @import("tree2_main_source.zig");
const types = @import("types.zig");
const native_provider_omit = @import("memory_provider_shards/native_provider_omit_v1.zig");

pub fn Ops(comptime Generation: type) type {
    return struct {
        pub const Columns = Generation.Columns;

        pub fn generateBase(
            allocator: std.mem.Allocator,
            workspace: *proof_workspace.ProofWorkspace,
            columns: *Columns,
            recorder: ?*stage_profile.Recorder,
            witness: *const commitment_witness.CommitmentWitness,
            geometry: statement_geometry.Geometry,
            main_source: *const tree2_main_source.Source,
            relations: *const relation_challenges.Relations,
            claim: *types.RiscVInteractionClaim,
        ) !void {
            return Generation.generateBase(
                allocator,
                workspace,
                columns,
                recorder,
                witness,
                geometry,
                main_source,
                relations,
                claim,
                null,
                .ambient,
            );
        }

        /// Generates the base prefix under the authenticated physical V2
        /// lookup authority without committing it. External profiles append
        /// their own typed columns before one shared Tree-2 commitment.
        pub fn generateBaseAuthenticatedLookupV2(
            allocator: std.mem.Allocator,
            workspace: *proof_workspace.ProofWorkspace,
            columns: *Columns,
            recorder: ?*stage_profile.Recorder,
            witness: *const commitment_witness.CommitmentWitness,
            geometry: statement_geometry.Geometry,
            main_source: *const tree2_main_source.Source,
            relations: *const relation_challenges.Relations,
            claim: *types.RiscVInteractionClaim,
            manifest: *const lookup_physical_v2.Manifest,
            statement: *const lookup_physical_v2.AuthenticatedStatement,
        ) !void {
            try statement.validateAgainst(&workspace.statement, manifest);
            return Generation.generateBase(
                allocator,
                workspace,
                columns,
                recorder,
                witness,
                geometry,
                main_source,
                relations,
                claim,
                .{ .manifest = manifest, .statement = statement },
                .ambient,
            );
        }

        /// Omission-aware authenticated V2 prefix. The workspace statement is
        /// already the exact projected statement minted by `ProjectionV1`.
        pub fn generateBaseWithoutNativePoseidonAuthenticatedLookupV2(
            allocator: std.mem.Allocator,
            workspace: *proof_workspace.ProofWorkspace,
            columns: *Columns,
            recorder: ?*stage_profile.Recorder,
            witness: *const commitment_witness.CommitmentWitness,
            geometry: native_provider_omit.ProjectedGeometryV1,
            main_source: *const tree2_main_source.Source,
            relations: *const relation_challenges.Relations,
            claim: *types.RiscVInteractionClaim,
            manifest: *const lookup_physical_v2.Manifest,
            statement: *const lookup_physical_v2.AuthenticatedStatement,
        ) !void {
            try statement.validateAgainst(&workspace.statement, manifest);
            return Generation.generateBaseWithoutNativePoseidonAuthenticatedLookupV2(
                allocator,
                workspace,
                columns,
                recorder,
                witness,
                geometry,
                main_source,
                relations,
                claim,
                manifest,
                .ambient,
            );
        }

        pub fn source(
            workspace: *const proof_workspace.ProofWorkspace,
            lookup_source: *const lookup_sources.Result,
        ) tree2_main_source.Source {
            return tree2_main_source.Source.fromLegacy(workspace, lookup_source);
        }
    };
}
