//! Transactional interaction-tree fill for binary transcript rows.

const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const binary_authority = @import("binary_pair_authority.zig");
const air = @import("air/mod.zig");
const manifest_mod = air.universal_adapter_manifest;
const schedule = air.verifier_schedule;
const universal = air.universal_challenges;

pub fn fill(
    self: anytype,
    workspace: anytype,
    vm_plan: *const schedule.Plan,
    recursion_plans: [2]*const schedule.Plan,
    preprocessing: *const binary_authority.TranscriptPreprocessing,
    prepared: anytype,
    manifest: *const manifest_mod.Manifest,
    relations: *const universal.UniversalRelations,
    destination: []const []M31,
    comptime Claims: type,
    comptime Stage: type,
    comptime preflightDestination: anytype,
    comptime generateControlInteraction: anytype,
    comptime generateTranscriptAirInteraction: anytype,
    comptime generateTranscriptBindingInteraction: anytype,
    comptime generateTranscriptStateInteraction: anytype,
    comptime generateTranscriptWordInteraction: anytype,
    comptime generateTranscriptPayloadInteraction: anytype,
    comptime generatePowCheckInteraction: anytype,
    comptime generatePowFrameInteraction: anytype,
    comptime generateRelationChallengeInteraction: anytype,
    comptime generateVerifierRandomnessInteraction: anytype,
) !Claims {
    try self.validateAgainst(vm_plan, recursion_plans, preprocessing, prepared);
    try workspace.validateFor(self, preprocessing, prepared);
    try self.validateManifest(manifest);
    try relations.validate();
    try preflightDestination(manifest, manifest_mod.INTERACTION_TREE_INDEX, destination);
    var stage = try Stage.init(
        self.allocator,
        manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
        destination,
    );
    defer stage.deinit();

    const claims = Claims{
        .control = try generateControlInteraction(
            self,
            workspace,
            relations,
            &stage,
        ),
        .transcript_air = try generateTranscriptAirInteraction(
            self,
            workspace,
            prepared,
            relations,
            &stage,
        ),
        .transcript_binding = try generateTranscriptBindingInteraction(
            self,
            workspace,
            preprocessing,
            prepared,
            relations,
            &stage,
        ),
        .transcript_state = try generateTranscriptStateInteraction(
            self,
            workspace,
            preprocessing,
            prepared,
            relations,
            &stage,
        ),
        .transcript_word = try generateTranscriptWordInteraction(
            self,
            workspace,
            preprocessing,
            prepared,
            relations,
            &stage,
        ),
        .transcript_payload = try generateTranscriptPayloadInteraction(
            self,
            workspace,
            preprocessing,
            prepared,
            relations,
            &stage,
        ),
        .pow_check = try generatePowCheckInteraction(
            self,
            workspace,
            prepared,
            relations,
            &stage,
        ),
        .pow_frame = try generatePowFrameInteraction(
            self,
            workspace,
            prepared,
            relations,
            &stage,
        ),
        .relation_challenge = try generateRelationChallengeInteraction(
            self,
            workspace,
            preprocessing,
            prepared,
            relations,
            &stage,
        ),
        .verifier_randomness = try generateVerifierRandomnessInteraction(
            self,
            workspace,
            preprocessing,
            prepared,
            relations,
            &stage,
        ),
    };
    stage.commit(manifest);
    return claims;
}
