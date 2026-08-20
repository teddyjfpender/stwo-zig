//! Internal shard of recursion_air_composition_circuit_v3.zig; use the public facade.

const dependency_0 = @import("recursion_air_composition_circuit_v3_canonical_empty_program_v3.zig");
const dependency_1 = @import("recursion_air_composition_circuit_v3_program_roster_v3.zig");
const dependency_4 = @import("recursion_air_composition_circuit_v3_write_inputs_from_validated_profile_and_policy.zig");
const dependency_5 = @import("recursion_air_composition_circuit_v3_authority_validation.zig");

const std = dependency_0.std;
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const Sha256 = dependency_0.Sha256;
const graph_mod = dependency_0.graph_mod;
const recorder = dependency_0.recorder;
const universal = dependency_0.universal;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const SCHEMA_VERSION = dependency_0.SCHEMA_VERSION;
const CIRCUIT_DOMAIN = dependency_0.CIRCUIT_DOMAIN;
const ProofKind = dependency_0.ProofKind;
const COMPOSITION_CLAIM_INPUT_COUNT = dependency_0.COMPOSITION_CLAIM_INPUT_COUNT;
const STATEMENT_WORD_COUNT = dependency_0.STATEMENT_WORD_COUNT;
const PROGRAM_KIND_COUNT = dependency_0.PROGRAM_KIND_COUNT;
const Error = dependency_0.Error;
const TrustedManifestsV3 = dependency_0.TrustedManifestsV3;
const AirProgramIdsV3 = dependency_0.AirProgramIdsV3;
const ConfigurationV3 = dependency_1.ConfigurationV3;
const RecordedHeterogeneousCircuitStorageV3 = dependency_4.RecordedHeterogeneousCircuitStorageV3;
const validateGraphBindings = dependency_5.validateGraphBindings;
const hashInt = dependency_5.hashInt;

pub const CircuitAuthorityStorageV3 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    configuration_identity: [32]u8,
    graph_identity: [32]u8,
    binding_count: u32,
    identity: [32]u8,

    pub fn validateAgainstValidatedConfiguration(
        self: CircuitAuthorityStorageV3,
        configuration: ConfigurationV3,
        graph: graph_mod.CircuitGraph,
        bindings: []const graph_mod.RecursionInputBinding,
    ) Error!void {
        try validateGraphBindings(configuration, graph, bindings);
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.eql(
                u8,
                &self.configuration_identity,
                &configuration.identity,
            ) or !std.mem.eql(u8, &self.graph_identity, &graph.identity_digest) or
            self.binding_count != bindings.len or
            !std.mem.eql(u8, &self.identity, &circuitAuthorityIdentity(self)))
        {
            return error.CircuitAuthorityMismatch;
        }
    }
};

/// Opaque borrow of one finalized recorder product.  Its representation is
/// the recorder-owned storage itself, so no detached graph/configuration tuple
/// can be assembled by a caller.
pub const CircuitViewV3 = opaque {
    pub fn validate(
        self: *const CircuitViewV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
    ) Error!void {
        try recordingStorageFromView(self).validate(manifests, air_program_ids);
    }

    pub fn validatedLane(
        self: *const CircuitViewV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        verifier_id: u32,
        circuit_id: u32,
        statement_scope: u32,
    ) Error!graph_mod.RecursionLane {
        try self.validate(manifests, air_program_ids);
        const storage = recordingStorageFromView(self);
        return .{
            .verifier_id = verifier_id,
            .circuit_id = circuit_id,
            .statement_scope = statement_scope,
            .graph = storage.graph(),
            .profile = storage.configuration.graphInputProfile(),
            .bindings = storage.bindings,
        };
    }
};

pub const WitnessV3 = struct {
    parent_binary_selector: bool,
    proof_kind: ProofKind,
    statement_words: *const [STATEMENT_WORD_COUNT]M31,
    sampled_values: []const QM31,
    claim_inputs: *const [COMPOSITION_CLAIM_INPUT_COUNT]QM31,
    public_wire_boundary: QM31,
    relations: *const universal.UniversalRelations,
    composition_randomness: QM31,
    oods_seed: QM31,
};

pub const HeterogeneousProgramStatisticsV3 = struct {
    constraints_per_kind: [PROGRAM_KIND_COUNT]usize,
    roster_rows_per_kind: [PROGRAM_KIND_COUNT]u8,
    sampled_values: u32,
    graph_inputs: usize,
    graph_nodes: usize,
    graph_outputs: usize,
};

pub fn circuitAuthorityIdentity(value: CircuitAuthorityStorageV3) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(CIRCUIT_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.configuration_identity);
    hash.update(&value.graph_identity);
    hashInt(&hash, u32, value.binding_count);
    return hash.finalResult();
}

pub fn recordingStorageFromView(
    view: *const CircuitViewV3,
) *const RecordedHeterogeneousCircuitStorageV3 {
    return @ptrCast(@alignCast(view));
}
