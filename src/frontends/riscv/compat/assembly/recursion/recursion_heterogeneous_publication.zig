//! Validated recording publication, final seal minting and construction-resource retirement.

const Root = @import("recursion_air_composition_circuit_heterogeneous_session.zig");
const dependency_0 = @import("recursion_air_composition_circuit_canonical_empty_program.zig");
const dependency_4 = @import("recursion_air_composition_circuit_write_inputs_from_validated_profile_and_policy.zig");
const dependency_5 = @import("recursion_air_composition_circuit_authority_validation.zig");
const proofKindIndex = dependency_0.proofKindIndex;
const RecordedHeterogeneousCircuitStorageV3 = dependency_4.RecordedHeterogeneousCircuitStorageV3;
const mintCircuitAuthorityFromValidatedRecording = dependency_5.mintCircuitAuthorityFromValidatedRecording;
const RecordedHeterogeneousCircuitV3 = Root.RecordedHeterogeneousCircuitV3;
const HeterogeneousSessionV3 = Root.HeterogeneousSessionV3;

pub fn finish(
    self: *HeterogeneousSessionV3,
) !*RecordedHeterogeneousCircuitV3 {
    if (self.finished or self.failed or !self.programs_recorded or
        !self.builder.active)
    {
        return error.IncompleteHeterogeneousProgram;
    }
    const segment = self.program_results[proofKindIndex(.segment_leaf)] orelse
        return error.IncompleteHeterogeneousProgram;
    const binary = self.program_results[proofKindIndex(.binary_node)] orelse
        return error.IncompleteHeterogeneousProgram;
    const empty = self.program_results[proofKindIndex(.empty_leaf)] orelse
        return error.IncompleteHeterogeneousProgram;

    try self.builder.constrainZero(
        self.child_kind_selectors[proofKindIndex(.segment_leaf)].mul(
            self.segment_split_composition.sub(segment.accumulation),
        ),
    );
    try self.builder.constrainZero(
        self.child_kind_selectors[proofKindIndex(.binary_node)].mul(
            self.universal_split_composition.sub(binary.accumulation),
        ),
    );
    try self.builder.constrainZero(
        self.child_kind_selectors[proofKindIndex(.empty_leaf)].mul(
            self.universal_split_composition.sub(empty.accumulation),
        ),
    );
    try self.builder.check();
    self.builder.deactivate();
    self.finished = true;

    var recorded = try self.builder.finish();
    errdefer recorded.deinit();
    const result = try self.allocator.create(
        RecordedHeterogeneousCircuitStorageV3,
    );
    errdefer self.allocator.destroy(result);
    result.* = .{
        .allocator = self.allocator,
        .recorded = recorded,
        .bindings = self.bindings,
        .configuration = self.configuration,
        .sample_input_authority = self.sample_input_authority,
        .statistics = .{
            .constraints_per_kind = .{
                segment.constraint_count,
                binary.constraint_count,
                empty.constraint_count,
            },
            .roster_rows_per_kind = .{
                segment.row_count,
                binary.row_count,
                empty.row_count,
            },
            .sampled_values = self.sample_input_authority.max_sample_count,
            .graph_inputs = recorded.input_count,
            .graph_nodes = recorded.nodes.len,
            .graph_outputs = recorded.outputs.len,
        },
        .authority = undefined,
    };
    try result.validateFinalizedRecording(
        self.manifests,
        self.air_program_ids,
    );
    result.authority = try mintCircuitAuthorityFromValidatedRecording(
        result,
    );
    try result.validate(self.manifests, self.air_program_ids);

    self.segment_layout.deinit();
    self.binary_layout.deinit();
    if (self.canonical_empty_layout) |*layout| layout.deinit();
    self.allocator.free(self.sampled_values);
    self.builder.deinit();
    const allocator = self.allocator;
    self.* = undefined;
    allocator.destroy(self);
    return @ptrCast(result);
}

pub fn finishAuthenticatedH1(
    self: *HeterogeneousSessionV3,
    h1_manifest: anytype,
) !*RecordedHeterogeneousCircuitV3 {
    if (self.finished or self.failed or !self.programs_recorded or
        !self.builder.active or self.authenticated_h1_empty_layout == null)
    {
        return error.IncompleteHeterogeneousProgram;
    }
    try self.configuration.validateAgainstAuthenticatedH1(
        self.manifests,
        self.air_program_ids,
        h1_manifest,
    );
    const segment = self.program_results[proofKindIndex(.segment_leaf)] orelse
        return error.IncompleteHeterogeneousProgram;
    const binary = self.program_results[proofKindIndex(.binary_node)] orelse
        return error.IncompleteHeterogeneousProgram;
    const empty = self.program_results[proofKindIndex(.empty_leaf)] orelse
        return error.IncompleteHeterogeneousProgram;

    try self.builder.constrainZero(
        self.child_kind_selectors[proofKindIndex(.segment_leaf)].mul(
            self.segment_split_composition.sub(segment.accumulation),
        ),
    );
    try self.builder.constrainZero(
        self.child_kind_selectors[proofKindIndex(.binary_node)].mul(
            self.universal_split_composition.sub(binary.accumulation),
        ),
    );
    try self.builder.constrainZero(
        self.child_kind_selectors[proofKindIndex(.empty_leaf)].mul(
            self.authenticated_h1_empty_split_composition.sub(
                empty.accumulation,
            ),
        ),
    );
    try self.builder.check();
    self.builder.deactivate();
    self.finished = true;

    var recorded = try self.builder.finish();
    errdefer recorded.deinit();
    const result = try self.allocator.create(
        RecordedHeterogeneousCircuitStorageV3,
    );
    errdefer self.allocator.destroy(result);
    result.* = .{
        .allocator = self.allocator,
        .recorded = recorded,
        .bindings = self.bindings,
        .configuration = self.configuration,
        .sample_input_authority = self.sample_input_authority,
        .statistics = .{
            .constraints_per_kind = .{
                segment.constraint_count,
                binary.constraint_count,
                empty.constraint_count,
            },
            .roster_rows_per_kind = .{
                segment.row_count,
                binary.row_count,
                empty.row_count,
            },
            .sampled_values = self.sample_input_authority.max_sample_count,
            .graph_inputs = recorded.input_count,
            .graph_nodes = recorded.nodes.len,
            .graph_outputs = recorded.outputs.len,
        },
        .authority = undefined,
    };
    try result.validateFinalizedRecordingAuthenticatedH1(
        self.manifests,
        self.air_program_ids,
        h1_manifest,
    );
    result.authority = try mintCircuitAuthorityFromValidatedRecording(
        result,
    );
    try result.validateAuthenticatedH1(
        self.manifests,
        self.air_program_ids,
        h1_manifest,
    );

    self.segment_layout.deinit();
    self.binary_layout.deinit();
    if (self.authenticated_h1_empty_layout) |*layout| layout.deinit();
    if (self.canonical_empty_layout) |*layout| layout.deinit();
    self.allocator.free(self.sampled_values);
    self.builder.deinit();
    const allocator = self.allocator;
    self.* = undefined;
    allocator.destroy(self);
    return @ptrCast(result);
}
