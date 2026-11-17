//! Failure-atomic allocation, symbolic input binding and pre-publication constraints.

const Root = @import("recursion_air_composition_circuit_heterogeneous_session.zig");
const dependency_0 = @import("recursion_air_composition_circuit_canonical_empty_program.zig");
const dependency_1 = @import("recursion_air_composition_circuit_program_roster.zig");
const dependency_4 = @import("recursion_air_composition_circuit_write_inputs_from_validated_profile_and_policy.zig");
const std = dependency_0.std;
const circle = dependency_0.circle;
const M31 = dependency_0.M31;
const m31 = dependency_0.m31;
const graph_mod = dependency_0.graph_mod;
const recorder = dependency_0.recorder;
const statement_input = dependency_0.statement_input;
const span_statement = dependency_0.span_statement;
const capture_layout_v3 = dependency_0.capture_layout_v3;
const SEGMENT_PHYSICAL_CLAIM_COUNT = dependency_0.SEGMENT_PHYSICAL_CLAIM_COUNT;
const RELATION_CHALLENGE_COUNT = dependency_0.RELATION_CHALLENGE_COUNT;
const STATEMENT_WORD_COUNT = dependency_0.STATEMENT_WORD_COUNT;
const PROGRAM_KIND_COUNT = dependency_0.PROGRAM_KIND_COUNT;
const TrustedManifestsV3 = dependency_0.TrustedManifestsV3;
const AirProgramIdsV3 = dependency_0.AirProgramIdsV3;
const CanonicalEmptyProgramV3 = dependency_0.CanonicalEmptyProgramV3;
const proofKindIndex = dependency_0.proofKindIndex;
const ConfigurationV3 = dependency_1.ConfigurationV3;
const takeSecureRecorderInput = dependency_4.takeSecureRecorderInput;
const reconstructSplitCompositionForLayout = dependency_4.reconstructSplitCompositionForLayout;
const recordClaimPolicyConstraintsForManifestPolicy = dependency_4.recordClaimPolicyConstraintsForManifestPolicy;
const recordCanonicalEmptyProviderConstraints = dependency_4.recordCanonicalEmptyProviderConstraints;
const validateManifests = dependency_4.validateManifests;
const HeterogeneousSessionV3 = Root.HeterogeneousSessionV3;

pub fn create(
    allocator: std.mem.Allocator,
    manifests: TrustedManifestsV3,
    air_program_ids: AirProgramIdsV3,
    segment_capture: anytype,
    binary_capture: anytype,
) !*HeterogeneousSessionV3 {
    return createInner(
        allocator,
        manifests,
        air_program_ids,
        segment_capture,
        binary_capture,
        null,
    );
}

pub fn createWithCanonicalEmpty(
    allocator: std.mem.Allocator,
    manifests: TrustedManifestsV3,
    air_program_ids: AirProgramIdsV3,
    segment_capture: anytype,
    binary_capture: anytype,
    canonical_empty_program: CanonicalEmptyProgramV3,
) !*HeterogeneousSessionV3 {
    return createInner(
        allocator,
        manifests,
        air_program_ids,
        segment_capture,
        binary_capture,
        canonical_empty_program,
    );
}

pub fn createWithAuthenticatedH1(
    allocator: std.mem.Allocator,
    manifests: TrustedManifestsV3,
    air_program_ids: AirProgramIdsV3,
    h1_manifest: anytype,
    segment_capture: anytype,
    h1_capture: anytype,
    universal_empty_capture: anytype,
) !*HeterogeneousSessionV3 {
    return createAuthenticatedH1Inner(
        allocator,
        manifests,
        air_program_ids,
        h1_manifest,
        segment_capture,
        h1_capture,
        universal_empty_capture,
        null,
    );
}

pub fn createWithAuthenticatedH1AndCanonicalEmpty(
    allocator: std.mem.Allocator,
    manifests: TrustedManifestsV3,
    air_program_ids: AirProgramIdsV3,
    h1_manifest: anytype,
    segment_capture: anytype,
    h1_capture: anytype,
    universal_empty_capture: anytype,
    canonical_empty_program: CanonicalEmptyProgramV3,
) !*HeterogeneousSessionV3 {
    return createAuthenticatedH1Inner(
        allocator,
        manifests,
        air_program_ids,
        h1_manifest,
        segment_capture,
        h1_capture,
        universal_empty_capture,
        canonical_empty_program,
    );
}

pub fn createAuthenticatedH1Inner(
    allocator: std.mem.Allocator,
    manifests: TrustedManifestsV3,
    air_program_ids: AirProgramIdsV3,
    h1_manifest: anytype,
    segment_capture: anytype,
    h1_capture: anytype,
    universal_empty_capture: anytype,
    canonical_empty_program: ?CanonicalEmptyProgramV3,
) !*HeterogeneousSessionV3 {
    try validateManifests(manifests);
    var segment_layout = try capture_layout_v3.CaptureLayoutV3.initSegment(
        allocator,
        manifests.segment,
        segment_capture,
    );
    errdefer segment_layout.deinit();
    var binary_layout = try capture_layout_v3.CaptureLayoutV3
        .initAuthenticatedBinaryWithProviderRow(
        allocator,
        .ethereum_poseidon_h1_v1,
        dependency_0.H1_POSEIDON_ROSTER_ROW,
        h1_manifest,
        h1_capture,
    );
    errdefer binary_layout.deinit();
    var empty_layout = try capture_layout_v3.CaptureLayoutV3.initBinary(
        allocator,
        manifests.universal,
        universal_empty_capture,
    );
    errdefer empty_layout.deinit();
    var canonical_empty_layout: ?capture_layout_v3.CanonicalEmptyCaptureLayoutV3 =
        null;
    errdefer if (canonical_empty_layout) |*layout| layout.deinit();
    if (canonical_empty_program) |program| {
        canonical_empty_layout =
            try capture_layout_v3.CanonicalEmptyCaptureLayoutV3.init(
                allocator,
                manifests.universal,
                &empty_layout,
            );
        try program.validateAgainst(
            manifests.universal,
            &empty_layout,
            &canonical_empty_layout.?,
        );
        if (!std.meta.eql(air_program_ids.empty_leaf, program.air_program_id))
            return error.CanonicalEmptyProgramMismatch;
    }
    const sample_authority = try capture_layout_v3.SampleInputAuthorityV3.seal(
        &segment_layout,
        &binary_layout,
    );
    if (empty_layout.sampled_value_count > sample_authority.max_sample_count)
        return error.InvalidHeterogeneousProgram;
    const configuration = if (canonical_empty_program) |program|
        try ConfigurationV3.sealWithAuthenticatedH1AndCanonicalEmpty(
            manifests,
            air_program_ids,
            sample_authority.max_sample_count,
            h1_manifest,
            program,
        )
    else
        try ConfigurationV3.sealWithAuthenticatedH1(
            manifests,
            air_program_ids,
            sample_authority.max_sample_count,
            h1_manifest,
        );
    const profile = configuration.graphInputProfile();
    const input_count = try graph_mod.recursionInputCount(profile);
    if (input_count >= m31.Modulus) return error.InvalidClaimInputProfile;

    const bindings = try allocator.alloc(
        graph_mod.RecursionInputBinding,
        input_count,
    );
    errdefer allocator.free(bindings);
    const sampled_values = try allocator.alloc(
        recorder.Scalar,
        sample_authority.max_sample_count,
    );
    errdefer allocator.free(sampled_values);
    const base_inputs = try allocator.alloc(recorder.Scalar, input_count);
    defer allocator.free(base_inputs);

    const self = try allocator.create(HeterogeneousSessionV3);
    errdefer allocator.destroy(self);
    self.* = .{
        .allocator = allocator,
        .builder = recorder.Builder.init(allocator),
        .bindings = bindings,
        .manifests = manifests,
        .air_program_ids = air_program_ids,
        .configuration = configuration,
        .sample_input_authority = sample_authority,
        .segment_layout = segment_layout,
        .binary_layout = binary_layout,
        .authenticated_h1_empty_layout = empty_layout,
        .canonical_empty_layout = canonical_empty_layout,
        .canonical_empty_program = canonical_empty_program,
        .sampled_values = sampled_values,
        .parent_binary_selector = undefined,
        .child_kind_selectors = undefined,
        .statement_words = undefined,
        .claim_inputs = undefined,
        .public_wire_boundary = undefined,
        .challenges = undefined,
        .composition_randomness = undefined,
        .oods_point = undefined,
        .segment_split_composition = undefined,
        .universal_split_composition = undefined,
        .authenticated_h1_empty_split_composition = undefined,
        .segment_denominators = .{null} ** circle.M31_CIRCLE_LOG_ORDER,
        .universal_denominators = .{null} ** circle.M31_CIRCLE_LOG_ORDER,
        .authenticated_h1_empty_denominators = .{null} ** circle.M31_CIRCLE_LOG_ORDER,
    };
    errdefer self.builder.deinit();

    const program_constraints = std.math.add(
        usize,
        manifests.segment.total_constraints,
        std.math.add(
            usize,
            h1_manifest.total_constraints,
            manifests.universal.total_constraints,
        ) catch return error.InvalidHeterogeneousProgram,
    ) catch return error.InvalidHeterogeneousProgram;
    const empty_provider_hint = if (canonical_empty_program != null)
        STATEMENT_WORD_COUNT + sample_authority.max_sample_count + 1
    else
        0;
    try self.builder.reserve(
        input_count,
        std.math.add(
            usize,
            program_constraints,
            empty_provider_hint,
        ) catch return error.InvalidHeterogeneousProgram,
    );
    for (base_inputs, bindings, 0..) |*value, *binding, index| {
        const input = try self.builder.input();
        const source = graph_mod.expectedRecursionSource(profile, index) orelse
            return error.InvalidHeterogeneousProgram;
        value.* = input.value;
        binding.* = .{ .node_id = input.node_id, .source = source };
    }

    try self.builder.activate();
    errdefer if (self.builder.active) self.builder.deactivate();
    try bindInputs(self, base_inputs, input_count);
    self.segment_split_composition = try reconstructSplitCompositionForLayout(
        &self.segment_layout,
        self.sampled_values[0..self.segment_layout.sampled_value_count],
        self.oods_point,
    );
    self.universal_split_composition = try reconstructSplitCompositionForLayout(
        &self.binary_layout,
        self.sampled_values[0..self.binary_layout.sampled_value_count],
        self.oods_point,
    );
    self.authenticated_h1_empty_split_composition =
        try reconstructSplitCompositionForLayout(
            &self.authenticated_h1_empty_layout.?,
            self.sampled_values[0..empty_layout.sampled_value_count],
            self.oods_point,
        );
    try bindChildKind(self);
    _ = try recordClaimPolicyConstraintsForManifestPolicy(
        &self.builder,
        &self.child_kind_selectors,
        &self.claim_inputs,
        .ethereum_poseidon_h1_v1,
        configuration.program_roster.forKind(.empty_leaf).claim_policy,
    );
    if (canonical_empty_program) |program| _ =
        try recordCanonicalEmptyProviderConstraints(
            &self.builder,
            self.child_kind_selectors[proofKindIndex(.empty_leaf)],
            &self.statement_words,
            self.sampled_values,
            &self.claim_inputs,
            &self.challenges,
            program,
        );
    try constrainGlobalLogup(self);
    try self.builder.check();

    segment_layout = undefined;
    binary_layout = undefined;
    empty_layout = undefined;
    canonical_empty_layout = null;
    return self;
}

pub fn createInner(
    allocator: std.mem.Allocator,
    manifests: TrustedManifestsV3,
    air_program_ids: AirProgramIdsV3,
    segment_capture: anytype,
    binary_capture: anytype,
    canonical_empty_program: ?CanonicalEmptyProgramV3,
) !*HeterogeneousSessionV3 {
    try validateManifests(manifests);
    var segment_layout = try capture_layout_v3.CaptureLayoutV3.initSegment(
        allocator,
        manifests.segment,
        segment_capture,
    );
    errdefer segment_layout.deinit();
    var binary_layout = try capture_layout_v3.CaptureLayoutV3.initBinary(
        allocator,
        manifests.universal,
        binary_capture,
    );
    errdefer binary_layout.deinit();
    var canonical_empty_layout: ?capture_layout_v3.CanonicalEmptyCaptureLayoutV3 =
        null;
    errdefer if (canonical_empty_layout) |*layout| layout.deinit();
    if (canonical_empty_program) |program| {
        canonical_empty_layout =
            try capture_layout_v3.CanonicalEmptyCaptureLayoutV3.init(
                allocator,
                manifests.universal,
                &binary_layout,
            );
        try program.validateAgainst(
            manifests.universal,
            &binary_layout,
            &canonical_empty_layout.?,
        );
        if (!std.meta.eql(air_program_ids.empty_leaf, program.air_program_id))
            return error.CanonicalEmptyProgramMismatch;
    }
    const sample_authority = try capture_layout_v3.SampleInputAuthorityV3.seal(
        &segment_layout,
        &binary_layout,
    );
    const configuration = if (canonical_empty_program) |program|
        try ConfigurationV3.sealWithCanonicalEmpty(
            manifests,
            air_program_ids,
            sample_authority.max_sample_count,
            program,
        )
    else
        try ConfigurationV3.seal(
            manifests,
            air_program_ids,
            sample_authority.max_sample_count,
        );
    const profile = configuration.graphInputProfile();
    const input_count = try graph_mod.recursionInputCount(profile);
    if (input_count >= m31.Modulus) return error.InvalidClaimInputProfile;

    const bindings = try allocator.alloc(
        graph_mod.RecursionInputBinding,
        input_count,
    );
    errdefer allocator.free(bindings);
    const sampled_values = try allocator.alloc(
        recorder.Scalar,
        sample_authority.max_sample_count,
    );
    errdefer allocator.free(sampled_values);
    const base_inputs = try allocator.alloc(recorder.Scalar, input_count);
    defer allocator.free(base_inputs);

    const self = try allocator.create(HeterogeneousSessionV3);
    errdefer allocator.destroy(self);
    self.* = .{
        .allocator = allocator,
        .builder = recorder.Builder.init(allocator),
        .bindings = bindings,
        .manifests = manifests,
        .air_program_ids = air_program_ids,
        .configuration = configuration,
        .sample_input_authority = sample_authority,
        .segment_layout = segment_layout,
        .binary_layout = binary_layout,
        .canonical_empty_layout = canonical_empty_layout,
        .canonical_empty_program = canonical_empty_program,
        .sampled_values = sampled_values,
        .parent_binary_selector = undefined,
        .child_kind_selectors = undefined,
        .statement_words = undefined,
        .claim_inputs = undefined,
        .public_wire_boundary = undefined,
        .challenges = undefined,
        .composition_randomness = undefined,
        .oods_point = undefined,
        .segment_split_composition = undefined,
        .universal_split_composition = undefined,
        .segment_denominators = .{null} ** circle.M31_CIRCLE_LOG_ORDER,
        .universal_denominators = .{null} ** circle.M31_CIRCLE_LOG_ORDER,
    };
    errdefer self.builder.deinit();

    const program_constraints = std.math.add(
        usize,
        manifests.segment.total_constraints,
        std.math.mul(
            usize,
            manifests.universal.total_constraints,
            2,
        ) catch return error.InvalidHeterogeneousProgram,
    ) catch return error.InvalidHeterogeneousProgram;
    const empty_provider_hint = if (canonical_empty_program != null)
        STATEMENT_WORD_COUNT + sample_authority.max_sample_count + 1
    else
        0;
    try self.builder.reserve(
        input_count,
        std.math.add(
            usize,
            program_constraints,
            empty_provider_hint,
        ) catch return error.InvalidHeterogeneousProgram,
    );
    for (base_inputs, bindings, 0..) |*value, *binding, index| {
        const input = try self.builder.input();
        const source = graph_mod.expectedRecursionSource(profile, index) orelse
            return error.InvalidHeterogeneousProgram;
        value.* = input.value;
        binding.* = .{ .node_id = input.node_id, .source = source };
    }

    try self.builder.activate();
    errdefer if (self.builder.active) self.builder.deactivate();

    var cursor: usize = 0;
    self.parent_binary_selector = base_inputs[cursor];
    cursor += 1;
    @memcpy(
        &self.child_kind_selectors,
        base_inputs[cursor..][0..PROGRAM_KIND_COUNT],
    );
    cursor += PROGRAM_KIND_COUNT;
    @memcpy(
        &self.statement_words,
        base_inputs[cursor..][0..STATEMENT_WORD_COUNT],
    );
    cursor += STATEMENT_WORD_COUNT;
    for (self.sampled_values) |*value|
        value.* = takeSecureRecorderInput(base_inputs, &cursor);
    for (&self.claim_inputs) |*value|
        value.* = takeSecureRecorderInput(base_inputs, &cursor);
    self.public_wire_boundary = takeSecureRecorderInput(base_inputs, &cursor);
    var challenge_draws: [RELATION_CHALLENGE_COUNT][2]recorder.Scalar =
        undefined;
    for (&challenge_draws) |*draw| {
        draw[0] = takeSecureRecorderInput(base_inputs, &cursor);
        draw[1] = takeSecureRecorderInput(base_inputs, &cursor);
    }
    self.composition_randomness = takeSecureRecorderInput(base_inputs, &cursor);
    const oods_seed = takeSecureRecorderInput(base_inputs, &cursor);
    if (cursor != input_count) return error.InvalidHeterogeneousProgram;
    self.challenges = try recorder.ChallengeSet.init(challenge_draws);
    self.oods_point = recorder.pointFromSeed(oods_seed);
    self.segment_split_composition = try reconstructSplitCompositionForLayout(
        &self.segment_layout,
        self.sampled_values[0..self.segment_layout.sampled_value_count],
        self.oods_point,
    );
    self.universal_split_composition = try reconstructSplitCompositionForLayout(
        &self.binary_layout,
        self.sampled_values[0..self.binary_layout.sampled_value_count],
        self.oods_point,
    );
    try bindChildKind(self);
    const empty_policy = configuration.program_roster
        .forKind(.empty_leaf).claim_policy;
    const binary_manifest_family = configuration.program_roster
        .forKind(.binary_node).manifest_family;
    _ = try recordClaimPolicyConstraintsForManifestPolicy(
        &self.builder,
        &self.child_kind_selectors,
        &self.claim_inputs,
        binary_manifest_family,
        empty_policy,
    );
    if (canonical_empty_program) |program| _ =
        try recordCanonicalEmptyProviderConstraints(
            &self.builder,
            self.child_kind_selectors[proofKindIndex(.empty_leaf)],
            &self.statement_words,
            self.sampled_values,
            &self.claim_inputs,
            &self.challenges,
            program,
        );
    try constrainGlobalLogup(self);
    try self.builder.check();

    segment_layout = undefined;
    binary_layout = undefined;
    canonical_empty_layout = null;
    return self;
}

pub fn bindInputs(
    self: *HeterogeneousSessionV3,
    base_inputs: []const recorder.Scalar,
    input_count: usize,
) !void {
    var cursor: usize = 0;
    self.parent_binary_selector = base_inputs[cursor];
    cursor += 1;
    @memcpy(
        &self.child_kind_selectors,
        base_inputs[cursor..][0..PROGRAM_KIND_COUNT],
    );
    cursor += PROGRAM_KIND_COUNT;
    @memcpy(
        &self.statement_words,
        base_inputs[cursor..][0..STATEMENT_WORD_COUNT],
    );
    cursor += STATEMENT_WORD_COUNT;
    for (self.sampled_values) |*value|
        value.* = takeSecureRecorderInput(base_inputs, &cursor);
    for (&self.claim_inputs) |*value|
        value.* = takeSecureRecorderInput(base_inputs, &cursor);
    self.public_wire_boundary = takeSecureRecorderInput(base_inputs, &cursor);
    var challenge_draws: [RELATION_CHALLENGE_COUNT][2]recorder.Scalar =
        undefined;
    for (&challenge_draws) |*draw| {
        draw[0] = takeSecureRecorderInput(base_inputs, &cursor);
        draw[1] = takeSecureRecorderInput(base_inputs, &cursor);
    }
    self.composition_randomness = takeSecureRecorderInput(base_inputs, &cursor);
    const oods_seed = takeSecureRecorderInput(base_inputs, &cursor);
    if (cursor != input_count) return error.InvalidHeterogeneousProgram;
    self.challenges = try recorder.ChallengeSet.init(challenge_draws);
    self.oods_point = recorder.pointFromSeed(oods_seed);
}

pub fn bindChildKind(self: *HeterogeneousSessionV3) !void {
    const one = recorder.Scalar.one();
    const segment = self.child_kind_selectors[proofKindIndex(.segment_leaf)];
    const binary = self.child_kind_selectors[proofKindIndex(.binary_node)];
    const empty = self.child_kind_selectors[proofKindIndex(.empty_leaf)];
    try self.builder.constrainZero(
        self.parent_binary_selector.mul(one.sub(self.parent_binary_selector)),
    );
    for (self.child_kind_selectors) |selector|
        try self.builder.constrainZero(selector.mul(one.sub(selector)));
    try self.builder.constrainZero(
        segment.add(binary).add(empty).sub(self.parent_binary_selector),
    );

    const height = self.statement_words[span_statement.canonical_layout.slot_height];
    try constrainActive(self, segment.add(empty).mul(height));
    const safe_height = height.add(one).sub(binary);
    const height_inverse = safe_height.inverse();
    try constrainActive(self, safe_height.mul(height_inverse).sub(one));
    try constrainActive(self, height.mul(height_inverse).sub(binary));

    const body_tag = self.statement_words[
        span_statement.canonical_layout.body_tag
    ];
    try constrainActive(self, segment.mul(body_tag.sub(
        recorder.Scalar.fromBase(M31.fromU64(@intFromEnum(
            span_statement.Tag.executed_body,
        ))),
    )));
    try constrainActive(self, empty.mul(body_tag.sub(
        recorder.Scalar.fromBase(M31.fromU64(@intFromEnum(
            span_statement.Tag.empty_body,
        ))),
    )));
}

pub fn constrainGlobalLogup(self: *HeterogeneousSessionV3) !void {
    const challenge = self.challenges.get(.recursion_statement_word);
    var public_sum = recorder.Scalar.zero();
    const scope = recorder.Scalar.fromBase(M31.fromU64(
        statement_input.PARENT_STATEMENT_SCOPE,
    ));
    for (self.statement_words, 0..) |word, word_index| {
        const tuple = [_]recorder.Scalar{
            scope,
            recorder.Scalar.fromBase(M31.fromU64(word_index)),
            word,
        };
        public_sum = public_sum.add((try challenge.combine(&tuple)).inverse());
    }
    var claimed_total = recorder.Scalar.zero();
    for (self.claim_inputs[0..SEGMENT_PHYSICAL_CLAIM_COUNT]) |claim|
        claimed_total = claimed_total.add(claim);
    const segment = self.child_kind_selectors[proofKindIndex(.segment_leaf)];
    const binary = self.child_kind_selectors[proofKindIndex(.binary_node)];
    const empty = self.child_kind_selectors[proofKindIndex(.empty_leaf)];
    if (self.configuration.program_roster
        .forKind(.binary_node).manifest_family ==
        .ethereum_poseidon_h1_v1)
    {
        // The statement-domain and verifier-input residuals are constants
        // in the authenticated H1 child program. Do not relabel either as
        // this legacy wire-boundary input or duplicate its closure here.
        try self.builder.constrainZero(segment.mul(
            claimed_total.add(self.public_wire_boundary),
        ));
        try self.builder.constrainZero(empty.mul(
            claimed_total.add(public_sum),
        ));
        try self.builder.constrainZero(
            binary.add(empty).mul(self.public_wire_boundary),
        );
        return;
    }
    const universal_branch = self.child_kind_selectors[
        proofKindIndex(.binary_node)
    ].add(empty);
    try self.builder.constrainZero(segment.mul(
        claimed_total.add(self.public_wire_boundary),
    ));
    try self.builder.constrainZero(universal_branch.mul(
        claimed_total.add(public_sum),
    ));
    try self.builder.constrainZero(
        universal_branch.mul(self.public_wire_boundary),
    );
}

pub fn constrainActive(
    self: *HeterogeneousSessionV3,
    value: recorder.Scalar,
) !void {
    try self.builder.constrainZero(self.parent_binary_selector.mul(value));
}
