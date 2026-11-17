//! Manifest-conditioned claim-input admission and recorder constraints.

const Root = @import("recursion_air_composition_circuit_write_inputs_from_validated_profile_and_policy.zig");
const dependency_0 = @import("recursion_air_composition_circuit_canonical_empty_program.zig");
const dependency_5 = @import("recursion_air_composition_circuit_authority_validation.zig");
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const recorder = dependency_0.recorder;
const statement_input = dependency_0.statement_input;
const ProofKind = dependency_0.ProofKind;
const UNIVERSAL_PHYSICAL_CLAIM_COUNT = dependency_0.UNIVERSAL_PHYSICAL_CLAIM_COUNT;
const INITIAL_PHYSICAL_CLAIM_COUNT = Root.INITIAL_PHYSICAL_CLAIM_COUNT;
const POSEIDON_ROSTER_ROW = dependency_0.POSEIDON_ROSTER_ROW;
const POSEIDON_AUX_START = dependency_0.POSEIDON_AUX_START;
const H1_POSEIDON_ROSTER_ROW = dependency_0.H1_POSEIDON_ROSTER_ROW;
const H1_POSEIDON_AUX_START = dependency_0.H1_POSEIDON_AUX_START;
const H1_SEMANTIC_CLAIM_INPUT_COUNT = dependency_0.H1_SEMANTIC_CLAIM_INPUT_COUNT;
const COMPOSITION_CLAIM_INPUT_COUNT = dependency_0.COMPOSITION_CLAIM_INPUT_COUNT;
const STATEMENT_WORD_COUNT = dependency_0.STATEMENT_WORD_COUNT;
const PROGRAM_KIND_COUNT = dependency_0.PROGRAM_KIND_COUNT;
const CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT = dependency_0.CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT;
const CANONICAL_EMPTY_PUBLIC_CLAIM_INDEX = dependency_0.CANONICAL_EMPTY_PUBLIC_CLAIM_INDEX;
const CANONICAL_EMPTY_CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT = dependency_0.CANONICAL_EMPTY_CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT;
const Error = dependency_0.Error;
const ManifestFamilyV3 = dependency_0.ManifestFamilyV3;
const ClaimPolicyV3 = dependency_0.ClaimPolicyV3;
const CanonicalEmptyProgramV3 = dependency_0.CanonicalEmptyProgramV3;
const proofKindIndex = dependency_0.proofKindIndex;
const requireCanonicalQm31 = dependency_5.requireCanonicalQm31;

pub fn validateClaimInputs(
    proof_kind: ProofKind,
    inputs: *const [COMPOSITION_CLAIM_INPUT_COUNT]QM31,
) Error!void {
    for (inputs) |value| try requireCanonicalQm31(value);
    switch (proof_kind) {
        .segment_leaf => {},
        .binary_node => for (inputs[UNIVERSAL_PHYSICAL_CLAIM_COUNT..POSEIDON_AUX_START]) |
            value,
        | if (!value.eql(QM31.zero())) return error.InactiveClaimInputMustBeZero,
        .empty_leaf => for (inputs) |value| if (!value.eql(QM31.zero()))
            return error.EmptyClaimInputMustBeZero,
    }
    if (proof_kind != .empty_leaf and
        !inputs[POSEIDON_AUX_START].add(inputs[POSEIDON_AUX_START + 1]).eql(
            inputs[POSEIDON_ROSTER_ROW],
        ))
    {
        return error.PoseidonPartialMismatch;
    }
}

pub fn validateClaimInputsForPolicy(
    proof_kind: ProofKind,
    policy: ClaimPolicyV3,
    inputs: *const [COMPOSITION_CLAIM_INPUT_COUNT]QM31,
) Error!void {
    if (policy == .ethereum_initial_wrapper_v1) return error.InvalidProgramRoster;
    if (proof_kind != .empty_leaf or policy != .canonical_empty_provider)
        return validateClaimInputs(proof_kind, inputs);
    for (inputs, 0..) |value, index| {
        try requireCanonicalQm31(value);
        if (index != CANONICAL_EMPTY_PUBLIC_CLAIM_INDEX and
            !value.eql(QM31.zero()))
        {
            return error.EmptyClaimInputMustBeZero;
        }
    }
}

pub fn validateClaimInputsForManifestPolicy(
    proof_kind: ProofKind,
    manifest_family: ManifestFamilyV3,
    policy: ClaimPolicyV3,
    inputs: *const [COMPOSITION_CLAIM_INPUT_COUNT]QM31,
) Error!void {
    if (manifest_family == .ethereum_initial_wrapper_v1) {
        if (proof_kind != .binary_node or policy != .ethereum_initial_wrapper_v1)
            return error.InvalidProgramRoster;
        for (inputs) |value| try requireCanonicalQm31(value);
        for (inputs[INITIAL_PHYSICAL_CLAIM_COUNT..POSEIDON_AUX_START]) |value|
            if (!value.eql(QM31.zero())) return error.InactiveClaimInputMustBeZero;
        if (!inputs[POSEIDON_AUX_START].add(inputs[POSEIDON_AUX_START + 1]).eql(inputs[POSEIDON_ROSTER_ROW]))
            return error.PoseidonPartialMismatch;
        return;
    }
    if (policy == .ethereum_initial_wrapper_v1) return error.InvalidProgramRoster;
    if (manifest_family == .common_fold_field_v2) {
        if (proof_kind != .binary_node or
            policy != .common_fold_field_v2)
        {
            return error.InvalidProgramRoster;
        }
        return validateClaimInputs(.binary_node, inputs);
    }
    if (manifest_family == .temporal_parent_v3) {
        if (proof_kind != .binary_node or policy != .temporal_parent)
            return error.InvalidProgramRoster;
        return validateClaimInputs(.binary_node, inputs);
    }
    if (manifest_family != .ethereum_poseidon_h1_v1)
        return validateClaimInputsForPolicy(proof_kind, policy, inputs);
    if (proof_kind != .binary_node or policy != .ethereum_poseidon_h1)
        return error.InvalidProgramRoster;
    for (inputs) |value| try requireCanonicalQm31(value);
    for (inputs[H1_SEMANTIC_CLAIM_INPUT_COUNT..]) |value|
        if (!value.eql(QM31.zero()))
            return error.InactiveClaimInputMustBeZero;
    if (!inputs[H1_POSEIDON_AUX_START].add(
        inputs[H1_POSEIDON_AUX_START + 1],
    ).eql(inputs[H1_POSEIDON_ROSTER_ROW]))
        return error.PoseidonPartialMismatch;
}

pub fn recordClaimPolicyConstraints(
    builder: *recorder.Builder,
    proof_kind_selectors: *const [PROGRAM_KIND_COUNT]recorder.Scalar,
    claim_inputs: *const [COMPOSITION_CLAIM_INPUT_COUNT]recorder.Scalar,
) Error!usize {
    return recordClaimPolicyConstraintsForPolicy(
        builder,
        proof_kind_selectors,
        claim_inputs,
        .canonical_empty,
    );
}

pub fn recordClaimPolicyConstraintsForPolicy(
    builder: *recorder.Builder,
    proof_kind_selectors: *const [PROGRAM_KIND_COUNT]recorder.Scalar,
    claim_inputs: *const [COMPOSITION_CLAIM_INPUT_COUNT]recorder.Scalar,
    empty_policy: ClaimPolicyV3,
) Error!usize {
    if (empty_policy == .ethereum_initial_wrapper_v1) return error.InvalidProgramRoster;
    const segment = proof_kind_selectors[proofKindIndex(.segment_leaf)];
    const binary = proof_kind_selectors[proofKindIndex(.binary_node)];
    const empty = proof_kind_selectors[proofKindIndex(.empty_leaf)];

    for (claim_inputs[UNIVERSAL_PHYSICAL_CLAIM_COUNT..POSEIDON_AUX_START]) |
        claim,
    | try builder.constrainZero(binary.mul(claim));
    for (claim_inputs, 0..) |claim, index| {
        if (empty_policy == .canonical_empty_provider and
            index == CANONICAL_EMPTY_PUBLIC_CLAIM_INDEX) continue;
        try builder.constrainZero(empty.mul(claim));
    }

    const partial_closure = claim_inputs[POSEIDON_AUX_START]
        .add(claim_inputs[POSEIDON_AUX_START + 1])
        .sub(claim_inputs[POSEIDON_ROSTER_ROW]);
    try builder.constrainZero(segment.add(binary).mul(partial_closure));
    try builder.check();
    return if (empty_policy == .canonical_empty_provider)
        CANONICAL_EMPTY_CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT
    else
        CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT;
}

pub fn recordClaimPolicyConstraintsForManifestPolicy(
    builder: *recorder.Builder,
    proof_kind_selectors: *const [PROGRAM_KIND_COUNT]recorder.Scalar,
    claim_inputs: *const [COMPOSITION_CLAIM_INPUT_COUNT]recorder.Scalar,
    binary_manifest_family: ManifestFamilyV3,
    empty_policy: ClaimPolicyV3,
) Error!usize {
    if (binary_manifest_family == .ethereum_initial_wrapper_v1) {
        if (empty_policy != .ethereum_initial_wrapper_v1) return error.InvalidProgramRoster;
        const segment = proof_kind_selectors[proofKindIndex(.segment_leaf)];
        const binary = proof_kind_selectors[proofKindIndex(.binary_node)];
        const empty = proof_kind_selectors[proofKindIndex(.empty_leaf)];
        for (claim_inputs[INITIAL_PHYSICAL_CLAIM_COUNT..POSEIDON_AUX_START]) |claim|
            try builder.constrainZero(binary.mul(claim));
        for (claim_inputs) |claim| try builder.constrainZero(empty.mul(claim));
        const partial_closure = claim_inputs[POSEIDON_AUX_START].add(claim_inputs[POSEIDON_AUX_START + 1]).sub(claim_inputs[POSEIDON_ROSTER_ROW]);
        try builder.constrainZero(segment.add(binary).mul(partial_closure));
        try builder.check();
        return (POSEIDON_AUX_START - INITIAL_PHYSICAL_CLAIM_COUNT) + COMPOSITION_CLAIM_INPUT_COUNT + 1;
    }
    if (empty_policy == .ethereum_initial_wrapper_v1) return error.InvalidProgramRoster;
    if (binary_manifest_family == .common_fold_field_v2) {
        if (empty_policy != .common_fold_field_v2)
            return error.InvalidProgramRoster;
        return recordClaimPolicyConstraintsForPolicy(
            builder,
            proof_kind_selectors,
            claim_inputs,
            .canonical_empty,
        );
    }
    if (binary_manifest_family == .temporal_parent_v3) {
        if (empty_policy != .temporal_parent)
            return error.InvalidProgramRoster;
        return recordClaimPolicyConstraintsForPolicy(
            builder,
            proof_kind_selectors,
            claim_inputs,
            .canonical_empty,
        );
    }
    if (binary_manifest_family != .ethereum_poseidon_h1_v1)
        return recordClaimPolicyConstraintsForPolicy(
            builder,
            proof_kind_selectors,
            claim_inputs,
            empty_policy,
        );
    const segment = proof_kind_selectors[proofKindIndex(.segment_leaf)];
    const binary = proof_kind_selectors[proofKindIndex(.binary_node)];
    const empty = proof_kind_selectors[proofKindIndex(.empty_leaf)];
    for (claim_inputs[H1_SEMANTIC_CLAIM_INPUT_COUNT..]) |claim|
        try builder.constrainZero(binary.mul(claim));
    for (claim_inputs, 0..) |claim, index| {
        if (empty_policy == .canonical_empty_provider and
            index == CANONICAL_EMPTY_PUBLIC_CLAIM_INDEX) continue;
        try builder.constrainZero(empty.mul(claim));
    }
    const segment_partial_closure = claim_inputs[POSEIDON_AUX_START]
        .add(claim_inputs[POSEIDON_AUX_START + 1])
        .sub(claim_inputs[POSEIDON_ROSTER_ROW]);
    try builder.constrainZero(segment.mul(segment_partial_closure));
    const h1_partial_closure = claim_inputs[H1_POSEIDON_AUX_START]
        .add(claim_inputs[H1_POSEIDON_AUX_START + 1])
        .sub(claim_inputs[H1_POSEIDON_ROSTER_ROW]);
    try builder.constrainZero(binary.mul(h1_partial_closure));
    try builder.check();
    const empty_count: usize = if (empty_policy == .canonical_empty_provider)
        COMPOSITION_CLAIM_INPUT_COUNT - 1
    else
        COMPOSITION_CLAIM_INPUT_COUNT;
    return (COMPOSITION_CLAIM_INPUT_COUNT -
        H1_SEMANTIC_CLAIM_INPUT_COUNT) + empty_count + 2;
}

pub fn recordCanonicalEmptyProviderConstraints(
    builder: *recorder.Builder,
    empty_selector: recorder.Scalar,
    statement_words: *const [STATEMENT_WORD_COUNT]recorder.Scalar,
    sampled_values: []const recorder.Scalar,
    claim_inputs: *const [COMPOSITION_CLAIM_INPUT_COUNT]recorder.Scalar,
    challenges: *const recorder.ChallengeSet,
    program: CanonicalEmptyProgramV3,
) Error!usize {
    for (statement_words, program.statement_words) |actual, expected| {
        try builder.constrainZero(empty_selector.mul(actual.sub(
            recorder.Scalar.fromBase(expected),
        )));
    }
    for (sampled_values) |sample|
        try builder.constrainZero(empty_selector.mul(sample));

    const challenge = challenges.get(.recursion_statement_word);
    const scope = recorder.Scalar.fromBase(M31.fromU64(
        statement_input.PARENT_STATEMENT_SCOPE,
    ));
    var public_sum = recorder.Scalar.zero();
    for (statement_words, 0..) |word, word_index| {
        const tuple = [_]recorder.Scalar{
            scope,
            recorder.Scalar.fromBase(M31.fromU64(word_index)),
            word,
        };
        public_sum = public_sum.add((try challenge.combine(&tuple)).inverse());
    }
    try builder.constrainZero(empty_selector.mul(
        claim_inputs[CANONICAL_EMPTY_PUBLIC_CLAIM_INDEX].add(public_sum),
    ));
    try builder.check();
    return STATEMENT_WORD_COUNT + sampled_values.len + 1;
}
