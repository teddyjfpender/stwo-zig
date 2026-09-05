//! Internal shard of binary_fri_outer_source.zig; use the public facade.

const dependency_0 = @import("binary_fri_outer_source_claims.zig");
const dependency_1 = @import("binary_fri_outer_source_trusted_composition_profile_v1.zig");
const dependency_2 = @import("binary_fri_outer_source_composition_rows_authority.zig");
const dependency_7 = @import("binary_fri_outer_source_materialize_child_paths.zig");
const dependency_9 = @import("binary_fri_outer_source_validate_captured_against_wire.zig");

const std = dependency_0.std;
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const captured_fri = dependency_0.captured_fri;
const pair_node = dependency_0.pair_node;
const composition = dependency_0.composition;
const lowering = dependency_0.lowering;
const schedule = dependency_0.schedule;
const framework = dependency_0.framework;
const CHILD_COUNT = dependency_0.CHILD_COUNT;
const LEFT_CHILD = dependency_0.LEFT_CHILD;
const RIGHT_CHILD = dependency_0.RIGHT_CHILD;
const LEFT_RECURSION_VERIFIER_ID = dependency_0.LEFT_RECURSION_VERIFIER_ID;
const RIGHT_RECURSION_VERIFIER_ID = dependency_0.RIGHT_RECURSION_VERIFIER_ID;
const UNIVERSAL_CLAIMED_SUM_COUNT = dependency_0.UNIVERSAL_CLAIMED_SUM_COUNT;
const POSEIDON2_ROSTER_ROW = dependency_0.POSEIDON2_ROSTER_ROW;
const POSEIDON2_PARTIAL_COUNT = dependency_0.POSEIDON2_PARTIAL_COUNT;
const COMPOSITION_CLAIMED_SUM_COUNT = dependency_0.COMPOSITION_CLAIMED_SUM_COUNT;
const POSEIDON2_PARTIAL_CLAIM_START = dependency_0.POSEIDON2_PARTIAL_CLAIM_START;
const POSEIDON2_INTERACTION_COLUMN_COUNT = dependency_0.POSEIDON2_INTERACTION_COLUMN_COUNT;
const POSEIDON2_PROVIDER_SAMPLE_COUNT = dependency_0.POSEIDON2_PROVIDER_SAMPLE_COUNT;
const TrustedCompositionProfileV1 = dependency_1.TrustedCompositionProfileV1;
const compositionStatementScope = dependency_1.compositionStatementScope;
const CompositionRowsAuthority = dependency_2.CompositionRowsAuthority;
const copyColumns = dependency_7.copyColumns;
const qm31FromCanonicalWords = dependency_9.qm31FromCanonicalWords;

/// Tree 0/1 workspaces retain logical row order because their witness
/// executors and custody validators operate over logical schedules. PCS
/// commitments consume the bit-reversed circle-domain order, so publication
/// must scatter exactly once at this boundary. Tree 2 is already emitted in
/// commitment order by `framework_interaction` and deliberately keeps using
/// `copyColumns`.
pub fn scatterColumnsToCommitmentOrder(destination: [][]M31, source: anytype) void {
    std.debug.assert(destination.len == source.len);
    var first_column: usize = 0;
    while (first_column < source.len) {
        const trace_size = source[first_column].len;
        std.debug.assert(trace_size != 0 and std.math.isPowerOfTwo(trace_size));
        var column_end = first_column + 1;
        while (column_end < source.len and
            source[column_end].len == trace_size)
        {
            column_end += 1;
        }
        for (
            destination[first_column..column_end],
            source[first_column..column_end],
        ) |target, values| std.debug.assert(target.len == values.len);

        // Compute the permutation once per equal-log family, not once per
        // column. Wide recursive rows have dozens of columns, so this keeps
        // publication memory-bandwidth-bound instead of bit-reversal-bound.
        const log_size: u32 = @intCast(std.math.log2_int(usize, trace_size));
        for (0..trace_size) |logical_row| {
            const committed_row = framework.committedRow(logical_row, log_size);
            for (
                destination[first_column..column_end],
                source[first_column..column_end],
            ) |target, values| {
                target[committed_row] = values[logical_row];
            }
        }
        first_column = column_end;
    }
}

pub fn columnArray(
    comptime count: usize,
    columns: anytype,
    offset: usize,
) *[count][]M31 {
    std.debug.assert(offset <= columns.len and count <= columns.len - offset);
    return @ptrCast(columns[offset..].ptr);
}

pub fn typedSlicesOverlap(
    comptime Left: type,
    left: []const Left,
    comptime Right: type,
    right: []const Right,
) bool {
    return bytesOverlap(std.mem.sliceAsBytes(left), std.mem.sliceAsBytes(right));
}

pub fn bytesOverlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = left_start + left.len;
    const right_end = right_start + right.len;
    return left_start < right_end and right_start < left_end;
}

pub fn validatePairBoundary(
    pair: anytype,
    root_pin: pair_node.RootVkPinV1,
    vm_plan: *const schedule.Plan,
    recursion_plans: [2]*const schedule.Plan,
) !void {
    try vm_plan.validate();
    try recursion_plans[0].validate();
    try recursion_plans[1].validate();
    if (vm_plan.schema != .vm or
        recursion_plans[0].schema != .recursion or
        recursion_plans[1].schema != .recursion or
        !std.meta.eql(recursion_plans[0].authority_digest, pair.plan_digest) or
        !std.meta.eql(recursion_plans[1].authority_digest, pair.plan_digest))
    {
        return error.PlanMismatch;
    }
    try root_pin.validate();
    try pair.authority.validate();
    try pair.record.validate();
    const authenticated = try pair_node.authenticateRoot(
        &pair.authority,
        &pair.record,
        &root_pin,
    );
    if (!std.meta.eql(authenticated, pair.authenticated_root))
        return error.PairAuthorityMismatch;
    for (&pair.authority.children, 0..) |*child, child_index| {
        const expected_position: pair_node.ChildPosition = if (child_index == LEFT_CHILD)
            .left
        else
            .right;
        if (child.position != expected_position)
            return error.ChildOrderMismatch;
    }
}

pub fn validateChildProfiles(children: anytype) !void {
    const left = children[LEFT_CHILD];
    const right = children[RIGHT_CHILD];
    if ((left.composition != null) != (right.composition != null) or
        (left.trusted_composition_profile != null) !=
            (right.trusted_composition_profile != null) or
        !std.meta.eql(left.shape, right.shape) or
        !std.mem.eql(
            u8,
            &left.capture.circuit.profile_digest,
            &right.capture.circuit.profile_digest,
        ) or
        !std.mem.eql(
            u8,
            &left.capture.circuit.identity_digest,
            &right.capture.circuit.identity_digest,
        ) or
        !std.mem.eql(
            u8,
            &left.capture.pcs_circuit.profile_digest,
            &right.capture.pcs_circuit.profile_digest,
        ) or
        !std.mem.eql(
            u8,
            &left.capture.pcs_circuit.identity_digest,
            &right.capture.pcs_circuit.identity_digest,
        ))
    {
        return error.ProfileMismatch;
    }
}

pub fn validateCompositionInputs(
    pair: anytype,
    child: anytype,
    child_index: usize,
    trusted: TrustedCompositionProfileV1,
) !void {
    try trusted.validate();
    if (!trusted.row18_input_authority or child_index >= CHILD_COUNT)
        return error.MissingCompositionAuthority;
    const authority = child.composition orelse
        return error.MissingCompositionAuthority;
    if (!std.mem.eql(
        u8,
        &authority.trusted_profile_digest,
        &trusted.profile_digest,
    ) or !std.mem.eql(
        u8,
        &authority.graph.identity_digest,
        &trusted.graph_identity,
    ) or authority.evaluation.values.len != authority.graph.nodes.len or
        trusted.input_profile.sampled_value_count != child.capture.sampled_values.len or
        trusted.input_profile.claimed_sum_count != COMPOSITION_CLAIMED_SUM_COUNT or
        child.wire.claimed_sums.len != UNIVERSAL_CLAIMED_SUM_COUNT or
        trusted.input_profile.relation_challenge_count !=
            pair.executions[child_index].relationChallengeCount())
    {
        return error.CompositionAuthorityMismatch;
    }
    const wire_poseidon_total = qm31FromCanonicalWords(
        child.wire.claimed_sums[POSEIDON2_ROSTER_ROW],
    ) catch return error.CompositionAuthorityMismatch;
    if (!authority.poseidon2_roster_total.eql(wire_poseidon_total) or
        !wire_poseidon_total.eql(
            authority.poseidon2_partials[0].add(
                authority.poseidon2_partials[1],
            ),
        ))
    {
        return error.CompositionAuthorityMismatch;
    }
    try validatePoseidon2CaptureGeometry(child.capture, trusted);
    try validateGraphEvaluation(authority.graph, authority.evaluation);
    for (trusted.input_bindings) |binding| {
        const node_id: usize = @intCast(binding.node_id);
        if (node_id >= authority.graph.nodes.len or
            std.meta.activeTag(authority.graph.nodes[node_id].op) != .input)
        {
            return error.CompositionAuthorityMismatch;
        }
        const actual = authority.evaluation.values[node_id].tryIntoM31() catch
            return error.CompositionAuthorityMismatch;
        const expected = try compositionSourceValue(
            pair,
            child,
            child_index,
            trusted,
            binding.source,
        );
        if (!actual.eql(expected)) return error.CompositionAuthorityMismatch;
    }
}

pub fn validatePoseidon2CaptureGeometry(
    capture: *const captured_fri.Owned,
    trusted: TrustedCompositionProfileV1,
) !void {
    const start: usize = @intCast(trusted.poseidon2_sample_layout_start);
    const end = std.math.add(
        usize,
        start,
        POSEIDON2_INTERACTION_COLUMN_COUNT,
    ) catch return error.CompositionAuthorityMismatch;
    if (end > capture.sample_layouts.len or
        capture.sampled_values.len < POSEIDON2_PROVIDER_SAMPLE_COUNT)
    {
        return error.CompositionAuthorityMismatch;
    }
    for (capture.sample_layouts[start..end]) |layout|
        if (layout != .current_previous)
            return error.CompositionAuthorityMismatch;
}

pub fn compositionSourceValue(
    pair: anytype,
    child: anytype,
    child_index: usize,
    trusted: TrustedCompositionProfileV1,
    source: composition.RecursionSource,
) !M31 {
    return switch (source) {
        .parent_binary_selector => M31.one(),
        .child_kind_selector => |kind| M31.fromCanonical(
            @intFromBool(kind == trusted.child_proof_kind),
        ),
        .statement_word => |word| blk: {
            const words = if (child_index == LEFT_CHILD)
                &pair.left_words
            else
                &pair.right_words;
            if (word >= words.len) return error.CompositionAuthorityMismatch;
            break :blk words[word];
        },
        .sampled_value => |coordinate| blk: {
            if (coordinate.item_index >= child.capture.sampled_values.len or
                coordinate.word_index >= 4)
            {
                return error.CompositionAuthorityMismatch;
            }
            break :blk child.capture.sampled_values[coordinate.item_index]
                .toM31Array()[coordinate.word_index];
        },
        .claimed_sum => |coordinate| blk: {
            if (coordinate.word_index >= 4)
                return error.CompositionAuthorityMismatch;
            const item_index: usize = @intCast(coordinate.item_index);
            if (item_index < UNIVERSAL_CLAIMED_SUM_COUNT) {
                break :blk M31.fromCanonical(
                    child.wire.claimed_sums[item_index][coordinate.word_index],
                );
            }
            if (item_index >= COMPOSITION_CLAIMED_SUM_COUNT)
                return error.CompositionAuthorityMismatch;
            const authority = child.composition orelse
                return error.MissingCompositionAuthority;
            break :blk authority.poseidon2_partials[
                item_index - POSEIDON2_PARTIAL_CLAIM_START
            ].toM31Array()[coordinate.word_index];
        },
        // Frozen binary captures do not retain a distinct canonical
        // transcript-claim vector. A nonzero append-only recursion profile
        // must arrive through the typed Ethereum bridge instead of silently
        // aliasing declaration-ordered claims.
        .transcript_claimed_sum => error.CompositionAuthorityMismatch,
        .public_wire_boundary => error.CompositionAuthorityMismatch,
        .relation_challenge => |coordinate| blk: {
            var challenge_at: usize = 0;
            for (pair.executions[child_index].operations) |operation| switch (operation.step) {
                .draw_relation_challenge => {
                    if (challenge_at == coordinate.challenge) {
                        const draw = operation.draw orelse
                            return error.CompositionAuthorityMismatch;
                        if (coordinate.word_index >= draw.len)
                            return error.CompositionAuthorityMismatch;
                        break :blk draw[coordinate.word_index];
                    }
                    challenge_at += 1;
                },
                else => {},
            };
            return error.CompositionAuthorityMismatch;
        },
        .composition_randomness => |word| blk: {
            if (word >= 4) return error.CompositionAuthorityMismatch;
            break :blk child.capture.composition_randomness.toM31Array()[word];
        },
        .oods_point => |word| blk: {
            if (word >= 4) return error.CompositionAuthorityMismatch;
            break :blk child.capture.oods_seed.toM31Array()[word];
        },
    };
}

pub fn validateGraphEvaluation(
    graph: composition.CircuitGraph,
    evaluation: lowering.Evaluation,
) !void {
    try graph.validate();
    if (!std.mem.eql(
        u8,
        &graph.identity_digest,
        &evaluation.circuit_identity,
    ) or evaluation.values.len != graph.nodes.len) {
        return error.CompositionAuthorityMismatch;
    }
    for (graph.nodes, 0..) |node, node_id| {
        const expected = switch (node.op) {
            .input => continue,
            .constant => |words| QM31.fromM31Array(.{
                M31.fromCanonical(words[0]),
                M31.fromCanonical(words[1]),
                M31.fromCanonical(words[2]),
                M31.fromCanonical(words[3]),
            }),
            .add => |operands| evaluation.values[operands.lhs].add(
                evaluation.values[operands.rhs],
            ),
            .sub => |operands| evaluation.values[operands.lhs].sub(
                evaluation.values[operands.rhs],
            ),
            .mul => |operands| evaluation.values[operands.lhs].mul(
                evaluation.values[operands.rhs],
            ),
            .neg => |operand| evaluation.values[operand].neg(),
            .inverse => |operand| evaluation.values[operand].inv() catch
                return error.CompositionAuthorityMismatch,
        };
        if (!expected.eql(evaluation.values[node_id]))
            return error.CompositionAuthorityMismatch;
    }
    for (graph.outputs) |output| if (!evaluation.values[output].isZero())
        return error.CompositionAuthorityMismatch;
}

pub const ClaimRange = struct {
    start: u32,
    end: u32,
};

/// Frozen V1 places the two Poseidon partials at claims 36/37. Authenticated
/// recorder lanes may carry a wider component roster, so select the same two
/// trailing partial claims from each sealed lane profile without projecting
/// that profile back to V1's claim count.
pub fn poseidonPartialClaimRanges(
    rows: *const CompositionRowsAuthority,
) ![CHILD_COUNT]ClaimRange {
    var ranges: [CHILD_COUNT]ClaimRange = undefined;
    var seen = [_]bool{false} ** CHILD_COUNT;
    for (rows.reference_storage.recursion_lanes) |lane| {
        const child_index: usize = switch (lane.verifier_id) {
            LEFT_RECURSION_VERIFIER_ID => LEFT_CHILD,
            RIGHT_RECURSION_VERIFIER_ID => RIGHT_CHILD,
            else => return error.CompositionAuthorityMismatch,
        };
        const partial_count: u32 = POSEIDON2_PARTIAL_COUNT;
        if (seen[child_index] or lane.profile.claimed_sum_count < partial_count)
            return error.CompositionAuthorityMismatch;
        ranges[child_index] = .{
            .start = lane.profile.claimed_sum_count - partial_count,
            .end = lane.profile.claimed_sum_count,
        };
        seen[child_index] = true;
    }
    if (!seen[LEFT_CHILD] or !seen[RIGHT_CHILD])
        return error.CompositionAuthorityMismatch;
    return ranges;
}

pub fn materializeRecorderScheduleValues(
    evaluations: [CHILD_COUNT]lowering.Evaluation,
    rows: []const composition.Row,
    destination: []M31,
) !void {
    if (destination.len != rows.len)
        return error.DestinationShapeMismatch;
    for (rows, destination) |row, *value| value.* = switch (row.classification) {
        .vm_input => M31.zero(),
        .recursion_input => |input| blk: {
            const child_index: usize = switch (input.verifier_id) {
                LEFT_RECURSION_VERIFIER_ID => LEFT_CHILD,
                RIGHT_RECURSION_VERIFIER_ID => RIGHT_CHILD,
                else => return error.CompositionAuthorityMismatch,
            };
            if (input.statement_scope != compositionStatementScope(child_index) or
                row.node_id >= evaluations[child_index].values.len)
            {
                return error.CompositionAuthorityMismatch;
            }
            break :blk evaluations[child_index].values[row.node_id]
                .tryIntoM31() catch return error.CompositionAuthorityMismatch;
        },
        .constant_anchor, .output_anchor => M31.zero(),
    };
}

pub fn validateRecorderScheduleValues(
    evaluations: [CHILD_COUNT]lowering.Evaluation,
    rows: []const composition.Row,
    values: []const M31,
) !void {
    if (rows.len != values.len) return error.SourceAuthorityMismatch;
    for (rows, values) |row, value| {
        const expected = switch (row.classification) {
            .vm_input => M31.zero(),
            .recursion_input => |input| blk: {
                const child_index: usize = switch (input.verifier_id) {
                    LEFT_RECURSION_VERIFIER_ID => LEFT_CHILD,
                    RIGHT_RECURSION_VERIFIER_ID => RIGHT_CHILD,
                    else => return error.CompositionAuthorityMismatch,
                };
                if (input.statement_scope != compositionStatementScope(child_index) or
                    row.node_id >= evaluations[child_index].values.len)
                {
                    return error.CompositionAuthorityMismatch;
                }
                break :blk evaluations[child_index].values[row.node_id]
                    .tryIntoM31() catch return error.CompositionAuthorityMismatch;
            },
            .constant_anchor, .output_anchor => M31.zero(),
        };
        if (!value.eql(expected)) return error.SourceAuthorityMismatch;
    }
}

pub fn materializeCompositionScheduleValues(
    pair: anytype,
    children: anytype,
    rows: []const composition.Row,
    destination: []M31,
) !void {
    if (destination.len != rows.len)
        return error.DestinationShapeMismatch;
    for (children, 0..) |child, child_index| {
        const trusted = child.trusted_composition_profile orelse
            return error.MissingCompositionAuthority;
        try validateCompositionInputs(pair, child, child_index, trusted);
    }
    for (rows, destination) |row, *value| value.* = switch (row.classification) {
        .vm_input => M31.zero(),
        .recursion_input => |input| blk: {
            const child_index: usize = switch (input.verifier_id) {
                LEFT_RECURSION_VERIFIER_ID => LEFT_CHILD,
                RIGHT_RECURSION_VERIFIER_ID => RIGHT_CHILD,
                else => return error.CompositionAuthorityMismatch,
            };
            if (input.statement_scope != compositionStatementScope(child_index))
                return error.CompositionAuthorityMismatch;
            const authority = children[child_index].composition orelse
                return error.MissingCompositionAuthority;
            if (row.node_id >= authority.evaluation.values.len)
                return error.CompositionAuthorityMismatch;
            break :blk authority.evaluation.values[row.node_id].tryIntoM31() catch
                return error.CompositionAuthorityMismatch;
        },
        .constant_anchor, .output_anchor => M31.zero(),
    };
}

pub fn validateCompositionScheduleValues(
    pair: anytype,
    children: anytype,
    rows: []const composition.Row,
    values: []const M31,
) !void {
    if (rows.len != values.len) return error.SourceAuthorityMismatch;
    for (rows, values) |row, value| {
        const expected = switch (row.classification) {
            .vm_input => M31.zero(),
            .recursion_input => |input| blk: {
                const child_index: usize = switch (input.verifier_id) {
                    LEFT_RECURSION_VERIFIER_ID => LEFT_CHILD,
                    RIGHT_RECURSION_VERIFIER_ID => RIGHT_CHILD,
                    else => return error.CompositionAuthorityMismatch,
                };
                if (input.statement_scope != compositionStatementScope(child_index))
                    return error.CompositionAuthorityMismatch;
                const trusted = children[child_index]
                    .trusted_composition_profile orelse
                    return error.MissingCompositionAuthority;
                const expected_input = try compositionSourceValue(
                    pair,
                    children[child_index],
                    child_index,
                    trusted,
                    input.source,
                );
                break :blk expected_input;
            },
            .constant_anchor, .output_anchor => M31.zero(),
        };
        if (!value.eql(expected)) return error.SourceAuthorityMismatch;
    }
}
