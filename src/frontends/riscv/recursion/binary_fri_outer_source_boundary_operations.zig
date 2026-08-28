//! Boundary operations for the authenticated binary FRI source.

pub fn Operations(comptime Context: type) type {
    const Self = Context.Source;

    const AuthenticatedVerifierInputBoundaryFold =
        Context.AuthenticatedVerifierInputBoundaryFoldType;
    const Boundary = Context.BoundaryType;
    const std = Context.std;
    const M31 = Context.M31;
    const QM31 = Context.QM31;
    const relation = Context.relation;
    const composition = Context.composition;
    const composition_input_witness = Context.composition_input_witness;
    const lowering = Context.lowering;
    const universal = Context.universal;
    const CHILD_COUNT = Context.CHILD_COUNT;
    const LEFT_CHILD = Context.LEFT_CHILD;
    const RIGHT_CHILD = Context.RIGHT_CHILD;
    const LEFT_RECURSION_VERIFIER_ID = Context.LEFT_RECURSION_VERIFIER_ID;
    const RIGHT_RECURSION_VERIFIER_ID = Context.RIGHT_RECURSION_VERIFIER_ID;
    const POSEIDON2_PARTIAL_COUNT = Context.POSEIDON2_PARTIAL_COUNT;
    const PHYSICAL_CLAIM_COUNT = Context.PHYSICAL_CLAIM_COUNT;
    const PublicBoundaryEvidence = Context.PublicBoundaryEvidence;
    const AuthenticatedRecorderVerifierInputBoundaryDescriptor = Context.AuthenticatedRecorderVerifierInputBoundaryDescriptor;
    const AuthenticatedRecorderVerifierInputBoundaryEvidence = Context.AuthenticatedRecorderVerifierInputBoundaryEvidence;
    const poseidonPartialClaimRanges = Context.poseidonPartialClaimRanges;
    const hashInt = Context.hashInt;

    return struct {
        pub fn wireBoundaryEvidence(
            self: *const Self,
            relations: *const universal.UniversalRelations,
        ) !PublicBoundaryEvidence {
            try self.requireFullBundleAuthority();
            if (self.shared_arithmetic == null)
                return error.MissingCompositionAuthority;
            const rows = &self.arithmetic_rows.?;
            var tuple_count: u32 = 0;
            var provenance = std.crypto.hash.sha2.Sha256.init(.{});
            provenance.update(
                "stwo-zig/typed-air/binary-wire-public-tuples/v1\x00",
            );
            provenance.update(&rows.reference.authority_digest);
            provenance.update(&rows.plan.authority_digest);
            hashInt(&provenance, u8, @intFromEnum(lowering.Mode.binary));
            for (rows.plan.public_terms) |term| {
                if (term.active_in != .binary) continue;
                tuple_count = std.math.add(u32, tuple_count, 1) catch
                    return error.ArithmeticOverflow;
                hashInt(&provenance, u32, term.lane);
                hashInt(&provenance, u8, @intFromEnum(term.active_in));
                hashInt(&provenance, u8, @intFromEnum(term.role));
                hashInt(&provenance, u32, term.circuit_id);
                hashInt(&provenance, u32, term.node_id);
                for (term.value.toM31Array()) |word|
                    hashInt(&provenance, u32, word.toU32());
                hashInt(&provenance, u32, term.multiplicity);
            }
            if (tuple_count == 0) return error.SourceAuthorityMismatch;
            hashInt(&provenance, u32, tuple_count);
            return .{
                .source_authority_id = rows.authority_digest,
                .snapshot_id = self.source_authority_digest,
                .tuple_provenance_id = provenance.finalResult(),
                .tuple_count = tuple_count,
                .claimed_sum = try rows.plan.publicBoundaryClaim(
                    .binary_node,
                    relations,
                ),
            };
        }

        pub fn verifierInputBoundaryEvidence(
            self: *const Self,
            relations: *const universal.UniversalRelations,
        ) !PublicBoundaryEvidence {
            try self.requireFullBundleAuthority();
            const rows = &self.composition_rows.?;
            const challenge = try relations.getExact(
                .recursion_verifier_input_word,
            );
            var tuple_count: u32 = 0;
            var claim = QM31.zero();
            var provenance = std.crypto.hash.sha2.Sha256.init(.{});
            provenance.update(
                "stwo-zig/typed-air/binary-composition-partial-tuples/v1\x00",
            );
            provenance.update(&rows.input_preprocessing.authority_digest);
            provenance.update(&rows.authority_digest);
            const partial_ranges = try poseidonPartialClaimRanges(rows);
            for (partial_ranges, 0..) |range, child_index| {
                hashInt(&provenance, u32, @as(u32, @intCast(child_index)));
                hashInt(&provenance, u32, range.start);
                hashInt(&provenance, u32, range.end);
            }
            for (
                rows.input_preprocessing.rows,
                rows.schedule_values,
            ) |row, value| {
                const input = switch (row.classification) {
                    .recursion_input => |input| input,
                    else => continue,
                };
                const coordinate = switch (input.source) {
                    .claimed_sum => |coordinate| coordinate,
                    else => continue,
                };
                const child_index: usize = switch (input.verifier_id) {
                    LEFT_RECURSION_VERIFIER_ID => LEFT_CHILD,
                    RIGHT_RECURSION_VERIFIER_ID => RIGHT_CHILD,
                    else => return error.CompositionAuthorityMismatch,
                };
                const range = partial_ranges[child_index];
                if (coordinate.item_index < range.start)
                    continue;
                if (coordinate.item_index >= range.end or
                    coordinate.word_index >= 4)
                {
                    return error.CompositionAuthorityMismatch;
                }
                tuple_count = std.math.add(u32, tuple_count, 1) catch
                    return error.ArithmeticOverflow;
                const tuple = [_]QM31{
                    QM31.fromBase(M31.fromCanonical(input.verifier_id)),
                    QM31.fromBase(M31.fromCanonical(
                        composition_input_witness.RECURSION_CLAIMED_SUM_KIND,
                    )),
                    QM31.fromBase(M31.fromCanonical(coordinate.item_index)),
                    QM31.fromBase(M31.fromCanonical(coordinate.word_index)),
                    QM31.fromBase(value),
                };
                const denominator = try challenge.combineSecure(&tuple);
                claim = claim.add(denominator.inv() catch
                    return error.ZeroDenominator);
                hashInt(&provenance, u32, input.verifier_id);
                hashInt(
                    &provenance,
                    u32,
                    composition_input_witness.RECURSION_CLAIMED_SUM_KIND,
                );
                hashInt(&provenance, u32, coordinate.item_index);
                hashInt(&provenance, u32, coordinate.word_index);
                hashInt(&provenance, u32, value.toU32());
            }
            const expected_count = CHILD_COUNT * POSEIDON2_PARTIAL_COUNT * 4;
            if (tuple_count != expected_count)
                return error.CompositionAuthorityMismatch;
            hashInt(&provenance, u32, tuple_count);
            return .{
                .source_authority_id = rows.authority_digest,
                .snapshot_id = self.source_authority_digest,
                .tuple_provenance_id = provenance.finalResult(),
                .tuple_count = tuple_count,
                .claimed_sum = claim,
            };
        }

        pub fn authenticatedRecorderVerifierInputBoundaryDescriptor(
            self: *const Self,
        ) !AuthenticatedRecorderVerifierInputBoundaryDescriptor {
            if (comptime Boundary.IS_LEGACY) @compileError(
                "recorder verifier-input boundary requires an authenticated boundary",
            );
            const folded = try foldAuthenticatedRecorderVerifierInputs(
                self,
                null,
            );
            return folded.descriptor;
        }

        pub fn authenticatedRecorderVerifierInputBoundaryEvidence(
            self: *const Self,
            relations: *const universal.UniversalRelations,
        ) !AuthenticatedRecorderVerifierInputBoundaryEvidence {
            if (comptime Boundary.IS_LEGACY) @compileError(
                "recorder verifier-input boundary requires an authenticated boundary",
            );
            const challenge = try relations.getExact(
                .recursion_verifier_input_word,
            );
            const folded = try foldAuthenticatedRecorderVerifierInputs(
                self,
                challenge,
            );
            return .{
                .descriptor = folded.descriptor,
                .claimed_sum = folded.claimed_sum,
            };
        }

        fn foldAuthenticatedRecorderVerifierInputs(
            self: *const Self,
            challenge: ?*const universal.Elements,
        ) !AuthenticatedVerifierInputBoundaryFold {
            try self.requireFullBundleAuthority();
            const rows = &self.composition_rows.?;
            const partial_claim_count: u32 = @intCast(
                POSEIDON2_PARTIAL_COUNT,
            );
            var expected = [_][2]u32{.{ 0, 0 }} ** CHILD_COUNT;
            var sample_starts = [_]u32{0} ** CHILD_COUNT;
            var sample_ends = [_]u32{0} ** CHILD_COUNT;
            var seen = [_]bool{false} ** CHILD_COUNT;
            for (rows.reference_storage.recursion_lanes) |lane| {
                const child_index: usize = switch (lane.verifier_id) {
                    LEFT_RECURSION_VERIFIER_ID => LEFT_CHILD,
                    RIGHT_RECURSION_VERIFIER_ID => RIGHT_CHILD,
                    else => return error.CompositionAuthorityMismatch,
                };
                if (seen[child_index])
                    return error.CompositionAuthorityMismatch;
                seen[child_index] = true;
                const capture_sample_count = std.math.cast(
                    u32,
                    self.children[child_index].capture.sampled_values.len,
                ) orelse return error.ArithmeticOverflow;
                if (capture_sample_count > lane.profile.sampled_value_count)
                    return error.CompositionAuthorityMismatch;
                sample_starts[child_index] = capture_sample_count;
                sample_ends[child_index] = lane.profile.sampled_value_count;
                expected[child_index][0] = std.math.mul(
                    u32,
                    lane.profile.sampled_value_count - capture_sample_count,
                    composition_input_witness.SECURE_VALUE_WORD_COUNT,
                ) catch return error.ArithmeticOverflow;
            }
            if (!seen[LEFT_CHILD] or !seen[RIGHT_CHILD])
                return error.CompositionAuthorityMismatch;
            const partial_ranges = try poseidonPartialClaimRanges(rows);
            var inactive_claim_counts = [_]u32{0} ** CHILD_COUNT;
            for (partial_ranges, 0..) |range, child_index| {
                if (PHYSICAL_CLAIM_COUNT > range.start)
                    return error.CompositionAuthorityMismatch;
                inactive_claim_counts[child_index] =
                    range.start - PHYSICAL_CLAIM_COUNT;
                const external_claim_count = std.math.add(
                    u32,
                    inactive_claim_counts[child_index],
                    partial_claim_count,
                ) catch return error.ArithmeticOverflow;
                expected[child_index][1] = std.math.mul(
                    u32,
                    external_claim_count,
                    composition_input_witness.SECURE_VALUE_WORD_COUNT,
                ) catch return error.ArithmeticOverflow;
            }

            var counts = [_][2]u32{.{ 0, 0 }} ** CHILD_COUNT;
            var tuple_count: u32 = 0;
            var claim = QM31.zero();
            var provenance = std.crypto.hash.sha2.Sha256.init(.{});
            provenance.update(
                "stwo-zig/typed-air/authenticated-recorder-external-verifier-input-tuples/v2\x00",
            );
            provenance.update(&rows.input_preprocessing.authority_digest);
            provenance.update(&rows.authority_digest);
            provenance.update(&self.source_authority_digest);
            hashInt(
                &provenance,
                u8,
                @intFromEnum(relation.Domain.recursion_verifier_input_word),
            );
            for (expected, 0..) |lane_counts, child_index| {
                hashInt(&provenance, u32, @as(u32, @intCast(child_index)));
                hashInt(&provenance, u32, sample_starts[child_index]);
                hashInt(&provenance, u32, sample_ends[child_index]);
                hashInt(&provenance, u32, partial_ranges[child_index].start);
                hashInt(&provenance, u32, partial_ranges[child_index].end);
                hashInt(&provenance, u32, PHYSICAL_CLAIM_COUNT);
                hashInt(&provenance, u32, inactive_claim_counts[child_index]);
                hashInt(&provenance, u32, lane_counts[0]);
                hashInt(&provenance, u32, lane_counts[1]);
            }

            const Selected = struct {
                kind: u32,
                coordinate: composition.SecureCoordinate,
                count_index: usize,
            };
            for (
                rows.input_preprocessing.rows,
                rows.schedule_values,
            ) |row, value| {
                const input = switch (row.classification) {
                    .recursion_input => |input| input,
                    else => continue,
                };
                const child_index: usize = switch (input.verifier_id) {
                    LEFT_RECURSION_VERIFIER_ID => LEFT_CHILD,
                    RIGHT_RECURSION_VERIFIER_ID => RIGHT_CHILD,
                    else => return error.CompositionAuthorityMismatch,
                };
                const selected: Selected = switch (input.source) {
                    .sampled_value => |coordinate| blk: {
                        if (coordinate.item_index < sample_starts[child_index])
                            continue;
                        if (coordinate.item_index >= sample_ends[child_index] or
                            !value.isZero())
                        {
                            return error.CompositionAuthorityMismatch;
                        }
                        break :blk .{
                            .kind = composition_input_witness.SAMPLED_VALUE_KIND,
                            .coordinate = coordinate,
                            .count_index = 0,
                        };
                    },
                    .claimed_sum => |coordinate| blk: {
                        const range = partial_ranges[child_index];
                        if (coordinate.item_index < PHYSICAL_CLAIM_COUNT)
                            continue;
                        if (coordinate.item_index < range.start and
                            !value.isZero())
                        {
                            return error.CompositionAuthorityMismatch;
                        }
                        if (coordinate.item_index >= range.end)
                            return error.CompositionAuthorityMismatch;
                        break :blk .{
                            .kind = composition_input_witness
                                .RECURSION_CLAIMED_SUM_KIND,
                            .coordinate = coordinate,
                            .count_index = 1,
                        };
                    },
                    // This exact source has a separately committed internal
                    // provider; treating it as public would double-produce it.
                    .public_wire_boundary => continue,
                    else => continue,
                };
                if (selected.coordinate.word_index >=
                    composition_input_witness.SECURE_VALUE_WORD_COUNT)
                {
                    return error.CompositionAuthorityMismatch;
                }
                counts[child_index][selected.count_index] = std.math.add(
                    u32,
                    counts[child_index][selected.count_index],
                    1,
                ) catch return error.ArithmeticOverflow;
                tuple_count = std.math.add(u32, tuple_count, 1) catch
                    return error.ArithmeticOverflow;

                const tuple = [_]QM31{
                    QM31.fromBase(M31.fromCanonical(input.verifier_id)),
                    QM31.fromBase(M31.fromCanonical(selected.kind)),
                    QM31.fromBase(M31.fromCanonical(
                        selected.coordinate.item_index,
                    )),
                    QM31.fromBase(M31.fromCanonical(
                        selected.coordinate.word_index,
                    )),
                    QM31.fromBase(value),
                };
                if (challenge) |active_challenge| {
                    const denominator = try active_challenge.combineSecure(
                        &tuple,
                    );
                    claim = claim.add(denominator.inv() catch
                        return error.ZeroDenominator);
                }
                hashInt(&provenance, u32, input.verifier_id);
                hashInt(&provenance, u32, selected.kind);
                hashInt(
                    &provenance,
                    u32,
                    selected.coordinate.item_index,
                );
                hashInt(
                    &provenance,
                    u32,
                    selected.coordinate.word_index,
                );
                hashInt(&provenance, u32, value.toU32());
            }
            if (!std.meta.eql(counts, expected))
                return error.CompositionAuthorityMismatch;
            var expected_total: u32 = 0;
            for (expected) |lane_counts| {
                for (lane_counts) |count| {
                    expected_total = std.math.add(
                        u32,
                        expected_total,
                        count,
                    ) catch return error.ArithmeticOverflow;
                }
            }
            if (tuple_count == 0 or tuple_count != expected_total)
                return error.CompositionAuthorityMismatch;
            hashInt(&provenance, u32, tuple_count);
            const descriptor = AuthenticatedRecorderVerifierInputBoundaryDescriptor{
                .boundary = .{
                    .source_authority_id = rows.authority_digest,
                    .snapshot_id = self.source_authority_digest,
                    .tuple_provenance_id = provenance.finalResult(),
                    .tuple_count = tuple_count,
                },
                .capture_sample_counts = sample_starts,
                .recorder_sample_counts = sample_ends,
                .zero_padding_item_counts = .{
                    sample_ends[LEFT_CHILD] - sample_starts[LEFT_CHILD],
                    sample_ends[RIGHT_CHILD] - sample_starts[RIGHT_CHILD],
                },
                .inactive_claim_item_counts = inactive_claim_counts,
                .poseidon_partial_claim_ranges = .{
                    .{
                        .start = partial_ranges[LEFT_CHILD].start,
                        .end = partial_ranges[LEFT_CHILD].end,
                    },
                    .{
                        .start = partial_ranges[RIGHT_CHILD].start,
                        .end = partial_ranges[RIGHT_CHILD].end,
                    },
                },
            };
            try descriptor.validate();
            return .{
                .descriptor = descriptor,
                .claimed_sum = claim,
            };
        }
    };
}
