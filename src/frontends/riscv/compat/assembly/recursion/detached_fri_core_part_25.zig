//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const QM31 = context.d_QM31;
        const recursion = context.d_recursion;
        const global_closure = context.d_global_closure;
        const air = context.d_air;
        const schedule = context.d_schedule;
        const lowering = context.d_lowering;
        const manifest_mod = context.d_manifest_mod;
        const universal = context.d_universal;
        const framework = context.d_framework;
        const V2_ROWS_18_35_PREFLIGHT_ID_DOMAIN = context.d_V2_ROWS_18_35_PREFLIGHT_ID_DOMAIN;
        const Error = context.d_Error;
        const TupleClosureReport = context.d_TupleClosureReport;
        const V2Rows18Through35PreflightReceipt = context.d_V2Rows18Through35PreflightReceipt;
        const PublicBoundaryClaims = context.d_PublicBoundaryClaims;
        const Claims = context.d_Claims;
        const RelationDomain = context.d_RelationDomain;
        const TupleLedger = context.d_TupleLedger;
        const TupleRole = context.d_TupleRole;
        const ClosureAudit = context.d_ClosureAudit;
        const validateAuxiliaryQm31 = context.d_validateAuxiliaryQm31;
        const printTupleComponentGroups = context.d_printTupleComponentGroups;
        const tupleComponentName = context.d_tupleComponentName;
        const printClosureValue = context.d_printClosureValue;
        const printDomainValue = context.d_printDomainValue;

        pub fn v2Rows18Through35PreflightIdentity(
            receipt: *const V2Rows18Through35PreflightReceipt,
        ) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(V2_ROWS_18_35_PREFLIGHT_ID_DOMAIN);
            hashSegmentInt(&hash, u16, receipt.format_version);
            hashSegmentInt(&hash, u8, receipt.universal_roster_count);
            hashSegmentInt(&hash, u8, receipt.authority_source_count);
            hashSegmentInt(&hash, u8, receipt.target_component_count);
            hashSegmentInt(&hash, u8, receipt.domain_count);
            hashSegmentInt(&hash, u64, receipt.target_domain_mask);
            hashSegmentInt(&hash, u64, receipt.closed_domain_mask);
            hashSegmentInt(
                &hash,
                u8,
                @intFromBool(receipt.rows_18_35_inputs_validated),
            );
            hashSegmentInt(&hash, u8, @intFromBool(receipt.rows_0_9_verified));
            hashSegmentInt(
                &hash,
                u8,
                @intFromBool(receipt.exact_47_domain_closure_verified),
            );
            hashSegmentInt(&hash, u8, @intFromBool(receipt.outer_stark_verified));
            hashSegmentPoseidonDigest(&hash, receipt.wire_id);
            hashSegmentPoseidonDigest(&hash, receipt.statement_authority_id);
            hashSegmentPoseidonDigest(&hash, receipt.authority_manifest_id);
            hashSegmentPoseidonDigest(&hash, receipt.authority_prepared_id);
            hash.update(&receipt.fri_circuit_id);
            hash.update(&receipt.pcs_circuit_id);
            hash.update(&receipt.vm_air_circuit_id);
            hashSegmentPoseidonDigest(&hash, receipt.vm_plan_id);
            hashSegmentPoseidonDigest(&hash, receipt.recursion_plan_id);
            hashSegmentPoseidonDigest(&hash, receipt.transcript_program_id);
            hashSegmentPoseidonDigest(&hash, receipt.transcript_execution_id);
            hashSegmentPoseidonDigest(&hash, receipt.transcript_evidence_id);
            hashSegmentPoseidonDigest(&hash, receipt.transcript_final_digest);
            hash.update(&receipt.transcript_trace_receipt);
            hashSegmentInt(&hash, u32, receipt.transcript_frame_count);
            hashSegmentInt(&hash, u32, receipt.transcript_poseidon_call_count);
            hashSegmentInt(&hash, u32, receipt.transcript_pow_check_count);
            hashSegmentInt(&hash, u32, receipt.transcript_final_draw_count);
            hashSegmentInt(&hash, u32, receipt.authority_poseidon_call_count);
            return hash.finalResult();
        }

        pub fn requireSha256Id(value: [32]u8) !void {
            var aggregate: u8 = 0;
            for (value) |byte| aggregate |= byte;
            if (aggregate == 0) return error.SegmentClosureIdentityMismatch;
        }

        pub fn requireCanonicalClosureVector(
            values: *const [global_closure.DOMAIN_COUNT]QM31,
        ) !void {
            for (values) |value| try validateAuxiliaryQm31(value);
        }

        pub fn requireZeroDomainClosure(
            values: *const [global_closure.DOMAIN_COUNT]QM31,
        ) !void {
            for (values) |value|
                if (!value.isZero()) return error.RelationDomainClosureMismatch;
        }

        pub fn allRelationDomainMask() u64 {
            return (@as(u64, 1) << global_closure.DOMAIN_COUNT) - 1;
        }

        pub fn hashSegmentPoseidonDigest(
            hash: anytype,
            value: recursion.poseidon2_channel.Digest,
        ) void {
            for (value) |word| hashSegmentInt(hash, u32, word);
        }

        pub fn hashSegmentQm31(hash: anytype, value: QM31) void {
            for (value.toM31Array()) |word|
                hashSegmentInt(hash, u32, word.toU32());
        }

        pub fn hashSegmentInt(
            hash: anytype,
            comptime T: type,
            value: anytype,
        ) void {
            var encoded: [@sizeOf(T)]u8 = undefined;
            std.mem.writeInt(T, &encoded, @intCast(value), .little);
            hash.update(&encoded);
        }

        /// Exact whole-roster LogUp closure. Every relation challenge is independently
        /// drawn, but framework claimed sums share one additive proof boundary. The
        /// roster closes against two disjoint verifier-owned authorities: the
        /// arithmetic lowering's wire boundary and row 18's detailed-claim boundary.
        pub fn verifyGlobalClosure(
            vector: *const manifest_mod.ClaimVector,
            public_boundaries: PublicBoundaryClaims,
        ) Error!void {
            var total = public_boundaries.total();
            for (vector.values) |claim| total = total.add(claim);
            if (!total.isZero()) return error.WireClosureMismatch;
        }

        pub fn diagnoseGlobalClosure(
            audit: *ClosureAudit,
            vector: *const manifest_mod.ClaimVector,
            claims: Claims,
        ) !void {
            if (!audit.collect_tuples) return error.AuthorityMismatch;
            if (!audit.public_boundaries.eql(claims.public_boundaries))
                return error.AuthorityMismatch;
            var domain_totals = [_]QM31{QM31.zero()} ** universal.RELATION_COUNT;
            var row_total = QM31.zero();
            std.debug.print("\n  OUTER_CLOSURE rows=36 domains={d}\n", .{
                universal.RELATION_COUNT,
            });
            for (audit.rows, vector.values, 0..) |row_audit, claim, row_index| {
                if (!row_audit.total.eql(claim)) return error.AuthorityMismatch;
                row_total = row_total.add(claim);
                for (&domain_totals, row_audit.values) |*total, value|
                    total.* = total.add(value);
                printClosureValue(
                    "row",
                    row_index,
                    air.universal_roster.DESCRIPTORS[row_index].name,
                    claim,
                    row_audit.logical_rows,
                    row_audit.event_terms,
                );
            }
            printClosureValue(
                "boundary",
                air.universal_roster.COMPONENT_COUNT,
                "public_wire_boundary",
                claims.public_boundaries.wire,
                0,
                0,
            );
            printClosureValue(
                "boundary",
                air.universal_roster.COMPONENT_COUNT + 1,
                "public_verifier_input_boundary",
                claims.public_boundaries.verifier_input,
                0,
                0,
            );
            printClosureValue(
                "wire-audit",
                air.universal_roster.COMPONENT_COUNT + 2,
                "input_wire",
                claims.input_wire,
                0,
                0,
            );
            domain_totals[@intFromEnum(RelationDomain.recursion_wire)] =
                domain_totals[@intFromEnum(RelationDomain.recursion_wire)].add(
                    claims.public_boundaries.wire,
                );
            domain_totals[@intFromEnum(RelationDomain.recursion_verifier_input_word)] =
                domain_totals[@intFromEnum(RelationDomain.recursion_verifier_input_word)].add(
                    claims.public_boundaries.verifier_input,
                );

            var recomposed = QM31.zero();
            var first_nonzero: ?usize = null;
            for (domain_totals, 0..) |subtotal, domain_index| {
                recomposed = recomposed.add(subtotal);
                if (subtotal.isZero()) continue;
                if (first_nonzero == null) first_nonzero = domain_index;
                const domain: RelationDomain = @enumFromInt(domain_index);
                printDomainValue("domain", domain_index, @tagName(domain), subtotal);
            }
            const expected = row_total.add(claims.public_boundaries.total());
            if (!recomposed.eql(expected)) return error.AuthorityMismatch;

            const wire_total = claims.input_wire
                .add(claims.multiply)
                .add(claims.inverse)
                .add(claims.linear)
                .add(claims.public_boundaries.wire);
            printDomainValue(
                "wire-total",
                @intFromEnum(RelationDomain.recursion_wire),
                @tagName(RelationDomain.recursion_wire),
                wire_total,
            );
            if (first_nonzero) |first_domain_index| {
                const first_domain: RelationDomain = @enumFromInt(first_domain_index);
                std.debug.print(
                    "  OUTER_CLOSURE first_nonzero domain={d}:{s}\n",
                    .{ first_domain_index, @tagName(first_domain) },
                );
                for (domain_totals, 0..) |subtotal, domain_index| {
                    if (subtotal.isZero()) continue;
                    const domain: RelationDomain = @enumFromInt(domain_index);
                    std.debug.print(
                        "  OUTER_CLOSURE provenance domain={d}:{s}:\n",
                        .{ domain_index, @tagName(domain) },
                    );
                    for (audit.rows, 0..) |row_audit, row_index| {
                        const value = row_audit.values[domain_index];
                        if (value.isZero()) continue;
                        printClosureValue(
                            "source",
                            row_index,
                            air.universal_roster.DESCRIPTORS[row_index].name,
                            value,
                            row_audit.logical_rows,
                            row_audit.event_terms,
                        );
                    }
                    if (domain == .recursion_wire) {
                        if (!claims.public_boundaries.wire.isZero()) {
                            printClosureValue(
                                "source",
                                air.universal_roster.COMPONENT_COUNT,
                                "public_wire_boundary",
                                claims.public_boundaries.wire,
                                0,
                                0,
                            );
                        }
                        printClosureValue(
                            "derived",
                            air.universal_roster.COMPONENT_COUNT + 2,
                            "input_wire_subset",
                            claims.input_wire,
                            0,
                            0,
                        );
                    } else if (domain == .recursion_verifier_input_word and
                        !claims.public_boundaries.verifier_input.isZero())
                    {
                        printClosureValue(
                            "source",
                            air.universal_roster.COMPONENT_COUNT + 1,
                            "public_verifier_input_boundary",
                            claims.public_boundaries.verifier_input,
                            0,
                            0,
                        );
                    }
                }
            } else {
                std.debug.print("  OUTER_CLOSURE all_domains=zero\n", .{});
            }
            try diagnoseTupleLedger(&audit.tuple_ledger, &domain_totals);
        }

        pub const MAX_PRINTED_UNMATCHED_TUPLES_PER_DOMAIN: usize = 8;
        pub const TUPLE_EVENT_CARDINALITY: usize = std.math.maxInt(u8) + 1;
        pub const TUPLE_ROLE_CARDINALITY: usize = std.enums.values(TupleRole).len;

        pub const TupleMismatchBucket = struct {
            tuple_groups: usize = 0,
            records: usize = 0,
            signed_weight: QM31 = QM31.zero(),
        };

        pub fn diagnoseTupleClosureReport(
            ledger: *const TupleLedger,
            report: TupleClosureReport,
        ) !void {
            std.debug.print(
                "\n  OUTER_TUPLE_ONLY contributions={d} unmatched={d} " ++
                    "red_domains={d}\n",
                .{
                    report.contribution_count,
                    report.unmatched_tuple_count,
                    report.redDomainCount(),
                },
            );
            for (report.unmatched_by_domain, 0..) |unmatched, domain_index| {
                if (unmatched == 0) continue;
                const domain: RelationDomain = @enumFromInt(domain_index);
                std.debug.print(
                    "  OUTER_TUPLE_ONLY domain={d}:{s} contributions={d} " ++
                        "unmatched_tuple_hashes={d}\n",
                    .{
                        domain_index,
                        @tagName(domain),
                        countDomainContributions(ledger.contributions.items, domain),
                        unmatched,
                    },
                );
                try printTupleMismatchSummary(ledger, domain);
            }
        }

        pub fn diagnoseTupleLedger(
            ledger: *TupleLedger,
            domain_totals: *const [universal.RELATION_COUNT]QM31,
        ) !void {
            const tuple_report = ledger.classify();
            const unmatched_counts = tuple_report.unmatched_by_domain;

            for (domain_totals, unmatched_counts, 0..) |
                domain_total,
                unmatched_count,
                domain_index,
            | {
                if (domain_total.isZero()) continue;
                const domain: RelationDomain = @enumFromInt(domain_index);
                std.debug.print(
                    "  OUTER_TUPLES domain={d}:{s} contributions={d} " ++
                        "unmatched_tuple_hashes={d}\n",
                    .{
                        domain_index,
                        @tagName(domain),
                        countDomainContributions(ledger.contributions.items, domain),
                        unmatched_count,
                    },
                );
                try printTupleMismatchSummary(ledger, domain);
                var printed: usize = 0;
                var cursor: usize = 0;
                while (cursor < ledger.contributions.items.len) {
                    const first = ledger.contributions.items[cursor];
                    const end = tupleGroupEnd(ledger.contributions.items, cursor);
                    if (first.domain != domain) {
                        cursor = end;
                        continue;
                    }
                    var signed_weight = QM31.zero();
                    var emits: usize = 0;
                    var consumes: usize = 0;
                    for (ledger.contributions.items[cursor..end]) |item| {
                        signed_weight = signed_weight.add(item.signed_weight);
                        if (item.role == .emit)
                            emits += 1
                        else
                            consumes += 1;
                    }
                    if (signed_weight.isZero()) {
                        cursor = end;
                        continue;
                    }
                    if (printed < MAX_PRINTED_UNMATCHED_TUPLES_PER_DOMAIN) {
                        const hash_hex = std.fmt.bytesToHex(first.tuple_hash, .lower);
                        const weight_words = signed_weight.toM31Array();
                        std.debug.print(
                            "  OUTER_TUPLES unmatched hash={s} arity={d} " ++
                                "weight=[{d},{d},{d},{d}] emits={d} consumes={d}\n",
                            .{
                                &hash_hex,
                                first.arity,
                                weight_words[0].toU32(),
                                weight_words[1].toU32(),
                                weight_words[2].toU32(),
                                weight_words[3].toU32(),
                                emits,
                                consumes,
                            },
                        );
                        printTupleComponentGroups(
                            ledger.contributions.items[cursor..end],
                        );
                        printed += 1;
                    }
                    cursor = end;
                }
                if (unmatched_count > printed) std.debug.print(
                    "  OUTER_TUPLES omitted={d} (print_cap={d})\n",
                    .{
                        unmatched_count - printed,
                        MAX_PRINTED_UNMATCHED_TUPLES_PER_DOMAIN,
                    },
                );
            }
        }

        /// Aggregates the exact unmatched tuples by their authenticated event owner.
        /// Hash-order samples are useful for reproducing one row, while this compact
        /// view exposes the structural schedule delta immediately (for example, 193
        /// missing root emissions versus 193 query consumers). The dense table is
        /// bounded by protocol enums and allocated only on the opt-in diagnostic path.
        pub fn printTupleMismatchSummary(
            ledger: *const TupleLedger,
            domain: RelationDomain,
        ) !void {
            const component_cardinality = air.universal_roster.COMPONENT_COUNT + 1;
            const bucket_count = component_cardinality *
                TUPLE_EVENT_CARDINALITY * TUPLE_ROLE_CARDINALITY;
            const buckets = try ledger.allocator.alloc(TupleMismatchBucket, bucket_count);
            defer ledger.allocator.free(buckets);
            @memset(buckets, .{});

            var cursor: usize = 0;
            while (cursor < ledger.contributions.items.len) {
                const first = ledger.contributions.items[cursor];
                const end = tupleGroupEnd(ledger.contributions.items, cursor);
                if (first.domain != domain) {
                    cursor = end;
                    continue;
                }
                var group_weight = QM31.zero();
                for (ledger.contributions.items[cursor..end]) |item|
                    group_weight = group_weight.add(item.signed_weight);
                if (group_weight.isZero()) {
                    cursor = end;
                    continue;
                }

                var owner_cursor = cursor;
                while (owner_cursor < end) {
                    const owner = ledger.contributions.items[owner_cursor];
                    var owner_end = owner_cursor + 1;
                    while (owner_end < end and
                        ledger.contributions.items[owner_end].component == owner.component and
                        ledger.contributions.items[owner_end].event == owner.event and
                        ledger.contributions.items[owner_end].role == owner.role) : (owner_end += 1)
                    {}
                    const bucket_index = tupleMismatchBucketIndex(
                        owner.component,
                        owner.event,
                        owner.role,
                    );
                    var bucket = &buckets[bucket_index];
                    bucket.tuple_groups += 1;
                    bucket.records += owner_end - owner_cursor;
                    for (ledger.contributions.items[owner_cursor..owner_end]) |item|
                        bucket.signed_weight = bucket.signed_weight.add(item.signed_weight);
                    owner_cursor = owner_end;
                }
                cursor = end;
            }

            for (0..component_cardinality) |component| {
                for (0..TUPLE_EVENT_CARDINALITY) |event| {
                    for (std.enums.values(TupleRole)) |role| {
                        const bucket = buckets[
                            tupleMismatchBucketIndex(
                                @intCast(component),
                                @intCast(event),
                                role,
                            )
                        ];
                        if (bucket.records == 0) continue;
                        const words = bucket.signed_weight.toM31Array();
                        const component_name = tupleComponentName(component, event);
                        std.debug.print(
                            "  OUTER_TUPLES summary component={d}:{s} event={d} " ++
                                "role={s} groups={d} records={d} " ++
                                "weight=[{d},{d},{d},{d}]\n",
                            .{
                                component,
                                component_name,
                                event,
                                @tagName(role),
                                bucket.tuple_groups,
                                bucket.records,
                                words[0].toU32(),
                                words[1].toU32(),
                                words[2].toU32(),
                                words[3].toU32(),
                            },
                        );
                    }
                }
            }
        }

        pub fn tupleMismatchBucketIndex(
            component: u8,
            event: u8,
            role: TupleRole,
        ) usize {
            return ((@as(usize, component) * TUPLE_EVENT_CARDINALITY) + event) *
                TUPLE_ROLE_CARDINALITY + tupleRoleIndex(role);
        }

        pub fn tupleRoleIndex(role: TupleRole) usize {
            return switch (role) {
                .request => 0,
                .consume => 1,
                .emit => 2,
            };
        }

        pub fn tupleGroupEnd(
            items: []const air.relation_interaction.TupleContribution,
            start: usize,
        ) usize {
            const first = items[start];
            var end = start + 1;
            while (end < items.len and
                items[end].domain == first.domain and
                std.mem.eql(u8, &items[end].tuple_hash, &first.tuple_hash)) : (end += 1)
            {}
            return end;
        }

        pub fn countDomainContributions(
            items: []const air.relation_interaction.TupleContribution,
            domain: RelationDomain,
        ) usize {
            var count: usize = 0;
            for (items) |item| count += @intFromBool(item.domain == domain);
            return count;
        }
    };
}
