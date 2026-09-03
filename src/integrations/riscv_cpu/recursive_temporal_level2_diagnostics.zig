//! Failure-only diagnostics for the recursive temporal node cohort.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const verifier_input = @import("recursive_temporal_level2_verifier_input_v1.zig");
const support = @import("recursive_temporal_parent_cohort_support.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const global_closure = recursion.binary_global_closure_outer_source;
const relation_interaction = recursion.air.relation_interaction;

pub fn reportVerifierInputResidual(
    cohort: anytype,
    rows: anytype,
    combined: global_closure.BoundaryEvidenceV2,
    relations: anytype,
) void {
    const recorder = cohort.suffix.source()
        .authenticatedRecorderVerifierInputBoundaryEvidence(relations) catch |err| {
        std.debug.print(
            "TEMPORAL_LEVEL2_BOUNDARY_SPLIT recorder_error={s}\n",
            .{@errorName(err)},
        );
        return;
    };
    const domain = @intFromEnum(
        global_closure.VERIFIER_INPUT_BOUNDARY_DOMAIN,
    );
    const statement_claim = combined.claimed_sum.sub(recorder.claimed_sum);
    const statement_residual = rows[10].domains[domain].value.add(
        statement_claim,
    );
    var non_statement_rows = QM31.zero();
    for (rows, 0..) |row, row_index| {
        if (row_index == 10) continue;
        non_statement_rows = non_statement_rows.add(row.domains[domain].value);
    }
    const recorder_residual = non_statement_rows.add(recorder.claimed_sum);
    reportValue("statement", statement_claim, statement_residual);
    reportValue("recorder", recorder.claimed_sum, recorder_residual);
    std.debug.print(
        "TEMPORAL_LEVEL2_BOUNDARY_COUNTS statement={d} recorder={d} " ++
            "statement_closed={} recorder_closed={}\n",
        .{
            verifier_input.STATEMENT_TUPLE_COUNT,
            recorder.descriptor.boundary.tuple_count,
            statement_residual.isZero(),
            recorder_residual.isZero(),
        },
    );
}

pub fn reportTupleClosure(
    cohort: anytype,
    generated: anytype,
    relations: anytype,
    provider_relations: anytype,
) void {
    var ledger = relation_interaction.TupleLedger.init(cohort.allocator);
    defer ledger.deinit();
    _ = cohort.prefix.auditInteractionDomains(relations, &ledger) catch |err| {
        std.debug.print(
            "TEMPORAL_LEVEL2_TUPLE_AUDIT prefix_error={s}\n",
            .{@errorName(err)},
        );
        return;
    };
    _ = cohort.fri.auditGeneratedInteractionsWithTupleLedger(
        cohort.allocator,
        relations,
        provider_relations,
        &generated.suffix,
        &ledger,
    ) catch |err| {
        std.debug.print(
            "TEMPORAL_LEVEL2_TUPLE_AUDIT suffix_error={s}\n",
            .{@errorName(err)},
        );
        return;
    };
    support.reportTupleLedger(&ledger);
}

fn reportValue(label: []const u8, claim: QM31, residual: QM31) void {
    const claim_words = claim.toM31Array();
    const residual_words = residual.toM31Array();
    std.debug.print(
        "TEMPORAL_LEVEL2_BOUNDARY_SPLIT source={s} " ++
            "claim={d},{d},{d},{d} residual={d},{d},{d},{d}\n",
        .{
            label,
            claim_words[0].toU32(),
            claim_words[1].toU32(),
            claim_words[2].toU32(),
            claim_words[3].toU32(),
            residual_words[0].toU32(),
            residual_words[1].toU32(),
            residual_words[2].toU32(),
            residual_words[3].toU32(),
        },
    );
}
