//! Cold domain audit for authenticated segment transcript rows.

const air = @import("air/mod.zig");
const binding = air.universal_relation_binding;
const relation_interaction = air.relation_interaction;
const schedule = air.verifier_schedule;
const universal = air.universal_challenges;
const segment_witness = @import("segment_transcript_witness.zig");

const control_witness = air.control_witness;
const transcript_air_witness = air.transcript_air_witness;
const transcript_binding_witness = air.transcript_binding_witness;
const transcript_state_witness = air.transcript_state_witness;
const transcript_word_witness = air.transcript_word_witness;
const transcript_payload_witness = air.transcript_payload_witness;
const relation_challenge_witness = air.relation_challenge_witness;
const verifier_randomness_witness = air.verifier_randomness_witness;

const ControlRelation = binding.Binding(air.control);
const TranscriptAirRelation = binding.Binding(air.transcript_air);
const TranscriptBindingRelation = binding.Binding(air.transcript_binding);
const TranscriptStateRelation = binding.Binding(air.transcript_state);
const TranscriptWordRelation = binding.Binding(air.transcript_word);
const TranscriptPayloadRelation = binding.Binding(air.transcript_payload);
const PowCheckRelation = binding.Binding(air.pow_check);
const PowFrameRelation = binding.Binding(air.pow_frame);
const RelationChallengeRelation = binding.Binding(air.relation_challenge);
const VerifierRandomnessRelation = binding.Binding(air.verifier_randomness);

pub fn audit(
    self: anytype,
    vm_plan: *const schedule.Plan,
    recursion_plan: *const schedule.Plan,
    preprocessing: *const segment_witness.Preprocessing,
    prepared: anytype,
    relations: *const universal.UniversalRelations,
    claims: anytype,
    tuple_ledger: ?*relation_interaction.TupleLedger,
    comptime DomainAudits: type,
    comptime rowIndex: anytype,
    comptime appendTupleContributions: anytype,
) !DomainAudits {
    try self.validateAgainst(vm_plan, recursion_plan, preprocessing, prepared);
    try relations.validate();
    var result: DomainAudits = undefined;

    {
        const rows = try self.allocator.alloc(
            ControlRelation.Row,
            self.control_preprocessing.rows.len,
        );
        defer self.allocator.free(rows);
        for (rows, self.control_preprocessing.rows) |*target, source|
            target.* = control_witness.logicalRow(source, .segment_leaf);
        result[rowIndex(.control)] =
            try self.owners.control.relation.auditPreparedDomainSums(
                self.allocator,
                rows,
                relations,
                claims.control,
            );
        try appendTupleContributions(
            &self.owners.control.relation,
            tuple_ledger,
            .control,
            rows,
        );
    }
    {
        const rows = try self.allocator.alloc(
            TranscriptAirRelation.Row,
            prepared.transcript_air.rows.len,
        );
        defer self.allocator.free(rows);
        for (rows, prepared.transcript_air.rows) |*target, source|
            target.* = try transcript_air_witness.logicalRow(source);
        result[rowIndex(.transcript_air)] =
            try self.owners.transcript_air.relation.auditPreparedDomainSums(
                self.allocator,
                rows,
                relations,
                claims.transcript_air,
            );
        try appendTupleContributions(
            &self.owners.transcript_air.relation,
            tuple_ledger,
            .transcript_air,
            rows,
        );
    }
    {
        const rows = try self.allocator.alloc(
            TranscriptBindingRelation.Row,
            preprocessing.transcript_binding.rows.len,
        );
        defer self.allocator.free(rows);
        for (
            rows,
            prepared.transcript_binding.rows,
            preprocessing.transcript_binding.rows,
        ) |*target, main, pp| target.* =
            transcript_binding_witness.logicalInputs(
                main,
                pp,
                .segment_leaf,
            );
        result[rowIndex(.transcript_binding)] =
            try self.owners.transcript_binding.relation.auditPreparedDomainSums(
                self.allocator,
                rows,
                relations,
                claims.transcript_binding,
            );
        try appendTupleContributions(
            &self.owners.transcript_binding.relation,
            tuple_ledger,
            .transcript_binding,
            rows,
        );
    }
    {
        const rows = try self.allocator.alloc(
            TranscriptStateRelation.Row,
            preprocessing.transcript_state.rows.len,
        );
        defer self.allocator.free(rows);
        for (
            rows,
            prepared.transcript_state.rows,
            preprocessing.transcript_state.rows,
        ) |*target, main, pp| target.* =
            transcript_state_witness.logicalInputs(
                main,
                pp,
                .segment_leaf,
            );
        result[rowIndex(.transcript_state)] =
            try self.owners.transcript_state.relation.auditPreparedDomainSums(
                self.allocator,
                rows,
                relations,
                claims.transcript_state,
            );
        try appendTupleContributions(
            &self.owners.transcript_state.relation,
            tuple_ledger,
            .transcript_state,
            rows,
        );
    }
    {
        const rows = try self.allocator.alloc(
            TranscriptWordRelation.Row,
            preprocessing.transcript_word.rows.len,
        );
        defer self.allocator.free(rows);
        for (
            rows,
            preprocessing.transcript_word.rows,
            prepared.transcript_word.values,
        ) |*target, pp, value| target.* =
            try transcript_word_witness.logicalRow(
                pp,
                value,
                .segment_leaf,
            );
        result[rowIndex(.transcript_word)] =
            try self.owners.transcript_word.relation.auditPreparedDomainSums(
                self.allocator,
                rows,
                relations,
                claims.transcript_word,
            );
        try appendTupleContributions(
            &self.owners.transcript_word.relation,
            tuple_ledger,
            .transcript_word,
            rows,
        );
    }
    {
        const rows = try self.allocator.alloc(
            TranscriptPayloadRelation.Row,
            preprocessing.transcript_payload.rows.len,
        );
        defer self.allocator.free(rows);
        for (
            rows,
            preprocessing.transcript_payload.rows,
            prepared.transcript_payload.values,
        ) |*target, pp, value| target.* =
            try transcript_payload_witness.logicalRow(
                pp,
                value,
                .segment_leaf,
            );
        result[rowIndex(.transcript_payload)] =
            try self.owners.transcript_payload.relation.auditPreparedDomainSums(
                self.allocator,
                rows,
                relations,
                claims.transcript_payload,
            );
        try appendTupleContributions(
            &self.owners.transcript_payload.relation,
            tuple_ledger,
            .transcript_payload,
            rows,
        );
    }
    {
        const rows = try self.allocator.alloc(
            PowCheckRelation.Row,
            prepared.pow_check.invocations.len,
        );
        defer self.allocator.free(rows);
        for (rows, 0..) |*target, index|
            target.* = prepared.pow_check.preparedRow(index);
        result[rowIndex(.pow_check)] =
            try self.owners.pow_check.relation.auditPreparedDomainSums(
                self.allocator,
                rows,
                relations,
                claims.pow_check,
            );
        try appendTupleContributions(
            &self.owners.pow_check.relation,
            tuple_ledger,
            .pow_check,
            rows,
        );
    }
    {
        const rows = try self.allocator.alloc(
            PowFrameRelation.Row,
            prepared.pow_frame.invocations.len,
        );
        defer self.allocator.free(rows);
        for (rows, 0..) |*target, index|
            target.* = prepared.pow_frame.preparedRow(index);
        result[rowIndex(.pow_frame)] =
            try self.owners.pow_frame.relation.auditPreparedDomainSums(
                self.allocator,
                rows,
                relations,
                claims.pow_frame,
            );
        try appendTupleContributions(
            &self.owners.pow_frame.relation,
            tuple_ledger,
            .pow_frame,
            rows,
        );
    }
    {
        const rows = try self.allocator.alloc(
            RelationChallengeRelation.Row,
            preprocessing.relation_challenge.rows.len,
        );
        defer self.allocator.free(rows);
        for (
            rows,
            prepared.relation_challenge.rows,
            preprocessing.relation_challenge.rows,
        ) |*target, main, pp| target.* =
            relation_challenge_witness.logicalInputs(
                main,
                pp,
                .segment_leaf,
            );
        result[rowIndex(.relation_challenge)] =
            try self.owners.relation_challenge.relation.auditPreparedDomainSums(
                self.allocator,
                rows,
                relations,
                claims.relation_challenge,
            );
        try appendTupleContributions(
            &self.owners.relation_challenge.relation,
            tuple_ledger,
            .relation_challenge,
            rows,
        );
    }
    {
        const rows = try self.allocator.alloc(
            VerifierRandomnessRelation.Row,
            preprocessing.verifier_randomness.rows.len,
        );
        defer self.allocator.free(rows);
        for (
            rows,
            prepared.verifier_randomness.rows,
            preprocessing.verifier_randomness.rows,
        ) |*target, main, pp| target.* =
            verifier_randomness_witness.logicalInputs(
                main,
                pp,
                .segment_leaf,
            );
        result[rowIndex(.verifier_randomness)] =
            try self.owners.verifier_randomness.relation.auditPreparedDomainSums(
                self.allocator,
                rows,
                relations,
                claims.verifier_randomness,
            );
        try appendTupleContributions(
            &self.owners.verifier_randomness.relation,
            tuple_ledger,
            .verifier_randomness,
            rows,
        );
    }
    return result;
}
