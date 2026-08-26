//! Internal segment public outer source v2 authority shard; use segment_public_outer_source_v2.zig publicly.

const dependency_0 = @import("segment_public_outer_source_v2_contract.zig");

const ARITHMETIC_BINDING_FORMAT_VERSION = dependency_0.ARITHMETIC_BINDING_FORMAT_VERSION;
const ARITHMETIC_BINDING_ID_DOMAIN = dependency_0.ARITHMETIC_BINDING_ID_DOMAIN;
const ARITHMETIC_PUBLICATION_WORD_COUNT = dependency_0.ARITHMETIC_PUBLICATION_WORD_COUNT;
const CAPABILITY_LEDGER = dependency_0.CAPABILITY_LEDGER;
const CHALLENGE_WORD_COUNT = dependency_0.CHALLENGE_WORD_COUNT;
const CONTROL_PUBLICATION_INDEX = dependency_0.CONTROL_PUBLICATION_INDEX;
const CONTROL_RELAY_CIRCUIT_ID = dependency_0.CONTROL_RELAY_CIRCUIT_ID;
const CapabilityLedgerV2 = dependency_0.CapabilityLedgerV2;
const ClosureLedgerV2 = dependency_0.ClosureLedgerV2;
const CountsV2 = dependency_0.CountsV2;
const Digest = dependency_0.Digest;
const Error = dependency_0.Error;
const FIRST_ROW = dependency_0.FIRST_ROW;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const IdentityHasher = dependency_0.IdentityHasher;
const LAST_ROW = dependency_0.LAST_ROW;
const LoweringObligationV2 = dependency_0.LoweringObligationV2;
const M31 = dependency_0.M31;
const ManifestV2 = dependency_0.ManifestV2;
const NATIVE_PUBLIC_SUM_WORD_COUNT = dependency_0.NATIVE_PUBLIC_SUM_WORD_COUNT;
const NATIVE_SUM_CIRCUIT_ID = dependency_0.NATIVE_SUM_CIRCUIT_ID;
const PRODUCTION_ACTIVATION = dependency_0.PRODUCTION_ACTIVATION;
const QM31 = dependency_0.QM31;
const ROW_COUNT = dependency_0.ROW_COUNT;
const SCHEMA_VERSION = dependency_0.SCHEMA_VERSION;
const SOURCE_ID_DOMAIN = dependency_0.SOURCE_ID_DOMAIN;
const Sha256Digest = dependency_0.Sha256Digest;
const allZeroBytes = dependency_0.allZeroBytes;
const checkedAdd = dependency_0.checkedAdd;
const control_witness_v2 = dependency_0.control_witness_v2;
const countsFromManifest = dependency_0.countsFromManifest;
const deriveCounts = dependency_0.deriveCounts;
const loweringObligationId = dependency_0.loweringObligationId;
const m31 = dependency_0.m31;
const manifestId = dependency_0.manifestId;
const native_relations = dependency_0.native_relations;
const public_logup_v2 = dependency_0.public_logup_v2;
const publicationEvents = dependency_0.publicationEvents;
const relation = dependency_0.relation;
const roster = dependency_0.roster;
const rowIndex = dependency_0.rowIndex;
const schedule = dependency_0.schedule;
const source_v2 = dependency_0.source_v2;
const statement_v1 = dependency_0.statement_v1;
const statement_v2 = dependency_0.statement_v2;
const std = dependency_0.std;
const sumsEql = dependency_0.sumsEql;
const traceLogSize = dependency_0.traceLogSize;
const universal = dependency_0.universal;

/// Exact graph-derived multiplicities for the rows 13--16 arithmetic relay.
///
/// This pointer-bearing view is issued by the owning native-sum graph.  Its
/// identity binds every count and all public-source custody identifiers; the
/// production integration must additionally compare `circuit_identity` and
/// `graph_identity` with that graph owner.  The public source deliberately
/// cannot import its consumer, which would create a module cycle.
pub const ArithmeticGraphBindingV2 = struct {
    format_version: u16 = ARITHMETIC_BINDING_FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    circuit_id: u32 = NATIVE_SUM_CIRCUIT_ID,
    input_count: u32,
    prepared_source_id: Digest,
    lowering_obligation_id: Digest,
    graph_identity: Sha256Digest,
    circuit_identity: Sha256Digest,
    input_use_counts: []const u32,
    identity: Sha256Digest,

    pub fn validateAgainst(
        self: ArithmeticGraphBindingV2,
        prepared: *const PreparedV2,
    ) Error!void {
        try prepared.manifest.validate();
        if (self.format_version != ARITHMETIC_BINDING_FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.circuit_id != NATIVE_SUM_CIRCUIT_ID or
            self.input_count != prepared.lowering_obligation.input_count or
            self.input_use_counts.len != self.input_count or
            !std.meta.eql(self.prepared_source_id, prepared.source_id) or
            !std.meta.eql(
                self.lowering_obligation_id,
                prepared.lowering_obligation.identity,
            ) or allZeroBytes(&self.graph_identity) or
            allZeroBytes(&self.circuit_identity))
        {
            return error.ArithmeticBindingMismatch;
        }
        for (self.input_use_counts) |count| if (count >= m31.Modulus)
            return error.ArithmeticBindingMismatch;
        if (!std.mem.eql(
            u8,
            &self.identity,
            &arithmeticGraphBindingId(self),
        )) return error.ArithmeticBindingMismatch;
    }
};

pub const PreparedV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    manifest: ManifestV2,
    capability_ledger: CapabilityLedgerV2 = CAPABILITY_LEDGER,
    wire_id: Digest,
    receipt_id: Digest,
    statement_authority_id: Digest,
    source_authority_id: Digest,
    publication_id: Digest,
    native_public_sums_id: Digest,
    relation_context_id: Digest,
    public_sums: public_logup_v2.Sums,
    public_total: QM31,
    lowering_obligation: LoweringObligationV2,
    authority_hash_plan: source_v2.AuthorityHashPoseidonPlanV2,
    control: control_witness_v2.PreparedV2,
    source_id: Digest,

    pub fn counts(self: *const PreparedV2) CountsV2 {
        return countsFromManifest(self.manifest);
    }

    pub fn validateAgainst(
        self: *const PreparedV2,
        inputs: InputsV2,
    ) Error!void {
        const expected = try derivePrepared(inputs);
        if (!preparedEql(self, &expected)) return error.SourceMismatch;
    }

    pub fn productionReady(_: *const PreparedV2) bool {
        return PRODUCTION_ACTIVATION;
    }

    pub fn closureLedger(self: *const PreparedV2) ClosureLedgerV2 {
        const wire_count = self.manifest.wire_word_count;
        return .{
            .source36_statement_word_emits = wire_count,
            .row11_statement_word_consumes = wire_count,
            .row11_boundary_bridge_emits = wire_count,
            .row15_boundary_bridge_consumes = wire_count,
            .rows13_16_arithmetic_wire_emits = self.lowering_obligation.input_count,
        };
    }
};

/// All values are borrowed from one successful native-verifier capture.  The
/// owned public-data wrapper prevents this source from retaining or accepting
/// caller-owned proof-byte storage.
pub const InputsV2 = struct {
    statement_source: *const source_v2.PreparedV2,
    owned_public_data: *const statement_v2.OwnedPublicDataV2,
    publication: *const source_v2.VerifiedNativePublicLogUpPublicationV2,
    native_public_sums: *const statement_v2.NativePublicSums,
    verified_receipt: *const statement_v2.VerifiedReceipt,
    relations: *const native_relations.Relations,
    component_descs: []const statement_v1.FamilyComponentDesc,
    infra_descs: []const statement_v1.InfraComponentDesc,
    vm_plan: *const schedule.Plan,

    pub fn validate(self: InputsV2) Error!void {
        try self.owned_public_data.validate();
        const data = &self.owned_public_data.data;
        try self.statement_source.validateAgainst(
            data,
            &self.statement_source.verifier_keys,
        );
        try self.native_public_sums.validateAgainst(data, self.relations);
        try self.verified_receipt.validateAgainst(data);
        try self.publication.validateAgainst(
            self.statement_source,
            data,
            self.relations,
            self.native_public_sums,
            self.verified_receipt,
            self.component_descs,
            self.infra_descs,
        );
        try self.vm_plan.validate();
        if (self.vm_plan.schema != .vm or
            !std.meta.eql(self.vm_plan.spec, schedule.VM_PROGRAM_SPEC_V1))
        {
            return error.InvalidProgramAnchor;
        }
    }
};

pub const RelaySourceKindV2 = enum(u8) {
    publication_bridge,
    boundary_bridge,
    native_challenge,
    control_wire,
};

/// Physical row contract shared with `air/segment_public_outer_air_v2.zig`.
/// `source_fields` excludes `value`; its first `source_arity - 1` entries are
/// inserted around the value at the source ABI's fixed value coordinate.
pub const RelayRowV2 = struct {
    enabler: u32 = 1,
    source_kind: RelaySourceKindV2,
    source_fields: [5]u32 = .{0} ** 5,
    value: M31,
    arithmetic_mask: u32 = 0,
    arithmetic_circuit_id: u32 = NATIVE_SUM_CIRCUIT_ID,
    arithmetic_node_id: u32 = 0,
    arithmetic_use_count: u32 = 0,
    control_mask: u32 = 0,
    control_circuit_id: u32 = CONTROL_RELAY_CIRCUIT_ID,
    control_node_id: u32 = 0,
    control_use_count: u32 = 0,
};

pub const RelationEventV2 = struct {
    roster_row: u8,
    logical_row: u32,
    event_ordinal: u8,
    domain: relation.Domain,
    role: relation.Role,
    multiplicity: u32,
    arity: u8,
    tuple: [universal.MAX_ARITY]M31,

    pub fn validate(self: RelationEventV2) Error!void {
        if (self.roster_row < FIRST_ROW or self.roster_row > LAST_ROW or
            self.multiplicity >= m31.Modulus or
            self.arity != relation.universalDescriptor(self.domain).arity)
        {
            return error.InvalidRelationEvent;
        }
        for (self.tuple[self.arity..]) |word| if (!word.isZero())
            return error.InvalidRelationEvent;
    }
};

pub const DestinationsV2 = struct {
    publication_header: []RelayRowV2,
    native_public_sums: []RelayRowV2,
    publication_seal: []RelayRowV2,
    boundary_bridge: []RelayRowV2,
    native_challenges: []RelayRowV2,
    relation_events: []RelationEventV2,
    control: control_witness_v2.DestinationsV2,
};

pub fn preflight(inputs: InputsV2) Error!PreparedV2 {
    return derivePrepared(inputs);
}

pub fn prepareInto(
    destination: *PreparedV2,
    inputs: InputsV2,
) Error!void {
    try rejectPreparedAlias(destination, inputs);
    const staged = try derivePrepared(inputs);
    destination.* = staged;
}

pub fn derivePrepared(inputs: InputsV2) Error!PreparedV2 {
    try CAPABILITY_LEDGER.validate();
    try inputs.validate();
    const data = &inputs.owned_public_data.data;
    const authority_hash_plan = try source_v2.AuthorityHashPoseidonPlanV2.init(
        data,
        inputs.verified_receipt,
        inputs.component_descs,
        inputs.infra_descs,
    );
    const authority_call_count = try authority_hash_plan.poseidonCallCount();
    const counts = try deriveCounts(data.words().len, authority_call_count);
    var obligation = LoweringObligationV2{
        .boundary_word_count = std.math.cast(u32, data.words().len) orelse
            return error.ArithmeticOverflow,
        .input_count = std.math.cast(
            u32,
            try checkedAdd(
                data.words().len,
                ARITHMETIC_PUBLICATION_WORD_COUNT + CHALLENGE_WORD_COUNT,
            ),
        ) orelse return error.ArithmeticOverflow,
        .identity = undefined,
    };
    obligation.identity = loweringObligationId(&obligation);
    try obligation.validate();

    const publication_events = try publicationEvents(inputs.publication);
    const control_relay = control_witness_v2.ControlRelayV2{
        .value = publication_events[CONTROL_PUBLICATION_INDEX].tuple[4],
    };
    const control = try control_witness_v2.preflight(
        inputs.vm_plan,
        &control_relay,
    );
    const manifest = try manifestFor(
        inputs,
        counts,
        &obligation,
        &authority_hash_plan,
        &control,
    );
    var result = PreparedV2{
        .manifest = manifest,
        .wire_id = data.wireId(),
        .receipt_id = inputs.verified_receipt.identity,
        .statement_authority_id = inputs.verified_receipt.authority_id,
        .source_authority_id = inputs.statement_source.source_id,
        .publication_id = inputs.publication.identity,
        .native_public_sums_id = inputs.native_public_sums.identity,
        .relation_context_id = inputs.native_public_sums.relation_context_id,
        .public_sums = inputs.native_public_sums.sums,
        .public_total = inputs.native_public_sums.total,
        .lowering_obligation = obligation,
        .authority_hash_plan = authority_hash_plan,
        .control = control,
        .source_id = undefined,
    };
    result.source_id = sourceId(&result);
    try result.closureLedger().validate();
    return result;
}

pub fn manifestFor(
    inputs: InputsV2,
    counts: CountsV2,
    obligation: *const LoweringObligationV2,
    authority_hash_plan: *const source_v2.AuthorityHashPoseidonPlanV2,
    control: *const control_witness_v2.PreparedV2,
) Error!ManifestV2 {
    const rows = counts.asRows();
    var logical_rows: [ROW_COUNT]u32 = undefined;
    var log_sizes: [ROW_COUNT]u8 = undefined;
    for (rows, 0..) |count, index| {
        logical_rows[index] = std.math.cast(u32, count) orelse
            return error.ArithmeticOverflow;
        log_sizes[index] = try traceLogSize(count);
    }
    logical_rows[rowIndex(.vm_public_claim_hash)] = @intCast(@max(
        NATIVE_PUBLIC_SUM_WORD_COUNT,
        authority_hash_plan.poseidon_call_count,
    ));
    log_sizes[rowIndex(.vm_public_claim_hash)] = try traceLogSize(
        logical_rows[rowIndex(.vm_public_claim_hash)],
    );
    var result = ManifestV2{
        .logical_rows = logical_rows,
        .log_sizes = log_sizes,
        .relation_event_count = std.math.cast(u32, counts.relation_events) orelse
            return error.ArithmeticOverflow,
        .wire_word_count = std.math.cast(
            u32,
            inputs.owned_public_data.data.words().len,
        ) orelse return error.ArithmeticOverflow,
        .statement_source_id = inputs.statement_source.source_id,
        .publication_id = inputs.publication.identity,
        .native_public_sums_id = inputs.native_public_sums.identity,
        .relation_context_id = inputs.native_public_sums.relation_context_id,
        .lowering_obligation_id = obligation.identity,
        .authority_hash_plan_id = authority_hash_plan.identity,
        .authority_poseidon_call_count = authority_hash_plan.poseidon_call_count,
        .control_source_id = control.identity,
        .identity = undefined,
    };
    result.identity = manifestId(&result);
    try result.validate();
    return result;
}

pub fn inputUseCount(counts: ?[]const u32, node: usize) u32 {
    if (counts) |values| return values[node];
    return 1;
}

pub fn writeRelayEvents(
    sink: *EventSink,
    component: roster.Component,
    logical_row: usize,
    row: RelayRowV2,
    source_domain: relation.Domain,
    source_tuple: []const M31,
) void {
    sink.put(component, logical_row, 0, source_domain, .consume, 1, source_tuple);
    const arithmetic_tuple = wireTuple(
        row.arithmetic_circuit_id,
        row.arithmetic_node_id,
        row.value,
    );
    sink.put(
        component,
        logical_row,
        1,
        .recursion_wire,
        .emit,
        row.arithmetic_mask * row.arithmetic_use_count,
        &arithmetic_tuple,
    );
    const control_tuple = wireTuple(
        row.control_circuit_id,
        row.control_node_id,
        row.value,
    );
    sink.put(
        component,
        logical_row,
        2,
        .recursion_wire,
        .emit,
        row.control_mask * row.control_use_count,
        &control_tuple,
    );
}

pub fn wireTuple(circuit_id: u32, node_id: u32, value: M31) [6]M31 {
    return .{
        felt(circuit_id),
        felt(node_id),
        value,
        M31.zero(),
        M31.zero(),
        M31.zero(),
    };
}

pub const EventSink = struct {
    events: []RelationEventV2,
    at: usize = 0,

    fn put(
        self: *EventSink,
        row: roster.Component,
        logical_row: usize,
        ordinal: u8,
        domain: relation.Domain,
        role: relation.Role,
        multiplicity: u32,
        values: []const M31,
    ) void {
        std.debug.assert(self.at < self.events.len);
        std.debug.assert(values.len == relation.universalDescriptor(domain).arity);
        var tuple = [_]M31{M31.zero()} ** universal.MAX_ARITY;
        @memcpy(tuple[0..values.len], values);
        self.events[self.at] = .{
            .roster_row = @intFromEnum(row),
            .logical_row = @intCast(logical_row),
            .event_ordinal = ordinal,
            .domain = domain,
            .role = role,
            .multiplicity = multiplicity,
            .arity = @intCast(values.len),
            .tuple = tuple,
        };
        self.at += 1;
    }
};

pub const ChallengeWord = struct {
    challenge: u32,
    limb: u32,
    value: M31,
};

pub fn challengeWords(
    relations: *const native_relations.Relations,
) [CHALLENGE_WORD_COUNT]ChallengeWord {
    var result: [CHALLENGE_WORD_COUNT]ChallengeWord = undefined;
    const pairs = .{
        .{ relations.registers_state.z, relations.registers_state.alpha },
        .{ relations.memory_access.z, relations.memory_access.alpha },
        .{ relations.program_access.z, relations.program_access.alpha },
        .{ relations.merkle.z, relations.merkle.alpha },
    };
    var at: usize = 0;
    inline for (pairs, 0..) |pair, challenge| {
        inline for (pair, 0..) |value, half| {
            for (value.toM31Array(), 0..) |word, limb| {
                result[at] = .{
                    .challenge = challenge,
                    .limb = @intCast(half * 4 + limb),
                    .value = word,
                };
                at += 1;
            }
        }
    }
    std.debug.assert(at == result.len);
    return result;
}

pub fn validateDestinationGeometry(
    destinations: DestinationsV2,
    counts: CountsV2,
) Error!void {
    if (destinations.publication_header.len != counts.publication_header or
        destinations.native_public_sums.len != counts.native_public_sums or
        destinations.publication_seal.len != counts.publication_seal or
        destinations.boundary_bridge.len != counts.boundary_bridge or
        destinations.native_challenges.len != counts.native_challenges or
        destinations.relation_events.len != counts.relay_relation_events or
        destinations.control.logical_rows.len !=
            control_witness_v2.TRACE_ROW_COUNT or
        destinations.control.relation_events.len !=
            counts.control_relation_events)
    {
        return error.DestinationLengthMismatch;
    }
    for (destinations.control.main) |column| if (column.len != control_witness_v2.TRACE_ROW_COUNT) return error.DestinationLengthMismatch;
    for (destinations.control.preprocessed) |column| if (column.len != control_witness_v2.TRACE_ROW_COUNT) return error.DestinationLengthMismatch;
}

pub fn rejectPreparedAlias(destination: *PreparedV2, inputs: InputsV2) Error!void {
    const output = std.mem.asBytes(destination);
    for (sourceBytes(inputs)) |source| if (overlap(output, source))
        return error.AliasedDestination;
}

pub fn rejectDestinationAliases(
    destinations: DestinationsV2,
    prepared: *const PreparedV2,
    inputs: InputsV2,
) Error!void {
    const outputs = destinationBytes(destinations);
    const sources = sourceBytes(inputs);
    for (outputs, 0..) |left, left_index| {
        for (outputs[left_index + 1 ..]) |right| if (overlap(left, right))
            return error.AliasedDestination;
        if (overlap(left, std.mem.asBytes(prepared)))
            return error.AliasedDestination;
        for (sources) |source| if (overlap(left, source))
            return error.AliasedDestination;
    }
}

pub fn destinationBytes(destinations: DestinationsV2) [18][]u8 {
    var result: [18][]u8 = undefined;
    result[0] = std.mem.sliceAsBytes(destinations.publication_header);
    result[1] = std.mem.sliceAsBytes(destinations.native_public_sums);
    result[2] = std.mem.sliceAsBytes(destinations.publication_seal);
    result[3] = std.mem.sliceAsBytes(destinations.boundary_bridge);
    result[4] = std.mem.sliceAsBytes(destinations.native_challenges);
    result[5] = std.mem.sliceAsBytes(destinations.relation_events);
    var at: usize = 6;
    for (destinations.control.main) |column| {
        result[at] = std.mem.sliceAsBytes(column);
        at += 1;
    }
    for (destinations.control.preprocessed) |column| {
        result[at] = std.mem.sliceAsBytes(column);
        at += 1;
    }
    result[at] = std.mem.sliceAsBytes(destinations.control.logical_rows);
    at += 1;
    result[at] = std.mem.sliceAsBytes(destinations.control.relation_events);
    at += 1;
    std.debug.assert(at == result.len);
    return result;
}

pub fn sourceBytes(inputs: InputsV2) [12][]const u8 {
    return .{
        std.mem.asBytes(inputs.statement_source),
        std.mem.asBytes(inputs.owned_public_data),
        std.mem.asBytes(&inputs.owned_public_data.data),
        std.mem.sliceAsBytes(inputs.owned_public_data.canonical_words),
        std.mem.asBytes(inputs.publication),
        std.mem.asBytes(inputs.native_public_sums),
        std.mem.asBytes(inputs.verified_receipt),
        std.mem.asBytes(inputs.relations),
        std.mem.sliceAsBytes(inputs.component_descs),
        std.mem.sliceAsBytes(inputs.infra_descs),
        std.mem.asBytes(inputs.vm_plan),
        std.mem.sliceAsBytes(inputs.vm_plan.steps),
    };
}

pub fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

pub fn arithmeticGraphBindingId(
    binding: ArithmeticGraphBindingV2,
) Sha256Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(ARITHMETIC_BINDING_ID_DOMAIN);
    shaInt(&hash, u16, binding.format_version);
    shaInt(&hash, u16, binding.schema_version);
    shaInt(&hash, u32, binding.circuit_id);
    shaInt(&hash, u32, binding.input_count);
    for (binding.prepared_source_id) |word|
        shaInt(&hash, u32, word);
    for (binding.lowering_obligation_id) |word|
        shaInt(&hash, u32, word);
    hash.update(&binding.graph_identity);
    hash.update(&binding.circuit_identity);
    for (binding.input_use_counts) |count| shaInt(&hash, u32, count);
    return hash.finalResult();
}

pub fn sourceId(prepared: *const PreparedV2) Digest {
    var hash = IdentityHasher.init(SOURCE_ID_DOMAIN);
    hash.scalar(prepared.format_version);
    hash.scalar(prepared.schema_version);
    hash.digest(prepared.manifest.identity);
    hash.digest(prepared.wire_id);
    hash.digest(prepared.receipt_id);
    hash.digest(prepared.statement_authority_id);
    hash.digest(prepared.source_authority_id);
    hash.digest(prepared.publication_id);
    hash.digest(prepared.native_public_sums_id);
    hash.digest(prepared.relation_context_id);
    hash.qm31(prepared.public_sums.registers_state);
    hash.qm31(prepared.public_sums.memory_access);
    hash.qm31(prepared.public_sums.program_access);
    hash.qm31(prepared.public_sums.merkle);
    hash.qm31(prepared.public_total);
    hash.digest(prepared.lowering_obligation.identity);
    hash.digest(prepared.authority_hash_plan.identity);
    hash.shaDigest(prepared.control.identity);
    return hash.finalize();
}

pub fn shaInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: anytype,
) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub fn preparedEql(left: *const PreparedV2, right: *const PreparedV2) bool {
    return left.format_version == right.format_version and
        left.schema_version == right.schema_version and
        std.meta.eql(left.manifest, right.manifest) and
        std.meta.eql(left.capability_ledger, right.capability_ledger) and
        std.meta.eql(left.wire_id, right.wire_id) and
        std.meta.eql(left.receipt_id, right.receipt_id) and
        std.meta.eql(left.statement_authority_id, right.statement_authority_id) and
        std.meta.eql(left.source_authority_id, right.source_authority_id) and
        std.meta.eql(left.publication_id, right.publication_id) and
        std.meta.eql(left.native_public_sums_id, right.native_public_sums_id) and
        std.meta.eql(left.relation_context_id, right.relation_context_id) and
        sumsEql(left.public_sums, right.public_sums) and
        left.public_total.eql(right.public_total) and
        std.meta.eql(left.lowering_obligation, right.lowering_obligation) and
        std.meta.eql(left.authority_hash_plan, right.authority_hash_plan) and
        std.meta.eql(left.control, right.control) and
        std.meta.eql(left.source_id, right.source_id);
}

pub fn felt(value: anytype) M31 {
    const canonical: u32 = @intCast(value);
    std.debug.assert(canonical < m31.Modulus);
    return M31.fromCanonical(canonical);
}
