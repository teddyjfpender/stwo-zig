//! Materialized field witness for the recursive Ethereum child emitters.
//!
//! Construction starts from verifier-retained V2 public data/context/receipt
//! plus the transcript Tree0 commitment.  Both Poseidon preimages are rebuilt
//! word-for-word and checked against the native protocol identities.  The
//! resulting rows are still only a wrapper sub-witness: ProgramV2 and provider
//! proof authorities remain mandatory before fresh wrapper verification.

const std = @import("std");
const core = @import("stwo_core");

const public_data_v2 = @import("../air/public_data_v2.zig");
const statement_v1 = @import("../air/statement.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const hash_air = @import("air/vm_public_claim_hash.zig");
const hash_witness = @import("air/vm_public_claim_hash_witness.zig");
const router_air = @import("air/ethereum_leaf_child_field_router_v1.zig");
const program_mod = @import("ethereum_leaf_child_field_program_v1.zig");
const leaf_source = @import("air/ethereum_leaf_link_source_v1.zig");
const leaf_v2 = @import("segment_leaf_authority_v2.zig");
const channel = @import("poseidon2_channel.zig");

const M31 = core.fields.m31.M31;
const m31 = core.fields.m31;

pub const InputsV1 = struct {
    public_data: *const public_data_v2.PublicDataV2,
    context: *const leaf_v2.NativeTemporalContextV2,
    receipt: *const statement_v2.VerifiedReceipt,
    tree0_root: channel.Digest,
    component_descs: []const statement_v1.FamilyComponentDesc,
    infra_descs: []const statement_v1.InfraComponentDesc,
};

pub const HashWitnessV1 = struct {
    main_rows: []hash_witness.MainRow,
    poseidon_calls: []hash_witness.PoseidonCall,

    fn deinit(self: *HashWitnessV1, allocator: std.mem.Allocator) void {
        allocator.free(self.poseidon_calls);
        allocator.free(self.main_rows);
        self.* = undefined;
    }
};

pub const WitnessV1 = struct {
    allocator: std.mem.Allocator,
    router_rows: []router_air.Row,
    authority_words: []M31,
    receipt_words: [program_mod.RECEIPT_WORD_COUNT]M31,
    authority_hash: HashWitnessV1,
    receipt_hash: HashWitnessV1,
    local_authority_digest: channel.Digest,
    local_wire_digest: channel.Digest,
    local_receipt_digest: channel.Digest,
    tree0_root: channel.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        program: *const program_mod.ProgramV1,
        input: InputsV1,
    ) !WitnessV1 {
        var result = try buildUnchecked(allocator, program, input);
        errdefer result.deinit();
        try result.validateAgainst(program, input);
        return result;
    }

    pub fn deinit(self: *WitnessV1) void {
        self.receipt_hash.deinit(self.allocator);
        self.authority_hash.deinit(self.allocator);
        self.allocator.free(self.authority_words);
        self.allocator.free(self.router_rows);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const WitnessV1,
        program: *const program_mod.ProgramV1,
        input: InputsV1,
    ) !void {
        try validateInputs(program, input);
        var expected = try buildUnchecked(self.allocator, program, input);
        defer expected.deinit();
        if (!metaSliceEqual(router_air.Row, self.router_rows, expected.router_rows) or
            !metaSliceEqual(M31, self.authority_words, expected.authority_words) or
            !std.meta.eql(self.receipt_words, expected.receipt_words) or
            !hashWitnessEqual(&self.authority_hash, &expected.authority_hash) or
            !hashWitnessEqual(&self.receipt_hash, &expected.receipt_hash) or
            !std.meta.eql(self.local_authority_digest, expected.local_authority_digest) or
            !std.meta.eql(self.local_wire_digest, expected.local_wire_digest) or
            !std.meta.eql(self.local_receipt_digest, expected.local_receipt_digest) or
            !std.meta.eql(self.tree0_root, expected.tree0_root))
        {
            return error.InvalidEthereumChildFieldWitness;
        }
    }

    pub fn authorityHashLogicalRow(
        self: *const WitnessV1,
        program: *const program_mod.ProgramV1,
        index: usize,
    ) ![hash_air.LOGICAL_INPUT_COUNT]M31 {
        if (index >= self.authority_hash.main_rows.len or
            index >= program.authority_hash.rows.len)
        {
            return error.InvalidEthereumChildFieldWitness;
        }
        return hashLogicalRow(
            self.authority_hash.main_rows[index],
            program.authority_hash.rows[index],
            &program.authority_hash,
        );
    }

    pub fn receiptHashLogicalRow(
        self: *const WitnessV1,
        program: *const program_mod.ProgramV1,
        index: usize,
    ) ![hash_air.LOGICAL_INPUT_COUNT]M31 {
        if (index >= self.receipt_hash.main_rows.len or
            index >= program.receipt_hash.rows.len)
        {
            return error.InvalidEthereumChildFieldWitness;
        }
        return hashLogicalRow(
            self.receipt_hash.main_rows[index],
            program.receipt_hash.rows[index],
            &program.receipt_hash,
        );
    }
};

fn buildUnchecked(
    allocator: std.mem.Allocator,
    program: *const program_mod.ProgramV1,
    input: InputsV1,
) !WitnessV1 {
    try validateInputs(program, input);
    const context_words = try input.context.canonicalWords();
    const wire_words = input.public_data.words();
    const router_rows = try allocator.alloc(router_air.Row, program.router_rows.len);
    errdefer allocator.free(router_rows);
    const authority_words = try allocator.alloc(M31, program.authority_hash.word_count);
    errdefer allocator.free(authority_words);
    const authority_seen = try allocator.alloc(bool, authority_words.len);
    defer allocator.free(authority_seen);
    @memset(authority_seen, false);
    var receipt_words: [program_mod.RECEIPT_WORD_COUNT]M31 = undefined;
    var receipt_seen = [_]bool{false} ** program_mod.RECEIPT_WORD_COUNT;

    for (program.router_rows, router_rows) |schedule, *logical| {
        const value = try valueForRow(
            schedule,
            wire_words,
            &context_words,
            input.receipt,
            input.tree0_root,
        );
        logical.* = schedule.logical(value);
        if (schedule.raw_a_sink_mask == 1) try assignRaw(
            schedule.raw_a_scope,
            schedule.raw_a_index,
            value,
            authority_words,
            authority_seen,
            &receipt_words,
            &receipt_seen,
        );
        if (schedule.raw_b_sink_mask == 1) try assignRaw(
            schedule.raw_b_scope,
            schedule.raw_b_index,
            value,
            authority_words,
            authority_seen,
            &receipt_words,
            &receipt_seen,
        );
    }
    for (authority_seen) |seen| if (!seen)
        return error.InvalidEthereumChildFieldWitness;
    for (receipt_seen) |seen| if (!seen)
        return error.InvalidEthereumChildFieldWitness;

    var authority_hash = try materializeHash(
        allocator,
        &program.authority_hash,
        authority_words,
        input.receipt.authority_id,
    );
    errdefer authority_hash.deinit(allocator);
    var receipt_hash = try materializeHash(
        allocator,
        &program.receipt_hash,
        &receipt_words,
        input.receipt.identity,
    );
    errdefer receipt_hash.deinit(allocator);
    return .{
        .allocator = allocator,
        .router_rows = router_rows,
        .authority_words = authority_words,
        .receipt_words = receipt_words,
        .authority_hash = authority_hash,
        .receipt_hash = receipt_hash,
        .local_authority_digest = input.receipt.authority_id,
        .local_wire_digest = input.receipt.wire_id,
        .local_receipt_digest = input.receipt.identity,
        .tree0_root = input.tree0_root,
    };
}

fn validateInputs(program: *const program_mod.ProgramV1, input: InputsV1) !void {
    try program.validateAgainst(input.component_descs, input.infra_descs);
    try input.public_data.validate();
    try input.receipt.validateAgainst(input.public_data);
    const context_words = try input.context.canonicalWords();
    const expected_authority = try statement_v2.authorityIdentityFromGeometry(
        input.public_data,
        input.component_descs,
        input.infra_descs,
    );
    if (!std.meta.eql(expected_authority, input.receipt.authority_id) or
        !std.meta.eql(input.public_data.wireId(), input.receipt.wire_id))
    {
        return error.InvalidEthereumChildFieldWitness;
    }
    const wire_start = leaf_v2.CONTEXT_SEGMENT_WIRE_ID_START;
    for (input.receipt.wire_id, context_words[wire_start..][0..8]) |
        expected,
        actual,
    | if (actual.toU32() != expected)
        return error.InvalidEthereumChildFieldWitness;
    try requireDigest(input.tree0_root);
}

fn valueForRow(
    row: program_mod.RouterScheduleRowV1,
    wire_words: []const M31,
    context_words: *const [leaf_v2.CONTEXT_WORD_COUNT]M31,
    receipt: *const statement_v2.VerifiedReceipt,
    tree0_root: channel.Digest,
) !M31 {
    if (row.constant_source_mask == 1)
        return M31.fromCanonical(row.constant_value);
    if (row.statement_source_mask == 1) {
        const words = if (row.statement_scope == leaf_v2.WIRE_SCOPE)
            wire_words
        else if (row.statement_scope == leaf_v2.CONTEXT_SCOPE)
            context_words
        else
            return error.InvalidEthereumChildFieldWitness;
        if (row.statement_index >= words.len)
            return error.InvalidEthereumChildFieldWitness;
        return words[row.statement_index];
    }
    if (row.verifier_source_mask == 1) {
        if (row.source_verifier_kind != 4 or row.source_index_0 != 0 or
            row.source_index_1 >= tree0_root.len)
        {
            return error.InvalidEthereumChildFieldWitness;
        }
        return M31.fromCanonical(tree0_root[row.source_index_1]);
    }
    if (row.derived_source_mask == 1) {
        const digest_value = if (row.sink_verifier_kind ==
            leaf_source.LOCAL_AUTHORITY_DIGEST_KIND)
            receipt.authority_id
        else if (row.sink_verifier_kind == leaf_source.LOCAL_RECEIPT_DIGEST_KIND)
            receipt.identity
        else
            return error.InvalidEthereumChildFieldWitness;
        if (row.sink_index_0 != 0 or row.sink_index_1 >= digest_value.len)
            return error.InvalidEthereumChildFieldWitness;
        return M31.fromCanonical(digest_value[row.sink_index_1]);
    }
    return error.InvalidEthereumChildFieldWitness;
}

fn assignRaw(
    scope: u32,
    raw_index: u32,
    value: M31,
    authority_words: []M31,
    authority_seen: []bool,
    receipt_words: *[program_mod.RECEIPT_WORD_COUNT]M31,
    receipt_seen: *[program_mod.RECEIPT_WORD_COUNT]bool,
) !void {
    const index: usize = raw_index;
    if (scope == program_mod.AUTHORITY_PREIMAGE_SCOPE) {
        if (index >= authority_words.len or authority_seen[index])
            return error.InvalidEthereumChildFieldWitness;
        authority_words[index] = value;
        authority_seen[index] = true;
    } else if (scope == program_mod.RECEIPT_PREIMAGE_SCOPE) {
        if (index >= receipt_words.len or receipt_seen[index])
            return error.InvalidEthereumChildFieldWitness;
        receipt_words[index] = value;
        receipt_seen[index] = true;
    } else return error.InvalidEthereumChildFieldWitness;
}

fn materializeHash(
    allocator: std.mem.Allocator,
    schedule: *const program_mod.HashScheduleV1,
    words: []const M31,
    expected_digest: channel.Digest,
) !HashWitnessV1 {
    if (words.len != schedule.word_count)
        return error.InvalidEthereumChildFieldWitness;
    const main_rows = try allocator.alloc(hash_witness.MainRow, schedule.rows.len);
    errdefer allocator.free(main_rows);
    const calls = try allocator.alloc(hash_witness.PoseidonCall, schedule.rows.len);
    errdefer allocator.free(calls);
    var state = [_]M31{M31.zero()} ** hash_witness.STATE_WIDTH;
    state[hash_witness.STATE_WIDTH - 1] = M31.fromCanonical(schedule.domain);
    for (schedule.rows, main_rows, calls) |preprocessed, *main, *call| {
        main.* = hash_witness.materialize(preprocessed, words, state);
        call.* = hash_witness.callFor(main.*);
        state = main.output;
    }
    for (expected_digest, state[0..program_mod.DIGEST_WORD_COUNT]) |expected, actual|
        if (actual.toU32() != expected)
            return error.InvalidEthereumChildFieldWitness;
    return .{ .main_rows = main_rows, .poseidon_calls = calls };
}

fn hashLogicalRow(
    main: hash_witness.MainRow,
    preprocessed: hash_witness.PreprocessedRow,
    schedule: *const program_mod.HashScheduleV1,
) [hash_air.LOGICAL_INPUT_COUNT]M31 {
    return main.values() ++ preprocessed.values() ++ .{
        M31.one(),
        M31.fromCanonical(schedule.domain),
        M31.fromCanonical(schedule.scope),
        M31.fromCanonical(leaf_source.VERIFIER_ID),
        M31.fromCanonical(schedule.digest_kind),
    };
}

fn hashWitnessEqual(left: *const HashWitnessV1, right: *const HashWitnessV1) bool {
    return metaSliceEqual(hash_witness.MainRow, left.main_rows, right.main_rows) and
        metaSliceEqual(
            hash_witness.PoseidonCall,
            left.poseidon_calls,
            right.poseidon_calls,
        );
}

fn metaSliceEqual(comptime T: type, left: []const T, right: []const T) bool {
    if (left.len != right.len) return false;
    for (left, right) |left_value, right_value| {
        if (!std.meta.eql(left_value, right_value)) return false;
    }
    return true;
}

fn requireDigest(value: channel.Digest) !void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus)
            return error.InvalidEthereumChildFieldWitness;
        aggregate |= word;
    }
    if (aggregate == 0) return error.InvalidEthereumChildFieldWitness;
}
