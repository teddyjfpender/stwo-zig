//! Sealed V2 receipt for a current-segment-authority bulk-memcpy microproof.

const std = @import("std");
const stwo_core = @import("stwo_core");

const authority_mod = @import("bulk_memcpy_current_selected_segment_authority_v1.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const v1 = @import("bulk_memcpy_retained_microproof_receipt_v1.zig");

pub const schema = "stwo.riscv.bulk-memcpy-retained-microproof.v2";
pub const status = "cold-fresh-verified-current-segment0-diagnostic-only";
pub const selection_rule = authority_mod.selection_rule;
pub const boundary_caveat =
    "current pass1 captures and seals the genuine const-only pre-retirement boundary and canonical tape while continuing through complete segment0; pass2 reexecutes current ELF/input to TraceRow.clk-1 and byte-matches that projection exactly";
pub const binding_scope =
    "authority-bound artifact custody only; the current-segment authority is not committed by the standalone bulk-memcpy AIR public statement";
pub const maximum_word_row_cap = authority_mod.maximum_word_rows;
pub const maximum_hard_cap_ns = v1.maximum_hard_cap_ns;
pub const maximum_receipt_bytes: usize = 1024 * 1024;

pub const FileIdentity = v1.FileIdentity;
pub const Timing = v1.Timing;
pub const CallDescriptor = v1.CallDescriptor;
pub const Selector = v1.Selector;
pub const ExecutionPass = v1.ExecutionPass;
pub const Pcs = v1.Pcs;
pub const ProveTimings = v1.ProveTimings;
pub const diagnostic_pcs = Pcs{
    .fold_step = 1,
    .log_blowup_factor = 1,
    .log_last_layer_degree_bound = 0,
    .n_queries = 3,
    .pow_bits = 0,
};

pub const Authorities = struct {
    current_selected_segment_authority: FileIdentity,
    current_selected_segment_authority_content_sha256: []const u8,
    elf: FileIdentity,
    historical_journal: FileIdentity,
    historical_observation: FileIdentity,
    historical_observation_content_sha256: []const u8,
    historical_role: []const u8,
    input: FileIdentity,
    source_request: FileIdentity,
};

pub const Boundary = struct {
    current_segment_entry_cpu_sha256: []const u8,
    current_segment_exit_cpu_sha256: []const u8,
    global_execution_cycle: u64,
    identity_sha256: []const u8,
    replay_access_clocks_sha256: []const u8,
    replay_cpu_sha256: []const u8,
    replay_rw_memory_sha256: []const u8,
    segment_index: u32,
    trace_clock: u32,
};

pub const ProofCustody = struct {
    authority_bound_proof_identity_sha256: []const u8,
    authority_bound_statement_identity_sha256: []const u8,
    binding_scope: []const u8,
    call_relation_closed: bool,
    cold_fresh_verified: bool,
    external_base_tables_required: bool,
    joint_custody_identity_sha256: []const u8,
    pcs: Pcs,
    producer_executable_sha256: []const u8,
    production_eligible: bool,
    proof: FileIdentity,
    proof_roots_sha256: []const u8,
    prove_timings: ProveTimings,
    statement: FileIdentity,
    statement_identity_sha256: []const u8,
    tape: FileIdentity,
    tape_identity_sha256: []const u8,
    verify_timing: Timing,
};

pub const UnsignedReceiptV2 = struct {
    authorities: Authorities,
    boundary: Boundary,
    boundary_authority_caveat: []const u8,
    execution_passes: [2]ExecutionPass,
    hard_cap_ns: u64,
    production: bool,
    proof: ProofCustody,
    schema: []const u8,
    selector: Selector,
    status: []const u8,
    total_timing: Timing,
};

pub const ReceiptV2 = struct {
    content_sha256: []const u8,
    authorities: Authorities,
    boundary: Boundary,
    boundary_authority_caveat: []const u8,
    execution_passes: [2]ExecutionPass,
    hard_cap_ns: u64,
    production: bool,
    proof: ProofCustody,
    schema: []const u8,
    selector: Selector,
    status: []const u8,
    total_timing: Timing,

    pub fn validate(self: ReceiptV2) !void {
        if (!std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.status, status) or
            !std.mem.eql(u8, self.selector.rule, authority_mod.selection_rule) or
            !std.mem.eql(
                u8,
                self.authorities.historical_role,
                authority_mod.historical_role,
            ) or
            !std.mem.eql(u8, self.boundary_authority_caveat, boundary_caveat) or
            !std.mem.eql(u8, self.proof.binding_scope, binding_scope) or
            self.production or self.proof.production_eligible or
            !self.proof.call_relation_closed or
            !self.proof.external_base_tables_required or
            !self.proof.cold_fresh_verified or
            self.hard_cap_ns == 0 or self.hard_cap_ns > maximum_hard_cap_ns or
            self.selector.max_word_rows != maximum_word_row_cap or
            self.selector.selected_word_rows == 0 or
            self.selector.selected_word_rows > self.selector.max_word_rows or
            self.selector.descriptor.execution_clock != self.boundary.trace_clock or
            self.selector.descriptor.projected_inst_word != 0x08c5_850b or
            self.boundary.segment_index != 0 or self.boundary.trace_clock <= 1 or
            self.execution_passes[0].segments != 1 or
            self.execution_passes[1].segments != 1 or
            self.execution_passes[0].cycles == 0 or
            self.execution_passes[1].cycles == 0 or
            self.execution_passes[0].core_rows == 0 or
            self.execution_passes[1].core_rows == 0 or
            !pcsMatchesDiagnostic(self.proof.pcs))
        {
            return error.InvalidRetainedMicroproofReceiptV2;
        }
        try self.authorities.current_selected_segment_authority.validate(false);
        try self.authorities.elf.validate(false);
        try self.authorities.input.validate(true);
        try self.authorities.historical_journal.validate(false);
        try self.authorities.historical_observation.validate(false);
        try self.authorities.source_request.validate(false);
        try self.proof.proof.validate(false);
        try self.proof.statement.validate(false);
        try self.proof.tape.validate(false);
        inline for (.{
            self.content_sha256,
            self.authorities.current_selected_segment_authority_content_sha256,
            self.authorities.historical_observation_content_sha256,
            self.boundary.current_segment_entry_cpu_sha256,
            self.boundary.current_segment_exit_cpu_sha256,
            self.boundary.identity_sha256,
            self.boundary.replay_access_clocks_sha256,
            self.boundary.replay_cpu_sha256,
            self.boundary.replay_rw_memory_sha256,
            self.proof.authority_bound_proof_identity_sha256,
            self.proof.authority_bound_statement_identity_sha256,
            self.proof.joint_custody_identity_sha256,
            self.proof.producer_executable_sha256,
            self.proof.proof_roots_sha256,
            self.proof.statement_identity_sha256,
            self.proof.tape_identity_sha256,
            self.selector.identity_sha256,
        }) |digest_text| try requireDigest(digest_text);

        const authority_file = try digest(
            self.authorities.current_selected_segment_authority.sha256,
        );
        const authority_content = try digest(
            self.authorities.current_selected_segment_authority_content_sha256,
        );
        const statement_file = try digest(self.proof.statement.sha256);
        const statement_identity = try digest(self.proof.statement_identity_sha256);
        const expected_statement = boundStatementIdentity(
            authority_file,
            authority_content,
            statement_file,
            statement_identity,
        );
        if (!std.meta.eql(
            expected_statement,
            try digest(self.proof.authority_bound_statement_identity_sha256),
        )) return error.InvalidRetainedMicroproofReceiptV2;
        const expected_proof = boundProofIdentity(
            authority_file,
            authority_content,
            expected_statement,
            try digest(self.proof.proof.sha256),
            try digest(self.proof.proof_roots_sha256),
            try digest(self.proof.tape_identity_sha256),
        );
        if (!std.meta.eql(
            expected_proof,
            try digest(self.proof.authority_bound_proof_identity_sha256),
        )) return error.InvalidRetainedMicroproofReceiptV2;
        const expected_joint = jointCustodyIdentity(
            authority_file,
            authority_content,
            expected_statement,
            expected_proof,
        );
        if (!std.meta.eql(
            expected_joint,
            try digest(self.proof.joint_custody_identity_sha256),
        )) return error.InvalidRetainedMicroproofReceiptV2;
    }
};

fn pcsMatchesDiagnostic(actual: Pcs) bool {
    return std.meta.eql(actual, diagnostic_pcs);
}

pub fn encode(
    allocator: std.mem.Allocator,
    value: UnsignedReceiptV2,
) ![]u8 {
    const unsigned = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(unsigned);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(unsigned);
    hash.update("\n");
    const content = std.fmt.bytesToHex(hash.finalResult(), .lower);
    const body = try std.fmt.allocPrint(
        allocator,
        "{{\"content_sha256\":\"{s}\",{s}\n",
        .{ &content, unsigned[1..] },
    );
    errdefer allocator.free(body);
    if (body.len > maximum_receipt_bytes)
        return error.InvalidRetainedMicroproofReceiptV2;
    var parsed = try parse(allocator, body);
    parsed.deinit();
    return body;
}

pub fn parse(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(ReceiptV2) {
    if (bytes.len == 0 or bytes.len > maximum_receipt_bytes or
        bytes[bytes.len - 1] != '\n')
    {
        return error.InvalidRetainedMicroproofReceiptV2;
    }
    const body = bytes[0 .. bytes.len - 1];
    var parsed = try std.json.parseFromSlice(ReceiptV2, allocator, body, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    errdefer parsed.deinit();
    const canonical = try std.json.Stringify.valueAlloc(
        allocator,
        parsed.value,
        .{},
    );
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, body))
        return error.NonCanonicalRetainedMicroproofReceiptV2;
    try parsed.value.validate();
    const unsigned = try std.json.Stringify.valueAlloc(
        allocator,
        withoutSeal(parsed.value),
        .{},
    );
    defer allocator.free(unsigned);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(unsigned);
    hash.update("\n");
    const expected = std.fmt.bytesToHex(hash.finalResult(), .lower);
    if (!std.mem.eql(u8, parsed.value.content_sha256, &expected))
        return error.InvalidRetainedMicroproofReceiptV2Seal;
    return parsed;
}

pub fn validateAgainstAuthority(
    receipt: ReceiptV2,
    authority: authority_mod.AuthorityV1,
    authority_file: evidence.FileIdentity,
) !void {
    try receipt.validate();
    try authority.validate();
    const expected_boundary_identity = try currentBoundaryIdentity(authority);
    if (!fileMatches(
        receipt.authorities.current_selected_segment_authority,
        authority_file,
    ) or !std.mem.eql(
        u8,
        receipt.authorities.current_selected_segment_authority_content_sha256,
        authority.content_sha256,
    ) or !wireFilesEqual(
        receipt.authorities.elf,
        authority.current_authorities.elf,
    ) or !wireFilesEqual(
        receipt.authorities.input,
        authority.current_authorities.input,
    ) or !wireFilesEqual(
        receipt.authorities.source_request,
        authority.current_authorities.source_request,
    ) or !wireFilesEqual(
        receipt.authorities.historical_journal,
        authority.historical_custody.journal,
    ) or !wireFilesEqual(
        receipt.authorities.historical_observation,
        authority.historical_custody.observation,
    ) or !std.mem.eql(
        u8,
        receipt.authorities.historical_observation_content_sha256,
        authority.historical_custody.observation_content_sha256,
    ) or !std.mem.eql(
        u8,
        receipt.proof.producer_executable_sha256,
        authority.current_authorities.producer_executable.sha256,
    ) or !std.mem.eql(
        u8,
        receipt.selector.identity_sha256,
        authority.selector.identity_sha256,
    ) or !std.mem.eql(
        u8,
        receipt.boundary.current_segment_entry_cpu_sha256,
        authority.current_segment.entry.cpu_sha256,
    ) or !std.mem.eql(
        u8,
        receipt.boundary.current_segment_exit_cpu_sha256,
        authority.current_segment.exit.cpu_sha256,
    ) or !std.mem.eql(
        u8,
        receipt.boundary.replay_access_clocks_sha256,
        authority.selected_boundary_projection.boundary.access_clocks_sha256,
    ) or !std.mem.eql(
        u8,
        receipt.boundary.replay_cpu_sha256,
        authority.selected_boundary_projection.boundary.cpu_sha256,
    ) or !std.mem.eql(
        u8,
        receipt.boundary.replay_rw_memory_sha256,
        authority.selected_boundary_projection.boundary.rw_memory_sha256,
    ) or !std.mem.eql(
        u8,
        receipt.proof.tape.sha256,
        authority.selected_boundary_projection.canonical_tape_sha256,
    ) or !std.mem.eql(
        u8,
        receipt.proof.tape_identity_sha256,
        authority.selected_boundary_projection.tape_identity_sha256,
    ) or !std.meta.eql(
        try digest(receipt.boundary.identity_sha256),
        expected_boundary_identity,
    ) or receipt.boundary.segment_index != authority.current_segment.segment_index or
        receipt.boundary.trace_clock != authority.selector.trace_row_clk or
        receipt.selector.selected_execution_ordinal !=
            authority.selector.selected_execution_ordinal or
        receipt.selector.selected_word_rows != authority.selector.selected_word_rows)
    {
        return error.RetainedMicroproofAuthorityBindingMismatch;
    }
}

fn currentBoundaryIdentity(
    authority: authority_mod.AuthorityV1,
) ![32]u8 {
    const selector = authority.selector;
    const descriptor = selector.descriptor;
    const boundary = authority.selected_boundary_projection.boundary;
    const authority_content = try digest(authority.content_sha256);
    const boundary_cpu = try digest(boundary.cpu_sha256);
    const boundary_memory = try digest(boundary.rw_memory_sha256);
    const boundary_clocks = try digest(boundary.access_clocks_sha256);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/bulk-memcpy-current-replay-boundary/v2\x00");
    hash.update(&authority_content);
    hashInt(&hash, u32, authority.current_segment.segment_index);
    hashInt(&hash, u32, selector.trace_row_clk);
    hashInt(&hash, u32, descriptor.destination);
    hashInt(&hash, u32, selector.trace_row_clk);
    hashInt(&hash, u32, descriptor.length);
    hashInt(&hash, u32, descriptor.pc);
    hashInt(&hash, u32, descriptor.projected_inst_word);
    hashInt(&hash, u32, descriptor.return_pc);
    hashInt(&hash, u32, descriptor.software_inst_word);
    hashInt(&hash, u32, descriptor.source);
    hashInt(&hash, u32, boundary.pc);
    hash.update(&boundary_cpu);
    hash.update(&boundary_memory);
    hashInt(&hash, u64, boundary.rw_memory_retained_words);
    hashInt(&hash, u64, boundary.rw_memory_nonzero_words);
    hashInt(&hash, u64, boundary.rw_memory_zero_words);
    hash.update(&boundary_clocks);
    hashInt(&hash, u64, boundary.memory_access_clock_entries);
    return hash.finalResult();
}

pub fn boundStatementIdentity(
    authority_file: [32]u8,
    authority_content: [32]u8,
    statement_file: [32]u8,
    statement_identity: [32]u8,
) [32]u8 {
    return hashParts(
        "stwo-zig/riscv/bulk-memcpy-authority-bound-statement/v1\x00",
        &.{ authority_file, authority_content, statement_file, statement_identity },
    );
}

pub fn boundProofIdentity(
    authority_file: [32]u8,
    authority_content: [32]u8,
    bound_statement: [32]u8,
    proof_file: [32]u8,
    proof_roots: [32]u8,
    tape_identity: [32]u8,
) [32]u8 {
    return hashParts(
        "stwo-zig/riscv/bulk-memcpy-authority-bound-proof/v1\x00",
        &.{
            authority_file,
            authority_content,
            bound_statement,
            proof_file,
            proof_roots,
            tape_identity,
        },
    );
}

pub fn jointCustodyIdentity(
    authority_file: [32]u8,
    authority_content: [32]u8,
    bound_statement: [32]u8,
    bound_proof: [32]u8,
) [32]u8 {
    return hashParts(
        "stwo-zig/riscv/bulk-memcpy-current-custody-closure/v1\x00",
        &.{ authority_file, authority_content, bound_statement, bound_proof },
    );
}

fn withoutSeal(value: ReceiptV2) UnsignedReceiptV2 {
    return .{
        .authorities = value.authorities,
        .boundary = value.boundary,
        .boundary_authority_caveat = value.boundary_authority_caveat,
        .execution_passes = value.execution_passes,
        .hard_cap_ns = value.hard_cap_ns,
        .production = value.production,
        .proof = value.proof,
        .schema = value.schema,
        .selector = value.selector,
        .status = value.status,
        .total_timing = value.total_timing,
    };
}

fn hashParts(domain: []const u8, parts: []const [32]u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(domain);
    for (parts) |part| hash.update(&part);
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn fileMatches(wire: FileIdentity, expected: evidence.FileIdentity) bool {
    return wire.bytes == expected.bytes and
        std.mem.eql(u8, wire.path, expected.path) and
        std.meta.eql(digest(wire.sha256) catch return false, expected.sha256);
}

fn wireFilesEqual(left: FileIdentity, right: authority_mod.FileIdentity) bool {
    return left.bytes == right.bytes and
        std.mem.eql(u8, left.path, right.path) and
        std.mem.eql(u8, left.sha256, right.sha256);
}

fn requireDigest(value: []const u8) !void {
    _ = try digest(value);
}

fn digest(value: []const u8) ![32]u8 {
    if (value.len != 64) return error.InvalidRetainedMicroproofReceiptV2;
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch
        return error.InvalidRetainedMicroproofReceiptV2;
    return result;
}

test "authority-bound proof custody changes with every authority digest" {
    const statement = boundStatementIdentity(
        .{1} ** 32,
        .{2} ** 32,
        .{3} ** 32,
        .{4} ** 32,
    );
    const proof = boundProofIdentity(
        .{1} ** 32,
        .{2} ** 32,
        statement,
        .{5} ** 32,
        .{6} ** 32,
        .{7} ** 32,
    );
    const mutated_statement = boundStatementIdentity(
        .{9} ** 32,
        .{2} ** 32,
        .{3} ** 32,
        .{4} ** 32,
    );
    const mutated_proof = boundProofIdentity(
        .{9} ** 32,
        .{2} ** 32,
        mutated_statement,
        .{5} ** 32,
        .{6} ** 32,
        .{7} ** 32,
    );
    try std.testing.expect(!std.meta.eql(statement, mutated_statement));
    try std.testing.expect(!std.meta.eql(proof, mutated_proof));
    try std.testing.expect(!std.meta.eql(
        jointCustodyIdentity(.{1} ** 32, .{2} ** 32, statement, proof),
        jointCustodyIdentity(
            .{9} ** 32,
            .{2} ** 32,
            mutated_statement,
            mutated_proof,
        ),
    ));
}

test "V2 receipt pins the exact live three-query diagnostic PCS" {
    const config = stwo_core.pcs.PcsConfig{
        .pow_bits = 0,
        .fri_config = try stwo_core.fri.FriConfig.init(0, 1, 3),
    };
    const from_prover = Pcs{
        .fold_step = config.fri_config.fold_step,
        .log_blowup_factor = config.fri_config.log_blowup_factor,
        .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound,
        .n_queries = @intCast(config.fri_config.n_queries),
        .pow_bits = config.pow_bits,
    };
    try std.testing.expect(pcsMatchesDiagnostic(from_prover));
    try std.testing.expectEqual(@as(u32, 1), from_prover.log_blowup_factor);
    try std.testing.expectEqual(
        @as(u32, 0),
        from_prover.log_last_layer_degree_bound,
    );
    try std.testing.expectEqual(@as(u32, 3), from_prover.n_queries);

    var stale_one_query = from_prover;
    stale_one_query.n_queries = 1;
    try std.testing.expect(!pcsMatchesDiagnostic(stale_one_query));
}
