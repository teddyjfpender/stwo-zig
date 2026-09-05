//! Sealed diagnostic receipt for a replay-derived retained bulk-memcpy proof.

const std = @import("std");

pub const schema = "stwo.riscv.bulk-memcpy-retained-microproof.v1";
pub const status = "cold-fresh-verified-diagnostic-only";
pub const selection_rule =
    "first execution-ordered memcpy entry for which validateRunnerCall succeeds and expectedWordCount()<=max_word_rows";
pub const boundary_caveat =
    "boundary is deterministically replay-derived from retained ELF/input/journal; the aggregate observation does not itself contain per-call boundary custody";
pub const maximum_word_row_cap: u32 = 16;
pub const maximum_hard_cap_ns: u64 = 60 * std.time.ns_per_s;
pub const maximum_receipt_bytes: usize = 512 * 1024;

pub const FileIdentity = struct {
    bytes: u64,
    path: []const u8,
    sha256: []const u8,

    pub fn validate(self: FileIdentity, allow_empty: bool) !void {
        if ((!allow_empty and self.bytes == 0) or
            !std.fs.path.isAbsolute(self.path))
        {
            return error.InvalidRetainedMicroproofReceipt;
        }
        try requireDigest(self.sha256);
    }
};

pub const Timing = struct {
    system_ns: u64,
    user_ns: u64,
    wall_ns: u64,
};

pub const Authorities = struct {
    elf: FileIdentity,
    input: FileIdentity,
    journal: FileIdentity,
    journal_record_sha256: []const u8,
    observation: FileIdentity,
    observation_content_sha256: []const u8,
    source_request: FileIdentity,
};

pub const CallDescriptor = struct {
    destination: u32,
    execution_clock: u32,
    length: u32,
    pc: u32,
    projected_inst_word: u32,
    return_pc: u32,
    software_inst_word: u32,
    source: u32,
};

pub const Selector = struct {
    descriptor: CallDescriptor,
    identity_sha256: []const u8,
    max_word_rows: u32,
    rule: []const u8,
    selected_execution_ordinal: u64,
    selected_word_rows: u32,
};

pub const Boundary = struct {
    full_segment_entry_cpu_sha256: []const u8,
    full_segment_exit_cpu_sha256: []const u8,
    global_execution_cycle: u64,
    identity_sha256: []const u8,
    replay_access_clocks_sha256: []const u8,
    replay_cpu_sha256: []const u8,
    replay_rw_memory_sha256: []const u8,
    segment_index: u32,
    trace_clock: u32,
};

pub const ExecutionPass = struct {
    core_rows: u64,
    cycles: u64,
    segments: u32,
    timing: Timing,
};

pub const Pcs = struct {
    fold_step: u32,
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    n_queries: u32,
    pow_bits: u32,
};

pub const ProveTimings = struct {
    interaction_commit_ns: u64,
    interaction_generation_ns: u64,
    main_commit_ns: u64,
    preprocessed_commit_ns: u64,
    prove_ns: u64,
    witness_ns: u64,
};

pub const ProofCustody = struct {
    call_relation_closed: bool,
    cold_fresh_verified: bool,
    external_base_tables_required: bool,
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

pub const UnsignedReceiptV1 = struct {
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

pub const ReceiptV1 = struct {
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

    pub fn validate(self: ReceiptV1) !void {
        if (!std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.status, status) or
            !std.mem.eql(u8, self.selector.rule, selection_rule) or
            !std.mem.eql(
                u8,
                self.boundary_authority_caveat,
                boundary_caveat,
            ) or self.production or self.proof.production_eligible or
            !self.proof.call_relation_closed or
            !self.proof.external_base_tables_required or
            !self.proof.cold_fresh_verified or
            self.hard_cap_ns == 0 or self.hard_cap_ns > maximum_hard_cap_ns or
            self.selector.max_word_rows != maximum_word_row_cap or
            self.selector.selected_word_rows == 0 or
            self.selector.selected_word_rows > self.selector.max_word_rows or
            self.selector.descriptor.execution_clock != self.boundary.trace_clock or
            self.selector.descriptor.projected_inst_word != 0x08c5_850b or
            self.boundary.trace_clock <= 1 or
            self.execution_passes[0].segments == 0 or
            self.execution_passes[1].segments == 0 or
            self.execution_passes[0].cycles == 0 or
            self.execution_passes[1].cycles == 0 or
            self.execution_passes[0].core_rows == 0 or
            self.execution_passes[1].core_rows == 0 or
            self.proof.pcs.fold_step != 1 or
            self.proof.pcs.log_blowup_factor != 0 or
            self.proof.pcs.log_last_layer_degree_bound != 3 or
            self.proof.pcs.n_queries != 1 or self.proof.pcs.pow_bits != 0)
        {
            return error.InvalidRetainedMicroproofReceipt;
        }
        try self.authorities.elf.validate(false);
        try self.authorities.input.validate(true);
        try self.authorities.journal.validate(false);
        try self.authorities.observation.validate(false);
        try self.authorities.source_request.validate(false);
        try self.proof.proof.validate(false);
        try self.proof.statement.validate(false);
        try self.proof.tape.validate(false);
        inline for (.{
            self.content_sha256,
            self.authorities.journal_record_sha256,
            self.authorities.observation_content_sha256,
            self.boundary.full_segment_entry_cpu_sha256,
            self.boundary.full_segment_exit_cpu_sha256,
            self.boundary.identity_sha256,
            self.boundary.replay_access_clocks_sha256,
            self.boundary.replay_cpu_sha256,
            self.boundary.replay_rw_memory_sha256,
            self.proof.producer_executable_sha256,
            self.proof.proof_roots_sha256,
            self.proof.statement_identity_sha256,
            self.proof.tape_identity_sha256,
            self.selector.identity_sha256,
        }) |digest| try requireDigest(digest);
    }
};

pub fn encode(
    allocator: std.mem.Allocator,
    value: UnsignedReceiptV1,
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
        return error.InvalidRetainedMicroproofReceipt;
    var parsed = try parse(allocator, body);
    parsed.deinit();
    return body;
}

pub fn parse(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(ReceiptV1) {
    if (bytes.len == 0 or bytes.len > maximum_receipt_bytes or
        bytes[bytes.len - 1] != '\n')
    {
        return error.InvalidRetainedMicroproofReceipt;
    }
    const body = bytes[0 .. bytes.len - 1];
    var parsed = try std.json.parseFromSlice(ReceiptV1, allocator, body, .{
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
        return error.NonCanonicalRetainedMicroproofReceipt;
    try parsed.value.validate();
    const unsigned_value = withoutSeal(parsed.value);
    const unsigned_bytes = try std.json.Stringify.valueAlloc(
        allocator,
        unsigned_value,
        .{},
    );
    defer allocator.free(unsigned_bytes);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(unsigned_bytes);
    hash.update("\n");
    const expected = std.fmt.bytesToHex(hash.finalResult(), .lower);
    if (!std.mem.eql(u8, parsed.value.content_sha256, &expected))
        return error.InvalidRetainedMicroproofReceiptSeal;
    return parsed;
}

fn withoutSeal(value: ReceiptV1) UnsignedReceiptV1 {
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

fn requireDigest(value: []const u8) !void {
    if (value.len != 64) return error.InvalidRetainedMicroproofReceipt;
    var decoded: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&decoded, value) catch
        return error.InvalidRetainedMicroproofReceipt;
}
