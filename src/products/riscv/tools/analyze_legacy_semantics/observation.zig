//! Canonical diagnostic wire encoding; retained borrows and sealed identity remain unchanged.
const std = @import("std");
const witness_codes = @import("witness_codes.zig");

const authority_owner = @import("authority.zig");
const FunctionAuthority = authority_owner.FunctionAuthority;
const Identity = authority_owner.Identity;
const InputFile = authority_owner.InputFile;
const JournalAuthority = authority_owner.JournalAuthority;
const claim_boundary = authority_owner.claim_boundary;
const clock_frame = authority_owner.clock_frame;
const digestWithNewline = authority_owner.digestWithNewline;
const function_authority = authority_owner.function_authority;
const profile_name = authority_owner.profile_name;
const schema = authority_owner.schema;
const status = authority_owner.status;
const capture_owner = @import("capture.zig");
const Call = capture_owner.Call;
const Capture = capture_owner.Capture;

pub const CallWire = struct {
    bitmap_bytes: u32,
    bytes_struct_pointer: u32,
    call_index: u32,
    entry_clock: u32,
    entry_segment_index: u32,
    eof_immediate_padding: u32,
    jumpdest_count: u32,
    length: u32,
    length_clock: u32,
    observation_segment_index: u32,
    opcode_positions: []const u32,
    pointer_clock: u32,
    push_count: u32,
    push_overflow: u32,
    scan_iterations: u32,
    source_bytes_sha256: []const u8,
    source_pointer: u32,
    total_padding: u32,
    witness_code_index: u32,
};

pub const Aggregate = struct {
    bitmap_bytes_sum: u64,
    call_count: u32,
    eof_immediate_padding_sum: u64,
    jumpdest_count_sum: u64,
    length_sum: u64,
    opcode_positions_sum: u64,
    push_count_sum: u64,
    push_overflow_sum: u64,
    scan_iterations_sum: u64,
    source_bytes_chain_sha256: []const u8,
    total_padding_sum: u64,
};

pub const WitnessCodeWire = struct {
    analyze_legacy_observed: bool,
    classification: []const u8,
    index: u32,
    length: usize,
    sha256: []const u8,
};

pub const WitnessInventoryWire = struct {
    accessed_legacy_code_count: u32,
    code_count: usize,
    eip7702_delegation_code_count: u32,
    empty_code_count: u32,
    legacy_bytes: u64,
    legacy_code_count: u32,
    routing_policy: []const u8,
    total_bytes: u64,
    unobserved_fallback_code_count: u32,
};

pub const Promotion = struct {
    air_claim: ?bool = null,
    end_to_end_wall_ns: ?u64 = null,
    fresh_verification: ?bool = null,
    performance_claim_eligible: bool = false,
    production_promotion_eligible: bool = false,
    proof_correctness: ?bool = null,
    savings_claim: ?bool = null,
    scope: []const u8 = "exact-analyze-legacy-call-semantics-only",
};

pub const UnsignedWire = struct {
    aggregate: Aggregate,
    calls: []const CallWire,
    claim_boundary: []const u8,
    clock_frame: []const u8,
    elf: Identity,
    execution_journal: Identity,
    execution_profile: []const u8,
    first_global_cycle: u64,
    first_segment_index: u32,
    function_authority: FunctionAuthority,
    function_value_evidence: Identity,
    input: Identity,
    nm_map: Identity,
    observer_executable: Identity,
    observer_semantics_source: Identity,
    observer_source: Identity,
    observer_witness_source: Identity,
    pc_observation: Identity,
    production: bool,
    promotion: Promotion,
    retired_instructions: u64,
    revm_cargo_lock: Identity,
    revm_source: Identity,
    sampled_cycles: u64,
    schema: []const u8,
    segment_count: u32,
    status: []const u8,
    witness_code_inventory: WitnessInventoryWire,
    witness_codes: []const WitnessCodeWire,
};

pub const Wire = struct {
    aggregate: Aggregate,
    calls: []const CallWire,
    claim_boundary: []const u8,
    clock_frame: []const u8,
    content_sha256: []const u8,
    elf: Identity,
    execution_journal: Identity,
    execution_profile: []const u8,
    first_global_cycle: u64,
    first_segment_index: u32,
    function_authority: FunctionAuthority,
    function_value_evidence: Identity,
    input: Identity,
    nm_map: Identity,
    observer_executable: Identity,
    observer_semantics_source: Identity,
    observer_source: Identity,
    observer_witness_source: Identity,
    pc_observation: Identity,
    production: bool,
    promotion: Promotion,
    retired_instructions: u64,
    revm_cargo_lock: Identity,
    revm_source: Identity,
    sampled_cycles: u64,
    schema: []const u8,
    segment_count: u32,
    status: []const u8,
    witness_code_inventory: WitnessInventoryWire,
    witness_codes: []const WitnessCodeWire,
};

pub fn encodeObservation(
    allocator: std.mem.Allocator,
    capture: *const Capture,
    expected: JournalAuthority,
    executable: InputFile,
    elf: InputFile,
    input: InputFile,
    journal: InputFile,
    observer_source: InputFile,
    observer_semantics_source: InputFile,
    observer_witness_source: InputFile,
    revm_source: InputFile,
    cargo_lock: InputFile,
    function_value_evidence: InputFile,
    nm_map: InputFile,
    pc_observation: InputFile,
    inventory: witness_codes.Inventory,
) ![]u8 {
    const calls = try allocator.alloc(CallWire, capture.calls.items.len);
    defer allocator.free(calls);
    var aggregate = Aggregate{
        .bitmap_bytes_sum = 0,
        .call_count = @intCast(calls.len),
        .eof_immediate_padding_sum = 0,
        .jumpdest_count_sum = 0,
        .length_sum = 0,
        .opcode_positions_sum = 0,
        .push_count_sum = 0,
        .push_overflow_sum = 0,
        .scan_iterations_sum = 0,
        .source_bytes_chain_sha256 = undefined,
        .total_padding_sum = 0,
    };
    var chain = std.crypto.hash.sha2.Sha256.init(.{});
    chain.update("stwo.riscv.analyze-legacy-source-bytes-chain.v1\x00");
    for (calls, 0..) |*wire, index| {
        const call = &capture.calls.items[index];
        const scan_iterations = call.analysis.scanIterations();
        wire.* = callWire(call, index, scan_iterations);
        try addAggregate(&aggregate, call, scan_iterations);
        chain.update(&call.source_bytes_sha256);
    }
    var chain_digest: [32]u8 = undefined;
    chain.final(&chain_digest);
    const chain_hex = std.fmt.bytesToHex(chain_digest, .lower);
    aggregate.source_bytes_chain_sha256 = &chain_hex;
    const code_hexes = try allocator.alloc([64]u8, inventory.codes.len);
    defer allocator.free(code_hexes);
    const code_wires = try allocator.alloc(WitnessCodeWire, inventory.codes.len);
    defer allocator.free(code_wires);
    for (code_hexes, code_wires, 0..) |*hex, *wire, index| {
        const code = &inventory.codes[index];
        hex.* = std.fmt.bytesToHex(code.sha256, .lower);
        wire.* = witnessCodeWire(
            code,
            capture.observed_codes[index],
            index,
            hex,
        );
    }
    const inventory_wire = WitnessInventoryWire{
        .accessed_legacy_code_count = @intCast(capture.calls.items.len),
        .code_count = inventory.codes.len,
        .eip7702_delegation_code_count = inventory.eip7702_delegation_count,
        .empty_code_count = inventory.empty_count,
        .legacy_bytes = inventory.legacy_bytes,
        .legacy_code_count = inventory.legacy_count,
        .routing_policy = "legacy=>analyze_legacy;empty-or-0xef01=>Bytecode::new_raw",
        .total_bytes = inventory.total_bytes,
        .unobserved_fallback_code_count = inventory.empty_count +
            inventory.eip7702_delegation_count,
    };

    const unsigned = UnsignedWire{
        .aggregate = aggregate,
        .calls = calls,
        .claim_boundary = claim_boundary,
        .clock_frame = clock_frame,
        .elf = elf.identity(),
        .execution_journal = journal.identity(),
        .execution_profile = profile_name,
        .first_global_cycle = expected.first_global_cycle,
        .first_segment_index = 0,
        .function_authority = function_authority,
        .function_value_evidence = function_value_evidence.identity(),
        .input = input.identity(),
        .nm_map = nm_map.identity(),
        .observer_executable = executable.identity(),
        .observer_semantics_source = observer_semantics_source.identity(),
        .observer_source = observer_source.identity(),
        .observer_witness_source = observer_witness_source.identity(),
        .pc_observation = pc_observation.identity(),
        .production = false,
        .promotion = .{},
        .retired_instructions = expected.retired_instructions,
        .revm_cargo_lock = cargo_lock.identity(),
        .revm_source = revm_source.identity(),
        .sampled_cycles = expected.sampled_cycles,
        .schema = schema,
        .segment_count = @intCast(expected.segments.len),
        .status = status,
        .witness_code_inventory = inventory_wire,
        .witness_codes = code_wires,
    };
    const unsigned_json = try std.json.Stringify.valueAlloc(allocator, unsigned, .{});
    defer allocator.free(unsigned_json);
    const content_digest = digestWithNewline(unsigned_json);
    const content_hex = std.fmt.bytesToHex(content_digest, .lower);
    const sealed = Wire{
        .aggregate = unsigned.aggregate,
        .calls = unsigned.calls,
        .claim_boundary = unsigned.claim_boundary,
        .clock_frame = unsigned.clock_frame,
        .content_sha256 = &content_hex,
        .elf = unsigned.elf,
        .execution_journal = unsigned.execution_journal,
        .execution_profile = unsigned.execution_profile,
        .first_global_cycle = unsigned.first_global_cycle,
        .first_segment_index = unsigned.first_segment_index,
        .function_authority = unsigned.function_authority,
        .function_value_evidence = unsigned.function_value_evidence,
        .input = unsigned.input,
        .nm_map = unsigned.nm_map,
        .observer_executable = unsigned.observer_executable,
        .observer_semantics_source = unsigned.observer_semantics_source,
        .observer_source = unsigned.observer_source,
        .observer_witness_source = unsigned.observer_witness_source,
        .pc_observation = unsigned.pc_observation,
        .production = unsigned.production,
        .promotion = unsigned.promotion,
        .retired_instructions = unsigned.retired_instructions,
        .revm_cargo_lock = unsigned.revm_cargo_lock,
        .revm_source = unsigned.revm_source,
        .sampled_cycles = unsigned.sampled_cycles,
        .schema = unsigned.schema,
        .segment_count = unsigned.segment_count,
        .status = unsigned.status,
        .witness_code_inventory = unsigned.witness_code_inventory,
        .witness_codes = unsigned.witness_codes,
    };
    const body = try std.json.Stringify.valueAlloc(allocator, sealed, .{});
    defer allocator.free(body);
    const encoded = try allocator.alloc(u8, body.len + 1);
    @memcpy(encoded[0..body.len], body);
    encoded[body.len] = '\n';
    return encoded;
}

pub fn callWire(call: *const Call, index: usize, scan_iterations: u32) CallWire {
    return .{
        .bitmap_bytes = call.analysis.bitmap_bytes,
        .bytes_struct_pointer = call.authority.bytes_struct_pointer,
        .call_index = @intCast(index),
        .entry_clock = call.authority.entry_clock,
        .entry_segment_index = call.authority.entry_segment_index,
        .eof_immediate_padding = call.analysis.eof_immediate_padding,
        .jumpdest_count = call.analysis.jumpdest_count,
        .length = call.authority.length,
        .length_clock = call.authority.length_clock,
        .observation_segment_index = call.authority.observation_segment_index,
        .opcode_positions = call.analysis.opcode_positions,
        .pointer_clock = call.authority.pointer_clock,
        .push_count = call.analysis.push_count,
        .push_overflow = call.analysis.push_overflow,
        .scan_iterations = scan_iterations,
        .source_bytes_sha256 = &call.source_bytes_sha256_hex,
        .source_pointer = call.authority.source_pointer,
        .total_padding = call.analysis.total_padding,
        .witness_code_index = call.authority.witness_code_index,
    };
}

pub fn witnessCodeWire(
    code: *const witness_codes.Code,
    observed: bool,
    index: usize,
    sha256_hex: *const [64]u8,
) WitnessCodeWire {
    return .{
        .analyze_legacy_observed = observed,
        .classification = code.classification.wireName(),
        .index = @intCast(index),
        .length = code.bytes.len,
        .sha256 = sha256_hex,
    };
}

pub fn addAggregate(aggregate: *Aggregate, call: *const Call, scan_iterations: u32) !void {
    aggregate.bitmap_bytes_sum = try add64(aggregate.bitmap_bytes_sum, call.analysis.bitmap_bytes);
    aggregate.eof_immediate_padding_sum = try add64(
        aggregate.eof_immediate_padding_sum,
        call.analysis.eof_immediate_padding,
    );
    aggregate.jumpdest_count_sum = try add64(
        aggregate.jumpdest_count_sum,
        call.analysis.jumpdest_count,
    );
    aggregate.length_sum = try add64(aggregate.length_sum, call.authority.length);
    for (call.analysis.opcode_positions) |position|
        aggregate.opcode_positions_sum = try add64(aggregate.opcode_positions_sum, position);
    aggregate.push_count_sum = try add64(aggregate.push_count_sum, call.analysis.push_count);
    aggregate.push_overflow_sum = try add64(
        aggregate.push_overflow_sum,
        call.analysis.push_overflow,
    );
    aggregate.scan_iterations_sum = try add64(aggregate.scan_iterations_sum, scan_iterations);
    aggregate.total_padding_sum = try add64(
        aggregate.total_padding_sum,
        call.analysis.total_padding,
    );
}

pub fn add64(left: u64, right: anytype) !u64 {
    return std.math.add(u64, left, @intCast(right)) catch
        return error.ObserverCountOverflow;
}
