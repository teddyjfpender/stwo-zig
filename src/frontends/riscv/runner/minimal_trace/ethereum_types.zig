//! Compact custody for one leaf-local Ethereum execution segment.
//!
//! Ordinary memory observations remain a word tape. Native Keccak and signer
//! recovery calls retain their existing typed call records: replay treats
//! those records as untrusted witness data, independently re-executes each
//! CUSTOM-0 transaction, and requires exact record equality before publishing
//! a typed witness.

const std = @import("std");
const execution_profile = @import("../../isa/execution_profile.zig");
const ethereum_abi = @import("../../isa/ethereum_signer_recovery.zig");
const Cpu = @import("../cpu.zig").Cpu;
const keccak_calls = @import("../guest_precompile/keccakf_call_buffer.zig");
const recovery_calls = @import("../guest_precompile/secp256k1_recover_call_buffer.zig");
const base_types = @import("types.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PROFILE = execution_profile.ExecutionProfile.rv32im_zkvm_ethereum_v1;
pub const Digest = base_types.Digest;
pub const CompletionV1 = base_types.CompletionV1;
pub const KeccakRecord = keccak_calls.Record;
pub const RecoveryRecord = recovery_calls.Record;

const LEAF_DOMAIN = "stwo.riscv.ethereum-minimal-leaf.v1\x00";
const CPU_IDENTITY_DOMAIN =
    "stwo-zig/riscv/segment-boundary-cpu/v1\x00";

/// Canonical CPU boundary identity shared with the execution journal and
/// compact-materialization manifest. Replay requests receive these identities
/// from that plan-owned authority; they must never derive them from the
/// resealable compact leaf being admitted.
pub fn cpuIdentity(cpu: Cpu) Digest {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(CPU_IDENTITY_DOMAIN);
    putCpu(&hasher, cpu);
    var result: Digest = undefined;
    hasher.final(&result);
    return result;
}

pub const SourceIdentityV1 = struct {
    program: Digest,
    input: Digest,
    session: Digest,
    entry_memory: Digest,
    exit_memory: Digest,

    pub fn validate(self: SourceIdentityV1) !void {
        inline for (.{
            self.program,
            self.input,
            self.session,
            self.entry_memory,
            self.exit_memory,
        }) |digest| {
            if (isZeroDigest(digest)) return error.MissingSourceIdentity;
        }
    }
};

/// Owned minimal tape for one independently replayable Ethereum leaf.
pub const LeafV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    source: SourceIdentityV1,
    /// Identity of the sparse touched-word boundary used by independent
    /// replay. These are deliberately distinct from `source.entry_memory`
    /// and `source.exit_memory`, which bind the complete segment snapshot and
    /// therefore compose across leaves with different touched-word sets.
    entry_boundary: Digest,
    exit_boundary: Digest,
    segment_index: u32,
    global_first_cycle: u64,
    cycle_count: u32,
    core_cycle_count: u32,
    entry_cpu: Cpu,
    exit_cpu: Cpu,
    completion: ?CompletionV1,
    ordinary_memory_read_words: []u32,
    keccak_records: []KeccakRecord,
    recovery_records: []RecoveryRecord,
    seal: Digest,
    allocator: std.mem.Allocator,

    pub fn initOwned(
        allocator: std.mem.Allocator,
        source: SourceIdentityV1,
        entry_boundary: Digest,
        exit_boundary: Digest,
        segment_index: u32,
        global_first_cycle: u64,
        cycle_count: u32,
        core_cycle_count: u32,
        entry_cpu: Cpu,
        exit_cpu: Cpu,
        completion: ?CompletionV1,
        ordinary_memory_read_words: []u32,
        keccak_records: []KeccakRecord,
        recovery_records: []RecoveryRecord,
    ) !LeafV1 {
        var result = LeafV1{
            .source = source,
            .entry_boundary = entry_boundary,
            .exit_boundary = exit_boundary,
            .segment_index = segment_index,
            .global_first_cycle = global_first_cycle,
            .cycle_count = cycle_count,
            .core_cycle_count = core_cycle_count,
            .entry_cpu = entry_cpu,
            .exit_cpu = exit_cpu,
            .completion = completion,
            .ordinary_memory_read_words = ordinary_memory_read_words,
            .keccak_records = keccak_records,
            .recovery_records = recovery_records,
            .seal = undefined,
            .allocator = allocator,
        };
        result.seal = result.calculateSeal();
        try result.validate();
        return result;
    }

    pub fn deinit(self: *LeafV1) void {
        self.allocator.free(self.ordinary_memory_read_words);
        self.allocator.free(self.keccak_records);
        self.allocator.free(self.recovery_records);
        self.* = undefined;
    }

    pub fn validate(self: *const LeafV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.UnsupportedTapeVersion;
        }
        try self.source.validate();
        if (isZeroDigest(self.entry_boundary) or
            isZeroDigest(self.exit_boundary))
        {
            return error.MissingBoundaryIdentity;
        }
        if (self.cycle_count == 0 or
            self.cycle_count > base_types.MAX_LEAF_CYCLES or
            self.core_cycle_count > self.cycle_count)
        {
            return error.LeafCycleLimitExceeded;
        }
        if (self.global_first_cycle == 0)
            return error.InvalidGlobalCycleRange;
        _ = std.math.add(
            u64,
            self.global_first_cycle - 1,
            self.cycle_count,
        ) catch return error.InvalidGlobalCycleRange;
        if (self.entry_cpu.regs[0] != 0 or self.exit_cpu.regs[0] != 0)
            return error.ZeroRegisterInvariant;
        if (self.ordinary_memory_read_words.len > self.core_cycle_count)
            return error.InvalidMemoryReadCount;

        const external_count = std.math.add(
            usize,
            self.keccak_records.len,
            self.recovery_records.len,
        ) catch return error.InvalidExternalCount;
        const expected_total = std.math.add(
            usize,
            self.core_cycle_count,
            external_count,
        ) catch return error.InvalidExternalCount;
        if (expected_total != self.cycle_count)
            return error.InvalidExternalCount;
        try validateEventOrder(
            self.keccak_records,
            self.recovery_records,
            self.cycle_count,
        );
        if (!std.mem.eql(u8, &self.seal, &self.calculateSeal()))
            return error.TapeSealMismatch;
    }

    pub fn reseal(self: *LeafV1) void {
        self.seal = self.calculateSeal();
    }

    pub fn calculateSeal(self: *const LeafV1) Digest {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(LEAF_DOMAIN);
        putInt(&hasher, u16, self.format_version);
        putInt(&hasher, u16, self.schema_version);
        putInt(&hasher, u16, @intFromEnum(PROFILE));
        hasher.update(&self.source.program);
        hasher.update(&self.source.input);
        hasher.update(&self.source.session);
        hasher.update(&self.source.entry_memory);
        hasher.update(&self.source.exit_memory);
        hasher.update(&self.entry_boundary);
        hasher.update(&self.exit_boundary);
        putInt(&hasher, u32, self.segment_index);
        putInt(&hasher, u64, self.global_first_cycle);
        putInt(&hasher, u32, self.cycle_count);
        putInt(&hasher, u32, self.core_cycle_count);
        putCpu(&hasher, self.entry_cpu);
        putCpu(&hasher, self.exit_cpu);
        putCompletion(&hasher, self.completion);
        putInt(
            &hasher,
            u32,
            std.math.cast(u32, self.ordinary_memory_read_words.len) orelse
                std.math.maxInt(u32),
        );
        for (self.ordinary_memory_read_words) |word|
            putInt(&hasher, u32, word);
        putInt(
            &hasher,
            u32,
            std.math.cast(u32, self.keccak_records.len) orelse
                std.math.maxInt(u32),
        );
        for (self.keccak_records) |record| putKeccak(&hasher, record);
        putInt(
            &hasher,
            u32,
            std.math.cast(u32, self.recovery_records.len) orelse
                std.math.maxInt(u32),
        );
        for (self.recovery_records) |record| putRecovery(&hasher, record);
        var result: Digest = undefined;
        hasher.final(&result);
        return result;
    }
};

fn validateEventOrder(
    keccak: []const KeccakRecord,
    recovery: []const RecoveryRecord,
    cycle_count: u32,
) !void {
    try validateKindOrder(KeccakRecord, keccak, cycle_count);
    try validateKindOrder(RecoveryRecord, recovery, cycle_count);
    var keccak_index: usize = 0;
    var recovery_index: usize = 0;
    var previous: u32 = 0;
    while (keccak_index < keccak.len or recovery_index < recovery.len) {
        const take_keccak = recovery_index == recovery.len or
            (keccak_index < keccak.len and
                keccak[keccak_index].execution_clock <
                    recovery[recovery_index].execution_clock);
        const clock = if (take_keccak)
            keccak[keccak_index].execution_clock
        else
            recovery[recovery_index].execution_clock;
        if (clock <= previous) return error.InvalidExternalClockOrder;
        previous = clock;
        if (take_keccak) keccak_index += 1 else recovery_index += 1;
    }
}

fn validateKindOrder(
    comptime Record: type,
    records: []const Record,
    cycle_count: u32,
) !void {
    var previous: u32 = 0;
    for (records) |record| {
        if (record.execution_clock == 0 or
            record.execution_clock > cycle_count or
            record.execution_clock <= previous or
            record.pc & 3 != 0)
        {
            return error.InvalidExternalClockOrder;
        }
        previous = record.execution_clock;
    }
}

fn putCompletion(hasher: anytype, completion: ?CompletionV1) void {
    if (completion) |value| {
        hasher.update(&.{1});
        hasher.update(&.{value.kind});
        putInt(hasher, u32, value.address);
        putInt(hasher, u32, value.value);
        putInt(hasher, u32, value.clock);
        if (value.exit_code) |exit_code| {
            hasher.update(&.{1});
            putInt(hasher, u32, exit_code);
        } else {
            hasher.update(&.{0});
        }
    } else {
        hasher.update(&.{0});
    }
}

fn putKeccak(hasher: anytype, record: KeccakRecord) void {
    putInt(hasher, u32, record.execution_clock);
    putInt(hasher, u32, record.pc);
    putInt(hasher, u32, record.state_ptr);
    hasher.update(&.{@intCast(record.pointer_register)});
    putInt(hasher, u32, record.pointer_previous_clock);
    for (record.input) |word| putInt(hasher, u32, word);
    for (record.output) |word| putInt(hasher, u32, word);
    for (record.memory_previous_clocks) |clock| putInt(hasher, u32, clock);
}

fn putRecovery(hasher: anytype, record: RecoveryRecord) void {
    putInt(hasher, u32, record.execution_clock);
    putInt(hasher, u32, record.pc);
    putInt(hasher, u32, record.io_ptr);
    hasher.update(&.{@intCast(record.pointer_register)});
    putInt(hasher, u32, record.pointer_previous_clock);
    hasher.update(&record.digest_big_endian);
    hasher.update(&record.r_big_endian);
    hasher.update(&record.s_big_endian);
    putInt(hasher, u32, record.recovery_id);
    hasher.update(&record.public_key_xy_big_endian);
    putInt(hasher, u32, record.status);
    for (record.input_previous_clocks) |clock| putInt(hasher, u32, clock);
    for (record.output_previous_words) |word| putInt(hasher, u32, word);
    for (record.output_previous_clocks) |clock| putInt(hasher, u32, clock);
    std.debug.assert(record.input_previous_clocks.len == ethereum_abi.input_word_count);
    std.debug.assert(record.output_previous_words.len == ethereum_abi.output_word_count);
}

fn putCpu(hasher: anytype, cpu: Cpu) void {
    putInt(hasher, u32, cpu.pc);
    for (cpu.regs) |value| putInt(hasher, u32, value);
}

fn putInt(hasher: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hasher.update(&encoded);
}

fn isZeroDigest(digest: Digest) bool {
    var aggregate: u8 = 0;
    for (digest) |byte| aggregate |= byte;
    return aggregate == 0;
}
