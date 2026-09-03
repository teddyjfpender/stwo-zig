//! Exact retained-journal projection for the adaptive Keccak candidate.
//!
//! The input byte digest is the corpus authority.  Parsed record chaining and
//! ordered segment indices prevent accidental reordering, while every cell
//! count is compiled through `keccakf_adaptive_profile_v1` rather than copied
//! into a benchmark script.  This is a cost projection, not proof evidence.

const std = @import("std");
const profile = @import("keccakf_adaptive_profile_v1.zig");

pub const production_active = false;
pub const schema_version: u16 = 1;
pub const schema = "stwo.riscv.keccak-adaptive-corpus-projection.v1";
pub const maximum_log_size: usize = 16;
pub const Digest = [32]u8;

const header_schema = "stwo.riscv.segmented-execution-header.v3";
const segment_schema = "stwo.riscv.segmented-execution-segment.v3";
const summary_schema = "stwo.riscv.segmented-execution-summary.v3";
const ethereum_profile = "rv32im-zkvm-ethereum-v1";
const keccak_family = "stwo.keccakf-1600.permute-in-place@1";

pub const Totals = struct {
    leaves: u32 = 0,
    calls: u64 = 0,
    adaptive_cells: u64 = 0,
    compact_baseline_cells: u64 = 0,
};

pub const Receipt = struct {
    journal_sha256: Digest,
    executable_sha256: Digest,
    executable_bytes: u64,
    elf_sha256: Digest,
    leaf_count: u32,
    total_core_rows: u64,
    total_keccak_calls: u64,
    modes: [4]Totals,
    log_sizes: [maximum_log_size + 1]Totals,
    adaptive_cells: u64,
    compact_baseline_cells: u64,
    saved_cells: u64,
    selected_profile_plan_sha256: Digest,
    projection_wall_ns: u64,
    max_rss_bytes: u64,
    projection_identity: Digest,

    pub fn validate(self: Receipt) !void {
        if (self.leaf_count == 0 or self.executable_bytes == 0 or
            self.projection_wall_ns == 0 or self.max_rss_bytes == 0 or
            isZero(self.journal_sha256) or isZero(self.executable_sha256) or
            isZero(self.elf_sha256) or isZero(self.selected_profile_plan_sha256))
        {
            return error.InvalidProjection;
        }
        var mode_sum = Totals{};
        for (self.modes) |entry| try addTotals(&mode_sum, entry);
        var log_sum = Totals{};
        for (self.log_sizes) |entry| try addTotals(&log_sum, entry);
        if (mode_sum.leaves != self.leaf_count or
            mode_sum.calls != self.total_keccak_calls or
            mode_sum.adaptive_cells != self.adaptive_cells or
            mode_sum.compact_baseline_cells != self.compact_baseline_cells or
            !std.meta.eql(mode_sum, log_sum) or
            self.compact_baseline_cells < self.adaptive_cells or
            self.saved_cells != self.compact_baseline_cells - self.adaptive_cells or
            !std.mem.eql(u8, &self.projection_identity, &identity(self)))
        {
            return error.InvalidProjection;
        }
    }
};

pub const Runtime = struct {
    executable_sha256: Digest,
    executable_bytes: u64,
};

pub fn project(
    allocator: std.mem.Allocator,
    journal: []const u8,
    runtime: Runtime,
) !Receipt {
    var journal_sha256: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(journal, &journal_sha256, .{});
    var result = Receipt{
        .journal_sha256 = journal_sha256,
        .executable_sha256 = runtime.executable_sha256,
        .executable_bytes = runtime.executable_bytes,
        .elf_sha256 = @splat(0),
        .leaf_count = 0,
        .total_core_rows = 0,
        .total_keccak_calls = 0,
        .modes = @splat(.{}),
        .log_sizes = @splat(.{}),
        .adaptive_cells = 0,
        .compact_baseline_cells = 0,
        .saved_cells = 0,
        .selected_profile_plan_sha256 = undefined,
        // Bound after projection so timing/RSS cover parsing and compilation.
        .projection_wall_ns = 1,
        .max_rss_bytes = 1,
        .projection_identity = undefined,
    };
    var plan_hash = std.crypto.hash.sha2.Sha256.init(.{});
    plan_hash.update("stwo.riscv.keccak-adaptive-selected-plan.v1\x00");
    var previous_content: ?Digest = null;
    var saw_header = false;
    var saw_summary = false;
    var lines = std.mem.splitScalar(u8, journal, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (saw_summary) return error.NonterminalSummary;
        var parsed = try std.json.parseFromSlice(
            std.json.Value,
            allocator,
            line,
            .{},
        );
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidJournal;
        const root = parsed.value.object;
        const payload_value = root.get("payload") orelse return error.InvalidJournal;
        const content_value = root.get("content_sha256") orelse
            return error.InvalidJournal;
        if (payload_value != .object or content_value != .string)
            return error.InvalidJournal;
        const content = try parseHexDigest(content_value.string);
        const payload = payload_value.object;
        const record_schema = try stringField(payload, "schema");
        if (!saw_header) {
            if (!std.mem.eql(u8, record_schema, header_schema) or
                !std.mem.eql(u8, try stringField(payload, "profile"), ethereum_profile))
            {
                return error.InvalidJournal;
            }
            result.elf_sha256 = try parseHexDigest(
                try stringField(payload, "elf_sha256"),
            );
            saw_header = true;
        } else if (std.mem.eql(u8, record_schema, segment_schema)) {
            const previous = try parseHexDigest(
                try stringField(payload, "previous_record_sha256"),
            );
            if (previous_content == null or
                !std.mem.eql(u8, &previous, &previous_content.?))
            {
                return error.InvalidJournalChain;
            }
            const segment_index = try unsignedField(payload, "segment_index");
            if (segment_index != result.leaf_count)
                return error.InvalidSegmentOrder;
            const core_rows = try unsignedField(payload, "core_trace_rows");
            const call_count = try keccakCalls(payload);
            if (call_count > std.math.maxInt(u32) or
                core_rows > std.math.maxInt(u32))
            {
                return error.InvalidJournal;
            }
            const selected = try profile.compile(@intCast(call_count));
            const baseline = try profile.compileCompactBaseline(
                @intCast(call_count),
            );
            try selected.validate();
            try baseline.validate();
            const mode_index: usize = @intFromEnum(selected.mode);
            const log_index: usize = selected.log_size;
            if (log_index > maximum_log_size) return error.InvalidJournal;
            const delta = Totals{
                .leaves = 1,
                .calls = call_count,
                .adaptive_cells = selected.costs.total_cells,
                .compact_baseline_cells = baseline.costs.total_cells,
            };
            try addTotals(&result.modes[mode_index], delta);
            try addTotals(&result.log_sizes[log_index], delta);
            result.leaf_count = try add(u32, result.leaf_count, 1);
            result.total_core_rows = try add(u64, result.total_core_rows, core_rows);
            result.total_keccak_calls = try add(
                u64,
                result.total_keccak_calls,
                call_count,
            );
            result.adaptive_cells = try add(
                u64,
                result.adaptive_cells,
                selected.costs.total_cells,
            );
            result.compact_baseline_cells = try add(
                u64,
                result.compact_baseline_cells,
                baseline.costs.total_cells,
            );
            plan_hash.update(&selected.instance_identity);
        } else if (std.mem.eql(u8, record_schema, summary_schema)) {
            const previous = try parseHexDigest(
                try stringField(payload, "previous_record_sha256"),
            );
            if (previous_content == null or
                !std.mem.eql(u8, &previous, &previous_content.?))
            {
                return error.InvalidJournalChain;
            }
            const segment_count = try unsignedField(payload, "segment_count");
            const total_core_rows = try unsignedField(
                payload,
                "total_core_trace_rows",
            );
            const total_calls = try keccakCalls(payload);
            if (segment_count != result.leaf_count or
                total_core_rows != result.total_core_rows or
                total_calls != result.total_keccak_calls)
            {
                return error.SummaryMismatch;
            }
            saw_summary = true;
        } else {
            return error.InvalidJournal;
        }
        previous_content = content;
    }
    if (!saw_header or result.leaf_count == 0) return error.InvalidJournal;
    if (!saw_summary) return error.MissingSummary;
    result.saved_cells = result.compact_baseline_cells - result.adaptive_cells;
    plan_hash.final(&result.selected_profile_plan_sha256);
    result.projection_identity = identity(result);
    try result.validate();
    return result;
}

pub fn bindRuntime(
    receipt: *Receipt,
    projection_wall_ns: u64,
    max_rss_bytes: u64,
) !void {
    if (projection_wall_ns == 0 or max_rss_bytes == 0)
        return error.InvalidProjection;
    receipt.projection_wall_ns = projection_wall_ns;
    receipt.max_rss_bytes = max_rss_bytes;
    receipt.projection_identity = identity(receipt.*);
    try receipt.validate();
}

pub fn encodeAlloc(allocator: std.mem.Allocator, receipt: Receipt) ![]u8 {
    try receipt.validate();
    const journal_hex = std.fmt.bytesToHex(receipt.journal_sha256, .lower);
    const executable_hex = std.fmt.bytesToHex(receipt.executable_sha256, .lower);
    const elf_hex = std.fmt.bytesToHex(receipt.elf_sha256, .lower);
    const plan_hex = std.fmt.bytesToHex(
        receipt.selected_profile_plan_sha256,
        .lower,
    );
    const identity_hex = std.fmt.bytesToHex(receipt.projection_identity, .lower);
    return std.json.Stringify.valueAlloc(allocator, .{
        .schema = schema,
        .schema_version = schema_version,
        .production_active = production_active,
        .measurement_kind = "exact-committed-m31-cell-projection",
        .proof_or_fresh_verification = false,
        .journal_sha256 = journal_hex[0..],
        .executable_sha256 = executable_hex[0..],
        .executable_bytes = receipt.executable_bytes,
        .elf_sha256 = elf_hex[0..],
        .leaf_count = receipt.leaf_count,
        .total_core_rows = receipt.total_core_rows,
        .total_keccak_calls = receipt.total_keccak_calls,
        .modes = receipt.modes,
        .log_sizes = receipt.log_sizes,
        .adaptive_cells = receipt.adaptive_cells,
        .compact_baseline_cells = receipt.compact_baseline_cells,
        .saved_cells = receipt.saved_cells,
        .selected_profile_plan_sha256 = plan_hex[0..],
        .projection_wall_ns = receipt.projection_wall_ns,
        .max_rss_bytes = receipt.max_rss_bytes,
        .projection_identity = identity_hex[0..],
    }, .{});
}

fn keccakCalls(payload: std.json.ObjectMap) !u64 {
    const families = payload.get("external_family_rows") orelse
        return error.InvalidJournal;
    if (families != .array) return error.InvalidJournal;
    var found: ?u64 = null;
    for (families.array.items) |entry| {
        if (entry != .object) return error.InvalidJournal;
        const family = try stringField(entry.object, "family");
        if (!std.mem.eql(u8, family, keccak_family)) continue;
        if (found != null) return error.DuplicateKeccakFamily;
        found = try unsignedField(entry.object, "calls");
    }
    return found orelse error.MissingKeccakFamily;
}

fn stringField(object: std.json.ObjectMap, name: []const u8) ![]const u8 {
    const value = object.get(name) orelse return error.InvalidJournal;
    if (value != .string) return error.InvalidJournal;
    return value.string;
}

fn unsignedField(object: std.json.ObjectMap, name: []const u8) !u64 {
    const value = object.get(name) orelse return error.InvalidJournal;
    if (value != .integer or value.integer < 0) return error.InvalidJournal;
    return @intCast(value.integer);
}

fn parseHexDigest(encoded: []const u8) !Digest {
    if (encoded.len != 64) return error.InvalidDigest;
    var result: Digest = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch return error.InvalidDigest;
    if (isZero(result)) return error.InvalidDigest;
    return result;
}

fn addTotals(destination: *Totals, value: Totals) !void {
    destination.leaves = try add(u32, destination.leaves, value.leaves);
    destination.calls = try add(u64, destination.calls, value.calls);
    destination.adaptive_cells = try add(
        u64,
        destination.adaptive_cells,
        value.adaptive_cells,
    );
    destination.compact_baseline_cells = try add(
        u64,
        destination.compact_baseline_cells,
        value.compact_baseline_cells,
    );
}

fn add(comptime T: type, lhs: T, rhs: T) !T {
    return std.math.add(T, lhs, rhs) catch error.ArithmeticOverflow;
}

fn identity(receipt: Receipt) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.keccak-adaptive-corpus-projection.v1\x00");
    hash.update(&receipt.journal_sha256);
    hash.update(&receipt.executable_sha256);
    hashInt(&hash, receipt.executable_bytes);
    hash.update(&receipt.elf_sha256);
    hashInt(&hash, receipt.leaf_count);
    hashInt(&hash, receipt.total_core_rows);
    hashInt(&hash, receipt.total_keccak_calls);
    for (receipt.modes) |entry| hashTotals(&hash, entry);
    for (receipt.log_sizes) |entry| hashTotals(&hash, entry);
    hashInt(&hash, receipt.adaptive_cells);
    hashInt(&hash, receipt.compact_baseline_cells);
    hashInt(&hash, receipt.saved_cells);
    hash.update(&receipt.selected_profile_plan_sha256);
    hashInt(&hash, receipt.projection_wall_ns);
    hashInt(&hash, receipt.max_rss_bytes);
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

fn hashTotals(hash: anytype, totals: Totals) void {
    hashInt(hash, totals.leaves);
    hashInt(hash, totals.calls);
    hashInt(hash, totals.adaptive_cells);
    hashInt(hash, totals.compact_baseline_cells);
}

fn hashInt(hash: anytype, value: anytype) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn isZero(value: Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

comptime {
    if (@intFromEnum(profile.Mode.inactive_zero_count) != 0 or
        @intFromEnum(profile.Mode.compact_v2) != 1 or
        @intFromEnum(profile.Mode.throughput_xor_v1) != 2 or
        @intFromEnum(profile.Mode.throughput_chi_xor_v1) != 3 or
        production_active)
    {
        @compileError("Keccak corpus projection mode ordering drifted");
    }
}
