//! Independently pinned public inputs for a canonical block-v4 CPU CLI.
//! This loader never reads pins from a proof bundle or assigns proof authority.
const std = @import("std");
const core = @import("stwo_core");
const runner = @import("block_v4_cpu_runner_source.zig");
const assembly = @import("block_v4_cpu_multi_segment_assembly.zig");
const parent = @import("../recursion/blake3_execution_parent_protocol.zig");
const v3 = @import("../recursion/blake3_block_execution_span_v3.zig");

pub const FORMAT_VERSION: u32 = 1;
pub const MAX_BYTES: usize = 1024 * 1024;

/// CLI argument parser for an out-of-band SHA-256 pin. No digest is accepted
/// from the manifest body itself.
pub fn parseSha256Hex(encoded: []const u8) ![32]u8 {
    if (encoded.len != 64) return error.InvalidTrustedManifestDigest;
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index| {
        const hi = hexNibble(encoded[2 * index]) orelse return error.InvalidTrustedManifestDigest;
        const lo = hexNibble(encoded[2 * index + 1]) orelse return error.InvalidTrustedManifestDigest;
        byte.* = (hi << 4) | lo;
    }
    return result;
}

fn hexNibble(char: u8) ?u8 {
    return if (char >= '0' and char <= '9') char - '0' else if (char >= 'a' and char <= 'f') char - 'a' + 10 else if (char >= 'A' and char <= 'F') char - 'A' + 10 else null;
}

/// JSON is a transport for already selected public policy. The caller must
/// supply `expected_sha256` through a separate trust channel, such as a
/// command-line pin or a previously authenticated job record.
pub const Wire = struct {
    format_version: u32,
    trusted: assembly.Trusted,
    source: runner.Pins,
};

pub const Owned = struct {
    parsed: std.json.Parsed(Wire),
    sha256: [32]u8,

    pub fn deinit(self: *Owned) void {
        self.parsed.deinit();
        self.* = undefined;
    }

    pub fn trusted(self: *const Owned) assembly.Trusted {
        return self.parsed.value.trusted;
    }

    pub fn sourcePins(self: *const Owned) runner.Pins {
        return self.parsed.value.source;
    }

    /// Check actual CLI-supplied source bytes before runner preflight/replay.
    /// The runner additionally checks program and initial-memory roots.
    pub fn admitInputs(self: *const Owned, elf: []const u8, input: []const u8, oracle: []const u8, schedule_json: []const u8) !void {
        const pins = self.parsed.value.source;
        const schedule_sha256 = pins.schedule_json_sha256 orelse return error.IncompleteTrustedBlockManifest;
        if (!std.meta.eql(runner.sha256(elf), pins.elf_sha256) or
            !std.meta.eql(runner.sha256(input), pins.input_sha256) or
            !std.meta.eql(runner.sha256(oracle), pins.oracle_sha256) or
            !std.meta.eql(runner.sha256(schedule_json), schedule_sha256))
            return error.UntrustedBlockRunnerInput;
    }
};

pub fn read(a: std.mem.Allocator, dir: std.fs.Dir, path: []const u8, expected_sha256: [32]u8) !Owned {
    var file = try dir.openFile(path, .{});
    defer file.close();
    const bytes = try file.readToEndAlloc(a, MAX_BYTES);
    defer a.free(bytes);
    const actual = runner.sha256(bytes);
    if (!std.meta.eql(actual, expected_sha256)) return error.UntrustedBlockManifestHash;
    var parsed = try std.json.parseFromSlice(Wire, a, bytes, .{ .allocate = .alloc_always, .ignore_unknown_fields = false });
    errdefer parsed.deinit();
    try admit(parsed.value, parent.Profile.csp_q70_pow26.config());
    return .{ .parsed = parsed, .sha256 = actual };
}

pub fn admit(wire: Wire, config: core.pcs.PcsConfig) !void {
    if (wire.format_version != FORMAT_VERSION or
        !std.meta.eql(config, parent.Profile.csp_q70_pow26.config()))
        return error.InvalidBlockManifestVersionOrSecurity;
    const trusted = wire.trusted;
    const pins = wire.source;
    try trusted.job.validate();
    const count = trusted.job.segment_count;
    if (count == 0 or count > 1024 or
        trusted.native_key_ids.len != count or
        trusted.base_seal.instance_count != count or
        pins.schedule_json_sha256 == null or
        pins.expected_job == null)
        return error.IncompleteTrustedBlockManifest;
    if (!std.meta.eql(pins.expected_job.?, trusted.job) or
        !std.meta.eql(trusted.job.complete.protocol_id, v3.protocolIdentity(config)) or
        !std.meta.eql(pins.initial_rw_root, trusted.job.complete.initial_state.rw_memory) or
        !std.meta.eql(pins.initial_rw_root, trusted.job.complete.final_state.rw_memory) or
        !std.meta.eql(pins.program_root, trusted.job.complete.program))
        return error.UntrustedBlockManifestJob;
}

test "block-v4 trusted manifest binds caller hash, job, source and exact key census" {
    const a = std.testing.allocator;
    const span = @import("../recursion/span_statement_blake3.zig");
    const config = parent.Profile.csp_q70_pow26.config();
    const registers: [32]u32 = @splat(0);
    const anchor = span.Digest{ .bytes = @splat(2) };
    const state = try span.MachineState.init(4, registers, anchor, .{ .bytes = @splat(0) });
    const final = try span.MachineState.init(8, registers, anchor, .{ .bytes = @splat(0) });
    const program = span.Digest{ .bytes = @splat(3) };
    const complete = try span.CompleteExecution.init(v3.protocolIdentity(config), program, state, final, .{ .bytes = @splat(4) }, .{ .bytes = @splat(5) }, 1);
    const job = try span.JobContext.init(complete, 1);
    const keys = [_][32]u8{@splat(9)};
    const elf = "elf";
    const input = "input";
    const oracle = "oracle";
    const schedule = "[1]";
    const wire = Wire{ .format_version = FORMAT_VERSION, .trusted = .{
        .job = job,
        .base_seal = .{ .digest = @splat(6), .instance_count = 1 },
        .native_key_ids = &keys,
        .outer_key_id = @splat(7),
        .forest_roster_digest = @splat(8),
    }, .source = .{
        .elf_sha256 = runner.sha256(elf),
        .input_sha256 = runner.sha256(input),
        .oracle_sha256 = runner.sha256(oracle),
        .initial_rw_root = anchor,
        .program_root = program,
        .schedule_json_sha256 = runner.sha256(schedule),
        .expected_job = job,
    } };
    try admit(wire, config);
    var wrong_count = wire;
    wrong_count.trusted.native_key_ids = &.{};
    try std.testing.expectError(error.IncompleteTrustedBlockManifest, admit(wrong_count, config));
    var wrong_job = wire;
    wrong_job.source.expected_job = try span.JobContext.init(complete, 2);
    try std.testing.expectError(error.UntrustedBlockManifestJob, admit(wrong_job, config));
    var missing_schedule = wire;
    missing_schedule.source.schedule_json_sha256 = null;
    try std.testing.expectError(error.IncompleteTrustedBlockManifest, admit(missing_schedule, config));
    try std.testing.expectError(error.InvalidBlockManifestVersionOrSecurity, admit(wire, parent.Profile.diagnostic_q8_pow0.config()));
    const encoded = try std.json.Stringify.valueAlloc(a, wire, .{});
    defer a.free(encoded);
    const digest_hex = std.fmt.bytesToHex(runner.sha256(encoded), .lower);
    try std.testing.expectEqual(runner.sha256(encoded), try parseSha256Hex(&digest_hex));
    try std.testing.expectError(error.InvalidTrustedManifestDigest, parseSha256Hex("not a digest"));
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "trusted.json", .data = encoded });
    try std.testing.expectError(error.UntrustedBlockManifestHash, read(a, tmp.dir, "trusted.json", @splat(0)));
    var owned = try read(a, tmp.dir, "trusted.json", runner.sha256(encoded));
    defer owned.deinit();
    try owned.admitInputs(elf, input, oracle, schedule);
    try std.testing.expectError(error.UntrustedBlockRunnerInput, owned.admitInputs(elf, "changed", oracle, schedule));
}
