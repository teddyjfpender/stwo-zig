//! Reference-free process boundary for the one-shot resident Metal runner.

const std = @import("std");

pub const max_report_bytes: usize = 16 * 1024 * 1024;
pub const max_stderr_bytes: usize = 2 * 1024 * 1024;

pub const CompositionProgramKind = enum { metal, metallib };

pub const Artifacts = struct {
    adapted_input: []const u8,
    witness_programs: []const u8,
    multiplicity_feeds: []const u8,
    relation_templates: []const u8,
    fixed_tables: []const u8,
    composition: []const u8,
    composition_program: []const u8,
    composition_program_kind: CompositionProgramKind,
    preprocessed_evaluations: []const u8,
    preprocessed_coefficients: []const u8,
    tree0_root_hex: []const u8,
};

pub const Invocation = struct {
    executable: []const u8,
    schedule: []const u8,
    budget_gib: u32,
    artifacts: Artifacts,
    proof_output: []const u8,
    statement_output: []const u8,
    timeout_ns: u64,
    termination_grace_ns: u64,
};

pub const ProofLayout = struct {
    interaction_claim_words: u32,
    sampled_value_words: u32,
    decommitment_capacity_words: u32,
};

pub const Report = struct {
    proof_layout: ProofLayout,
    proof_output_bytes: u64,
};

pub fn execute(allocator: std.mem.Allocator, invocation: Invocation) !Report {
    try validateInvocation(invocation);
    const budget = try std.fmt.allocPrint(allocator, "{}", .{invocation.budget_gib});
    defer allocator.free(budget);
    const argv = [_][]const u8{
        invocation.executable,
        invocation.schedule,
        budget,
        invocation.artifacts.witness_programs,
        invocation.artifacts.multiplicity_feeds,
        invocation.artifacts.relation_templates,
        invocation.artifacts.fixed_tables,
        invocation.artifacts.composition,
    };
    var environment = try runnerEnvironment(allocator, invocation);
    defer environment.deinit();
    const result = try runWithTimeout(
        allocator,
        &argv,
        &environment,
        std.fs.path.dirname(invocation.schedule),
        invocation.timeout_ns,
        invocation.termination_grace_ns,
    );
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    try requireSuccessfulExit(result.term);
    return parseReport(allocator, result.stdout);
}

fn validateInvocation(invocation: Invocation) !void {
    if (!std.fs.path.isAbsolute(invocation.executable) or
        !std.fs.path.isAbsolute(invocation.schedule) or
        !std.fs.path.isAbsolute(invocation.proof_output) or
        !std.fs.path.isAbsolute(invocation.statement_output) or
        invocation.budget_gib == 0 or invocation.budget_gib > 1024 or
        invocation.timeout_ns == 0 or invocation.termination_grace_ns == 0 or
        invocation.artifacts.tree0_root_hex.len != 64)
        return error.InvalidArenaInvocation;
    inline for (.{
        invocation.artifacts.adapted_input,
        invocation.artifacts.witness_programs,
        invocation.artifacts.multiplicity_feeds,
        invocation.artifacts.relation_templates,
        invocation.artifacts.fixed_tables,
        invocation.artifacts.composition,
        invocation.artifacts.composition_program,
        invocation.artifacts.preprocessed_evaluations,
        invocation.artifacts.preprocessed_coefficients,
    }) |path| if (!std.fs.path.isAbsolute(path)) return error.InvalidArenaInvocation;
    var tree0_root: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&tree0_root, invocation.artifacts.tree0_root_hex) catch
        return error.InvalidArenaInvocation;
}

fn runnerEnvironment(allocator: std.mem.Allocator, invocation: Invocation) !std.process.EnvMap {
    var environment = try std.process.getEnvMap(allocator);
    errdefer environment.deinit();
    try scrubStwoEnvironment(allocator, &environment);
    const artifacts = invocation.artifacts;
    const values = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "STWO_ZIG_SN2_POPULATE_INPUT", .value = artifacts.adapted_input },
        .{ .name = "STWO_ZIG_SN2_PREPARE_METAL", .value = "1" },
        .{ .name = "STWO_ZIG_SN2_RESTORE_PREPROCESSED_EVALUATIONS", .value = artifacts.preprocessed_evaluations },
        .{ .name = "STWO_ZIG_SN2_TREE0_ROOT_HEX", .value = artifacts.tree0_root_hex },
        .{ .name = "STWO_ZIG_SN2_EXECUTE_PREPROCESSED", .value = "1" },
        .{ .name = "STWO_ZIG_SN2_EXECUTE_WITNESS", .value = "1" },
        .{ .name = "STWO_ZIG_SN2_EXECUTE_BASE_INTERPOLATION", .value = "1" },
        .{ .name = "STWO_ZIG_SN2_EXECUTE_COMMITMENTS", .value = "1" },
        .{ .name = "STWO_ZIG_SN2_COMMIT_TREE_COUNT", .value = "4" },
        .{ .name = "STWO_ZIG_SN2_EXECUTE_RELATIONS", .value = "1" },
        .{ .name = "STWO_ZIG_SN2_PREPROCESSED_COEFFS", .value = artifacts.preprocessed_coefficients },
        .{ .name = "STWO_ZIG_SN2_EXECUTE_COMPOSITION", .value = "1" },
        .{ .name = "STWO_ZIG_SN2_PROOF_OUTPUT", .value = invocation.proof_output },
        .{ .name = "STWO_ZIG_SN2_COMPACT_STATEMENT_OUTPUT", .value = invocation.statement_output },
        .{ .name = "STWO_ZIG_SN2_EXECUTE_OODS", .value = "1" },
        .{ .name = "STWO_ZIG_SN2_EXECUTE_PROOF", .value = "1" },
        .{ .name = "STWO_ZIG_SN2_VERIFY_PROOF", .value = "1" },
        .{ .name = "STWO_ZIG_METAL_REPLAY_RETAINED_LOOKUPS", .value = "1" },
    };
    for (values) |entry| try environment.put(entry.name, entry.value);
    if (artifacts.composition_program_kind == .metal) {
        try environment.put("STWO_ZIG_SN2_COMPOSITION_SOURCE", artifacts.composition_program);
        try environment.put("STWO_ZIG_SN2_ENABLE_COMPOSITION_PART_FUSION", "1");
    }
    return environment;
}

fn scrubStwoEnvironment(allocator: std.mem.Allocator, environment: *std.process.EnvMap) !void {
    var names: std.ArrayList([]u8) = .empty;
    defer {
        for (names.items) |name| allocator.free(name);
        names.deinit(allocator);
    }
    var iterator = environment.iterator();
    while (iterator.next()) |entry| {
        if (std.mem.startsWith(u8, entry.key_ptr.*, "STWO_ZIG_"))
            try names.append(allocator, try allocator.dupe(u8, entry.key_ptr.*));
    }
    for (names.items) |name| environment.remove(name);
}

fn parseReport(allocator: std.mem.Allocator, encoded: []const u8) !Report {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, encoded, .{}) catch
        return error.InvalidArenaReport;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidArenaReport;
    const root = parsed.value.object;
    inline for (.{
        "proof_assembled",
        "proof_bundle_valid",
        "proof_verified",
        "statement_self_derived",
        "quotient_executed",
        "fri_executed",
        "fri_final_degree_valid",
        "decommit_executed",
        "proof_derived_artifact_used",
    }) |name| try requireBool(root, name, true);
    inline for (.{
        "legacy_transcript_bootstrap_used",
        "parity_fixture_used",
        "quotient_reference_parity",
        "fri_reference_parity",
        "self_contained",
    }) |name| try requireBool(root, name, false);
    try requireString(root, "proof_serialization", "resident_sn2_bundle_v1");
    const proof_output_bytes = try positiveInteger(root, "proof_output_bytes");
    const layout_value = root.get("proof_layout") orelse return error.InvalidArenaReport;
    if (layout_value != .object or layout_value.object.count() != 3)
        return error.InvalidArenaReport;
    const layout = layout_value.object;
    return .{
        .proof_layout = .{
            .interaction_claim_words = try positiveU32(layout, "interaction_claim_words"),
            .sampled_value_words = try positiveU32(layout, "sampled_value_words"),
            .decommitment_capacity_words = try positiveU32(layout, "decommitment_capacity_words"),
        },
        .proof_output_bytes = proof_output_bytes,
    };
}

fn requireBool(object: std.json.ObjectMap, name: []const u8, expected: bool) !void {
    const value = object.get(name) orelse return error.InvalidArenaReport;
    if (value != .bool or value.bool != expected) return error.InvalidArenaReport;
}

fn requireString(object: std.json.ObjectMap, name: []const u8, expected: []const u8) !void {
    const value = object.get(name) orelse return error.InvalidArenaReport;
    if (value != .string or !std.mem.eql(u8, value.string, expected))
        return error.InvalidArenaReport;
}

fn positiveInteger(object: std.json.ObjectMap, name: []const u8) !u64 {
    const value = object.get(name) orelse return error.InvalidArenaReport;
    if (value != .integer or value.integer <= 0)
        return error.InvalidArenaReport;
    return std.math.cast(u64, value.integer) orelse error.InvalidArenaReport;
}

fn positiveU32(object: std.json.ObjectMap, name: []const u8) !u32 {
    return std.math.cast(u32, try positiveInteger(object, name)) orelse
        error.InvalidArenaReport;
}

const ProcessResult = struct {
    term: std.process.Child.Term,
    stdout: []u8,
    stderr: []u8,
};

const Watchdog = struct {
    pid: std.posix.pid_t,
    complete: std.Thread.ResetEvent = .{},
    timeout_ns: u64,
    grace_ns: u64,
    timed_out: bool = false,
    signal_failed: bool = false,

    fn signalGroup(self: *Watchdog, signal: u8) void {
        std.posix.kill(-self.pid, signal) catch |group_error| switch (group_error) {
            error.ProcessNotFound => return,
            else => std.posix.kill(self.pid, signal) catch |leader_error| switch (leader_error) {
                error.ProcessNotFound => return,
                else => self.signal_failed = true,
            },
        };
    }

    fn run(self: *Watchdog) void {
        self.complete.timedWait(self.timeout_ns) catch |wait_error| switch (wait_error) {
            error.Timeout => {
                self.timed_out = true;
                self.signalGroup(std.posix.SIG.TERM);
                self.complete.timedWait(self.grace_ns) catch {};
                self.signalGroup(std.posix.SIG.KILL);
            },
        };
    }
};

fn runWithTimeout(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    environment: *const std.process.EnvMap,
    cwd: ?[]const u8,
    timeout_ns: u64,
    grace_ns: u64,
) !ProcessResult {
    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.env_map = environment;
    child.cwd = cwd;
    child.expand_arg0 = .no_expand;
    child.pgid = 0;
    try child.spawn();
    child.waitForSpawn() catch |err| {
        _ = child.wait() catch {};
        return err;
    };
    var watchdog = Watchdog{ .pid = child.id, .timeout_ns = timeout_ns, .grace_ns = grace_ns };
    const watchdog_thread = std.Thread.spawn(.{}, Watchdog.run, .{&watchdog}) catch |err| {
        watchdog.signalGroup(std.posix.SIG.KILL);
        _ = child.wait() catch {};
        return err;
    };
    var stdout: std.ArrayList(u8) = .empty;
    defer stdout.deinit(allocator);
    var stderr: std.ArrayList(u8) = .empty;
    defer stderr.deinit(allocator);
    const collect_result = child.collectOutput(
        allocator,
        &stdout,
        &stderr,
        @max(max_report_bytes, max_stderr_bytes),
    );
    if (collect_result) |_| {} else |err| {
        watchdog.signalGroup(std.posix.SIG.KILL);
        _ = child.wait() catch {};
        watchdog.complete.set();
        watchdog_thread.join();
        return err;
    }
    const wait_result = child.wait();
    watchdog.complete.set();
    watchdog_thread.join();
    if (watchdog.signal_failed) return error.ProcessGroupTerminationFailed;
    if (watchdog.timed_out) return error.ArenaRunnerTimedOut;
    if (stdout.items.len > max_report_bytes or stderr.items.len > max_stderr_bytes)
        return error.ArenaRunnerOutputTooLarge;
    return .{
        .term = try wait_result,
        .stdout = try stdout.toOwnedSlice(allocator),
        .stderr = try stderr.toOwnedSlice(allocator),
    };
}

fn requireSuccessfulExit(term: std.process.Child.Term) !void {
    switch (term) {
        .Exited => |code| if (code != 0) return error.ArenaRunnerFailed,
        else => return error.ArenaRunnerTerminated,
    }
}

test "Metal process runner: command environment excludes diagnostic proof inputs" {
    const allocator = std.testing.allocator;
    var environment = std.process.EnvMap.init(allocator);
    defer environment.deinit();
    try environment.put("PATH", "/usr/bin");
    try environment.put("STWO_ZIG_SN2_TRANSCRIPT_REFERENCE", "/forbidden");
    try environment.put("STWO_ZIG_SN2_QUOTIENT_REFERENCE", "/forbidden");
    try environment.put("STWO_ZIG_SN2_COMPOSITION_COMPONENT_LIMIT", "1");
    try scrubStwoEnvironment(allocator, &environment);
    try std.testing.expectEqualStrings("/usr/bin", environment.get("PATH").?);
    try std.testing.expect(environment.get("STWO_ZIG_SN2_TRANSCRIPT_REFERENCE") == null);
    try std.testing.expect(environment.get("STWO_ZIG_SN2_QUOTIENT_REFERENCE") == null);
    try std.testing.expect(environment.get("STWO_ZIG_SN2_COMPOSITION_COMPONENT_LIMIT") == null);
}

test "Metal process runner: exit status fails closed" {
    try requireSuccessfulExit(.{ .Exited = 0 });
    try std.testing.expectError(error.ArenaRunnerFailed, requireSuccessfulExit(.{ .Exited = 7 }));
    try std.testing.expectError(error.ArenaRunnerTerminated, requireSuccessfulExit(.{ .Signal = 9 }));
}

test "Metal process runner: direct argv reaches a bounded isolated child" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const report =
        \\{"proof_assembled":true,"proof_bundle_valid":true,"proof_verified":true,"statement_self_derived":true,"quotient_executed":true,"fri_executed":true,"fri_final_degree_valid":true,"decommit_executed":true,"proof_derived_artifact_used":true,"legacy_transcript_bootstrap_used":false,"parity_fixture_used":false,"quotient_reference_parity":false,"fri_reference_parity":false,"self_contained":false,"proof_serialization":"resident_sn2_bundle_v1","proof_output_bytes":4096,"proof_layout":{"interaction_claim_words":120,"sampled_value_words":256,"decommitment_capacity_words":512}}
    ;
    const script = try std.fmt.allocPrint(
        allocator,
        "#!/bin/sh\n" ++
            "test \"$#\" -eq 7 || exit 31\n" ++
            "test \"$1\" = /schedule.json || exit 32\n" ++
            "test \"$2\" = 9 || exit 33\n" ++
            "test -z \"$STWO_ZIG_SN2_TRANSCRIPT_REFERENCE\" || exit 34\n" ++
            "test -z \"$STWO_ZIG_SN2_QUOTIENT_REFERENCE\" || exit 35\n" ++
            "test \"$STWO_ZIG_SN2_EXECUTE_PROOF\" = 1 || exit 36\n" ++
            "test \"$3\" = /witness.bin || exit 37\n" ++
            "test \"$4\" = /feeds.bin || exit 38\n" ++
            "test \"$5\" = /relations.bin || exit 39\n" ++
            "test \"$6\" = /fixed.bin || exit 40\n" ++
            "test \"$7\" = /composition.bin || exit 41\n" ++
            "test \"$STWO_ZIG_SN2_POPULATE_INPUT\" = /input.bin || exit 42\n" ++
            "printf '%s' '{s}'\n",
        .{report},
    );
    defer allocator.free(script);
    try temporary.dir.writeFile(.{ .sub_path = "fake-arena", .data = script });
    const script_file = try temporary.dir.openFile("fake-arena", .{ .mode = .read_write });
    try script_file.chmod(0o700);
    script_file.close();
    const script_path = try temporary.dir.realpathAlloc(allocator, "fake-arena");
    defer allocator.free(script_path);
    const result = try execute(allocator, .{
        .executable = script_path,
        .schedule = "/schedule.json",
        .budget_gib = 9,
        .artifacts = .{
            .adapted_input = "/input.bin",
            .witness_programs = "/witness.bin",
            .multiplicity_feeds = "/feeds.bin",
            .relation_templates = "/relations.bin",
            .fixed_tables = "/fixed.bin",
            .composition = "/composition.bin",
            .composition_program = "/composition.metal",
            .composition_program_kind = .metal,
            .preprocessed_evaluations = "/evaluations.bin",
            .preprocessed_coefficients = "/coefficients.bin",
            .tree0_root_hex = "00" ** 32,
        },
        .proof_output = "/proof.bin",
        .statement_output = "/statement.bin",
        .timeout_ns = 5 * std.time.ns_per_s,
        .termination_grace_ns = std.time.ns_per_s,
    });
    try std.testing.expectEqual(@as(u32, 120), result.proof_layout.interaction_claim_words);
}

test "Metal process runner: report requires reference-free verified evidence" {
    const encoded =
        \\{"proof_assembled":true,"proof_bundle_valid":true,"proof_verified":true,
        \\"statement_self_derived":true,"quotient_executed":true,"fri_executed":true,
        \\"fri_final_degree_valid":true,"decommit_executed":true,"proof_derived_artifact_used":true,
        \\"legacy_transcript_bootstrap_used":false,"parity_fixture_used":false,
        \\"quotient_reference_parity":false,"fri_reference_parity":false,"self_contained":false,
        \\"proof_serialization":"resident_sn2_bundle_v1","proof_output_bytes":4096,
        \\"proof_layout":{"interaction_claim_words":120,"sampled_value_words":256,
        \\"decommitment_capacity_words":512}}
    ;
    const report = try parseReport(std.testing.allocator, encoded);
    try std.testing.expectEqual(@as(u32, 120), report.proof_layout.interaction_claim_words);
    try std.testing.expectEqual(@as(u64, 4096), report.proof_output_bytes);

    const diagnostic = try std.mem.replaceOwned(
        u8,
        std.testing.allocator,
        encoded,
        "\"parity_fixture_used\":false",
        "\"parity_fixture_used\":true",
    );
    defer std.testing.allocator.free(diagnostic);
    try std.testing.expectError(
        error.InvalidArenaReport,
        parseReport(std.testing.allocator, diagnostic),
    );
}
