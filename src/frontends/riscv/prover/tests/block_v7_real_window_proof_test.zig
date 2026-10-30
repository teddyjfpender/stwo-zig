const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Scope = @import("../block_v7_real_window_statement_v1.zig");
const Proof = @import("../block_v7_real_window_proof_v1.zig");
const Profile = @import("../blake3_ethereum_sha_profile.zig");
const Original = @import("../blake3_ethereum_sha_proof.zig");
const Api = Original.ForBackend(Cpu);
test "explicit nonterminal window original proof binds full independently selected machine endpoints" {
    var whole = try std.time.Timer.start();
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 24 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    const tiny = @import("block_v7_keccak_execution_test_support.zig").elf();
    const elf = if (std.posix.getenv("STWO_REAL_WINDOW_PROOF_ELF")) |path| try std.fs.cwd().readFileAlloc(a, path, 32 << 20) else try a.dupe(u8, &tiny);
    defer a.free(elf);
    const input = if (std.posix.getenv("STWO_REAL_WINDOW_PROOF_INPUT")) |path| try std.fs.cwd().readFileAlloc(a, path, 4 << 20) else try a.dupe(u8, &.{});
    defer a.free(input);
    const real = std.process.hasEnvVarConstant("STWO_REAL_WINDOW_PROOF_ELF");
    var pins: Capture.Pins = .{ .elf = Capture.sha(elf), .input = Capture.sha(input) };
    if (real) {
        _ = try std.fmt.hexToBytes(&pins.elf, "ef68fdca9e627a4969e64aa97119f52f2d9c9d6b6e8d5cbbeb541fb93dab0688");
        _ = try std.fmt.hexToBytes(&pins.input, "737368031bfec21aa2bd557a3a71d2cbf253ec730199f7ec4c3bccd628df8e82");
    }
    const source_loading_ns = whole.read();
    const window: Capture.Window = .{
        .skip_cycles = if (std.posix.getenv("STWO_REAL_WINDOW_SKIP")) |value| try std.fmt.parseInt(u64, value, 10) else 6,
        .cycles = if (std.posix.getenv("STWO_REAL_WINDOW_CYCLES")) |value| try std.fmt.parseInt(u32, value, 10) else 3,
    };
    var captured = try Capture.capture(a, elf, input, pins, window, .{});
    defer captured.deinit();
    const capture_ns = whole.read() - source_loading_ns;
    var timer = try std.time.Timer.start();
    const trusted: Scope.Trusted = .{ .elf_sha256 = pins.elf, .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = window };
    const scope = try Scope.Statement.derive(a, elf, captured.incoming, captured.outgoing, trusted, .{});
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const config = if (real) @import("../../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG else @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config();
    var owner = try Profile.Witness.initCompactSegmentSparseProgram(a, &captured.segment);
    var owner_alive = true;
    defer if (owner_alive) owner.deinit();
    try scope.admit(owner.native.statement.public_data);
    try scope.admitPlan(captured.incoming, captured.outgoing, &owner.plan);
    if (!real) try rejectUnaccessedStateChange(a, elf, &captured, trusted, &owner.plan);
    const key = try Api.PreparedVerifier.initCompact(a, &owner.native.statement, owner.statement, try owner.admission(), config, owner.native.compact_ranges.?.plan);
    var key_alive = true;
    defer if (key_alive) key.deinit();
    const metadata = try Proof.Manifest.encodeCompact(a, &key.native, key.extension, key.admission(), config, .{ .elf_sha256 = pins.elf, .input_sha256 = pins.input }, .{}, key.ranges.?);
    defer a.free(metadata);
    const expected_metadata = Proof.Manifest.identity(metadata);
    const preparation_ns = timer.read();
    timer.reset();
    var proved = try Api.prove(a, &owner, key, key.id, &pool);
    var proved_alive = true;
    defer if (proved_alive) proved.proof.deinit(a);
    const proving_ns = timer.read();
    timer.reset();
    const bytes = try Original.codec.encode(a, &proved.proof, key, key.id);
    defer a.free(bytes);
    const transcript = proved.transcript_digest;
    var data = try @import("../blake3_segment_public.zig").Owned.init(a, &captured.segment.base);
    defer data.deinit();
    proved.proof.deinit(a);
    proved_alive = false;
    owner.deinit();
    owner_alive = false;
    key.deinit();
    key_alive = false;
    captured.releaseExecution();
    const serialization_and_release_ns = timer.read();
    timer.reset();
    const received = try Proof.For(Cpu).verify(a, elf, captured.incoming, captured.outgoing, trusted, pins.input, config, metadata, expected_metadata, bytes, .{});
    try std.testing.expectEqualDeep(transcript, received);
    const verification_ns = timer.read();
    const whole_request_ns = whole.read();
    const prepared_window_to_verified_ns = whole_request_ns - source_loading_ns - capture_ns;
    var altered = trusted;
    altered.outgoing_sha256[0] ^= 1;
    try std.testing.expectError(error.UntrustedRealWindowState, Proof.For(Cpu).verify(a, elf, captured.incoming, captured.outgoing, altered, pins.input, config, metadata, expected_metadata, bytes, .{}));
    data.data.program_root = scope.roots[0];
    data.data.initial_rw_root = scope.roots[1];
    data.data.final_rw_root = scope.roots[2];
    try scope.admit(data.data);
    data.data.final_regs[7] ^= 1;
    try std.testing.expectError(error.UntrustedRealWindowStatement, scope.admit(data.data));
    if (std.posix.getenv("STWO_REAL_WINDOW_PROOF_OUTPUT")) |path| {
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
        try dir.writeFile(.{ .sub_path = "window.proof", .data = bytes });
        try dir.writeFile(.{ .sub_path = "window.admission", .data = metadata });
        const report = try std.json.Stringify.valueAlloc(a, .{
            .schema = "stwo-explicit-real-window-original-proof-v1",
            .scope = "independently selected complete machine-state transition; no authentication of skipped Ethereum prefix or complete block",
            .proof_verified = true,
            .producer_traces_deleted_before_verification = true,
            .real_retained_source = real,
            .config = config,
            .window = window,
            .elf_sha256 = std.fmt.bytesToHex(pins.elf, .lower),
            .original_input_sha256 = std.fmt.bytesToHex(pins.input, .lower),
            .incoming_sha256 = std.fmt.bytesToHex(trusted.incoming_sha256, .lower),
            .outgoing_sha256 = std.fmt.bytesToHex(trusted.outgoing_sha256, .lower),
            .metadata_identity = std.fmt.bytesToHex(expected_metadata, .lower),
            .proof_sha256 = std.fmt.bytesToHex(Capture.sha(bytes), .lower),
            .proof_bytes = bytes.len,
            .metadata_bytes = metadata.len,
            .capture = captured.stats,
            .timing = .{ .source_loading_ns = source_loading_ns, .capture_total_ns = capture_ns, .preparation_ns = preparation_ns, .proving_ns = proving_ns, .serialization_and_release_ns = serialization_and_release_ns, .fresh_verification_ns = verification_ns, .prepared_window_to_verified_ns = prepared_window_to_verified_ns, .whole_request_ns = whole_request_ns },
            .charged_peak_bytes = budget.snapshot().peak_live_bytes,
            .host_budget_bytes = @as(u64, 24 << 30),
        }, .{ .whitespace = .indent_2 });
        defer a.free(report);
        try dir.writeFile(.{ .sub_path = "report.json", .data = report });
    }
    std.debug.print("V7_REAL_WINDOW_PROOF real_source={any} cycles={d} keccak={d} recovery={d} sha={d} preparation_ns={d} proving_ns={d} serialization_and_release_ns={d} verification_ns={d} proof_bytes={d} metadata_bytes={d} charged_peak={d} prefix_replay_ns={d} window_execution_ns={d} proof_verified=true producer_traces_deleted=true whole_ethereum_block=false\n", .{ real, window.cycles, captured.stats.keccak_calls, captured.stats.recovery_calls, captured.stats.sha_calls, preparation_ns, proving_ns, serialization_and_release_ns, verification_ns, bytes.len, metadata.len, budget.snapshot().peak_live_bytes, captured.stats.prefix_ns, captured.stats.window_ns });
}

fn rejectUnaccessedStateChange(a: std.mem.Allocator, elf: []const u8, captured: *const Capture.Captured, trusted: Scope.Trusted, original: *const @import("../blake3_commitment_plan.zig").Plan) !void {
    const words = try a.dupe(Capture.Word, captured.outgoing.words);
    defer a.free(words);
    var changed = captured.outgoing;
    changed.words = words;
    // The tiny Keccak fixture has a 256-byte state area but reads/writes only
    // 200 bytes. Alter an unused tail word and reseal BOTH the endpoint root
    // and all proposed memory boundary root references.
    const address: u32 = 0x1001fc;
    for (original.memories) |item| try std.testing.expect(item.address != address);
    var found = false;
    for (words) |*word| if (word.address == address) {
        word.value ^= 1;
        found = true;
        break;
    };
    try std.testing.expect(found);
    var changed_trusted = trusted;
    changed_trusted.outgoing_sha256 = changed.identity();
    const changed_scope = try Scope.Statement.derive(a, elf, captured.incoming, changed, changed_trusted, .{});
    var proposed = original.*;
    proposed.memories = try a.dupe(@TypeOf(original.memories[0]), original.memories);
    defer a.free(proposed.memories);
    proposed.roots = changed_scope.roots;
    for (proposed.memories) |*item| item.root = proposed.roots[if (item.direction == .initial) @as(usize, 1) else 2];
    try proposed.validate();
    try std.testing.expectError(error.UnprovedRealWindowStateChange, changed_scope.admitPlan(captured.incoming, changed, &proposed));
}
