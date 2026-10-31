//! Full block driver for the mixed-service Word16 global-memory protocol.
//! Verify modes consume only independently pinned config and durable proofs.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Request = @import("../../rv64_ethereum_request.zig");
const Image = @import("../../word16_execution/expected_image.zig");
const Program = @import("../../word16_execution/program.zig").Program;
const Driver = @import("../../word16_execution/driver.zig");
const Capture = @import("capture.zig").Owner;
const Plan = @import("plan.zig");
const Keys = @import("keys.zig").Owner;
const Receiver = @import("receiver.zig");
const E = @import("../services/execution.zig");
const P = @import("../services/protocol.zig");
const W = @import("../services/wire.zig");
const Recycler = @import("../../rv64_large_block_recycler.zig").LargeBlockRecycler;
pub fn main() !void {
    var recycler = Recycler.init(std.heap.smp_allocator, 4 << 30);
    defer recycler.deinit();
    const a = recycler.allocator();
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len == 2 and std.mem.eql(u8, args[1], "describe")) return emit(a, .{ .core_schema = @import("../../word16_execution/protocol.zig").SCHEMA, .core_claims = P.CORE_CLAIM_COUNT, .cpu_claims_with_services = P.CPU_CLAIM_COUNT, .pcs_config = @import("../protocol.zig").T.P.config() });
    if (args.len < 4) return error.ExpectedModeConfigAndDirectory;
    const verify = std.mem.eql(u8, args[1], "verify");
    const prefix = std.mem.eql(u8, args[1], "verify-prefix");
    const produce = std.mem.eql(u8, args[1], "produce");
    const plan = std.mem.eql(u8, args[1], "plan");
    if (!verify and !prefix and !produce and !plan) return error.InvalidWord16EthereumMode;
    if ((verify or prefix) and args.len != 4) return error.VerifierNeedsNoExecutionPackets;
    if ((produce or plan) and args.len != 6) return error.ExpectedModeConfigJobsOutputPrefixCount;
    const raw = try std.fs.cwd().readFileAlloc(a, args[2], 16384);
    defer a.free(raw);
    const config = try std.json.parseFromSlice(Request.Config, a, raw, .{});
    defer config.deinit();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = try Request.effectiveWorkers(config.value), .stack_size = 1024 * 1024, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var timer = try std.time.Timer.start();
    var image = try Image.Owner.init(a, config.value);
    defer image.deinit();
    if (verify or prefix) {
        var dir = try std.fs.cwd().openDir(args[3], .{});
        defer dir.close();
        var loaded = try W.read(a, dir, .{ .max_total_steps = config.value.max_steps });
        defer loaded.deinit(a);
        // Cheap schedule/genesis/completion admission precedes expensive keys.
        var trusted_program = try Program.initWithAuthority(a, &image.authority);
        defer trusted_program.deinit();
        _ = try Receiver.expected(&image, trusted_program.identity, &loaded.bundle, config.value.max_steps, config.value.batch_steps, verify);
        var keys = try Keys.init(a, &image, loaded.cpu_declarations, loaded.truth_declarations);
        defer keys.deinit();
        const setup_ns = timer.read();
        const output = try Receiver.verify(a, &image, &keys, &loaded.bundle, config.value.max_steps, config.value.batch_steps, verify);
        return emit(a, .{ .core_schema = @import("../../word16_execution/protocol.zig").SCHEMA, .accepted = true, .completed_ethereum_block = verify, .output = output, .cpu_proofs = loaded.bundle.cpus.len, .truth_proofs = loaded.bundle.truths.len, .load_and_setup_ns = setup_ns, .verify_ns = timer.read() - setup_ns });
    }
    const count = try std.fmt.parseUnsigned(u32, args[5], 10);
    var jobs = try std.fs.cwd().openDir(args[3], .{});
    defer jobs.close();
    var program = try Program.initWithAuthority(a, &image.authority);
    defer program.deinit();
    var captured = try Capture.init(a, &image, &program, config.value, jobs, count);
    defer captured.deinit();
    const capture_ns = timer.read();
    const cpu_declarations = try Plan.cpus(a, &captured);
    defer a.free(cpu_declarations);
    const truth_declarations = try Plan.truths(a, &captured);
    defer a.free(truth_declarations);
    if (truth_declarations.len > (W.Limits{}).max_truths) return error.TooManyEthereumTruths;
    if (plan) return emit(a, .{ .core_schema = @import("../../word16_execution/protocol.zig").SCHEMA, .scope = "producer advice and bounded geometry only; no proof or acceptance", .total_steps = captured.total_steps, .cpu = cpu_declarations, .truth = truth_declarations, .memory_words = captured.advice.initial.len, .capture_ns = capture_ns });
    var keys = try Keys.init(a, &image, cpu_declarations, truth_declarations);
    defer keys.deinit();
    const expected = P.Expected{ .admission = Driver.admission(&image), .program_identity = program.identity, .total_steps = captured.total_steps, .max_total_steps = config.value.max_steps, .final_pc = captured.final_pc, .final_registers = captured.final_registers };
    // Full completion is explicit. Prefix fixtures can never accidentally
    // publish a block-completed report merely because their proofs verify.
    const completed = count == 0;
    if (completed and expected.final_pc != image.terminal_pc) return error.MissingEthereumTerminalPacket;
    try std.fs.cwd().makeDir(args[4]);
    var dir = try std.fs.cwd().openDir(args[4], .{});
    defer dir.close();
    const setup_ns = timer.read() - capture_ns;
    try @import("telemetry.zig").write(a, dir, &keys, &captured);
    var store = try @import("../retained_main_store.zig").Store.init(args[4], 128 << 30);
    defer store.deinit();
    var observations = try @import("observations.zig").Owner.init(a, keys.cpus.len + keys.truths.len);
    defer observations.deinit();
    const prove_start = timer.read();
    var bundle = try E.produceWithOptions(a, keys.cpus, keys.truths, captured.native.items, &captured.advice, expected, .{ .retained_main = &store, .recorders = if (config.value.profile_stages) observations.pointers else &.{}, .directory = if (config.value.profile_stages) dir else null });
    defer bundle.deinit(a);
    const prove_ns = timer.read() - prove_start;
    const verify_start = timer.read();
    const output = try Receiver.verify(a, &image, &keys, &bundle, config.value.max_steps, config.value.batch_steps, completed);
    const verify_ns = timer.read() - verify_start;
    const publish_start = timer.read();
    try W.write(a, dir, keys.cpus, keys.truths, &bundle);
    try Driver.writeJson(a, dir, "report.json", .{ .core_schema = @import("../../word16_execution/protocol.zig").SCHEMA, .completed_ethereum_block = completed, .total_steps = expected.total_steps, .cpu_proofs = bundle.cpus.len, .truth_proofs = bundle.truths.len, .memory_words = captured.advice.initial.len, .output = output, .capture_ns = capture_ns, .setup_ns = setup_ns, .prove_ns = prove_ns, .same_process_verify_ns = verify_ns, .publish_before_report_ns = timer.read() - publish_start, .total_before_report_ns = timer.read(), .retained_main = store.stats() });
    try std.posix.fsync(dir.fd);
}
fn emit(a: std.mem.Allocator, value: anytype) !void {
    const json = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}
