//! One execution journal, one physical witness, one native execution proof.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const air = frontend.rv64_air;
const engine = @import("stwo_prover_engine");
const native = @import("stwo_riscv_cpu_integration").rv64_full;
const Capture = native.Capture;
const Trace = native.Trace;
const wire = @import("stwo_proof_wire");
const base = std.heap.smp_allocator;
const Config = struct {
    artifact_dir: []const u8,
    guest: rv.csp_contract.Config,
    expected_steps: u32,
    memory_limit_bytes: usize = 48 * 1024 * 1024 * 1024,
    profile_only: bool = false,
    profile_stages: bool = false,
    control_policy: air.control_policy.Policy = .bytes_v1,
};
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(base);
    defer arena.deinit();
    const scratch = arena.allocator();
    const args = try std.process.argsAlloc(scratch);
    if (args.len != 2) return error.ExpectedConfig;
    const parsed = try std.json.parseFromSlice(Config, scratch, try std.fs.cwd().readFileAlloc(scratch, args[1], 32768), .{});
    const config = parsed.value;
    if (config.memory_limit_bytes == 0 or config.memory_limit_bytes > 48 * 1024 * 1024 * 1024) return error.InvalidMemoryBudget;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(base, config.memory_limit_bytes);
    defer budget.destroy();
    const a = budget.allocator();
    const elf = try std.fs.cwd().readFileAlloc(scratch, config.guest.elf, 32 * 1024 * 1024);
    const input = try std.fs.cwd().readFileAlloc(scratch, config.guest.input, 4096);
    var timer = try std.time.Timer.start();
    var capture = try Capture.run(a, config.guest, elf, input, .{ .expected_steps = config.expected_steps });
    defer capture.deinit();
    const capture_ns = timer.lap();
    const public = capture.statement();
    const plan = try native.planForStatementWithControl(public, .inline_v4, .rv64im, config.control_policy);
    const rows = @as(usize, 1) << @intCast(public.logSize());
    const main_columns = plan.main_count + air.full.frame.widthWithControl(.rv64im, config.control_policy);
    const interaction_columns = 44 + air.range.cpu.interactionCount(&plan) + air.range.table_cpu.interactionCount(&plan, .byte_and) + air.range.table_cpu.interactionCount(&plan, .byte_shift);
    const cpu_base_bytes = rows * (3 + main_columns + interaction_columns) * 4;
    if (config.profile_only) {
        try print(scratch, .{ .control_policy = config.control_policy, .profile_only = true, .whole_guest_proof = false, .instructions = public.steps, .rows = rows, .main_columns = main_columns, .interaction_columns = interaction_columns, .cpu_base_bytes = cpu_base_bytes, .journal_bytes = capture.records.len * @sizeOf(rv.machine.Retirement), .rom_words = capture.program_words.len, .ram_cells = capture.cells.len, .capture_ns = capture_ns, .peak_caller_bytes = budget.snapshot().peak_live_bytes, .opcode_histogram = capture.histogram });
        return;
    }
    try std.fs.cwd().makePath(config.artifact_dir);
    var artifacts = try std.fs.cwd().openDir(config.artifact_dir, .{});
    defer artifacts.close();
    try writeJson(a, artifacts, "statement.json", public);
    var setup = try native.PreparedSetup.initWithControl(a, public, config.control_policy);
    defer setup.deinit();
    const setup_ns = timer.lap();
    var trace = try Trace.init(a, capture.records, public, &setup.materials.program, &setup.materials.plan);
    defer trace.deinit();
    const witness_ns = timer.lap();
    // The narrow capture journal has served its purpose. Keep public boundaries
    // alive but release every retirement before commitment/domain expansion.
    a.free(capture.records.ptr[0..capture.record_capacity]);
    capture.records = &.{};
    capture.record_capacity = 0;
    const Stage = @import("stwo_prover_api").stage_profile;
    var recorder = Stage.Recorder.initWithOptions(a, "cpu", "rv64-full", .{ .capture_tasks = false });
    defer recorder.deinit();
    var bundle = try native.proveTraceProfiled(a, &setup, public, &trace, if (config.profile_stages) &recorder else null);
    defer bundle.deinit(a);
    const prove_ns = timer.lap();
    const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
    defer a.free(encoded);
    try artifacts.writeFile(.{ .sub_path = "proof.bin", .data = encoded });
    try writeJson(a, artifacts, "claims.json", bundle.claims);
    const decoded = try wire.decodeProofBytesBinary(a, encoded);
    const encode_decode_ns = timer.lap();
    try setup.verifyOwned(a, public, bundle.claims, decoded);
    const verify_ns = timer.lap();
    var stages: ?Stage.StageProfile = if (config.profile_stages) try recorder.snapshot(a) else null;
    defer if (stages) |*profile| profile.deinit(a);
    var oods_samples: usize = 0;
    var queried_values: usize = 0;
    var authenticated_hashes: usize = 0;
    for (bundle.proof.commitment_scheme_proof.sampled_values.items) |tree| for (tree) |column| {
        oods_samples += column.len;
    };
    for (bundle.proof.commitment_scheme_proof.queried_values.items) |tree| for (tree) |column| {
        queried_values += column.len;
    };
    for (bundle.proof.commitment_scheme_proof.decommitments.items) |tree| {
        authenticated_hashes += tree.hash_witness.len;
    }
    try print(scratch, .{ .control_policy = config.control_policy, .pcs_config = air.protocol.config(), .stage_profile = stages, .verified = true, .whole_guest_proof = true, .instructions = public.steps, .rows = rows, .main_columns = main_columns, .interaction_columns = interaction_columns, .cpu_base_bytes = cpu_base_bytes, .rom_words = capture.program_words.len, .ram_cells = capture.cells.len, .capture_ns = capture_ns, .setup_ns = setup_ns, .witness_ns = witness_ns, .prove_ns = prove_ns, .encode_decode_ns = encode_decode_ns, .verify_ns = verify_ns, .proof_bytes = encoded.len, .oods_samples = oods_samples, .queried_base_values = queried_values, .authenticated_hashes = authenticated_hashes, .peak_caller_bytes = budget.snapshot().peak_live_bytes, .pow_bits = air.protocol.config().pow_bits, .fri_queries = air.protocol.config().fri_config.n_queries, .workers = if (engine.work_pool.getGlobalPool()) |pool| pool.n_workers else @as(usize, 1), .build_mode = @tagName(@import("builtin").mode) });
}
fn writeJson(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, value: anytype) !void {
    const bytes = try std.json.Stringify.valueAlloc(a, value, .{});
    defer a.free(bytes);
    try dir.writeFile(.{ .sub_path = name, .data = bytes });
}
fn print(a: std.mem.Allocator, value: anytype) !void {
    const bytes = try std.json.Stringify.valueAlloc(a, value, .{});
    try std.fs.File.stdout().writeAll(bytes);
    try std.fs.File.stdout().writeAll("\n");
}
