//! Opt-in benchmark/qualification adapter; reuses pinned Sail authority and the
//! existing complete OM services coordinator. No production route is selected.
const std = @import("std");
const core = @import("stwo_core");
const Image = @import("sail_image.zig");
const Capture = @import("sail_capture.zig");
const Raw = @import("../rv64_ethereum_request.zig").Program;
const Program = @import("../word16_execution/program.zig").Program;
const Native = @import("../word16_execution/prepared.zig").Prepared;
const Geometry = @import("native_geometry.zig");
const Coverage = @import("../word16_execution/coverage.zig");
const Driver = @import("../word16_execution/driver.zig");
const R = @import("../word16_global_execution/services/roster.zig");
const P = @import("../word16_global_execution/services/protocol.zig");
const Collector = @import("../word16_global_execution/services/collector.zig");
const C = @import("../word16_global_execution/services/gkr_local/coordinator.zig");
const Wire = @import("../word16_global_execution/services/gkr_local/bundle_wire.zig");
const W = @import("../word16_global_execution/services/gkr_local/worker_protocol.zig");
const Fixed = @import("../word16_global_execution/services/gkr_local/fixed_authority.zig").Fixed;
const FixedSet = @import("../word16_global_execution/services/gkr_local/fixed_authority_set.zig").Set;
pub const GKR_BYTES: usize = 16 << 30;
pub const GLOBAL_BYTES: usize = 4 << 30;
pub const RETAINED_BYTES: usize = 8 << 30;
pub const FIXED_BYTES: usize = 2 << 30;
pub fn config(candidate: bool) !W.PcsConfig {
    if (candidate) return @import("../word16_execution/om31_security_candidate.zig").config();
    var value = W.PcsConfig{ .pow_bits = 26, .fri_config = try core.fri.ForField(W.O).FriConfig.init(0, 1, 70) };
    value.fri_config.fold_step = 4;
    return value;
}
fn expected(image: *const Image.Owner, identity: [32]u8) P.Expected {
    const oracle = image.parsed.value;
    return .{ .admission = image.admission(), .program_identity = identity, .total_steps = oracle.steps, .max_total_steps = oracle.steps, .final_pc = oracle.final_pc, .final_registers = oracle.final_registers };
}
fn verifyBundle(a: std.mem.Allocator, bundle: *const C.Bundle, setup: *const R.CpuSetup, want: P.Expected, cfg: W.PcsConfig, fixed: ?*const FixedSet) !@import("../word16_global_execution/services/gkr_local/execution.zig").Verified {
    if (fixed) |authority| return bundle.verifyWithAuthority(a, &.{setup}, &.{}, want, cfg, authority);
    return bundle.verify(a, &.{setup}, &.{}, want, cfg);
}
pub fn prove(a: std.mem.Allocator, image: *Image.Owner, path: []const u8, candidate: bool) !void {
    const cfg = try config(candidate);
    var timer = try std.time.Timer.start();
    var captured = try Capture.run(a, image);
    defer captured.deinit();
    for (captured.histogram[0..63]) |count| if (count == 0) return error.IncompleteSailIsaCoverage;
    if (captured.histogram[63] != 0 or captured.histogram[64] != 0 or captured.tape.service_calls.items.len != 0 or captured.tape.secp_calls.items.len != 0) return error.NonordinarySailWorkload;
    const capture_ns = timer.read();
    // Both existing profiles use the same ordinary RV64IM semantics. Only
    // after full independent RVFI comparison and explicit no-service coverage
    // checks do we select the existing services tape/ROM decoder for this
    // benchmark. No production collector guard or service scope is widened.
    captured.tape.execution_profile = .ethereum_services_v2;
    var raw = try Raw.init(a, &image.loaded.memory);
    defer raw.deinit(a);
    var program = try Program.init(a, raw.value());
    defer program.deinit();
    const log = try Coverage.minimalPrefixLog(captured.boundary.steps);
    var native = try Native.init(a, &program, captured.boundary, 1, log, &captured.tape, .{ .deduplicate_shift = true });
    defer native.deinit();
    var advice = try Collector.collect(a, &.{&native}, &.{&captured.tape}, image.admission().image);
    defer advice.deinit();
    captured.releaseTape();
    const geometry = try Geometry.choose(try native.geometry(), native.raw_counts.memory, image.config.ls_ladder);
    var setup = try R.CpuSetup.initProgram(a, raw.value(), geometry, .{});
    defer setup.deinit();
    var fixed_cache = try Fixed.Cache.init(a, FIXED_BYTES);
    defer fixed_cache.deinit();
    var fixed: ?FixedSet = if (candidate) try FixedSet.init(a, &fixed_cache, &.{&setup}, &.{}, cfg) else null;
    defer if (fixed) |*authority| authority.deinit();
    var timings: [1]C.WorkerTiming = @splat(.{});
    const prepare_ns = timer.read() - capture_ns;
    var prove_timer = try std.time.Timer.start();
    var bundle = try C.produceWithAuthority(a, &.{&setup}, &.{}, &.{&native}, &advice, expected(image, program.identity), cfg, .{ .gkr_budget = GKR_BYTES, .global_budget = GLOBAL_BYTES, .max_retained_frontend_bytes = RETAINED_BYTES, .worker_timings = &timings, .schedule = .{ .lanes = 1, .workers_per_lane = @intCast(image.config.workers), .memory_cap_bytes = 32 << 30 } }, if (fixed) |*authority| authority else null);
    defer bundle.deinit(a);
    const prove_ns = prove_timer.read();
    try image.validateResult(bundle.requests[0].base.cpu, bundle.requests[0].base.memory.terminal);
    const accepted = try verifyBundle(a, &bundle, &setup, expected(image, program.identity), cfg, if (fixed) |*authority| authority else null);
    if (!accepted.completed or accepted.total_steps != image.parsed.value.steps) return error.IncompleteSailProof;
    try std.fs.cwd().makeDir(path);
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    try Wire.write(a, dir, &.{&setup}, &.{}, &bundle);
    try Driver.writeJson(a, dir, "qualification.json", .{ .scope = "current complete OM services CPU proof of pinned continuous Sail RV64IM corpus; all63 ordinary opcodes; no service calls", .security_qualified = false, .candidate = candidate, .pcs_config = cfg, .steps = image.parsed.value.steps, .target_cases = image.parsed.value.target_cases, .every_retirement_compared = true, .opcode_histogram = captured.histogram, .image_identity = image.identity, .program_identity = program.identity, .geometry = geometry, .workers = image.config.workers, .build_mode = @tagName(@import("builtin").mode), .gkr_budget = GKR_BYTES, .global_budget = GLOBAL_BYTES, .retained_budget = RETAINED_BYTES, .fixed_cache = if (candidate) fixed_cache.snapshot() else null, .capture_ns = capture_ns, .prepare_and_setup_ns = prepare_ns, .prove_ns = prove_ns, .total_ns = timer.read(), .worker_timings = timings, .proof_bytes = bundle.cpus[0].bytes.len, .accepted = accepted.completed });
}
pub const Verification = struct { accepted: bool, completed: bool, security_qualified: bool = false, candidate: bool, steps: u64, expected_cpu_and_ram_endpoint_bound: bool = true, fresh_process: bool = true, wrong_endpoint_rejected: bool = true, verify_ns: u64 };
pub fn verify(a: std.mem.Allocator, image: *Image.Owner, path: []const u8, candidate: bool) !Verification {
    const cfg = try config(candidate);
    var timer = try std.time.Timer.start();
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    var loaded = try Wire.read(a, dir, .{ .max_cpus = 1, .max_truths = 0, .max_total_steps = image.parsed.value.steps });
    defer loaded.deinit(a);
    if (loaded.cpu_declarations.len != 1 or loaded.truth_declarations.len != 0) return error.InvalidSailProofInventory;
    const request = loaded.bundle.requests[0].base;
    try image.validateResult(request.cpu, request.memory.terminal);
    try image.admission().validateGeometry(loaded.cpu_declarations[0].geometry, request);
    const bridges = loaded.cpu_declarations[0].bridges;
    if (bridges.keccak != null or bridges.add != null or bridges.double != null) return error.NonordinarySailWorkload;
    var raw = try Raw.init(a, &image.loaded.memory);
    defer raw.deinit(a);
    var setup = try R.CpuSetup.initProgram(a, raw.value(), loaded.cpu_declarations[0].geometry, .{});
    defer setup.deinit();
    var cache = try Fixed.Cache.init(a, FIXED_BYTES);
    defer cache.deinit();
    var fixed: ?FixedSet = if (candidate) try FixedSet.init(a, &cache, &.{&setup}, &.{}, cfg) else null;
    defer if (fixed) |*authority| authority.deinit();
    const want = expected(image, setup.materials.program.identity);
    const accepted = try verifyBundle(a, &loaded.bundle, &setup, want, cfg, if (fixed) |*authority| authority else null);
    var wrong = want;
    wrong.final_registers[3] ^= 1;
    if (verifyBundle(a, &loaded.bundle, &setup, wrong, cfg, if (fixed) |*authority| authority else null)) |_| return error.AcceptedWrongSailEndpoint else |_| {}
    return .{ .accepted = accepted.completed, .completed = accepted.completed, .candidate = candidate, .steps = accepted.total_steps, .verify_ns = timer.read() };
}
