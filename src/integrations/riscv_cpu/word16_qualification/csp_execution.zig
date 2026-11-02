//! Complete single-request CSP execution on the joined Word16 CPU/family/RAM
//! AIR. A fresh receiver loads only independently expected ELF/input/config.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const Image = @import("csp_image.zig");
const Capture = @import("csp_capture.zig").Capture;
const RawProgram = @import("../rv64_ethereum_request.zig").Program;
const Program = @import("../word16_execution/program.zig").Program;
const Prepared = @import("../word16_execution/prepared.zig").Prepared;
const Source = @import("../word16_execution/sources.zig").Source;
const Setup = @import("../word16_execution/setup.zig").Setup;
const Suite = @import("../word16_execution/pcs_suite.zig").Suite;
const Coverage = @import("../word16_execution/coverage.zig");
const G = @import("../word16_execution/geometry.zig");
const E = @import("../word16_execution/execution.zig");
const P = @import("../word16_execution/protocol.zig");
const Driver = @import("../word16_execution/driver.zig");
const Cells = @import("../word16_execution/cells_wire.zig");
const Metrics = @import("proof_metrics.zig");
const Profile = @import("stwo_prover_api").stage_profile;

fn programFromImage(a: std.mem.Allocator, image: *Image.Owner) !Program {
    var raw = try RawProgram.init(a, &image.loaded.memory);
    defer raw.deinit(a);
    return Program.initWithProfile(a, raw.value(), .rv64im);
}
pub fn prove(a: std.mem.Allocator, image: *Image.Owner, path: []const u8) !void {
    return proveWithSuite(a, image, path, Suite.production());
}
pub fn proveWithSuite(a: std.mem.Allocator, image: *Image.Owner, path: []const u8, suite: Suite) !void {
    try suite.validate();
    var timer = try std.time.Timer.start();
    var capture = try Capture.run(a, image);
    defer capture.deinit();
    const capture_ns = timer.read();
    var program = try programFromImage(a, image);
    var owns_program = true;
    defer if (owns_program) program.deinit();
    const cpu_log = try Coverage.minimalPrefixLog(capture.boundary.steps);
    var prepared = try Prepared.capture(a, &program, capture.boundary, 1, cpu_log, &capture.tape, .{ .deduplicate_shift = true });
    defer prepared.deinit();
    capture.releaseTape();
    const prepare_ns = timer.read() - capture_ns;
    const geometry = try @import("native_geometry.zig").choose(try prepared.geometryOmittingEmptyDivision(), prepared.raw_counts.memory, image.config.ls_ladder);
    try E.Admission.validateCounts(geometry, capture.boundary.steps, prepared.raw_counts.memory, prepared.unique_memory_words);
    const shapes = G.shapes(&program, geometry);
    owns_program = false;
    const setup_start = timer.read();
    var setup = try Setup.initOwnedProgramWithSuite(a, program, geometry, suite);
    defer setup.deinit();
    const setup_ns = timer.read() - setup_start;
    var recorder = Profile.Recorder.initWithOptions(a, "cpu", "rv64-word16-software-CSP", .{ .capture_process_usage = true });
    defer recorder.deinit();
    const source = try Source.fromPreparedProfiled(a, &setup.materials, image.admission().image, &prepared, &recorder);
    const source_ns = timer.read() - setup_start - setup_ns;
    const prove_start = timer.read();
    var encoded = try E.provePreparedWithOptions(a, &setup, image.admission(), source, &recorder, .{ .main_batch_columns = 64, .interaction_batch_columns = 64 });
    defer encoded.deinit(a);
    const prove_ns = timer.read() - prove_start;
    try image.validateTerminal(encoded.request.cpu.steps, encoded.request.memory.terminal);
    const verify_start = timer.read();
    try E.verify(a, &setup, image.admission(), encoded);
    const verify_ns = timer.read() - verify_start;
    try std.fs.cwd().makeDir(path);
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    try Driver.publish(a, dir, &setup, encoded);
    var stages = try recorder.snapshot(a);
    defer stages.deinit(a);
    try Driver.writeJson(a, dir, "stages.json", stages);
    const metrics = try Metrics.encoded(a, encoded.bytes);
    const report = .{ .pcs_config = P.T.P.config(), .pow_bits = P.T.P.config().pow_bits, .fri_queries = P.T.P.config().fri_config.n_queries, .workers = image.config.workers, .build_mode = @tagName(@import("builtin").mode), .oods_samples = metrics.oods_samples, .queried_base_values = metrics.queried_base_values, .authenticated_hashes = metrics.authenticated_hashes, .scope = "complete CSP32 request; software RV64IM; joined Word16 AIR; no service acceleration", .physical_proof_verified = true, .expected_output_bound_to_terminal_ram = true, .steps = capture.boundary.steps, .opcode_histogram = capture.histogram, .opcode_names = Metrics.OPCODE_NAMES, .program_identity = setup.materials.program.identity, .image_identity = image.identity, .geometry = geometry, .shapes = shapes, .evaluation_domains = G.domains(shapes), .source_cells = try G.cells(&shapes), .capture_ns = capture_ns, .prepare_ns = prepare_ns, .setup_ns = setup_ns, .source_ns = source_ns, .prove_ns = prove_ns, .same_process_verify_ns = verify_ns, .proof_bytes = encoded.bytes.len, .total_ns = timer.read() };
    try Driver.writeJson(a, dir, "report.json", report);
    try stdout(a, report);
}
pub fn verify(a: std.mem.Allocator, image: *Image.Owner, path: []const u8) !void {
    return verifyWithSuite(a, image, path, Suite.production());
}
pub fn verifyWithSuite(a: std.mem.Allocator, image: *Image.Owner, path: []const u8, suite: Suite) !void {
    try suite.validate();
    var timer = try std.time.Timer.start();
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const raw = try dir.readFileAlloc(a, "statement.json", 128 * 1024);
    defer a.free(raw);
    const parsed = try std.json.parseFromSlice(Driver.Bundle, a, raw, .{});
    defer parsed.deinit();
    const b = parsed.value;
    if (b.schema != P.SCHEMA or b.epoch != 1) return error.InvalidCspProofBundle;
    try image.admission().validateCpu(b.geometry, b.cpu);
    try E.Admission.validateCounts(b.geometry, b.cpu.steps, b.ls_count, b.memory_words);
    try P.validateDivisionClass(b.geometry, b.division_requests, b.claims.division);
    try P.validateLsTailClass(b.geometry, b.ls_count, b.claims.ls_tail);
    try b.claims.validate();
    const cells = try Cells.read(a, dir, b.memory_words);
    defer cells.deinit(a);
    try image.validateTerminal(b.cpu.steps, cells.terminal);
    const request = P.Request{ .cpu = b.cpu, .epoch = b.epoch, .division_requests = b.division_requests, .multiplication_requests = b.multiplication_requests, .memory = .{ .initial = cells.initial, .terminal = cells.terminal, .epoch = b.epoch, .ls_count = b.ls_count } };
    try image.admission().validateGeometry(b.geometry, request);
    var program = try programFromImage(a, image);
    var owns_program = true;
    defer if (owns_program) program.deinit();
    owns_program = false;
    var setup = try Setup.initOwnedProgramWithSuite(a, program, b.geometry, suite);
    defer setup.deinit();
    const bytes = try dir.readFileAlloc(a, "proof.bin", 64 * 1024 * 1024);
    defer a.free(bytes);
    try E.verify(a, &setup, image.admission(), .{ .bytes = bytes, .claims = b.claims, .request = request });
    try stdout(a, .{ .pcs_config = P.T.P.config(), .workers = image.config.workers, .build_mode = @tagName(@import("builtin").mode), .scope = "fresh CSP32 receiver with independently pinned ELF/input and expected output", .physical_proof_verified = true, .steps = b.cpu.steps, .proof_bytes = bytes.len, .receiver_ns = timer.read() });
}
pub fn stdout(a: std.mem.Allocator, value: anytype) !void {
    const json = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}
