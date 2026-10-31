//! One complete continuous Sail workload, independently sized family providers,
//! one INIT/TEARDOWN pair and actual new Word16 proof verification.
const std = @import("std");
const Image = @import("sail_image.zig");
const Capture = @import("sail_capture.zig");
const RawProgram = @import("../rv64_ethereum_request.zig").Program;
const Program = @import("../word16_execution/program.zig").Program;
const Prepared = @import("../word16_execution/prepared.zig").Prepared;
const Source = @import("../word16_execution/sources.zig").Source;
const Setup = @import("../word16_execution/setup.zig").Setup;
const Coverage = @import("../word16_execution/coverage.zig");
const G = @import("../word16_execution/geometry.zig");
const E = @import("../word16_execution/execution.zig");
const P = @import("../word16_execution/protocol.zig");
const Driver = @import("../word16_execution/driver.zig");
const Cells = @import("../word16_execution/cells_wire.zig");
const Output = @import("csp_execution.zig");

fn programFromImage(a: std.mem.Allocator, image: *Image.Owner) !Program {
    var raw = try RawProgram.init(a, &image.loaded.memory);
    defer raw.deinit(a);
    return Program.initWithProfile(a, raw.value(), .rv64im);
}
pub fn prove(a: std.mem.Allocator, image: *Image.Owner, path: []const u8) !void {
    var timer = try std.time.Timer.start();
    var capture = try Capture.run(a, image);
    defer capture.deinit();
    // Coverage describes this fixture, not an opcode whitelist selected from
    // advice. Every retiring ordinary RV64IM opcode must actually occur.
    for (capture.histogram[0..63]) |count| if (count == 0) return error.IncompleteSailIsaCoverage;
    const capture_ns = timer.read();
    var program = try programFromImage(a, image);
    var owns_program = true;
    defer if (owns_program) program.deinit();
    const cpu_log = try Coverage.minimalPrefixLog(capture.boundary.steps);
    var prepared = try Prepared.capture(a, &program, capture.boundary, 1, cpu_log, &capture.tape, .{ .deduplicate_shift = true });
    defer prepared.deinit();
    capture.releaseTape();
    const prepare_ns = timer.read() - capture_ns;
    const geometry = try @import("native_geometry.zig").choose(try prepared.geometry(), prepared.raw_counts.memory, image.config.ls_ladder);
    try E.Admission.validateCounts(geometry, capture.boundary.steps, prepared.raw_counts.memory, prepared.unique_memory_words);
    const shapes = G.shapes(&program, geometry);
    owns_program = false;
    const setup_start = timer.read();
    var setup = try Setup.initOwnedProgram(a, program, geometry);
    defer setup.deinit();
    const setup_ns = timer.read() - setup_start;
    const source = try Source.fromPrepared(a, &setup.materials, image.admission().image, &prepared);
    const source_ns = timer.read() - setup_start - setup_ns;
    const prove_start = timer.read();
    var encoded = try E.provePreparedWithOptions(a, &setup, image.admission(), source, null, .{ .main_batch_columns = 64, .interaction_batch_columns = 64 });
    defer encoded.deinit(a);
    const prove_ns = timer.read() - prove_start;
    try image.validateResult(encoded.request.cpu, encoded.request.memory.terminal);
    const verify_start = timer.read();
    try E.verify(a, &setup, image.admission(), encoded);
    const verify_ns = timer.read() - verify_start;
    try std.fs.cwd().makeDir(path);
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    try Driver.publish(a, dir, &setup, encoded);
    const report = .{ .scope = "one continuous Sail RV64IM workload; all63 ordinary retiring opcodes; no ECALL/EBREAK or service acceptance", .physical_proof_verified = true, .every_retirement_compared = true, .expected_cpu_and_ram_endpoint_bound = true, .steps = capture.boundary.steps, .target_cases = image.parsed.value.target_cases, .opcode_histogram = capture.histogram, .image_identity = image.identity, .program_identity = setup.materials.program.identity, .geometry = geometry, .shapes = shapes, .evaluation_domains = G.domains(shapes), .source_cells = try G.cells(&shapes), .capture_ns = capture_ns, .prepare_ns = prepare_ns, .setup_ns = setup_ns, .source_ns = source_ns, .prove_ns = prove_ns, .same_process_verify_ns = verify_ns, .proof_bytes = encoded.bytes.len, .total_ns = timer.read() };
    try Driver.writeJson(a, dir, "report.json", report);
    try Output.stdout(a, report);
}
pub fn verify(a: std.mem.Allocator, image: *Image.Owner, path: []const u8) !void {
    var timer = try std.time.Timer.start();
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const raw = try dir.readFileAlloc(a, "statement.json", 128 * 1024);
    defer a.free(raw);
    const parsed = try std.json.parseFromSlice(Driver.Bundle, a, raw, .{});
    defer parsed.deinit();
    const b = parsed.value;
    if (b.schema != P.SCHEMA or b.epoch != 1) return error.InvalidSailProofBundle;
    try image.admission().validateCpu(b.geometry, b.cpu);
    try E.Admission.validateCounts(b.geometry, b.cpu.steps, b.ls_count, b.memory_words);
    try P.validateDivisionClass(b.geometry, b.division_requests, b.claims.division);
    try P.validateLsTailClass(b.geometry, b.ls_count, b.claims.ls_tail);
    try b.claims.validate();
    const cells = try Cells.read(a, dir, b.memory_words);
    defer cells.deinit(a);
    try image.validateResult(b.cpu, cells.terminal);
    const request = P.Request{ .cpu = b.cpu, .epoch = b.epoch, .division_requests = b.division_requests, .multiplication_requests = b.multiplication_requests, .memory = .{ .initial = cells.initial, .terminal = cells.terminal, .epoch = b.epoch, .ls_count = b.ls_count } };
    try image.admission().validateGeometry(b.geometry, request);
    var program = try programFromImage(a, image);
    var owns_program = true;
    defer if (owns_program) program.deinit();
    owns_program = false;
    var setup = try Setup.initOwnedProgram(a, program, b.geometry);
    defer setup.deinit();
    const bytes = try dir.readFileAlloc(a, "proof.bin", 64 * 1024 * 1024);
    defer a.free(bytes);
    try E.verify(a, &setup, image.admission(), .{ .bytes = bytes, .claims = b.claims, .request = request });
    try Output.stdout(a, .{ .scope = "fresh receiver with independently pinned Sail expected ELF and CPU/RAM endpoints", .physical_proof_verified = true, .steps = b.cpu.steps, .proof_bytes = bytes.len, .receiver_ns = timer.read() });
}
