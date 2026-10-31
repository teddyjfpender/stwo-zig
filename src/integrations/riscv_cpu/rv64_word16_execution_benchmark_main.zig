//! Read-only planning by default; explicit prove writes a genesis-prefix proof.
//! No services or cross-batch acceptance is implied by this diagnostic.
const std = @import("std");
const Request = @import("rv64_ethereum_request.zig");
const Image = @import("word16_execution/expected_image.zig");
const Packet = @import("word16_execution/packet.zig");
const Program = @import("word16_execution/program.zig").Program;
const Coverage = @import("word16_execution/coverage.zig");
const G = @import("word16_execution/geometry.zig");
const Setup = @import("word16_execution/setup.zig").Setup;
const Execution = @import("word16_execution/execution.zig");
const Prepared = @import("word16_execution/prepared.zig").Prepared;
const Sources = @import("word16_execution/sources.zig");
const Coordinator = @import("word16_execution/coordinator.zig");
const Driver = @import("word16_execution/driver.zig");
const Profile = @import("stwo_prover_api").stage_profile;
const Memory = @import("rv64_batch_memory.zig");
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    const verifying = args.len == 4 and std.mem.eql(u8, args[1], "--verify");
    const proving = args.len == 5 and std.mem.eql(u8, args[3], "--prove");
    if (!verifying and !proving and args.len != 3) return error.ExpectedConfigPacketOrVerifyConfigDirectory;
    const raw = try std.fs.cwd().readFileAlloc(a, args[if (verifying) 2 else 1], 16384);
    defer a.free(raw);
    const config = try std.json.parseFromSlice(Request.Config, a, raw, .{});
    defer config.deinit();
    const work = @import("stwo_prover_engine").work_pool;
    var pool: work.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = try Request.effectiveWorkers(config.value), .stack_size = 1024 * 1024, .backing_allocator = a });
    defer pool.deinit();
    var binding = try work.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var timer = try std.time.Timer.start();
    var image = try Image.Owner.init(a, config.value);
    defer image.deinit();
    const image_ns = timer.read();
    if (verifying) {
        try Driver.verifyDirectory(a, &image, args[3]);
        try stdout(a, .{ .scope = "fresh independent genesis-prefix receiver", .physical_proof_verified = true, .global_chain_accepted = false, .receiver_ns = timer.read(), .image_ns = image_ns });
        return;
    }
    var file = try std.fs.cwd().openFile(args[2], .{});
    defer file.close();
    var packet = try Packet.read(a, file, &image, config.value);
    defer packet.deinit();
    const packet_ns = timer.read() - image_ns;
    var program = try Program.initWithAuthority(a, &image.authority);
    var owns_program = true;
    defer if (owns_program) program.deinit();
    const cpu_log = try Coverage.minimalPrefixLog(@intCast(packet.tape.len));
    if (!proving) {
        const counts = try Coverage.Counts.fromTape(&program, &packet.tape);
        const unique_words = try Coverage.memoryWords(a, &program, &packet.tape);
        const geometry = G.Geometry{ .cpu_log = try Coverage.minimalPrefixLog(@intCast(packet.tape.len)), .alu_log = try Coverage.minimalLog(counts.alu), .binary_log = try Coverage.minimalLog(counts.binary), .shift_log = try Coverage.minimalLog(counts.shift), .jalr_log = try Coverage.minimalLog(counts.jalr), .division_log = try Coverage.minimalLog(counts.division), .multiplication_log = try Coverage.minimalLog(counts.multiplication), .ls_log = try Coverage.minimalPrefixLog(counts.memory), .boundary_log = try Coverage.minimalPrefixLog(unique_words) };
        try geometry.validate();
        const shapes = G.shapes(&program, geometry);
        const planning = .{ .scope = "planning only; boundary capacity uses exact unique touched words", .physical_proof_verified = false, .global_chain_accepted = false, .packet_index = packet.metadata.index, .steps = packet.tape.len, .packet_bytes = try file.getEndPos(), .tape_retained_bytes = packet.tape.retainedBytes(), .image_ns = image_ns, .packet_read_ns = packet_ns, .total_ns = timer.read(), .counts = counts, .unique_memory_words = unique_words, .geometry = geometry, .shapes = shapes, .evaluation_domains = G.domains(shapes), .composition_log_split = 2, .source_cells = try G.cells(&shapes) };
        return stdout(a, planning);
    }
    try Coordinator.requireGenesis(&image, &packet);
    if (packet.opcode_counts[63] != 0) return error.UnqualifiedWord16ServiceOwners;
    try std.fs.cwd().makeDir(args[4]); // Existing output is never overwritten.
    var dir = try std.fs.cwd().openDir(args[4], .{});
    defer dir.close();
    var sampler: Memory.Sampler = .{ .report = .{ .scope = "new Word16 native preparation through setup, proof, same-process verification and durable publication; excludes packet decode" } };
    try sampler.start();
    defer _ = sampler.finish();
    var recorder = Profile.Recorder.initWithOptions(a, "cpu", "rv64-word16-genesis-prefix", .{ .capture_process_usage = true });
    defer recorder.deinit();
    const prove_start = timer.read();
    var native_scope = try Profile.StageScope.begin(&recorder, "native_advice_preparation", "One CPU witness and exact family grouping");
    defer native_scope.end();
    var prepared = try Prepared.init(a, &program, Coordinator.boundary(&packet), 1, cpu_log, &packet.tape, .{});
    defer prepared.deinit();
    native_scope.end();
    const native_prepare_ns = timer.read() - prove_start;
    const proof_geometry = try prepared.geometry();
    const proof_shapes = G.shapes(&program, proof_geometry);
    try Driver.writeJson(a, dir, "planning.json", .{ .scope = "actual grouped native advice; not a proof", .raw_counts = prepared.raw_counts, .alu_unique_facts = prepared.alu.facts.len, .binary_unique_facts = prepared.binary.facts.len, .geometry = proof_geometry, .shapes = proof_shapes, .evaluation_domains = G.domains(proof_shapes), .source_cells = try G.cells(&proof_shapes) });
    const setup_start = timer.read();
    var setup_scope = try Profile.StageScope.begin(&recorder, "immutable_setup", "Program and selected geometry fixed commitment");
    defer setup_scope.end();
    owns_program = false;
    var setup = try Setup.initOwnedProgram(a, program, proof_geometry);
    defer setup.deinit();
    setup_scope.end();
    const setup_ns = timer.read() - setup_start;
    const sources_start = timer.read();
    var source_scope = try Profile.StageScope.begin(&recorder, "provider_source_construction", "Independent provider witnesses from retained native facts");
    defer source_scope.end();
    var source = try Sources.Source.fromPrepared(a, &setup.materials, Driver.admission(&image).image, &prepared);
    var owns_source = true;
    defer if (owns_source) source.deinit();
    source_scope.end();
    const provider_source_ns = timer.read() - sources_start;
    owns_source = false; // provePrepared consumes on success AND failure.
    var encoded = try Execution.provePrepared(a, &setup, Driver.admission(&image), source, &recorder);
    defer encoded.deinit(a);
    const prove_ns = timer.read() - prove_start - setup_ns;
    const verify_start = timer.read();
    try Execution.verify(a, &setup, Driver.admission(&image), encoded);
    const verify_ns = timer.read() - verify_start;
    try Driver.publish(a, dir, &setup, encoded);
    var stages = try recorder.snapshot(a);
    defer stages.deinit(a);
    try Driver.writeJson(a, dir, "stages.json", stages);
    const cell_bytes = (try dir.statFile("cells.bin")).size;
    const statement_bytes = (try dir.statFile("statement.json")).size;
    const report = .{ .public_ram_sidecar_bytes = cell_bytes, .public_statement_json_bytes = statement_bytes, .proof_and_public_statement_bytes = cell_bytes + statement_bytes + encoded.bytes.len, .scope = "closed genesis execution prefix; no service or cross-batch acceptance", .physical_proof_verified = true, .global_chain_accepted = false, .steps = packet.tape.len, .source_cells = try G.cells(&proof_shapes), .geometry = proof_geometry, .native_prepare_ns = native_prepare_ns, .provider_source_ns = provider_source_ns, .setup_ns = setup_ns, .prove_ns = prove_ns, .same_process_verify_ns = verify_ns, .proof_bytes = encoded.bytes.len, .total_ns = timer.read(), .memory = sampler.finish() };
    try Driver.writeJson(a, dir, "report.json", report);
    try stdout(a, report);
}
fn stdout(a: std.mem.Allocator, value: anytype) !void {
    const json = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}
