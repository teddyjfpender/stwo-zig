//! Research qualification of an admitted execution capture through one parent.
//! This does not attach Span custody or claim a complete execution/block root.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const parent = @import("../recursion/blake3_execution_parent_proof.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
pub fn run(a: std.mem.Allocator, admitted: anytype, capture: anytype, expected: [32]u8, pool: *engine.work_pool.WorkPool, proof_path: []const u8, report_path: []const u8) !void {
    try capture.validate(admitted, expected);
    if (!std.meta.eql(admitted.config, parent.protocol.CSP_CONFIG)) return error.NonCanonicalChildProfile;
    var timer = try std.time.Timer.start();
    var binding = try engine.work_pool.ScopedPoolBinding.init(pool);
    var binding_alive = true;
    defer if (binding_alive) binding.deinit();
    var prepared = try parent.preparation.prepareBounded(a, admitted, capture, expected, 2, 32 * 1024 * 1024 * 1024);
    defer prepared.deinit();
    const key = try parent.ForBackend(Cpu).deriveKeyWithProfile(a, &prepared, .csp_q70_pow26);
    const identity = try key.identity();
    const admission = try parent.protocol.Admission.init(key, identity);
    const prepare_ns = timer.read();
    binding.deinit();
    binding_alive = false;
    const Worker = parent.pipeline.ForBackend(Cpu).Worker;
    const worker = try Worker.init(a, &prepared.rows, admission, .{ .worker_count = 16, .host_byte_limit = 32 * 1024 * 1024 * 1024, .retained_scratch_limit = 0 });
    var worker_alive = true;
    defer if (worker_alive) worker.deinit();
    var proof = try worker.proveConsuming(&prepared.rows);
    defer proof.deinit();
    const worker_peak = worker.budget.snapshot().peak_live_bytes;
    const prove_ns = timer.read() - prepare_ns;
    const bytes = try parent.codec.encode(a, &proof, &admission);
    defer a.free(bytes);
    proof.deinit();
    worker.deinit();
    worker_alive = false;
    var decoded = try parent.codec.decode(a, bytes, &admission);
    defer decoded.deinit();
    var verified = try parent.verify(&decoded, &admission);
    defer verified.deinit();
    try verified.validate(&admission, identity);
    if (verified.capture.queries.raw.len != 70 or !std.mem.eql(u8, &expected, &key.context.child_key_id)) return error.InvalidRecursiveQualification;
    var output = try std.fs.cwd().createFile(proof_path, .{ .exclusive = true });
    defer output.close();
    try output.writeAll(bytes);
    const report = try std.json.Stringify.valueAlloc(a, .{
        .recursive_capture_verified = true,
        .span_custody_attached = false,
        .block_verified = false,
        .queries = 70,
        .pow_bits = 26,
        .child_key_id = expected,
        .admission = admission,
        .preparation_ns = prepare_ns,
        .parent_proving_ns = prove_ns,
        .total_ns = timer.read(),
        .worker_peak_bytes = worker_peak,
        .proof_bytes = bytes.len,
    }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    var file = try std.fs.cwd().createFile(report_path, .{ .exclusive = true });
    defer file.close();
    try file.writeAll(report);
}
