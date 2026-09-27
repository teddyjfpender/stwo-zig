//! Object-only concrete CUDA bridge gate. Retains actual NativeSession owners;
//! no function is invoked, no CUDA library linked, and no device is opened.
const std = @import("std");
const secure = @import("backends/cuda/runtime/secure_polynomial_v1.zig");
const Session = @import("backends/cuda/runtime/session.zig").NativeSession;
const SecureField = @import("backends/cuda/abi/field.zig").SecureField;
fn uploadPlan(session: *Session, plan: *secure.Plan, metadata: secure.Metadata) anyerror!secure.Binding {
    return plan.upload(session, metadata);
}
fn launchPlan(session: *Session, plan: *const secure.Plan, catalog: *const secure.registry.Catalog, binding: secure.Binding, buffers: secure.Buffers, table: ?secure.RangeTable, status: *const secure.ProofStatus) anyerror!secure.Pending {
    return plan.launch(session, catalog, binding, buffers, table, status);
}
fn uploadRange(session: *Session, plan: *secure.RangeTablePlan, destination: secure.Words) anyerror!void {
    return plan.upload(session, destination);
}
fn generateRange(session: *Session, plan: *secure.RangeTablePlan, catalog: *const secure.registry.Catalog, destination: secure.Words, limits: secure.Limits) anyerror!secure.RangeTable {
    return plan.generate(session, catalog, destination, limits);
}
fn scan(session: *Session, catalog: *const secure.registry.Catalog, pending: secure.Pending, log: u32, buses: u32, scratch: secure.ScanBuffers, status: *const secure.ProofStatus, limits: secure.Limits) anyerror!secure.Pending {
    return secure.scanAndCenter(session, catalog, pending, log, buses, scratch, status, limits);
}
fn uploadWitness(session: *Session, witness: *secure.WitnessPlan, destination: secure.Words) anyerror!void {
    return witness.upload(session, destination);
}
fn generateWitness(session: *Session, witness: *const secure.WitnessPlan, catalog: *const secure.registry.Catalog, records: secure.Words, output: secure.Words, status: *const secure.ProofStatus, limits: secure.Limits) anyerror!secure.Pending {
    return witness.generate(session, catalog, records, output, status, limits);
}
fn generateProvider(session: *Session, catalog: *const secure.registry.Catalog, multiplicities: secure.Words, output: secure.Words, status: *const secure.ProofStatus, limits: secure.Limits) anyerror!secure.Pending {
    return secure.rangeWitness(session, catalog, multiplicities, output, status, limits);
}
fn beginStatus(session: *Session, word: secure.Words) anyerror!secure.ProofStatus {
    return secure.ProofStatus.begin(session, word);
}
fn checkStatus(session: *Session, status: *secure.ProofStatus) anyerror!secure.Completion {
    return status.check(session);
}
fn completeStatus(session: *Session, status: *secure.ProofStatus, pending: secure.Pending) anyerror!secure.Completed {
    return status.complete(session, pending);
}
fn admit(session: *Session, completion: secure.Completion, pending: secure.Pending) anyerror!secure.Completed {
    return completion.admit(session, pending);
}
fn readTotals(session: *Session, completed: secure.Completed, output: []SecureField) anyerror!void {
    return completed.readTotals(session, output);
}
export fn stwo_word_cuda_runtime_codegen_gate() void {
    inline for (.{
        &secure.registry.Catalog.read,
        &secure.registry.Catalog.deinit,
        &secure.Plan.init,
        &secure.Plan.deinit,
        &secure.RangeTablePlan.init,
        &secure.Geometry.fractions,
        &secure.WitnessPlan.init,
        &uploadPlan,
        &launchPlan,
        &uploadRange,
        &generateRange,
        &scan,
        &uploadWitness,
        &generateWitness,
        &generateProvider,
        &beginStatus,
        &checkStatus,
        &completeStatus,
        &admit,
        &readTotals,
    }) |function| std.mem.doNotOptimizeAway(function);
}
