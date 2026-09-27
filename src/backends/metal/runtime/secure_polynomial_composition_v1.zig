//! Production typed secure quotient dispatch. Installation requires an
//! independently pinned AOT image. No CPU evaluator or source-JIT fallback.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const external = prover.shared_external_memory;
const runtime = @import("../runtime.zig");
const shared = @import("../shared_runtime.zig");
const secure = @import("secure_polynomial_v1.zig");
const ingress = @import("secure_coefficient_ingress_v1.zig");
const capability = prover.air.secure_polynomial_capability_v1;
const ir = capability.ir;
const Component = prover.air.component_prover.ComponentProver;
const Trace = prover.air.component_prover.Trace;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Twiddles = prover.poly.twiddles.TwiddleTree([]const M);
const Column = prover.secure_column.SecureColumnByCoords;
pub const Limits = capability.Limits;
var lock: std.Thread.Mutex = .{};
var installed: ?Installation = null;
const OutputOwner = struct { handle: *anyopaque, bytes: usize, reservation: external.Reservation };
var outputs: [16]?OutputOwner = @splat(null);
var live_output_bytes: usize = 0;
const Installation = struct {
    runtime_handle: *anyopaque,
    initialization_count: u64,
    image_sha: [32]u8,
    identities: [16][32]u8,
    count: usize,
    limits: Limits,
};
/// Initialize the authenticated core runtime first. Typed Specs supplied by
/// the caller define the executable roster; the image SHA is out-of-band.
/// This serial owner also prevents catalog mutation during a quotient command.
pub fn install(a: std.mem.Allocator, image: []const u8, image_sha: [32]u8, programs: []const *const ir.Program, limits: Limits) !void {
    if (limits.max_components == 0 or limits.max_components > 16 or limits.max_metadata_bytes == 0 or limits.max_resident_bytes == 0 or programs.len == 0 or programs.len > 16) return error.InvalidSecureCompositionLimits;
    lock.lock();
    defer lock.unlock();
    var lease = try shared.acquireExisting();
    defer lease.deinit();
    const lifecycle = lease.identitySnapshot();
    if (lifecycle.identity.origin != .authenticated_core_aot) return error.SecureCompositionRequiresAuthenticatedRuntime;
    var proposal = Installation{ .runtime_handle = lease.runtime.handle, .initialization_count = lifecycle.initialization_count, .image_sha = image_sha, .identities = undefined, .count = programs.len, .limits = limits };
    var bytes: usize = 0;
    for (programs, 0..) |program, i| {
        try program.validate();
        bytes = try std.math.add(usize, bytes, try capability.metadataBytes(program));
        if (bytes > limits.max_metadata_bytes) return error.SecureCompositionMetadataCap;
        proposal.identities[i] = program.identity;
        for (proposal.identities[0..i]) |prior| if (std.mem.eql(u8, &prior, &program.identity)) return error.DuplicateSecureCompositionProgram;
    }
    if (installed) |previous| {
        if (previous.initialization_count == proposal.initialization_count) {
            if (previous.runtime_handle != proposal.runtime_handle or !std.mem.eql(u8, &previous.image_sha, &image_sha) or !std.meta.eql(previous.limits, limits) or previous.count != proposal.count) return error.SecureCompositionInstallationConflict;
            for (previous.identities[0..previous.count], proposal.identities[0..proposal.count]) |left, right| if (!std.mem.eql(u8, &left, &right)) return error.SecureCompositionInstallationConflict;
            // Recheck image bytes even on repeated installation.
            var observed: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(image, &observed, .{});
            if (!std.mem.eql(u8, &observed, &image_sha)) return error.SecureAotImageHashMismatch;
            return;
        }
    }
    try secure.installAot(a, lease.runtime, image, image_sha, programs);
    installed = proposal;
}
pub fn validateExport(component: Component, cap: capability.Capability, program: *const ir.Program, trace: *const Trace, a: std.mem.Allocator) !void {
    try program.validate();
    const shape = ir.layout(cap.kind);
    _ = try capability.residentBytes(cap.kind, cap.trace_log);
    if (program.kind != cap.kind or ir.isFraction(cap.kind) or component.nConstraints() != shape.roots or component.maxConstraintLogDegreeBound() != cap.trace_log + shape.expansion_bits or component.compositionLogSplit() != shape.expansion_bits or trace.polys.items.len != 3) return error.InvalidSecureCompositionExport;
    var logs = try component.traceLogDegreeBounds(a);
    defer logs.deinitDeep(a);
    if (logs.items.len != 3) return error.InvalidSecureCompositionExport;
    const counts = [_]usize{ shape.fixed, shape.main, shape.interaction };
    for (logs.items, trace.polys.items, counts) |tree_logs, columns, count| {
        if (tree_logs.len != count or columns.len != count) return error.InvalidSecureCompositionExport;
        for (tree_logs) |log| if (log != cap.trace_log) return error.InvalidSecureCompositionExport;
    }
}
/// null means no component requested this capability. Once requested, absent
/// AOT/source/geometry/caps return an error, including mixed unsupported graphs.
/// Current production word/range/lane PCS proofs have one component each;
/// multiple components sharing the same committed layout/domain are supported.
pub fn evaluate(a: std.mem.Allocator, components: []const Component, random: Q, trace: *const Trace, residents: []const ?*anyopaque, tower: ?Twiddles) !?Column {
    var requested = false;
    for (components) |component| requested = requested or component.secure_polynomial_capability_v1 != null;
    if (!requested) return null;
    lock.lock();
    defer lock.unlock();
    var lease = try shared.acquireExisting();
    defer lease.deinit();
    const config = installed orelse return error.SecureCompositionAotNotInstalled;
    if (config.runtime_handle != lease.runtime.handle or config.initialization_count != lease.identitySnapshot().initialization_count) return error.StaleSecureCompositionInstallation;
    if (components.len > config.limits.max_components) return error.SecureCompositionMetadataCap;
    var programs: [16]ir.Program = undefined;
    var plans: [16]secure.EquationPlan = undefined;
    var initialized: usize = 0;
    var prepared: usize = 0;
    defer for (plans[0..prepared]) |*plan| plan.deinit();
    defer for (programs[0..initialized]) |*program| program.deinit();
    var total: usize = 0;
    var metadata: usize = 0;
    const first = components[0].secure_polynomial_capability_v1 orelse return error.MixedSecureCompositionCapabilities;
    for (components, 0..) |component, i| {
        const cap = component.secure_polynomial_capability_v1 orelse return error.MixedSecureCompositionCapabilities;
        if (cap.kind != first.kind or cap.trace_log != first.trace_log) return error.MixedSecureCompositionDomains;
        programs[i] = try cap.export_program(cap.context, a);
        initialized += 1;
        try validateExport(component, cap, &programs[i], trace, a);
        metadata = try std.math.add(usize, metadata, try capability.metadataBytes(&programs[i]));
        if (metadata > config.limits.max_metadata_bytes) return error.SecureCompositionMetadataCap;
        var admitted = false;
        for (config.identities[0..config.count]) |identity| admitted = admitted or std.mem.eql(u8, &identity, &programs[i].identity);
        if (!admitted) return error.SecureCompositionProgramNotAdmitted;
        plans[i] = try secure.EquationPlan.init(a, &programs[i]);
        prepared += 1;
        try plans[i].prepare(lease.runtime);
        total = try std.math.add(usize, total, programs[i].roots.len);
    }
    const shape = ir.layout(first.kind);
    const eval_log = first.trace_log + shape.expansion_bits;
    const exact = try (tower orelse return error.MissingSecureCompositionTwiddles).subtree(eval_log - 1);
    const source_columns: usize = @as(usize, shape.fixed) + shape.main + shape.interaction;
    const g = try ingress.geometry(source_columns, first.trace_log, eval_log, config.limits.max_resident_bytes);
    const output_bytes = try std.math.mul(usize, g.rows, 16);
    // Include one full FFT workspace envelope and both direction twiddle
    // ingress, output arena and all bounded invocation metadata in the cap.
    const resident_charge = try std.math.add(usize, try std.math.add(usize, g.charged_bytes, g.output_bytes), try std.math.add(usize, output_bytes, try std.math.mul(usize, g.rows, 4)));
    const power_bytes = try std.math.mul(usize, total, 16);
    const peak = try std.math.add(usize, resident_charge, try std.math.add(usize, metadata, power_bytes));
    if (try std.math.add(usize, live_output_bytes, peak) > config.limits.max_resident_bytes) return error.SecureCompositionResidentCap;
    var free_output_slot: ?usize = null;
    for (outputs, 0..) |owner, i| if (owner == null) {
        free_output_slot = i;
        break;
    };
    const output_slot = free_output_slot orelse return error.SecureCompositionOutputOwnerCap;
    const powers = try prover.air.accumulation.generateSecurePowers(a, random, total);
    defer a.free(powers);
    var inputs = try ingress.Owned.init(a, lease.runtime, trace, residents, first.trace_log, eval_log, exact, g.charged_bytes);
    defer inputs.deinit();
    var output_reservation = try external.reserve(a, output_bytes, .require_shared_budget);
    defer output_reservation.deinit();
    var output = try lease.runtime.allocateResidentBuffer(output_bytes);
    output.external_reservation = output_reservation.take();
    var transferred = false;
    defer if (!transferred) output.deinit();
    const values: [*]M = @ptrCast(@alignCast(output.contents));
    // Zeroing output is a GPU blit, not a host quotient initialization.
    try clearOutput(lease.runtime, &output);
    const trees: [3]?secure.Tree = .{
        .{ .buffer = &inputs.resident, .column_offsets = inputs.offsets[0] },
        .{ .buffer = &inputs.resident, .column_offsets = inputs.offsets[1] },
        .{ .buffer = &inputs.resident, .column_offsets = inputs.offsets[2] },
    };
    var cursor = total;
    var gpu_ms = inputs.gpu_milliseconds;
    for (plans[0..prepared], programs[0..initialized]) |*plan, *program| {
        const start = try capability.powerStart(total, &cursor, program.roots.len);
        gpu_ms += try plan.evaluate(program, first.trace_log, trees, powers[start..][0..program.roots.len], &output, .{ .max_resident_bytes = config.limits.max_resident_bytes, .budget_allocator = a });
    }
    if (cursor != 0) return error.InvalidSecurePowerPartition;
    var columns: [4][]M = undefined;
    for (&columns, 0..) |*column, coordinate| column.* = values[coordinate * g.rows ..][0..g.rows];
    const inverse = try lease.runtime.transformCircleResidentBatch(a, &output, &columns, exact.itwiddles, eval_log, true);
    if (!inverse.exact_resident_source or !inverse.direct_host_alias) return error.SecureQuotientTransformNotResident;
    try inputs.requireSource(trace);
    var result = try Column.initResident(columns, .{ .handle = output.handle, .destroyFn = destroyOutput });
    outputs[output_slot] = .{ .handle = output.handle, .bytes = output_bytes, .reservation = output.external_reservation.take() };
    live_output_bytes += output_bytes; // checked by peak admission above
    shared.retainResidentResource();
    transferred = true;
    result.representation = .coefficients;
    std.log.debug("secure typed Metal quotient: kind={s} ingress_bytes={} resident_charge={} gpu_ms={d:.3}", .{ @tagName(first.kind), inputs.ingress_bytes, resident_charge, gpu_ms + inverse.gpu_milliseconds });
    return result;
}
fn destroyOutput(handle: *anyopaque) void {
    lock.lock();
    defer lock.unlock();
    for (&outputs) |*slot| if (slot.*) |owner| {
        if (owner.handle == handle) {
            std.debug.assert(live_output_bytes >= owner.bytes);
            live_output_bytes -= owner.bytes;
            slot.* = null;
            shared.destroyResidentBuffer(handle);
            var reservation = owner.reservation;
            reservation.deinit();
            return;
        }
    };
    unreachable; // A moved resident owner must never be destroyed twice.
}
extern fn stwo_zig_secure_clear_quotient_v1(*anyopaque, *anyopaque, usize) u32;
fn clearOutput(metal: *runtime.Runtime, output: *const runtime.ResidentBuffer) !void {
    if (stwo_zig_secure_clear_quotient_v1(metal.handle, output.handle, output.byte_length) != 0) return error.SecureQuotientClearFailed;
}
