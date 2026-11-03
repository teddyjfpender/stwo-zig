//! In-process PCS service. Coefficients are borrowed, never serialized to disk.
const std = @import("std");
const core = @import("stwo_core");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const Abi = @import("pcs_native_abi.zig");
const Export = @import("pcs_request_export.zig");
const Decode = @import("hybrid_pcs.zig");
pub const Context = struct {
    library: std.DynLib,
    session: *anyopaque,
    native_prove: Abi.Prove,
    release: Abi.Release,
    destroy: Abi.Destroy,
    last_error: Abi.Error,
    submit: Abi.Submit,
    lease_allocate: Abi.LeaseAllocate,
    lease_validate: Abi.LeaseValidate,
    lease_validate_range: Abi.LeaseValidateRange,
    lease_release: Abi.LeaseRelease,
    pub fn init(path: []const u8, device: u32, capacity: u64) !Context {
        var library = try std.DynLib.open(path);
        errdefer library.close();
        const create = library.lookup(Abi.Create, "stwo_rv64_pcs_native_create") orelse return error.MissingGpuPcsSymbol;
        const native_prove = library.lookup(Abi.Prove, "stwo_rv64_pcs_native_prove") orelse return error.MissingGpuPcsSymbol;
        const release = library.lookup(Abi.Release, "stwo_rv64_pcs_native_release") orelse return error.MissingGpuPcsSymbol;
        const destroy = library.lookup(Abi.Destroy, "stwo_rv64_pcs_native_destroy") orelse return error.MissingGpuPcsSymbol;
        const last_error = library.lookup(Abi.Error, "stwo_rv64_pcs_native_error") orelse return error.MissingGpuPcsSymbol;
        const submit = library.lookup(Abi.Submit, "stwo_rv64_gpu_session_submit") orelse return error.MissingGpuPcsSymbol;
        const lease_allocate = library.lookup(Abi.LeaseAllocate, "stwo_rv64_gpu_lease_allocate") orelse return error.MissingGpuPcsSymbol;
        const lease_validate = library.lookup(Abi.LeaseValidate, "stwo_rv64_gpu_lease_validate") orelse return error.MissingGpuPcsSymbol;
        const lease_validate_range = library.lookup(Abi.LeaseValidateRange, "stwo_rv64_gpu_lease_validate_range") orelse return error.MissingGpuPcsSymbol;
        const lease_release = library.lookup(Abi.LeaseRelease, "stwo_rv64_gpu_lease_release") orelse return error.MissingGpuPcsSymbol;
        var session: ?*anyopaque = null;
        if (create(device, capacity, &session) != 0 or session == null) return error.GpuPcsInitializationFailed;
        return .{ .library = library, .session = session.?, .native_prove = native_prove, .release = release, .destroy = destroy, .last_error = last_error, .submit = submit, .lease_allocate = lease_allocate, .lease_validate = lease_validate, .lease_validate_range = lease_validate_range, .lease_release = lease_release };
    }
    pub fn deinit(self: *Context) void {
        if (self.destroy(self.session) != 0) @panic("GPU context failed to join before library close");
        self.library.close();
        self.* = undefined;
    }
    pub fn stage(self: *Context) D.Stage {
        return .{ .context = self, .prove = prove };
    }
    fn prove(raw: *anyopaque, a: std.mem.Allocator, request: D.Request, channel: *D.Channel) !D.P.ExtendedCommitmentSchemeProof(D.H) {
        const self: *Context = @ptrCast(@alignCast(raw));
        var timer = try std.time.Timer.start();
        var prepared = try Export.prepareRequest(a, request, channel.*);
        defer prepared.deinit(a);
        const prepare_ns = timer.read();
        const descriptor = prepared.descriptor();
        var result: Abi.Result = .{};
        if (self.native_prove(self.session, &descriptor, &result) != 0) {
            std.debug.print("GPU_PCS_NATIVE error={s}\n", .{self.last_error(self.session)});
            return error.GpuPcsFailed;
        }
        defer self.release(&result);
        if (result.words == null or result.count > (1 << 28)) return error.InvalidGpuPcsProof;
        var decoded = try Decode.decodeWords(a, prepared.metadata.shape, result.words.?[0..@intCast(result.count)]);
        errdefer decoded.proof.deinit(a);
        channel.* = decoded.channel;
        std.debug.print("GPU_PCS_NATIVE prepare_ns={} device_ns={} total_ns={} device_bytes={} retained_bytes={} coefficient_cells={}\n", .{ prepare_ns, result.device_ns, timer.read(), result.requested_bytes, result.retained_bytes, prepared.metadata.coefficient_cells });
        return .{ .proof = decoded.proof, .aux = .{ .unsorted_query_locations = &.{}, .trace_decommitment = core.pcs.TreeVec(core.vcs_lifted.verifier.MerkleDecommitmentLiftedAux(D.H)).initOwned(&.{}), .fri = .{ .first_layer = .{ .all_values = &.{}, .decommitment = .{ .all_node_values = &.{} } }, .inner_layers = &.{} } } };
    }
};
