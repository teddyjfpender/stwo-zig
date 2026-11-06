//! Production-worker GKR numerical adapter on the caller's persistent session.
//! Physical MAIN is reconstructed from the actual committed coefficients. Raw
//! fractions, relation draws and traversal stay on device. Native services still
//! owns terminal binding and final acceptance; this is not that admission gate.
const std = @import("std");
const DeviceCopy = @import("scoped_device_copy.zig");
const ProjectionLifetime = @import("projection_lifetime.zig");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Child = @import("stwo_riscv_cpu_integration").rv64_gkr_child;
const Native = @import("pcs_native_abi.zig");
const SC = @import("session_context.zig");
const R = @import("resident.zig");
const G = @import("gkr.zig");
const Results = @import("gkr_result.zig");
const Sources = @import("gkr_sources.zig");
const Source = @import("projection_codegen.zig").Source;
const N = @import("runtime_api.zig");
const A = @import("abi.zig");
const Events = @import("cuda_events.zig");
const DeviceBindingRuntime = @import("device_binding_runtime.zig");
const TwiddleCache = @import("gkr_twiddles.zig");
const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
const O = core.fields.om31.OM31;
const Cost = @import("native_gkr_cost.zig");
const Admission = @import("admission_runtime.zig");
const Service = @import("pcs_native.zig");
const Proof = engine.lookups.gkr_verifier.ForField(O).GkrBatchProof;
const Projection = extern struct {
    fixed: [*]const u32,
    main: [*]const u32,
    public_values: [*]const u32,
    offsets: [*]const u64,
    parameters: [*]const u32,
    n: [*]u32,
    d: [*]u32,
    status: [*]u32,
    log: u32,
    first: u32,
    rows: u32,
};
const Launch = *const fn (*anyopaque, *const Projection) callconv(.c) c_int;
const N2b = *const fn ([*]u32, usize, u32, u32, [*]const u32, u32, u32, *anyopaque, *u32) callconv(.c) c_int;
const Gather = *const fn (*anyopaque, u32, [*]const u32, [*]u32, [*]const u32, u32, u32, [*]u32) callconv(.c) c_int;
const Functions = struct {
    submit: Native.Submit,
    copy_device: Native.CopyDevice,
    n2b: N2b,
    gather: Gather,
    channel_init: *const @TypeOf(@import("abi.zig").stwo_rv64_channel_init_on),
    channel_mix: *const @TypeOf(@import("abi.zig").stwo_rv64_channel_mix_on),
    channel_draw: *const @TypeOf(@import("abi.zig").stwo_rv64_channel_draw_on),
    launch: [@import("projection_fixture_support.zig").count]Launch,
};
fn symbol(comptime T: type, library: *std.DynLib, name: [:0]const u8) !T {
    return library.lookup(T, name) orelse return error.MissingCudaGkrSymbol;
}
fn checked(status: c_int) !void {
    if (status != 0) return error.CudaGkrStageFailed;
}
fn treeBatchEnabled(value: ?[]const u8, available: bool) !bool {
    const text = value orelse return false;
    if (std.mem.eql(u8, text, "0")) return false;
    if (!std.mem.eql(u8, text, "1")) return error.InvalidCudaGkrTreeMode;
    if (!available) return error.MissingCudaBatchedTreeSymbol;
    return true;
}
fn batchEnabled(available: bool, explicit_batch: bool, explicit_serial: bool) !bool {
    if (explicit_batch and explicit_serial) return error.ConflictingCudaGkrOracleModes;
    if (explicit_batch and !available) return error.MissingCudaBatchedOracleSymbol;
    return available and !explicit_serial;
}
pub const CoefficientSink = struct {
    context: *anyopaque,
    /// Owner-thread publication. Success adopts the lease and copies only
    /// metadata; failure must leave lease ownership with the caller.
    publish: *const fn (*anyopaque, [8]u32, Native.Lease, []const @import("stwo_riscv_cpu_integration").rv64_device_pcs.Column, []const @import("stwo_riscv_cpu_integration").rv64_device_pcs.Column, []const usize) anyerror!void,
};
pub const FixedProvider = struct {
    context: *anyopaque,
    acquire: *const fn (*anyopaque, *anyopaque, @import("stwo_riscv_cpu_integration").rv64_device_pcs.Scope, []const @import("stwo_riscv_cpu_integration").rv64_device_pcs.Column) anyerror![]const @import("stwo_riscv_cpu_integration").rv64_device_pcs.Column,
    release: *const fn (*anyopaque, @import("stwo_riscv_cpu_integration").rv64_device_pcs.Scope) anyerror!void,
};
pub const Backend = struct {
    service: ?*Service.Context = null,
    fixed_provider: ?FixedProvider = null,
    coefficient_sink: ?CoefficientSink = null,
    binding_runtime: ?*DeviceBindingRuntime.Runtime = null,
    configuration_sealed: bool = false,
    allocator: std.mem.Allocator,
    session: *anyopaque,
    session_api: SC.Api,
    numerical: N.Api,
    functions: Functions,
    timing: Events.Api,
    catalogue: Sources.Catalogue,
    twiddle_cache: TwiddleCache.Cache,
    batched_oracles: bool,
    batched_trees: bool,
    batched_tail: bool = false,
    batched_fold_sum: bool = false,
    byte_cap: usize,
    pub const ClassAllocations = struct { numerical: Cost.Plan, binding: Cost.Binding };
    /// Receiver-owned class geometry. No synthetic device pointers,
    /// challenges, fraction arrays or public RAM values are constructed.
    pub fn classAllocationPlan(self: *const Backend, a: std.mem.Allocator, setup: *const @import("stwo_riscv_cpu_integration").rv64_services_roster.CpuSetup) !ClassAllocations {
        const CPU = @import("stwo_riscv_cpu_integration");
        var components = try CPU.rv64_gkr_cpu_components.Plan.init(a, setup);
        defer components.deinit();
        if (components.binding_count == 0 or components.binding_count > A.batch_max_oracles) return error.InvalidGeometry;
        const items = try a.alloc(Cost.Item, components.binding_count);
        defer a.free(items);
        const variables = try a.alloc(u32, components.binding_count);
        defer a.free(variables);
        var cells: usize = 0;
        var fixed_words: usize = 0;
        var max_log: u32 = 0;
        for (0..2) |tree| {
            const logs = try setup.logs(a, tree);
            defer a.free(logs);
            for (logs) |log| {
                if (log < 3 or log > 28) return error.InvalidGkrSourceColumn;
                const n = @as(usize, 1) << @intCast(log);
                cells = try std.math.add(usize, cells, n);
                if (tree == 0) fixed_words = try std.math.add(usize, fixed_words, n);
                max_log = @max(max_log, log);
            }
        }
        var binding_rows: u64 = 0;
        var binding_log: u32 = 0;
        for (components.slots) |slot| if (slot.binding_index) |i| {
            const mode_role = slot.origin == .core and (slot.origin.core == .cpu or slot.origin.core == .and_table);
            const descriptor = Source.Descriptor{ .origin = slot.origin, .cpu_u8_pairs = mode_role and setup.materials.geometry.cpu_u8_pairs, .cpu_compact_decode = slot.origin == .core and slot.origin.core == .cpu and setup.materials.geometry.cpu_compact_decode };
            const artifact = &self.catalogue.artifacts[try self.catalogue.find(descriptor)];
            variables[i] = try std.math.add(u32, slot.log, std.math.log2_int(u32, artifact.lanes));
            if (variables[i] > 28) return error.InvalidGeometry;
            items[i] = .{ .facts = @as(u64, 1) << @intCast(variables[i]), .offsets = artifact.program.inputs.len, .public = Source.Public.count, .parameters = artifact.source_slots.len };
            binding_rows = try std.math.add(u64, binding_rows, @as(u64, 1) << @intCast(slot.log));
            binding_log = @max(binding_log, slot.log);
        };
        const workspace = try G.Plan.init(variables, self.byte_cap);
        return .{ .numerical = try Cost.init(.{ .cells = cells, .twiddles = @as(usize, 1) << @intCast(max_log - 1), .workspace = workspace.total_words, .relation_count = if (setup.materials.geometry.cpu_u8_pairs) @intCast(std.enums.values(Source.Fractions.Relation).len) else @intFromEnum(Source.Fractions.Relation.byte_pair), .items = items, .publish_coefficients = false, .binding_state_words = if (self.binding_runtime != null) A.gkr_state_words else 0, .cold_fixed_words = if (self.fixed_provider != null) fixed_words else 0 }), .binding = try Cost.binding(binding_rows, binding_log) };
    }
    pub fn init(a: std.mem.Allocator, library: *std.DynLib, session: *anyopaque, byte_cap: usize) !Backend {
        var catalogue = try Sources.Catalogue.init(a);
        errdefer catalogue.deinit();
        var functions = Functions{
            .submit = try symbol(Native.Submit, library, "stwo_rv64_gpu_session_submit"),
            .copy_device = try symbol(Native.CopyDevice, library, "stwo_exec_context_memcpy_d2d_async"),
            .n2b = try symbol(N2b, library, "stwo_ntt_n2b_columns_on"),
            .gather = try symbol(Gather, library, "stwo_rv64_parameter_gather_on"),
            .channel_init = try symbol(*const @TypeOf(@import("abi.zig").stwo_rv64_channel_init_on), library, "stwo_rv64_channel_init_on"),
            .channel_mix = try symbol(*const @TypeOf(@import("abi.zig").stwo_rv64_channel_mix_on), library, "stwo_rv64_channel_mix_on"),
            .channel_draw = try symbol(*const @TypeOf(@import("abi.zig").stwo_rv64_channel_draw_on), library, "stwo_rv64_channel_draw_on"),
            .launch = undefined,
        };
        for (&functions.launch, 0..) |*launch, i| {
            var name: [32]u8 = undefined;
            const text = try std.fmt.bufPrintZ(&name, "launch_{}", .{i});
            launch.* = try symbol(Launch, library, text);
        }
        const numerical = try N.Api.load(library);
        const batch_available = numerical.stwo_rv64_batch_sum_on != null and numerical.stwo_rv64_batch_fold_on != null;
        const batch_enabled = try batchEnabled(batch_available, std.process.hasEnvVarConstant("STWO_RV64_GKR_BATCH_ORACLES"), std.process.hasEnvVarConstant("STWO_RV64_GKR_SERIAL_ORACLES"));
        const tree_flag = std.process.getEnvVarOwned(a, "STWO_RV64_GKR_BATCH_TREES") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (tree_flag) |value| a.free(value);
        const trees_enabled = try treeBatchEnabled(tree_flag, numerical.stwo_rv64_batch_layer_on != null);
        const tail_enabled = std.process.hasEnvVarConstant("STWO_RV64_GKR_BATCH_TAIL");
        if (tail_enabled and (!batch_enabled or numerical.stwo_rv64_batch_tail_on == null)) return error.MissingCudaBatchedTailSymbol;
        const fold_sum_flag = std.process.getEnvVarOwned(a, "STWO_RV64_GKR_BATCH_FOLD_SUM") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (fold_sum_flag) |value| a.free(value);
        const fold_sum_enabled = if (fold_sum_flag) |value| blk: {
            if (std.mem.eql(u8, value, "0")) break :blk false;
            if (!std.mem.eql(u8, value, "1")) return error.InvalidCudaBatchedFoldSumMode;
            if (!batch_enabled or numerical.stwo_rv64_batch_fold_sum_on == null) return error.MissingCudaBatchedFoldSumSymbol;
            if (tail_enabled) return error.ConflictingCudaGkrFusions;
            break :blk true;
        } else false;
        return .{ .allocator = a, .session = session, .session_api = .{
            .allocate = try symbol(Native.LeaseAllocate, library, "stwo_rv64_gpu_lease_allocate"),
            .release = try symbol(Native.LeaseRelease, library, "stwo_rv64_gpu_lease_release"),
            .validate_range = try symbol(Native.LeaseValidateRange, library, "stwo_rv64_gpu_lease_validate_range"),
            .upload = try symbol(Native.Upload, library, "stwo_exec_context_memcpy_h2d_async"),
            .download = try symbol(Native.Download, library, "stwo_exec_context_memcpy_d2h_async"),
            .sync = try symbol(Native.Sync, library, "stwo_exec_context_sync"),
            .lane_stream = try symbol(Native.LaneStream, library, "stwo_exec_context_lane_stream"),
        }, .numerical = numerical, .functions = functions, .timing = try Events.Api.load(library), .catalogue = catalogue, .twiddle_cache = .{ .allocator = a }, .batched_oracles = batch_enabled, .batched_trees = trees_enabled, .batched_tail = tail_enabled, .batched_fold_sum = fold_sum_enabled, .byte_cap = byte_cap };
    }
    pub fn enableDeviceBinding(self: *Backend, library: *std.DynLib) !void {
        if (self.configuration_sealed) return error.DeviceBindingConfigurationSealed;
        if (self.binding_runtime != null) return error.DeviceBindingAlreadyEnabled;
        self.binding_runtime = try DeviceBindingRuntime.Runtime.create(self.allocator, library, self.session, self.session_api, self.numerical);
        self.binding_runtime.?.service = self.service;
    }
    pub fn deinit(self: *Backend) void {
        if (self.binding_runtime) |runtime| runtime.destroy();
        self.twiddle_cache.deinit();
        self.catalogue.deinit();
        self.* = undefined;
    }
    pub fn stage(self: *Backend) Child.NumericalStage {
        self.configuration_sealed = true;
        return .{ .context = self, .prove = prove, .bind = if (self.binding_runtime != null) bind else null, .abort = if (self.binding_runtime != null) abort else null, .replay_binding = if (self.binding_runtime != null) replayBinding else null };
    }
    fn prove(raw: *anyopaque, a: std.mem.Allocator, request: Child.NumericalStage.Request) !Proof {
        const self: *Backend = @ptrCast(@alignCast(raw));
        var permit = try self.reserve(a, request);
        if (self.binding_runtime) |runtime| {
            if (permit != null) {
                // Never hold the physical gate while waiting on a preceding
                // worker's partial-verification/binding custody lock.
                while (!runtime.tryAcquire(request.scope)) {
                    // Admission already replaced this scope's old future. A
                    // cancelled, unentered attempt must preserve its pending
                    // numerical work before waiting without the physical gate.
                    try self.service.?.completeAdmission(&permit.?, physicalScope(request.scope), permit.?.demand.successor);
                    runtime.waitAvailable();
                    permit = try self.reserve(a, request);
                }
            } else runtime.acquire(request.scope);
        }
        defer if (permit) |*p| if (!p.closed) p.finish(.{}) catch {
            p.endpoint.planner.poisonPhysical(p.endpoint.physical);
        };
        var job = Job{ .backend = self, .allocator = a, .request = request, .permit = if (permit) |*p| p else null };
        const status = self.functions.submit(self.session, Job.callback, &job);
        if (job.failure) |err| return err;
        try checked(status);
        if (permit) |*p| try self.service.?.completeAdmission(p, physicalScope(request.scope), p.demand.successor);
        return job.proof orelse error.CudaGkrStageFailed;
    }
    fn reserve(self: *Backend, a: std.mem.Allocator, request: Child.NumericalStage.Request) !?Admission.Permit {
        const service = self.service orelse return null;
        const endpoint = service.admission orelse return null;
        var source = try Sources.Plan.init(a, request, &self.catalogue);
        defer source.deinit();
        const items = try a.alloc(Cost.Item, source.items.len);
        defer a.free(items);
        const variables = try a.alloc(u32, source.items.len);
        defer a.free(variables);
        for (source.items, items, variables) |item, *cost, *variable| {
            cost.* = .{ .facts = item.facts, .offsets = item.offsets.len, .public = item.public.len, .parameters = self.catalogue.artifacts[item.kernel].source_slots.len };
            variable.* = item.log + std.math.log2_int(u32, item.lanes);
        }
        const traversal = try G.Plan.init(variables, @min(self.byte_cap, request.byte_cap));
        var fixed_words: u64 = 0;
        if (self.fixed_provider != null) for (request.native_fixed_columns) |column| {
            fixed_words = try std.math.add(u64, fixed_words, @as(u64, 1) << @intCast(column.log_size));
        };
        var all_main_resident = true;
        for (request.native_main_columns) |column| all_main_resident = all_main_resident and column.device != null;
        const native = request.native_source orelse return error.NativeGkrSourceRequired;
        const plan = try Cost.init(.{ .cells = source.cells, .twiddles = @as(usize, 1) << @intCast(source.max_log - 1), .workspace = traversal.total_words, .relation_count = if (native.core.cpu.u8_pairs) @intCast(std.enums.values(Source.Fractions.Relation).len) else @intFromEnum(Source.Fractions.Relation.byte_pair), .items = items, .publish_coefficients = self.coefficient_sink != null and !all_main_resident, .binding_state_words = if (self.binding_runtime != null) A.gkr_state_words else 0, .cold_fixed_words = fixed_words });
        const successor = try service.admissionSuccessor(physicalScope(request.scope), .native_gkr);
        const Global = @import("global_admission.zig");
        return try endpoint.reserve(.{ .progress_key = Global.progressKey(request.scope), .owner = .{ .request = std.mem.readInt(u64, request.scope.statement[0..8], .little), .domain = .gkr_packet, .ordinal = request.scope.ordinal }, .stage = .gkr, .temporary = plan.peak, .stage_retained_upper = plan.retained, .successor = successor, .known = true, .host_known = false });
    }
    fn bind(raw: *anyopaque, a: std.mem.Allocator, request: Child.DeviceBinding.Request) !Child.DeviceBinding.Owner {
        const self: *Backend = @ptrCast(@alignCast(raw));
        return (self.binding_runtime orelse return error.DeviceBindingUnavailable).bind(a, request);
    }
    fn replayBinding(raw: *anyopaque, a: std.mem.Allocator, request: Child.NumericalStage.Request, owner: *Child.DeviceBinding.Owner) !void {
        const self: *Backend = @ptrCast(@alignCast(raw));
        // Replay also invokes the projected binding and replay digest in the
        // same owner callback. Its joined cost is not this numerical plan.
        if (self.service) |service| if (service.admission != null) return error.NativeGkrReplayAdmissionUnavailable;
        if (!owner.parked or !std.meta.eql(owner.scope, request.scope)) return error.DeviceBindingReplayPhase;
        const runtime = self.binding_runtime orelse return error.DeviceBindingUnavailable;
        runtime.acquire(request.scope);
        defer runtime.abort(request.scope);
        var job = Job{ .backend = self, .allocator = a, .request = request, .replay_owner = owner };
        const status = self.functions.submit(self.session, Job.callback, &job);
        if (job.failure) |err| return err;
        try checked(status);
        if (owner.parked) return error.DeviceBindingReplayRequired;
    }
    fn abort(raw: *anyopaque, scope: @TypeOf(@as(Child.NumericalStage.Request, undefined).scope)) void {
        const self: *Backend = @ptrCast(@alignCast(raw));
        if (self.binding_runtime) |runtime| runtime.abort(scope);
    }
};
const Job = struct {
    backend: *Backend,
    allocator: std.mem.Allocator,
    request: Child.NumericalStage.Request,
    proof: ?Proof = null,
    failure: ?anyerror = null,
    replay_owner: ?*Child.DeviceBinding.Owner = null,
    permit: ?*Admission.Permit = null,
    fn callback(raw_context: *anyopaque, token: u64, raw: ?*anyopaque) callconv(.c) c_int {
        const self: *Job = @ptrCast(@alignCast(raw orelse return 1));
        const Observer = @import("allocation_observer.zig");
        var observed: ?Observer.Range = null;
        if (Observer.enabled()) {
            const service = self.backend.service orelse {
                self.failure = error.MissingNativeAllocationObserverService;
                return 1;
            };
            observed = Observer.Range.begin(&service.library, raw_context, physicalScope(self.request.scope), 2, .native_gkr, 0) catch |err| {
                self.failure = err;
                return 1;
            };
        }
        defer if (observed) |*range| range.deinit();
        // Diagnostic only (STWO_RV64_NVTX=1): names this owner callback for
        // scripts/rv64_m8_native_timeline.py idle attribution.
        var nvtx: ?@import("nvtx_stage.zig").Range = if (self.backend.service) |service| @import("nvtx_stage.zig").Range.beginUnlessAdmitted(&service.library, raw_context, "rv64/native/gkr", self.permit != null) catch |err| {
            self.failure = err;
            return 1;
        } else null;
        defer if (nvtx) |*range| range.deinit();
        if (self.permit) |p| p.enterOwner(raw_context) catch |err| {
            self.failure = err;
            return 1;
        };
        self.execute(raw_context, token) catch |err| {
            self.failure = err;
            if (self.permit) |p| {
                p.leaveOwner(raw_context) catch {};
                p.endpoint.planner.poisonPhysical(p.endpoint.physical);
            }
            return 1;
        };
        if (self.permit) |p| {
            if (self.backend.session_api.sync(raw_context) != 0) {
                self.failure = error.CudaGkrStageFailed;
                return 1;
            }
            p.leaveOwner(raw_context) catch |err| {
                self.failure = err;
                return 1;
            };
        }
        return 0;
    }
    fn execute(self: *Job, raw_context: *anyopaque, token: u64) !void {
        var timer = try std.time.Timer.start();
        const a = self.allocator;
        const b = self.backend;
        var events = try Events.Recorder.init(&b.timing);
        defer events.deinit();
        var ingress_stream: ?*anyopaque = null;
        try checked(b.session_api.lane_stream(raw_context, 0, &ingress_stream));
        const upload_stream = ingress_stream orelse return error.InvalidLane;
        var context = SC.Context{ .session = b.session, .native_context = raw_context, .token = token, .scope = @import("pcs_scope.zig").identity(self.request.scope), .api = &b.session_api };
        defer context.active = false;
        const original_fixed_columns = self.request.native_fixed_columns;
        defer self.request.native_fixed_columns = original_fixed_columns;
        const fixed_scope = @import("stwo_riscv_cpu_integration").rv64_device_pcs.Scope{ .statement = self.request.scope.statement, .fixed = self.request.scope.fixed, .main = self.request.scope.main, .ordinal = self.request.scope.ordinal };
        var fixed_acquired = false;
        var fixed_joined = false;
        defer if (fixed_acquired) {
            // Failure paths also drain readers before revoking immutable aliases.
            if (!fixed_joined) context.join() catch {};
            const provider = b.fixed_provider.?;
            provider.release(provider.context, fixed_scope) catch {};
        };
        if (b.fixed_provider) |provider| {
            self.request.native_fixed_columns = try provider.acquire(provider.context, raw_context, fixed_scope, original_fixed_columns);
            fixed_acquired = true;
        }
        var source = try Sources.Plan.init(a, self.request, &b.catalogue);
        defer source.deinit();
        const variables = try a.alloc(u32, source.items.len);
        defer a.free(variables);
        var input_words: usize = 0;
        for (source.items, variables) |item, *v| {
            v.* = item.log + std.math.log2_int(u32, item.lanes);
            input_words = try std.math.add(usize, input_words, @as(usize, item.facts) * 9);
        }
        const native_source = self.request.native_source orelse return error.NativeGkrSourceRequired;
        if (self.request.instances[0].origin != .core or self.request.instances[0].origin.core != .cpu) return error.InvalidGkrSourceColumn;
        const v3 = native_source.core.cpu.u8_pairs;
        if (source.items[0].terms != Source.Fractions.cpuTerms(v3)) return error.InvalidGkrSourceColumn;
        const relations = comptime std.enums.values(Source.Fractions.Relation);
        const relation_count: u32 = if (v3) @intCast(relations.len) else @intFromEnum(Source.Fractions.Relation.byte_pair);
        const cap = @min(b.byte_cap, self.request.byte_cap);
        const plan = try G.Plan.init(variables, cap);
        var main_already_resident = true;
        for (self.request.native_main_columns) |column| main_already_resident = main_already_resident and column.device != null;
        const publish_coefficients = b.coefficient_sink != null and !main_already_resident;
        const twiddle_words = @as(usize, 1) << @intCast(source.max_log - 1);
        var metadata_words: usize = 9 + 16 + 16 + 310 * 8 + 1 + 3 + 2 * @as(usize, relation_count);
        if (b.binding_runtime != null) metadata_words += A.gkr_state_words;
        for (source.items) |item| {
            const parameter_words = try std.math.mul(usize, b.catalogue.artifacts[item.kernel].source_slots.len, 8);
            const item_words = try std.math.add(usize, try std.math.mul(usize, item.offsets.len, 2), try std.math.add(usize, item.public.len, parameter_words));
            metadata_words = try std.math.add(usize, metadata_words, item_words);
        }
        const workspace_words = if (self.replay_owner != null) 0 else plan.total_words;
        const requested = try ProjectionLifetime.peakWords(metadata_words, input_words, source.cells, twiddle_words, workspace_words, publish_coefficients);
        if (try std.math.mul(usize, requested, 4) > cap) return error.GkrWorkspaceBudgetExceeded;
        var leases: std.ArrayList(Native.Lease) = .empty;
        var published_generation: u64 = 0;
        var pending_generations: [2 * A.batch_max_oracles + 1]u64 = undefined;
        var pending_count: usize = 0;
        defer {
            for (leases.items) |*lease| {
                if (lease.generation == published_generation) continue;
                var keep = false;
                for (pending_generations[0..pending_count]) |generation| keep = keep or generation == lease.generation;
                if (!keep) context.release(lease) catch {};
            }
            leases.deinit(a);
        }
        // Device MAIN already has a durable coefficient owner. Decode directly
        // into the base-evaluation warehouse instead of cloning another1.56GB
        // of immutable coefficients merely to discard it after this traversal.
        const coeff = try allocateKind(a, &context, &leases, source.cells, if (publish_coefficients) 2 else 0);
        const coefficient_lease = leases.items[0];
        const values = if (publish_coefficients) try allocate(a, &context, &leases, source.cells) else coeff;
        const tw = try allocate(a, &context, &leases, twiddle_words);
        try events.mark(.ingress, false, upload_stream);
        var offset: usize = 0;
        var pending_copy: ?DeviceCopy.Run = null;
        for (source.columns) |column| {
            const count = @as(usize, 1) << @intCast(column.log_size);
            const destination = try coeff.sub(offset, count);
            if (column.device) |device| {
                if (device.count != count) return error.InvalidGkrDeviceColumn;
                const next = try DeviceCopy.Run.init(@intFromPtr(device.words), offset, count, device.context_token, device.generation);
                if (pending_copy) |*run| {
                    if (!try run.append(next)) {
                        try DeviceCopy.execute(&context, b.functions.copy_device, coeff, run.*);
                        pending_copy = next;
                    }
                } else pending_copy = next;
            } else {
                if (pending_copy) |run| try DeviceCopy.execute(&context, b.functions.copy_device, coeff, run);
                pending_copy = null;
                try context.upload(destination, @as([*]const u32, @ptrCast(column.coefficients.ptr))[0..count]);
            }
            offset += count;
        }
        if (pending_copy) |run| try DeviceCopy.execute(&context, b.functions.copy_device, coeff, run);
        var twiddle_timer = try std.time.Timer.start();
        var twiddles = try b.twiddle_cache.acquire(source.max_log);
        const twiddle_setup_ns = twiddle_timer.read();
        var twiddles_ingress_joined = false;
        defer {
            if (!twiddles_ingress_joined) context.join() catch {};
            twiddles.deinit();
        }
        try context.upload(tw, @as([*]const u32, @ptrCast(twiddles.values.ptr))[0..twiddles.values.len]);
        if (publish_coefficients) try checked(b.functions.copy_device(raw_context, @ptrFromInt(values.address), @ptrFromInt(coeff.address), source.cells * 4));
        try events.mark(.ingress, true, upload_stream);
        try context.join();
        twiddles_ingress_joined = true;
        var stream: ?*anyopaque = null;
        try checked(b.session_api.lane_stream(raw_context, 1, &stream));
        const assigned_stream = stream orelse return error.InvalidLane;
        try events.mark(.base_fft, false, assigned_stream);
        for (source.groups) |group| {
            var launches: u32 = 0;
            const count = @as(u32, 1) << @intCast(group.log - 1);
            try checked(b.functions.n2b(@ptrFromInt(values.address + 4 * group.offset), @as(usize, 1) << @intCast(group.log), group.log, group.count, @ptrFromInt(tw.address + 4 * (twiddle_words - count)), count, count, assigned_stream, &launches));
        }
        try events.mark(.base_fft, true, assigned_stream);
        const seed = try allocate(a, &context, &leases, 9);
        var seed_words: [9]u32 = undefined;
        for (seed_words[0..8], 0..) |*word, i| word.* = std.mem.readInt(u32, self.request.source_channel.inner.digest[4 * i ..][0..4], .little);
        seed_words[8] = self.request.source_channel.inner.n_draws;
        try context.upload(seed, &seed_words);
        const channel = try allocate(a, &context, &leases, 16);
        const boundary = try allocate(a, &context, &leases, 16);
        const reservoir = try allocate(a, &context, &leases, 310 * 8);
        const status = try allocate(a, &context, &leases, 1);
        try context.upload(status, &.{0});
        const zeros: [310 * 8]u32 = @splat(0);
        try context.upload(reservoir, &zeros);
        var metadata: [3 + 2 * relations.len]u32 = undefined;
        metadata[0..3].* = .{ if (v3) 0x4c474b33 else 0x4c474b31, 8, relation_count };
        for (relations[0..relation_count], 0..) |relation, i| {
            metadata[3 + 2 * i] = @intCast(i);
            metadata[4 + 2 * i] = @intCast(relation.arity());
        }
        const constants = try upload(a, &context, &leases, metadata[0 .. 3 + 2 * relation_count]);
        try context.join();
        var step: u32 = 0;
        var chain: u64 = 0x47524b5300000000;
        try events.mark(.relation_draws, false, assigned_stream);
        try checked(b.functions.channel_init(raw_context, 1, @ptrFromInt(channel.address), @ptrFromInt(seed.address), chain));
        try checked(b.functions.channel_mix(raw_context, 1, @ptrFromInt(channel.address), step, chain, chain + 1, @ptrFromInt(constants.address), 3, 0, @ptrFromInt(boundary.address)));
        step += 1;
        chain += 1;
        for (relations[0..relation_count], 0..) |relation, i| {
            try checked(b.functions.channel_mix(raw_context, 1, @ptrFromInt(channel.address), step, chain, chain + 1, @ptrFromInt(constants.address + 4 * (3 + 2 * i)), 2, 0, @ptrFromInt(boundary.address)));
            step += 1;
            chain += 1;
            const draws: u32 = 1 + if (relation == .range8) @as(u32, 0) else @as(u32, @intCast(relation.arity()));
            try checked(b.functions.channel_draw(raw_context, 1, @ptrFromInt(channel.address), step, chain, chain + 1, draws, @ptrFromInt(reservoir.address + 4 * i * 31 * 8), @ptrFromInt(boundary.address)));
            step += 1;
            chain += 1;
        }
        try events.mark(.relation_draws, true, assigned_stream);
        const fractions = try a.alloc(R.Fraction, source.items.len);
        defer a.free(fractions);
        const packets = try a.alloc(Projection, source.items.len);
        defer a.free(packets);
        for (source.items, fractions, packets) |item, *fraction, *packet| {
            const artifact = &b.catalogue.artifacts[item.kernel];
            const offsets = try upload(a, &context, &leases, @as([*]const u32, @ptrCast(item.offsets.ptr))[0 .. item.offsets.len * 2]);
            const public = try upload(a, &context, &leases, &item.public);
            const parameters = try allocate(a, &context, &leases, artifact.source_slots.len * 8);
            const numerator = try allocate(a, &context, &leases, item.facts);
            const denominator = try allocate(a, &context, &leases, @as(usize, item.facts) * 8);
            packet.* = .{ .fixed = @ptrFromInt(values.address), .main = @ptrFromInt(values.address), .public_values = @ptrFromInt(public.address), .offsets = @ptrFromInt(offsets.address), .parameters = @ptrFromInt(parameters.address), .n = @ptrFromInt(numerator.address), .d = @ptrFromInt(denominator.address), .status = @ptrFromInt(status.address), .log = item.log, .first = 0, .rows = @as(u32, 1) << @intCast(item.log) };
            fraction.* = .{ .n = .{ .data = numerator, .stride = item.facts, .coordinates = 1 }, .d = .{ .data = denominator, .stride = item.facts, .coordinates = 8 }, .count = item.facts };
        }
        try context.join();
        try events.mark(.projection, false, assigned_stream);
        for (source.items, packets) |item, *packet| {
            const artifact = &b.catalogue.artifacts[item.kernel];
            try checked(b.functions.gather(raw_context, 1, @ptrFromInt(reservoir.address), @constCast(packet.parameters), artifact.source_slots.ptr, @intCast(artifact.source_slots.len), relation_count, @ptrFromInt(status.address)));
            try checked(b.functions.launch[item.kernel](assigned_stream, packet));
        }
        try events.mark(.projection, true, assigned_stream);
        // Projection is the last reader of decoded MAIN/FIXED and FFT scratch.
        // Join before releasing those exact scoped leases, then admit the large
        // traversal workspace. Original published coefficients keep custody.
        try context.join();
        try ProjectionLifetime.retire(&context, &leases, values);
        try ProjectionLifetime.retire(&context, &leases, tw);
        std.debug.print("GPU_GKR_RETIRE ordinal={} projection_temporary_bytes={} before_workspace_bytes={}\n", .{ self.request.scope.ordinal, (source.cells + twiddle_words) * 4, workspace_words * 4 });
        if (self.replay_owner) |owner| {
            try context.join();
            var verdict: [1]u32 = undefined;
            var channel_words: [16]u32 = undefined;
            try context.download(status, &verdict);
            try context.download(channel, &channel_words);
            try context.join();
            fixed_joined = true;
            if (verdict[0] != 0) return error.DeviceBindingReplayRejected;
            const snapshot: @import("channel.zig").Snapshot = @bitCast(channel_words);
            try snapshot.validate(step, chain);
            for (snapshot.digest, 0..) |word, i| if (word != std.mem.readInt(u32, self.request.channel.inner.digest[4 * i ..][0..4], .little)) return error.InvalidDeviceTranscript;
            if (snapshot.draws != self.request.channel.inner.n_draws) return error.InvalidDeviceTranscript;
            var owned: [2 * A.batch_max_oracles]Native.Lease = undefined;
            var count: usize = 0;
            for (fractions) |fraction| for ([_]u64{ fraction.n.data.generation, fraction.d.data.generation }) |generation| {
                owned[count] = try findLease(leases.items, generation);
                count += 1;
            };
            var adopted = false;
            defer if (adopted) {
                for (owned[0..count], pending_generations[0..count]) |lease, *generation| generation.* = lease.generation;
                pending_count = count;
            };
            owner.retained_bytes = try b.binding_runtime.?.adoptReplay(owner.context, raw_context, token, self.request.scope, self.request.instances, fractions, owned[0..count], &adopted);
            owner.parked = false;
            std.debug.print("GPU_GKR_BINDING_REPLAY ordinal={} wall_ns={} facts={} requested_payload_bytes={}\n", .{ self.request.scope.ordinal, timer.read(), input_words / 9, requested * 4 });
            return;
        }
        var commands = R.Commands(SC.Context, N.Api){ .context = &context, .api = &b.numerical, .lane_index = 1 };
        const workspace = try allocate(a, &context, &leases, plan.total_words);
        try events.mark(.traversal, false, assigned_stream);
        commands.batched_oracles = b.batched_oracles;
        commands.batched_trees = b.batched_trees;
        commands.batched_tail = b.batched_tail;
        commands.batched_fold_sum = b.batched_fold_sum;
        const traversal = try G.enqueueWithClosure(&commands, fractions, try channel.sub(0, 9), workspace, cap, chain, status);
        try events.mark(.traversal, true, assigned_stream);
        try context.join();
        const numerical_ready_ns = timer.read();
        try events.mark(.readback, false, upload_stream);
        var verdict: [1]u32 = undefined;
        var header_words: [20]u32 = undefined;
        var channel_words: [16]u32 = undefined;
        var binding_state: ?Slice = null;
        var binding_state_words: [A.gkr_state_words]u32 = undefined;
        if (b.binding_runtime != null) {
            const state = try allocate(a, &context, &leases, A.gkr_state_words);
            try checked(b.functions.copy_device(raw_context, @ptrFromInt(state.address), @ptrFromInt(traversal.traversal.state.address), A.gkr_state_words * 4));
            try context.download(state, &binding_state_words);
            binding_state = state;
        }
        try context.download(status, &verdict);
        try context.download(try traversal.traversal.state.sub(0, 20), &header_words);
        try context.download(channel, &channel_words);
        const roots = try a.alloc(u32, source.items.len * 16);
        defer a.free(roots);
        try context.download(traversal.traversal.roots, roots);
        const layers = try a.alloc(Results.Layer, traversal.traversal.layers);
        defer a.free(layers);
        var made: usize = 0;
        defer for (layers[0..made]) |layer| {
            a.free(layer.records);
            a.free(layer.masks);
        };
        for (layers, traversal.traversal.proof[0..traversal.traversal.layers]) |*layer, device| {
            const records = try a.alloc(u32, device.records.len);
            const masks = a.alloc(u32, device.masks.len) catch |err| {
                a.free(records);
                return err;
            };
            layer.* = .{ .records = records, .masks = masks };
            made += 1;
            if (records.len != 0) try context.download(device.records, records);
            try context.download(device.masks, masks);
        }
        try events.mark(.readback, true, upload_stream);
        try context.join();
        fixed_joined = true;
        const readback_done_ns = timer.read();
        const header: G.Header = @bitCast(header_words);
        try traversal.validate(header, verdict[0]);
        const snapshot: @import("channel.zig").Snapshot = @bitCast(channel_words);
        try snapshot.validate(step, chain);
        for (snapshot.digest, 0..) |word, i| if (word != std.mem.readInt(u32, self.request.channel.inner.digest[4 * i ..][0..4], .little)) return error.InvalidDeviceTranscript;
        if (snapshot.draws != self.request.channel.inner.n_draws) return error.InvalidDeviceTranscript;
        const decode_start_ns = timer.read();
        var proof = try Results.assemble(a, .{ .variables = variables, .roots = roots, .layers = layers });
        errdefer proof.deinit(a);
        const decode_ns = timer.read() - decode_start_ns;
        if (b.coefficient_sink) |sink| if (!main_already_resident) {
            try sink.publish(sink.context, context.scope, coefficient_lease, original_fixed_columns, self.request.native_main_columns, source.offsets);
            published_generation = coefficient_lease.generation;
        };
        if (b.binding_runtime) |runtime| {
            var owned: [2 * A.batch_max_oracles + 1]Native.Lease = undefined;
            var count: usize = 0;
            for (fractions) |fraction| for ([_]u64{ fraction.n.data.generation, fraction.d.data.generation }) |generation| {
                owned[count] = try findLease(leases.items, generation);
                count += 1;
            };
            owned[count] = try findLease(leases.items, binding_state.?.generation);
            count += 1;
            try runtime.install(self.request.scope, self.request.instances, fractions, owned[0..count], binding_state.?, binding_state_words, traversal.traversal.layers, chain);
            for (owned[0..count], pending_generations[0..count]) |lease, *generation| generation.* = lease.generation;
            pending_count = count;
        }
        self.proof = proof;
        var readback_words: usize = 1 + 20 + 16 + roots.len;
        for (layers) |layer| readback_words += layer.records.len + layer.masks.len;
        if (binding_state != null) readback_words += A.gkr_state_words;
        std.debug.print("GPU_GKR_SPANS ordinal={} ingress_ms={d:.6} base_fft_ms={d:.6} draws_ms={d:.6} projection_ms={d:.6} traversal_ms={d:.6} compact_readback_ms={d:.6} numerical_ready_wall_ns={} readback_wall_ns={} native_decode_ns={}\n", .{ self.request.scope.ordinal, try events.milliseconds(.ingress), try events.milliseconds(.base_fft), try events.milliseconds(.relation_draws), try events.milliseconds(.projection), try events.milliseconds(.traversal), try events.milliseconds(.readback), numerical_ready_ns, readback_done_ns - numerical_ready_ns, decode_ns });
        std.debug.print("GPU_GKR ordinal={} native_stage_wall_ns={} facts={} coefficient_cells={} workspace_bytes={} requested_payload_bytes={} compact_d2h_words={} retained_coefficients={} gkr_kernel_launches={} batched_oracles={} batched_trees={} batched_masks={} batched_tail={} batched_fold_sum={} batch_fold_sum_calls={} batch_fold_sum_launches={} twiddle_setup_ns={} twiddle_cache_hit={} twiddle_cache_bytes={}\n", .{ self.request.scope.ordinal, timer.read(), input_words / 9, source.cells, plan.total_words * 4, requested * 4, readback_words, published_generation != 0, commands.launches, b.batched_oracles, b.batched_trees, b.batched_oracles and b.numerical.stwo_rv64_batch_masks_on != null, b.batched_tail, b.batched_fold_sum, commands.batch_fold_sum_calls, commands.batch_fold_sum_launches, twiddle_setup_ns, twiddles.cache_hit, b.twiddle_cache.retained_bytes });
    }
    test "GKR batching defaults to qualified capability and keeps an explicit serial control" {
        try std.testing.expect(try batchEnabled(true, false, false));
        try std.testing.expect(!try batchEnabled(false, false, false));
        try std.testing.expect(!try batchEnabled(true, false, true));
        try std.testing.expectError(error.MissingCudaBatchedOracleSymbol, batchEnabled(false, true, false));
        try std.testing.expectError(error.ConflictingCudaGkrOracleModes, batchEnabled(true, true, true));
    }
};
fn allocate(a: std.mem.Allocator, context: *SC.Context, leases: *std.ArrayList(Native.Lease), words: usize) !Slice {
    return allocateKind(a, context, leases, words, 0);
}
fn allocateKind(a: std.mem.Allocator, context: *SC.Context, leases: *std.ArrayList(Native.Lease), words: usize, kind: u32) !Slice {
    var lease = try context.allocate(words, kind);
    errdefer context.release(&lease) catch {};
    try leases.append(a, lease);
    return context.borrow(lease);
}
fn upload(a: std.mem.Allocator, context: *SC.Context, leases: *std.ArrayList(Native.Lease), words: []const u32) !Slice {
    const out = try allocate(a, context, leases, words.len);
    try context.upload(out, words);
    return out;
}

test "resident GKR worker callback is fully typed without a CUDA link" {
    _ = &Backend.init;
    _ = &Backend.stage;
}
test "GKR product tree batching is explicit and fails closed on invalid mode or old images" {
    try std.testing.expect(!try treeBatchEnabled(null, true));
    try std.testing.expect(!try treeBatchEnabled("0", false));
    try std.testing.expect(try treeBatchEnabled("1", true));
    try std.testing.expectError(error.MissingCudaBatchedTreeSymbol, treeBatchEnabled("1", false));
    try std.testing.expectError(error.InvalidCudaGkrTreeMode, treeBatchEnabled("yes", true));
}

fn findLease(leases: []const Native.Lease, generation: u64) !Native.Lease {
    for (leases) |lease| if (lease.generation == generation) return lease;
    return error.DeviceBindingUnavailable;
}

fn physicalScope(scope: anytype) @import("stwo_riscv_cpu_integration").rv64_device_pcs.Scope {
    return .{ .statement = scope.statement, .fixed = scope.fixed, .main = scope.main, .ordinal = scope.ordinal };
}
