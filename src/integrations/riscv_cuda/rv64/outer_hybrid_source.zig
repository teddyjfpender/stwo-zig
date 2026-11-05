//! Concrete hybrid extension over the original resident MAIN factory. No MAIN,
//! original fractions, Eq/Pre or composition plane is built on the host.
const std = @import("std");
const core = @import("stwo_core");
const CPU = @import("stwo_circuit_cpu_integration");
const Integration = @import("stwo_riscv_cpu_integration");
const Outer = CPU.om31;
const HD = Integration.rv64_outer_hybrid_device;
const H = Integration.rv64_outer_hybrid_air;
const Key = Integration.rv64_outer_hybrid_receiver.Key;
const P = Integration.rv64_outer_gkr_profile;
const S = Integration.rv64_outer_gkr_section;
const Legacy = Integration.rv64_outer_gkr_binding;
const Base = @import("outer_source.zig");
const Native = @import("pcs_native_abi.zig");
const SC = @import("session_context.zig");
const R = @import("resident.zig");
const G = @import("gkr.zig");
const Results = @import("gkr_result.zig");
const A = @import("abi.zig");
const N = @import("runtime_api.zig");
const RC = @import("resident_composition.zig");
const Code = @import("composition_codegen.zig");
const Prefix = @import("prefix_plan.zig");
const D = Integration.rv64_device_pcs;
const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const RawSource = extern struct { fixed: ?[*]const u32, main: [*]const u32, parameters: [*]const u32, status: *u32, fixed_words: u64, main_words: u64, component: u32, row_log: u32, lane_first: u32, lane_log: u32 };
const RawBinding = extern struct { source: RawSource, metadata: [*]const u32, eq: A.Plane, prefix: A.Plane };
const BindingFn = *const fn (*anyopaque, u32, *const RawBinding) callconv(.c) c_int;
const IdentityFn = *const fn (u32, [*]u8) callconv(.c) c_int;
fn symbol(comptime T: type, lib: *std.DynLib, name: [:0]const u8) !T {
    return lib.lookup(T, name) orelse error.MissingOuterHybridKernel;
}
comptime {
    if (@sizeOf(RawSource) != 64 or @sizeOf(RawBinding) != 120) @compileError("hybrid source ABI changed");
}
pub const Runtime = struct {
    allocator: std.mem.Allocator,
    numerical: N.Api,
    validate: @FieldType(R.ProjectedSource, "validate"),
    layer: @FieldType(R.ProjectedSource, "layer"),
    sum: @FieldType(R.ProjectedSource, "sum"),
    fold: @FieldType(R.ProjectedSource, "fold"),
    mask: @FieldType(R.ProjectedSource, "mask"),
    binding: BindingFn,
    role: *const @TypeOf(A.stwo_rv64_composition_role_on),
    metadata: [P.N_COMPONENTS]RC.KernelMetadata,
    base_context: ?*Base.Context = null,
    pub fn create(a: std.mem.Allocator, library: *std.DynLib) !*Runtime {
        const out = try a.create(Runtime);
        errdefer a.destroy(out);
        out.* = .{ .allocator = a, .numerical = try N.Api.load(library), .validate = try symbol(@FieldType(R.ProjectedSource, "validate"), library, "stwo_circuit_outer_gkr_validate_on"), .layer = try symbol(@FieldType(R.ProjectedSource, "layer"), library, "stwo_circuit_outer_gkr_layer_on"), .sum = try symbol(@FieldType(R.ProjectedSource, "sum"), library, "stwo_circuit_outer_gkr_sum_on"), .fold = try symbol(@FieldType(R.ProjectedSource, "fold"), library, "stwo_circuit_outer_gkr_fold_on"), .mask = try symbol(@FieldType(R.ProjectedSource, "mask"), library, "stwo_circuit_outer_gkr_mask_on"), .binding = try symbol(BindingFn, library, "stwo_circuit_outer_gkr_binding_on"), .role = try symbol(*const @TypeOf(A.stwo_rv64_composition_role_on), library, "stwo_circuit_hybrid_om31_composition_role_on"), .metadata = undefined };
        const identity = try symbol(IdentityFn, library, "stwo_circuit_hybrid_om31_composition_identity");
        const bytes = try std.fs.cwd().readFileAlloc(a, CPU.air.bundle_path, 64 << 20);
        defer a.free(bytes);
        var template = try Outer.prove.parsePinnedAir(a, bytes);
        defer template.deinit();
        var made: usize = 0;
        errdefer for (out.metadata[0..made]) |*item| item.deinit();
        for (&out.metadata, template.components, 0..) |*metadata, *captured, i| {
            var artifact = try H.record(a, captured, @enumFromInt(i));
            defer artifact.deinit();
            var expected: [64]u8 = undefined;
            @memcpy(expected[0..32], &artifact.program.identity);
            @memcpy(expected[32..], &(try Code.identity(&artifact.program)));
            var actual: [64]u8 = undefined;
            try Base.checked(identity(@intCast(i), &actual));
            if (!std.mem.eql(u8, &expected, &actual)) return error.HybridCompositionAuthorityMismatch;
            metadata.* = try RC.KernelMetadata.fromProgram(a, &artifact.program, &artifact.parameter_slots);
            made += 1;
        }
        return out;
    }
    pub fn destroy(self: *Runtime) void {
        for (&self.metadata) |*item| item.deinit();
        const a = self.allocator;
        a.destroy(self);
    }
    pub fn attach(self: *Runtime, context: *Base.Context, base: Outer.device_prove.Factory) !Outer.device_prove.Factory {
        if (@import("trace_input_reuse.zig").enabled()) return error.UnqualifiedHybridInterReuse;
        if (base.context != @as(*anyopaque, context) or (self.base_context != null and self.base_context.? != context)) return error.InvalidHybridFactoryExtension;
        self.base_context = context;
        return HD.attach(base, self, &interface);
    }
    const interface = HD.Interface{ .prepare = prepare };
    fn prepare(raw: *anyopaque, base_context: *anyopaque, a: std.mem.Allocator, key: *const Key, base: Outer.device_prove.Source) !HD.Source {
        const self: *Runtime = @ptrCast(@alignCast(raw));
        if (self.base_context == null or @as(*anyopaque, self.base_context.?) != base_context) return error.InvalidHybridFactoryExtension;
        try key.class.validate();
        if (key.class.binding_version != .cyclic_eq_v2 or key.class.instances.len != 8) return error.OuterGkrBindingShape;
        const native: *Base.Owner = @ptrCast(@alignCast(base.context));
        if (@as(*anyopaque, native.backend) != base_context or native.key != key.source or !std.meta.eql(native.scope, base.scope)) return error.InvalidHybridSourceCustody;
        const owner = try a.create(Owner);
        errdefer a.destroy(owner);
        const columns = try a.alloc(D.TraceColumn, H.interactionColumns());
        a.free(native.inter_columns);
        native.inter_columns = columns;
        owner.* = .{ .allocator = a, .runtime = self, .native = native, .base = base, .key = key, .composition = .{ .context = owner, .evaluate_and_commit = Owner.compose } };
        return .{ .context = owner, .base = base, .composition = &owner.composition, .gkr = Owner.gkr, .interaction = Owner.interaction, .release = Owner.release };
    }
};
const BindingData = struct { point: [28]O, point_len: usize, claims: [8][2]O, late: Legacy.Challenges };
const Owner = struct {
    allocator: std.mem.Allocator,
    runtime: *Runtime,
    native: *Base.Owner,
    base: Outer.device_prove.Source,
    key: *const Key,
    composition: @import("stwo_prover_api").device_composition.ResidentOm31Stage,
    parameters: ?Native.Lease = null,
    status: ?Native.Lease = null,
    fixed: [P.N_COMPONENTS]?Native.Lease = @splat(null),
    main: [P.N_COMPONENTS]Slice = undefined,
    descriptors: [8]RawSource = undefined,
    borrowed: [8][4]Slice = undefined,
    borrowed_counts: [8]usize = undefined,
    claims: Outer.witness.Claims = undefined,
    section: ?S.Section = null,
    binding_data: ?BindingData = null,
    ready: bool = false,
    failure: ?anyerror = null,
    operation: *const fn (*Owner, *anyopaque, u64) anyerror!void = undefined,
    phase: []const u8 = "none",
    seed: [9]u32 = undefined,
    fn run(self: *Owner, phase: []const u8, operation: *const fn (*Owner, *anyopaque, u64) anyerror!void) !void {
        self.phase = phase;
        self.operation = operation;
        self.failure = null;
        const status = self.native.backend.service.submit(self.native.backend.service.session, callback, self);
        if (self.failure) |err| return err;
        try Base.checked(status);
    }
    fn callback(raw: *anyopaque, token: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *Owner = @ptrCast(@alignCast(data.?));
        self.operation(self, raw, token) catch |err| {
            std.debug.print("GPU_OUTER_HYBRID_PHASE_ERROR phase={s} error={s}\n", .{ self.phase, @errorName(err) });
            self.failure = err;
            return 1;
        };
        return 0;
    }
    fn gkr(raw: *anyopaque, a: std.mem.Allocator, key: *const Key, scope: D.Scope, z: O, alpha: O, channel: *const S.RawChannel) !HD.Stage {
        const self: *Owner = @ptrCast(@alignCast(raw));
        if (self.ready or self.parameters != null or key != self.key or !std.meta.eql(scope, self.base.scope)) return error.InvalidOuterInteractionScope;
        self.native.z = z;
        self.native.alpha = alpha;
        const gate: ?*std.Thread.Mutex = if (comptime @hasField(RC.Context, "phase_mutex")) self.native.backend.composition.phase_mutex else null;
        if (gate) |mutex| mutex.lock();
        defer if (gate) |mutex| mutex.unlock();
        try self.run("classic", classic);
        var start = channel.*;
        start.mixFelts(&self.claims.toArray());
        var attempt: u32 = 0;
        while (attempt < S.MAX_SALT_ATTEMPTS) : (attempt += 1) {
            const salt = O.fromBase(M.fromCanonical(attempt));
            self.seed = try S.deviceSeed(&start, &key.class, salt);
            try self.run("gkr", traverse);
            var section = self.section orelse return error.HybridGkrUnavailable;
            self.section = null;
            section.class = &key.class;
            section.salt = salt;
            var replay = start;
            if (S.verify(a, &replay, &section)) |checked| {
                var verified = checked;
                defer verified.deinit(a);
                var strict = S.StrictChannel{ .inner = replay };
                _ = Legacy.drawChallenges(&strict, key.class.instances.len);
                if (strict.rejected) {
                    section.deinit(a);
                    continue;
                }
                return .{ .claims = self.claims, .section = section };
            } else |err| {
                section.deinit(a);
                switch (err) {
                    error.OuterGkrDrawRejected, error.OuterGkrShapeMismatch, error.DegenerateEvalPoint => continue,
                    else => return err,
                }
            }
        }
        return error.OuterGkrSaltExhausted;
    }
    fn classic(self: *Owner, raw: *anyopaque, token: u64) !void {
        const n = self.native;
        var ctx = n.context(raw, token, n.initial_scope);
        defer ctx.active = false;
        const b = n.backend;
        const a = self.allocator;
        const elements = Outer.witness.Elements.init(n.z, n.alpha);
        var words: [56]u32 = undefined;
        for (n.z.toM31Array(), 0..) |value, i| words[i] = value.v;
        for (elements.powers, 0..) |power, i| for (power.toM31Array(), 0..) |value, j| {
            words[8 + 8 * i + j] = value.v;
        };
        self.parameters = try n.owned(&ctx, 56);
        try ctx.upload(try ctx.borrow(self.parameters.?), &words);
        self.status = try n.owned(&ctx, 1);
        try Base.checked(b.clear(raw, self.status.?.words.?, 0, 4));
        var results = try ctx.allocate(8 * P.N_COMPONENTS, 0);
        defer ctx.release(&results) catch {};
        try Base.checked(b.clear(raw, results.words.?, 0, results.count * 4));
        var claims: [P.N_COMPONENTS]O = @splat(O.zero());
        const kinds = std.enums.values(@import("stwo_circuit_frontend").common.component_list.ComponentList);
        const widths = @import("stwo_circuit_frontend").witness.trace.traceWidths();
        var main_at: usize = 0;
        for (n.key.logs.toArray(), kinds, widths, 0..) |log, kind, width, ci| {
            const rows = @as(usize, 1) << @intCast(log);
            const component: P.Component = @enumFromInt(ci);
            const indices = try Base.lookupIndices(a, n.key, ci);
            defer a.free(indices);
            const main = n.main_columns[main_at].device orelse return error.MissingOuterDeviceMain;
            for (n.main_columns[main_at..][0..width], 0..) |column, i| {
                const input = column.device orelse return error.MissingOuterDeviceMain;
                if (column.log_size != log or input.count != rows or input.words != main.words + i * rows or input.context_token != main.context_token or input.generation != main.generation) return error.InvalidCircuitLookupGeometry;
                try Base.checked(b.service.lease_validate_range(b.service.session, input.words, input.count, input.context_token, input.generation, &@import("pcs_scope.zig").identity(n.initial_scope)));
            }
            if (P.gkrBound(component)) {
                if (indices.len != 0) {
                    const fixed = try n.owned(&ctx, indices.len * rows);
                    self.fixed[ci] = fixed;
                    for (indices, 0..) |index, i| {
                        const input = n.raw_fixed[index];
                        if (input.count != rows) return error.InvalidCircuitLookupGeometry;
                        try Base.checked(b.service.lease_validate_range(b.service.session, input.words.?, input.count, input.context_token, input.generation, &@import("pcs_scope.zig").identity(n.initial_scope)));
                        try Base.checked(b.copy(raw, @ptrCast(fixed.words.? + i * rows), @ptrCast(input.words.?), rows * 4));
                    }
                }
                const all = try ctx.borrow(n.main_evaluations);
                const offset = (@intFromPtr(main.words) - all.address) / 4;
                self.main[ci] = try all.sub(offset, width * rows);
            } else {
                const pairs = (@import("stwo_circuit_frontend").witness.trace.RawLookupRows.count(kind) + 1) / 2;
                var fixed = try ctx.allocate(@max(1, indices.len * rows), 0);
                defer ctx.release(&fixed) catch {};
                for (indices, 0..) |index, i| {
                    const input = n.raw_fixed[index];
                    if (input.count != rows) return error.InvalidCircuitLookupGeometry;
                    try Base.checked(b.service.lease_validate_range(b.service.session, input.words.?, input.count, input.context_token, input.generation, &@import("pcs_scope.zig").identity(n.initial_scope)));
                    try Base.checked(b.copy(raw, @ptrCast(fixed.words.? + i * rows), @ptrCast(input.words.?), rows * 4));
                }
                const output = try n.owned(&ctx, 8 * (pairs + 1) * rows);
                var numerators = try ctx.allocate(8 * pairs * rows, 0);
                defer ctx.release(&numerators) catch {};
                const plan = try Prefix.Plan.init(log);
                var scratch = try ctx.allocate(plan.scratch_words, 0);
                defer ctx.release(&scratch) catch {};
                const job = Base.Fractions{ .fixed = fixed.words.?, .main = main.words, .parameters = self.parameters.?.words.?, .numerators = numerators.words.?, .denominators = output.words.?, .status = @ptrCast(self.status.?.words.?), .fixed_words = indices.len * rows, .main_words = width * rows, .numerator_words = 8 * pairs * rows, .denominator_words = 8 * pairs * rows, .component = @intCast(ci), .row_log = log };
                try Base.checked(b.fractions(raw, 0, &job));
                const global = A.GlobalPairs{ .output = output.words.?, .contributions = numerators.words.?, .scan_scratch = scratch.words.?, .claim = results.words.? + 8 * ci, .status = self.status.?.words.?, .stride = rows, .scan_words = plan.scratch_words, .row_log = log, .pairs = @intCast(pairs) };
                try Base.checked(b.global_pairs(raw, 0, &global));
                const cumulative = Base.Cumulative{ .output = output.words.?, .contributions = numerators.words.?, .claim = results.words.? + 8 * ci, .stride = rows, .row_log = log, .pairs = @intCast(pairs) };
                try Base.checked(b.cumulative(raw, 0, &cumulative));
                for (0..8 * pairs) |i| n.inter_columns[H.interactionStart(component) + i] = .{ .log_size = log, .encoding = .evaluations, .device = .{ .words = output.words.? + i * rows, .count = rows, .context_token = token, .generation = output.generation } };
            }
            main_at += width;
        }
        var claim_words: [8 * P.N_COMPONENTS]u32 = undefined;
        var verdict: [1]u32 = undefined;
        try ctx.download(try ctx.borrow(results), &claim_words);
        try ctx.download(try ctx.borrow(self.status.?), &verdict);
        try ctx.join();
        if (verdict[0] != 0) return error.InvalidCircuitDeviceInteraction;
        for (&claims, 0..) |*claim, ci| {
            if (P.gkrBound(@enumFromInt(ci))) continue;
            var coordinates: [8]M = undefined;
            for (&coordinates, claim_words[8 * ci ..][0..8]) |*coordinate, value| {
                if (value >= core.fields.m31.Modulus) return error.NoncanonicalOuterClaim;
                coordinate.* = M.fromCanonical(value);
            }
            claim.* = O.fromM31Array(coordinates);
        }
        self.claims = Outer.witness.Claims.fromArray(claims);
        const parameter_slice = try ctx.borrow(self.parameters.?);
        const status_slice = try ctx.borrow(self.status.?);
        for (self.key.class.instances, 0..) |instance, i| {
            const ci = @intFromEnum(instance.component);
            var first: u32 = 0;
            for (self.key.class.instances[0..i]) |previous| if (previous.component == instance.component) {
                first += previous.lanes_used;
            };
            const main = self.main[ci];
            self.descriptors[i] = .{ .fixed = if (self.fixed[ci]) |fixed| fixed.words.? else null, .main = @ptrFromInt(main.address), .parameters = @ptrFromInt(parameter_slice.address), .status = @ptrFromInt(status_slice.address), .fixed_words = if (self.fixed[ci]) |fixed| fixed.count else 0, .main_words = main.len, .component = @intCast(ci), .row_log = instance.row_log, .lane_first = first, .lane_log = instance.lane_log };
            var count: usize = 0;
            if (self.fixed[ci]) |fixed| {
                self.borrowed[i][count] = try ctx.borrow(fixed);
                count += 1;
            }
            self.borrowed[i][count] = main;
            count += 1;
            self.borrowed[i][count] = parameter_slice;
            count += 1;
            self.borrowed[i][count] = status_slice;
            count += 1;
            self.borrowed_counts[i] = count;
        }
    }
    fn traverse(self: *Owner, raw: *anyopaque, token: u64) !void {
        const a = self.allocator;
        var ctx = self.native.context(raw, token, self.native.initial_scope);
        defer ctx.active = false;
        var variables: [8]u32 = undefined;
        var inputs: [8]R.Fraction = undefined;
        for (self.key.class.instances, 0..) |instance, i| {
            variables[i] = instance.variables();
            inputs[i] = .{ .count = @as(u32, 1) << @intCast(variables[i]), .projected = .{ .descriptor = &self.descriptors[i], .borrowed = self.borrowed[i][0..self.borrowed_counts[i]], .validate = self.runtime.validate, .layer = self.runtime.layer, .sum = self.runtime.sum, .fold = self.runtime.fold, .mask = self.runtime.mask } };
        }
        const mode = self.native.backend.gkr_mode;
        const plan = try G.Plan.initMode(&variables, @intCast(self.native.backend.service.byte_cap), mode);
        std.debug.print("GPU_OUTER_GKR_PLAN ordinal={} instances=8 facts={} workspace_bytes={} original_fraction_bytes=0 mode={s}\n", .{ self.base.scope.ordinal, self.key.class.fractions(), plan.total_words * 4, @tagName(mode) });
        var workspace = try ctx.allocate(plan.total_words, 0);
        defer ctx.release(&workspace) catch {};
        var seed = try ctx.allocate(9, 0);
        defer ctx.release(&seed) catch {};
        try ctx.upload(try ctx.borrow(seed), &self.seed);
        try ctx.join();
        var commands = R.Commands(SC.Context, N.Api){ .context = &ctx, .api = &self.runtime.numerical, .lane_index = 0 };
        const traversal = try G.enqueueMode(&commands, &inputs, try ctx.borrow(seed), try ctx.borrow(workspace), @intCast(self.native.backend.service.byte_cap), 0, mode);
        try ctx.join();
        var header_words: [20]u32 = undefined;
        var verdict: [1]u32 = undefined;
        try ctx.download(try traversal.state.sub(0, 20), &header_words);
        try ctx.download(try ctx.borrow(self.status.?), &verdict);
        const roots = try a.alloc(u32, 16 * inputs.len);
        defer a.free(roots);
        try ctx.download(traversal.roots, roots);
        const layers = try a.alloc(Results.Layer, traversal.layers);
        defer a.free(layers);
        var made: usize = 0;
        defer for (layers[0..made]) |layer| {
            a.free(layer.records);
            a.free(layer.masks);
        };
        for (layers, traversal.proof[0..traversal.layers]) |*layer, device| {
            const records = try a.alloc(u32, device.records.len);
            const masks = a.alloc(u32, device.masks.len) catch |err| {
                a.free(records);
                return err;
            };
            layer.* = .{ .records = records, .masks = masks };
            made += 1;
            if (records.len != 0) try ctx.download(device.records, records);
            try ctx.download(device.masks, masks);
        }
        try ctx.join();
        if (verdict[0] != 0) return error.InvalidHybridOriginalFraction;
        const header: G.Header = @bitCast(header_words);
        try header.validate(traversal);
        const proof = try Results.assemble(a, .{ .variables = &variables, .roots = roots, .layers = layers });
        self.section = .{ .class = &self.key.class, .salt = O.zero(), .proof = proof };
    }
    fn interaction(raw: *anyopaque, a: std.mem.Allocator, key: *const Key, scope: D.Scope, z: O, alpha: O, verified: *const S.Verified, late: *const Legacy.Challenges) !D.Tree {
        const self: *Owner = @ptrCast(@alignCast(raw));
        if (self.ready or self.binding_data != null or key != self.key or !std.meta.eql(scope, self.base.scope) or !z.eql(self.native.z) or !alpha.eql(self.native.alpha) or verified.artifact.ood_point.len != key.class.layers()) return error.InvalidOuterInteractionScope;
        var binding = BindingData{ .point = undefined, .point_len = verified.artifact.ood_point.len, .claims = undefined, .late = late.* };
        @memcpy(binding.point[0..binding.point_len], verified.artifact.ood_point);
        for (&binding.claims, verified.artifact.claims_to_verify_by_instance) |*out, claims| {
            if (claims.len != 2) return error.OuterGkrShapeMismatch;
            out.* = claims[0..2].*;
        }
        self.binding_data = binding;
        try self.run("binding", fillBindings);
        try self.native.run(Base.Owner.dropMainEvaluations);
        try self.run("promote", promoteInteractions);
        const commit = self.native.backend.trace_commit.stage();
        var request: D.TraceCommitRequest = .{ .scope = scope, .config = key.config, .tree_index = 2, .columns = self.native.inter_columns };
        if (key.config.fri_config.log_blowup_factor == 1) request.retire_input = .{ .context = self.native, .scope = scope, .retire = Base.Owner.retireInteractionInputs };
        const tree = try commit.commit(commit.context, a, request);
        self.native.inter_ready = true;
        self.ready = true;
        try self.native.run(Base.Owner.dropEvaluations);
        self.native.backend.service.finishProofScope(self.native.initial_scope);
        return tree;
    }
    fn promoteInteractions(self: *Owner, _: *anyopaque, _: u64) !void {
        // GKR reads the original MAIN namespace. After all readers join and
        // MAIN evaluations retire, transfer the remaining owned INTER inputs
        // to the final MAIN-root namespace expected by the commitment stage.
        const previous = @import("pcs_scope.zig").identity(self.native.initial_scope);
        const next = @import("pcs_scope.zig").identity(self.native.scope);
        for (self.native.leases.items) |*lease| {
            try Base.checked(self.native.backend.trace_commit.rebind(self.native.backend.service.session, lease, &previous, &next));
        }
    }
    fn fillBindings(self: *Owner, raw: *anyopaque, token: u64) !void {
        const n = self.native;
        var ctx = n.context(raw, token, n.initial_scope);
        defer ctx.active = false;
        const binding = self.binding_data orelse return error.HybridBindingUnavailable;
        const a = self.allocator;
        const eq_fn = try symbol(*const @TypeOf(A.stwo_rv64_binding_eq_on), &n.backend.service.library, "stwo_rv64_binding_eq_on");
        const scan_fn = try symbol(*const @TypeOf(A.stwo_rv64_prefix_scan_on), &n.backend.service.library, "stwo_rv64_prefix_scan_on");
        for (0..P.N_COMPONENTS) |ci| {
            const component: P.Component = @enumFromInt(ci);
            if (!P.gkrBound(component)) continue;
            const log: u32 = self.key.class.row_logs[ci];
            const rows = @as(usize, 1) << @intCast(log);
            var metadata: [28 * 8]u32 = @splat(0);
            var first: usize = 0;
            var target = O.zero();
            var descriptor: ?RawSource = null;
            for (self.key.class.instances, 0..) |instance, g| {
                if (instance.component != component) continue;
                if (descriptor == null) descriptor = self.descriptors[g];
                const weights = try Legacy.eqTable(a, binding.point[binding.point_len - instance.variables() .. binding.point_len - log]);
                defer a.free(weights);
                for (weights, 0..) |weight, lane| for (binding.late.rho[g].mul(weight).toM31Array(), 0..) |value, c| {
                    metadata[8 * (first + lane) + c] = value.v;
                };
                first += instance.lanes_used;
                target = target.add(binding.late.rho[g].mul(binding.claims[g][0].add(binding.late.gamma.mul(binding.claims[g][1]))));
            }
            if (first != P.FACTS[ci].lookups) return error.OuterGkrBindingShape;
            for (binding.late.gamma.toM31Array(), 0..) |value, c| metadata[8 * 26 + c] = value.v;
            target = target.mulM31(try M.fromU64(rows).inv());
            for (target.toM31Array(), 0..) |value, c| metadata[8 * 27 + c] = value.v;
            var point_words: [28 * 8]u32 = undefined;
            for (binding.point[binding.point_len - log .. binding.point_len], 0..) |point, i| for (point.toM31Array(), 0..) |value, c| {
                point_words[8 * i + c] = value.v;
            };
            var point = try ctx.allocate(8 * log, 0);
            defer ctx.release(&point) catch {};
            try ctx.upload(try ctx.borrow(point), point_words[0 .. 8 * log]);
            var meta = try ctx.allocate(metadata.len, 0);
            defer ctx.release(&meta) catch {};
            try ctx.upload(try ctx.borrow(meta), &metadata);
            const output = try n.owned(&ctx, 16 * rows);
            const eq = A.Plane{ .words = output.words.?, .stride = rows, .coordinates = 8 };
            const prefix = A.Plane{ .words = output.words.? + 8 * rows, .stride = rows, .coordinates = 8 };
            try Base.checked(eq_fn(raw, 0, point.words.?, log, eq, self.status.?.words.?));
            const job = RawBinding{ .source = descriptor.?, .metadata = meta.words.?, .eq = eq, .prefix = prefix };
            try Base.checked(self.runtime.binding(raw, 0, &job));
            const plan = try Prefix.Plan.init(log);
            var scratch = try ctx.allocate(plan.scratch_words, 0);
            defer ctx.release(&scratch) catch {};
            var claim = try ctx.allocate(8, 0);
            defer ctx.release(&claim) catch {};
            const scan = A.PrefixScan{ .data = prefix, .scratch = scratch.words.?, .scratch_words = plan.scratch_words, .claim = claim.words.?, .status = self.status.?.words.?, .row_log = log, .center = 0 };
            try Base.checked(scan_fn(raw, 0, &scan));
            for (0..16) |i| n.inter_columns[H.interactionStart(component) + i] = .{ .log_size = log, .encoding = .evaluations, .device = .{ .words = output.words.? + i * rows, .count = rows, .context_token = token, .generation = output.generation } };
        }
        var verdict: [1]u32 = undefined;
        try ctx.download(try ctx.borrow(self.status.?), &verdict);
        try ctx.join();
        if (verdict[0] != 0) return error.HybridBindingRejected;
    }
    fn compose(raw: *anyopaque, a: std.mem.Allocator, randomness: O, log: u32, split: u32, total: usize, trace: *const anyopaque) !D.Tree {
        const self: *Owner = @ptrCast(@alignCast(raw));
        if (!self.ready) return error.OuterInteractionsNotReady;
        const binding = self.binding_data orelse return error.HybridBindingUnavailable;
        var wanted: usize = 0;
        for (self.key.artifacts) |artifact| wanted += artifact.program.roots.len;
        if (total != wanted or log != self.key.source.bound.max_evaluation_log_size or split != 1) return error.InvalidOuterCompositionAuthority;
        const views: [8][]const O = blk: {
            var out: [8][]const O = undefined;
            for (&out, &binding.claims) |*view, *claims| view.* = claims;
            break :blk out;
        };
        const verified = struct { artifact: struct { ood_point: []const O, claims_to_verify_by_instance: []const []const O } }{ .artifact = .{ .ood_point = binding.point[0..binding.point_len], .claims_to_verify_by_instance = &views } };
        var roles: [P.N_COMPONENTS]RC.RuntimeRole = undefined;
        var made: usize = 0;
        defer for (roles[0..made]) |role| a.free(role.parameters);
        for (&roles, self.key.artifacts, self.key.source.bound.components, self.claims.toArray(), 0..) |*role, *artifact, *captured, claim, i| {
            const params = try artifact.parametersFor(O, a, captured, self.native.z, self.native.alpha, &self.key.class, &verified, &binding.late, claim);
            const main = try Outer.geometry.span(captured.*, 1);
            role.* = .{ .id = @intCast(i), .artifact = &self.runtime.metadata[i], .evaluate = self.runtime.role, .trace_log = captured.trace_log_size, .eval_log = captured.evaluation_log_size, .widths = .{ captured.preprocessed_indices.len, main.end - main.start, H.interactionWidth(@enumFromInt(i)) }, .offsets = .{ 0, main.start, H.interactionStart(@enumFromInt(i)) }, .fixed_indices = captured.preprocessed_indices, .parameters = params };
            made += 1;
            if (P.gkrBound(@enumFromInt(i))) {
                const mle = try Integration.rv64_outer_mle_point.MleEvalPointFor(O).init(binding.point[binding.point_len - role.trace_log .. binding.point_len]);
                if (role.trace_log > 27) return error.UnsupportedHybridAuxGeometry;
                var hc: [2 * 27 * 8]u32 = undefined;
                for (0..2) |half| for (0..role.trace_log) |j| for ((if (half == 0) mle.hc0[j] else mle.hc1[j]).toM31Array(), 0..) |value, c| {
                    hc[(half * role.trace_log + j) * 8 + c] = value.v;
                };
                role.auxiliary = .{ .hc = hc };
            }
        }
        return self.native.backend.composition.evaluateRolesAtBlowup(a, &roles, randomness, log, split, total, trace, self.native.scope, self.key.config.fri_config.log_blowup_factor);
    }
    fn release(raw: *anyopaque) void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        if (self.section) |*section| section.deinit(self.allocator);
        const a = self.allocator;
        self.base.release(self.base.context);
        a.destroy(self);
    }
};
