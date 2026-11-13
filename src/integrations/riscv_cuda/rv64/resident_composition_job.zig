//! Resident composition request execution owner; all per-job device leases and cleanup stay together.
const Schema = @import("resident_composition.zig");
const std = @import("std");
const CopyRun = @import("device_copy_run.zig").Run;
const engine = @import("stwo_prover_engine");
const D = CPU.rv64_device_pcs;
const Native = @import("pcs_native_abi.zig");
const SC = @import("session_context.zig");
const Abi = @import("abi.zig");
const Span = enum { coefficients, auxiliary, domain_fft, rows, finalize, commit_fft, commit_hash };
const Timing = Events.RecorderFor(Span);
const O = D.O;
const M = D.M;
const Trace = engine.air.component_prover.ForField(O).Trace;
const CPU = @import("stwo_riscv_cpu_integration");
const Events = @import("cuda_events.zig");

pub const Job = struct {
    outer_workspace: bool = false,
    backend: *Schema.Context,
    allocator: std.mem.Allocator,
    roles: []const Schema.RuntimeRole,
    alpha: O,
    log: u32,
    split: u32,
    total: usize,
    trace: *const Trace,
    scope: D.Scope,
    log_blowup: ?u32 = null,
    result: ?D.Tree = null,
    failure: ?anyerror = null,
    active_role: u32 = 999,
    native_context: ?*anyopaque = null,
    fn checked(self: *Job, comptime operation: []const u8, status: c_int) !void {
        if (status != 0) {
            std.debug.print("GPU_COMPOSITION_FAILED ordinal={} role={} operation={s} native_status={}\n", .{ self.scope.ordinal, self.active_role, operation, status });
            if (self.native_context) |raw| self.backend.service.logMemoryFailure(raw, operation);
            return error.CudaResidentCompositionFailed;
        }
    }
    pub fn callback(raw: *anyopaque, token: u64, user: ?*anyopaque) callconv(.c) c_int {
        const self: *Job = @ptrCast(@alignCast(user orelse return 1));
        self.native_context = raw;
        defer self.native_context = null;
        const Observer = @import("allocation_observer.zig");
        var observed = Observer.Range.begin(&self.backend.service.library, raw, self.scope, if (self.outer_workspace) 1 else 2, .composition, 0) catch |err| {
            self.failure = err;
            return 1;
        };
        defer observed.deinit();
        self.run(raw, token) catch |err| {
            if (self.failure == null) self.failure = err;
        };
        return @intFromBool(self.failure != null);
    }
    fn cleanupFailure(self: *Job, err: anyerror) void {
        if (self.failure == null) self.failure = err;
    }

    fn copyRun(self: *Job, raw: *anyopaque, context: *SC.Context, arena: [*]u32, segment: CopyRun) !void {
        const b = self.backend;
        // Check the WHOLE merged range in this proof's namespace. Adjacency
        // alone is never allocation authority or permission to cross scopes.
        try self.checked("service.lease_validate_range", b.service.lease_validate_range(b.service.session, @ptrFromInt(segment.source), segment.words, segment.context_token, segment.generation, &context.scope));
        try self.checked("copy", b.copy(raw, @ptrCast(arena + segment.target_word), @ptrFromInt(segment.source), try std.math.mul(usize, segment.words, 4)));
    }
    // Each authenticated mask retains its tree identity and full-domain row
    // shift, but its column offset names a slot in one shared evaluation slab.
    fn run(self: *Job, raw: *anyopaque, token: u64) !void {
        var range = try @import("nvtx_stage.zig").Range.beginUnlessAdmitted(&self.backend.service.library, raw, "rv64/composition", false);
        defer range.deinit();
        const a = self.allocator;
        const b = self.backend;
        var context = SC.Context{ .session = b.service.session, .native_context = raw, .token = token, .scope = @import("pcs_scope.zig").identity(self.scope), .api = &b.session_api };
        defer context.active = false;
        // One stream orders ingress, role transforms, quotient accumulation and
        // the final commitment. Keep each role's events until the root readback;
        // collecting timing is observational and must not drain the GPU per role.
        const compute_lane: u32 = 0;
        var events = try Timing.init(&b.timing);
        defer events.deinit();
        const role_events = try a.alloc(Timing, self.roles.len);
        defer a.free(role_events);
        var made_events: usize = 0;
        defer for (role_events[0..made_events]) |*timing| timing.deinit();
        for (role_events) |*timing| {
            timing.* = try Timing.init(&b.timing);
            made_events += 1;
        }
        var spans: [std.meta.fields(Span).len]f64 = @splat(0);
        var stream0: ?*anyopaque = null;
        var stream1: ?*anyopaque = null;
        try self.checked("lane0", b.session_api.lane_stream(raw, 0, &stream0));
        try self.checked("lane1", b.session_api.lane_stream(raw, compute_lane, &stream1));
        // A whole FIXED forest is acquired once under its independently derived
        // root and ordered logs. Its read-only aliases live through native PCS.
        if (self.trace.polys.items.len == 0) return error.MissingResidentFixedTree;
        const fixed_columns = try a.alloc(D.Column, self.trace.polys.items[0].len);
        defer a.free(fixed_columns);
        for (self.trace.polys.items[0], fixed_columns) |column, *out| out.* = try sourceColumn(column);
        // Explicit device FIXED setup already owns scoped coefficients through
        // PCS. Do not clone its forest into a second immutable allocation.
        const all_fixed_device = @import("fixed_forest_policy.zig").isDeviceOnly(fixed_columns);
        const immutable_fixed = if (all_fixed_device) fixed_columns else try b.service.immutableFixed(raw, self.scope, fixed_columns);
        var host_cells: u64 = 0;
        var device_cells: u64 = 0;
        var device_copy_calls: usize = 0;
        var domain_cells: u64 = 0;
        var leases: std.ArrayList(Native.Lease) = .empty;
        defer {
            context.join() catch |err| {
                self.cleanupFailure(err);
            };
            for (leases.items) |*lease| context.release(lease) catch |err| {
                self.cleanupFailure(err);
            };
            leases.deinit(a);
        }
        var buckets: [29]?Native.Lease = @splat(null);
        const powers = try a.alloc(O, self.total);
        defer a.free(powers);
        var power = O.one();
        for (powers) |*p| {
            p.* = power;
            power = power.mul(self.alpha);
        }
        var next = self.total;
        for (self.roles, role_events) |*role, *timing| {
            const id = role.id;
            self.active_role = id;
            const artifact = role.artifact;
            const rl = role.trace_log;
            const el = role.eval_log;
            if (el < rl + 1 or el > rl + 2 or el > self.log) return error.UnsupportedResidentCompositionDomain;
            const n = @as(usize, 1) << @intCast(el);
            const iw = role.widths[2];
            const aux: usize = switch (role.auxiliary) {
                .none => 0,
                .hc => 10,
                .last => 1,
            };
            var widths = role.widths;
            widths[2] += aux;
            const column_count = widths[0] + widths[1] + widths[2];
            var sources: std.ArrayList(engine.air.component_prover.ForField(O).Poly) = .empty;
            defer sources.deinit(a);
            const offsets = role.offsets;
            if (role.fixed_indices) |indices| {
                for (indices) |index| try sources.append(a, self.trace.polys.items[0][index]);
            } else try sources.appendSlice(a, self.trace.polys.items[0][offsets[0]..][0..widths[0]]);
            try sources.appendSlice(a, self.trace.polys.items[1][offsets[1]..][0..widths[1]]);
            try sources.appendSlice(a, self.trace.polys.items[2][offsets[2]..][0..iw]);
            const source_metadata = try a.alloc(D.Column, sources.items.len);
            defer a.free(source_metadata);
            for (source_metadata, sources.items) |*column, source| column.* = try sourceColumn(source);
            var tw_borrow = try b.tw(el);
            defer tw_borrow.deinit(b.allocator);
            const tw = &tw_borrow.value;
            var geometry_borrow = try b.geometry(artifact, rl, el, widths, source_metadata, aux, tw.twiddles.len);
            defer geometry_borrow.deinit(b.allocator);
            const geometry = &geometry_borrow.value;
            // Direct extension: a device column of degree el-1 is extended
            // straight from its retained lease (compact stride) instead of
            // first being copied into the arena. The row kernel reads only the
            // evaluations, so the arena keeps just a staging slab for host,
            // lower-degree and auxiliary columns. Exact field LDE: identical
            // evaluations, identical proof bytes. STWO_RV64_COMPOSITION_DIRECT=0
            // restores the full coefficient copy.
            const direct_enabled = b.n2b_columns != null;
            // M5 platform: degree el-2 device columns are extended directly too
            // (compact source, stride n/4). Same kernels, same evaluations;
            // removes their staged-coefficient copy from the arena (3.69 GB on
            // the 18.44 GB rl+2 truth role). STWO_RV64_COMPOSITION_DIRECT_EL2=0
            // keeps them staged.
            const direct_el2 = direct_enabled and b.n2b_columns_compact != null;
            const direct = try a.alloc(?D.DeviceCoefficients, column_count);
            defer a.free(direct);
            const staging_offsets = try a.alloc(usize, column_count);
            defer a.free(staging_offsets);
            var staging_words: usize = 0;
            var direct_columns: usize = 0;
            for (direct, staging_offsets, 0..) |*slot, *offset, i| {
                slot.* = null;
                offset.* = staging_words;
                if (i < source_metadata.len) {
                    const original = source_metadata[i];
                    const source_tree: u32 = if (i < widths[0]) 0 else if (i < widths[0] + widths[1]) 1 else 2;
                    const original_index = switch (source_tree) {
                        0 => if (role.fixed_indices) |indices| indices[i] else offsets[0] + i,
                        1 => offsets[1] + i - widths[0],
                        else => offsets[2] + i - widths[0] - widths[1],
                    };
                    const immutable = if (source_tree == 0 and original.device == null) immutable_fixed[original_index].device else null;
                    const device = if (original.device != null) original.device else immutable orelse b.service.retainedColumn(context.scope, source_tree, original_index, original);
                    if ((direct_enabled and original.log_size + 1 == el and device != null and device.?.count == (n / 2)) or
                        (direct_el2 and el >= 3 and original.log_size + 2 == el and device != null and device.?.count == (n / 4)))
                    {
                        slot.* = device;
                        direct_columns += 1;
                        continue;
                    }
                    staging_words += @as(usize, 1) << @intCast(original.log_size);
                } else staging_words += @as(usize, 1) << @intCast(rl);
            }
            const eval_base = staging_words;
            const tw_base = try std.math.add(usize, eval_base, try std.math.mul(usize, column_count, n));
            const desc_base = std.mem.alignForward(usize, tw_base + tw.twiddles.len, 2);
            const arena_words = desc_base + column_count * 6;
            const descriptors = try a.alloc(u32, column_count * 6);
            defer a.free(descriptors);
            for (0..column_count) |i| {
                const degree: u32 = if (i < source_metadata.len) source_metadata[i].log_size else rl;
                const destination = eval_base + i * n;
                descriptors[i * 6 ..][0..6].* = .{ @truncate(staging_offsets[i]), @truncate(@as(u64, staging_offsets[i]) >> 32), @truncate(destination), @truncate(@as(u64, destination) >> 32), degree, 0 };
            }
            std.debug.print("GPU_COMPOSITION_ARENA ordinal={} role={} arena_words={} legacy_arena_words={} direct_columns={} columns={} eval_log={}\n", .{ self.scope.ordinal, id, arena_words, geometry.arena_words, direct_columns, column_count, el });
            // M5 platform: under device pressure, release unborrowed immutable
            // setup (other nodes' PP/schedules kept by a resident service) and
            // retry once before failing. Scheduling only: misses re-upload.
            var arena = context.allocate(arena_words, 0) catch |err| blk: {
                if (err != error.CudaAllocationFailed) return err;
                const cache = b.service.immutable_setup orelse return err;
                const freed = try cache.trimUnborrowed();
                std.debug.print("GPU_COMPOSITION_IMMUTABLE_TRIM ordinal={} role={} arena_words={} released_bytes={}\n", .{ self.scope.ordinal, id, arena_words, freed });
                if (freed == 0) return err;
                break :blk try context.allocate(arena_words, 0);
            };
            defer {
                context.release(&arena) catch |err| {
                    self.cleanupFailure(err);
                };
            }
            const arena_ptr = arena.words.?;
            var coefficient_offset: usize = 0;
            var copy_run: ?CopyRun = null;
            try timing.mark(.coefficients, false, stream0.?);
            for (source_metadata, 0..) |original, i| {
                if (direct[i] != null) continue;
                coefficient_offset = staging_offsets[i];
                const values = original.coefficients;
                const length: usize = if (original.device) |device| @intCast(device.count) else values.len;
                const target = arena_ptr + coefficient_offset;
                const source_tree: u32 = if (i < widths[0]) 0 else if (i < widths[0] + widths[1]) 1 else 2;
                const original_index = switch (source_tree) {
                    0 => if (role.fixed_indices) |indices| indices[i] else offsets[0] + i,
                    1 => offsets[1] + i - widths[0],
                    else => offsets[2] + i - widths[0] - widths[1],
                };
                const immutable = if (source_tree == 0 and original.device == null) immutable_fixed[original_index].device else null;
                if (if (original.device != null) original.device else immutable orelse b.service.retainedColumn(context.scope, source_tree, original_index, original)) |device| {
                    const next_run = try CopyRun.init(@intFromPtr(device.words), coefficient_offset, length, device.context_token, device.generation);
                    if (copy_run) |*pending| {
                        if (!try pending.append(next_run)) {
                            try self.copyRun(raw, &context, arena_ptr, pending.*);
                            device_copy_calls += 1;
                            copy_run = next_run;
                        }
                    } else copy_run = next_run;
                    device_cells += length;
                } else {
                    if (copy_run) |pending| {
                        try self.copyRun(raw, &context, arena_ptr, pending);
                        device_copy_calls += 1;
                        copy_run = null;
                    }
                    try self.checked("session_api.upload", b.session_api.upload(raw, @ptrCast(target), values.ptr, values.len * 4));
                    host_cells += values.len;
                }
                coefficient_offset += length;
            }
            if (copy_run) |pending| {
                try self.copyRun(raw, &context, arena_ptr, pending);
                device_copy_calls += 1;
            }
            coefficient_offset = if (source_metadata.len < column_count) staging_offsets[source_metadata.len] else staging_words;
            try timing.mark(.coefficients, true, stream0.?);
            if (aux != 0) {
                var role_tw_borrow = try b.tw(rl);
                defer role_tw_borrow.deinit(b.allocator);
                const role_tw = &role_tw_borrow.value;
                const it = try upload(a, &context, &leases, words(role_tw.itwiddles));

                var stream: ?*anyopaque = null;
                try self.checked("session_api.lane_stream", b.session_api.lane_stream(raw, compute_lane, &stream));
                var launches: u32 = 0;
                try timing.mark(.auxiliary, false, stream.?);
                switch (role.auxiliary) {
                    .hc => |hc| {
                        const h = try upload(a, &context, &leases, hc[0 .. 16 * rl]);

                        try self.checked("auxiliary", b.auxiliary(raw, compute_lane, h.words.?, arena_ptr + coefficient_offset, rl, &launches));
                    },
                    .last => {
                        const size = @as(usize, 1) << @intCast(rl);
                        try self.checked("last_anchor_clear", b.clear(raw, @ptrCast(arena_ptr + coefficient_offset), 0, size * 4));
                        // Native truth last-anchor is logical last, physical row 1.
                        // Legacy lane 1 needs a join; enqueue mode interpolates on lane 0.
                        const one: u32 = 1;
                        try self.checked("last_anchor_set", b.session_api.upload(raw, @ptrCast(arena_ptr + coefficient_offset + 1), &one, 4));
                    },
                    .none => unreachable,
                }
                const rows = @as(usize, 1) << @intCast(rl);
                try self.checked("b2n", b.b2n(arena_ptr + coefficient_offset, rows, arena_ptr + coefficient_offset, rows, rl, @intCast(aux), it.words.?, @intCast(role_tw.itwiddles.len), @intCast(rows / 2), stream.?, &launches));
                try timing.mark(.auxiliary, true, stream.?);
            }
            try self.checked("session_api.upload", b.session_api.upload(raw, @ptrCast(arena_ptr + tw_base), tw.twiddles.ptr, tw.twiddles.len * 4));
            try self.checked("session_api.upload", b.session_api.upload(raw, @ptrCast(arena_ptr + desc_base), descriptors.ptr, descriptors.len * 4));
            const direct_logs = try a.alloc(u32, column_count);
            defer a.free(direct_logs);
            @memset(direct_logs, el - 1);
            for (direct, direct_logs) |slot, *log| {
                if (slot) |device| if (device.count == n / 4) {
                    log.* = el - 2;
                };
            }
            const direct_log_lease = try upload(a, &context, &leases, direct_logs);
            const parameter_words = try felts(a, role.parameters);
            defer a.free(parameter_words);
            const params = try upload(a, &context, &leases, parameter_words);
            if (artifact.program.roots.len > next) return error.NotEnoughCoefficients;
            next -= artifact.program.roots.len;
            const pw = blk: {
                const power_words = try felts(a, powers[next..][0..artifact.program.roots.len]);
                defer a.free(power_words);
                break :blk try upload(a, &context, &leases, power_words);
            };
            const mask_offsets = geometry.masks;
            const masks = try upload(a, &context, &leases, @as([*]const u32, @ptrCast(mask_offsets.ptr))[0 .. mask_offsets.len * 2]);
            const denom = try upload(a, &context, &leases, words(geometry.denominators));
            if (buckets[el] == null) {
                buckets[el] = try allocate(a, &context, &leases, 8 * n, 0);
                try self.checked("clear", b.clear(raw, @ptrCast(buckets[el].?.words.?), 0, 8 * n * 4));
            }

            var stream: ?*anyopaque = null;
            try self.checked("session_api.lane_stream", b.session_api.lane_stream(raw, compute_lane, &stream));
            var launches: u32 = 0;
            try timing.mark(.domain_fft, false, stream.?);
            var column: usize = 0;
            while (column < column_count) {
                var end = column + 1;
                if (direct[column]) |first| {
                    // Merge adjacent columns of one lease (and one degree) into
                    // one compact run.
                    const stride: usize = @intCast(first.count);
                    var merged = try CopyRun.init(@intFromPtr(first.words), column * stride, stride, first.context_token, first.generation);
                    while (end < column_count) : (end += 1) {
                        const following = direct[end] orelse break;
                        if (following.count != first.count) break;
                        if (!try merged.append(try CopyRun.init(@intFromPtr(following.words), end * stride, stride, following.context_token, following.generation))) break;
                    }
                    try self.checked("service.lease_validate_range", b.service.lease_validate_range(b.service.session, @ptrFromInt(merged.source), merged.words, merged.context_token, merged.generation, &context.scope));
                    if (stride == n / 2) {
                        try self.checked("n2b_columns", b.n2b_columns.?(@ptrFromInt(merged.source), n / 2, direct_log_lease.words.? + column, arena_ptr + eval_base + column * n, n, el, @intCast(end - column), arena_ptr + tw_base + tw.twiddles.len - n / 2, @intCast(n / 2), @intCast(n / 2), stream.?, &launches));
                    } else {
                        try self.checked("n2b_columns_compact", b.n2b_columns_compact.?(@ptrFromInt(merged.source), stride, direct_log_lease.words.? + column, arena_ptr + eval_base + column * n, n, el, @intCast(end - column), arena_ptr + tw_base + tw.twiddles.len - n / 2, @intCast(n / 2), @intCast(n / 2), stride, stream.?, &launches));
                    }
                } else {
                    while (end < column_count and direct[end] == null) : (end += 1) {}
                    try self.checked("n2b", b.n2b(arena_ptr, arena.count, arena_ptr + desc_base + 6 * column, @intCast(end - column), eval_base + column * n, el, arena_ptr + tw_base, @intCast(tw.twiddles.len), @intCast(n / 2), stream.?, 1, &launches));
                }
                column = end;
            }
            try timing.mark(.domain_fft, true, stream.?);
            const packet = Abi.CompositionRole{ .role = id, .trace_log = rl, .eval_log = el, .first_row = 0, .row_count = @intCast(n), .trees = .{ arena_ptr + eval_base, arena_ptr + eval_base + widths[0] * n, arena_ptr + eval_base + (widths[0] + widths[1]) * n }, .tree_words = .{ @max(@as(usize, 1), widths[0] * n), @max(@as(usize, 1), widths[1] * n), @max(@as(usize, 1), widths[2] * n) }, .column_offsets = @ptrCast(@alignCast(masks.words.?)), .mask_count = mask_offsets.len, .parameters = params.words.?, .parameter_count = role.parameters.len, .powers = pw.words.?, .constraint_count = artifact.program.roots.len, .denominator_inverses = denom.words.?, .output = buckets[el].?.words.? };
            try timing.mark(.rows, false, stream.?);
            try self.checked("role", role.evaluate(raw, compute_lane, &packet, &launches));
            try timing.mark(.rows, true, stream.?);

            domain_cells += column_count * n;
        }
        if (next != 0) return error.UnusedCompositionCoefficients;
        const n = @as(usize, 1) << @intCast(self.log);
        const coeff_count = 8 * n;
        const chunk_log = self.log - self.split;
        const count = @as(usize, 8) << @intCast(self.split);
        const beta = self.log_blowup orelse b.log_blowup;
        if (beta < 1 or beta > 4) return error.UnsupportedResidentCompositionBlowup;
        const commit_log = chunk_log + beta;
        const commit_rows = @as(usize, 1) << @intCast(commit_log);
        const eval_words = count * commit_rows;
        if (commit_log > 28) return error.UnsupportedResidentCompositionBlowup;
        var commit_tw_borrow = try b.tw(commit_log);
        defer commit_tw_borrow.deinit(b.allocator);
        const tw = &commit_tw_borrow.value;
        var composition_tw_borrow = try b.tw(self.log);
        defer composition_tw_borrow.deinit(b.allocator);
        const composition_tw = &composition_tw_borrow.value;
        // PCS retains compact coefficients only. Commitment LDE/twiddles are
        // scratch and retire with this joined job, rather than sharing the
        // retained coefficient lease for the entire opening phase.
        const separate = (beta == 1 and b.n2b_columns != null) or (beta == 2 and b.n2b_columns_compact != null);
        const eval_base: usize = if (separate) 0 else coeff_count;
        const output_tw = eval_base + eval_words;
        const output_desc = std.mem.alignForward(usize, output_tw + tw.twiddles.len, 2);
        const scratch_words = output_desc + if (separate) count else count * 6;
        var output = try context.allocate(if (separate) coeff_count else scratch_words, 2);
        errdefer context.release(&output) catch |err| {
            self.cleanupFailure(err);
        };
        const scratch = if (separate) try allocate(a, &context, &leases, scratch_words, 0) else output;
        const accumulator = try allocate(a, &context, &leases, coeff_count, 0);
        const inv = try upload(a, &context, &leases, words(composition_tw.itwiddles));
        var list: std.ArrayList(Abi.CompositionBucket) = .empty;
        defer list.deinit(a);
        for (buckets, 0..) |bucket, log| if (bucket) |value| try list.append(a, .{ .words = value.words.?, .log = @intCast(log) });

        var launches: u32 = 0;
        try events.mark(.finalize, false, stream1.?);
        try self.checked("finish", b.finish(raw, compute_lane, list.items.ptr, @intCast(list.items.len), accumulator.words.?, output.words.?, self.log, self.split, inv.words.?, @intCast(composition_tw.itwiddles.len), &launches));
        try events.mark(.finalize, true, stream1.?);
        var descriptors: std.ArrayList(u32) = .empty;
        defer descriptors.deinit(a);
        for (0..count) |i| {
            if (separate) {
                try descriptors.append(a, chunk_log);
            } else {
                const src = i * (@as(usize, 1) << @intCast(chunk_log));
                const dst = eval_base + i * commit_rows;
                try descriptors.appendSlice(a, &.{ @truncate(src), @truncate(@as(u64, src) >> 32), @truncate(dst), @truncate(@as(u64, dst) >> 32), chunk_log, 0 });
            }
        }
        try self.checked("session_api.upload", b.session_api.upload(raw, @ptrCast(scratch.words.? + output_tw), tw.twiddles.ptr, tw.twiddles.len * 4));
        try self.checked("session_api.upload", b.session_api.upload(raw, @ptrCast(scratch.words.? + output_desc), descriptors.items.ptr, descriptors.items.len * 4));

        var stream: ?*anyopaque = null;
        try self.checked("session_api.lane_stream", b.session_api.lane_stream(raw, compute_lane, &stream));
        try events.mark(.commit_fft, false, stream.?);
        if (separate) {
            if (beta == 2) {
                const source_words = @as(usize, 1) << @intCast(chunk_log);
                try self.checked("n2b_columns_compact", b.n2b_columns_compact.?(output.words.?, source_words, scratch.words.? + output_desc, scratch.words.?, commit_rows, commit_log, @intCast(count), scratch.words.? + output_tw, @intCast(tw.twiddles.len), @intCast(commit_rows / 2), source_words, stream.?, &launches));
            } else try self.checked("n2b_columns", b.n2b_columns.?(output.words.?, @as(usize, 1) << @intCast(chunk_log), scratch.words.? + output_desc, scratch.words.?, commit_rows, commit_log, @intCast(count), scratch.words.? + output_tw, @intCast(tw.twiddles.len), @intCast(commit_rows / 2), stream.?, &launches));
        } else try self.checked("n2b", b.n2b(output.words.?, output.count, output.words.? + output_desc, @intCast(count), eval_base, commit_log, output.words.? + output_tw, @intCast(tw.twiddles.len), @intCast(commit_rows / 2), stream.?, 1, &launches));
        try events.mark(.commit_fft, true, stream.?);
        const tree_words = (2 * commit_rows - 1) * 8;
        const tree = try allocate(a, &context, &leases, tree_words, 0);
        const segment = Abi.MixedSegment{ .columns = scratch.words.? + eval_base, .stride_words = commit_rows, .capacity_words = eval_words, .source_size = @intCast(commit_rows), .reserved = 0 };
        try events.mark(.commit_hash, false, stream1.?);
        try self.checked("tree", b.tree(raw, compute_lane, @ptrCast(&segment), 1, commit_log, tree.words.?, tree_words));
        try events.mark(.commit_hash, true, stream1.?);

        var root_words: [8]u32 = undefined;
        try self.checked("session_api.download", b.session_api.download(raw, &root_words, @ptrCast(tree.words.? + tree_words - 8), 32));
        try context.join();
        for (role_events, self.roles) |*timing, role| {
            spans[@intFromEnum(Span.coefficients)] += try timing.milliseconds(.coefficients);
            spans[@intFromEnum(Span.domain_fft)] += try timing.milliseconds(.domain_fft);
            spans[@intFromEnum(Span.rows)] += try timing.milliseconds(.rows);
            if (role.auxiliary != .none) spans[@intFromEnum(Span.auxiliary)] += try timing.milliseconds(.auxiliary);
        }
        spans[@intFromEnum(Span.finalize)] = try events.milliseconds(.finalize);
        spans[@intFromEnum(Span.commit_fft)] = try events.milliseconds(.commit_fft);
        spans[@intFromEnum(Span.commit_hash)] = try events.milliseconds(.commit_hash);
        var root: [32]u8 = undefined;
        for (root_words, 0..) |v, i| std.mem.writeInt(u32, root[i * 4 ..][0..4], v, .little);
        const columns = try b.allocator.alloc(D.Column, count);
        errdefer b.allocator.free(columns);
        for (columns, 0..) |*column, i| column.* = .{ .log_size = chunk_log, .device = .{ .words = output.words.? + i * (@as(usize, 1) << @intCast(chunk_log)), .count = @as(u64, 1) << @intCast(chunk_log), .context_token = output.context_token, .generation = output.generation } };
        try b.service.retainDeviceLease(context.scope, output);
        std.debug.print("GPU_COMPOSITION_OWNERSHIP ordinal={} retained_coefficient_words={} joined_commit_scratch_words={} separate_coefficients={} log_blowup={}\n", .{ self.scope.ordinal, output.count, if (separate) scratch.count else 0, separate, beta });
        self.result = .{ .root = root, .columns = columns };
        var kernel_ms: f64 = 0;
        for (spans[1..]) |value| kernel_ms += value;
        std.debug.print("GPU_COMPOSITION_TIMING ordinal={} coefficient_stream_ms={d:.3} auxiliary_ms={d:.3} domain_fft_ms={d:.3} rows_ms={d:.3} finalize_ms={d:.3} commit_fft_ms={d:.3} commit_hash_ms={d:.3} gpu_enqueued_kernel_spans_ms={d:.3} host_coefficient_cells={} device_coefficient_cells={} device_copy_calls={} domain_cells={} geometry_hits={} geometry_misses={} retained_setup_bytes={} retained_geometry_bytes={} retained_twiddle_bytes={} retained_artifact_bytes={} setup_cache_cap_bytes={} uncached_geometries={} uncached_twiddles={}\n", .{ self.scope.ordinal, spans[0], spans[1], spans[2], spans[3], spans[4], spans[5], spans[6], kernel_ms, host_cells, device_cells, device_copy_calls, domain_cells, b.geometry_hits, b.geometry_misses, b.retainedBytes(), b.geometry_bytes, b.twiddle_bytes, b.artifact_bytes, b.cache_limit_bytes, b.uncached_geometries, b.uncached_twiddles });
    }
};
fn allocate(a: std.mem.Allocator, c: *SC.Context, list: *std.ArrayList(Native.Lease), n: usize, kind: u32) !Native.Lease {
    var lease = try c.allocate(n, kind);
    errdefer c.release(&lease) catch {};
    try list.append(a, lease);
    return lease;
}
fn upload(a: std.mem.Allocator, c: *SC.Context, list: *std.ArrayList(Native.Lease), data: []const u32) !Native.Lease {
    const lease = try allocate(a, c, list, @max(@as(usize, 1), data.len), 0);
    if (data.len != 0) try check(c.api.upload(c.native_context, @ptrCast(lease.words.?), data.ptr, data.len * 4));
    return lease;
}

pub fn check(status: c_int) !void {
    if (status != 0) return error.CudaResidentCompositionFailed;
}

pub fn words(values: []const M) []const u32 {
    return @as([*]const u32, @ptrCast(values.ptr))[0..values.len];
}

pub fn felts(a: std.mem.Allocator, values: []const O) ![]u32 {
    const out = try a.alloc(u32, values.len * 8);
    for (values, 0..) |v, i| for (v.toM31Array(), 0..) |w, j| {
        out[i * 8 + j] = w.v;
    };
    return out;
}

pub fn sourceColumn(source: engine.air.component_prover.ForField(O).Poly) !D.Column {
    try source.validate();
    if (source.device) |device| {
        if (device.count == 0 or !std.math.isPowerOfTwo(device.count) or device.count > (@as(u64, 1) << 28)) return error.InvalidResidentSource;
        return .{ .log_size = std.math.log2_int(u64, device.count), .device = device };
    }
    const p = source.coefficients orelse return error.DevicePcsCoefficientsRequired;
    return .{ .log_size = p.logSize(), .coefficients = p.coefficients() };
}
