//! Independent fixed verifier join for the complete finite v7 source roster.
//! Builds every family from original policy/claims; no captures or MAIN rows.
const std = @import("std");
const core = @import("stwo_core");
const Pool = @import("stwo_prover_engine").work_pool;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Bus = @import("block_v7_mixed_public_v1.zig");
const Inputs = @import("block_v7_mixed_inputs_v1.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Namespace = @import("air/block_v5_recursive_fixed_namespace_v1.zig");
const Rebase = @import("air/blake3_parent_rebase.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Capsule = @import("block_v7_caller_joint_compiler_capsule_v1.zig").Capsule;
const Resources = @import("block_v7_family_resource_limits_v1.zig");
pub const Limits = struct {
    /// Maximum simultaneous independent original-family compiler pieces.
    /// The same request budget covers the whole cohort and accumulated rows.
    /// One preserves the original serial path; unavailable nested leases fall
    /// back serially instead of oversubscribing or waiting for worker capacity.
    parallel_families: usize = 1,
    family_max_bytes: ?usize = null,
    max_bytes: usize = 8 << 30,
    max_row_log: u32 = 25,
    /// Indexed by whole-job caller ordinal; null entries compile normally.
    native_compilers: ?[]const ?*const @import("block_v7_native_compiler_capsule_v1.zig").Capsule = null,
    caller_compilers: ?[]const ?*const Capsule = null,
    active_caller_compilers: ?[]const ?*const @import("block_v7_caller_family_v1.zig").Active.Capsule.Capsule = null,
};
const Lists = blk: {
    var entries: [Storage.Airs.len]type = undefined;
    for (Storage.Airs, &entries) |Air, *T| T.* = std.ArrayList(Storage.FixedRow(Air));
    break :blk std.meta.Tuple(&entries);
};
const Builder = struct {
    a: std.mem.Allocator,
    rows: Lists,
    wires: std.ArrayList(Bus.Wire) = .empty,
    contexts: [5]core.channel.blake3.Channel = @splat(.{}),
    next_namespace: u32 = 1,
    max_row_log: u32,
    fn init(a: std.mem.Allocator, expected: []const Bus.Expected, max_row_log: u32) !@This() {
        var result: @This() = .{ .a = a, .rows = undefined, .max_row_log = max_row_log };
        inline for (0..Storage.Airs.len) |i| result.rows[i] = .empty;
        for (&result.contexts, 0..) |*channel, i| channel.mixU32s(&.{ 0x42374d47, Bus.VERSION, @intCast(i), @intCast(expected.len) });
        result.contexts[0].mixRoot(try Bus.rosterDigest(expected));
        return result;
    }
    fn deinit(self: *@This()) void {
        inline for (0..Storage.Airs.len) |i| self.rows[i].deinit(self.a);
        self.wires.deinit(self.a);
    }
    fn append(self: *@This(), comptime kind: Bus.Kind, piece: anytype, ordinal: usize) !void {
        const ids = try self.a.dupe(u32, piece.namespace.original.old);
        var outer = Rebase.Plan{ .allocator = self.a, .first = self.next_namespace, .old = ids };
        defer outer.deinit();
        const identity = try outer.identity();
        self.next_namespace = try outer.end();
        for (piece.wires) |wire| {
            try self.wires.append(self.a, .{ .circuit = outer.map(wire.circuit) orelse return error.MissingMixedDirectNamespace, .wire = wire.wire, .uses = wire.uses, .child = @intCast(ordinal), .source = @unionInit(Bus.Source, @tagName(kind), wire.source), .coordinate = wire.coordinate });
        }
        const plan = Namespace.Plan{ .original = outer, .main_identifier_rows = 0, .lease = null };
        try Namespace.apply(&piece.fixed, &plan, identity);
        inline for (0..Storage.Airs.len) |i| {
            const count = try std.math.add(usize, self.rows[i].items.len, piece.fixed[i].len);
            if (count > @as(usize, 1) << @intCast(self.max_row_log)) {
                if (std.process.hasEnvVarConstant("STWO_V7_PROFILE_ERRORS"))
                    std.debug.print("V7_MIXED_RESOURCE phase=cold_rows family={s} child={d} air={s} rows={d} max_row_log={d}\n", .{ @tagName(kind), ordinal, @typeName(Storage.Airs[i]), count, self.max_row_log });
                return error.MixedDirectResourceLimit;
            }
            try self.rows[i].appendSlice(self.a, piece.fixed[i]);
        }
        self.contexts[0].mixRoot(piece.context.child_key_id);
        for (self.contexts[1..4], piece.context.graph_ids) |*channel, digest| {
            channel.mixRoot(digest);
            channel.mixRoot(identity);
        }
        self.contexts[4].mixRoot(piece.context.transcript_plan_id);
        self.contexts[4].mixRoot(identity);
    }
};
fn FamilyFactory(comptime kind: Bus.Kind) type {
    return switch (kind) {
        .native => @import("block_v7_native_fixed_roster_v1.zig"),
        .caller_active => @import("block_v7_caller_family_v1.zig").Active.FixedRoster,
        .caller => @import("block_v7_caller_joint_fixed_roster_v1.zig"),
        .program => @import("block_v7_program_fixed_roster_v1.zig"),
        .lookup => @import("block_v7_lookup_compact_fixed_roster_v1.zig"),
        .memory => @import("block_v7_memory_joint_fixed_roster_v1.zig"),
        .window_memory => @import("block_v7_window_memory_family_v1.zig").FixedRoster,
        .ram, .interval, .range16, .terminal => @import("block_v7_memory_component_recursive_v1.zig").For(@field(@import("air/block_v7_memory_composition_v1.zig").Family, @tagName(kind))).FixedRoster,
    };
}
const Piece = union(Bus.Kind) {
    native: FamilyFactory(.native).Owned,
    caller_active: FamilyFactory(.caller_active).Owned,
    caller: FamilyFactory(.caller).Owned,
    program: FamilyFactory(.program).Owned,
    lookup: FamilyFactory(.lookup).Owned,
    ram: FamilyFactory(.ram).Owned,
    interval: FamilyFactory(.interval).Owned,
    range16: FamilyFactory(.range16).Owned,
    terminal: FamilyFactory(.terminal).Owned,
    memory: FamilyFactory(.memory).Owned,
    window_memory: FamilyFactory(.window_memory).Owned,
    fn deinit(self: *Piece) void {
        switch (self.*) {
            inline else => |*value| value.deinit(),
        }
        self.* = undefined;
    }
    fn append(self: *Piece, builder: *Builder, ordinal: usize) !void {
        switch (self.*) {
            inline else => |*value, kind| try builder.append(kind, value, ordinal),
        }
    }
};
fn compileOne(a: std.mem.Allocator, input: Inputs.Input, pin: Bus.Expected, capacity: u32, limits: Limits) !Piece {
    switch (pin.kind) {
        .native => {
            const native = input.natives[pin.index];
            const Module = @import("block_v7_native_fixed_roster_v1.zig");
            const capsule = if (limits.native_compilers) |capsules| capsules[pin.index] else null;
            if (capsule) |compiled| try compiled.requireProfile(native.profile);
            const child_limits = try Resources.forSetup(Module.Limits, limits.max_bytes, limits.family_max_bytes);
            const piece = if (capsule) |compiled| try Module.Owned.deriveFromCapsule(a, compiled, native.claims, capacity, child_limits) else try Module.Owned.derive(a, native.profile, native.claims, capacity, child_limits);
            return @unionInit(Piece, "native", piece);
        },
        .caller_active => {
            const FactoryModule = @import("block_v7_caller_family_v1.zig").Active.FixedRoster;
            const Factory = FactoryModule.Owned;
            const child_limits = try Resources.forSetup(FactoryModule.Limits, limits.max_bytes, limits.family_max_bytes);
            const capsule = if (limits.active_caller_compilers) |capsules| capsules[pin.index] else null;
            if (capsule) |compiled| try compiled.requireProfile(a, input.active_callers[pin.index]);
            const piece = if (capsule) |compiled| try Factory.deriveFromCapsule(a, compiled, capacity, child_limits) else try Factory.derive(a, input.active_callers[pin.index].input(), capacity, child_limits);
            return @unionInit(Piece, "caller_active", piece);
        },
        .caller => {
            const FactoryModule = @import("block_v7_caller_joint_fixed_roster_v1.zig");
            const Factory = FactoryModule.Owned;
            const child_limits = try Resources.forSetup(FactoryModule.Limits, limits.max_bytes, limits.family_max_bytes);
            const capsule = if (limits.caller_compilers) |capsules| capsules[pin.index] else null;
            if (capsule) |compiled| try compiled.requireProfile(a, input.callers[pin.index]);
            const piece = if (capsule) |compiled| try Factory.deriveFromCapsule(a, compiled, capacity, child_limits) else try Factory.derive(a, input.callers[pin.index].input(), capacity, child_limits);
            return @unionInit(Piece, "caller", piece);
        },
        inline .ram, .interval, .range16, .terminal => |kind| {
            const family: @import("air/block_v7_memory_composition_v1.zig").Family = @field(@import("air/block_v7_memory_composition_v1.zig").Family, @tagName(kind));
            const Module = @import("block_v7_memory_component_recursive_v1.zig").For(family);
            const separate = input.separate_memory orelse return error.InvalidV7CompleteMixedRoster;
            const profile = if (kind == .ram) separate.ram[pin.index] else @field(separate, @tagName(kind));
            const piece = try Module.FixedRoster.Owned.derive(a, profile.input, capacity, try Resources.forSetup(Module.FixedRoster.Limits, limits.max_bytes, limits.family_max_bytes));
            return @unionInit(Piece, @tagName(kind), piece);
        },
        inline .program, .lookup, .memory, .window_memory => |kind| {
            const Module = switch (kind) {
                .program => @import("block_v7_program_fixed_roster_v1.zig"),
                .lookup => @import("block_v7_lookup_compact_fixed_roster_v1.zig"),
                .memory => @import("block_v7_memory_joint_fixed_roster_v1.zig"),
                .window_memory => @import("block_v7_window_memory_family_v1.zig").FixedRoster,
                else => unreachable,
            };
            const profile = if (kind == .memory or kind == .window_memory) @field(input, @tagName(kind)) orelse return error.InvalidV7CompleteMixedRoster else @field(input, @tagName(kind));
            const piece = try Module.Owned.derive(a, profile.input, capacity, try Resources.forSetup(Module.Limits, limits.max_bytes, limits.family_max_bytes));
            return @unionInit(Piece, @tagName(kind), piece);
        },
    }
}
const CompileJob = struct {
    a: std.mem.Allocator,
    input: Inputs.Input,
    pin: Bus.Expected,
    capacity: u32,
    limits: Limits,
    piece: ?Piece = null,
    failure: ?anyerror = null,
    fn run(self: *CompileJob) void {
        self.piece = compileOne(self.a, self.input, self.pin, self.capacity, self.limits) catch |failure| {
            self.failure = failure;
            return;
        };
    }
    fn deinit(self: *CompileJob) void {
        if (self.piece) |*piece| piece.deinit();
        self.piece = null;
    }
};

pub const Owned = struct {
    allocator: std.mem.Allocator,
    budget: *Budget,
    fixed: Storage.FixedTuple(false),
    wires: []Bus.Wire,
    expected: []Bus.Expected,
    context: Base.Context,
    pub const fixed_setup_only = true;
    pub const complete_family_setup = true;
    pub const whole_family_live_parity_qualified = false;
    pub const complete_block_authority = false;
    /// Canonical direct root emits one original verifier piece per roster child.
    /// Public reconstruction checks the entire source/claim/order binding before
    /// any key rows are derived; the eventual proof still enforces every claim.
    pub fn derive(backing: std.mem.Allocator, input: Inputs.Input, capacity: u32, limits: Limits) !Owned {
        const total = try input.count();
        return deriveWindow(backing, input, 0, total, Bus.MAX_CHILDREN, capacity, limits);
    }
    /// Independently compile one OPEN contiguous batch from a fully admitted
    /// job. The explicit whole limit does not enlarge the direct proof fan-in.
    pub fn deriveWindow(backing: std.mem.Allocator, input: Inputs.Input, first: usize, count: usize, max_entries: usize, capacity: u32, limits: Limits) !Owned {
        if (limits.parallel_families == 0 or limits.parallel_families > Pool.MAX_WORKERS or limits.max_bytes == 0 or limits.max_row_log == 0 or limits.max_row_log > 30 or capacity == 0) return error.InvalidMixedDirectLimits;
        if (limits.native_compilers) |capsules| if (capsules.len != input.natives.len) return error.NativeCompilerCountMismatch;
        if (limits.caller_compilers) |capsules| if (capsules.len != input.callers.len) return error.CallerCompilerCountMismatch;
        if (limits.active_caller_compilers) |capsules| if (capsules.len != input.active_callers.len) return error.CallerCompilerCountMismatch;
        const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        var public = try Inputs.Owned.initWhole(a, input, max_entries);
        defer public.deinit();
        _ = try public.window(first, count);
        const selected = public.expected[first..][0..count];
        var builder = try Builder.init(a, selected, limits.max_row_log);
        defer builder.deinit();
        var active_kind: ?Bus.Kind = null;
        var active_index: u32 = 0;
        errdefer if (std.process.hasEnvVarConstant("STWO_V7_WINDOW_PROFILE")) {
            const usage = budget.snapshot();
            std.debug.print("V7_WINDOW_COLD_FAILURE first={d} count={d} kind={s} index={d} budget_limit={d} peak={d} live={d} exceeded={}\n", .{ first, count, if (active_kind) |kind| @tagName(kind) else "metadata", active_index, usage.limit, usage.peak_live_bytes, usage.live_bytes, usage.exceeded });
        };
        var lease: ?Pool.WorkLease = null;
        if (limits.parallel_families > 1 and selected.len > 1) if (Pool.currentScopedPool()) |pool| {
            const workers = @min(@min(limits.parallel_families, selected.len), pool.workerCount());
            if (workers > 1) lease = pool.acquire(try Pool.WorkerBudget.init(workers)) catch |err| switch (err) {
                error.WorkerBudgetUnavailable => null,
                else => return err,
            };
        };
        defer if (lease) |*held| held.deinit();
        const width = if (lease) |*held| held.workerCount() else 1;
        // Job metadata is request-charged and bounded by one worker cohort.
        const jobs = try a.alloc(CompileJob, width);
        defer a.free(jobs);
        var begin: usize = 0;
        while (begin < selected.len) {
            const end = @min(selected.len, begin + width);
            const cohort = jobs[0 .. end - begin];
            var initialized: usize = 0;
            // This runs after the inner join on submission, compiler, budget,
            // namespace, or row-limit failure. No worker retains a borrowed
            // capsule/input or a child budget after the enclosing return.
            defer for (cohort[0..initialized]) |*job| job.deinit();
            var wait = std.Thread.WaitGroup{};
            {
                defer {
                    wait.wait();
                    if (lease) |*held| held.completeWave();
                }
                for (cohort, selected[begin..end], 0..) |*job, pin, index| {
                    job.* = .{ .a = a, .input = input, .pin = pin, .capacity = capacity, .limits = limits };
                    initialized += 1;
                    if (index + 1 < cohort.len) try lease.?.spawnWg(&wait, CompileJob.run, .{job}) else job.run();
                }
            }
            // A failed cohort is never appended, even if earlier jobs finished.
            // Preserve canonical first-error selection after every worker joins.
            for (cohort) |job| if (job.failure) |failure| {
                active_kind = job.pin.kind;
                active_index = job.pin.index;
                return failure;
            };
            for (cohort, 0..) |*job, index| {
                active_kind = job.pin.kind;
                active_index = job.pin.index;
                // Namespace allocation and transcript/wire concatenation stay
                // exactly in the independently admitted canonical roster order.
                try job.piece.?.append(&builder, begin + index);
                job.deinit();
            }
            begin = end;
        }
        var fixed: Storage.FixedTuple(false) = undefined;
        inline for (0..Storage.Airs.len) |i| fixed[i] = &.{};
        errdefer inline for (0..Storage.Airs.len) |i| a.free(fixed[i]);
        inline for (0..Storage.Airs.len) |i| fixed[i] = try builder.rows[i].toOwnedSlice(a);
        try @import("block_v6_mixed_direct_fixed_v1.zig").partitionFixed(a, &fixed);
        std.mem.sort(Bus.Wire, builder.wires.items, {}, struct {
            fn less(_: void, l: Bus.Wire, r: Bus.Wire) bool {
                return l.circuit < r.circuit or (l.circuit == r.circuit and l.wire < r.wire);
            }
        }.less);
        _ = try Bus.scheduleDigest(builder.wires.items);
        const wires = try builder.wires.toOwnedSlice(a);
        errdefer a.free(wires);
        const pins = try a.dupe(Bus.Expected, selected);
        return .{ .allocator = a, .budget = budget, .fixed = fixed, .wires = wires, .expected = pins, .context = .{ .child_key_id = builder.contexts[0].digestBytes(), .child_config = input.epoch.config, .graph_ids = .{ builder.contexts[1].digestBytes(), builder.contexts[2].digestBytes(), builder.contexts[3].digestBytes() }, .transcript_plan_id = builder.contexts[4].digestBytes() } };
    }
    pub fn validateLive(self: *const Owned, live: *@import("block_v7_mixed_preparation_v1.zig").Prepared) !void {
        try live.recursive.rows.partitionHashRows();
        if (!std.meta.eql(self.context, live.recursive.context)) return error.MixedFixedContextMismatch;
        if (self.wires.len != live.wires.len) return error.MixedFixedWireCountMismatch;
        if (self.expected.len != live.expected.len) return error.MixedFixedRosterCountMismatch;
        for (self.expected, live.expected) |got, want| if (!std.meta.eql(got, want)) return error.MixedFixedRosterMismatch;
        for (self.wires, live.wires) |got, want| if (!std.meta.eql(got, want)) return error.MixedFixedWireMismatch;
        inline for (0..Storage.Airs.len) |i| {
            if (self.fixed[i].len != live.recursive.rows.fixed[i].len) {
                std.log.warn("v7 mixed fixed component {d}: cold rows {d}, live rows {d}", .{ i, self.fixed[i].len, live.recursive.rows.fixed[i].len });
                return error.MixedFixedRowCountMismatch;
            }
            for (self.fixed[i], live.recursive.rows.fixed[i], 0..) |got, want, row| if (!std.meta.eql(got, want)) {
                std.log.warn("v7 mixed fixed component {d}: row {d} differs", .{ i, row });
                return error.MixedFixedRowMismatch;
            };
        }
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        const budget = self.budget;
        inline for (0..Storage.Airs.len) |i| a.free(self.fixed[i]);
        a.free(self.wires);
        a.free(self.expected);
        self.* = undefined;
        budget.destroy();
    }
};
