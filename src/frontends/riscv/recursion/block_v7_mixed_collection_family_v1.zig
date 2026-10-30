//! Collect only a bounded window of genuine original verifiers, then drain
//! them into one OPEN direct batch. Original proofs remain caller-owned;
//! captures and family owners are released before returning the batch rows.
//! Shared-prefix collection accepts the complete roster only. Baseline window
//! collection remains OPEN and is the API used by the bounded batch producer.
pub fn For(comptime shared: bool) type {
    return struct {
        const std = @import("std");
        const Pool = @import("stwo_prover_engine").work_pool;
        const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
        const Cpu = @import("stwo_cpu_backend").CpuBackend;
        const Original = @import("../prover/block_v7_execution_receiver_v1.zig");
        const Inputs = @import("block_v7_mixed_inputs_v1.zig");
        const Bus = @import("block_v7_mixed_public_v1.zig");
        const Mixed = if (shared) @import("block_v7_shared_epoch_mixed_preparation_v1.zig") else @import("block_v7_mixed_preparation_v1.zig");
        const Piece = union(Bus.Kind) {
            native: Mixed.PreparedFor(.native),
            caller_active: Mixed.PreparedFor(.caller_active),
            caller: Mixed.PreparedFor(.caller),
            program: Mixed.PreparedFor(.program),
            lookup: Mixed.PreparedFor(.lookup),
            ram: Mixed.PreparedFor(.ram),
            interval: Mixed.PreparedFor(.interval),
            range16: Mixed.PreparedFor(.range16),
            terminal: Mixed.PreparedFor(.terminal),
            memory: Mixed.PreparedFor(.memory),
            window_memory: Mixed.PreparedFor(.window_memory),
            fn deinit(self: *Piece) void {
                switch (self.*) {
                    inline else => |*p| p.deinit(),
                }
            }
            fn view(self: *Piece, index: u32) Mixed.Input {
                return switch (self.*) {
                    inline else => |*p, kind| @unionInit(Mixed.Input, @tagName(kind), .{ .index = index, .prepared = p }),
                };
            }
        };
        const Capsule = @import("block_v7_caller_joint_compiler_capsule_v1.zig").Capsule;
        pub const FamilyStats = struct { jobs: usize = 0, total_ns: u64 = 0, maximum_ns: u64 = 0 };
        pub const Stats = struct {
            /// Inclusive capture plus witness preparation, excluding canonical
            /// join. Parallel per-job times must not be summed as wall time.
            families: [@typeInfo(Bus.Kind).@"enum".fields.len]FamilyStats = @splat(.{}),
        };
        pub const Limits = struct {
            stats: ?*Stats = null,
            original_captures: ?*Original.Captures = null,
            /// Independent capture/witness jobs; canonical joining stays serial.
            parallel_preparation: usize = 1,
            family_max_bytes: ?usize = null,
            max_entries: usize = Bus.MAX_CHILDREN,
            capacity: u32 = 2,
            join: Mixed.Limits = .{},
            native_compilers: ?[]const ?*const @import("block_v7_native_compiler_capsule_v1.zig").Capsule = null,
            caller_compilers: ?[]const ?*const Capsule = null,
            active_caller_compilers: ?[]const ?*const @import("block_v7_caller_family_v1.zig").Active.Capsule.Capsule = null,
        };
        fn prepareOne(a: std.mem.Allocator, original: Original.Input, input: Inputs.Input, pin: Bus.Expected, limits: Limits, family_max: usize) !Piece {
            return switch (pin.kind) {
                .native => blk: {
                    const metadata = input.natives[pin.index];
                    var retained: Original.RetainedCapture(.native) = if (limits.original_captures) |captures| try captures.take(.native, pin.index, try metadata.profile.pin.entry(a), original.natives[pin.index].proof) else .{ .capture = try @import("../prover/block_v7_native_proof_v1.zig").For(Cpu).verifyAndCapture(a, original.natives[pin.index].proof, metadata.profile.pin, input.epoch, input.entries) };
                    defer retained.deinit();
                    const capture = &retained.capture;
                    const Prepare = @import("block_v7_native_preparation_v1.zig");
                    const capsule = if (limits.native_compilers) |capsules| capsules[pin.index] else null;
                    if (capsule) |compiled| try compiled.requireProfile(metadata.profile);
                    break :blk .{ .native = if (capsule) |compiled| try Prepare.prepareFromCapsule(a, compiled, capture, limits.capacity, .{ .shared_epoch = shared, .max_bytes = family_max }) else try Prepare.prepare(a, metadata.profile, capture, limits.capacity, .{ .shared_epoch = shared, .max_bytes = family_max }) };
                },
                .caller_active => blk: {
                    const Family = @import("block_v7_caller_family_v1.zig").Active;
                    const metadata = input.active_callers[pin.index];
                    var capture = if (limits.original_captures) |captures| reuse: {
                        var retained = try captures.take(.caller_active, pin.index, try metadata.admitted.pin().entry(a), original.active_callers[pin.index].proof);
                        errdefer retained.deinit();
                        break :reuse try Family.Capture.adoptVerifiedOriginal(retained.capture, retained.budget.?, &metadata.admitted);
                    } else try Family.Capture.ForBackend(Cpu).verify(a, original.active_callers[pin.index].proof, &metadata.admitted);
                    defer capture.deinit();
                    const capsule = if (limits.active_caller_compilers) |capsules| capsules[pin.index] else null;
                    if (capsule) |compiled| try compiled.requireProfile(a, metadata);
                    break :blk .{ .caller_active = if (capsule) |compiled| try Family.Preparation.prepareFromCapsule(a, compiled, &capture, limits.capacity, .{ .shared_epoch = shared, .max_bytes = family_max }) else try Family.Preparation.prepare(a, &metadata.admitted, &capture, limits.capacity, .{ .shared_epoch = shared, .max_bytes = family_max }) };
                },
                .caller => blk: {
                    const metadata = input.callers[pin.index];
                    var capture = if (limits.original_captures) |captures| reuse: {
                        var retained = try captures.take(.caller, pin.index, try metadata.admitted.pin().entry(a), original.callers[pin.index].proof);
                        errdefer retained.deinit();
                        break :reuse try @import("block_v7_caller_family_v1.zig").Full.Capture.adoptVerifiedOriginal(retained.capture, retained.budget.?, &metadata.admitted);
                    } else try @import("../prover/block_v7_caller_joint_capture_v1.zig").ForBackend(Cpu).verify(a, original.callers[pin.index].proof, &metadata.admitted);
                    defer capture.deinit();
                    const Prepare = @import("block_v7_caller_joint_preparation_v1.zig");
                    const capsule = if (limits.caller_compilers) |capsules| capsules[pin.index] else null;
                    if (capsule) |compiled| try compiled.requireProfile(a, metadata);
                    break :blk .{ .caller = if (capsule) |compiled| try Prepare.prepareFromCapsule(a, compiled, &capture, limits.capacity, .{ .shared_epoch = shared, .max_bytes = family_max }) else try Prepare.prepare(a, &metadata.admitted, &capture, limits.capacity, .{ .shared_epoch = shared, .max_bytes = family_max }) };
                },
                .program => blk: {
                    var retained: Original.RetainedCapture(.program) = if (limits.original_captures) |captures| try captures.take(.program, pin.index, try input.program.input.policy.entry(), original.program) else .{ .capture = try @import("../prover/block_v7_program_provider_v1.zig").ForBackend(Cpu).verifyAndCapture(a, original.program, input.program.input.policy) };
                    defer retained.deinit();
                    const capture = &retained.capture;
                    break :blk .{ .program = try @import("block_v7_program_preparation_v1.zig").prepare(a, input.program, capture, limits.capacity, .{ .shared_epoch = shared, .max_bytes = family_max }) };
                },
                .lookup => blk: {
                    var retained: Original.RetainedCapture(.lookup) = if (limits.original_captures) |captures| try captures.take(.lookup, pin.index, try input.lookup.input.policy.entry(), original.lookup.compact.proof) else .{ .capture = try @import("../prover/block_v7_lookup_compact_proof_v1.zig").For(Cpu).verifyAndCapture(a, original.lookup.compact.proof, input.lookup.input.policy, .{}) };
                    defer retained.deinit();
                    const capture = &retained.capture;
                    break :blk .{ .lookup = try @import("block_v7_lookup_compact_preparation_v1.zig").prepare(a, input.lookup, capture, limits.capacity, .{ .shared_epoch = shared, .max_bytes = family_max }) };
                },
                .memory => blk: {
                    const profile = input.memory orelse return error.UntrustedV7CollectionInput;
                    var retained: Original.RetainedCapture(.memory) = if (limits.original_captures) |captures| try captures.take(.memory, pin.index, try @import("../prover/block_v7_memory_joint_protocol_v1.zig").entry(profile.input.policy, &profile.layout, profile.input.roots), original.memory.joint) else .{ .capture = try @import("../prover/block_v7_memory_joint_proof_v1.zig").For(Cpu).verifyAndCapture(a, profile.input.policy, input.epoch, input.entries, original.memory.joint, .{}) };
                    defer retained.deinit();
                    const capture = &retained.capture;
                    break :blk .{ .memory = try @import("block_v7_memory_joint_preparation_v1.zig").prepare(a, profile, capture, limits.capacity, .{ .shared_epoch = shared, .max_bytes = family_max }) };
                },
                .window_memory => blk: {
                    const Family = @import("block_v7_window_memory_family_v1.zig");
                    const profile = input.window_memory orelse return error.UntrustedV7CollectionInput;
                    var retained: Original.RetainedCapture(.window_memory) = if (limits.original_captures) |captures| try captures.take(.window_memory, pin.index, try @import("../prover/block_v7_window_memory_joint_protocol_v1.zig").entry(profile.input.policy, &profile.layout, profile.input.roots), original.memory.window_joint) else .{ .capture = try Family.Capture.For(Cpu).verifyAndCapture(a, profile.input.policy, input.epoch, input.entries, original.memory.window_joint, .{}) };
                    defer retained.deinit();
                    const capture = &retained.capture;
                    break :blk .{ .window_memory = try Family.Preparation.prepare(a, profile, capture, limits.capacity, .{ .shared_epoch = shared, .max_bytes = family_max }) };
                },
                inline .ram, .interval, .range16, .terminal => |kind| blk: {
                    const family: @import("air/block_v7_memory_composition_v1.zig").Family = @field(@import("air/block_v7_memory_composition_v1.zig").Family, @tagName(kind));
                    const Module = @import("block_v7_memory_component_recursive_v1.zig").For(family);
                    const separate = input.separate_memory orelse return error.UntrustedV7CollectionInput;
                    const profile = if (kind == .ram) separate.ram[pin.index] else @field(separate, @tagName(kind));
                    const received = if (kind == .ram) &original.memory.separate.ram[pin.index].proof else &@field(original.memory.separate, @tagName(kind));
                    var capture = try Module.Profile.verifyAndCapture(Cpu, a, profile, received);
                    defer capture.deinit();
                    break :blk @unionInit(Piece, @tagName(kind), try Module.Preparation.prepare(a, profile, &capture, limits.capacity, .{ .shared_epoch = shared, .max_bytes = family_max }));
                },
            };
        }
        const PrepareContext = struct {
            a: std.mem.Allocator,
            original: Original.Input,
            input: Inputs.Input,
            expected: []const Bus.Expected,
            pieces: []?Piece,
            limits: Limits,
            family_max: usize,
            elapsed: []u64,
            fn prepare(self: *@This(), index: usize) !void {
                var timer = try std.time.Timer.start();
                defer self.elapsed[index] = timer.read();
                self.pieces[index] = try prepareOne(self.a, self.original, self.input, self.expected[index], self.limits, self.family_max);
            }
        };
        /// Shape preflight only; actual captures and canonical frames remain
        /// mandatory. Reject missing source proof slots before indexing them.
        pub fn requireMatchingOriginalShape(original: Original.Input, input: Inputs.Input) !void {
            if (original.lookup != .compact or original.natives.len != input.natives.len or original.callers.len != input.callers.len or original.active_callers.len != input.active_callers.len or !std.meta.eql(original.epoch, input.epoch)) return error.UntrustedV7CollectionInput;
            if ((original.memory == .joint) != (input.memory != null) or (original.memory == .window_joint) != (input.window_memory != null) or (original.memory == .separate) != (input.separate_memory != null)) return error.UntrustedV7CollectionInput;
            if (original.memory == .separate and original.memory.separate.ram.len != input.separate_memory.?.ram.len) return error.UntrustedV7CollectionInput;
        }
        pub fn prepareWindow(a: std.mem.Allocator, original: Original.Input, input: Inputs.Input, first: usize, count: usize, limits: Limits) !Mixed.Prepared {
            if (limits.parallel_preparation == 0 or limits.parallel_preparation > Pool.MAX_WORKERS) return error.InvalidParallelPreparation;
            if (shared and (first != 0 or count != try input.count())) return error.InvalidSharedEpochRoster;
            try requireMatchingOriginalShape(original, input);
            if (limits.original_captures) |captures| try captures.requireRequest(original);
            const family_max = (try @import("block_v7_family_resource_limits_v1.zig").clamp(limits.join.max_join_bytes, limits.family_max_bytes)) orelse (4 << 30);
            if (limits.native_compilers) |capsules| if (capsules.len != input.natives.len) return error.NativeCompilerCountMismatch;
            if (limits.caller_compilers) |capsules| if (capsules.len != input.callers.len) return error.CallerCompilerCountMismatch;
            if (limits.active_caller_compilers) |capsules| if (capsules.len != input.active_callers.len) return error.CallerCompilerCountMismatch;
            var canonical = try Inputs.Owned.initWhole(a, input, limits.max_entries);
            defer canonical.deinit();
            _ = try canonical.window(first, count);
            const expected = canonical.expected[first..][0..count];
            var pieces: [Bus.MAX_CHILDREN]?Piece = @splat(null);
            defer for (&pieces) |*piece| if (piece.*) |*p| p.deinit();
            var views: [Bus.MAX_CHILDREN]Mixed.Input = undefined;
            var elapsed: [Bus.MAX_CHILDREN]u64 = @splat(0);
            // A synchronized request allocator protects arbitrary backing
            // allocators and bounds simultaneous family peaks. Joining uses the
            // caller allocator; transferred singleton rows retain their family
            // budget, which in turn retains this request budget.
            const preparation_budget = if (limits.parallel_preparation > 1) try Budget.createRetainingParent(a, limits.join.max_join_bytes) else null;
            defer if (preparation_budget) |budget| budget.destroy();
            const prep_a = if (preparation_budget) |budget| budget.allocator() else a;
            var context = PrepareContext{ .a = prep_a, .original = original, .input = input, .expected = expected, .pieces = pieces[0..count], .limits = limits, .family_max = family_max, .elapsed = elapsed[0..count] };
            try @import("block_v7_preparation_jobs_v1.zig").run(a, count, limits.parallel_preparation, &context, PrepareContext.prepare);
            if (limits.stats) |stats| {
                stats.* = .{};
                for (expected, elapsed[0..count]) |pin, ns| {
                    const family = &stats.families[@intFromEnum(pin.kind)];
                    family.jobs += 1;
                    family.total_ns += ns;
                    family.maximum_ns = @max(family.maximum_ns, ns);
                }
            }
            for (expected, 0..) |pin, i| views[i] = pieces[i].?.view(pin.index);

            return if (shared) Mixed.prepareDrainingWithLimits(a, views[0..count], expected, input.epoch, limits.capacity, limits.join) else Mixed.prepareDrainingWithLimits(a, views[0..count], expected, limits.join);
        }
    };
}
