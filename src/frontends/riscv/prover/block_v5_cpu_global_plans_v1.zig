//! Actual global memory/source/ROM/lookup first roots for late native admission.
//! Collection never manufactures a SourceSeal or proof authority.
const std = @import("std");
const core = @import("stwo_core");
const packed_mod = @import("block_v5_sorted_memory_replay_v1.zig");
const writer = @import("block_v5_memory_source_writer_v1.zig");
const groups_mod = @import("block_v5_cpu_lookup_groups_v1.zig");
const driver = @import("block_v5_cpu_driver_admission_v1.zig");
const rom_proof = @import("block_v5_program_table_proof_v1.zig");
const rom = @import("block_v5_program_table_v1.zig");
const seals = @import("block_v5_source_seal_v1.zig");
const memory_receiver = @import("block_v5_sorted_memory_v1.zig");
pub const Limits = struct { minimum_memory_log: u32, maximum_memory_log: u32, max_memory_instances: usize, max_range_shards: usize, max_program_rows: u64, lane_resources: @import("block_v5_ram_lanes_replay_v1.zig").Resources = .{} };
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        a: std.mem.Allocator,
        memory: packed_mod.ForBackend(Backend),
        sources: writer.Result,
        sorted: packed_mod.SortedSource,
        config: core.pcs.PcsConfig,
        limits: Limits,
        program_entry: ?seals.Entry = null,
        program_plan: ?rom.Plan = null,
        /// Borrowed group stage/census live until proving and receiving end.
        groups: ?*groups_mod.Stage = null,
        pub fn deinit(self: *Self) void {
            self.memory.deinit();
            self.sources.deinit();
            self.* = undefined;
        }
        /// Collect memory/source first, then Planning.bind(actual digests),
        /// then bindProviders(bound). This resolves the late-ID dependency
        /// without placeholder global digests or admissions.
        pub fn collect(a: std.mem.Allocator, dir: std.fs.Dir, sorted: packed_mod.SortedSource, source_input: writer.Input, config: core.pcs.PcsConfig, limits: Limits) !Self {
            if (limits.minimum_memory_log < 8 or limits.maximum_memory_log > 24 or limits.maximum_memory_log < limits.minimum_memory_log or limits.max_memory_instances == 0 or limits.max_range_shards == 0) return error.InvalidV5GlobalPlanLimits;
            if (source_input.register_custody_mode == 1) {
                var sizes = try @import("block_v5_ram_lanes_replay_v1.zig").selectSizes(Backend, a, source_input.expected_total_events, .{ .minimum_row_log = limits.minimum_memory_log, .maximum_row_log = limits.maximum_memory_log, .max_instances = limits.max_memory_instances }, config, try packed_mod.laneResources(limits.lane_resources, limits.maximum_memory_log, limits.max_memory_instances, limits.max_range_shards));
                defer sizes.deinit();
            } else if (source_input.expected_total_events != 0) {
                var sizes = try @import("../air/block/memory_size_plan.zig").select(a, source_input.expected_total_events, limits.minimum_memory_log, limits.maximum_memory_log);
                defer sizes.deinit();
                if (sizes.capacities.len > limits.max_memory_instances) return error.V5GlobalPlanResourceLimit;
            } else return error.InvalidV5EmptyRwMode;
            var sources = try writer.write(dir, source_input, sorted);
            errdefer sources.deinit();
            var memory = try packed_mod.ForBackend(Backend).collect(a, sorted, sources.event_count, limits.minimum_memory_log, limits.maximum_memory_log, limits.max_memory_instances, limits.max_range_shards, source_input.register_custody_mode, config, limits.lane_resources);
            errdefer memory.deinit();
            if (memory.rangeCount() > limits.max_range_shards) return error.V5GlobalPlanResourceLimit;
            return .{ .a = a, .memory = memory, .sources = sources, .sorted = sorted, .config = config, .limits = limits };
        }
        pub fn digests(self: *const Self) !driver.GlobalPlans {
            return .{ .register_custody_mode = self.sources.register_custody_mode, .memory_plan_digest = self.memory.memoryPlan().plan_digest, .initial_source_plan_digest = try self.sources.initial_pins.digest(), .rw_endpoint_plan_digest = try self.sources.endpointPins(self.memory.memoryPlan().plan_digest).digest(), .register_endpoint_plan_digest = try self.sources.registerPlanDigest() };
        }
        pub fn bindProviders(self: *Self, bound: anytype, groups: *groups_mod.Stage) !void {
            if (self.program_entry != null or self.groups != null or !std.meta.eql(bound.config, self.config) or !std.meta.eql(groups.config, self.config)) return error.InvalidV5GlobalPlanPhase;
            try groups.requirePlans(bound.lookup_plans);
            if (groups.execution_count != bound.entries.len or !std.meta.eql(bound.register_endpoint_plan_digest, try self.sources.registerPlanDigest())) return error.ChangedV5GlobalBoundPlans;
            if ((@as(u64, 1) << @intCast(bound.program_plan.log_size)) > self.limits.max_program_rows) return error.V5GlobalPlanResourceLimit;
            const globals = try self.digests();
            for (bound.admissions) |pin| if (!std.meta.eql(pin.context.memory_plan_digest, globals.memory_plan_digest) or
                !std.meta.eql(pin.context.initial_source_plan_digest, globals.initial_source_plan_digest) or
                !std.meta.eql(pin.context.rw_endpoint_plan_digest, globals.rw_endpoint_plan_digest)) return error.ChangedV5GlobalBoundPlans;
            var first = try rom_proof.ForBackend(Backend).commitFirstRound(self.a, bound.program_plan, self.config);
            defer first.deinit(self.a);
            self.program_entry = .{ .family = .program, .index = 0, .instance_id = try rom_proof.instanceId(bound.program_plan), .roots = first.roots };
            self.program_plan = bound.program_plan;
            self.groups = groups;
        }
        /// These entries join the driver-owned native/sidecar/caller roster.
        /// They must be sorted with every other family before a seal is made.
        pub fn entries(self: *const Self, a: std.mem.Allocator, max_entries: usize) ![]seals.Entry {
            const groups = self.groups orelse return error.IncompleteV5GlobalProviders;
            const program = self.program_entry orelse return error.IncompleteV5GlobalProviders;
            const n = try std.math.add(usize, 1, try std.math.add(usize, self.memory.instanceCount(), try std.math.add(usize, self.memory.rangeCount(), groups.records.len)));
            if (n > max_entries) return error.V5GlobalPlanResourceLimit;
            const result = try a.alloc(seals.Entry, n);
            errdefer a.free(result);
            result[0] = program;
            var at: usize = 1;
            for (0..self.memory.instanceCount()) |i| {
                result[at] = try self.memory.memoryEntry(i);
                at += 1;
            }
            for (0..self.memory.rangeCount()) |i| {
                result[at] = try self.memory.rangeEntry(i);
                at += 1;
            }
            for (groups.records) |record| {
                result[at] = try record.entry();
                at += 1;
            }
            return result;
        }
        pub fn receiverPins(self: *const Self, pins: seals.Pins, entries_: []const seals.Entry, sealed: seals.Sealed) memory_receiver.Pins {
            return self.memory.receiverPins(pins, entries_, sealed, self.sources.event_count, self.sources.endpointPins(self.memory.memoryPlan().plan_digest), self.sources.register_pins);
        }
        pub fn proveProgram(self: *const Self, pins: seals.Pins, entries_: []const seals.Entry, sealed: seals.Sealed) !rom_proof.Proof {
            try sealed.require(pins, entries_);
            const plan = self.program_plan orelse return error.IncompleteV5GlobalProviders;
            const entry = self.program_entry.?;
            var first = try rom_proof.ForBackend(Backend).commitFirstRound(self.a, plan, self.config);
            defer first.deinit(self.a);
            if (!std.meta.eql(first.roots, entry.roots) or !std.meta.eql(pins.program_plan_digest, try plan.digest()) or !std.meta.eql(sealed.program_first_roots, entry.roots)) return error.ChangedV5GlobalProgramRoots;
            return rom_proof.ForBackend(Backend).prove(self.a, &first, plan, sealed.programSeal());
        }
    };
}
