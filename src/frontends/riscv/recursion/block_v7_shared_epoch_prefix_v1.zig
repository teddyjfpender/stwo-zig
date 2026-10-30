//! One exact epoch producer, independent of any child proof capture.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../prover/block_v7_execution_epoch_v1.zig");
const T = @import("air/blake3_transcript_witness.zig");
const Plan = @import("air/blake3_transcript_plan.zig").Plan;
const Storage = @import("air/blake3_parent_row_storage.zig");
const Direct = @import("air/blake3_direct_cohort_columns_v1.zig");
const Fanout = @import("air/blake3_transcript_fanout_v1.zig");
pub const PUBLIC_CIRCUIT: u32 = 6_300_001;
pub const FANOUT_CIRCUIT: u32 = 6_300_002;
pub const Owned = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    epoch: E.Epoch,
    consumers: u32,
    operations: []const T.Operation,
    plan: Plan,
    fixed: Storage.FixedTuple(false),
    pub fn create(a: std.mem.Allocator, epoch: E.Epoch, capacity: u32, consumers: usize) !Owned {
        if (consumers == 0 or consumers > 64) return error.InvalidSharedEpochConsumers;
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const temp = arena.allocator();
        var recorder = @import("air/blake3_fixed_operation_recorder_v1.zig").Recorder{ .a = temp, .limits = .{} };
        recorder.mixU32s(&.{ epoch.sharedTag(), E.VERSION, 2 });
        recorder.mixPublicRoot(.{ .circuit = PUBLIC_CIRCUIT, .first_wire = 0 }, epoch.digest);
        try @import("air/block_v7_epoch_transcript_v1.zig").fixed(temp, &recorder);
        recorder.operations.items[1].routed_root.value = epoch.digest;
        var plan = try Plan.initBoundaryCompact(a, .{ .namespace = 7_000_000, .attempt_capacity = capacity }, recorder.operations.items, .{ .final_state_uses = @splat(@intCast(consumers)) });
        errdefer plan.deinit();
        var fixed: Storage.FixedTuple(false) = undefined;
        inline for (0..Storage.Airs.len) |i| fixed[i] = &.{};
        errdefer inline for (0..Storage.Airs.len) |i| a.free(fixed[i]);
        fixed[0] = try a.dupe(Storage.FixedRow(Storage.Airs[0]), plan.fixed.hash_metadata.?.g_rows);
        fixed[1] = try a.dupe(Storage.FixedRow(Storage.Airs[1]), plan.fixed.hash_metadata.?.xor_rows);
        inline for (.{ 2, 6, 7, 8, 14, 15 }) |slot| fixed[slot] = try a.dupe(Storage.FixedRow(Storage.Airs[slot]), try plan.fixed.nonhash_fixed.?.rows(slot));
        var fanout = try Fanout.prepare(a, FANOUT_CIRCUIT, plan.fixed.draw_outputs, &@as([424]u32, @splat(@intCast(consumers))), &@as([424]core.fields.m31.M31, @splat(core.fields.m31.M31.zero())));
        defer fanout.deinit();
        fixed[12] = try a.alloc(Storage.FixedRow(Storage.Airs[12]), fanout.rows.len);
        for (fanout.rows, fixed[12]) |row, *out| out.* = Storage.compactFixed(Storage.Airs[12], row);
        return .{ .allocator = a, .arena = arena, .epoch = epoch, .consumers = @intCast(consumers), .operations = recorder.operations.items, .plan = plan, .fixed = fixed };
    }
    pub fn state(self: *const Owned) T.StatePorts {
        return self.plan.fixed.exported_state.?;
    }
    pub fn scalarValues(self: *const Owned) ![424]core.fields.m31.M31 {
        const fields = try @import("air/block_v7_memory_joint_inputs_v1.zig").challenges(self.allocator, self.epoch);
        var values: [424]core.fields.m31.M31 = undefined;
        for (fields, 0..) |value, i| values[4 * i ..][0..4].* = value.toM31Array();
        return values;
    }
    pub fn emit(self: *const Owned) !Storage.Prepared {
        const a = self.allocator;
        const count = self.plan.fixed.hashCounts();
        var hashes = try @import("blake3_native_hash_columns.zig").Owner.init(a, try @import("blake3_native_hash_layout.zig").Layout.fromCounts(count, .{ .g = 0, .xor = 0 }));
        defer hashes.deinit();
        var live = try self.plan.prepareBoundaryMainColumns(a, self.operations, .{ .final_state_uses = @splat(self.consumers) }, try hashes.transcript());
        defer live.deinit();
        var result = Storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
        inline for (0..Storage.Airs.len) |i| result.fixed[i] = &.{};
        errdefer result.deinit();
        result.main[0] = hashes.main[0];
        result.main[1] = hashes.main[1];
        result.fixed[0] = hashes.g_metadata;
        result.fixed[1] = hashes.xor_metadata;
        hashes.owns_backing = false;
        inline for (@import("air/blake3_nonhash_emission_v1.zig").slots, 0..) |slot, i| {
            const taken = try live.nonhash.?.columns.owners[i].take();
            result.main[slot] = taken.main;
            result.fixed[slot] = taken.fixed;
        }
        const values = try self.scalarValues();
        var fanout = try Fanout.prepare(a, FANOUT_CIRCUIT, self.plan.fixed.draw_outputs, &@as([424]u32, @splat(self.consumers)), &values);
        defer fanout.deinit();
        inline for (Storage.Airs, 0..) |Air, slot| {
            if (slot != 0 and slot != 1 and slot != 2 and slot != 6 and slot != 7 and slot != 8 and slot != 9 and slot != 13 and slot != 14 and slot != 15) {
                var columns = try Direct.ForAir(Air).init(a, if (slot == 12) fanout.rows.len else 0);
                defer columns.deinit();
                if (slot == 12) for (fanout.rows) |row| try columns.append(row);
                const taken = try columns.take();
                result.main[slot] = taken.main;
                result.fixed[slot] = taken.fixed;
            }
            if (self.fixed[slot].len != result.fixed[slot].len) return error.SharedEpochFixedMismatch;
            for (self.fixed[slot], result.fixed[slot]) |expected, actual| if (!std.meta.eql(expected, actual)) return error.SharedEpochFixedMismatch;
        }
        return result;
    }
    pub fn deinit(self: *Owned) void {
        inline for (0..Storage.Airs.len) |i| self.allocator.free(self.fixed[i]);
        self.plan.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
};
