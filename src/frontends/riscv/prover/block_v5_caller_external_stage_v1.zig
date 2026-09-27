//! Warm packed caller-memory witness commitment and proof. Physical metadata
//! is provisional; only fresh family11/13 verification can admit its claims.
const std = @import("std");
const core = @import("stwo_core");
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Batch = @import("block_v5_precompile_batch_v1.zig");
const External = @import("block_v5_external_memory_sidecar_proof_v1.zig");
const Source = @import("block_execution_external_trace_v2.zig");
const Old = @import("block_execution_external_batch_v2.zig");
const Selected = @import("block_v5_committed_projection_columns_v1.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Bytes = @import("block_v5_memory_byte_demand_v1.zig");
const Counters = @import("../air/lookups/tables/counter.zig");
const Frame = @import("../air/block/memory_event.zig").Frame;
pub const Sink = struct { context: *anyopaque, put_memory: *const fn (*anyopaque, u32, *External.Proof) anyerror!void };
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Api = External.ForPackedBackend(Backend);
        const Warm = Batch.ForBackend(Backend).WarmCaller;
        pub const Prepared = struct {
            columns: Selected.Columns,
            slots: []External.Slot,
            traces: []Source.Trace,
            inputs: []External.Input,
            first: Api.FirstRound,
            byte_demand: Bytes.Demand,
            byte_snapshot: [32]u8,
            pub fn deinit(self: *Prepared, a: std.mem.Allocator) void {
                self.first.deinit(a);
                for (self.traces) |*trace| trace.deinit();
                a.free(self.traces);
                a.free(self.inputs);
                a.free(self.slots);
                self.columns.deinit(a);
                self.* = undefined;
            }
            /// Prefix can be physical/unbound or bound; no native identity is
            /// used to commit its physical trees or integer witness root.
            pub fn init(a: std.mem.Allocator, prefix: anytype, statement: *const @import("blake3_ethereum_sha_profile.zig").admission.Statement, frame: Frame, index: u32, counter: *Counters.Counter) !Prepared {
                return initForMode(a, prefix, statement, frame, index, counter, 0);
            }
            pub fn initForMode(a: std.mem.Allocator, prefix: anytype, statement: *const @import("blake3_ethereum_sha_profile.zig").admission.Statement, frame: Frame, index: u32, counter: *Counters.Counter, mode: u32) !Prepared {
                try Protocol.execution_recipe.requireMode(mode);
                if (!prefix.owns_scheme or counter.kind != .range_check_8_8) return error.UntrustedV5WarmExternalPrefix;
                const fixed_logs = try Protocol.columnLogs(a, statement, .fixed);
                defer a.free(fixed_logs);
                const main_logs = try Protocol.columnLogs(a, statement, .main);
                defer a.free(main_logs);
                const slots = try Source.descriptorsFromStatementForMode(a, statement, fixed_logs, main_logs, frame, mode);
                errdefer a.free(slots);
                const demand = try Bytes.externalDemandForMode(statement, slots, mode);
                var mask = try Old.masks(a, slots, fixed_logs.len, main_logs.len);
                defer mask.deinit(a);
                var ranges: std.ArrayList(Selected.Range) = .empty;
                defer ranges.deinit(a);
                for (mask.fixed, 0..) |selected, i| if (selected) try ranges.append(a, .{ .fixed_offset = i, .fixed_width = 1, .main_offset = 0, .main_width = 0, .log_size = fixed_logs[i] });
                for (mask.main, 0..) |selected, i| if (selected) try ranges.append(a, .{ .fixed_offset = 0, .fixed_width = 0, .main_offset = i, .main_width = 1, .log_size = main_logs[i] });
                if (mask.state_offset) |offset| try ranges.append(a, .{ .fixed_offset = 0, .fixed_width = 0, .main_offset = offset, .main_width = @import("../air/guest_precompile/keccakf_witness.zig").state_cell_count, .log_size = main_logs[offset] });
                var columns = try Selected.Columns.init(a, &prefix.scheme, fixed_logs, main_logs, ranges.items);
                errdefer columns.deinit(a);
                const traces = try a.alloc(Source.Trace, slots.len);
                errdefer a.free(traces);
                const inputs = try a.alloc(External.Input, slots.len);
                errdefer a.free(inputs);
                var initialized: usize = 0;
                errdefer for (traces[0..initialized]) |*trace| trace.deinit();
                var count: u64 = 0;
                for (slots, traces, inputs) |slot, *trace, *input| {
                    trace.* = try Source.Trace.initSelected(a, slot, columns.fixed, columns.main);
                    initialized += 1;
                    input.* = .{ .descriptor = slot, .trace = trace };
                    for (0..trace.domainSize()) |row| count = try std.math.add(u64, count, @intFromBool((try trace.row(row)).active));
                }
                if (count != demand.event_count) return error.InvalidV5WarmExternalCensus;
                var local = try Counters.Counter.init(a, .range_check_8_8);
                defer local.deinit(a);
                var first = try Api.borrowFirstRound(a, &prefix.scheme, columns.fixed, columns.main, inputs, slots, &local, index, prefix.key_id);
                errdefer first.deinit(a);
                if (!std.meta.eql(first.roots[0..2].*, prefix.roots)) return error.UnsharedV5WarmExternalRoots;
                var mass: u64 = 0;
                for (local.values) |value| mass = try std.math.add(u64, mass, value.toU32());
                if (mass != demand.request_count or local.values.len != counter.values.len) return error.InvalidV5WarmExternalByteCensus;
                const snapshot = @import("../air/block/memory_range_interaction_v2.zig").counterSnapshot(&local);
                for (counter.values, local.values) |*value, addend| value.* = value.add(addend);
                return .{ .columns = columns, .slots = slots, .traces = traces, .inputs = inputs, .first = first, .byte_demand = demand, .byte_snapshot = snapshot };
            }
        };
        sink: Sink,
        frame: Frame,
        expected_witness_root: [32]u8,
        expected_byte_snapshot: [32]u8,
        pub fn proveWarm(self: *@This(), a: std.mem.Allocator, warm: Warm) !void {
            try Protocol.admit(warm.first.binding(warm.sealed), warm.sealed, warm.pins, warm.entries);
            if (!std.meta.eql(warm.first.entry(), warm.record.entry()) or self.frame.cycle_count != warm.record.total_steps)
                return error.UntrustedV5WarmExternalRecord;
            var counter = try Counters.Counter.init(a, .range_check_8_8);
            defer counter.deinit(a);
            var prepared = try Prepared.initForMode(a, warm.first, &warm.record.statement, self.frame, warm.record.execution.index, &counter, warm.sealed.register_custody_mode);
            defer prepared.deinit(a);
            if (!std.meta.eql(prepared.first.roots[2], self.expected_witness_root) or !std.meta.eql(prepared.byte_snapshot, self.expected_byte_snapshot))
                return error.ChangedV5WarmExternalWitness;
            const binding = warm.first.binding(warm.sealed);
            var proof = try Api.prove(a, &prepared.first, prepared.inputs, prepared.slots, warm.sealed, warm.pins, warm.entries, &binding, warm.record.execution.index, self.expected_witness_root);
            var owned = true;
            defer if (owned) proof.deinit(a);
            try self.sink.put_memory(self.sink.context, warm.record.execution.index, &proof);
            owned = false;
        }
    };
}
