//! Bounded producer-side table/state stages while family11 trees are warm.
//! Staged proof bytes remain provisional until the global fresh receiver.
const std = @import("std");
const Batch = @import("block_v5_precompile_batch_v1.zig");
const Tables = @import("block_v5_precompile_lookup_proof_v1.zig");
const State = @import("block_v5_precompile_state_request_proof_v1.zig");

pub const Sink = struct {
    context: *anyopaque,
    /// Success transfers ownership; error leaves it with this producer.
    put_tables: *const fn (*anyopaque, u32, *Tables.Proof) anyerror!void,
    put_state: ?*const fn (*anyopaque, u32, *State.Proof) anyerror!void = null,
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const Producer = Batch.ForBackend(Backend);
        sink: Sink,

        /// This adapter plugs directly into the bounded arithmetic producer.
        /// It never consumes the warm family11 scheme or retains witness rows.
        pub fn hooks(self: *Self) Producer.Hooks {
            return .{ .context = self, .on_first_round = onFirstRound };
        }
        fn onFirstRound(raw: *anyopaque, a: std.mem.Allocator, warm: Producer.WarmCaller) !void {
            const self: *Self = @ptrCast(@alignCast(raw));
            if (!warm.first.owns_scheme or !std.meta.eql(warm.first.entry(), warm.record.entry()) or
                !std.meta.eql(warm.witness.statement, warm.record.statement)) return error.UntrustedV5WarmCallerTables;
            const binding = warm.first.binding(warm.sealed);
            const TableApi = Tables.ForBackend(Backend);
            var table_first = try TableApi.borrowFirstRound(a, warm.first, binding);
            defer table_first.deinit(a);
            if (!std.meta.eql(table_first.roots, warm.record.roots) or table_first.scheme.trees.items[1].columns[0].values.ptr != warm.first.scheme.trees.items[1].columns[0].values.ptr) return error.UnsharedV5WarmCallerTables;
            var table_proof = try TableApi.proveFromCommitted(a, &table_first, &warm.record.statement, warm.record.total_steps, binding, warm.sealed, warm.pins, warm.entries);
            var table_owned = true;
            defer if (table_owned) table_proof.deinit(a);
            try self.sink.put_tables(self.sink.context, binding.execution_index, &table_proof);
            table_owned = false;
            if (self.sink.put_state) |accept| {
                const StateApi = State.ForBackend(Backend);
                var state_first = try StateApi.borrowFirstRound(a, warm.first);
                defer state_first.deinit(a);
                var state_proof = try StateApi.proveFromCommitted(a, &state_first, &warm.record.statement, binding, warm.sealed, warm.pins, warm.entries, warm.record.total_steps);
                var state_owned = true;
                defer if (state_owned) state_proof.deinit(a);
                try accept(self.sink.context, binding.execution_index, &state_proof);
                state_owned = false;
            }
        }
    };
}
