pub fn ForMode(comptime window: bool) type {
    return struct {
        //! Original v7 memory witness construction before either commitment layout.
        //! No PCS commitments or proofs are constructed here. Both separate and joint
        //! original protocols consume this one witness/census authority.
        const std = @import("std");
        const core = @import("stwo_core");
        const Policy = @import("block_v7_execution_policy_v1.zig").Policy;
        const T = @import("block_v7_memory_trace_v1.zig");
        const Terminal = @import("block_v7_terminal_protocol_v1.zig");
        const Original = @import("../air/block/word_memory_lanes_trace_v1.zig");
        const Geometry = @import("block_v5_ram_lanes_protocol_v1.zig");
        const Event = @import("../air/block/memory_transition.zig").Transition;
        const Limits = @import("block_v7_memory_bundle_v1.zig").Limits;
        pub const Ram = struct { geometry: Geometry.Claim, matrix: T.Matrix };
        pub const Owner = struct {
            allocator: std.mem.Allocator,
            ram: []Ram,
            interval: T.Matrix,
            range16: T.Matrix,
            terminal: if (window) void else T.Matrix,
            pub fn init(a: std.mem.Allocator, policy: Policy, guest: []const Event, high_byte: u8, per_shard: u32, limits: Limits) !Owner {
                try policy.validate();
                if ((policy.window != null) != window) return error.InvalidV7MemoryPolicyMode;
                const extra: usize = if (window) 0 else Terminal.READS;
                if (guest.len == 0 and window) return error.EmptyV7WindowMemory;
                if (window and high_byte != 0) return error.InvalidV7WindowPadding;
                if (per_shard == 0 or guest.len > limits.max_events or guest.len + extra > limits.max_events or (guest.len + extra) * 24 >= core.fields.m31.Modulus) return error.V7MemoryResourceLimit;
                const plan = if (window) {} else try Terminal.Plan.init(policy.terminal);
                const total = guest.len + extra;
                const events = try a.alloc(Event, total);
                defer a.free(events);
                @memcpy(events[0..guest.len], guest);
                for (guest) |event| if (event.space != 1 or event.address & 3 != 0 or event.clock == 0 or event.clock % 4 == 0 or event.clock > 4 * policy.finalCycle() - 1) return error.InvalidV7GuestTransition;
                if (!window) for (events[guest.len..], 0..) |*event, i| {
                    event.* = try plan.transition(i, high_byte);
                };
                std.mem.sort(Event, events, {}, struct {
                    fn less(_: void, l: Event, r: Event) bool {
                        return if (l.address == r.address) l.clock < r.clock else l.address < r.address;
                    }
                }.less);
                const count = try std.math.divCeil(usize, total, per_shard);
                if (count > limits.max_shards) return error.V7MemoryResourceLimit;
                const ram = try a.alloc(Ram, count);
                errdefer a.free(ram);
                var ready: usize = 0;
                errdefer for (ram[0..ready]) |*item| item.matrix.deinit();
                const intervals = try a.alloc(u32, policy.initialized.intervals.len);
                defer a.free(intervals);
                @memset(intervals, 0);
                const ranges = try a.alloc(u32, 65536);
                defer a.free(ranges);
                @memset(ranges, 0);
                // The independently admitted policy is immutable throughout
                // this witness lifetime. Validate/derive its public halt
                // constants once rather than revalidating the complete sparse
                // initialization partition for every RAM component.
                const halt_constants = if (window) try policy.window.?.nonhaltConstants() else try @import("block_v7_halt_algebra_v1.zig").derive(policy.terminal);
                for (ram, 0..) |*item, i| {
                    const begin = i * per_shard;
                    const end = @min(total, begin + per_shard);
                    const n = end - begin;
                    const log = @max(@as(u32, 4), std.math.log2_int_ceil(usize, (n + 1) / 2));
                    if (log > limits.max_row_log) return error.V7MemoryResourceLimit;
                    try @import("block_v5_ram_lanes_proof_v1.zig").validateGeometry(log, policy.config);
                    const geometry = Geometry.Claim{ .first_event = begin, .total_events = total, .events = @intCast(n), .row_log = log, .first = events[begin], .last = events[end - 1], .preceding = if (begin == 0) null else events[begin - 1] };
                    var original = try Original.Trace.init(a, geometry, .{ .max_row_log = limits.max_row_log, .max_events = limits.max_events, .max_owned_bytes = limits.max_matrix_bytes });
                    defer original.deinit();
                    for (events[begin..end]) |event| try original.append(event);
                    try original.seal();
                    var matrix = try T.ramWithHaltConstants(a, &original, policy.initialized, halt_constants, limits.max_matrix_bytes);
                    errdefer matrix.deinit();
                    try T.census(matrix, geometry, policy.initialized, intervals, ranges);
                    item.* = .{ .geometry = geometry, .matrix = matrix };
                    ready += 1;
                }
                var interval = try T.interval(a, policy.initialized, intervals, limits.max_matrix_bytes);
                errdefer interval.deinit();
                var range16 = try T.range16(a, ranges, limits.max_matrix_bytes);
                errdefer range16.deinit();
                var terminal = if (window) {} else try T.terminal(a, plan, high_byte, limits.max_matrix_bytes);
                errdefer if (!window) terminal.deinit();
                for ((if (window) [2]u32{ interval.log, range16.log } else [3]u32{ interval.log, range16.log, terminal.log })) |log| try @import("block_v5_ram_lanes_proof_v1.zig").validateGeometry(log, policy.config);
                return .{ .allocator = a, .ram = ram, .interval = interval, .range16 = range16, .terminal = terminal };
            }
            pub fn deinit(self: *Owner) void {
                for (self.ram) |*item| item.matrix.deinit();
                self.allocator.free(self.ram);
                self.interval.deinit();
                self.range16.deinit();
                if (!window) self.terminal.deinit();
                self.* = undefined;
            }
        };
    };
}
