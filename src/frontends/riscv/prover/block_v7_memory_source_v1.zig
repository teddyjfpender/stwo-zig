//! Versioned memory-source metadata and verification under the whole v7 epoch.
//! No public guest transition list or old source image root grants authority.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const E = @import("block_v7_execution_epoch_v1.zig");
const Policy = @import("block_v7_execution_policy_v1.zig").Policy;
const B = @import("block_v7_memory_bundle_v1.zig");
const R = @import("block_v7_memory_relations_v1.zig");
const Q = R.Q;
const Ram = @import("block_v7_ram_component_v1.zig");
const Provider = @import("block_v7_provider_component_v1.zig");
const T = @import("block_v7_memory_trace_v1.zig");
const Original = @import("../air/block/word_memory_lanes_trace_v1.zig");
const Geometry = @import("block_v5_ram_lanes_protocol_v1.zig");
const Pcs = @import("block_v5_word_pcs_v1.zig");
pub const Bundle = B.Bundle;
pub const Limits = B.Limits;
pub fn entry(policy: Policy, family: E.Family, index: u32, log: u32, roots: [2][32]u8, geometry: ?Geometry.Claim) !E.Entry {
    var ch = suite.Channel{};
    ch.mixU32s(&.{ 0x42374d53, 2, @intFromEnum(family), index, log });
    ch.mixRoot(try policy.digest());
    switch (family) {
        .ram => {
            const g = geometry orelse return error.InvalidV7MemoryEntry;
            try g.validate();
            g.mix(&ch);
        },
        .interval, .range16, .terminal => {
            if (geometry != null or index != 0) return error.InvalidV7MemoryEntry;
        },
        else => return error.InvalidV7MemoryEntry,
    }
    return E.Entry.init(family, index, ch.digestBytes(), &roots);
}
pub fn channel(drawn: *const E.Drawn, item: E.Entry, sums: []const Q) !suite.Channel {
    var ch = drawn.channel;
    try recordAfterChallenges(&ch, item, sums);
    return ch;
}
/// Exact shared framing for native and recursively compiled verifiers.
pub fn recordAfterChallenges(ch: anytype, item: E.Entry, sums: []const Q) !void {
    ch.mixU32s(&.{ 0x42374d50, 2 });
    item.mix(ch);
    ch.mixU64(sums.len);
    for (sums) |sum| {
        if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&sum)) return error.InvalidV7MemoryClaims;
        ch.mixFelts(&.{sum});
    }
}
pub fn firstChannel(policy: Policy, family: E.Family, index: u32, log: u32) !suite.Channel {
    var ch = suite.Channel{};
    ch.mixU32s(&.{ 0x42374d46, 2, @intFromEnum(family), index, log });
    ch.mixRoot(try policy.digest());
    return ch;
}
pub const Open = @import("block_v7_memory_claim_closure_v1.zig").Open;
pub fn For(comptime Backend: type) type {
    return struct {
        pub fn verify(a: std.mem.Allocator, policy: Policy, epoch: E.Epoch, roster: []const E.Entry, bundle: *const Bundle, limits: Limits) !Open {
            try policy.validate();
            try @import("block_v5_ram_lanes_proof_v1.zig").validateGeometry(4, policy.config);
            try @import("block_v5_ram_lanes_proof_v1.zig").validateGeometry(16, policy.config);
            if (!std.meta.eql(epoch.statement, try policy.digest()) or !std.meta.eql(epoch.config, policy.config)) return error.UntrustedV7MemoryPolicy;
            if (bundle.ram.len == 0 or bundle.ram.len > limits.max_shards or bundle.ram.len != epoch.counts[@intFromEnum(E.Family.ram)]) return error.InvalidV7MemoryRoster;
            const claims = try a.alloc(Geometry.Claim, bundle.ram.len);
            defer a.free(claims);
            for (claims, bundle.ram) |*g, item| g.* = item.geometry;
            const events = claims[0].total_events;
            if (events < 13 or events > limits.max_events or events * 24 >= core.fields.m31.Modulus) return error.V7MemoryResourceLimit;
            try Geometry.admitSequence(claims, events);
            const drawn = try epoch.draw(a);
            var transition = Q.zero();
            var link = Q.zero();
            var initialization = bundle.interval.sums[0];
            var range = bundle.range16.sums[0];
            var first_count: u64 = 0;
            var range_count: u64 = 0;
            const RP = Pcs.For(Backend, Ram.Spec);
            for (bundle.ram, 0..) |item, i| {
                if (item.geometry.row_log > limits.max_row_log) return error.V7MemoryResourceLimit;
                try @import("block_v5_ram_lanes_proof_v1.zig").validateGeometry(item.geometry.row_log, policy.config);
                const pin = try entry(policy, .ram, @intCast(i), item.geometry.row_log, item.proof.roots, item.geometry);
                try epoch.requireEntry(roster, pin);
                var fixed = try Original.FixedTrace.init(a, item.geometry, limits.max_matrix_bytes);
                defer fixed.deinit();
                var columns: [24]Pcs.Column = undefined;
                for (&columns, 0..) |*column, j| column.* = .{ .log_size = item.geometry.row_log, .values = fixed.column(j) };
                var capture = try RP.verifyCaptureBorrowed(a, &item.proof.stark, .{ .claim = item.geometry, .halt = try @import("block_v7_halt_algebra_v1.zig").derive(policy.terminal), .sums = item.proof.sums, .challenges = drawn.memory }, item.geometry.row_log, &columns, item.proof.roots, policy.config, try firstChannel(policy, .ram, @intCast(i), item.geometry.row_log), try channel(&drawn, pin, &item.proof.sums));
                capture.deinit(a);
                transition = transition.add(item.proof.sums[0]);
                link = link.add(item.proof.sums[1]);
                initialization = initialization.add(item.proof.sums[2]);
                for (item.proof.sums[3..27]) |sum| range = range.add(sum);
                const f = try T.natural(item.proof.sums[27]);
                const r = try T.natural(item.proof.sums[28]);
                if (f > item.geometry.events or r > @as(u64, item.geometry.events) * 24) return error.InvalidV7MemoryCensus;
                first_count += f;
                range_count += r;
            }
            const counts = try a.alloc(u32, policy.initialized.intervals.len);
            defer a.free(counts);
            @memset(counts, 0);
            var it = try T.interval(a, policy.initialized, counts, limits.max_matrix_bytes);
            defer it.deinit();
            if (it.log != bundle.interval_log) return error.InvalidV7MemoryRoster;
            try @import("block_v5_ram_lanes_proof_v1.zig").validateGeometry(it.log, policy.config);
            const ranges = try a.alloc(u32, 65536);
            defer a.free(ranges);
            @memset(ranges, 0);
            var rt = try T.range16(a, ranges, limits.max_matrix_bytes);
            defer rt.deinit();
            var tt = try T.terminal(a, try @import("block_v7_terminal_protocol_v1.zig").Plan.init(policy.terminal), 0, limits.max_matrix_bytes);
            defer tt.deinit();
            try provider(.interval, a, policy, epoch, roster, &drawn, it, &bundle.interval);
            try provider(.range16, a, policy, epoch, roster, &drawn, rt, &bundle.range16);
            try provider(.terminal, a, policy, epoch, roster, &drawn, tt, &bundle.terminal);
            transition = transition.add(bundle.terminal.sums[0]);
            if (!link.isZero() or !initialization.isZero() or !range.isZero() or first_count != try T.natural(bundle.interval.sums[1]) or range_count != try T.natural(bundle.range16.sums[1])) return error.UnclosedV7MemoryRelations;
            return .{ .transition = transition, .event_count = events - 13 };
        }
        fn provider(comptime kind: Provider.Kind, a: std.mem.Allocator, policy: Policy, epoch: E.Epoch, roster: []const E.Entry, drawn: *const E.Drawn, m: T.Matrix, proof: *const B.Item(Provider.For(kind).PLANES)) !void {
            const S = Provider.For(kind);
            const PC = Pcs.For(Backend, S);
            const family: E.Family = switch (kind) {
                .interval => .interval,
                .range16 => .range16,
                .terminal => .terminal,
            };
            const pin = try entry(policy, family, 0, m.log, proof.roots, null);
            try epoch.requireEntry(roster, pin);
            var captured = try PC.verifyCaptureBorrowed(a, &proof.stark, .{ .challenges = drawn.memory, .sums = proof.sums }, m.log, m.columns[0..S.FIXED_COUNT], proof.roots, policy.config, try firstChannel(policy, family, 0, m.log), try channel(drawn, pin, &proof.sums));
            captured.deinit(a);
        }
    };
}
