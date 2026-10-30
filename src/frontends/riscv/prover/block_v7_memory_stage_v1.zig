//! Prechallenge memory staging from actual source witnesses. Each wide trace is
//! committed once; no original source proof or host receipt is treated as valid.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Source = @import("block_v7_memory_source_v1.zig");
const Policy = @import("block_v7_execution_policy_v1.zig").Policy;
const E = @import("block_v7_execution_epoch_v1.zig");
const T = @import("block_v7_memory_trace_v1.zig");
const Ram = @import("block_v7_ram_component_v1.zig");
const P = @import("block_v7_provider_component_v1.zig");
const B = @import("block_v7_memory_bundle_v1.zig");
const Geometry = @import("block_v5_ram_lanes_protocol_v1.zig");
const Witness = @import("block_v7_memory_witness_v1.zig");
const Event = @import("../air/block/memory_transition.zig").Transition;
const PCS = @import("block_v5_word_pcs_v1.zig");
pub fn For(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const RP = PCS.For(Backend, Ram.Spec);
        const IS = P.For(.interval);
        const RS = P.For(.range16);
        const TS = P.For(.terminal);
        const IP = PCS.For(Backend, IS);
        const GP = PCS.For(Backend, RS);
        const TP = PCS.For(Backend, TS);
        a: std.mem.Allocator,
        policy: Policy,
        limits: B.Limits,
        ram: []RamStage,
        witness: Witness.Owner,
        fi: IP.First,
        fr: GP.First,
        ft: TP.First,
        consumed: bool = false,
        // Matrix views borrow the single witness owner; only it releases cells.
        const RamStage = struct { geometry: Geometry.Claim, matrix: T.Matrix, first: RP.First };
        pub fn init(a: std.mem.Allocator, policy: Policy, guest: []const Event, high_byte: u8, per_shard: u32, limits: B.Limits) !Self {
            var witness = try Witness.Owner.init(a, policy, guest, high_byte, per_shard, limits);
            errdefer witness.deinit();
            const ram = try a.alloc(RamStage, witness.ram.len);
            errdefer a.free(ram);
            var ready: usize = 0;
            errdefer for (ram[0..ready]) |*item| item.first.deinit(a);
            for (ram, witness.ram, 0..) |*item, source, i| {
                const first = try RP.commit(a, source.matrix.columns[0..24], source.matrix.columns[24..], try Source.firstChannel(policy, .ram, @intCast(i), source.geometry.row_log), policy.config, true);
                item.* = .{ .geometry = source.geometry, .matrix = source.matrix, .first = first };
                ready += 1;
            }
            var fi = try IP.commit(a, witness.interval.columns[0..7], witness.interval.columns[7..], try Source.firstChannel(policy, .interval, 0, witness.interval.log), policy.config, true);
            errdefer fi.deinit(a);
            var fr = try GP.commit(a, witness.range16.columns[0..2], witness.range16.columns[2..], try Source.firstChannel(policy, .range16, 0, 16), policy.config, true);
            errdefer fr.deinit(a);
            const ft = try TP.commit(a, witness.terminal.columns[0..10], witness.terminal.columns[10..], try Source.firstChannel(policy, .terminal, 0, 4), policy.config, true);
            return .{ .a = a, .policy = policy, .limits = limits, .ram = ram, .witness = witness, .fi = fi, .fr = fr, .ft = ft };
        }
        pub fn deinit(self: *Self) void {
            for (self.ram) |*item| {
                item.first.deinit(self.a);
            }
            self.a.free(self.ram);
            self.fi.deinit(self.a);
            self.fr.deinit(self.a);
            self.ft.deinit(self.a);
            self.witness.deinit();
            self.* = undefined;
        }
        pub fn entries(self: *const Self, a: std.mem.Allocator) ![]E.Entry {
            const out = try a.alloc(E.Entry, self.ram.len + 3);
            errdefer a.free(out);
            for (self.ram, out[0..self.ram.len], 0..) |item, *pin, i| pin.* = try Source.entry(self.policy, .ram, @intCast(i), item.geometry.row_log, item.first.roots, item.geometry);
            out[self.ram.len] = try Source.entry(self.policy, .interval, 0, self.witness.interval.log, self.fi.roots, null);
            out[self.ram.len + 1] = try Source.entry(self.policy, .range16, 0, 16, self.fr.roots, null);
            out[self.ram.len + 2] = try Source.entry(self.policy, .terminal, 0, 4, self.ft.roots, null);
            return out;
        }
        pub fn prove(self: *Self, epoch: E.Epoch, roster: []const E.Entry) !Source.Bundle {
            if (self.consumed or !std.meta.eql(epoch.statement, try self.policy.digest()) or !std.meta.eql(epoch.config, self.policy.config)) return error.InvalidV7MemoryStage;
            const expected = try self.entries(self.a);
            defer self.a.free(expected);
            for (expected) |pin| try epoch.requireEntry(roster, pin);
            self.consumed = true;
            const drawn = try epoch.draw(self.a);
            const items = try self.a.alloc(B.RamItem, self.ram.len);
            errdefer self.a.free(items);
            var ready: usize = 0;
            errdefer for (items[0..ready]) |*item| item.proof.deinit(self.a);
            for (self.ram, items, expected[0..self.ram.len]) |*stage, *item, pin| {
                var spec = Ram.Spec{ .claim = stage.geometry, .halt = try @import("block_v7_halt_algebra_v1.zig").derive(self.policy.terminal), .sums = @splat(Q.zero()), .challenges = drawn.memory };
                var generated = try T.interactions(Ram.PLANES, self.a, stage.matrix, B.RamContext{ .spec = spec }, self.limits.max_matrix_bytes);
                defer generated.deinit();
                spec.sums = generated.sums;
                item.* = .{ .geometry = stage.geometry, .proof = .{ .roots = stage.first.roots, .sums = generated.sums, .stark = try RP.prove(self.a, &stage.first, spec, stage.matrix.log, generated.matrix.columns, try Source.channel(&drawn, pin, &generated.sums)) } };
                ready += 1;
            }
            var ip = try self.provider(IS, IP, &self.fi, self.witness.interval, &drawn, expected[self.ram.len]);
            errdefer ip.deinit(self.a);
            var rp = try self.provider(RS, GP, &self.fr, self.witness.range16, &drawn, expected[self.ram.len + 1]);
            errdefer rp.deinit(self.a);
            var tp = try self.provider(TS, TP, &self.ft, self.witness.terminal, &drawn, expected[self.ram.len + 2]);
            errdefer tp.deinit(self.a);
            return .{ .ram = items, .interval_log = self.witness.interval.log, .interval = ip, .range16 = rp, .terminal = tp };
        }
        fn provider(self: *Self, comptime S: type, comptime PC: type, first: *PC.First, m: T.Matrix, drawn: *const E.Drawn, pin: E.Entry) !B.Item(S.PLANES) {
            const Context = struct {
                ch: @TypeOf(drawn.memory),
                pub fn termsAt(c: @This(), matrix: T.Matrix, logical: usize) ![S.PLANES]@import("block_v7_memory_relations_v1.zig").Term(Q) {
                    return S.terms(Q, c.ch, matrix.row(S.FIXED_COUNT, 0, logical), matrix.row(S.MAIN_COUNT, S.FIXED_COUNT, logical));
                }
            };
            var generated = try T.interactions(S.PLANES, self.a, m, Context{ .ch = drawn.memory }, self.limits.max_matrix_bytes);
            defer generated.deinit();
            return .{ .roots = first.roots, .sums = generated.sums, .stark = try PC.prove(self.a, first, .{ .challenges = drawn.memory, .sums = generated.sums }, m.log, generated.matrix.columns, try Source.channel(drawn, pin, &generated.sums)) };
        }
    };
}
