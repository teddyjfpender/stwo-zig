//! Physical row parity on actual two-shard K/ADD/DOUBLE fixtures. Not a new
//! accepting GKR services proof: this qualifies narrow metadata custody only.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const R = @import("../roster.zig");
const F = @import("../fixture.zig");
const Input = @import("inputs.zig");
const Frame = @import("frame.zig");
const Provider = @import("native_provider.zig").Provider;
const a = std.testing.allocator;
fn publicFor(p: A.word16_execution.types.Boundary) A.word16_cpu.boundary.PublicFor(O) {
    var out: A.word16_cpu.boundary.PublicFor(O) = undefined;
    for (0..32) |r| {
        for (0..4) |i| {
            const sh: u6 = @intCast(16 * i);
            out.initial_registers[r][i] = O.fromBase(M.fromCanonical(@as(u16, @truncate(p.initial_registers[r] >> sh))));
            out.final_registers[r][i] = O.fromBase(M.fromCanonical(@as(u16, @truncate(p.final_registers[r] >> sh))));
        }
        out.register_clocks[r] = O.fromBase(M.fromCanonical(p.register_clocks[r]));
    }
    return out;
}
const Sample = struct { instance: Frame.Instance, logical: usize, n: [128]M, d: [128]O };
test "actual K ADD DOUBLE metadata equals physical MAIN fractions and survives owned take" {
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    for (0..2) |shard| {
        const bridge_logs: @import("../types.zig").Logs = if (shard == 0) .{ .keccak = 5 } else .{ .add = 5, .double = 5 };
        var setup = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, try captured.native[shard].geometry(), bridge_logs);
        defer setup.deinit();
        const g = setup.materials.geometry;
        const Memory = @import("../../../word16_execution/memory/prepared.zig").Prepared;
        const before = try a.dupe(A.memory.closed_ram.types.Cell, if (shard == 0) captured.advice.initial else &.{});
        const after = try a.dupe(A.memory.closed_ram.types.Cell, if (shard == 1) captured.advice.terminal else &.{});
        const memory = try Memory.initOwnedForGlobalRamLadderIndependent(a, captured.advice.events[shard], before, after, @intCast(shard + 1), g.ls_log, g.ls_tail_log, g.initialLog(), g.terminalLog());
        var source = R.Sources{ .core = try @import("../../../word16_execution/sources.zig").Source.fromPreparedWithOwnedMemory(a, &setup.materials, &captured.native[shard], memory) };
        defer source.deinit();
        if (shard == 0) source.keccak = try A.crypto.keccak.word16_bridge.source.Source.init(a, captured.advice.keccak[0], 1, 5) else {
            source.add = try A.crypto.secp256k1.word16_bridge.source.Source.init(a, .add, captured.advice.secp[1][0], 1, 5);
            source.double = try A.crypto.secp256k1.word16_bridge.source.Source.init(a, .double, captured.advice.secp[1][1], 1, 5);
        }
        try source.mergeRanges();
        const instances = try @import("roster.zig").fromSetup(a, &setup);
        defer a.free(instances);
        const fixed = try setup.fixedColumns(a);
        defer a.free(fixed);
        const main = try source.columns(a, &setup, 1);
        defer a.free(main);
        var channel = core.channel.raw_mod_m31.Om31Channel.init();
        const challenges = @import("challenges.zig").For(O).draw(&channel);
        var saved = std.ArrayList(Sample).empty;
        defer saved.deinit(a);
        const provider = Provider{ .source = &source };
        const boundary = publicFor(source.core.cpu.public);
        for (instances) |instance| {
            const rows = try instance.rows();
            for ([_]usize{ 0, 1, rows / 2, rows - 2, rows - 1 }) |logical| {
                const p = A.witness.physical(logical, instance.row_log);
                var f: [64]O = undefined;
                var m: [256]O = undefined;
                const fw: usize = if (instance.origin == .core) setup.materials.shapes()[@intFromEnum(instance.origin.core)].widths[0] else if (instance.origin.bridge == .keccak) A.crypto.keccak.word16_bridge.layout.FIXED else A.crypto.secp256k1.word16_bridge.layout.FIXED;
                const mw: usize = if (instance.origin == .core) setup.materials.shapes()[@intFromEnum(instance.origin.core)].widths[1] else if (instance.origin.bridge == .keccak) A.crypto.keccak.word16_bridge.layout.MAIN else A.crypto.secp256k1.word16_bridge.layout.MAIN;
                for (f[0..fw], 0..) |*v, c| v.* = O.fromBase(fixed[instance.fixed_offset + c].values[p]);
                for (m[0..mw], 0..) |*v, c| v.* = O.fromBase(main[instance.main_offset + c].values[p]);
                var expected = Sample{ .instance = instance, .logical = logical, .n = undefined, .d = undefined };
                var raw = Input.RowSink{ .challenges = &challenges, .numerator = expected.n[0..instance.terms], .denominator = expected.d[0..instance.terms] };
                try @import("dispatch.zig").emitFor(O, instance.origin, f[0..fw], m[0..mw], O.fromBase(M.fromCanonical(@intCast(shard + 1))), boundary, &raw);
                var actual = Sample{ .instance = instance, .logical = logical, .n = undefined, .d = undefined };
                var metadata = Input.RowSink{ .challenges = &challenges, .numerator = actual.n[0..instance.terms], .denominator = actual.d[0..instance.terms] };
                try provider.emit(instance, logical, &metadata);
                try std.testing.expect(!raw.invalid and !metadata.invalid);
                try std.testing.expectEqual(instance.terms, raw.count);
                try std.testing.expectEqual(raw.count, metadata.count);
                try std.testing.expectEqualSlices(M, expected.n[0..raw.count], actual.n[0..raw.count]);
                try std.testing.expectEqualSlices(O, expected.d[0..raw.count], actual.d[0..raw.count]);
                try saved.append(a, expected);
            }
        }
        // OWNED commit is allowed to overwrite every old source row in place.
        // Metadata queries must not consult the detached allocation again.
        const owned = try source.takeMain(&setup);
        defer owned.deinit(a);
        for (owned.backings) |backing| @memset(backing, M.zero());
        for (saved.items) |sample| {
            var n: [128]M = undefined;
            var d: [128]O = undefined;
            var sink = Input.RowSink{ .challenges = &challenges, .numerator = n[0..sample.instance.terms], .denominator = d[0..sample.instance.terms] };
            try provider.emit(sample.instance, sample.logical, &sink);
            try std.testing.expectEqualSlices(M, sample.n[0..sink.count], n[0..sink.count]);
            try std.testing.expectEqualSlices(O, sample.d[0..sink.count], d[0..sink.count]);
        }
    }
}
