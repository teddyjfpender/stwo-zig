//! Experimental ORIGINAL-STARK memory+terminal bundle. This proves consistency
//! against an independently supplied public guest-transition multiset; it does
//! NOT yet prove guest execution or admit an Ethereum block statement.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("block_v7_memory_relations_v1.zig");
const Q = R.Q;
const suite = core.proof_suites.Blake3;
const Ram = @import("block_v7_ram_component_v1.zig");
const Provider = @import("block_v7_provider_component_v1.zig");
const T = @import("block_v7_memory_trace_v1.zig");
const Initial = @import("block_v7_initial_intervals_v1.zig");
const Terminal = @import("block_v7_terminal_protocol_v1.zig");
const Geometry = @import("block_v5_ram_lanes_protocol_v1.zig");
const Original = @import("../air/block/word_memory_lanes_trace_v1.zig");
const Event = @import("../air/block/memory_transition.zig").Transition;
const Pcs = @import("block_v5_word_pcs_v1.zig");
const IS = Provider.For(.interval);
const RS = Provider.For(.range16);
const TS = Provider.For(.terminal);
pub const Limits = struct { max_events: u32 = 65536, max_shards: u32 = 4096, max_row_log: u32 = 16, max_matrix_bytes: usize = 128 << 20, initial: Initial.Limits = .{} };
pub const Trusted = struct {
    elf: []const u8,
    elf_sha256: [32]u8,
    profile: @import("../runner/elf_loader.zig").ExecutionProfile,
    terminal: Terminal.Policy,
    guest: []const Event,
    config: core.pcs.PcsConfig,
    pub fn validate(self: Trusted, limits: Limits) !void {
        try self.terminal.validate();
        if (self.guest.len > limits.max_events or self.guest.len + Terminal.READS > limits.max_events or (self.guest.len + Terminal.READS) * 24 >= core.fields.m31.Modulus) return error.V7MemoryResourceLimit;
        for (self.guest) |event| {
            if (event.space != 1 or event.address & 3 != 0 or event.clock % 4 == 0 or event.clock > 4 * self.terminal.final_cycle - 1) return error.InvalidV7GuestTransition;
        }
        try @import("blake3_execution_protocol.zig").validateConfig(self.config);
        try requireGeometry(4, self.config);
        try requireGeometry(16, self.config);
    }
};
pub fn Item(comptime n: usize) type {
    return struct {
        roots: [2][32]u8,
        sums: [n]Q,
        stark: suite.Proof,
        pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
            self.stark.deinit(a);
            self.* = undefined;
        }
    };
}
pub const RamItem = struct { geometry: Geometry.Claim, proof: Item(Ram.PLANES) };
pub const Bundle = struct {
    ram: []RamItem,
    interval_log: u32,
    interval: Item(2),
    range16: Item(2),
    terminal: Item(1),
    pub fn deinit(self: *Bundle, a: std.mem.Allocator) void {
        for (self.ram) |*item| item.proof.deinit(a);
        a.free(self.ram);
        self.interval.deinit(a);
        self.range16.deinit(a);
        self.terminal.deinit(a);
        self.* = undefined;
    }
};
fn statement(trusted: Trusted, policy: *const Initial.Owned) suite.Channel {
    var ch = suite.Channel{};
    ch.mixU32s(&.{ 0x42374d42, 2, 24, 88, 116, 161, 4, 2, @intFromEnum(trusted.profile) });
    ch.mixRoot(trusted.elf_sha256);
    trusted.config.mixInto(&ch);
    ch.mixU64(trusted.terminal.final_cycle);
    ch.mixU32s(&.{ trusted.terminal.halt_address, trusted.terminal.length_address, trusted.terminal.data_address, trusted.terminal.output_end });
    for (trusted.terminal.output) |byte| ch.mixU32s(&.{byte});
    ch.mixU64(policy.intervals.len);
    for (policy.intervals) |item| for (item.tuple()) |v| ch.mixU32s(&.{v.toU32()});
    ch.mixU64(trusted.guest.len);
    for (trusted.guest) |event| for (@import("block_v5_word_memory_protocol_v1.zig").transitionTuple(event)) |v| ch.mixU32s(&.{v.toU32()});
    return ch;
}
fn firstChannel(common: suite.Channel, family: u32, index: u32, log: u32) suite.Channel {
    var ch = common;
    ch.mixU32s(&.{ 0x42374652, 1, family, index, log });
    return ch;
}
fn proofChannel(common: suite.Channel, family: u32, index: u32, sums: []const Q) suite.Channel {
    var ch = common;
    ch.mixU32s(&.{ 0x42375048, 1, family, index, @intCast(sums.len) });
    ch.mixFelts(sums);
    return ch;
}
fn roster(base: suite.Channel, ram: []const RamItem, interval_log: u32, interval_roots: [2][32]u8, range_roots: [2][32]u8, terminal_roots: [2][32]u8) suite.Channel {
    var ch = base;
    ch.mixU32s(&.{ 0x42375253, 1, @intCast(ram.len) });
    for (ram, 0..) |item, i| {
        ch.mixU32s(&.{ 0, @intCast(i) });
        item.geometry.mix(&ch);
        for (item.proof.roots) |root| ch.mixRoot(root);
    }
    for ([3][2][32]u8{ interval_roots, range_roots, terminal_roots }, [3]u32{ interval_log, 16, 4 }, 0..) |roots, log, i| {
        ch.mixU32s(&.{ @intCast(i + 1), 0, log });
        for (roots) |root| ch.mixRoot(root);
    }
    return ch;
}
pub const RamContext = struct {
    spec: Ram.Spec,
    pub const Prepared = struct {
        spec: Ram.Spec,
        incoming: Q,
        pub fn termsAt(self: @This(), matrix: T.Matrix, logical: usize) ![Ram.PLANES]R.Term(Q) {
            const f = Original.fixedPoint(Q, matrix.row(24, 0, logical), self.spec.claim);
            return Ram.terms(Q, self.spec.challenges, self.incoming, f, matrix.row(Ram.Spec.MAIN_COUNT, 24, logical), matrix.row(Ram.Spec.MAIN_COUNT, 24, if (logical == 0) matrix.size() - 1 else logical - 1));
        }
    };
    pub fn prepare(self: @This(), size: usize) !Prepared {
        const domain = try self.spec.prepareDomain(@intCast(size));
        return .{ .spec = self.spec, .incoming = domain.incoming };
    }
    pub fn termsAt(self: @This(), matrix: T.Matrix, logical: usize) ![Ram.PLANES]R.Term(Q) {
        return (try self.prepare(matrix.size())).termsAt(matrix, logical);
    }
};
fn ProviderContext(comptime S: type) type {
    return struct {
        ch: R.Challenges(Q),
        pub fn termsAt(self: @This(), matrix: T.Matrix, logical: usize) ![S.PLANES]R.Term(Q) {
            return S.terms(Q, self.ch, matrix.row(S.FIXED_COUNT, 0, logical), matrix.row(S.MAIN_COUNT, S.FIXED_COUNT, logical));
        }
    };
}
pub fn For(comptime Backend: type) type {
    return struct {
        const RP = Pcs.For(Backend, Ram.Spec);
        const IP = Pcs.For(Backend, IS);
        const GP = Pcs.For(Backend, RS);
        const TP = Pcs.For(Backend, TS);
        pub fn prove(a: std.mem.Allocator, trusted: Trusted, high_byte: u8, events_per_shard: u32, limits: Limits) !Bundle {
            try trusted.validate(limits);
            if (events_per_shard == 0) return error.V7MemoryResourceLimit;
            var policy = try Initial.Owned.derive(a, trusted.elf, trusted.elf_sha256, trusted.profile, limits.initial);
            defer policy.deinit();
            const halt = try policy.find(trusted.terminal.halt_address);
            if (!halt.allowed or halt.private or halt.value != 0) return error.InvalidV7InitialHalt;
            try requireTerminalAbi(trusted.terminal, policy.info);
            const plan = try Terminal.Plan.init(trusted.terminal);
            const total = trusted.guest.len + Terminal.READS;
            const events = try a.alloc(Event, total);
            defer a.free(events);
            @memcpy(events[0..trusted.guest.len], trusted.guest);
            for (events[trusted.guest.len..], 0..) |*event, i| event.* = try plan.transition(i, high_byte);
            std.mem.sort(Event, events, {}, less);
            const count = std.math.divCeil(usize, total, events_per_shard) catch return error.V7MemoryResourceLimit;
            if (count > limits.max_shards) return error.V7MemoryResourceLimit;
            const items = try a.alloc(RamItem, count);
            errdefer a.free(items);
            const matrices = try a.alloc(T.Matrix, count);
            defer a.free(matrices);
            var matrix_count: usize = 0;
            defer for (matrices[0..matrix_count]) |*m| m.deinit();
            const firsts = try a.alloc(RP.First, count);
            defer a.free(firsts);
            var first_count: usize = 0;
            defer for (firsts[0..first_count]) |*f| f.deinit(a);
            const interval_counts = try a.alloc(u32, policy.intervals.len);
            defer a.free(interval_counts);
            @memset(interval_counts, 0);
            const range_counts = try a.alloc(u32, 65536);
            defer a.free(range_counts);
            @memset(range_counts, 0);
            const base = statement(trusted, &policy);
            for (items, 0..) |*item, i| {
                const begin = i * events_per_shard;
                const end = @min(total, begin + events_per_shard);
                const n = end - begin;
                const log = @max(@as(u32, 4), std.math.log2_int_ceil(usize, (n + 1) / 2));
                if (log > limits.max_row_log) return error.V7MemoryResourceLimit;
                try requireGeometry(log, trusted.config);
                const geometry = Geometry.Claim{ .first_event = begin, .total_events = total, .events = @intCast(n), .row_log = log, .first = events[begin], .last = events[end - 1], .preceding = if (begin == 0) null else events[begin - 1] };
                var original = try Original.Trace.init(a, geometry, .{ .max_row_log = limits.max_row_log, .max_events = limits.max_events, .max_owned_bytes = limits.max_matrix_bytes });
                defer original.deinit();
                for (events[begin..end]) |event| try original.append(event);
                try original.seal();
                matrices[i] = try T.ram(a, &original, &policy, trusted.terminal, limits.max_matrix_bytes);
                matrix_count += 1;
                try T.census(matrices[i], geometry, &policy, interval_counts, range_counts);
                firsts[i] = try RP.commit(a, matrices[i].columns[0..24], matrices[i].columns[24..], firstChannel(base, 0, @intCast(i), log), trusted.config, true);
                first_count += 1;
                item.* = .{ .geometry = geometry, .proof = .{ .roots = firsts[i].roots, .sums = @splat(Q.zero()), .stark = undefined } };
            }
            var it = try T.interval(a, &policy, interval_counts, limits.max_matrix_bytes);
            defer it.deinit();
            try requireGeometry(it.log, trusted.config);
            var rt = try T.range16(a, range_counts, limits.max_matrix_bytes);
            defer rt.deinit();
            var tt = try T.terminal(a, plan, high_byte, limits.max_matrix_bytes);
            defer tt.deinit();
            var fi = try IP.commit(a, it.columns[0..7], it.columns[7..], firstChannel(base, 1, 0, it.log), trusted.config, true);
            defer fi.deinit(a);
            var fr = try GP.commit(a, rt.columns[0..2], rt.columns[2..], firstChannel(base, 2, 0, 16), trusted.config, true);
            defer fr.deinit(a);
            var ft = try TP.commit(a, tt.columns[0..10], tt.columns[10..], firstChannel(base, 3, 0, 4), trusted.config, true);
            defer ft.deinit(a);
            var shared = roster(base, items, it.log, fi.roots, fr.roots, ft.roots);
            const ch = R.draw(&shared);
            var proved: usize = 0;
            errdefer for (items[0..proved]) |*item| item.proof.deinit(a);
            for (items, matrices, firsts, 0..) |*item, m, *f, i| {
                var spec = Ram.Spec{ .claim = item.geometry, .halt = try @import("block_v7_halt_algebra_v1.zig").derive(trusted.terminal), .sums = @splat(Q.zero()), .challenges = ch };
                var generated = try T.interactions(Ram.PLANES, a, m, RamContext{ .spec = spec }, limits.max_matrix_bytes);
                defer generated.deinit();
                spec.sums = generated.sums;
                item.proof.sums = generated.sums;
                item.proof.stark = try RP.prove(a, f, spec, m.log, generated.matrix.columns, proofChannel(shared, 0, @intCast(i), &generated.sums));
                proved += 1;
            }
            var ip = try proveProvider(IS, IP, a, &fi, it, ch, shared, 1, limits);
            errdefer ip.deinit(a);
            var rp = try proveProvider(RS, GP, a, &fr, rt, ch, shared, 2, limits);
            errdefer rp.deinit(a);
            var tp = try proveProvider(TS, TP, a, &ft, tt, ch, shared, 3, limits);
            errdefer tp.deinit(a);
            return .{ .ram = items, .interval_log = it.log, .interval = ip, .range16 = rp, .terminal = tp };
        }
        fn proveProvider(comptime S: type, comptime PC: type, a: std.mem.Allocator, first: *PC.First, m: T.Matrix, ch: R.Challenges(Q), shared: suite.Channel, family: u32, limits: Limits) !Item(S.PLANES) {
            var generated = try T.interactions(S.PLANES, a, m, ProviderContext(S){ .ch = ch }, limits.max_matrix_bytes);
            defer generated.deinit();
            const spec = S{ .challenges = ch, .sums = generated.sums };
            return .{ .roots = first.roots, .sums = generated.sums, .stark = try PC.prove(a, first, spec, m.log, generated.matrix.columns, proofChannel(shared, family, 0, &generated.sums)) };
        }
        pub fn verify(a: std.mem.Allocator, trusted: Trusted, bundle: *const Bundle, limits: Limits) !void {
            try trusted.validate(limits);
            if (bundle.ram.len == 0 or bundle.ram.len > limits.max_shards) return error.InvalidV7Roster;
            var policy = try Initial.Owned.derive(a, trusted.elf, trusted.elf_sha256, trusted.profile, limits.initial);
            defer policy.deinit();
            const halt = try policy.find(trusted.terminal.halt_address);
            if (!halt.allowed or halt.private or halt.value != 0) return error.InvalidV7InitialHalt;
            try requireTerminalAbi(trusted.terminal, policy.info);
            const geometries = try a.alloc(Geometry.Claim, bundle.ram.len);
            defer a.free(geometries);
            for (geometries, bundle.ram) |*g, item| {
                g.* = item.geometry;
                if (g.row_log > limits.max_row_log) return error.V7MemoryResourceLimit;
                try requireGeometry(g.row_log, trusted.config);
            }
            try Geometry.admitSequence(geometries, trusted.guest.len + Terminal.READS);
            const ic = try a.alloc(u32, policy.intervals.len);
            defer a.free(ic);
            @memset(ic, 0);
            var it = try T.interval(a, &policy, ic, limits.max_matrix_bytes);
            defer it.deinit();
            if (it.log != bundle.interval_log) return error.InvalidV7Roster;
            try requireGeometry(it.log, trusted.config);
            const rc = try a.alloc(u32, 65536);
            defer a.free(rc);
            @memset(rc, 0);
            var rt = try T.range16(a, rc, limits.max_matrix_bytes);
            defer rt.deinit();
            var tt = try T.terminal(a, try Terminal.Plan.init(trusted.terminal), 0, limits.max_matrix_bytes);
            defer tt.deinit();
            const base = statement(trusted, &policy);
            var shared = roster(base, bundle.ram, it.log, bundle.interval.roots, bundle.range16.roots, bundle.terminal.roots);
            const ch = R.draw(&shared);
            for (bundle.ram, 0..) |item, i| {
                var fixed = try Original.FixedTrace.init(a, item.geometry, limits.max_matrix_bytes);
                defer fixed.deinit();
                var columns: [24]Pcs.Column = undefined;
                for (&columns, 0..) |*column, j| column.* = .{ .log_size = item.geometry.row_log, .values = fixed.column(j) };
                var captured = try RP.verifyCaptureBorrowed(a, &item.proof.stark, .{ .claim = item.geometry, .halt = try @import("block_v7_halt_algebra_v1.zig").derive(trusted.terminal), .sums = item.proof.sums, .challenges = ch }, item.geometry.row_log, &columns, item.proof.roots, trusted.config, firstChannel(base, 0, @intCast(i), item.geometry.row_log), proofChannel(shared, 0, @intCast(i), &item.proof.sums));
                captured.deinit(a);
            }
            try verifyProvider(IS, IP, a, &bundle.interval, it, ch, base, shared, 1, trusted.config);
            try verifyProvider(RS, GP, a, &bundle.range16, rt, ch, base, shared, 2, trusted.config);
            try verifyProvider(TS, TP, a, &bundle.terminal, tt, ch, base, shared, 3, trusted.config);
            try close(trusted, bundle, ch);
        }
        fn verifyProvider(comptime S: type, comptime PC: type, a: std.mem.Allocator, item: *const Item(S.PLANES), m: T.Matrix, ch: R.Challenges(Q), base: suite.Channel, shared: suite.Channel, family: u32, config: core.pcs.PcsConfig) !void {
            var captured = try PC.verifyCaptureBorrowed(a, &item.stark, .{ .challenges = ch, .sums = item.sums }, m.log, m.columns[0..S.FIXED_COUNT], item.roots, config, firstChannel(base, family, 0, m.log), proofChannel(shared, family, 0, &item.sums));
            captured.deinit(a);
        }
    };
}
fn less(_: void, l: Event, r: Event) bool {
    return if (l.address == r.address) l.clock < r.clock else l.address < r.address;
}
fn close(trusted: Trusted, bundle: *const Bundle, ch: R.Challenges(Q)) !void {
    var transition = bundle.terminal.sums[0];
    var link = Q.zero();
    var interval = bundle.interval.sums[0];
    var range = bundle.range16.sums[0];
    var first_count: u64 = 0;
    var range_count: u64 = 0;
    for (trusted.guest) |event| {
        var tuple: [11]Q = undefined;
        for (&tuple, @import("block_v5_word_memory_protocol_v1.zig").transitionTuple(event)) |*v, x| v.* = Q.fromBase(x);
        transition = transition.add(try ch.transition.combineSecure(tuple).inv());
    }
    for (bundle.ram) |item| {
        transition = transition.add(item.proof.sums[0]);
        link = link.add(item.proof.sums[1]);
        interval = interval.add(item.proof.sums[2]);
        for (item.proof.sums[3..27]) |sum| range = range.add(sum);
        const f = try T.natural(item.proof.sums[27]);
        const r = try T.natural(item.proof.sums[28]);
        if (f > item.geometry.events or r > @as(u64, item.geometry.events) * 24) return error.InvalidV7MemoryCensus;
        first_count += f;
        range_count += r;
    }
    if (!transition.isZero() or !link.isZero() or !interval.isZero() or !range.isZero() or first_count != try T.natural(bundle.interval.sums[1]) or range_count != try T.natural(bundle.range16.sums[1])) return error.UnclosedV7MemoryRelations;
}

fn requireTerminalAbi(t: Terminal.Policy, info: @import("../runner/elf_loader.zig").ElfInfo) !void {
    if (t.halt_address != info.halt_flag or t.length_address != info.output_len or t.data_address != info.output_data or t.output_end != info.output_end) return error.InvalidV7TerminalAbi;
}

fn requireGeometry(log: u32, config: core.pcs.PcsConfig) !void {
    const fri = config.fri_config;
    if (log < 1 or log > 24 or log + fri.log_blowup_factor >= core.circle.M31_CIRCLE_LOG_ORDER or log < fri.fold_step or log - fri.fold_step < fri.log_last_layer_degree_bound) return error.InvalidV7PcsGeometry;
}
