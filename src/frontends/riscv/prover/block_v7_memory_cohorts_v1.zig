//! Bounded original RAM cohorts under the existing whole-execution epoch.
//! Input is an independently sorted stream INCLUDING the thirteen terminal
//! reads. The stream is untrusted: unchanged RAM/provider proofs and the final
//! original source verifier enforce execution, initialization and terminal IO.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Policy = @import("block_v7_execution_policy_v1.zig").Policy;
const E = @import("block_v7_execution_epoch_v1.zig");
const Source = @import("block_v7_memory_source_v1.zig");
const B = @import("block_v7_memory_bundle_v1.zig");
const T = @import("block_v7_memory_trace_v1.zig");
const Ram = @import("block_v7_ram_component_v1.zig");
const Provider = @import("block_v7_provider_component_v1.zig");
const Pcs = @import("block_v5_word_pcs_v1.zig");
const Checkpoint = @import("block_v7_memory_cohort_checkpoint_v1.zig");
const Geometry = @import("block_v5_ram_lanes_protocol_v1.zig");
const Original = @import("../air/block/word_memory_lanes_trace_v1.zig");
const Event = @import("../air/block/memory_transition.zig").Transition;
const Terminal = @import("block_v7_terminal_protocol_v1.zig");
const Q = core.fields.qm31.QM31;
pub const Limits = struct {
    memory: B.Limits = .{},
    ram_quotient: @import("block_v7_ram_quotient_policy_v1.zig").Policy = .{ .bounded_tiles = .{} },
    checkpoint: Checkpoint.Limits = .{},
    input_storage: @import("block_v7_input_storage_v1.zig").Policy = .resident,
    interaction_storage: @import("block_v7_input_storage_v1.zig").Policy = .resident,
    consume_rows: bool = false,
    max_live_bytes: usize = 2 << 30,
    max_total_file_bytes: u64 = 128 << 30,
};
pub const Record = struct { geometry: Geometry.Claim, pin: Checkpoint.Pin };
pub const Result = struct {
    allocator: std.mem.Allocator,
    budget: *Budget,
    bundle: Source.Bundle,
    pub fn deinit(self: *Result) void {
        const budget = self.budget;
        self.bundle.deinit(self.allocator);
        self.* = undefined;
        budget.destroy();
    }
};
pub const Owner = struct {
    allocator: std.mem.Allocator,
    budget: *Budget,
    policy: Policy,
    limits: Limits,
    ram: []Record,
    providers: [3]Checkpoint.Pin,
    written_bytes: u64,
    consumed: bool = false,
    pub fn deinit(self: *Owner) void {
        const budget = self.budget;
        self.allocator.free(self.ram);
        self.* = undefined;
        budget.destroy();
    }
    /// Directory is caller-owned and must be dedicated to this collection.
    /// No wide matrices/PCS allocations survive this function.
    pub fn collectSorted(backing: std.mem.Allocator, dir: std.fs.Dir, policy: Policy, reader: anytype, total: u64, per_shard: u32, high_byte: u8, limits: Limits) !Owner {
        try policy.validate();
        try limits.ram_quotient.validate();
        try limits.input_storage.validate();
        try limits.interaction_storage.validate();
        if (limits.max_live_bytes == 0 or per_shard == 0 or total < Terminal.READS or total > limits.memory.max_events or total * 24 >= core.fields.m31.Modulus) return error.V7MemoryResourceLimit;
        const count = try std.math.divCeil(u64, total, per_shard);
        if (count == 0 or count > limits.memory.max_shards) return error.V7MemoryResourceLimit;
        const budget = try Budget.createRetainingParent(backing, limits.max_live_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        const records = try a.alloc(Record, @intCast(count));
        errdefer a.free(records);
        var published: usize = 0;
        errdefer for (0..published) |i| {
            var buf: [64]u8 = undefined;
            dir.deleteFile(fileName(&buf, i) catch unreachable) catch {};
        };
        const events = try a.alloc(Event, @intCast(@min(total, per_shard)));
        defer a.free(events);
        const intervals = try a.alloc(u32, policy.initialized.intervals.len);
        defer a.free(intervals);
        @memset(intervals, 0);
        const ranges = try a.alloc(u32, 65536);
        defer a.free(ranges);
        @memset(ranges, 0);
        var previous: ?Event = null;
        var first: u64 = 0;
        var written: u64 = 0;
        for (records, 0..) |*record, i| {
            const n: usize = @intCast(@min(total - first, per_shard));
            for (events[0..n]) |*event| event.* = (try reader.next()) orelse return error.TruncatedV7MemoryStream;
            const log = @max(@as(u32, 4), std.math.log2_int_ceil(usize, (n + 1) / 2));
            if (log > limits.memory.max_row_log) return error.V7MemoryResourceLimit;
            try @import("block_v5_ram_lanes_proof_v1.zig").validateGeometry(log, policy.config);
            const geometry = Geometry.Claim{ .first_event = first, .total_events = total, .events = @intCast(n), .row_log = log, .first = events[0], .last = events[n - 1], .preceding = previous };
            try geometry.validate();
            var matrix = blk: {
                var original = try Original.Trace.init(a, geometry, .{ .max_row_log = limits.memory.max_row_log, .max_events = limits.memory.max_events, .max_owned_bytes = limits.memory.max_matrix_bytes });
                defer original.deinit();
                for (events[0..n]) |event| try original.append(event);
                try original.seal();
                break :blk try T.ram(a, &original, policy.initialized, policy.terminal, limits.memory.max_matrix_bytes);
            };
            defer matrix.deinit();
            try T.census(matrix, geometry, policy.initialized, intervals, ranges);
            var buf: [64]u8 = undefined;
            const pin = try commitAndSpill(Ram.Spec, a, dir, try fileName(&buf, i), policy, .ram, @intCast(i), matrix, geometry, limits);
            record.* = .{ .geometry = geometry, .pin = pin };
            published += 1;
            written = try std.math.add(u64, written, pin.bytes);
            if (written > limits.max_total_file_bytes) return error.V7CohortStorageLimit;
            first += n;
            previous = geometry.last;
        }
        if (try reader.next() != null) return error.ExtraV7MemoryStream;
        var providers: [3]Checkpoint.Pin = undefined;
        inline for ([_]Provider.Kind{ .interval, .range16, .terminal }, 0..) |kind, i| {
            var matrix = switch (kind) {
                .interval => try T.interval(a, policy.initialized, intervals, limits.memory.max_matrix_bytes),
                .range16 => try T.range16(a, ranges, limits.memory.max_matrix_bytes),
                .terminal => try T.terminal(a, try Terminal.Plan.init(policy.terminal), high_byte, limits.memory.max_matrix_bytes),
            };
            defer matrix.deinit();
            var buf: [64]u8 = undefined;
            providers[i] = try commitAndSpill(Provider.For(kind), a, dir, try fileName(&buf, records.len + i), policy, @field(E.Family, @tagName(kind)), 0, matrix, null, limits);
            published += 1;
            written = try std.math.add(u64, written, providers[i].bytes);
            if (written > limits.max_total_file_bytes) return error.V7CohortStorageLimit;
        }
        return .{ .allocator = a, .budget = budget, .policy = policy, .limits = limits, .ram = records, .providers = providers, .written_bytes = written };
    }
    pub fn entries(self: *const Owner, a: std.mem.Allocator) ![]E.Entry {
        const out = try a.alloc(E.Entry, self.ram.len + 3);
        errdefer a.free(out);
        for (self.ram, out[0..self.ram.len]) |record, *entry| entry.* = record.pin.entry;
        for (self.providers, out[self.ram.len..]) |pin, *entry| entry.* = pin.entry;
        return out;
    }
    pub fn prove(self: *Owner, dir: std.fs.Dir, epoch: E.Epoch, roster: []const E.Entry) !Result {
        return self.proveWithExecutor(dir, epoch, roster, null);
    }
    pub fn proveWithExecutor(self: *Owner, dir: std.fs.Dir, epoch: E.Epoch, roster: []const E.Entry, executor: ?*const @import("stwo_prover_engine").pcs.QuotientExecutor) !Result {
        if (self.consumed or !std.meta.eql(epoch.statement, try self.policy.digest()) or !std.meta.eql(epoch.config, self.policy.config) or epoch.counts[@intFromEnum(E.Family.ram)] != self.ram.len or epoch.counts[@intFromEnum(E.Family.memory_joint)] != 0) return error.InvalidV7MemoryStage;
        inline for ([_]E.Family{ .interval, .range16, .terminal }) |family| if (epoch.counts[@intFromEnum(family)] != 1) return error.InvalidV7MemoryStage;
        for (self.ram) |record| try epoch.requireEntry(roster, record.pin.entry);
        for (self.providers) |pin| try epoch.requireEntry(roster, pin.entry);
        self.consumed = true;
        const a = self.allocator;
        const drawn = try epoch.draw(a);
        const ram = try a.alloc(B.RamItem, self.ram.len);
        errdefer a.free(ram);
        var ready: usize = 0;
        errdefer for (ram[0..ready]) |*item| item.proof.deinit(a);
        for (self.ram, ram, 0..) |record, *item, i| {
            var buf: [64]u8 = undefined;
            var loaded = try Checkpoint.For(Ram.Spec).load(a, dir, try fileName(&buf, i), self.policy.config, record.pin, self.limits.checkpoint);
            defer loaded.deinit(a);
            loaded.first.scheme.quotient_executor = executor;
            var spec = Ram.Spec{ .claim = record.geometry, .halt = try @import("block_v7_halt_algebra_v1.zig").derive(self.policy.terminal), .challenges = drawn.memory, .sums = @splat(Q.zero()) };
            var generated = try T.interactions(Ram.PLANES, a, loaded.matrix, B.RamContext{ .spec = spec }, self.limits.memory.max_matrix_bytes);
            var generated_live = true;
            defer if (generated_live) generated.deinit();
            spec.sums = generated.sums;
            const log = loaded.matrix.log;
            if (self.limits.consume_rows) try loaded.releaseMatrix();
            const sums = generated.sums;
            var channel = try Source.channel(&drawn, record.pin.entry, &sums);
            try Pcs.For(Cpu, Ram.Spec).commitInteractionWithStorage(a, &loaded.first, generated.matrix.columns, &channel, try self.limits.interaction_storage.minimumCommitmentLog(self.policy.config));
            if (self.limits.consume_rows) {
                generated.deinit();
                generated_live = false;
            }
            item.* = .{ .geometry = record.geometry, .proof = .{ .roots = loaded.first.roots, .sums = sums, .stark = try Pcs.For(Cpu, Ram.Spec).proveCommittedWithDomainOptions(a, &loaded.first, spec, log, channel, try self.limits.ram_quotient.select(log, self.limits.max_live_bytes)) } };
            ready += 1;
        }
        var interval = try self.proveProvider(.interval, dir, &drawn, 0, executor);
        errdefer interval.deinit(a);
        var range16 = try self.proveProvider(.range16, dir, &drawn, 1, executor);
        errdefer range16.deinit(a);
        const terminal = try self.proveProvider(.terminal, dir, &drawn, 2, executor);
        return .{ .allocator = a, .budget = self.budget.retain(), .bundle = .{ .ram = ram, .interval_log = self.providers[0].log, .interval = interval, .range16 = range16, .terminal = terminal } };
    }
    fn proveProvider(self: *Owner, comptime kind: Provider.Kind, dir: std.fs.Dir, drawn: *const E.Drawn, index: usize, executor: ?*const @import("stwo_prover_engine").pcs.QuotientExecutor) !B.Item(Provider.For(kind).PLANES) {
        const S = Provider.For(kind);
        const a = self.allocator;
        var buf: [64]u8 = undefined;
        var loaded = try Checkpoint.For(S).load(a, dir, try fileName(&buf, self.ram.len + index), self.policy.config, self.providers[index], self.limits.checkpoint);
        defer loaded.deinit(a);
        loaded.first.scheme.quotient_executor = executor;
        const Context = struct {
            ch: @TypeOf(drawn.memory),
            pub fn termsAt(c: @This(), m: T.Matrix, row: usize) ![S.PLANES]@import("block_v7_memory_relations_v1.zig").Term(Q) {
                return S.terms(Q, c.ch, m.row(S.FIXED_COUNT, 0, row), m.row(S.MAIN_COUNT, S.FIXED_COUNT, row));
            }
        };
        var generated = try T.interactions(S.PLANES, a, loaded.matrix, Context{ .ch = drawn.memory }, self.limits.memory.max_matrix_bytes);
        var generated_live = true;
        defer if (generated_live) generated.deinit();
        const log = loaded.matrix.log;
        if (self.limits.consume_rows) try loaded.releaseMatrix();
        const sums = generated.sums;
        var channel = try Source.channel(drawn, self.providers[index].entry, &sums);
        try Pcs.For(Cpu, S).commitInteractionWithStorage(a, &loaded.first, generated.matrix.columns, &channel, try self.limits.interaction_storage.minimumCommitmentLog(self.policy.config));
        if (self.limits.consume_rows) {
            generated.deinit();
            generated_live = false;
        }
        return .{ .roots = loaded.first.roots, .sums = sums, .stark = try Pcs.For(Cpu, S).proveCommittedWithDomainOptions(a, &loaded.first, .{ .challenges = drawn.memory, .sums = sums }, log, channel, null) };
    }
};
pub fn fileName(buffer: []u8, index: usize) ![]const u8 {
    return std.fmt.bufPrint(buffer, "memory-{d}.checkpoint", .{index});
}
fn commitAndSpill(comptime S: type, a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, policy: Policy, family: E.Family, index: u32, matrix: T.Matrix, geometry: ?Geometry.Claim, limits: Limits) !Checkpoint.Pin {
    const compact = try limits.input_storage.selected(matrix.log);
    var first = try Pcs.For(Cpu, S).commitWithStorage(a, matrix.columns[0..S.FIXED_COUNT], matrix.columns[S.FIXED_COUNT..], try Source.firstChannel(policy, family, index, matrix.log), policy.config, compact, if (compact) try limits.input_storage.minimumCommitmentLog(policy.config) else null);
    defer first.deinit(a);
    return Checkpoint.For(S).write(dir, name, matrix, &first, try Source.entry(policy, family, index, matrix.log, first.roots, geometry), limits.checkpoint);
}
