//! Online field-safe provider roots and immutable per-group counter transport.
//! One counter Set and fixed table basis stay live; no third guest replay.
const std = @import("std");
const core = @import("stwo_core");
const tables = @import("../air/lookups/tables/mod.zig");
const batch = @import("block_v5_native_lookup_batch_v1.zig");
const proof = @import("block_v5_native_lookup_proof_v1.zig");
const planning = @import("block_v5_native_lookup_plan_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
pub const Demand = [tables.schema.KIND_COUNT]u64;
pub const Limits = struct { request_limit: u64, max_groups: usize, max_metadata_bytes: usize, max_counter_file_bytes: u64 };
pub const FilePin = struct { sha256: [32]u8, bytes: u64 };
fn name(index: u32, buffer: *[64]u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "v5-native-group-{d}.counters", .{index});
}

pub const Stage = struct {
    a: std.mem.Allocator,
    dir: std.fs.Dir,
    records: []batch.Record,
    files: []FilePin,
    execution_count: u32,
    config: core.pcs.PcsConfig,
    pub fn deinit(self: *Stage) void {
        self.a.free(self.records);
        self.a.free(self.files);
        self.* = undefined;
    }
    pub fn requirePlans(self: *const Stage, plans: []const planning.Plan) !void {
        try planning.validateRoster(plans, self.execution_count);
        if (plans.len != self.records.len) return error.ChangedV5OnlineLookupPlans;
        for (plans, self.records) |plan, record| if (!std.meta.eql(plan, record.plan)) return error.ChangedV5OnlineLookupPlans;
    }
    pub fn source(self: *Stage) batch.Source {
        return .{ .context = self, .load = load };
    }
    fn load(raw: *anyopaque, plan: planning.Plan) anyerror!tables.counter.Set {
        const self: *Stage = @ptrCast(@alignCast(raw));
        if (plan.index >= self.records.len or !std.meta.eql(plan, self.records[plan.index].plan)) return error.ChangedV5OnlineLookupPlans;
        var buffer: [64]u8 = undefined;
        const file = try self.dir.openFile(try name(plan.index, &buffer), .{});
        defer file.close();
        const pin = self.files[plan.index];
        if (try file.getEndPos() != pin.bytes) return error.UntrustedV5CounterFile;
        var read = RecordReader{ .file = file, .remaining = pin.bytes };
        if (try read.word() != 0x42354354 or try read.word() != 1 or try read.word() != tables.schema.KIND_COUNT) return error.UntrustedV5CounterFile;
        var counters = try tables.counter.Set.init(self.a);
        errdefer counters.deinit(self.a);
        for (&counters.counters, 0..) |*counter, index| {
            if (try read.word() != index or try read.wide() != counter.values.len) return error.UntrustedV5CounterFile;
            for (counter.values) |*value| {
                const canonical = try read.word();
                if (canonical >= core.fields.m31.Modulus) return error.UntrustedV5CounterFile;
                value.* = core.fields.m31.M31.fromCanonical(canonical);
            }
        }
        if (read.remaining != 0 or !std.meta.eql(read.hash.finalResult(), pin.sha256)) return error.UntrustedV5CounterFile;
        return counters;
    }
    pub fn prove(self: *Stage, comptime Backend: type, sink: batch.Sink, pins: seal.Pins, entries: []const seal.Entry, sealed: seal.Sealed) !void {
        return self.proveWithBoundary(Backend, sink, pins, entries, sealed, null);
    }
    pub fn proveWithBoundary(self: *Stage, comptime Backend: type, sink: batch.Sink, pins: seal.Pins, entries: []const seal.Entry, sealed: seal.Sealed, boundary: ?@import("block_v5_proof_boundary_v1.zig").Boundary) !void {
        if (!std.meta.eql(self.config, pins.config)) return error.UntrustedV5OnlineLookupConfig;
        const adapter = batch.ForBackend(Backend){ .records = self.records, .config = self.config };
        try adapter.proveWithBoundary(self.a, self.source(), sink, sealed, pins, entries, boundary);
    }
};

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const Api = proof.ForBackend(Backend);
        a: std.mem.Allocator,
        dir: std.fs.Dir,
        config: core.pcs.PcsConfig,
        limits: Limits,
        basis: ?Api.FixedBasis = null,
        current: ?tables.counter.Set = null,
        plan: planning.Plan = .{ .index = 0, .first_execution = 0, .execution_count = 0, .max_requests = @splat(0) },
        total_demand: u64 = 0,
        next_execution: u32 = 0,
        file_bytes: u64 = 0,
        records: std.ArrayList(batch.Record),
        files: std.ArrayList(FilePin),
        failed: bool = false,
        finished: bool = false,
        pub fn init(a: std.mem.Allocator, dir: std.fs.Dir, config: core.pcs.PcsConfig, limits: Limits) !Self {
            const bytes = try std.math.mul(usize, limits.max_groups, @sizeOf(batch.Record) + @sizeOf(FilePin));
            if (limits.request_limit == 0 or limits.request_limit >= core.fields.m31.Modulus or limits.max_groups == 0 or limits.max_groups > std.math.maxInt(u32) or bytes > limits.max_metadata_bytes) return error.InvalidV5OnlineLookupLimits;
            var records = try std.ArrayList(batch.Record).initCapacity(a, limits.max_groups);
            errdefer records.deinit(a);
            const files = try std.ArrayList(FilePin).initCapacity(a, limits.max_groups);
            return .{ .a = a, .dir = dir, .config = config, .limits = limits, .records = records, .files = files };
        }
        pub fn deinit(self: *Self) void {
            if (self.current) |*counter| counter.deinit(self.a);
            if (self.basis) |*basis| basis.deinit(self.a);
            self.records.deinit(self.a);
            self.files.deinit(self.a);
            self.* = undefined;
        }
        /// The caller supplies one execution's real native/caller/byte counters
        /// and independent admitted demand. Ownership remains with the caller.
        pub fn addExecution(self: *Self, index: u32, demand: Demand, counters: *const tables.counter.Set) !void {
            if (self.failed or self.finished or index != self.next_execution) return error.InvalidV5OnlineLookupOrder;
            errdefer self.failed = true;
            var total: u64 = 0;
            for (demand) |count| total = try std.math.add(u64, total, count);
            if (total > self.limits.request_limit) return error.BlockV5LookupGroupExceedsField;
            // Validate centered mass per execution before merging modulo M31.
            for (&counters.counters, demand, 0..) |*counter, bound, kind| {
                if (@intFromEnum(counter.kind) != kind or counter.values.len != tables.schema.size(counter.kind)) return error.InvalidBlockV5NativeLookupCounter;
                var mass: u64 = 0;
                for (counter.values) |value| {
                    if (value.v >= core.fields.m31.Modulus) return error.NonCanonicalM31;
                    mass = try std.math.add(u64, mass, @min(value.v, core.fields.m31.Modulus - value.v));
                }
                if (mass > bound) return error.BlockV5NativeLookupDemandExceeded;
            }
            if (self.plan.execution_count != 0 and total > self.limits.request_limit - self.total_demand) try self.flush();
            if (self.current == null) self.current = try tables.counter.Set.init(self.a);
            self.current.?.mergeFrom(counters);
            try planning.addDemand(&self.plan.max_requests, demand);
            self.total_demand += total;
            self.plan.execution_count = try std.math.add(u32, self.plan.execution_count, 1);
            self.next_execution = try std.math.add(u32, self.next_execution, 1);
        }
        fn flush(self: *Self) !void {
            if (self.plan.execution_count == 0 or self.records.items.len >= self.limits.max_groups) return error.V5OnlineLookupResourceLimit;
            if (self.basis == null) self.basis = try Api.FixedBasis.init(self.a, self.config);
            var first = try Api.commitFirstRoundWithBasis(self.a, &self.current.?, self.plan, &self.basis.?);
            defer first.deinit(self.a);
            var buffer: [64]u8 = undefined;
            const filename = try name(self.plan.index, &buffer);
            const file = try self.dir.createFile(filename, .{ .exclusive = true });
            defer file.close();
            errdefer self.dir.deleteFile(filename) catch {};
            var output = RecordWriter{ .file = file, .maximum = self.limits.max_counter_file_bytes - self.file_bytes };
            try output.word(0x42354354);
            try output.word(1);
            try output.word(tables.schema.KIND_COUNT);
            for (&self.current.?.counters, 0..) |*counter, index| {
                try output.word(@intCast(index));
                try output.wide(counter.values.len);
                for (counter.values) |value| try output.word(value.toU32());
            }
            try output.flush();
            try file.sync();
            self.records.appendAssumeCapacity(.{ .plan = self.plan, .roots = first.roots });
            self.files.appendAssumeCapacity(.{ .sha256 = output.hash.finalResult(), .bytes = output.written });
            self.file_bytes = try std.math.add(u64, self.file_bytes, output.written);
            self.current.?.deinit(self.a);
            self.current = null;
            self.plan = .{ .index = @intCast(self.records.items.len), .first_execution = self.next_execution, .execution_count = 0, .max_requests = @splat(0) };
            self.total_demand = 0;
        }
        pub fn finish(self: *Self, execution_count: u32) !Stage {
            if (self.failed or self.finished or execution_count == 0 or self.next_execution != execution_count) return error.IncompleteV5OnlineLookupGroups;
            errdefer self.failed = true;
            try self.flush();
            const records = try self.records.toOwnedSlice(self.a);
            errdefer self.a.free(records);
            const files = try self.files.toOwnedSlice(self.a);
            if (self.basis) |*basis| basis.deinit(self.a);
            self.basis = null;
            self.finished = true;
            return .{ .a = self.a, .dir = self.dir, .records = records, .files = files, .execution_count = execution_count, .config = self.config };
        }
    };
}
const RecordWriter = struct {
    file: std.fs.File,
    maximum: u64,
    written: u64 = 0,
    hash: std.crypto.hash.sha2.Sha256 = .init(.{}),
    buffer: [8192]u8 = undefined,
    used: usize = 0,
    fn append(self: *RecordWriter, data: []const u8) !void {
        const next = try std.math.add(u64, self.written, data.len);
        if (next > self.maximum) return error.V5OnlineLookupResourceLimit;
        if (self.used + data.len > self.buffer.len) try self.flush();
        @memcpy(self.buffer[self.used..][0..data.len], data);
        self.used += data.len;
        self.hash.update(data);
        self.written = next;
    }
    fn word(self: *RecordWriter, value: u32) !void {
        var data: [4]u8 = undefined;
        std.mem.writeInt(u32, &data, value, .little);
        try self.append(&data);
    }
    fn wide(self: *RecordWriter, value: u64) !void {
        var data: [8]u8 = undefined;
        std.mem.writeInt(u64, &data, value, .little);
        try self.append(&data);
    }
    fn flush(self: *RecordWriter) !void {
        try self.file.writeAll(self.buffer[0..self.used]);
        self.used = 0;
    }
};
const RecordReader = struct {
    file: std.fs.File,
    remaining: u64,
    offset: u64 = 0,
    hash: std.crypto.hash.sha2.Sha256 = .init(.{}),
    buffer: [8192]u8 = undefined,
    used: usize = 0,
    at: usize = 0,
    fn bytes(self: *RecordReader, comptime count: usize) ![count]u8 {
        if (self.remaining < count) return error.UntrustedV5CounterFile;
        var result: [count]u8 = undefined;
        var written: usize = 0;
        while (written < count) {
            if (self.at == self.used) {
                self.used = @intCast(@min(self.remaining, @as(u64, self.buffer.len)));
                if (try self.file.preadAll(self.buffer[0..self.used], self.offset) != self.used) return error.UntrustedV5CounterFile;
                self.offset += self.used;
                self.at = 0;
            }
            const take = @min(count - written, self.used - self.at);
            @memcpy(result[written..][0..take], self.buffer[self.at..][0..take]);
            self.at += take;
            self.remaining -= take;
            written += take;
        }
        self.hash.update(&result);
        return result;
    }
    fn word(self: *RecordReader) !u32 {
        return std.mem.readInt(u32, &(try self.bytes(4)), .little);
    }
    fn wide(self: *RecordReader) !u64 {
        return std.mem.readInt(u64, &(try self.bytes(8)), .little);
    }
};
