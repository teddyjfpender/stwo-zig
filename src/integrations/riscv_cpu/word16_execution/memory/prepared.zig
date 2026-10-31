//! Concrete LS/INIT/TEARDOWN/selection owners for one shared PCS transaction.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const X = front.rv64_air.memory.load_store_v2;
const V1 = front.rv64_air.memory.load_store_v1;
const CPU = @import("../cpu_source.zig");
pub const public = @import("statement.zig");
const Collector = @import("collector.zig");
const Profile = @import("stwo_prover_api").stage_profile;
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    statement: public.Statement,
    ls: X.source.Source,
    initial: X.boundary_source.Source,
    terminal: X.boundary_source.Source,
    selection: X.selection_source.Source,
    counts16: []u64,
    counts8: []u64,
    pub fn init(a: std.mem.Allocator, image: public.Image, records: []const CPU.MemoryRecord, epoch: u16, ls_log: u32, boundary_log: u32) !Prepared {
        return initIndependent(a, image, records, epoch, ls_log, boundary_log, boundary_log);
    }
    pub fn initIndependent(a: std.mem.Allocator, image: public.Image, records: []const CPU.MemoryRecord, epoch: u16, ls_log: u32, initial_log: u32, terminal_log: u32) !Prepared {
        return initIndependentProfiled(a, image, records, epoch, ls_log, initial_log, terminal_log, null);
    }
    pub fn initIndependentProfiled(a: std.mem.Allocator, image: public.Image, records: []const CPU.MemoryRecord, epoch: u16, ls_log: u32, initial_log: u32, terminal_log: u32, recorder: ?*Profile.Recorder) !Prepared {
        const collected = blk: {
            var stage = try Profile.StageScope.begin(recorder, "source_memory_collect", "Collect expected memory boundaries");
            defer stage.end();
            break :blk try Collector.collect(a, image, records, epoch);
        };
        defer a.free(collected.events);
        errdefer {
            a.free(collected.initial);
            a.free(collected.terminal);
        }
        const statement = public.Statement{ .initial = collected.initial, .terminal = collected.terminal, .epoch = epoch, .ls_count = @intCast(records.len) };
        {
            var stage = try Profile.StageScope.begin(recorder, "source_memory_validate", "Validate constructed memory statement against expected image");
            defer stage.end();
            try statement.validate(image);
        }
        return fromRows(a, collected.events, statement, ls_log, initial_log, terminal_log, recorder);
    }
    /// Witness-only global path: consumes both boundary arrays on success/error.
    /// Genesis authority and aggregate closure belong to the NEW global receiver.
    pub fn initOwnedForGlobalRam(a: std.mem.Allocator, events: []const X.native.Event, initial: []const public.Cell, terminal: []const public.Cell, epoch: u16, ls_log: u32, boundary_log: u32) !Prepared {
        return initOwnedForGlobalRamIndependent(a, events, initial, terminal, epoch, ls_log, boundary_log, boundary_log);
    }
    pub fn initOwnedForGlobalRamIndependent(a: std.mem.Allocator, events: []const X.native.Event, initial: []const public.Cell, terminal: []const public.Cell, epoch: u16, ls_log: u32, initial_log: u32, terminal_log: u32) !Prepared {
        errdefer {
            a.free(initial);
            a.free(terminal);
        }
        const statement = public.Statement{ .initial = initial, .terminal = terminal, .epoch = epoch, .ls_count = @intCast(events.len) };
        return fromRows(a, events, statement, ls_log, initial_log, terminal_log, null);
    }
    fn fromRows(a: std.mem.Allocator, events: []const X.native.Event, statement: public.Statement, ls_log: u32, initial_log: u32, terminal_log: u32, recorder: ?*Profile.Recorder) !Prepared {
        var ls = blk: {
            var stage = try Profile.StageScope.begin(recorder, "source_memory_ls", "Ordinary LS witness");
            defer stage.end();
            break :blk try X.source.Source.init(a, events, ls_log);
        };
        errdefer ls.deinit();
        var initial = blk: {
            var stage = try Profile.StageScope.begin(recorder, "source_memory_initial", "Initial boundary witness");
            defer stage.end();
            break :blk try X.boundary_source.Source.init(a, .initial, statement.initial, initial_log);
        };
        errdefer initial.deinit();
        var terminal = blk: {
            var stage = try Profile.StageScope.begin(recorder, "source_memory_terminal", "Terminal boundary witness");
            defer stage.end();
            break :blk try X.boundary_source.Source.init(a, .terminal, statement.terminal, terminal_log);
        };
        errdefer terminal.deinit();
        var selection = blk: {
            var stage = try Profile.StageScope.begin(recorder, "source_memory_selection", "Memory selection multiplicities");
            defer stage.end();
            break :blk try X.selection_source.Source.init(a, ls.selection_counts);
        };
        errdefer selection.deinit();
        var count_stage = try Profile.StageScope.begin(recorder, "source_memory_range_counts", "Merge LS and boundary range histograms");
        defer count_stage.end();
        const counts16 = try a.dupe(u64, ls.counts16);
        errdefer a.free(counts16);
        const counts8 = try a.dupe(u64, ls.counts8);
        errdefer a.free(counts8);
        for ([_][]const u64{ initial.counts16, terminal.counts16 }) |input| for (counts16, input) |*out, v| {
            out.* = try std.math.add(u64, out.*, v);
            if (out.* >= @import("stwo_core").fields.m31.Modulus) return error.MemoryLookupMassExceeded;
        };
        for ([_][]const u64{ initial.counts8, terminal.counts8 }) |input| for (counts8, input) |*out, v| {
            out.* = try std.math.add(u64, out.*, v);
            if (out.* >= @import("stwo_core").fields.m31.Modulus) return error.MemoryLookupMassExceeded;
        };
        return .{ .allocator = a, .statement = statement, .ls = ls, .initial = initial, .terminal = terminal, .selection = selection, .counts16 = counts16, .counts8 = counts8 };
    }
    pub fn deinit(self: *Prepared) void {
        self.ls.deinit();
        self.initial.deinit();
        self.terminal.deinit();
        self.selection.deinit();
        self.allocator.free(self.counts16);
        self.allocator.free(self.counts8);
        self.allocator.free(self.statement.initial);
        self.allocator.free(self.statement.terminal);
        self.* = undefined;
    }
    pub fn releaseMain(self: *Prepared) void {
        self.ls.releaseMain();
        self.initial.releaseMain();
        self.terminal.releaseMain();
        self.selection.releaseMain();
    }
    pub fn validateStatement(image: public.Image, statement: public.Statement) !void {
        try statement.validate(image);
    }
    pub fn generate(self: *Prepared, ch: X.types.Challenges, dict16: []const X.types.Q, dict8: []const X.types.Q) ![4]X.types.Claims {
        return self.generateProfiled(ch, dict16, dict8, null);
    }
    pub fn generateProfiled(self: *Prepared, ch: X.types.Challenges, dict16: []const X.types.Q, dict8: []const X.types.Q, recorder: ?*Profile.Recorder) ![4]X.types.Claims {
        const ls = block: {
            var stage = try Profile.StageScope.begin(recorder, "inter_ls", "Load store interactions");
            defer stage.end();
            break :block try self.ls.generate(ch, dict16, dict8);
        };
        const initial = block: {
            var stage = try Profile.StageScope.begin(recorder, "inter_initial", "INIT interactions");
            defer stage.end();
            break :block try self.initial.generate(ch, dict16, dict8);
        };
        const terminal = block: {
            var stage = try Profile.StageScope.begin(recorder, "inter_terminal", "TEARDOWN interactions");
            defer stage.end();
            break :block try self.terminal.generate(ch, dict16, dict8);
        };
        const selection = block: {
            var stage = try Profile.StageScope.begin(recorder, "inter_selection", "Selection table interactions");
            defer stage.end();
            break :block try self.selection.generate(ch);
        };
        var authority_stage = try Profile.StageScope.begin(recorder, "inter_boundary_authority", "Independent public memory boundary claims");
        defer authority_stage.end();
        if (!initial.ram.eql(try X.boundary_source.expectedClaim(self.statement.initial, true, ch.ram)) or !terminal.ram.eql(try X.boundary_source.expectedClaim(self.statement.terminal, false, ch.ram))) return error.MemoryBoundaryClaimMismatch;
        return .{ ls, initial, terminal, selection };
    }
};
