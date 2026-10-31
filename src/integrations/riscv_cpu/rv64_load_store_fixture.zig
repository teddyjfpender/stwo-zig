//! Native observed RAM supplies untrusted witness only; expected image, decoded
//! requests and terminal state are independently supplied to the receiver.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const R = front.rv64_air.memory.closed_ram;
const X = front.rv64_air.memory.load_store_v1;
const P = @import("rv64_load_store_public.zig");
const Bound = @import("rv64_closed_ram_fixture.zig");
const L = X.layout;
const M = core.fields.m31.M31;
pub const Fixture = struct {
    allocator: std.mem.Allocator,
    ls: [2]X.trace.Trace,
    boundary: [2]R.trace.Trace,
    owner: X.trace.Trace,
    range: [2]R.trace.Trace,
    selection: X.trace.Trace,
    pub fn initGeometry(a: std.mem.Allocator, expected: P.Expected) !Fixture {
        try expected.validate();
        var self: Fixture = undefined;
        self.allocator = a;
        var built: usize = 0;
        errdefer {
            if (built >= 8) self.selection.deinit();
            if (built >= 7) self.range[1].deinit();
            if (built >= 6) self.range[0].deinit();
            if (built >= 5) self.owner.deinit();
            if (built >= 4) self.boundary[1].deinit();
            if (built >= 3) self.boundary[0].deinit();
            if (built >= 2) self.ls[1].deinit();
            if (built >= 1) self.ls[0].deinit();
        }
        self.ls[0] = try X.trace.Trace.init(a, .ls, 6, expected.split);
        built += 1;
        self.ls[1] = try X.trace.Trace.init(a, .ls, 7, @intCast(expected.operations.len - expected.split));
        built += 1;
        self.boundary[0] = try R.trace.Trace.init(a, .initial, 5, @intCast(expected.initial.len));
        built += 1;
        self.boundary[1] = try R.trace.Trace.init(a, .terminal, 5, @intCast(expected.terminal.len));
        built += 1;
        self.owner = try X.trace.Trace.init(a, .owner, 6, @intCast(expected.operations.len));
        built += 1;
        self.range[0] = try R.trace.Trace.init(a, .range16, 16, 0);
        built += 1;
        self.range[1] = try R.trace.Trace.init(a, .range8, 8, 0);
        built += 1;
        self.selection = try X.trace.Trace.init(a, .selection, 16, 0);
        built += 1;
        Bound.boundary(&self.boundary[0], expected.initial);
        Bound.boundary(&self.boundary[1], expected.terminal);
        self.owner.bindPublic(try ownerRows(expected));
        return self;
    }
    pub fn init(a: std.mem.Allocator, expected: P.Expected) !Fixture {
        var self = try initGeometry(a, expected);
        errdefer self.deinit();
        var memory = front.rv64.memory.Memory.init(a, .{});
        defer memory.deinit();
        const states = try a.alloc(R.types.State, expected.initial.len);
        defer a.free(states);
        for (expected.initial, states) |cell, *state| {
            state.* = cell.state;
            try memory.map(.{ .start = cell.address, .size = 8, .permissions = .{ .read = cell.state.rights & 1 != 0, .write = cell.state.rights & 2 != 0 } });
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, cell.state.value, .little);
            try memory.initialize(cell.address, &bytes);
        }
        for (expected.operations, 0..) |op, index| {
            const d = try P.describe(op.instruction);
            const ea = op.a +% d.immediate;
            const address = ea & ~@as(u64, 7);
            const ci = try expected.cellIndex(address);
            const before = states[ci];
            const observed = if (d.write) try memory.storeObserved(ea, d.width, op.b) else try memory.loadObserved(ea, d.width);
            var row: [L.MAIN]M = @splat(M.zero());
            row[0] = M.one();
            row[1] = M.fromCanonical(@intFromBool(d.write));
            row[2] = M.fromCanonical(@intFromBool(before.epoch == op.epoch));
            row[3] = M.fromCanonical(op.id);
            R.trace.word(row[4..], address);
            row[8] = M.fromCanonical(before.epoch);
            row[9] = M.fromCanonical(op.epoch);
            row[10] = M.fromCanonical(@as(u16, @truncate(before.tick)));
            row[11] = M.fromCanonical(before.tick >> 16);
            row[12] = M.fromCanonical(@as(u16, @truncate(op.tick)));
            row[13] = M.fromCanonical(op.tick >> 16);
            R.trace.word(row[14..], observed.before_word);
            R.trace.word(row[18..], observed.after_word);
            row[22] = M.fromCanonical(before.rights & 1);
            row[23] = M.fromCanonical(before.rights >> 1);
            if (before.epoch == op.epoch) {
                if (op.tick <= before.tick) return error.InvalidLoadStoreNativeOrder;
                const gap = op.tick - before.tick - 1;
                row[25] = M.fromCanonical(@as(u16, @truncate(gap)));
                row[26] = M.fromCanonical(gap >> 16);
                row[27] = M.fromCanonical((@as(u32, @as(u16, @truncate(before.tick))) + @as(u16, @truncate(gap)) + 1) >> 16);
            } else {
                if (op.epoch <= before.epoch) return error.InvalidLoadStoreNativeOrder;
                row[24] = M.fromCanonical(op.epoch - before.epoch - 1);
            }
            R.trace.word(row[L.a..], op.a);
            R.trace.word(row[L.immediate..], d.immediate);
            R.trace.word(row[L.b..], op.b);
            R.trace.word(row[L.c..], op.c);
            R.trace.word(row[L.effective..], ea);
            row[L.opcode] = M.fromCanonical(@intFromEnum(d.opcode));
            row[L.flags + d.flag] = M.one();
            const offset: usize = @intCast(ea & 7);
            row[L.offsets + offset] = M.one();
            row[L.quotient] = M.fromCanonical(@as(u16, @truncate(address)) / 8);
            const top = offset / 2 + (if (d.width == 1) 0 else d.width / 2 - 1);
            const selected: u16 = @truncate(observed.before_word >> @as(u6, @intCast(16 * top)));
            const tuple = X.selection.fact(2 * @as(usize, selected) + (offset & 1));
            row[L.selected_limb] = M.fromCanonical(selected);
            row[L.selected_byte] = M.fromCanonical(tuple[2]);
            row[L.selected_sign] = M.fromCanonical(tuple[3]);
            row[L.limb_sign] = M.fromCanonical(tuple[4]);
            row[L.b_low] = M.fromCanonical(@as(u8, @truncate(op.b)));
            row[L.b_high] = M.fromCanonical(@as(u8, @truncate(op.b >> 8)));
            var carry: u32 = 0;
            for (0..4) |c| {
                carry = (row[L.a + c].v + row[L.immediate + c].v + carry) >> 16;
                row[L.address_carries + c] = M.fromCanonical(carry);
            }
            const shard: usize = if (index < expected.split) 0 else 1;
            self.ls[shard].put(if (shard == 0) index else index - expected.split, &row);
            states[ci] = .{ .value = observed.after_word, .epoch = op.epoch, .tick = op.tick, .rights = before.rights };
        }
        try self.recount();
        return self;
    }
    pub fn deinit(self: *Fixture) void {
        for (&self.ls) |*t| t.deinit();
        for (&self.boundary) |*t| t.deinit();
        self.owner.deinit();
        for (&self.range) |*t| t.deinit();
        self.selection.deinit();
        self.* = undefined;
    }
    pub fn recount(self: *Fixture) !void {
        const c16 = try self.allocator.alloc(u64, 65536);
        defer self.allocator.free(c16);
        @memset(c16, 0);
        const select = try self.allocator.alloc(u64, X.selection.SIZE);
        defer self.allocator.free(select);
        @memset(select, 0);
        var c8: [256]u64 = @splat(0);
        for (&self.ls) |*trace| trace.count(c16, &c8, select);
        for (&self.boundary) |*trace| trace.countRanges(c16, &c8);
        try self.range[0].setCounts(c16);
        try self.range[1].setCounts(&c8);
        try self.selection.setCounts(select);
    }
    pub fn columns(self: *const Fixture, tree: u2) ![]engine.pcs.ColumnEvaluation {
        const spans = switch (tree) {
            0 => [_][]const M{ self.ls[0].fixed, self.ls[1].fixed, self.boundary[0].fixed, self.boundary[1].fixed, self.owner.fixed, self.range[0].fixed, self.range[1].fixed, self.selection.fixed },
            1 => [_][]const M{ self.ls[0].main, self.ls[1].main, self.boundary[0].main, self.boundary[1].main, self.owner.main, self.range[0].main, self.range[1].main, self.selection.main },
            2 => [_][]const M{ self.ls[0].interaction, self.ls[1].interaction, self.boundary[0].interaction, self.boundary[1].interaction, self.owner.interaction, self.range[0].interaction, self.range[1].interaction, self.selection.interaction },
            else => return error.InvalidLoadStoreTree,
        };
        const logs = [_]u32{ 6, 7, 5, 5, 6, 16, 8, 16 };
        var count: usize = 0;
        for (spans, logs) |span, log| count += span.len >> @intCast(log);
        const headers = try self.allocator.alloc(engine.pcs.ColumnEvaluation, count);
        var cursor: usize = 0;
        for (spans, logs) |span, log| {
            const n = @as(usize, 1) << @intCast(log);
            for (0..span.len / n) |c| {
                headers[cursor] = .{ .log_size = log, .values = span[c * n ..][0..n] };
                cursor += 1;
            }
        }
        return headers;
    }
    pub fn generate(self: *Fixture, ch: X.types.Challenges) ![8]X.types.Claims {
        const dummy = R.types.OwnerChallenges{ .offset = R.types.Q.zero(), .coefficients = @splat(R.types.Q.zero()) };
        const rc = R.types.Challenges{ .ram = ch.ram, .owner = dummy, .range16 = ch.range16, .range8 = ch.range8 };
        var result: [8]X.types.Claims = undefined;
        result[0] = try self.ls[0].generate(ch);
        result[1] = try self.ls[1].generate(ch);
        result[2] = convert(try self.boundary[0].generate(rc));
        result[3] = convert(try self.boundary[1].generate(rc));
        result[4] = try self.owner.generate(ch);
        result[5] = convert(try self.range[0].generate(rc));
        result[6] = convert(try self.range[1].generate(rc));
        result[7] = try self.selection.generate(ch);
        return result;
    }
};
fn convert(c: R.types.Claims) X.types.Claims {
    return .{ .ram = c.ram, .owner = c.owner, .range16 = c.range16, .range8 = c.range8, .selection = R.types.Q.zero() };
}

/// Public coefficients are derived ONLY from independently expected inputs;
/// the receiving process never executes memory loads/stores to derive them.
fn ownerRows(expected: P.Expected) !X.types.OwnerRows {
    var rows: X.types.OwnerRows = @splat(@splat(M.zero()));
    for (expected.operations, 0..) |op, i| {
        const d = try P.describe(op.instruction);
        rows[i][0] = M.fromCanonical(op.id);
        rows[i][1] = M.fromCanonical(@intFromEnum(d.opcode));
        R.trace.word(rows[i][2..], op.a);
        R.trace.word(rows[i][6..], d.immediate);
        R.trace.word(rows[i][10..], op.b);
        R.trace.word(rows[i][14..], op.c);
        rows[i][18] = M.fromCanonical(op.epoch);
        rows[i][19] = M.fromCanonical(@as(u16, @truncate(op.tick)));
        rows[i][20] = M.fromCanonical(op.tick >> 16);
        rows[i][21] = M.one();
    }
    return rows;
}
