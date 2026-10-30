//! Local lowering equivalence/hostile tests. No complete proof authority.
const std = @import("std");
const A = @import("abi.zig");
const R = @import("relations.zig");
const P = @import("projection.zig");
const W = @import("writer.zig");
const Arithmetic = @import("arithmetic.zig");
const LS = @import("load_store.zig");
const Local = @import("spec_test.zig");
const Residual = struct { value: A.M, degree: u8 };
const EquationRecorder = struct {
    items: [128]Residual = undefined,
    len: usize = 0,
    pub fn add(self: *@This(), value: A.M, degree: u8) void {
        std.debug.assert(self.len < self.items.len);
        self.items[self.len] = .{ .value = value, .degree = degree };
        self.len += 1;
    }
};
const Event = struct { domain: R.Domain, multiplicity: A.M, fields: [5]A.M, len: usize };
const EventRecorder = struct {
    items: [64]Event = undefined,
    len: usize = 0,
    fn record(self: *@This(), domain: R.Domain, multiplicity: A.M, fields: anytype) void {
        std.debug.assert(self.len < self.items.len and fields.len <= 5);
        var event: Event = .{ .domain = domain, .multiplicity = multiplicity, .fields = @splat(A.M.zero()), .len = fields.len };
        for (fields, 0..) |field, i| event.fields[i] = field;
        self.items[self.len] = event;
        self.len += 1;
    }
    pub fn access(self: *@This(), comptime domain: R.Domain, multiplicity: A.M, tuple: R.Tuple(A.M)) void {
        self.record(domain, multiplicity, tuple.fields());
    }
    pub fn clock(self: *@This(), previous: A.M, current: A.M, active: A.M) void {
        self.record(.clock_order, active, [2]A.M{ previous, current });
    }
    pub fn range16(self: *@This(), active: A.M, value: A.M) void {
        self.record(.range16, active, [1]A.M{value});
    }
    pub fn range8_8(self: *@This(), active: A.M, value: [2]A.M) void {
        self.record(.range8_8, active, value);
    }
    pub fn bitwise(self: *@This(), active: A.M, op: u32, value: [3]A.M) void {
        self.record(.bitwise_byte, active, [4]A.M{ A.c(A.M, op), value[0], value[1], value[2] });
    }
    pub fn cpu(self: *@This(), active: A.M, values: [2]A.M) void {
        self.record(.cpu, active, values);
    }
    pub fn rom(self: *@This(), active: A.M, pc: A.M, op: u32, rd: A.M, rs1: A.M, operand: A.M) void {
        self.record(.rom_signed_imm, active, [5]A.M{ pc, A.c(A.M, op), rd, rs1, operand });
    }
};
fn honest(comptime profile: P.Profile) !P.Semantic(A.M, profile) {
    const base: W.Read = .{ .address = 1, .previous_clock = 0, .value = 0x4000 };
    const source: W.Read = .{ .address = 2, .previous_clock = 0, .value = 0x89abcdef };
    const destination: W.Destination = .{ .address = 3, .previous_clock = 0, .before = 0x22222222 };
    return switch (profile) {
        .add => W.arithmetic(.add, 1, 0x2000, base, source, destination, .{}),
        .sub => W.arithmetic(.sub, 1, 0x2000, base, source, destination, .{}),
        .addi => W.addi(1, 0x2000, base, destination, -1, .{}),
        .lw => W.load(.lw, 1, 0x2000, base, destination, 0, .{ .previous_clock = 0, .before = 0x12345678 }, .{ .address = 0x8000 }, .{}),
        .sw => W.store(.sw, 1, 0x2000, base, source, 0, .{ .previous_clock = 0, .before = 0x12345678 }, .{ .address = 0x8000 }, .{}),
    };
}
fn original(comptime profile: P.Profile, row: P.Semantic(A.M, profile), equations: anytype, events: anytype) void {
    switch (profile) {
        .add => Arithmetic.register(A.M, .add, row, A.M.one(), equations, events),
        .sub => Arithmetic.register(A.M, .sub, row, A.M.one(), equations, events),
        .addi => Arithmetic.immediate(A.M, row, A.M.one(), equations, events),
        .lw => LS.load(A.M, .lw, row, A.M.one(), .{ .address = 0x8000 }, equations, events),
        .sw => LS.store(A.M, .sw, row, A.M.one(), .{ .address = 0x8000 }, equations, events),
    }
}
fn fixed() P.Fixed(A.M) {
    return .{ .active_prefix = A.M.one(), .domain_first = A.M.one(), .domain_last = A.M.one() };
}
test "word16 compact source-only honest lowering preserves every residual degree and event" {
    inline for (comptime std.meta.tags(P.Profile)) |profile| {
        const semantic = try honest(profile);
        const compact = try P.pack(profile, semantic);
        try std.testing.expectEqualDeep(semantic, P.expand(A.M, profile, compact));
        var original_eq: EquationRecorder = .{};
        var compact_eq: EquationRecorder = .{};
        var original_events: EventRecorder = .{};
        var compact_events: EventRecorder = .{};
        original(profile, semantic, &original_eq, &original_events);
        P.evaluate(A.M, profile, compact, fixed(), .{ .address = 0x8000 }, &compact_eq, &compact_events);
        try std.testing.expectEqualDeep(original_eq.items[0..original_eq.len], compact_eq.items[0..compact_eq.len]);
        try std.testing.expectEqualDeep(original_events.items[0..original_events.len], compact_events.items[0..compact_events.len]);
        try std.testing.expectEqual(@as(usize, P.inventory(profile).main), compact.len);
        try std.testing.expectEqual(@as(usize, P.inventory(profile).semantic_residuals), compact_eq.len);
        var checks: Local.Checks = .{};
        var events: Local.Events = .{};
        P.evaluate(A.M, profile, compact, fixed(), .{ .address = 0x8000 }, &checks, &events);
        try std.testing.expect(!checks.bad and !events.bad);
    }
}
test "word16 compact source-only rejects actual committed x0 and halt mutations without packer" {
    var add = try P.pack(.add, try honest(.add));
    add[2] = A.M.zero();
    add[18] = A.M.zero();
    add[19] = A.M.zero();
    add[6] = A.M.one();
    var checks: Local.Checks = .{};
    var events: Local.Events = .{};
    P.evaluate(A.M, .add, add, fixed(), .{ .address = 0x8000 }, &checks, &events);
    try std.testing.expect(checks.bad);
    var store = try P.pack(.sw, try honest(.sw));
    store[3] = A.c(A.M, 0x8000);
    store[4] = A.M.zero();
    store[7] = A.M.one();
    store[8] = A.M.zero();
    store[14] = A.c(A.M, 0x2000);
    store[15] = A.M.zero();
    store[16] = A.M.one();
    store[17] = A.M.zero();
    checks = .{};
    events = .{};
    P.evaluate(A.M, .sw, store, fixed(), .{ .address = 0x8000 }, &checks, &events);
    try std.testing.expect(checks.bad);
}
test "word16 compact source-only range provider rejects inverse-quarter mutation without packer" {
    var load = try P.pack(.lw, try honest(.lw));
    load[9] = A.M.one();
    load[10] = A.M.zero();
    load[16] = try A.c(A.M, 4).inv();
    load[17] = A.M.zero();
    load[20] = A.M.zero();
    load[21] = try A.M.one().sub(A.c(A.M, 0x8000)).inv();
    var checks: Local.Checks = .{};
    var events: Local.Events = .{};
    P.evaluate(A.M, .lw, load, fixed(), .{ .address = 0x8000 }, &checks, &events);
    try std.testing.expect(!checks.bad);
    try std.testing.expect(events.bad);
}
test "word16 compact source-only host pack hygiene never substitutes for AIR" {
    var load = try honest(.lw);
    load.result.lo = load.result.lo.add(A.M.one());
    try std.testing.expectError(error.NoncanonicalWord16Projection, P.pack(.lw, load));
    var stored = try honest(.sw);
    stored.memory.after.hi = stored.memory.after.hi.add(A.M.one());
    try std.testing.expectError(error.NoncanonicalWord16Projection, P.pack(.sw, stored));
}
test "word16 compact source-only final matrix owns only compact columns and fixed padding" {
    var matrix = try P.Matrix(.lw).init(std.testing.allocator, 2, .{});
    defer matrix.deinit();
    const cells = try P.pack(.lw, try honest(.lw));
    try matrix.append(cells);
    try std.testing.expectError(error.UnsealedWord16Projection, matrix.column(0));
    try matrix.seal();
    try std.testing.expectEqual(@as(usize, 44), matrix.storage.len);
    for (cells, 0..) |value, i| {
        const column = try matrix.column(i);
        try std.testing.expectEqualDeep(value, column[0]);
        try std.testing.expect(column[1].isZero());
    }
    var padded: P.Cells(A.M, .lw) = undefined;
    for (&padded, 0..) |*value, i| value.* = (try matrix.column(i))[1];
    var checks: Local.Checks = .{};
    var events: Local.Events = .{};
    P.evaluate(A.M, .lw, padded, try matrix.fixedAt(1), .{ .address = 0x8000 }, &checks, &events);
    try std.testing.expect(!checks.bad and !events.bad);
    try std.testing.expectError(error.SealedWord16Projection, matrix.append(cells));
}
test "word16 compact source-only aliased register access chains retain ordered ports" {
    inline for (.{ P.Profile.add, P.Profile.sub }) |profile| {
        const semantic = try W.arithmetic(if (profile == .add) .add else .sub, 1, 0x2000, .{ .address = 1, .previous_clock = 0, .value = 7 }, .{ .address = 1, .previous_clock = 1, .value = 7 }, .{ .address = 1, .previous_clock = 2, .before = 7 }, .{});
        const cells = try P.pack(profile, semantic);
        var checks: Local.Checks = .{};
        var events: Local.Events = .{};
        P.evaluate(A.M, profile, cells, fixed(), .{ .address = 0x8000 }, &checks, &events);
        try std.testing.expect(!checks.bad and !events.bad);
        var recorder: EventRecorder = .{};
        P.evaluate(A.M, profile, cells, fixed(), .{ .address = 0x8000 }, &checks, &recorder);
        var registers: [6]Event = undefined;
        var count: usize = 0;
        for (recorder.items[0..recorder.len]) |event| if (event.domain == .register_word) {
            registers[count] = event;
            count += 1;
        };
        try std.testing.expectEqual(@as(usize, 6), count);
        // Internal read→read→write edges cancel exactly for rs1=rs2=rd.
        // External initial/final register closure is still OPEN in this test.
        try std.testing.expectEqualDeep(registers[1].fields, registers[2].fields);
        try std.testing.expectEqualDeep(registers[3].fields, registers[4].fields);
        try std.testing.expect(registers[1].multiplicity.add(registers[2].multiplicity).isZero());
        try std.testing.expect(registers[3].multiplicity.add(registers[4].multiplicity).isZero());
        try std.testing.expectEqual(@as(u32, 3), registers[5].fields[1].v);
    }
    const addi = try P.pack(.addi, try W.addi(1, 0x2000, .{ .address = 1, .previous_clock = 0, .value = 7 }, .{ .address = 1, .previous_clock = 1, .before = 7 }, -1, .{}));
    var checks: Local.Checks = .{};
    var events: Local.Events = .{};
    P.evaluate(A.M, .addi, addi, fixed(), .{ .address = 0x8000 }, &checks, &events);
    try std.testing.expect(!checks.bad and !events.bad);
    const load = try P.pack(.lw, try W.load(.lw, 1, 0x2000, .{ .address = 1, .previous_clock = 0, .value = 0x4000 }, .{ .address = 1, .previous_clock = 1, .before = 0x4000 }, 0, .{ .previous_clock = 0, .before = 7 }, .{ .address = 0x8000 }, .{}));
    checks = .{};
    events = .{};
    P.evaluate(A.M, .lw, load, fixed(), .{ .address = 0x8000 }, &checks, &events);
    try std.testing.expect(!checks.bad and !events.bad);
    const store = try P.pack(.sw, try W.store(.sw, 1, 0x2000, .{ .address = 1, .previous_clock = 0, .value = 0x4000 }, .{ .address = 1, .previous_clock = 1, .value = 0x4000 }, 0, .{ .previous_clock = 0, .before = 7 }, .{ .address = 0x8000 }, .{}));
    checks = .{};
    events = .{};
    P.evaluate(A.M, .sw, store, fixed(), .{ .address = 0x8000 }, &checks, &events);
    try std.testing.expect(!checks.bad and !events.bad);
}
test "word16 compact source-only LW to x0 retains RAM read and forces zero destination" {
    var load = try P.pack(.lw, try W.load(.lw, 1, 0x2000, .{ .address = 1, .previous_clock = 0, .value = 0x4000 }, .{ .address = 0, .previous_clock = 0, .before = 0 }, 0, .{ .previous_clock = 0, .before = 0xffffffff }, .{ .address = 0x8000 }, .{}));
    var checks: Local.Checks = .{};
    var events: Local.Events = .{};
    P.evaluate(A.M, .lw, load, fixed(), .{ .address = 0x8000 }, &checks, &events);
    try std.testing.expect(!checks.bad and !events.bad);
    const semantic = P.expand(A.M, .lw, load);
    try std.testing.expectEqual(@as(u32, 65535), semantic.memory.value.lo.v);
    try std.testing.expect(semantic.destination.after.lo.isZero() and semantic.destination.after.hi.isZero());
    // Direct compact-cell mutant; no host packer can reject it for us.
    load[6] = A.M.one();
    checks = .{};
    events = .{};
    P.evaluate(A.M, .lw, load, fixed(), .{ .address = 0x8000 }, &checks, &events);
    try std.testing.expect(checks.bad);
}
test "word16 compact source-only native terminal halt permission is exact-cycle only" {
    const terminal: LS.Halt = .{ .address = 0x4000, .permitted_native_cycle = 7 };
    const store = try P.pack(.sw, try W.store(.sw, 7, 0x2000, .{ .address = 1, .previous_clock = 0, .value = 0x4000 }, .{ .address = 2, .previous_clock = 0, .value = 1 }, 0, .{ .previous_clock = 0, .before = 0 }, terminal, .{}));
    var checks: Local.Checks = .{};
    var events: Local.Events = .{};
    P.evaluate(A.M, .sw, store, fixed(), terminal, &checks, &events);
    try std.testing.expect(!checks.bad and !events.bad);
    // This permits the exact access, not a claim that final output/completion
    // is proved. A separately admitted full terminal boundary is mandatory.
    checks = .{};
    events = .{};
    P.evaluate(A.M, .sw, store, fixed(), .{ .address = 0x4000, .permitted_native_cycle = 6 }, &checks, &events);
    try std.testing.expect(checks.bad);
    checks = .{};
    events = .{};
    P.evaluate(A.M, .sw, store, fixed(), .{ .address = 0x4000 }, &checks, &events);
    try std.testing.expect(checks.bad);
}
test "word16 compact source-only every inactive committed slot is constrained" {
    inline for (comptime std.meta.tags(P.Profile)) |profile| {
        for (0..P.names(profile).len) |slot| {
            var cells: P.Cells(A.M, profile) = @splat(A.M.zero());
            cells[slot] = A.M.one();
            var checks: Local.Checks = .{};
            var events: Local.Events = .{};
            P.evaluate(A.M, profile, cells, .{ .active_prefix = A.M.zero(), .domain_first = A.M.one(), .domain_last = A.M.one() }, .{ .address = 0x8000 }, &checks, &events);
            try std.testing.expect(checks.bad);
        }
    }
}
