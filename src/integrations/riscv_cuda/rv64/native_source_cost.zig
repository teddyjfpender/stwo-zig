//! UNQUALIFIED, UNCOMPILED draft native formatter allocation schedule. Sizes are
//! individual payloads, never summed before the caller's arena rounding.
//! Host payload/lifetime completion and runtime endpoint wiring are separate.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const A = @import("stwo_riscv_frontend").rv64_air;
const R = CPU.rv64_services_roster;
const T = CPU.rv64_services_types;
const Request = CPU.rv64_device_source_stage.Request;
const Inputs = CPU.rv64_family_input;
const Memory = CPU.rv64_memory_input;
pub const Phase = enum(u8) { cpu_projection, core, bridges, bulk, sponge, extensions, source_release, immutable_release };
pub const Owner = enum(u8) { cpu_projection, core, bridge, bulk_sponge, immutable };
pub const Allocation = struct { bytes: usize, start: Phase, end: Phase, owner: Owner, kind: u32 };
pub const Policy = struct {
    /// Must be frozen by the caller before preparing the request. Cold ROM is
    /// an explicit source branch, not an averaged cache-hit assumption.
    compact_ingress: bool,
    cold_rom: bool,
};
pub const Plan = struct {
    allocator: std.mem.Allocator,
    scope: CPU.rv64_device_pcs.Scope,
    allocations: std.ArrayList(Allocation) = .empty,
    device_complete: bool = false,
    host_complete: bool = false,
    cpu_steps: usize = 0,
    cpu_rows: usize = 0,
    rom_rows: usize = 0,
    pub fn deinit(self: *Plan) void {
        self.allocations.deinit(self.allocator);
        self.* = undefined;
    }
    fn add(self: *Plan, words: usize, start: Phase, end: Phase, owner: Owner, kind: u32) !void {
        try self.allocations.append(self.allocator, .{ .bytes = try std.math.mul(usize, @max(words, 1), 4), .start = start, .end = end, .owner = owner, .kind = kind });
    }
    pub fn activeBytes(self: *const Plan, phase: Phase) !usize {
        var total: usize = 0;
        for (self.allocations.items) |allocation| if (@intFromEnum(allocation.start) <= @intFromEnum(phase) and @intFromEnum(phase) < @intFromEnum(allocation.end)) {
            total = try std.math.add(usize, total, allocation.bytes);
        };
        return total;
    }
    pub fn activeAllocationBytes(self: *const Plan, a: std.mem.Allocator, phase: Phase) ![]usize {
        var result: std.ArrayList(usize) = .empty;
        errdefer result.deinit(a);
        for (self.allocations.items) |allocation| if (@intFromEnum(allocation.start) <= @intFromEnum(phase) and @intFromEnum(phase) < @intFromEnum(allocation.end)) try result.append(a, allocation.bytes);
        return result.toOwnedSlice(a);
    }
};
fn rows(log: u32) !usize {
    if (log < 5 or log > 24) return error.InvalidNativeSourceCost;
    return @as(usize, 1) << @intCast(log);
}
fn product(x: usize, y: usize) !usize {
    return std.math.mul(usize, x, y);
}
/// Draft constructor schedule for the two production contributors
/// bridge_witness and bulk_sponge, including extension owners. This is not
/// sufficient to mark a whole CPU stage known while host_complete is false.
pub fn derive(a: std.mem.Allocator, request: Request, policy: Policy) !Plan {
    if (request.ordinal >= request.advice.events.len or request.scope.ordinal != request.ordinal or !std.mem.allEqual(u8, &request.scope.main, 0)) return error.InvalidNativeSourceCost;
    const p = request.native;
    const cpu = p.cpu orelse return error.NativeSourceAlreadyConsumed;
    const g = request.setup.materials.geometry;
    try g.validate();
    if (!g.cpu_compact_decode or cpu.metadata.len != cpu.public.steps or g.cpu_log > 22) return error.InvalidNativeSourceCost;
    const splits = try CPU.rv64_native_provider_tails.validate(g, p);
    const ls = try g.lsCounts(request.request.base.memory.ls_count);
    var out = Plan{ .allocator = a, .scope = request.scope, .cpu_steps = cpu.metadata.len, .cpu_rows = try rows(g.cpu_log), .rom_rows = request.setup.materials.program.size() };
    errdefer out.deinit();
    const X = A.word16_execution;
    if (policy.cold_rom) try out.add(try product(X.layout.rom.FIXED, out.rom_rows), .cpu_projection, .immutable_release, .immutable, 2);
    const metadata_words = try product(cpu.metadata.len, @sizeOf(CPU.rv64_cpu_source.Metadata) / 4);
    const cpu_scratch = try std.math.add(usize, @max(metadata_words, 1), 65536 + 256 + out.rom_rows + 1 + 65536);
    try out.add(cpu_scratch, .cpu_projection, .source_release, .cpu_projection, 0);
    try out.add(try product(out.cpu_rows, X.layout.mainCount(true)), .cpu_projection, .source_release, .cpu_projection, 1);
    if (policy.compact_ingress) {
        const seeds = try std.math.divCeil(usize, cpu.metadata.len, 256);
        try out.add(try std.math.add(usize, try product(cpu.metadata.len, 4), try product(seeds, 96)), .cpu_projection, .core, .cpu_projection, 0);
    }
    try out.add(65536 + 256 + 65536 + 65536 + 16 * 65536 + 2 * 65536 + out.rom_rows + 1, .core, .source_release, .core, 0);
    if (p.multiplication.len != p.raw_counts.multiplication + 2 * p.division.len) return error.InvalidNativeSourceCost;
    try out.add(try product(p.multiplication.len, 8), .core, .source_release, .core, 0);
    try out.add(try product(p.division.len, 8), .core, .source_release, .core, 0);
    for (request.setup.materials.shapes()) |shape| {
        if (shape.widths[1] == 0 or shape.role == .cpu) continue;
        switch (shape.role) {
            .alu, .alu_tail => try out.add(try product(if (shape.role == .alu) splits.alu.head else splits.alu.tail, @sizeOf(Inputs.Fact) / 4), .core, .source_release, .core, 0),
            .binary, .binary_tail => try out.add(try product(if (shape.role == .binary) splits.binary.head else splits.binary.tail, @sizeOf(Inputs.Fact) / 4), .core, .source_release, .core, 0),
            .shift, .shift_tail => try out.add(try product(if (shape.role == .shift) splits.shift.head else splits.shift.tail, @sizeOf(Inputs.Fact) / 4), .core, .source_release, .core, 0),
            .jalr => try out.add(try product((p.jalr orelse return error.NativeSourceAlreadyConsumed).facts.len, @sizeOf(Inputs.Fact) / 4), .core, .source_release, .core, 0),
            .ls, .ls_tail => try out.add(try product(if (shape.role == .ls) ls.head else ls.tail, @sizeOf(Memory.Event) / 4), .core, .source_release, .core, 0),
            .initial, .terminal => try out.add(try product(if (shape.role == .initial) request.request.base.memory.initial.len else request.request.base.memory.terminal.len, @sizeOf(Memory.Cell) / 4), .core, .source_release, .core, 0),
            .division, .multiplication, .rom, .range16, .range8, .and_table, .shift_table, .selection => {},
            else => return error.UnknownNativeSourceCostRole,
        }
        try out.add(try product(try rows(shape.log), shape.widths[1]), .core, .source_release, .core, 1);
    }
    for (std.enums.values(T.Family), 0..) |family, index| if (request.setup.bridges.at(family)) |log| {
        const coordinates: usize = if (family == .keccak) 25 else 4 * A.crypto.secp256k1.word16_bridge.types.coordinates(T.bridgeKind(family));
        const stride = try std.math.add(usize, 4, try product(coordinates, 8));
        try out.add(try product(request.request.calls[index], stride), .bridges, .source_release, .bridge, 0);
        try out.add(try product(try rows(log), T.widths(family)[1]), .bridges, .source_release, .bridge, 1);
    };
    if (request.setup.bridges.bulk.any()) {
        const B = A.crypto.bulk_memory;
        const advice = request.advice.bulk[request.ordinal];
        var scans: usize = 0;
        for (advice.calls) |call| if (call.op == .jumpdest) {
            scans = try std.math.add(usize, scans, call.bodyRows());
        };
        try out.add(try product(advice.calls.len, 128 / 4), .bulk, .source_release, .bulk_sponge, 0);
        try out.add(try product(advice.words.len, 32 / 4), .bulk, .source_release, .bulk_sponge, 0);
        try out.add(scans, .bulk, .source_release, .bulk_sponge, 0);
        try out.add(8448, .bulk, .source_release, .bulk_sponge, 0);
        for (T.bulk_kinds) |kind| if (request.setup.bridges.bulk.at(kind)) |log| {
            const n = B.source.Source.rowsFor(kind, advice.calls);
            try out.add(try product(n, 16 / 4), .bulk, .source_release, .bulk_sponge, 0);
            try out.add(try product(try rows(log), B.layout.main(kind)), .bulk, .source_release, .bulk_sponge, 1);
        };
    }
    if (request.setup.bridges.sponge.any()) {
        const S = A.crypto.keccak_sponge;
        const advice = request.advice.sponge[request.ordinal];
        try out.add(try product(advice.calls.len, 488 / 4), .sponge, .source_release, .bulk_sponge, 0);
        try out.add(try product(advice.words.len, 16 / 4), .sponge, .source_release, .bulk_sponge, 0);
        try out.add(try product(advice.inputs.len, 50), .sponge, .source_release, .bulk_sponge, 0);
        try out.add(try product(advice.inputs.len, 50), .sponge, .source_release, .bulk_sponge, 0);
        for (T.sponge_kinds) |kind| if (request.setup.bridges.sponge.at(kind)) |log| {
            const n = if (kind == .call) advice.calls.len else advice.inputs.len;
            try out.add(try product(n, 16 / 4), .sponge, .source_release, .bulk_sponge, 0);
            try out.add(try product(try rows(log), S.layout.main(kind)), .sponge, .source_release, .bulk_sponge, 1);
        };
    }
    if (request.setup.bridges.zbb) |log| {
        try out.add(try product(p.zbb.facts.len, @sizeOf(Inputs.Fact) / 4), .extensions, .source_release, .core, 0);
        try out.add(try product(try rows(log), A.word16_v1.binary_zbb_source.MAIN), .extensions, .source_release, .core, 1);
    }
    const dwords = try T.dwordCounts(request.setup.bridges, request.request.ls_dword);
    for (dwords, 0..) |count, k| if (request.setup.bridges.dwordLog(k)) |log| {
        try out.add(try product(count, @sizeOf(Memory.Event) / 4), .extensions, .source_release, .core, 0);
        try out.add(try product(try rows(log), 39), .extensions, .source_release, .core, 1);
    };
    // Deliberately incomplete: no allocator/lifetime or host coverage gate.
    out.device_complete = false;
    return out;
}
