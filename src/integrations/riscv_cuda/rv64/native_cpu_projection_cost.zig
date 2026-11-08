//! Allocation/lifetime model for the existing compact CPU projection only.
//! Callers derive Layout from the actual CPU/formatter types with layoutFor;
//! this module imports no backend, never launches work and never admits itself.
const std = @import("std");
pub const Format = enum { word16_compact_v1, unsupported };
pub const Layout = struct {
    metadata_words: u32,
    main_columns: u32,
    rom_columns: u32,
    compact_record_words: u32,
    compact_seed_words: u32,
    compact_chunk_rows: u32,
    trace_column_header_bytes: u32,
};
/// Use the SAME types/constants as cpu_projection.Job and cpu_witness.Compact.
/// No locally guessed 14-word metadata or 47-column ABI enters a runtime plan.
pub fn layoutFor(comptime Metadata: type, comptime CircuitLayout: type, comptime Record: type, comptime Seed: type, comptime TraceColumn: type, chunk_rows: u32) !Layout {
    if (@sizeOf(Metadata) % 4 != 0 or @sizeOf(Record) % 4 != 0 or @sizeOf(Seed) % 4 != 0) return error.UnsupportedCpuProjectionLayout;
    const result = Layout{
        .metadata_words = @intCast(@sizeOf(Metadata) / 4),
        .main_columns = std.math.cast(u32, CircuitLayout.mainCount(true)) orelse return error.UnsupportedCpuProjectionLayout,
        .rom_columns = CircuitLayout.rom.FIXED,
        .compact_record_words = @intCast(@sizeOf(Record) / 4),
        .compact_seed_words = @intCast(@sizeOf(Seed) / 4),
        .compact_chunk_rows = chunk_rows,
        .trace_column_header_bytes = @intCast(@sizeOf(TraceColumn)),
    };
    try validateLayout(result);
    return result;
}
fn validateLayout(l: Layout) !void {
    if (l.metadata_words == 0 or l.metadata_words > 1024 or l.main_columns == 0 or l.main_columns > 65535 or l.rom_columns == 0 or l.rom_columns > 65535 or l.compact_record_words == 0 or l.compact_record_words > 1024 or l.compact_seed_words == 0 or l.compact_seed_words > 65536 or l.compact_chunk_rows == 0 or l.compact_chunk_rows > 65536 or l.trace_column_header_bytes == 0) return error.UnsupportedCpuProjectionLayout;
}
pub const Input = struct {
    format: Format = .word16_compact_v1,
    layout: Layout,
    program_identity: [32]u8,
    program_profile: u32,
    log: u32,
    rom_log: u32,
    active: u64,
    public_steps: u64,
    source_compact: bool,
    program_compact: bool,
    program_fixed_retired: bool,
    compact_ingress: bool,
    retain_ledgers: bool,
    /// A cold immutable ROM allocation, not a Source-owned allocation. Warm
    /// ROM is already owned/charged by the physical cache's existing lifetime.
    cold_rom: bool,
};
pub const Owner = enum { immutable_rom, projection_scratch, projection_evaluations, compact_ingress };
pub const Boundary = enum { joined_projection, source_release, immutable_release };
pub const Action = enum { allocate, release };
pub const Event = struct { action: Action, owner: Owner, words: u64, kind: u32, boundary: ?Boundary = null };
pub const Allocation = struct { owner: Owner, words: u64, kind: u32, release: Boundary };
pub const Host = struct {
    /// Borrowed capture storage remains alive, but is NOT newly allocated here.
    borrowed_metadata_bytes: u64,
    borrowed_rom_bytes: u64,
    /// New reconstruction payload exists only while the cold ROM uploads,
    /// before scratch/eval allocation; do not sum it with a later host peak.
    cold_reconstructed_rom_bytes: u64,
    compact_records_bytes: u64,
    compact_seeds_bytes: u64,
    returned_column_headers_bytes: u64,
    extra_pack_threads: u32,
    /// Actual implementation uses spawn(.{}): stack reservation is unbounded
    /// by this model. ROM reconstruction, JSON identity, Pending/Owner/header
    /// and allocator metadata also need the enclosing source-owner audit.
    cost_known: bool = false,
};
pub const Plan = struct {
    identity: [32]u8,
    allocations: [4]Allocation = undefined,
    allocation_count: usize = 0,
    events: [8]Event = undefined,
    event_count: usize = 0,
    host: Host,
    /// Payload sums ONLY. Round allocations separately before arena admission.
    peak_additional_payload_bytes: u64 = 0,
    source_retained_payload_bytes: u64 = 0,
    immutable_new_payload_bytes: u64 = 0,
    pub fn allocationList(self: *const Plan) []const Allocation {
        return self.allocations[0..self.allocation_count];
    }
    pub fn eventList(self: *const Plan) []const Event {
        return self.events[0..self.event_count];
    }
    fn allocate(self: *Plan, owner: Owner, words: u64, kind: u32, release: Boundary) !void {
        if (self.allocation_count == self.allocations.len or self.event_count == self.events.len or words == 0) return error.InvalidCpuProjectionAllocationPlan;
        const bytes = try std.math.mul(u64, words, 4);
        self.allocations[self.allocation_count] = .{ .owner = owner, .words = words, .kind = kind, .release = release };
        self.allocation_count += 1;
        self.events[self.event_count] = .{ .action = .allocate, .owner = owner, .words = words, .kind = kind };
        self.event_count += 1;
        self.peak_additional_payload_bytes = try std.math.add(u64, self.peak_additional_payload_bytes, bytes);
        switch (release) {
            .source_release => self.source_retained_payload_bytes = try std.math.add(u64, self.source_retained_payload_bytes, bytes),
            .immutable_release => self.immutable_new_payload_bytes = try std.math.add(u64, self.immutable_new_payload_bytes, bytes),
            .joined_projection => {},
        }
    }
};
pub fn init(input: Input) !Plan {
    if (input.format != .word16_compact_v1 or !input.source_compact or !input.program_compact or !input.retain_ledgers) return error.UnsupportedCpuProjectionMode;
    try validateLayout(input.layout);
    if (std.mem.allEqual(u8, &input.program_identity, 0) or input.log < 5 or input.log > 22 or input.rom_log < 5 or input.rom_log > 24 or input.active != input.public_steps) return error.InvalidCpuProjectionGeometry;
    const rows = @as(u64, 1) << @intCast(input.log);
    const rom_rows = @as(u64, 1) << @intCast(input.rom_log);
    if (input.active >= rows) return error.InvalidCpuProjectionGeometry;
    const l = input.layout;
    const seed_count = try std.math.divCeil(u64, input.active, l.compact_chunk_rows);
    const record_words = if (input.compact_ingress) try std.math.mul(u64, input.active, l.compact_record_words) else 0;
    const seed_words = if (input.compact_ingress) try std.math.mul(u64, seed_count, l.compact_seed_words) else 0;
    const workers: u64 = if (input.compact_ingress and input.active >= 1 << 20) @min(4, seed_count) else 1;
    var plan = Plan{ .identity = undefined, .host = .{
        .borrowed_metadata_bytes = try std.math.mul(u64, try std.math.mul(u64, input.active, l.metadata_words), 4),
        .borrowed_rom_bytes = if (!input.program_fixed_retired) try std.math.mul(u64, try std.math.mul(u64, rom_rows, l.rom_columns), 4) else 0,
        .cold_reconstructed_rom_bytes = if (input.cold_rom and input.program_fixed_retired) try std.math.mul(u64, try std.math.mul(u64, rom_rows, l.rom_columns), 4) else 0,
        .compact_records_bytes = try std.math.mul(u64, record_words, 4),
        .compact_seeds_bytes = try std.math.mul(u64, seed_words, 4),
        .returned_column_headers_bytes = try std.math.mul(u64, l.main_columns, l.trace_column_header_bytes),
        .extra_pack_threads = @intCast(workers - 1),
    } };
    // Exact Job.run order: ROM lookup/allocation, scratch, eval, compact input.
    if (input.cold_rom) try plan.allocate(.immutable_rom, try std.math.mul(u64, rom_rows, l.rom_columns), 4, .immutable_release);
    const metadata_words = try std.math.mul(u64, input.active, l.metadata_words);
    const scratch = try std.math.add(u64, try std.math.add(u64, @max(1, metadata_words), rom_rows), 65536 + 256 + 1 + 65536);
    try plan.allocate(.projection_scratch, scratch, 0, .source_release);
    try plan.allocate(.projection_evaluations, try std.math.mul(u64, rows, l.main_columns), 1, .source_release);
    if (input.compact_ingress) try plan.allocate(.compact_ingress, @max(1, try std.math.add(u64, record_words, seed_words)), 0, .joined_projection);
    // Deferred compact input free follows joined verdict; retained owners free
    // only on their later actual owner destruction, never at projection return.
    for ([_]Boundary{ .joined_projection, .source_release, .immutable_release }) |boundary| {
        // Source Owner.releaseDevice frees ledger before eval, matching order.
        for (plan.allocationList()) |allocation| if (allocation.release == boundary) {
            plan.events[plan.event_count] = .{ .action = .release, .owner = allocation.owner, .words = allocation.words, .kind = allocation.kind, .boundary = boundary };
            plan.event_count += 1;
        };
    }
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64/cpu-projection-allocation/v1\x00");
    hash.update(@embedFile("native_cpu_projection_cost.zig"));
    hash.update(&input.program_identity);
    inline for (std.meta.fields(Layout)) |field| {
        var word: [4]u8 = undefined;
        std.mem.writeInt(u32, &word, @field(l, field.name), .little);
        hash.update(&word);
    }
    inline for (.{ input.program_profile, input.log, input.rom_log }) |n| {
        var word: [4]u8 = undefined;
        std.mem.writeInt(u32, &word, n, .little);
        hash.update(&word);
    }
    var active: [8]u8 = undefined;
    std.mem.writeInt(u64, &active, input.active, .little);
    hash.update(&active);
    hash.update(&.{ @intFromBool(input.compact_ingress), @intFromBool(input.cold_rom), @intFromBool(input.retain_ledgers), @intFromBool(input.program_fixed_retired) });
    plan.identity = hash.finalResult();
    return plan;
}

fn fixture() Input {
    // ABI schema from the CPU witness formatter. Runtime must call layoutFor
    // using actual imported types, not copy these fixture constants.
    return .{ .layout = .{ .metadata_words = 14, .main_columns = 47, .rom_columns = 32, .compact_record_words = 4, .compact_seed_words = 96, .compact_chunk_rows = 256, .trace_column_header_bytes = 64 }, .program_identity = @splat(7), .program_profile = 0, .log = 5, .rom_log = 5, .active = 17, .public_steps = 17, .source_compact = true, .program_compact = true, .program_fixed_retired = false, .compact_ingress = true, .retain_ledgers = true, .cold_rom = true };
}
test "CPU projection orders allocations and retires compact input before source owners" {
    const p = try init(fixture());
    try std.testing.expectEqual(@as(usize, 4), p.allocation_count);
    try std.testing.expectEqual(@as(u64, 32 * 32), p.allocations[0].words);
    try std.testing.expectEqual(@as(u64, 17 * 14 + 65536 + 256 + 32 + 1 + 65536), p.allocations[1].words);
    try std.testing.expectEqual(@as(u64, 32 * 47), p.allocations[2].words);
    try std.testing.expectEqual(@as(u64, 17 * 4 + 96), p.allocations[3].words);
    try std.testing.expectEqual(Owner.compact_ingress, p.events[4].owner);
    try std.testing.expectEqual(Boundary.joined_projection, p.events[4].boundary.?);
    try std.testing.expectEqual(Owner.projection_scratch, p.events[5].owner);
    try std.testing.expectEqual(Owner.projection_evaluations, p.events[6].owner);
    try std.testing.expectEqual(Owner.immutable_rom, p.events[7].owner);
    try std.testing.expect(!p.host.cost_known);
}
test "warm raw metadata input omits only new immutable ROM and compact input" {
    var x = fixture();
    x.cold_rom = false;
    x.compact_ingress = false;
    const p = try init(x);
    try std.testing.expectEqual(@as(usize, 2), p.allocation_count);
    try std.testing.expectEqual(Owner.projection_scratch, p.allocations[0].owner);
    try std.testing.expectEqual(@as(u64, 0), p.immutable_new_payload_bytes);
    try std.testing.expectEqual(@as(u64, 0), p.host.compact_records_bytes);
}
test "empty compact capture still charges one word and boundary chunk seeds are exact" {
    var x = fixture();
    x.active = 0;
    x.public_steps = 0;
    const empty = try init(x);
    try std.testing.expectEqual(@as(u64, 1), empty.allocations[3].words);
    x.log = 10;
    x.active = 257;
    x.public_steps = 257;
    const next = try init(x);
    try std.testing.expectEqual(@as(u64, 257 * 4 + 2 * 96), next.allocations[3].words);
    x.log = 22;
    x.active = 1 << 20;
    x.public_steps = x.active;
    const wide = try init(x);
    try std.testing.expectEqual(@as(u32, 3), wide.host.extra_pack_threads);
}
test "geometry mutation changes plan identity and invalid modes fail before work" {
    var x = fixture();
    const p = try init(x);
    x.program_profile += 1;
    const q = try init(x);
    try std.testing.expect(!std.mem.eql(u8, &p.identity, &q.identity));
    x.public_steps += 1;
    try std.testing.expectError(error.InvalidCpuProjectionGeometry, init(x));
    x = fixture();
    x.active = 32;
    x.public_steps = 32;
    try std.testing.expectError(error.InvalidCpuProjectionGeometry, init(x));
    x = fixture();
    x.retain_ledgers = false;
    try std.testing.expectError(error.UnsupportedCpuProjectionMode, init(x));
    x = fixture();
    x.layout.compact_chunk_rows = 0;
    try std.testing.expectError(error.UnsupportedCpuProjectionLayout, init(x));
}

test "layout adapter uses the supplied formatter types instead of fixture widths" {
    const Metadata = extern struct { words: [19]u32 };
    const Circuit = struct {
        pub const rom = struct {
            pub const FIXED = 7;
        };
        pub fn mainCount(compact: bool) usize {
            return if (compact) 53 else 99;
        }
    };
    const Record = extern struct { words: [6]u32 };
    const Seed = extern struct { words: [101]u32 };
    const Column = extern struct { words: [11]u32 };
    const l = try layoutFor(Metadata, Circuit, Record, Seed, Column, 128);
    try std.testing.expectEqual(@as(u32, 19), l.metadata_words);
    try std.testing.expectEqual(@as(u32, 53), l.main_columns);
    try std.testing.expectEqual(@as(u32, 7), l.rom_columns);
    var x = fixture();
    x.layout = l;
    const p = try init(x);
    try std.testing.expectEqual(@as(u64, 32 * 53), p.allocations[2].words);
    try std.testing.expectEqual(@as(u64, 17 * 6 + 101), p.allocations[3].words);
    try std.testing.expectEqual(@as(u64, 53 * 44), p.host.returned_column_headers_bytes);
}

test "cold retired ROM host reconstruction has its own early lifetime" {
    var x = fixture();
    x.program_fixed_retired = true;
    const p = try init(x);
    try std.testing.expectEqual(@as(u64, 0), p.host.borrowed_rom_bytes);
    try std.testing.expectEqual(@as(u64, 32 * 32 * 4), p.host.cold_reconstructed_rom_bytes);
    x.cold_rom = false;
    const warm = try init(x);
    try std.testing.expectEqual(@as(u64, 0), warm.host.cold_reconstructed_rom_bytes);
}
