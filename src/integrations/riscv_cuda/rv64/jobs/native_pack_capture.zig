//! Capture-side serializer of compact TraceChunk v2 (stream gn-pack, IO lever
//! L0): one native segment's compact facts/events -> the v2 launch program
//! (native_pack.zig) written straight into the pinned capture ring.
//!
//! This is the host half of the legacy resident source orchestration, ported
//! record for record and launch for launch so the device MAIN is
//! byte-identical:
//!   cpu_projection.zig Job.run          CompactRecord + seeds, ROM, CPU scratch,
//!                                       cpu_unpack + cpu_witness
//!   core_witness.zig BuildJob.run       core ledgers (seeded from the CPU
//!                                       ledgers), DIV -> MUL support, every
//!                                       core family/memory/boundary role,
//!   core_witness.zig Finish.run         table multiplicities (deferred, last)
//!   bridge_witness.zig format           keccak/secp/sha256/arith256/curves
//!   bulk_sponge.zig format              bulk analyse + bulk kinds, sponge
//!   device_source.zig appendLocalExtensions   Zbb, LS-D64
//! The validations the legacy host runs on these inputs are kept (fail
//! closed on the capture thread). What is NOT ported: the narrow host
//! descriptors (`Headers`) the legacy CPU worker reads after the source; the
//! GPU-native Stage 2 owns its own descriptors.
//!
//! The only per-request host work here is encoding (no field arithmetic, no
//! MAIN): ~16-32 B per fact/event/row, the same bytes the legacy uploads.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const Front = @import("stwo_riscv_frontend").rv64_air;
const G = @import("gpu_native.zig");
const P = @import("native_pack.zig");
const Ingress = @import("../cpu_witness.zig");

pub const Stage = CPU.rv64_device_source_stage;
const Inputs = CPU.rv64_family_input;
const Memory = CPU.rv64_memory_input;
const T = CPU.rv64_services_types;
const Tail = CPU.rv64_provider_tails;
const X = Front.word16_execution;
const K = Front.crypto.keccak.word16_bridge;
const W = Front.crypto.secp256k1.word16_bridge;
const B = Front.crypto.bulk_memory;
const S = Front.crypto.keccak_sponge;

// bulk_sponge.zig device records (copied ABI; sizes pinned there and here).
pub const State = extern struct { value: u64, tick: u32, epoch: u16, rights: u8, reserved: u8 = 0 };
pub const BulkCall = extern struct { pointer: u64, dst: u64, word1: u64, len: u64, epoch: u32, tick: u32, op: u32, examined: u32, result: i32, first_word: u32, first_scan: u32, reserved: u32 = 0, packet: [4]State };
pub const Word = extern struct { dst: State, src: State };
pub const Row = extern struct { call: u32, word: u32, index: u32, reserved: u32 = 0 };
pub const SpongeCall = extern struct { pointer: u64, epoch: u32, tick: u32, first_word: u32, first_perm: u32, packet: [4]State, state: [25]State };
comptime {
    std.debug.assert(@sizeOf(State) == 16 and @sizeOf(BulkCall) == 128 and @sizeOf(SpongeCall) == 488 and @sizeOf(Row) == 16 and @sizeOf(Word) == 32);
}
fn state(v: B.types.State) State {
    return .{ .value = v.value, .tick = v.tick, .epoch = v.epoch, .rights = v.rights };
}

/// What a packed segment cost on the capture thread [M] and shipped [M].
pub const Stats = struct {
    rows: u64 = 0,
    chunks: u32 = 0,
    launches: u32 = 0,
    buffers: u32 = 0,
    chunk_words: u64 = 0,
    data_words: u64 = 0,
    /// Stage-1 arena words of the program buffers (Spec.compact_words bound).
    arena_words: u64 = 0,
    cpu_records: u64 = 0,
    pack_ns: u64 = 0,
    /// Of pack_ns: the CompactRecord/seed pack (cpu_witness Compact.fromCapture).
    compact_ns: u64 = 0,
    /// Of pack_ns: ROM reconstruction (first request of a program only).
    rom_ns: u64 = 0,
};

/// The ROM key (= legacy immutable-ROM cache identity, cpu_projection.zig rom()).
pub fn romKey(program: anytype) [8]u32 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo/rv64/cuda/immutable-cpu-rom/v2\x00");
    h.update(&program.identity);
    var log_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &log_bytes, program.log_size, .little);
    h.update(&log_bytes);
    h.update(&.{@intFromBool(program.compact)});
    std.mem.writeInt(u32, &log_bytes, @intFromEnum(program.profile), .little);
    h.update(&log_bytes);
    const digest = h.finalResult();
    var identity: [8]u32 = undefined;
    for (&identity, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    return identity;
}

/// cpu_projection.zig reconstructRom (identical physical ROM tuple layout).
pub fn romWords(a: std.mem.Allocator, program: anytype) ![]u32 {
    const rows = program.size();
    const count = X.layout.rom.FIXED * rows;
    if (!program.fixed_retired) {
        const words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(program.fixed));
        if (words.len != count) return error.InvalidCpuRomGeometry;
        return a.dupe(u32, words);
    }
    const data = try a.alloc(u32, count);
    errdefer a.free(data);
    @memset(data, 0);
    for (0..rows) |logical| {
        const tuple = try program.tupleAt(logical);
        const physical = X.layout.physical(logical, program.log_size);
        for (tuple, 0..) |value, col| data[col * rows + physical] = value.v;
    }
    data[X.layout.rom.FIRST * rows + X.layout.physical(0, program.log_size)] = 1;
    data[X.layout.rom.LAST * rows + X.layout.physical(rows - 1, program.log_size)] = 1;
    return data;
}

fn words32(comptime E: type, values: []const E) []const u32 {
    return @alignCast(std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(values)));
}

/// Core ledger layout (core_witness.zig BuildJob sizes).
const Ledger = struct {
    id: u16,
    rom_count: usize,
    const range16: usize = 0;
    const range8: usize = 65536;
    const pairs: usize = range8 + 256;
    const and_: usize = pairs + 65536;
    const shift: usize = and_ + 65536;
    const selection: usize = shift + 16 * 65536;
    const rom: usize = selection + 2 * 65536;
    fn status(self: Ledger) usize {
        return rom + self.rom_count;
    }
    fn words(self: Ledger) usize {
        return self.status() + 1;
    }
    fn at(self: Ledger, off: usize) P.Ref {
        return P.ref(self.id, off);
    }
};

/// Pack one native segment (`req` = the legacy DeviceSourceStage.Request the
/// segment's source would be built from) into v2 chunks through `out`.
/// `roms` receives the program ROM host words once per program (Stage 1
/// fills its worker-persistent ROM region from them). Read-only on `req`.
/// `rows` = the segment rows the request was planned with (TraceChunk row
/// total, carried by the last chunk); null = the CPU domain 2^cpu_log.
pub fn pack(a: std.mem.Allocator, req: Stage.Request, roms: *P.Roms, out: G.ChunkWriter, rows: ?u64) !Stats {
    var timer = try std.time.Timer.start();
    var stats = Stats{};
    var w = P.Writer.init(out);
    const setup = req.setup;
    const g = setup.materials.geometry;
    const p = req.native;
    const statement = req.request.base.memory;
    try g.validate();
    const logs = try setup.logs(a, 1);
    defer a.free(logs);
    const shapes = setup.materials.shapes();

    // ---- CPU (cpu_projection.zig projectFresh / projectPacked / Job.run) ----
    var src = p.cpu orelse return error.PreparedExecutionConsumed;
    const program = &setup.materials.program;
    if (!std.mem.eql(u8, &p.program_identity, &program.identity)) return error.PreparedProgramMismatch;
    if (src.log_size != g.cpu_log or src.compact != program.compact) return error.PreparedGeometryMismatch;
    if (src.compact != g.cpu_compact_decode or src.epoch != statement.epoch) return error.PreparedGeometryMismatch;
    src.program = program;
    if (!src.compact or !program.compact or src.main.len != 0 or src.main_projection_closed or src.metadata.len != src.public.steps or src.public.steps >= src.size() or src.log_size < 5 or src.log_size > 22 or src.public.final_pc & 3 != 0 or !X.features.compactPcAdmitted(src.public.final_pc)) return error.CpuDeviceIngressUnavailable;
    if (!program.fixed_retired) _ = try Ingress.Input.fromCapture(&src);
    const rom_rows = program.size();
    const rom_words = X.layout.rom.FIXED * rom_rows;
    const key = romKey(program);
    if (!roms.has(key)) {
        const t0 = timer.read();
        try roms.put(key, try romWords(roms.a, program));
        stats.rom_ns = timer.read() - t0;
    }
    const rom = try w.persistent(rom_words, key);
    const c0 = timer.read();
    var compact = try Ingress.Compact.fromCapture(a, &src);
    defer compact.deinit();
    stats.compact_ns = timer.read() - c0;
    stats.cpu_records = compact.records.len;
    const records = words32(Ingress.CompactRecord, compact.records);
    const seeds = words32(Ingress.CompactSeed, compact.seeds);
    const metadata_words = compact.records.len * 14;
    const count_base = @max(@as(usize, 1), metadata_words);
    const c8_base = count_base + 65536;
    const rom_base = c8_base + 256;
    const status_base = rom_base + rom_rows;
    const pair_base = status_base + 1;
    const scratch = try w.declare(pair_base + 65536, .zero);
    const input = try w.declare(records.len + seeds.len, .upload);
    try w.data(input, 0, records);
    try w.data(input, records.len, seeds);
    try w.launch(.cpu_unpack, .{ .records = P.ref(input, 0), .seeds = P.ref(input, records.len), .rom = P.ref(rom, 0), .metadata = P.ref(scratch, 0), .status = P.ref(scratch, status_base), .count = @intCast(compact.records.len), .rom_log = program.log_size, .chunk_rows = Ingress.compact_chunk_rows }, 0, 0);
    var cpu_column: ?usize = null;
    var cpu_width: usize = 0;
    for (shapes) |shape| if (shape.role == .cpu and shape.widths[1] != 0) {
        cpu_column = shape.offsets[1];
        cpu_width = shape.widths[1];
    };
    if (cpu_width != X.layout.mainCount(true) or (cpu_column orelse return error.InvalidCpuDeviceProjection) + cpu_width > logs.len) return error.InvalidCpuDeviceProjection;
    try w.launch(.cpu_witness, .{ .metadata = if (metadata_words != 0) P.ref(scratch, 0) else 0, .rom = P.ref(rom, 0), .main = P.column(cpu_column.?), .counts16 = P.ref(scratch, count_base), .counts8 = P.ref(scratch, c8_base), .rom_counts = P.ref(scratch, rom_base), .status = P.ref(scratch, status_base), .count = @intCast(src.public.steps), .log = src.log_size, .rom_log = program.log_size, .final_pc = @intCast(src.public.final_pc), .pair_counts = P.ref(scratch, pair_base) }, @intCast(cpu_column.?), @intCast(cpu_width));
    try w.status(P.ref(scratch, status_base));

    // ---- core ledgers (core_witness.zig BuildJob.run) ----
    const ledger = Ledger{ .id = try w.declare((Ledger{ .id = 0, .rom_count = rom_rows }).words(), .zero), .rom_count = rom_rows };
    try w.status(ledger.at(ledger.status()));
    // CPU histograms seed the shared ledgers (range8 not in pair mode).
    try w.launch(.copy, .{ .dst = ledger.at(Ledger.range16), .src = P.ref(scratch, count_base), .words = 65536 }, 0, 0);
    if (!g.cpu_u8_pairs) try w.launch(.copy, .{ .dst = ledger.at(Ledger.range8), .src = P.ref(scratch, c8_base), .words = 256 }, 0, 0);
    try w.launch(.copy, .{ .dst = ledger.at(Ledger.pairs), .src = P.ref(scratch, pair_base), .words = 65536 }, 0, 0);
    try w.launch(.copy, .{ .dst = ledger.at(Ledger.rom), .src = P.ref(scratch, rom_base), .words = rom_rows }, 0, 0);

    // Headers.take validations (device_headers.zig).
    const splits = try Tail.validate(g, p);
    const ls_counts = try g.lsCounts(statement.ls_count);
    if (g.omit_empty_division and p.division.len != 0) return error.OmittedDivisionRequests;
    if (p.division.len > @as(usize, 1) << @intCast(g.division_log) or p.multiplication.len > @as(usize, 1) << @intCast(g.multiplication_log)) return error.ArithmeticRequestCapacity;
    if (statement.initial.len >= @as(usize, 1) << @intCast(g.initialLog()) or statement.terminal.len >= @as(usize, 1) << @intCast(g.terminalLog())) return error.BoundaryCapacityExceeded;
    const jalr = p.jalr orelse return error.PreparedExecutionConsumed;
    if (jalr.log_size != g.jalr_log) return error.PreparedGeometryMismatch;

    // core_witness.zig Context.buildCore: the general LS events.
    const events = req.advice.events[req.ordinal];
    const general = try Memory.routedEvents(a, events, setup.bridges.ls_dword != null, false);
    defer a.free(general);
    if (general.len != statement.ls_count or events.len - general.len != req.request.ls_dword) return error.InvalidCombinedServiceCount;

    // DIV creates its two MUL support facts on device; only guest MUL facts upload.
    const raw_mul: usize = p.raw_counts.multiplication;
    if (p.multiplication.len != raw_mul + 2 * p.division.len) return error.InvalidMultiplicationSupportCount;
    var mul_batch = try Inputs.Batch.multiplication(a, p.multiplication[0..raw_mul], g.multiplication_log);
    defer mul_batch.deinit();
    const mul_input = try w.declare(p.multiplication.len * 8, .zero);
    if (raw_mul != 0) try w.data(mul_input, 0, mul_batch.words());
    var div_batch = try Inputs.Batch.division(a, p.division, g.division_log);
    defer div_batch.deinit();
    const div_input = try w.declare(div_batch.words().len, .upload);
    if (div_batch.words().len != 0) try w.data(div_input, 0, div_batch.words()) else try w.data(div_input, 0, &.{0});
    for (shapes) |shape| if (shape.role == .division and shape.widths[1] != 0) {
        try w.launch(.arithmetic, .{ .requests = if (p.division.len == 0) 0 else P.ref(div_input, 0), .main = P.column(shape.offsets[1]), .range16 = ledger.at(Ledger.range16), .range8 = ledger.at(Ledger.range8), .pairs = ledger.at(Ledger.pairs), .status = ledger.at(ledger.status()), .mul_support = if (p.division.len == 0) 0 else P.ref(mul_input, raw_mul * 8), .count = @intCast(p.division.len), .log = shape.log, .division = 1, .fused_pairs = 0 }, @intCast(shape.offsets[1]), @intCast(shape.widths[1]));
    };
    var tables: std.ArrayListUnmanaged(P.Table) = .empty;
    defer tables.deinit(a);
    var table_columns: std.ArrayListUnmanaged([2]u32) = .empty;
    defer table_columns.deinit(a);
    for (shapes) |shape| {
        if (shape.widths[1] == 0 or shape.role == .division or shape.role == .cpu) continue;
        const col: u32 = @intCast(shape.offsets[1]);
        const width: u32 = @intCast(shape.widths[1]);
        switch (shape.role) {
            .alu, .alu_tail => {
                const start: usize = if (shape.role == .alu) 0 else splits.alu.head;
                const count: usize = if (shape.role == .alu) splits.alu.head else splits.alu.tail;
                var batch = try Inputs.Batch.alu(a, p.alu.facts[start..][0..count], p.alu.weights[start..][0..count], shape.log);
                defer batch.deinit();
                try family(&w, ledger, &batch, col, width);
            },
            .binary, .binary_tail => {
                const start: usize = if (shape.role == .binary) 0 else splits.binary.head;
                const count: usize = if (shape.role == .binary) splits.binary.head else splits.binary.tail;
                var batch = try Inputs.Batch.binary(a, p.binary.facts[start..][0..count], p.binary.weights[start..][0..count], shape.log);
                defer batch.deinit();
                try family(&w, ledger, &batch, col, width);
            },
            .shift, .shift_tail => {
                const start: usize = if (shape.role == .shift) 0 else splits.shift.head;
                const count: usize = if (shape.role == .shift) splits.shift.head else splits.shift.tail;
                var batch = try Inputs.Batch.shift(a, p.shift[start..][0..count], if (p.shift_weights.len == 0) null else p.shift_weights[start..][0..count], shape.log);
                defer batch.deinit();
                try family(&w, ledger, &batch, col, width);
            },
            .jalr => {
                var batch = try Inputs.Batch.jalr(a, jalr.facts, shape.log);
                defer batch.deinit();
                try family(&w, ledger, &batch, col, width);
            },
            .ls, .ls_tail => {
                const start: usize = if (shape.role == .ls) 0 else ls_counts.head;
                const count: usize = if (shape.role == .ls) ls_counts.head else ls_counts.tail;
                if (start + count > general.len) return error.InvalidCombinedServiceCount;
                try memory(&w, ledger, general[start..][0..count], shape.log, false, g.ls_fused_pairs, col, width);
            },
            .initial, .terminal => {
                const cells = if (shape.role == .initial) statement.initial else statement.terminal;
                const encoded = try Memory.cells(a, cells);
                defer a.free(encoded);
                if (width != 14) return error.InvalidDeviceCoreWidth;
                const buf = try w.declare(encoded.len * 8, .upload);
                try w.data(buf, 0, if (encoded.len == 0) &.{0} else words32(Memory.Cell, encoded));
                try w.launch(.boundary, .{ .cells = if (cells.len == 0) 0 else P.ref(buf, 0), .main = P.column(col), .status = ledger.at(ledger.status()), .count = @intCast(cells.len), .log = shape.log }, col, width);
            },
            .multiplication => {
                try w.launch(.arithmetic, .{ .requests = if (p.multiplication.len == 0) 0 else P.ref(mul_input, 0), .main = P.column(col), .range16 = ledger.at(Ledger.range16), .range8 = ledger.at(Ledger.range8), .pairs = ledger.at(Ledger.pairs), .status = ledger.at(ledger.status()), .mul_support = 0, .count = @intCast(p.multiplication.len), .log = shape.log, .division = 0, .fused_pairs = @intFromBool(g.mul_u8_pairs) }, col, width);
            },
            .rom, .range16, .range8, .and_table, .shift_table, .selection => {
                const kind: u32 = switch (shape.role) {
                    .range16 => 0,
                    .range8 => 1,
                    .and_table => if (g.cpu_u8_pairs) 3 else 2,
                    .shift_table => 4,
                    .selection => 5,
                    .rom => 6,
                    else => unreachable,
                };
                const counts: usize = switch (kind) {
                    0 => Ledger.range16,
                    1 => Ledger.range8,
                    2, 3 => Ledger.and_,
                    4 => Ledger.shift,
                    5 => Ledger.selection,
                    6 => Ledger.rom,
                    else => unreachable,
                };
                try tables.append(a, .{ .counts = ledger.at(counts), .pairs = if (kind == 3) ledger.at(Ledger.pairs) else 0, .main = P.column(col), .status = ledger.at(ledger.status()), .log = shape.log, .kind = kind });
                try table_columns.append(a, .{ col, width });
            },
            else => return error.UnsupportedDeviceCoreRole,
        }
    }

    // ---- service bridges (bridge_witness.zig format) ----
    for (0..T.FAMILIES) |index| {
        const fam: T.Family = @enumFromInt(index);
        const log = setup.bridges.at(fam) orelse continue;
        const count = req.request.calls[index];
        const first = req.first_ids[index];
        const col = setup.offset(fam, 1);
        const width = T.widths(fam)[1];
        if (col + width > logs.len) return error.InvalidResidentBridgeColumns;
        var encoded: []u32 = undefined;
        var coordinates: usize = undefined;
        var write_mask: u32 = 0;
        if (fam == .keccak) {
            const calls = req.advice.keccak[req.ordinal];
            if (calls.len != count) return error.InvalidCombinedServiceCount;
            _ = try K.types.validateGeometry(calls.len, first, log);
            for (calls, 0..) |call, i| {
                try K.source.validate(call);
                if (i != 0 and (call.epoch < calls[i - 1].epoch or (call.epoch == calls[i - 1].epoch and call.tick <= calls[i - 1].tick))) return error.InvalidWord16KeccakCallOrder;
            }
            encoded = try encodeKeccak(a, calls);
            coordinates = 25;
        } else {
            const kind = T.bridgeKind(fam);
            const calls: []const W.types.Call = switch (fam) {
                .add => req.advice.secp[req.ordinal][0],
                .double => req.advice.secp[req.ordinal][1],
                .sha256 => req.advice.sha256[req.ordinal],
                .arith256_mod => req.advice.arith256_mod[req.ordinal],
                else => req.advice.curves[req.ordinal][index - T.FIRST_CURVE],
            };
            if (calls.len != count) return error.InvalidCombinedServiceCount;
            _ = try W.types.validateGeometry(kind, calls.len, first, log);
            for (calls, 0..) |call, i| {
                try W.source.validate(kind, call);
                if (i != 0 and (call.epoch < calls[i - 1].epoch or (call.epoch == calls[i - 1].epoch and call.tick <= calls[i - 1].tick))) return error.InvalidWord16SecpCallOrder;
            }
            coordinates = W.types.coordinates(kind);
            for (0..coordinates) |coord| if (W.types.isWritten(kind, coord)) {
                write_mask |= @as(u32, 1) << @intCast(coord);
            };
            encoded = try encodeWire(a, kind, calls);
        }
        defer a.free(encoded);
        const buf = try w.declare(encoded.len, .upload);
        try w.data(buf, 0, if (encoded.len == 0) &.{0} else encoded);
        const fam_rows = @as(usize, 1) << @intCast(log);
        try w.launch(.bridge, .{ .inputs = if (encoded.len == 0) 0 else P.ref(buf, 0), .main = P.column(col), .range16 = ledger.at(Ledger.range16), .range8 = ledger.at(Ledger.range8), .status = ledger.at(ledger.status()), .input_words = encoded.len, .main_words = fam_rows * width, .calls = count, .first_id = first, .log = log, .kind = if (fam == .keccak) 0 else 1, .coordinates = @intCast(coordinates), .write_mask = write_mask }, @intCast(col), @intCast(width));
    }

    // ---- bulk memory + keccak sponge (bulk_sponge.zig) ----
    if (setup.bridges.bulk.any()) try bulk(a, &w, req, ledger);
    if (setup.bridges.sponge.any()) try sponge(a, &w, req, ledger);

    // ---- local extensions (device_source.zig appendLocalExtensions) ----
    if (setup.bridges.zbb) |log| {
        var batch = try Inputs.Batch.zbb(a, p.zbb.facts, p.zbb.weights, log);
        defer batch.deinit();
        const col = setup.zbbOffset(1);
        if (col + 32 > logs.len) return error.InvalidDeviceZbbWidth;
        var mass: u64 = 0;
        for (p.zbb.weights) |weight| mass = try std.math.add(u64, mass, weight);
        if (mass >= @import("stwo_core").fields.m31.Modulus) return error.DeviceFamilyMultiplicityMassExceeded;
        try family(&w, ledger, &batch, @intCast(col), 32);
    } else if (p.zbb.facts.len != 0) return error.MissingZbbComponent;
    const dword_events = try Memory.routedEvents(a, events, setup.bridges.ls_dword != null, true);
    defer a.free(dword_events);
    const counts = try T.dwordCounts(setup.bridges, req.request.ls_dword);
    var at: usize = 0;
    for (counts, 0..) |count, k| if (setup.bridges.dwordLog(k)) |log| {
        if (at > dword_events.len or count > dword_events.len - at) return error.InvalidCombinedServiceCount;
        const col = setup.dwordOffset(k, 1);
        if (col + 39 > logs.len) return error.InvalidDeviceDwordWidth;
        try memory(&w, ledger, dword_events[at..][0..count], log, true, g.ls_dword_fused_pairs, @intCast(col), 39);
        at += count;
    };
    if (at != dword_events.len) return error.InvalidCombinedServiceCount;

    // ---- tables last (core_witness.zig Finish.run), then the end record ----
    for (tables.items, table_columns.items) |t, tc| try w.launch(.table, t, tc[0], tc[1]);
    const seg_rows: u64 = rows orelse @as(u64, 1) << @intCast(g.cpu_log);
    try w.end(@intCast(logs.len), seg_rows);
    stats.rows = seg_rows;
    stats.chunks = w.chunks;
    stats.launches = w.launches;
    stats.buffers = w.buffers;
    stats.chunk_words = w.words_out;
    stats.data_words = w.data_words;
    stats.arena_words = w.arena_words;
    stats.pack_ns = timer.read();
    return stats;
}

fn family(w: *P.Writer, ledger: Ledger, batch: *const Inputs.Batch, col: u32, width: u32) !void {
    const words = batch.words();
    const buf = try w.declare(words.len, .upload);
    try w.data(buf, 0, if (words.len == 0) &.{0} else words);
    try w.launch(.family, .{ .facts = if (batch.facts.len == 0) 0 else P.ref(buf, 0), .main = P.column(col), .range16 = ledger.at(Ledger.range16), .and_ = ledger.at(Ledger.and_), .shift = ledger.at(Ledger.shift), .status = ledger.at(ledger.status()), .count = @intCast(batch.facts.len), .log = batch.log, .kind = @intFromEnum(batch.kind) }, col, width);
}

fn memory(w: *P.Writer, ledger: Ledger, events: []const Memory.Event, log: u32, dword: bool, fused_pairs: bool, col: u32, width: u32) !void {
    if (width != (if (dword) @as(u32, 39) else 70)) return error.InvalidDeviceCoreWidth;
    const words = words32(Memory.Event, events);
    const buf = try w.declare(words.len, .upload);
    try w.data(buf, 0, if (words.len == 0) &.{0} else words);
    try w.launch(.memory, .{ .events = if (events.len == 0) 0 else P.ref(buf, 0), .main = P.column(col), .range16 = ledger.at(Ledger.range16), .range8 = ledger.at(Ledger.range8), .pairs = ledger.at(Ledger.pairs), .selection = ledger.at(Ledger.selection), .status = ledger.at(ledger.status()), .count = @intCast(events.len), .log = log, .dword = @intFromBool(dword), .fused_pairs = @intFromBool(fused_pairs) }, col, width);
}

// bridge_witness.zig encoders (same words).
fn pair(out: []u32, value: u64) void {
    out[0] = @truncate(value);
    out[1] = @truncate(value >> 32);
}
fn packet(out: []u32, pointer: u64, epoch: u16, tick: u24) void {
    pair(out, pointer);
    out[2] = epoch;
    out[3] = tick;
}
fn ram(out: []u32, before: u64, after: u64, pred: Front.memory.closed_ram.types.State) void {
    pair(out, before);
    pair(out[2..], after);
    pair(out[4..], pred.value);
    out[6] = @as(u32, pred.epoch) | (@as(u32, pred.rights) << 16);
    out[7] = pred.tick;
}
pub fn encodeKeccak(a: std.mem.Allocator, calls: []const K.types.Call) ![]u32 {
    const stride = 4 + 25 * 8;
    const out = try a.alloc(u32, try std.math.mul(usize, calls.len, stride));
    for (calls, 0..) |call, i| {
        const row = out[i * stride ..][0..stride];
        packet(row, call.pointer, call.epoch, call.tick);
        for (0..25) |j| ram(row[4 + j * 8 ..], call.before[j], call.after[j], call.predecessors[j]);
    }
    return out;
}
pub fn encodeWire(a: std.mem.Allocator, kind: W.types.Kind, calls: []const W.types.Call) ![]u32 {
    const words = 4 * W.types.coordinates(kind);
    const stride = 4 + words * 8;
    const out = try a.alloc(u32, try std.math.mul(usize, calls.len, stride));
    for (calls, 0..) |call, i| {
        const row = out[i * stride ..][0..stride];
        packet(row, call.pointer, call.epoch, call.tick);
        for (0..words) |j| ram(row[4 + j * 8 ..], call.before[j], call.after[j], call.predecessors[j]);
    }
    return out;
}

fn upload(w: *P.Writer, comptime E: type, values: []const E) !u16 {
    const words = words32(E, values);
    const buf = try w.declare(words.len, .upload);
    try w.data(buf, 0, if (words.len == 0) &.{0} else words);
    return buf;
}

fn bulk(a: std.mem.Allocator, w: *P.Writer, req: Stage.Request, ledger: Ledger) !void {
    const advice = req.advice.bulk[req.ordinal];
    const calls = try a.alloc(BulkCall, advice.calls.len);
    defer a.free(calls);
    const words = try a.alloc(Word, advice.words.len);
    defer a.free(words);
    var first_word: u32 = 0;
    var scans: u32 = 0;
    for (advice.calls, calls) |c, *o| {
        if (@as(u64, first_word) + c.entries() > advice.words.len) return error.InvalidBulkMemoryWords;
        try B.types.validateCall(c, advice.words[first_word..][0..c.entries()]);
        o.* = .{ .pointer = c.pointer, .dst = c.dst, .word1 = c.word1, .len = c.len, .epoch = c.epoch, .tick = c.tick, .op = @intFromEnum(c.op), .examined = c.examined, .result = c.result, .first_word = first_word, .first_scan = scans, .packet = undefined };
        for (c.packet, &o.packet) |v, *s| s.* = state(v);
        first_word += c.entries();
        if (c.op == .jumpdest) scans += c.bodyRows();
    }
    if (first_word != advice.words.len) return error.InvalidBulkMemoryWords;
    for (advice.words, words) |v, *o| o.* = .{ .dst = state(v.dst), .src = state(v.src) };
    const dc = try upload(w, BulkCall, calls);
    const dw = try upload(w, Word, words);
    const pending = try w.declare(scans, .zero);
    const jumps = try w.declare(8448, .zero);
    try w.launch(.bulk_analyze, .{ .calls = P.ref(dc, 0), .words = P.ref(dw, 0), .pending = P.ref(pending, 0), .jumps = P.ref(jumps, 0), .status = ledger.at(ledger.status()), .call_count = @intCast(calls.len), .word_count = @intCast(words.len), .pending_count = scans }, 0, 0);
    for (T.bulk_kinds) |kind| if (req.setup.bridges.bulk.at(kind)) |log| {
        const total = B.source.Source.rowsFor(kind, advice.calls);
        _ = try B.types.validateGeometry(kind, total, log);
        var rows: std.ArrayListUnmanaged(Row) = .empty;
        defer rows.deinit(a);
        for (advice.calls, 0..) |c, k| {
            if (c.descriptor() == kind) try rows.append(a, .{ .call = @intCast(k), .word = calls[k].first_word, .index = 0 });
            if (c.body() == kind) {
                for (0..c.bodyRows()) |j| try rows.append(a, .{ .call = @intCast(k), .word = calls[k].first_word + @as(u32, @intCast(if (kind == .jscan) 0 else j)), .index = @intCast(j) });
            }
        }
        const dr = try upload(w, Row, rows.items);
        const col = req.setup.bulkOffset(kind, 1);
        const width = B.layout.main(kind);
        try w.launch(.bulk, .{ .calls = P.ref(dc, 0), .words = P.ref(dw, 0), .rows = P.ref(dr, 0), .pending = P.ref(pending, 0), .main = P.column(col), .range16 = ledger.at(Ledger.range16), .jump_counts = P.ref(jumps, 0), .status = ledger.at(ledger.status()), .count = @intCast(total), .log = log, .kind = @intFromEnum(kind), .call_count = @intCast(calls.len), .word_count = @intCast(words.len), .pending_count = scans }, @intCast(col), @intCast(width));
    };
}

fn sponge(a: std.mem.Allocator, w: *P.Writer, req: Stage.Request, ledger: Ledger) !void {
    const advice = req.advice.sponge[req.ordinal];
    const calls = try a.alloc(SpongeCall, advice.calls.len);
    defer a.free(calls);
    const words = try a.alloc(State, advice.words.len);
    defer a.free(words);
    var nw: usize = 0;
    var np: usize = 0;
    for (advice.calls, calls) |c, *o| {
        if (c.first_word != nw or c.first_perm != np or nw + c.words() > advice.words.len) return error.InvalidKeccakSpongeCallOrder;
        try S.types.validateCall(c, advice.words[nw..][0..c.words()]);
        o.* = .{ .pointer = c.pointer, .epoch = c.epoch, .tick = c.tick, .first_word = c.first_word, .first_perm = c.first_perm, .packet = undefined, .state = undefined };
        for (c.packet, &o.packet) |v, *s| s.* = state(v);
        for (c.state, &o.state) |v, *s| s.* = state(v);
        nw += c.words();
        np += c.permutations();
    }
    if (nw != advice.words.len or np != advice.inputs.len) return error.InvalidKeccakSpongeWords;
    for (advice.words, words) |v, *s| s.* = state(v);
    const dc = try upload(w, SpongeCall, calls);
    const dw = try upload(w, State, words);
    const di = try upload(w, [25]u64, advice.inputs);
    const dout = try w.declare(np * 50, .zero);
    if (np != 0) try w.launch(.sponge_outputs, .{ .inputs = P.ref(di, 0), .outputs = P.ref(dout, 0), .status = ledger.at(ledger.status()), .count = @intCast(np) }, 0, 0);
    // Row -> call map (S.source.Plan.row_call), host only.
    const row_call = try a.alloc(u32, np);
    defer a.free(row_call);
    for (advice.calls, 0..) |c, k| @memset(row_call[c.first_perm..][0..c.permutations()], @intCast(k));
    for (T.sponge_kinds) |kind| if (req.setup.bridges.sponge.at(kind)) |log| {
        const count: usize = if (kind == .call) advice.calls.len else np;
        _ = try S.types.validateGeometry(kind, @intCast(count), log);
        const rows = try a.alloc(Row, count);
        defer a.free(rows);
        if (kind == .call) {
            for (rows, 0..) |*r, k| r.* = .{ .call = @intCast(k), .word = 0, .index = 0 };
        } else for (rows, 0..) |*r, k| {
            const ci = row_call[k];
            r.* = .{ .call = ci, .word = 0, .index = @intCast(k - advice.calls[ci].first_perm) };
        }
        const dr = try upload(w, Row, rows);
        const col = req.setup.spongeOffset(kind, 1);
        const width = S.layout.main(kind);
        try w.launch(.sponge, .{ .calls = P.ref(dc, 0), .words = P.ref(dw, 0), .outputs = P.ref(dout, 0), .rows = P.ref(dr, 0), .main = P.column(col), .range16 = ledger.at(Ledger.range16), .range8 = ledger.at(Ledger.range8), .and_counts = ledger.at(Ledger.and_), .status = ledger.at(ledger.status()), .count = @intCast(count), .log = log, .kind = @intFromEnum(kind), .first_id = req.request.sponge.first_id, .call_count = @intCast(calls.len), .word_count = @intCast(words.len), .permutation_count = @intCast(np) }, @intCast(col), @intCast(width));
    };
}

// ---------------------------------------------------------------------------
// NativeFactory.pack adapter (capture thread)
// ---------------------------------------------------------------------------

/// The legacy source request of a captured segment. The class/shape owner
/// (setup per class, coordinator advice, first ids) provides it; `release`
/// runs after `pack` returns (the request's borrowed data stays owned by the
/// capture until the request detaches, as `CapturedSegment` documents).
pub const Planned = struct { request: Stage.Request, rows: u64 };
pub const RequestSource = struct {
    ctx: *anyopaque,
    request: *const fn (*anyopaque, *const G.RequestContext, G.CapturedSegment) anyerror!Planned,
    release: ?*const fn (*anyopaque, *const G.RequestContext, u32) void = null,
};

/// `NativeFactory.VTable.pack` body: `RequestSource` -> `pack` -> rows.
pub const Packer = struct {
    a: std.mem.Allocator,
    roms: *P.Roms,
    source: RequestSource,
    mutex: std.Thread.Mutex = .{},
    last: Stats = .{},
    total_pack_ns: u64 = 0,
    total_chunk_words: u64 = 0,
    pub fn packSegment(self: *Packer, rctx: *const G.RequestContext, cs: G.CapturedSegment, out: G.ChunkWriter) !u64 {
        const planned = try self.source.request(self.source.ctx, rctx, cs);
        defer if (self.source.release) |r| r(self.source.ctx, rctx, cs.segment);
        if (planned.request.ordinal != cs.segment) return error.GnPackSegmentMismatch;
        const st = try pack(self.a, planned.request, self.roms, out, planned.rows);
        self.mutex.lock();
        defer self.mutex.unlock();
        self.last = st;
        self.total_pack_ns += st.pack_ns;
        self.total_chunk_words += st.chunk_words;
        return st.rows;
    }
    /// The vtable-shaped entry (ctx = *Packer).
    pub fn hook(raw: *anyopaque, rctx: *const G.RequestContext, cs: G.CapturedSegment, out: G.ChunkWriter) anyerror!u64 {
        const self: *Packer = @ptrCast(@alignCast(raw));
        return self.packSegment(rctx, cs, out);
    }
};

test "gn-pack capture serializer compiles against the legacy source request" {
    std.mem.doNotOptimizeAway(&pack);
    std.mem.doNotOptimizeAway(&Packer.hook);
}
