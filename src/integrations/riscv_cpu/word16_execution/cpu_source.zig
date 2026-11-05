//! One pass over narrow captured advice; no interpreter or bulk Retirement copy.
//! The original matrix may be released after sealing. Owned56-byte metadata
//! retains exactly the register values/clocks, dynamic target and ROM row.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const X = front.rv64_air.word16_execution;
const L = X.layout;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Program = @import("program.zig").Program;
const Tape = front.rv64.compact_tape.Tape;
const Projection = front.rv64_air.word16_cpu.native_projection;
pub const FunctionFact = struct { operation: u8, a: u64, b: u64, c: u64 };
pub const MemoryRecord = struct {
    opcode: front.rv64.decode.Opcode,
    a: u64,
    immediate: u64,
    b: u64,
    c: u64,
    epoch: u16,
    tick: u24,
    effect: front.rv64.machine.MemoryEffect,
};
pub const ServiceRecord = struct { pointer: u64, tag: u64, epoch: u16, tick: u24 };
/// Stable narrow ingress layout shared with resident witness formatters. This
/// remains advice: ROM authentication and the CPU/family AIR prove its meaning.
pub const Metadata = extern struct { values: [5]u64, clocks: [3]u32, rom_row: u32 };
comptime {
    std.debug.assert(@sizeOf(Metadata) == 56);
    std.debug.assert(@offsetOf(Metadata, "clocks") == 40);
    std.debug.assert(@offsetOf(Metadata, "rom_row") == 52);
}
const Device = @import("stwo_prover_api").device_pcs;
pub const ProjectionOwner = struct {
    context: *anyopaque,
    /// Must join/release on the device owner thread. Invoked exactly once on
    /// failure, MAIN handoff, or Source destruction before handoff.
    release: *const fn (*anyopaque) void,
};
pub const DeviceLedgers = struct {
    metadata: ?Device.DeviceCoefficients = null,
    range16: Device.DeviceCoefficients,
    range8: Device.DeviceCoefficients,
    pairs: Device.DeviceCoefficients,
    rom: Device.DeviceCoefficients,
};
pub const DeviceProjection = struct {
    ledgers: ?DeviceLedgers = null,
    owner: ?ProjectionOwner = null,
    columns: []const Device.TraceColumn,
    counts16: []const u64,
    counts8: []const u64,
    pair_counts: []const u64,
};
pub const ProjectionStage = struct {
    context: *anyopaque,
    /// Synchronous narrow ingress. The stage owns returned device evaluations
    /// through MAIN commitment and transfers their custody to its proof scope.
    project: *const fn (*anyopaque, *const Source, Device.Scope) anyerror!DeviceProjection,
    /// Optional producer-only CPU0 work before global RAM/roster binding.
    /// Scheduling must return immediately; join/cancel must finish all source
    /// borrows before capture or program owners can be destroyed.
    prestage: ?*const fn (*anyopaque, *const Source, [32]u8) void = null,
    join_prestage: ?*const fn (*anyopaque) anyerror!void = null,
    cancel_prestage: ?*const fn (*anyopaque) void = null,
};
/// Upper bound on parallel capture ranges per tape.
pub const MAX_CAPTURE_CHUNKS = 16;
/// Steps per capture range below which a tape is not split further.
pub const MIN_CAPTURE_CHUNK_STEPS: usize = 1 << 18;
/// Default range count for `Source.capture`: `STWO_RV64_CPU_CAPTURE_CHUNKS`
/// (1 = serial scan) or 8, bounded so every range has at least
/// `MIN_CAPTURE_CHUNK_STEPS` steps. Producer scheduling only.
pub fn captureChunks(steps: usize) usize {
    const wanted: usize = if (std.posix.getenv("STWO_RV64_CPU_CAPTURE_CHUNKS")) |text| std.fmt.parseInt(usize, text, 10) catch 8 else 8;
    return @max(1, @min(@min(wanted, MAX_CAPTURE_CHUNKS), steps / MIN_CAPTURE_CHUNK_STEPS));
}
/// Process-wide budget of extra capture threads (`STWO_RV64_CPU_CAPTURE_THREADS`,
/// default 8). Concurrent batch captures share it first come, first served,
/// so a burst of finished segment walks cannot oversubscribe the host (a CPU
/// quota then throttles the serial ordered ledger, the capture critical path).
/// Any grant yields the same Source; it only changes how many ranges run.
var helper_threads_in_use = std.atomic.Value(usize).init(0);
fn helperBudget() usize {
    const text = std.posix.getenv("STWO_RV64_CPU_CAPTURE_THREADS") orelse return 8;
    return std.fmt.parseInt(usize, text, 10) catch 8;
}
/// M6: a capture on a thread marked critical (the batch the ordered ledger
/// waits on first, see `direct.Job`) is granted `wanted` helpers even past
/// the shared budget (bounded: one batch's ranges). Scheduling only.
pub threadlocal var critical_capture: bool = false;
/// Reserves up to `wanted` helper threads; returns the number granted.
fn reserveHelpers(wanted: usize) usize {
    if (critical_capture) {
        _ = helper_threads_in_use.fetchAdd(wanted, .monotonic);
        return wanted;
    }
    const budget = helperBudget();
    var used = helper_threads_in_use.load(.monotonic);
    while (true) {
        const grant = @min(wanted, budget -| used);
        if (grant == 0) return 0;
        used = helper_threads_in_use.cmpxchgWeak(used, used + grant, .monotonic, .monotonic) orelse return grant;
    }
}
fn releaseHelpers(count: usize) void {
    _ = helper_threads_in_use.fetchSub(count, .monotonic);
}
/// Runs `func` on every item, items[1..] on their own threads (inline if a
/// thread cannot be spawned), items[0] on the caller, and joins them all.
fn parallel(comptime T: type, items: []T, comptime func: fn (*T) void) void {
    var threads: [MAX_CAPTURE_CHUNKS]?std.Thread = @splat(null);
    for (items[1..], 1..) |*item, i| threads[i] = std.Thread.spawn(.{}, func, .{item}) catch blk: {
        func(item);
        break :blk null;
    };
    func(&items[0]);
    for (threads[1..items.len]) |t| if (t) |thread| thread.join();
}
/// One contiguous step range of `Source.capture` (see `captureChunked`).
const Scan = struct {
    const Expectation = struct { index: usize, register: u5, value: u64 };
    const Fixup = struct { index: usize, slot: u2, register: u5 };
    allocator: std.mem.Allocator,
    program: *const Program,
    tape: *const Tape,
    metadata: []Metadata,
    epoch: u16,
    stride: u32,
    start: usize,
    end: usize,
    /// In: the pc before step `start`. Out: the pc after the last step.
    pc: u64,
    registers: [32]u64,
    clocks: [32]u32 = @splat(0),
    /// Registers whose value (resp. access clock) is known in this range:
    /// all of them for the first range; otherwise x0, plus each register
    /// once it is first read/written (resp. accessed) here.
    known: u32 = ~@as(u32, 0),
    touched: u32 = ~@as(u32, 0),
    /// First reads of registers unknown on entry, in step order.
    expectations: [96]Expectation = undefined,
    expected: usize = 0,
    /// First accesses of registers whose clock is unknown on entry.
    fixups: [96]Fixup = undefined,
    fixed: usize = 0,
    /// Serial scan: the Source's ROM counts. Stitched range: its own.
    rom_counts: []u64 = &.{},
    rom_local: []u32 = &.{},
    functions: std.ArrayList(FunctionFact) = .empty,
    memory: std.ArrayList(MemoryRecord) = .empty,
    services: std.ArrayList(ServiceRecord) = .empty,
    err: ?anyerror = null,
    err_index: usize = 0,
    fn deinit(self: *Scan) void {
        self.functions.deinit(self.allocator);
        self.memory.deinit(self.allocator);
        self.services.deinit(self.allocator);
    }
    fn runStitched(self: *Scan) void {
        self.run(true);
    }
    fn run(self: *Scan, comptime stitched: bool) void {
        if (stitched) {
            // Typical density (FUNCTION ~1/2, memory ~1/3 of steps): reserve
            // virtual capacity once instead of regrowing; growth still works.
            const n = self.end - self.start;
            self.functions.ensureTotalCapacity(self.allocator, n / 2) catch {};
            self.memory.ensureTotalCapacity(self.allocator, n / 2) catch {};
        }
        var index = self.start;
        while (index < self.end) : (index += 1) {
            self.step(stitched, index) catch |err| {
                self.err = err;
                self.err_index = index;
                return;
            };
        }
    }
    inline fn adopt(self: *Scan, id: u5, value: u64, index: usize) void {
        const bit = @as(u32, 1) << id;
        if (self.known & bit != 0) return;
        self.known |= bit;
        self.registers[id] = value;
        self.expectations[self.expected] = .{ .index = index, .register = id, .value = value };
        self.expected += 1;
    }
    inline fn step(self: *Scan, comptime stitched: bool, index: usize) !void {
        const program = self.program;
        const pc = self.pc;
        const registers = &self.registers;
        const clocks = &self.clocks;
        const meta = &self.metadata[index];
        const word = try program.lookup(pc);
        const entry = program.entries[word];
        if (!entry.valid or (program.compact and !entry.compactValid())) return error.UnadmittedExecutionInstruction;
        const record = try self.tape.restore(index, .{ .raw = entry.raw, .instruction = entry.instruction }, .local);
        const effects = front.rv64.execution_profile.effects(.ethereum_services_v2, entry.instruction.opcode);
        if (stitched) {
            self.adopt(entry.ids[0], record.lhs.toInt(), index);
            self.adopt(entry.ids[1], record.rhs.toInt(), index);
            if (effects.writes_rd) self.adopt(entry.ids[2], record.previous_rd.toInt(), index);
        }
        const jump = entry.instruction.opcode == .JAL or entry.dynamic_next;
        if (record.clock != index + 1 or record.pc.toInt() != pc or record.instruction != entry.raw or record.opcode != entry.instruction.opcode or record.rs1 != entry.ids[0] or record.rs2 != entry.ids[1] or record.rd != entry.ids[2] or record.lhs.toInt() != registers[entry.ids[0]] or record.rhs.toInt() != registers[entry.ids[1]] or record.previous_rd.toInt() != (if (effects.writes_rd) registers[entry.ids[2]] else 0) or record.writes_rd != (effects.writes_rd and entry.ids[2] != 0) or record.immediate.toInt() != @as(u64, @bitCast(entry.instruction.imm))) return error.InvalidExecutionAdvice;
        if ((!entry.branch and record.branch_taken != jump) or (entry.branch and record.result.toInt() != 0)) return error.InvalidExecutionAdvice;
        const next = record.next_pc.toInt();
        if (next & 3 != 0 or (!entry.dynamic_next and next != entry.staticNext(entry.branch and record.branch_taken))) return error.InvalidExecutionAdvice;
        if (program.compact and !X.features.compactPcAdmitted(next)) return error.InvalidExecutionAdvice;
        const c = if (entry.branch) @intFromBool(record.branch_taken) else record.result.toInt();
        const rom_row = try program.factIndex(word, entry.branch and record.branch_taken);
        meta.* = .{ .values = .{ record.lhs.toInt(), record.rhs.toInt(), c, record.previous_rd.toInt(), next }, .clocks = undefined, .rom_row = @intCast(rom_row) };
        for (entry.ids, 0..) |id, slot| {
            if (stitched and id != 0 and self.touched & (@as(u32, 1) << @intCast(id)) == 0) {
                self.touched |= @as(u32, 1) << @intCast(id);
                self.fixups[self.fixed] = .{ .index = index, .slot = @intCast(slot), .register = @intCast(id) };
                self.fixed += 1;
                meta.clocks[slot] = 0; // patched by the ordered stitch
            } else meta.clocks[slot] = if (id == 0) 0 else clocks[id];
            if (id != 0) clocks[id] = @intCast(4 * index + slot + 1);
        }
        if (stitched) self.rom_local[L.physical(rom_row, program.log_size)] += 1 else self.rom_counts[L.physical(rom_row, program.log_size)] += 1;
        const a = self.allocator;
        if (entry.function) {
            if (record.memory != null) return error.InvalidExecutionAdvice;
            // Compact decode folds AUIPC/JAL to ADD(0, pc+imm) / ADD(0, pc+4).
            const fact_a = if (entry.use_pc and !program.compact) pc else meta.values[0];
            const fact_b = if (!entry.use_immediate) meta.values[1] else if (program.compact) entry.compactB() else entry.immediate;
            try self.functions.append(a, .{ .operation = entry.operation, .a = fact_a, .b = fact_b, .c = if (entry.dynamic_next) next else c });
        } else if (entry.instruction.opcode == .ECALL) {
            if (record.memory != null or c != 0) return error.InvalidExecutionAdvice;
            try self.services.append(a, .{ .pointer = meta.values[0], .tag = meta.values[1], .epoch = self.epoch, .tick = @intCast(self.stride * (index + 1)) });
        } else {
            const effect = record.memory orelse return error.MissingExecutionMemory;
            try self.memory.append(a, .{ .opcode = entry.instruction.opcode, .a = meta.values[0], .immediate = entry.immediate, .b = meta.values[1], .c = c, .epoch = self.epoch, .tick = @intCast(self.stride * (index + 1)), .effect = effect });
        }
        // A written register is already known: its previous value was adopted.
        if (effects.writes_rd and entry.ids[2] != 0) registers[entry.ids[2]] = record.result.toInt();
        self.pc = next;
    }
};
/// Ordered concatenation of one range's records, plus one slice of the ROM
/// count reduction, run in parallel after the stitch.
const Join = struct {
    scan: *const Scan,
    functions: []FunctionFact,
    memory: []MemoryRecord,
    services: []ServiceRecord,
    rom: []u64,
    rom_start: usize,
    local_counts: []const []u32,
    fn run(self: *Join) void {
        @memcpy(self.functions, self.scan.functions.items);
        @memcpy(self.memory, self.scan.memory.items);
        @memcpy(self.services, self.scan.services.items);
        for (self.local_counts) |counts| for (self.rom, counts[self.rom_start..][0..self.rom.len]) |*total, n| {
            total.* += n;
        };
    }
};
pub const Source = struct {
    allocator: std.mem.Allocator,
    program: *const Program,
    public: X.types.Boundary,
    epoch: u16,
    log_size: u32,
    metadata: []Metadata,
    main: []M = &.{},
    device_main: []const Device.TraceColumn = &.{},
    device_ledgers: ?DeviceLedgers = null,
    device_projection_owner: ?ProjectionOwner = null,
    device_pair_counts: []u64 = &.{},
    /// Sticky after successful projection or explicit retirement. A cleared
    /// MAIN never authorizes a second wide projection from the same capture.
    main_projection_closed: bool = false,
    interaction: []M = &.{},
    /// Opt-in fused-tail interaction encoding (Geometry.cpu_fused_tail).
    fused_tail: bool = false,
    /// Opt-in byte-pair lookups (Geometry.cpu_u8_pairs, implies fused_tail).
    u8_pairs: bool = false,
    /// Compact decode MAIN (Geometry.cpu_compact_decode). Fixed at capture
    /// from Program.compact: it changes the AUIPC/JAL FUNCTION facts, so a
    /// capture can only be bound to a program owner of the same layout.
    compact: bool = false,
    rom_counts: []u64,
    counts16: []u64,
    counts8: []u64,
    capture_records_retired: bool = false,
    functions: std.ArrayList(FunctionFact) = .empty,
    memory: std.ArrayList(MemoryRecord) = .empty,
    services: std.ArrayList(ServiceRecord) = .empty,
    /// Narrow replay transport only. Normalized family and RAM obligations are
    /// retained separately by Prepared/Advice; no host field-column witness is
    /// cloned or constructed. The normal device formatter still proves it.
    pub fn cloneCapture(self: *const Source, a: std.mem.Allocator) !Source {
        if (self.main_projection_closed or self.main.len != 0 or self.interaction.len != 0 or self.device_main.len != 0 or self.device_projection_owner != null) return error.CpuReplayRequiresUnmaterializedCapture;
        const metadata = try a.dupe(Metadata, self.metadata);
        errdefer a.free(metadata);
        const rom = try a.dupe(u64, self.rom_counts);
        errdefer a.free(rom);
        const r16 = try a.dupe(u64, self.counts16);
        errdefer a.free(r16);
        const r8 = try a.dupe(u64, self.counts8);
        // Raw memory/service records are deliberately NOT copied. Their
        // normalized obligations stay owned by Prepared/Advice, even when
        // Ethereum already retired the transport records before proving.
        return .{ .allocator = a, .program = self.program, .public = self.public, .epoch = self.epoch, .log_size = self.log_size, .metadata = metadata, .rom_counts = rom, .counts16 = r16, .counts8 = r8, .fused_tail = self.fused_tail, .u8_pairs = self.u8_pairs, .compact = self.compact, .capture_records_retired = true };
    }
    /// Compatibility wrapper: one capture followed by one wide projection.
    pub fn init(a: std.mem.Allocator, program: *const Program, public: X.types.Boundary, epoch: u16, log_size: u32, tape: *const Tape) !Source {
        var result = try capture(a, program, public, epoch, log_size, tape);
        errdefer result.deinit();
        try result.materializeMain();
        return result;
    }
    /// Validates/restores Tape once and retains only narrow advice and facts.
    /// Neither MAIN nor its range histograms are constructed in this phase.
    /// Long tapes are scanned as up to `captureChunks` contiguous ranges on
    /// parallel threads and stitched in order (see `captureChunked`).
    pub fn capture(a: std.mem.Allocator, program: *const Program, public: X.types.Boundary, epoch: u16, log_size: u32, tape: *const Tape) !Source {
        const wanted = captureChunks(public.steps);
        const helpers = if (wanted > 1) reserveHelpers(wanted - 1) else 0;
        defer releaseHelpers(helpers);
        return captureChunked(a, program, public, epoch, log_size, tape, helpers + 1);
    }
    /// Producer scheduling only: every `chunks` value returns the same Source
    /// (metadata, ROM counts, FUNCTION/memory/service records in step order)
    /// and the error the serial scan returns, for the same reason.
    ///
    /// A chunk [start, end) starts at the tape's own recorded pc
    /// (`storage[start-1].next_pc`, exactly the serial loop's `pc`). Register
    /// values and access clocks entering the chunk are unknown: the first read
    /// of a register adopts the tape's value and records an expectation; the
    /// first access of a register records a clock fix-up. The ordered stitch
    /// then checks every expectation against the true prefix state (an
    /// unmet one fails as the serial check at that step would) and patches the
    /// fix-ups before folding the chunk's state into the prefix. Checks inside
    /// a chunk are the serial checks verbatim, so once the expectations hold
    /// they see the serial register file.
    pub fn captureChunked(a: std.mem.Allocator, program: *const Program, public: X.types.Boundary, epoch: u16, log_size: u32, tape: *const Tape, requested_chunks: usize) !Source {
        _ = try X.types.inputs(public, epoch, log_size);
        if (tape.len != public.steps or tape.initial_pc != public.initial_pc) return error.InvalidExecutionAdvice;
        const metadata = try a.alloc(Metadata, public.steps);
        errdefer a.free(metadata);
        const rom_counts = try a.alloc(u64, program.size());
        errdefer a.free(rom_counts);
        const counts16 = try a.alloc(u64, 65536);
        errdefer a.free(counts16);
        const counts8 = try a.alloc(u64, 256);
        errdefer a.free(counts8);
        @memset(rom_counts, 0);
        @memset(counts16, 0);
        @memset(counts8, 0);
        const stride: u32 = L.ramStride(log_size);
        const steps: usize = public.steps;
        const chunks = @max(1, @min(requested_chunks, @min(MAX_CAPTURE_CHUNKS, steps)));
        var functions: std.ArrayList(FunctionFact) = .empty;
        errdefer functions.deinit(a);
        var memory: std.ArrayList(MemoryRecord) = .empty;
        errdefer memory.deinit(a);
        var services: std.ArrayList(ServiceRecord) = .empty;
        errdefer services.deinit(a);
        if (chunks == 1) {
            var scan = Scan{ .allocator = a, .program = program, .tape = tape, .metadata = metadata, .epoch = epoch, .stride = stride, .start = 0, .end = steps, .pc = public.initial_pc, .registers = public.initial_registers, .rom_counts = rom_counts };
            errdefer scan.deinit();
            scan.run(false);
            if (scan.err) |err| return err;
            if (scan.pc != public.final_pc or !std.mem.eql(u64, &scan.registers, &public.final_registers) or !std.mem.eql(u32, &scan.clocks, &public.register_clocks)) return error.InvalidExecutionBoundary;
            functions = scan.functions;
            memory = scan.memory;
            services = scan.services;
        } else {
            var scans: [MAX_CAPTURE_CHUNKS]Scan = undefined;
            var local_counts: [MAX_CAPTURE_CHUNKS][]u32 = undefined;
            var made: usize = 0;
            defer for (scans[0..made], local_counts[0..made]) |*scan, counts| {
                scan.deinit();
                a.free(counts);
            };
            for (0..chunks) |c| {
                const start = steps * c / chunks;
                const counts = try a.alloc(u32, program.size());
                errdefer a.free(counts);
                @memset(counts, 0);
                local_counts[c] = counts;
                scans[c] = .{ .allocator = a, .program = program, .tape = tape, .metadata = metadata, .epoch = epoch, .stride = stride, .start = start, .end = steps * (c + 1) / chunks, .pc = if (start == 0) public.initial_pc else tape.storage[start - 1].next_pc, .registers = if (start == 0) public.initial_registers else @splat(0), .known = if (start == 0) ~@as(u32, 0) else 1, .touched = if (start == 0) ~@as(u32, 0) else 0, .rom_local = counts };
                made += 1;
            }
            parallel(Scan, scans[0..chunks], Scan.runStitched);
            // Ordered stitch: the first failing step wins, as in the serial scan.
            var registers = public.initial_registers;
            var clocks: [32]u32 = @splat(0);
            for (scans[0..chunks]) |*scan| {
                for (scan.expectations[0..scan.expected]) |e| if (registers[e.register] != e.value) {
                    if (scan.err == null or e.index <= scan.err_index) return error.InvalidExecutionAdvice;
                    break;
                };
                if (scan.err) |err| return err;
                for (scan.fixups[0..scan.fixed]) |f| metadata[f.index].clocks[f.slot] = clocks[f.register];
                for (0..32) |r| {
                    if (scan.known & (@as(u32, 1) << @intCast(r)) != 0) registers[r] = scan.registers[r];
                    if (scan.touched & (@as(u32, 1) << @intCast(r)) != 0) clocks[r] = scan.clocks[r];
                }
            }
            if (scans[chunks - 1].pc != public.final_pc or !std.mem.eql(u64, &registers, &public.final_registers) or !std.mem.eql(u32, &clocks, &public.register_clocks)) return error.InvalidExecutionBoundary;
            var totals: [3]usize = @splat(0);
            for (scans[0..chunks]) |*scan| {
                totals[0] += scan.functions.items.len;
                totals[1] += scan.memory.items.len;
                totals[2] += scan.services.items.len;
            }
            try functions.ensureTotalCapacityPrecise(a, totals[0]);
            try memory.ensureTotalCapacityPrecise(a, totals[1]);
            try services.ensureTotalCapacityPrecise(a, totals[2]);
            functions.items.len = totals[0];
            memory.items.len = totals[1];
            services.items.len = totals[2];
            var joins: [MAX_CAPTURE_CHUNKS]Join = undefined;
            var offsets: [3]usize = @splat(0);
            for (scans[0..chunks], 0..) |*scan, c| {
                joins[c] = .{ .scan = scan, .functions = functions.items[offsets[0]..][0..scan.functions.items.len], .memory = memory.items[offsets[1]..][0..scan.memory.items.len], .services = services.items[offsets[2]..][0..scan.services.items.len], .rom = rom_counts[rom_counts.len * c / chunks .. rom_counts.len * (c + 1) / chunks], .rom_start = rom_counts.len * c / chunks, .local_counts = local_counts[0..chunks] };
                offsets[0] += scan.functions.items.len;
                offsets[1] += scan.memory.items.len;
                offsets[2] += scan.services.items.len;
            }
            parallel(Join, joins[0..chunks], Join.run);
        }
        if (program.compact) try X.types.validateCompactInputs(try X.types.inputs(public, epoch, log_size), log_size);
        return .{ .allocator = a, .program = program, .compact = program.compact, .public = public, .epoch = epoch, .log_size = log_size, .metadata = metadata, .rom_counts = rom_counts, .counts16 = counts16, .counts8 = counts8, .functions = functions, .memory = memory, .services = services };
    }
    pub fn projectDevice(self: *Source, stage: ProjectionStage, scope: Device.Scope) !void {
        if (self.main_projection_closed or self.main.len != 0 or self.device_main.len != 0) return error.ExecutionMainProjectionClosed;
        const projected = try stage.project(stage.context, self, scope);
        var adopted = false;
        defer if (!adopted) {
            if (projected.owner) |owner| owner.release(owner.context);
        };
        if (projected.columns.len != L.mainCount(self.compact)) return error.InvalidCpuDeviceProjection;
        for (projected.columns) |column| {
            try column.validate();
            if (column.log_size != self.log_size or column.encoding != .evaluations or column.device == null) return error.InvalidCpuDeviceProjection;
        }
        if (projected.ledgers) |ledgers| {
            if (projected.owner == null or projected.counts16.len != 0 or projected.counts8.len != 0 or projected.pair_counts.len != 0) return error.InvalidCpuDeviceProjection;
            const token = projected.columns[0].device.?.context_token;
            for ([_]Device.DeviceCoefficients{ ledgers.range16, ledgers.range8, ledgers.pairs, ledgers.rom }, [_]usize{ 65536, 256, 65536, self.program.size() }) |ledger, count| {
                if (@intFromPtr(ledger.words) == 0 or ledger.count != count or ledger.context_token != token or ledger.generation == 0) return error.InvalidCpuDeviceProjection;
            }
            if (ledgers.metadata) |metadata| {
                if (@intFromPtr(metadata.words) == 0 or metadata.count != self.metadata.len * (@sizeOf(Metadata) / 4) or metadata.context_token != token or metadata.generation == 0) return error.InvalidCpuDeviceProjection;
            } else if (self.metadata.len != 0) return error.InvalidCpuDeviceProjection;
            self.device_ledgers = ledgers;
        } else {
            if (projected.counts16.len != self.counts16.len or projected.counts8.len != self.counts8.len or projected.pair_counts.len != 65536) return error.InvalidCpuDeviceProjection;
            for (projected.counts16) |count| if (count >= core.fields.m31.Modulus) return error.InvalidCpuDeviceProjection;
            for (projected.counts8) |count| if (count >= core.fields.m31.Modulus) return error.InvalidCpuDeviceProjection;
            const pairs = try self.allocator.dupe(u64, projected.pair_counts);
            @memcpy(self.counts16, projected.counts16);
            @memcpy(self.counts8, projected.counts8);
            self.device_pair_counts = pairs;
        }
        self.device_main = projected.columns;
        self.device_projection_owner = projected.owner;
        adopted = true;
        self.main_projection_closed = true;
    }
    /// A failed allocation/projection leaves the capture reusable: MAIN stays
    /// empty, range histograms stay zero, metadata/facts/ROM counts stay owned.
    /// No Tape access or instruction replay occurs here.
    pub fn materializeMain(self: *Source) !void {
        if (self.main_projection_closed or self.main.len != 0) return error.ExecutionMainProjectionClosed;
        _ = try X.types.inputs(self.public, self.epoch, self.log_size);
        if (self.metadata.len != self.public.steps) return error.InvalidExecutionSourcePhase;
        if (self.compact != self.program.compact) return error.InvalidCpuCompactGeometry;
        @memset(self.counts16, 0);
        @memset(self.counts8, 0);
        errdefer {
            @memset(self.counts16, 0);
            @memset(self.counts8, 0);
        }
        const main = try self.allocator.alloc(M, L.mainCount(self.compact) * self.size());
        errdefer self.allocator.free(main);
        var staged = self.*;
        staged.main = main;
        // Total captured rows and all allocations/submissions are admitted
        // before writes. Only this provisional matrix may be discarded.
        try Projection.fill(self.allocator, self.log_size, .{ .context = &staged, .rows = fill }, self.counts16, self.counts8, engine.work_pool.currentScopedPool());
        self.main = main;
        self.main_projection_closed = true;
    }
    fn fill(ctx: *const anyopaque, start: usize, end: usize, counts16: []u64, counts8: []u64) void {
        const self: *const Source = @ptrCast(@alignCast(ctx));
        const n = self.size();
        const wide = L.wideClock(self.log_size);
        for (start..end) |physical| {
            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, self.log_size), self.log_size);
            const values = self.row(logical) catch unreachable; // prevalidated framing.
            for (values[0..L.mainCount(self.compact)], 0..) |value, column| self.main[column * n + physical] = value;
            const gap16: usize = if (self.compact) L.compact.gap16 else L.main.gap16;
            const gap8: usize = if (self.compact) L.compact.gap8 else L.main.gap8;
            for (0..3) |slot| {
                counts16[values[gap16 + slot].v] += 1;
                // Wide clock: gap8 < 2^9 is queried as the U16 value 128*gap8.
                if (wide) counts16[L.WIDE_GAP_SCALE * values[gap8 + slot].v] += 1 else counts8[values[gap8 + slot].v] += 1;
            }
        }
    }
    pub fn row(self: *const Source, logical: usize) !X.row.Main {
        if (self.metadata.len != self.public.steps) return error.InvalidExecutionSourcePhase;
        if (logical >= self.size()) return error.InvalidExecutionRow;
        if (self.compact != self.program.compact) return error.InvalidCpuCompactGeometry;
        if (logical >= self.metadata.len) return if (self.compact) X.row.compact.padding(@intCast(logical), self.public.final_pc) else X.row.padding(@intCast(logical), self.public.final_pc);
        const meta = self.metadata[logical];
        const entry = self.program.entries[self.program.row_to_entry[meta.rom_row]];
        if (self.compact) return X.row.compact.active(entry, @intCast(logical), meta.values[4], .{ .a = meta.values[0], .b = meta.values[1], .c = meta.values[2], .previous_rd = meta.values[3] }, meta.clocks);
        return X.row.active(entry, @intCast(logical), meta.values[4], .{ .a = meta.values[0], .b = meta.values[1], .c = meta.values[2], .previous_rd = meta.values[3] }, meta.clocks);
    }
    pub fn size(self: *const Source) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn releaseMain(self: *Source) void {
        self.main_projection_closed = true;
        self.allocator.free(self.main);
        self.main = &.{};
        self.device_main = &.{};
        self.device_ledgers = null;
        if (self.device_projection_owner) |owner| {
            self.device_projection_owner = null;
            owner.release(owner.context);
        }
    }
    pub fn takeMainForCommit(self: *Source) ![]M {
        if (self.main.len == 0) return error.ExecutionMainUnavailable;
        const main = self.main;
        self.main = &.{};
        self.main_projection_closed = true;
        return main;
    }
    /// Grouped provider facts have copied these values; CPU projection and
    /// interactions read only metadata and the authenticated ROM entries.
    pub fn releaseFunctionFacts(self: *Source) void {
        self.functions.deinit(self.allocator);
        self.functions = .empty;
    }
    /// Only after chronological RAM/service advice has copied all records.
    /// A caller must then supply owned prepared memory to build this source.
    pub fn releaseCaptureRecords(self: *Source) void {
        self.memory.deinit(self.allocator);
        self.memory = .empty;
        self.services.deinit(self.allocator);
        self.services = .empty;
        self.capture_records_retired = true;
    }
    pub fn releaseFacts(self: *Source) void {
        self.releaseFunctionFacts();
        self.releaseCaptureRecords();
    }
    pub fn deinit(self: *Source) void {
        self.releaseMain();
        self.releaseFacts();
        self.allocator.free(self.interaction);
        self.allocator.free(self.metadata);
        self.allocator.free(self.rom_counts);
        self.allocator.free(self.counts16);
        self.allocator.free(self.counts8);
        self.allocator.free(self.device_pair_counts);
        self.* = undefined;
    }
    pub fn columns(self: *const Source, a: std.mem.Allocator, tree: u2) ![]engine.pcs.ColumnEvaluation {
        const data = switch (tree) {
            1 => self.main,
            2 => self.interaction,
            else => return error.InvalidExecutionTree,
        };
        if (data.len == 0) return error.InvalidExecutionSourcePhase;
        const result = try a.alloc(engine.pcs.ColumnEvaluation, data.len / self.size());
        for (result, 0..) |*c, i| c.* = .{ .log_size = self.log_size, .values = data[i * self.size() ..][0..self.size()] };
        return result;
    }
    pub fn generate(self: *Source, ch: X.types.Challenges, dictionaries: @import("cpu_interaction.zig").Dictionaries) !Q {
        return @import("cpu_interaction.zig").generate(self, ch, dictionaries, engine.work_pool.currentScopedPool());
    }
};
