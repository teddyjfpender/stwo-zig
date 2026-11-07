//! One CPU witness and one native family routing/grouping pass, before setup.
//! Program is borrowed. After moving it into Setup, callers MUST transfer via
//! Sources.fromPrepared, which validates identity and rebinds CPU.program to
//! the final stable Setup address before any row/interaction access.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const core = @import("stwo_core");
const A = front.rv64_air;
const B = A.word16_v1;
const CPU = @import("cpu_source.zig");
const Program = @import("program.zig").Program;
const J = @import("jalr_source.zig");
const Coverage = @import("coverage.zig");
const G = @import("geometry.zig");
pub const Binary = @import("binary_dedup.zig");
pub const Shift = @import("shift_dedup.zig");
pub const Zbb = B.binary_zbb_source;
const Execution = front.rv64.execution_profile;
pub const Options = struct {
    deduplicate_binary: bool = true,
    deduplicate_shift: bool = false,
    /// Legacy wrapper keeps its caller-declared padded JALR geometry.
    jalr_log: ?u32 = null,
};
/// Grouping input size (ALU + BINARY facts + memory records) below which the
/// concurrent groupings run on the calling thread: small inputs are not worth
/// a thread. Pre-T10 legacy value, shared by both routes; not re-tuned by T10
/// (no A/B on record).
const PARALLEL_GROUPING_MIN = 1 << 16;
/// Concurrent provider grouping for `captureInternal` (producer scheduling
/// only: each result is exactly the serial function's result).
const Grouping = struct {
    a: std.mem.Allocator,
    af: []const B.operations.AluFact,
    bf: []const Binary.Fact,
    zf: []const Zbb.Fact,
    memory: []const CPU.MemoryRecord,
    deduplicate_binary: bool,
    alu: anyerror!B.alu_experiment.source.WeightedFacts = error.Unstarted,
    binary: anyerror!Binary.WeightedFacts = error.Unstarted,
    zbb: anyerror!Zbb.Weighted = error.Unstarted,
    words: anyerror!u32 = error.Unstarted,
    const Part = enum { alu, binary, zbb };
    fn run(self: *Grouping) void {
        const parallel = self.af.len + self.bf.len + self.memory.len >= PARALLEL_GROUPING_MIN;
        var threads: [2]?std.Thread = @splat(null);
        if (parallel) {
            threads[0] = std.Thread.spawn(.{}, runBinaryZbb, .{self}) catch null;
            threads[1] = std.Thread.spawn(.{}, runWords, .{self}) catch null;
        }
        if (threads[0] == null) runBinaryZbb(self);
        if (threads[1] == null) runWords(self);
        self.alu = B.alu_experiment.source.deduplicate(self.a, self.af);
        for (threads) |t| if (t) |thread| thread.join();
    }
    fn runBinaryZbb(self: *Grouping) void {
        self.binary = Binary.collect(self.a, self.bf, self.deduplicate_binary);
        self.zbb = Zbb.collect(self.a, self.zf);
    }
    fn runWords(self: *Grouping) void {
        var words: std.AutoHashMapUnmanaged(u64, void) = .empty;
        defer words.deinit(self.a);
        for (self.memory) |record| words.put(self.a, record.effect.address.toInt() & ~@as(u64, 7), {}) catch |err| {
            self.words = err;
            return;
        };
        self.words = @intCast(words.count());
    }
    /// Frees every successful result after `failed` (the caller unwraps in
    /// order, so earlier ones are already owned by its errdefers).
    fn release(self: *Grouping, failed: Part) void {
        if (@intFromEnum(failed) < @intFromEnum(Part.binary)) if (self.binary) |*v| v.deinit() else |_| {};
        if (@intFromEnum(failed) < @intFromEnum(Part.zbb)) if (self.zbb) |*v| v.deinit() else |_| {};
    }
};
/// STWO_RV64_M8_CAPTURE_RECORDER (M8 T10): when set to 1, narrow capture uses
/// the presized recorder route (`Prepared.captureRecorder`, plus the presized
/// scan record lists in cpu_source.zig). Outputs and errors are identical;
/// any other value keeps the legacy route.
pub fn recorderEnabled() bool {
    return CPU.recorderEnabled();
}
const Dedup = @import("stable_dedup.zig");
/// Concurrent provider grouping of the recorder route. Reads ALU/BINARY/SHIFT
/// facts straight from `functions` (op-id ranges as in the legacy routing
/// switch), followed by the JALR-derived extras, exactly the legacy `af`/`bf`
/// concatenation order. Validation and mass checks are the legacy groupers'.
const RecorderGrouping = struct {
    const Op = B.operations;
    const AluCheck = B.alu_experiment.equations;
    const ShiftResult = struct { facts: []Op.ShiftFact, weights: []u32 };
    a: std.mem.Allocator,
    functions: []const CPU.FunctionFact,
    extra_alu: []const Op.AluFact,
    extra_binary: []const Binary.Fact,
    zf: []const Zbb.Fact,
    memory: []const CPU.MemoryRecord,
    n_alu: usize,
    n_binary: usize,
    n_shift: usize,
    deduplicate_binary: bool,
    deduplicate_shift: bool,
    alu: anyerror!B.alu_experiment.source.WeightedFacts = error.Unstarted,
    binary: anyerror!Binary.WeightedFacts = error.Unstarted,
    zbb: anyerror!Zbb.Weighted = error.Unstarted,
    words: anyerror!u32 = error.Unstarted,
    shift: anyerror!?ShiftResult = error.Unstarted,
    adopted: bool = false,
    fn run(self: *RecorderGrouping) void {
        const parallel = self.n_alu + self.n_binary + self.memory.len >= PARALLEL_GROUPING_MIN;
        var threads: [2]?std.Thread = @splat(null);
        if (parallel) {
            threads[0] = std.Thread.spawn(.{}, runBinaryZbbShift, .{self}) catch null;
            threads[1] = std.Thread.spawn(.{}, runWords, .{self}) catch null;
        }
        if (threads[0] == null) runBinaryZbbShift(self);
        if (threads[1] == null) runWords(self);
        self.alu = groupAlu(self);
        for (threads) |t| if (t) |thread| thread.join();
    }
    fn groupAlu(self: *RecorderGrouping) !B.alu_experiment.source.WeightedFacts {
        const total = self.n_alu + self.extra_alu.len;
        if (total >= core.fields.m31.Modulus) return error.AluMultiplicityMassExceeded;
        var g = try Dedup.Grouper(Op.AluFact).init(self.a, total, true);
        {
            errdefer g.deinit();
            for (self.functions) |f| if (f.operation <= 9) {
                const fact: Op.AluFact = .{ .op = @enumFromInt(f.operation), .a = f.a, .b = f.b, .c = f.c };
                if (fact.c != AluCheck.nativeResult(fact.op, fact.a, fact.b)) return error.InvalidAluFact;
                g.add(fact);
            };
            for (self.extra_alu) |fact| {
                if (@intFromEnum(fact.op) > 9 or fact.c != AluCheck.nativeResult(fact.op, fact.a, fact.b)) return error.InvalidAluFact;
                g.add(fact);
            }
        }
        const out = try g.finish();
        return .{ .allocator = self.a, .facts = out.facts, .weights = out.weights };
    }
    fn groupBinary(self: *RecorderGrouping) !Binary.WeightedFacts {
        const total = self.n_binary + self.extra_binary.len;
        if (total >= core.fields.m31.Modulus) return error.BinaryMultiplicityMassExceeded;
        var g = try Dedup.Grouper(Binary.Fact).init(self.a, total, self.deduplicate_binary);
        {
            errdefer g.deinit();
            for (self.functions) |f| if (f.operation >= 16 and f.operation <= 18) g.add(.{ .op = @enumFromInt(f.operation - 16), .a = f.a, .b = f.b, .c = f.c });
            for (self.extra_binary) |fact| {
                if (@intFromEnum(fact.op) > 2) return error.InvalidBinaryFact;
                g.add(fact);
            }
        }
        const out = try g.finish();
        return .{ .allocator = self.a, .facts = out.facts, .weights = out.weights };
    }
    fn groupShift(self: *RecorderGrouping) !?ShiftResult {
        if (!self.deduplicate_shift) return null;
        if (self.n_shift >= core.fields.m31.Modulus) return error.ShiftMultiplicityMassExceeded;
        var g = try Dedup.Grouper(Op.ShiftFact).init(self.a, self.n_shift, true);
        for (self.functions) |f| if (f.operation >= 32 and f.operation <= 37) g.add(.{ .op = @enumFromInt(f.operation - 32), .a = f.a, .b = f.b, .c = f.c });
        const out = try g.finish();
        return .{ .facts = out.facts, .weights = out.weights };
    }
    fn runBinaryZbbShift(self: *RecorderGrouping) void {
        self.binary = groupBinary(self);
        self.zbb = Zbb.collect(self.a, self.zf);
        self.shift = groupShift(self);
    }
    fn runWords(self: *RecorderGrouping) void {
        var words = Dedup.DistinctWords.init(self.a, self.memory.len) catch |err| {
            self.words = err;
            return;
        };
        defer words.deinit();
        for (self.memory) |record| words.add(record.effect.address.toInt() & ~@as(u64, 7));
        self.words = words.distinct;
    }
    /// Frees every successful result unless the caller adopted them all.
    fn release(self: *RecorderGrouping) void {
        if (self.adopted) return;
        if (self.alu) |*v| v.deinit() else |_| {}
        if (self.binary) |*v| v.deinit() else |_| {}
        if (self.zbb) |*v| v.deinit() else |_| {}
        const shift: ?ShiftResult = self.shift catch null;
        if (shift) |v| {
            self.a.free(v.facts);
            self.a.free(v.weights);
        }
    }
};
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    device_cpu_projection: ?CPU.ProjectionStage = null,
    device_cpu_scope: ?@import("stwo_prover_api").device_pcs.Scope = null,
    program_identity: [32]u8,
    cpu: ?CPU.Source,
    jalr: ?J.Source,
    alu: B.alu_experiment.source.WeightedFacts,
    binary: Binary.WeightedFacts,
    shift: []B.operations.ShiftFact,
    shift_weights: []u32,
    division: []A.arithmetic.division.trace.Request,
    multiplication: []A.arithmetic.multiplication.trace.Request,
    /// Zbb BINARY FUNCTION facts (ids 19..24), deduplicated. Non-empty only for
    /// a Zbb-profile program on the v3 services route; their provider is the
    /// services-lane Zbb component (no core role), so core-only routes reject them.
    zbb: Zbb.Weighted,
    raw_counts: Coverage.Counts,
    unique_memory_words: u32,
    pub fn init(a: std.mem.Allocator, program: *const Program, public: A.word16_execution.types.Boundary, epoch: u16, cpu_log: u32, tape: *const front.rv64.compact_tape.Tape, options: Options) !Prepared {
        var result = try capture(a, program, public, epoch, cpu_log, tape, options);
        errdefer result.deinit();
        try result.ensureCpuMain(program, cpu_log);
        return result;
    }
    /// Explicit service witness route. Old constructors remain fail-closed;
    /// acceptance belongs only to the complete Keccak service coordinator.
    pub fn initForKeccak(a: std.mem.Allocator, program: *const Program, public: A.word16_execution.types.Boundary, epoch: u16, cpu_log: u32, tape: *const front.rv64.compact_tape.Tape, options: Options) !Prepared {
        var result = try captureForKeccak(a, program, public, epoch, cpu_log, tape, options);
        errdefer result.deinit();
        try result.ensureCpuMain(program, cpu_log);
        return result;
    }
    /// Explicit LE-word secp witness route; acceptance belongs only to the
    /// complete OWNER/RAM/Wire35 service coordinator, never the old receiver.
    pub fn initForSecp(a: std.mem.Allocator, program: *const Program, public: A.word16_execution.types.Boundary, epoch: u16, cpu_log: u32, tape: *const front.rv64.compact_tape.Tape, options: Options) !Prepared {
        var result = try captureForSecp(a, program, public, epoch, cpu_log, tape, options);
        errdefer result.deinit();
        try result.ensureCpuMain(program, cpu_log);
        return result;
    }
    /// Geometry/grouping ready without CPU MAIN. JALR retains its existing
    /// independently sized witness; this does not claim all providers narrow.
    pub fn capture(a: std.mem.Allocator, program: *const Program, public: A.word16_execution.types.Boundary, epoch: u16, cpu_log: u32, tape: *const front.rv64.compact_tape.Tape, options: Options) !Prepared {
        return captureInternal(a, program, public, epoch, cpu_log, tape, options, .none);
    }
    pub fn captureForKeccak(a: std.mem.Allocator, program: *const Program, public: A.word16_execution.types.Boundary, epoch: u16, cpu_log: u32, tape: *const front.rv64.compact_tape.Tape, options: Options) !Prepared {
        return captureInternal(a, program, public, epoch, cpu_log, tape, options, .keccak);
    }
    pub fn captureForSecp(a: std.mem.Allocator, program: *const Program, public: A.word16_execution.types.Boundary, epoch: u16, cpu_log: u32, tape: *const front.rv64.compact_tape.Tape, options: Options) !Prepared {
        return captureInternal(a, program, public, epoch, cpu_log, tape, options, .secp_words);
    }
    /// Explicit all-three LE ABI route. Old named service routes preserve
    /// their narrower whitelists; actual acceptance requires joined proofs.
    pub fn captureForCombinedServicesLEv2(a: std.mem.Allocator, program: *const Program, public: A.word16_execution.types.Boundary, epoch: u16, cpu_log: u32, tape: *const front.rv64.compact_tape.Tape, options: Options) !Prepared {
        if (tape.execution_profile != .ethereum_services_v2) return error.UnqualifiedWord16ServiceOwners;
        return captureInternal(a, program, public, epoch, cpu_log, tape, options, .combined_words);
    }
    pub fn initForCombinedServicesLEv2(a: std.mem.Allocator, program: *const Program, public: A.word16_execution.types.Boundary, epoch: u16, cpu_log: u32, tape: *const front.rv64.compact_tape.Tape, options: Options) !Prepared {
        var result = try captureForCombinedServicesLEv2(a, program, public, epoch, cpu_log, tape, options);
        errdefer result.deinit();
        try result.ensureCpuMain(program, cpu_log);
        return result;
    }
    /// Admitted v3 LE ABI: v2's three families plus SHA-256 compression. The
    /// v2 route above keeps its exact whitelist; v3 tags need v3 tapes.
    pub fn captureForCombinedServicesV3(a: std.mem.Allocator, program: *const Program, public: A.word16_execution.types.Boundary, epoch: u16, cpu_log: u32, tape: *const front.rv64.compact_tape.Tape, options: Options) !Prepared {
        if (!Execution.isV3(tape.execution_profile)) return error.UnqualifiedWord16ServiceOwners;
        // A Zbb tape needs a Zbb ROM and a Zbb ROM needs a Zbb tape: the
        // program profile (bound into the program identity) and the tape agree.
        if (A.word16_execution.features.zbbProfile(tape.execution_profile) != A.word16_execution.features.zbbProfile(program.profile)) return error.UnqualifiedWord16ServiceOwners;
        return captureInternal(a, program, public, epoch, cpu_log, tape, options, .combined_words_v3);
    }
    /// Either admitted combined profile, selected by the tape's own profile.
    pub fn captureForCombinedServices(a: std.mem.Allocator, program: *const Program, public: A.word16_execution.types.Boundary, epoch: u16, cpu_log: u32, tape: *const front.rv64.compact_tape.Tape, options: Options) !Prepared {
        return if (Execution.isV3(tape.execution_profile)) captureForCombinedServicesV3(a, program, public, epoch, cpu_log, tape, options) else captureForCombinedServicesLEv2(a, program, public, epoch, cpu_log, tape, options);
    }
    pub fn initForCombinedServicesV3(a: std.mem.Allocator, program: *const Program, public: A.word16_execution.types.Boundary, epoch: u16, cpu_log: u32, tape: *const front.rv64.compact_tape.Tape, options: Options) !Prepared {
        var result = try captureForCombinedServicesV3(a, program, public, epoch, cpu_log, tape, options);
        errdefer result.deinit();
        try result.ensureCpuMain(program, cpu_log);
        return result;
    }
    pub const Service = enum { none, keccak, secp_words, combined_words, combined_words_v3 };
    /// Capture route selection (producer scheduling only; every route
    /// returns the same Prepared). `chunks` null = `CPU.Source.capture`'s
    /// own range count; `recorder` = STWO_RV64_M8_CAPTURE_RECORDER.
    pub const Route = struct { recorder: bool, chunks: ?usize = null };
    fn captureInternal(a: std.mem.Allocator, program: *const Program, public: A.word16_execution.types.Boundary, epoch: u16, cpu_log: u32, tape: *const front.rv64.compact_tape.Tape, options: Options, service: Service) !Prepared {
        return captureRoute(a, program, public, epoch, cpu_log, tape, options, service, .{ .recorder = recorderEnabled() });
    }
    pub fn captureRoute(a: std.mem.Allocator, program: *const Program, public: A.word16_execution.types.Boundary, epoch: u16, cpu_log: u32, tape: *const front.rv64.compact_tape.Tape, options: Options, service: Service, route: Route) !Prepared {
        var cpu = if (route.chunks) |chunks| try CPU.Source.captureChunkedRoute(a, program, public, epoch, cpu_log, tape, chunks, route.recorder) else try CPU.Source.captureRoute(a, program, public, epoch, cpu_log, tape, route.recorder);
        errdefer cpu.deinit();
        for (cpu.services.items) |call| {
            const valid = switch (service) {
                .none => false,
                .keccak => call.tag == 0x10001,
                .secp_words => call.tag == 0x20011 or call.tag == 0x20012,
                .combined_words => call.tag == 0x10001 or call.tag == 0x20011 or call.tag == 0x20012,
                .combined_words_v3 => call.tag == 0x10001 or call.tag == 0x20011 or call.tag == 0x20012 or call.tag == 0x30010 or call.tag == 0x30021 or call.tag == 0x30001 or call.tag == 0x30002 or call.tag == 0x30040 or call.tag == 0x30003 or call.tag == 0x30130 or @import("stwo_riscv_frontend").rv64.execution_profile.isCurveTag(call.tag),
            };
            if (!valid) return error.UnqualifiedWord16ServiceOwners;
        }
        if (route.recorder) {
            const result = try captureRecorder(a, program, &cpu, options, service == .combined_words_v3 and A.word16_execution.features.zbbProfile(program.profile));
            reportDigest(&result, epoch, public.steps);
            return result;
        }
        var af: std.ArrayList(B.operations.AluFact) = .empty;
        defer af.deinit(a);
        var bf: std.ArrayList(Binary.Fact) = .empty;
        defer bf.deinit(a);
        var sf: std.ArrayList(B.operations.ShiftFact) = .empty;
        defer sf.deinit(a);
        var jf: std.ArrayList(J.Fact) = .empty;
        defer jf.deinit(a);
        var df: std.ArrayList(A.arithmetic.division.trace.Request) = .empty;
        defer df.deinit(a);
        var mf: std.ArrayList(A.arithmetic.multiplication.trace.Request) = .empty;
        defer mf.deinit(a);
        var zf: std.ArrayList(Zbb.Fact) = .empty;
        defer zf.deinit(a);
        const allow_zbb = service == .combined_words_v3 and A.word16_execution.features.zbbProfile(program.profile);
        for (cpu.functions.items) |f| switch (f.operation) {
            0...9 => try af.append(a, .{ .op = @enumFromInt(f.operation), .a = f.a, .b = f.b, .c = f.c }),
            10 => try jf.append(a, .{ .a = f.a, .b = f.b, .c = f.c }),
            16...18 => try bf.append(a, .{ .op = @enumFromInt(f.operation - 16), .a = f.a, .b = f.b, .c = f.c }),
            32...37 => try sf.append(a, .{ .op = @enumFromInt(f.operation - 32), .a = f.a, .b = f.b, .c = f.c }),
            49...52, 57 => try mf.append(a, .{ .opcode = @enumFromInt(f.operation), .a = f.a, .b = f.b, .result = f.c }),
            53...56, 58...61 => try df.append(a, .{ .opcode = @enumFromInt(f.operation), .a = f.a, .b = f.b, .result = f.c }),
            B.binary_zbb.FIRST_ID...B.binary_zbb.FIRST_ID + B.binary_zbb.OPS - 1 => if (allow_zbb) try zf.append(a, .{ .op = @enumFromInt(f.operation - B.binary_zbb.FIRST_ID), .a = f.a, .b = f.b, .c = f.c }) else return error.UnroutedWord16Function,
            else => return error.UnroutedWord16Function,
        };
        const raw_mul_count: u32 = @intCast(mf.items.len);
        // These are provider obligations, not retired MUL instructions.
        // The same normalized operands authority is used by the DIV witness.
        for (df.items) |request| try mf.appendSlice(a, &try A.arithmetic.division.word16_product.witness.support(request));
        const jalr_log = options.jalr_log orelse try Coverage.minimalLog(@intCast(jf.items.len));
        var jalr = try J.Source.capture(a, jf.items, jalr_log);
        errdefer jalr.deinit();
        const extra_alu = try jalr.aluFacts(a);
        defer a.free(extra_alu);
        try af.appendSlice(a, extra_alu);
        const extra_binary = try jalr.binaryFacts(a);
        defer a.free(extra_binary);
        try bf.appendSlice(a, extra_binary);
        // The four groupings are independent pure functions of finished
        // inputs: run them concurrently, then adopt in the serial order (so a
        // failure reports the error the serial sequence would report first).
        var group = Grouping{ .a = a, .af = af.items, .bf = bf.items, .zf = zf.items, .memory = cpu.memory.items, .deduplicate_binary = options.deduplicate_binary };
        group.run();
        var alu = group.alu catch |err| {
            group.release(.alu);
            return err;
        };
        errdefer alu.deinit();
        var binary = group.binary catch |err| {
            group.release(.binary);
            return err;
        };
        errdefer binary.deinit();
        var zbb = group.zbb catch |err| {
            group.release(.zbb);
            return err;
        };
        errdefer zbb.deinit();
        const unique_memory_words = try group.words;
        const raw_shift_count: u32 = @intCast(sf.items.len);
        const grouped_shift = if (options.deduplicate_shift) try Shift.collect(a, sf.items, true) else null;
        const shift = if (grouped_shift) |value| value.facts else try sf.toOwnedSlice(a);
        errdefer a.free(shift);
        const shift_weights: []u32 = if (grouped_shift) |value| value.weights else &.{};
        errdefer a.free(shift_weights);
        const division = try df.toOwnedSlice(a);
        errdefer a.free(division);
        const multiplication = try mf.toOwnedSlice(a);
        // Every provider fact is now independently owned. Avoid retaining a
        // second copy until all execution shards have sealed their MAIN.
        cpu.releaseFunctionFacts();
        const result: Prepared = .{ .allocator = a, .program_identity = program.identity, .cpu = cpu, .jalr = jalr, .alu = alu, .binary = binary, .shift = shift, .shift_weights = shift_weights, .division = division, .multiplication = multiplication, .zbb = zbb, .raw_counts = .{ .alu = @intCast(af.items.len), .binary = @intCast(bf.items.len), .shift = raw_shift_count, .jalr = @intCast(jf.items.len), .division = @intCast(division.len), .multiplication = raw_mul_count, .memory = @intCast(cpu.memory.items.len), .service = @intCast(cpu.services.items.len) }, .unique_memory_words = unique_memory_words };
        reportDigest(&result, epoch, public.steps);
        return result;
    }
    /// STWO_RV64_M8_CAPTURE_RECORDER_DIGEST set: report-only per-segment
    /// parity line on stderr (both routes), compared across A/B arms.
    fn reportDigest(result: *const Prepared, epoch: u16, steps: usize) void {
        if (std.posix.getenv("STWO_RV64_M8_CAPTURE_RECORDER_DIGEST") == null) return;
        const d = result.diagnosticDigest();
        std.debug.print("T10DIGEST epoch={d} steps={d} sha={s}\n", .{ epoch, steps, std.fmt.bytesToHex(d, .lower) });
    }
    /// Report-only parity digest over every capture output this module
    /// produces (CPU metadata/ROM counts/records, JALR facts, grouped facts and
    /// weights, census). Field by field, never raw struct bytes (padding).
    pub fn diagnosticDigest(self: *const Prepared) [32]u8 {
        const H = struct {
            hash: std.crypto.hash.sha2.Sha256 = .init(.{}),
            fn value(h: *@This(), item: anytype) void {
                const T = @TypeOf(item);
                switch (@typeInfo(T)) {
                    .int => |info| {
                        var bytes: [8]u8 = undefined;
                        std.mem.writeInt(u64, &bytes, @as(std.meta.Int(.unsigned, info.bits), @bitCast(item)), .little);
                        h.hash.update(&bytes);
                    },
                    .bool => h.value(@as(u8, @intFromBool(item))),
                    .@"enum" => h.value(@intFromEnum(item)),
                    .optional => if (item) |inner| {
                        h.value(@as(u8, 1));
                        h.value(inner);
                    } else h.value(@as(u8, 0)),
                    .array => for (item) |entry| h.value(entry),
                    .pointer => |info| {
                        if (info.size != .slice) @compileError("digest may not follow pointers");
                        h.value(@as(u64, item.len));
                        for (item) |entry| h.value(entry);
                    },
                    .@"struct" => |info| inline for (info.fields) |field| h.value(@field(item, field.name)),
                    else => @compileError("unsupported digest value " ++ @typeName(T)),
                }
            }
        };
        var h = H{};
        h.hash.update("stwo/rv64/m8/t10/prepared/v1\x00");
        if (self.cpu) |*cpu| {
            h.value(cpu.metadata);
            h.value(cpu.rom_counts);
            h.value(cpu.memory.items);
            h.value(cpu.services.items);
            h.value(cpu.functions.items);
            h.value(cpu.log_size);
        }
        if (self.jalr) |*jalr| {
            h.value(jalr.facts);
            h.value(jalr.log_size);
        }
        h.value(self.alu.facts);
        h.value(self.alu.weights);
        h.value(self.binary.facts);
        h.value(self.binary.weights);
        h.value(self.shift);
        h.value(self.shift_weights);
        h.value(self.division);
        h.value(self.multiplication);
        h.value(self.zbb.facts);
        h.value(self.zbb.weights);
        h.value(self.raw_counts);
        h.value(self.unique_memory_words);
        return h.hash.finalResult();
    }
    /// STWO_RV64_M8_CAPTURE_RECORDER=1 route of `captureInternal` after the
    /// CPU scan: the same Prepared, field for field, and the same error for
    /// the same reason (pinned by prepared_recorder_test.zig and the
    /// T10DIGEST capture parity). Differences are producer scheduling only:
    /// one counting pass sizes every family list exactly (no regrowth), the
    /// ALU/BINARY/SHIFT groupers read `cpu.functions` in place (no routed
    /// copies), every grouper is a presized open-addressing table
    /// (stable_dedup.zig) instead of a growing std AutoHashMap, and the
    /// SHIFT grouping joins the concurrent groupings. Errors are adopted in
    /// the serial order: routing, ALU, BINARY, ZBB, memory words, SHIFT.
    fn captureRecorder(a: std.mem.Allocator, program: *const Program, cpu: *CPU.Source, options: Options, allow_zbb: bool) !Prepared {
        const Op = B.operations;
        const functions = cpu.functions.items;
        // Pass 1: classify; an unroutable fact fails here exactly as the
        // legacy routing loop fails at its first unroutable fact.
        var n_alu: usize = 0;
        var n_binary: usize = 0;
        var n_shift: usize = 0;
        var n_jalr: usize = 0;
        var n_mul: usize = 0;
        var n_div: usize = 0;
        var n_zbb: usize = 0;
        for (functions) |f| switch (f.operation) {
            0...9 => n_alu += 1,
            10 => n_jalr += 1,
            16...18 => n_binary += 1,
            32...37 => n_shift += 1,
            49...52, 57 => n_mul += 1,
            53...56, 58...61 => n_div += 1,
            B.binary_zbb.FIRST_ID...B.binary_zbb.FIRST_ID + B.binary_zbb.OPS - 1 => if (allow_zbb) {
                n_zbb += 1;
            } else return error.UnroutedWord16Function,
            else => return error.UnroutedWord16Function,
        };
        // Pass 2: the small families (and SHIFT when it is not grouped) as
        // exact-capacity lists, in step order.
        const keep_shift = !options.deduplicate_shift;
        var jf = try std.ArrayList(J.Fact).initCapacity(a, n_jalr);
        defer jf.deinit(a);
        var df = try std.ArrayList(A.arithmetic.division.trace.Request).initCapacity(a, n_div);
        defer df.deinit(a);
        var zf = try std.ArrayList(Zbb.Fact).initCapacity(a, n_zbb);
        defer zf.deinit(a);
        var sf = try std.ArrayList(Op.ShiftFact).initCapacity(a, if (keep_shift) n_shift else 0);
        defer sf.deinit(a);
        if (n_jalr + n_div + n_zbb + n_mul != 0 or keep_shift) for (functions) |f| switch (f.operation) {
            10 => jf.appendAssumeCapacity(.{ .a = f.a, .b = f.b, .c = f.c }),
            32...37 => if (keep_shift) sf.appendAssumeCapacity(.{ .op = @enumFromInt(f.operation - 32), .a = f.a, .b = f.b, .c = f.c }),
            53...56, 58...61 => df.appendAssumeCapacity(.{ .opcode = @enumFromInt(f.operation), .a = f.a, .b = f.b, .result = f.c }),
            B.binary_zbb.FIRST_ID...B.binary_zbb.FIRST_ID + B.binary_zbb.OPS - 1 => zf.appendAssumeCapacity(.{ .op = @enumFromInt(f.operation - B.binary_zbb.FIRST_ID), .a = f.a, .b = f.b, .c = f.c }),
            else => {},
        };
        // MUL requests in step order, then the DIV witness obligations.
        var mf = try std.ArrayList(A.arithmetic.multiplication.trace.Request).initCapacity(a, n_mul);
        defer mf.deinit(a);
        if (n_mul != 0) for (functions) |f| switch (f.operation) {
            49...52, 57 => mf.appendAssumeCapacity(.{ .opcode = @enumFromInt(f.operation), .a = f.a, .b = f.b, .result = f.c }),
            else => {},
        };
        const raw_mul_count: u32 = @intCast(mf.items.len);
        for (df.items) |request| try mf.appendSlice(a, &try A.arithmetic.division.word16_product.witness.support(request));
        const jalr_log = options.jalr_log orelse try Coverage.minimalLog(@intCast(jf.items.len));
        var jalr = try J.Source.capture(a, jf.items, jalr_log);
        errdefer jalr.deinit();
        const extra_alu = try jalr.aluFacts(a);
        defer a.free(extra_alu);
        const extra_binary = try jalr.binaryFacts(a);
        defer a.free(extra_binary);
        var group = RecorderGrouping{ .a = a, .functions = functions, .extra_alu = extra_alu, .extra_binary = extra_binary, .zf = zf.items, .memory = cpu.memory.items, .n_alu = n_alu, .n_binary = n_binary, .n_shift = n_shift, .deduplicate_binary = options.deduplicate_binary, .deduplicate_shift = options.deduplicate_shift };
        group.run();
        defer group.release();
        const alu = try group.alu;
        const binary = try group.binary;
        const zbb = try group.zbb;
        const unique_memory_words = try group.words;
        const grouped_shift = try group.shift;
        group.adopted = true;
        errdefer {
            var v = alu;
            v.deinit();
            var w = binary;
            w.deinit();
            var z = zbb;
            z.deinit();
            if (grouped_shift) |g| {
                a.free(g.facts);
                a.free(g.weights);
            }
        }
        const shift = if (grouped_shift) |value| value.facts else try sf.toOwnedSlice(a);
        errdefer if (grouped_shift == null) a.free(shift);
        const shift_weights: []u32 = if (grouped_shift) |value| value.weights else &.{};
        const division = try df.toOwnedSlice(a);
        errdefer a.free(division);
        const multiplication = try mf.toOwnedSlice(a);
        const raw_jalr: u32 = @intCast(jf.items.len);
        cpu.releaseFunctionFacts();
        return .{ .allocator = a, .program_identity = program.identity, .cpu = cpu.*, .jalr = jalr, .alu = alu, .binary = binary, .shift = shift, .shift_weights = shift_weights, .division = division, .multiplication = multiplication, .zbb = zbb, .raw_counts = .{ .alu = @intCast(n_alu + extra_alu.len), .binary = @intCast(n_binary + extra_binary.len), .shift = @intCast(n_shift), .jalr = raw_jalr, .division = @intCast(division.len), .multiplication = raw_mul_count, .memory = @intCast(cpu.memory.items.len), .service = @intCast(cpu.services.items.len) }, .unique_memory_words = unique_memory_words };
    }
    pub fn geometry(self: *const Prepared) !G.Geometry {
        const cpu = self.cpu orelse return error.PreparedExecutionConsumed;
        return .{ .cpu_log = cpu.log_size, .alu_log = try Coverage.minimalLog(@intCast(self.alu.facts.len)), .binary_log = try Coverage.minimalLog(@intCast(self.binary.facts.len)), .shift_log = try Coverage.minimalLog(@intCast(self.shift.len)), .jalr_log = (self.jalr orelse return error.PreparedExecutionConsumed).log_size, .division_log = try Coverage.minimalLog(@intCast(self.division.len)), .multiplication_log = try Coverage.minimalMultiplicationLog(@intCast(self.multiplication.len)), .ls_log = try Coverage.minimalPrefixLog(self.raw_counts.memory), .boundary_log = try Coverage.minimalPrefixLog(self.unique_memory_words) };
    }
    /// Explicit optional physical class. Ordinary geometry() keeps the legacy
    /// present provider and exact historical proof bytes by default.
    pub fn geometryOmittingEmptyDivision(self: *const Prepared) !G.Geometry {
        var result = try self.geometry();
        result.omit_empty_division = self.division.len == 0;
        return result;
    }
    /// Move the active shard from scratch backing into the prover heap before
    /// projecting MAIN. Normalized memory and service advice has its own owner.
    pub fn moveRetiredCpuCapture(self: *Prepared, a: std.mem.Allocator) !void {
        const cpu = if (self.cpu) |*value| value else return error.PreparedExecutionConsumed;
        const jalr = if (self.jalr) |*value| value else return error.PreparedExecutionConsumed;
        const same = A.memory.ownership.same;
        if (same(cpu.allocator, a) and same(jalr.allocator, a)) return;
        if (!cpu.capture_records_retired or jalr.fixed.len != 0 or jalr.main.len != 0 or jalr.interaction.len != 0)
            return error.CaptureSpillRequiresUnmaterializedCpu;
        var heap_cpu = try cpu.cloneCapture(a);
        errdefer heap_cpu.deinit();
        const heap_jalr = try J.Source.capture(a, jalr.facts, jalr.log_size);
        cpu.deinit();
        jalr.deinit();
        cpu.* = heap_cpu;
        jalr.* = heap_jalr;
    }
    /// Validate/rebind before projection. A projection failure leaves the CPU
    /// and grouped facts here for retry; no ownership moves on this barrier.
    pub fn ensureCpuMain(self: *Prepared, program: *const Program, expected_cpu_log: u32) !void {
        if (!std.mem.eql(u8, &self.program_identity, &program.identity)) return error.PreparedProgramMismatch;
        const cpu = if (self.cpu) |*value| value else return error.PreparedExecutionConsumed;
        if (cpu.log_size != expected_cpu_log) return error.PreparedGeometryMismatch;
        // Compact decode changes AUIPC/JAL facts; layouts cannot be rebound.
        if (cpu.compact != program.compact) return error.PreparedGeometryMismatch;
        cpu.program = program;
        if (cpu.main_projection_closed) {
            if (cpu.main.len == 0 and cpu.device_main.len == 0) return error.ExecutionMainUnavailable;
        } else if (self.device_cpu_projection) |stage| try cpu.projectDevice(stage, self.device_cpu_scope orelse return error.DeviceProjectionScopeRequired) else try cpu.materializeMain();
    }
    pub fn takeCpu(self: *Prepared, program: *const Program, expected_cpu_log: u32) !CPU.Source {
        if (!std.mem.eql(u8, &self.program_identity, &program.identity)) return error.PreparedProgramMismatch;
        var cpu = self.cpu orelse return error.PreparedExecutionConsumed;
        if (cpu.log_size != expected_cpu_log) return error.PreparedGeometryMismatch;
        // Compact decode changes AUIPC/JAL facts; layouts cannot be rebound.
        if (cpu.compact != program.compact) return error.PreparedGeometryMismatch;
        cpu.program = program;
        self.cpu = null;
        return cpu;
    }
    pub fn takeJalr(self: *Prepared, expected_log: u32) !J.Source {
        const value = self.jalr orelse return error.PreparedExecutionConsumed;
        if (value.log_size != expected_log) return error.PreparedGeometryMismatch;
        self.jalr = null;
        return value;
    }
    /// Providers have copied their narrow metadata; discard temporary grouping
    /// arrays immediately, while retaining census fields for telemetry.
    pub fn releaseFacts(self: *Prepared) void {
        self.allocator.free(self.alu.facts);
        self.allocator.free(self.alu.weights);
        self.alu.facts = &.{};
        self.alu.weights = &.{};
        self.allocator.free(self.binary.facts);
        self.allocator.free(self.binary.weights);
        self.binary.facts = &.{};
        self.binary.weights = &.{};
        self.allocator.free(self.shift);
        self.allocator.free(self.shift_weights);
        self.allocator.free(self.division);
        self.allocator.free(self.multiplication);
        self.shift = &.{};
        self.shift_weights = &.{};
        self.division = &.{};
        self.multiplication = &.{};
        // `zbb` is consumed by the services-lane Zbb provider, built after the
        // core sources release their facts; it is freed by deinit.
    }
    pub fn deinit(self: *Prepared) void {
        if (self.cpu) |*value| value.deinit();
        if (self.jalr) |*value| value.deinit();
        self.alu.deinit();
        self.binary.deinit();
        self.allocator.free(self.shift);
        self.allocator.free(self.shift_weights);
        self.allocator.free(self.division);
        self.allocator.free(self.multiplication);
        self.zbb.deinit();
        self.* = undefined;
    }
};
test {
    _ = @import("prepared_recorder_test.zig");
}
