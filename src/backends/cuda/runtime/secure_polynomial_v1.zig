//! Strict-AOT resident bridge for canonical word-memory/range16 secure DAGs.
//! Plans own only bounded host schema/ingress metadata; every device buffer is
//! provided and charged by the proof owner's arena. Device outputs are pending
//! until ProofStatus.complete reads/synchronizes status at proof assembly.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
pub const ir = @import("stwo_prover_engine").air.secure_polynomial_program_v1;
const codegen = @import("../secure_polynomial_resident_codegen_v1.zig");
pub const registry = @import("../aot/secure_polynomial_registry_v1.zig");
const common = @import("stages/common.zig");
const layout = @import("stages/resident_layout.zig");
const column = @import("column.zig");
const Kernel = @import("kernel.zig").Kernel;
const Stage = @import("telemetry.zig").Stage;
const quotient = core.poly.circle.quotient_geometry;
pub const Words = common.Words;
pub const U64s = column.DeviceSlice(u64);
pub const TABLE_WORDS = 65536 * 5;
pub const MAX_SCAN_LEVELS = 4;
pub const Limits = struct {
    max_trace_log: u32 = 25,
    max_resident_bytes: usize = 24 * 1024 * 1024 * 1024,
    max_metadata_bytes: usize = 2 * 1024 * 1024,
};
pub const Geometry = struct {
    rows: u32,
    batches: u32,
    output_words: usize,
    totals_words: usize,
    scan_words: [MAX_SCAN_LEVELS]usize = @splat(0),
    scan_rows: [MAX_SCAN_LEVELS]u32 = @splat(0),
    levels: usize = 0,
    charged_bytes: usize,
    pub fn fractions(trace_log: u32, batches: u32, limits: Limits) !Geometry {
        const rows = try admittedRows(trace_log, limits);
        if (batches != 17 and batches != 2 and batches != 23) return error.InvalidSecureInvocation;
        var g = Geometry{ .rows = rows, .batches = batches, .output_words = try wordsFor(rows, batches * 4), .totals_words = batches * 4, .charged_bytes = 0 };
        var n = rows;
        while (true) {
            const next = (n + 255) / 256;
            if (g.levels == MAX_SCAN_LEVELS) return error.InvalidSecureScanGeometry;
            g.scan_rows[g.levels] = next;
            g.scan_words[g.levels] = try wordsFor(next, batches * 4);
            g.levels += 1;
            if (next == 1) break;
            n = next;
        }
        var total = try std.math.add(usize, g.output_words, g.totals_words);
        total = try std.math.add(usize, total, TABLE_WORDS);
        total = try std.math.add(usize, total, 1); // aggregate fail-closed status
        for (g.scan_words[0..g.levels]) |n_words| total = try std.math.add(usize, total, n_words);
        g.charged_bytes = try std.math.mul(usize, total, 4);
        if (g.charged_bytes > limits.max_resident_bytes) return error.SecureResidentCap;
        return g;
    }
};
/// One status word per proof, initialized once at ingress and shared by all
/// secure dispatches. Never clear it between kernels. Complete before publishing
/// or consuming a proof; zero-filled rows from a pole are never successful data.
var next_status_id = std.atomic.Value(u64).init(1);
pub const ProofStatus = struct {
    word: Words,
    id: u64,
    checked: bool = false,
    successful: bool = false,
    pub fn begin(session: anytype, word: Words) !ProofStatus {
        try common.requireStage(session, .ingress);
        _ = try exact(session, word, 1);
        try session.context.zeroDeviceSlice(u32, word);
        var id = next_status_id.load(.monotonic);
        while (true) {
            if (id == std.math.maxInt(u64)) return error.SecureStatusIdentityExhausted;
            if (next_status_id.cmpxchgWeak(id, id + 1, .monotonic, .monotonic)) |observed| {
                id = observed;
            } else break;
        }
        return .{ .word = word, .id = id };
    }
    pub fn requirePending(self: *const ProofStatus, session: anytype) !void {
        if (self.checked) return error.SecureStatusAlreadyCompleted;
        _ = try exact(session, self.word, 1);
    }
    pub fn check(self: *ProofStatus, session: anytype) !Completion {
        try common.requireStage(session, .proof_assembly);
        try self.requirePending(session);
        var status: [1]u32 = undefined;
        try session.context.readProofSlice(u32, &status, self.word);
        try session.context.sync();
        self.checked = true;
        try checkStatus(status[0]);
        self.successful = true;
        return .{ .source = self, .id = self.id };
    }
    pub fn complete(self: *ProofStatus, session: anytype, pending: Pending) !Completed {
        if (pending.status_id != self.id or !sameSlice(self.word, pending.status)) return error.SecureStatusBindingMismatch;
        const completion = try self.check(session);
        return completion.admit(session, pending);
    }
};
/// One checked proof boundary may admit multiple outputs from that same status
/// lifetime. Reinitializing the status invalidates all earlier completions.
pub const Completion = struct {
    source: *const ProofStatus,
    id: u64,
    pub fn require(self: Completion, session: anytype) !void {
        try common.requireStage(session, .proof_assembly);
        if (self.source.id != self.id or !self.source.checked or !self.source.successful) return error.SecureStatusBindingMismatch;
        _ = try exact(session, self.source.word, 1);
    }
    pub fn admit(self: Completion, session: anytype, pending: Pending) !Completed {
        try self.require(session);
        if (pending.status_id != self.id or !sameSlice(self.source.word, pending.status)) return error.SecureStatusBindingMismatch;
        _ = try exact(session, pending.columns, pending.columns.len);
        _ = try exact(session, pending.status, 1);
        if (pending.totals) |totals| _ = try exact(session, totals, totals.len);
        return .{ .columns = pending.columns, .totals = pending.totals, .invocation = pending.invocation, .completion = self };
    }
};
pub fn checkStatus(status: u32) !void {
    if (status & 1 != 0) return error.ActiveSecurePole;
    if (status & 2 != 0) return error.InvalidSecureWitness;
    if (status & 4 != 0) return error.NonCanonicalSecureValue;
    if (status != 0) return error.UnknownSecureDeviceFailure;
}
pub const Pending = struct {
    /// Unverified resident output: may be used internally by PCS, never admitted
    /// as checked claim/columns or a successfully consumed proof before complete.
    columns: Words,
    totals: ?Words = null,
    status: Words,
    status_id: u64,
    invocation: [32]u8,
};
pub const Completed = struct {
    completion: Completion,
    columns: Words,
    totals: ?Words,
    invocation: [32]u8,
    /// Claims can only be extracted at the proof-assembly boundary after status.
    pub fn readTotals(self: Completed, session: anytype, output: []@import("../abi/field.zig").SecureField) !void {
        try self.completion.require(session);
        const source = (self.totals orelse return error.SecureTotalsAbsent).cast(@import("../abi/field.zig").SecureField);
        try session.context.readProofSlice(@import("../abi/field.zig").SecureField, output, try source);
        try session.context.sync();
    }
};
pub const Metadata = struct { offsets: U64s, parameters: Words, powers: Words, denominators: Words };
pub const Binding = struct { metadata: Metadata, invocation: [32]u8 };
pub const Buffers = struct { trees: [3]?common.WordMatrix, output: Words };
pub const Plan = struct {
    a: std.mem.Allocator,
    name: [:0]u8,
    entry: registry.Entry,
    kind: ir.Kind,
    trace_log: u32,
    rows: u32,
    invocation: [32]u8,
    inputs: []ir.Input,
    parameters: []u32,
    offsets: []u64,
    powers: []u32,
    denominators: [quotient.MAX_DENOMINATORS]u32 = @splat(0),
    denominator_count: u32 = 1,
    range_z: ?Q,
    limits: Limits,
    uploaded: bool = false,
    bound_metadata: ?Metadata = null,
    /// Host metadata must stay at its stable address until ingress is joined;
    /// do not move/deinit a Plan while async uploads or launches are outstanding.
    pub fn init(a: std.mem.Allocator, catalog: *const registry.Catalog, program: *const ir.Program, trace_log: u32, coefficient_powers: []const Q, limits: Limits) !Plan {
        try program.validate();
        const trace_rows = try admittedRows(trace_log, limits);
        const fractions = ir.isFraction(program.kind);
        if ((fractions and coefficient_powers.len != 0) or (!fractions and coefficient_powers.len != program.roots.len)) return error.InvalidSecureInvocation;
        if ((program.kind == .range16_equations_v4 or program.kind == .range16_fractions_v4) and trace_log != 16) return error.InvalidSecureInvocation;
        const eval_log = trace_log + ir.layout(program.kind).expansion_bits;
        if (eval_log > 27) return error.InvalidSecureInvocation;
        const rows: u32 = if (fractions) trace_rows else @as(u32, 1) << @intCast(eval_log);
        const metadata_bytes = try std.math.add(usize, try std.math.mul(usize, program.inputs.len, 8), try std.math.mul(usize, program.parameters.len + coefficient_powers.len, 16));
        if (metadata_bytes + 32 > limits.max_metadata_bytes) return error.SecureMetadataCap;
        if (try std.math.mul(usize, try wordsFor(rows, if (fractions) 4 * @as(u32, @intCast(program.roots.len)) else 4), 4) > limits.max_resident_bytes) return error.SecureResidentCap;
        const id = try codegen.dag.identity(program);
        const entry = try catalog.entry(id);
        const name = try a.dupeZ(u8, entry.name);
        errdefer a.free(name);
        const inputs = try a.dupe(ir.Input, program.inputs);
        errdefer a.free(inputs);
        const parameters = try fieldWords(a, program.parameters);
        errdefer a.free(parameters);
        const offsets = try a.alloc(u64, inputs.len);
        errdefer a.free(offsets);
        for (inputs, offsets) |input, *offset| offset.* = @as(u64, input.column) * rows;
        const powers = try fieldWords(a, coefficient_powers);
        errdefer a.free(powers);
        var plan = Plan{ .a = a, .name = name, .entry = entry, .kind = program.kind, .trace_log = trace_log, .rows = rows, .invocation = planInvocation(program, trace_log, powers), .inputs = inputs, .parameters = parameters, .offsets = offsets, .powers = powers, .range_z = try program.rangeChallenge(), .limits = limits };
        if (!fractions) {
            const d = try quotient.derive(trace_log, eval_log);
            plan.denominators = quotient.words(d);
            plan.denominator_count = d.count;
        }
        return plan;
    }
    pub fn deinit(self: *Plan) void {
        self.a.free(self.name);
        self.a.free(self.inputs);
        self.a.free(self.parameters);
        self.a.free(self.offsets);
        self.a.free(self.powers);
        self.* = undefined;
    }
    pub fn upload(self: *Plan, session: anytype, metadata: Metadata) !Binding {
        try common.requireStage(session, .ingress);
        if (self.uploaded) return error.SecurePlanAlreadyUploaded;
        _ = try exactTyped(session, u64, metadata.offsets, self.offsets.len);
        _ = try exact(session, metadata.parameters, self.parameters.len);
        _ = try exact(session, metadata.powers, self.powers.len);
        _ = try exact(session, metadata.denominators, self.denominators.len);
        const ranges = [_]layout.DeviceRange{ try rangeOf(u64, metadata.offsets), try rangeOf(u32, metadata.parameters), try rangeOf(u32, metadata.powers), try rangeOf(u32, metadata.denominators) };
        try layout.requireDisjoint(&ranges, &.{});
        try session.context.uploadSlice(u64, metadata.offsets, self.offsets);
        try session.context.uploadSlice(u32, metadata.parameters, self.parameters);
        try session.context.uploadSlice(u32, metadata.powers, self.powers);
        try session.context.uploadSlice(u32, metadata.denominators, &self.denominators);
        self.uploaded = true;
        self.bound_metadata = metadata;
        return .{ .metadata = metadata, .invocation = self.invocation };
    }
    pub fn launch(self: *const Plan, session: anytype, catalog: *const registry.Catalog, binding: Binding, buffers: Buffers, table: ?RangeTable, status: *const ProofStatus) !Pending {
        try common.requireStage(session, .constraint_evaluation);
        try status.requirePending(session);
        if (!self.uploaded or !std.mem.eql(u8, &binding.invocation, &self.invocation)) return error.InvalidSecureInvocation;
        try requireDevice(catalog, session);
        const admitted = self.bound_metadata orelse return error.SecurePlanNotUploaded;
        if (!sameTypedSlice(u64, admitted.offsets, binding.metadata.offsets) or !sameSlice(admitted.parameters, binding.metadata.parameters) or !sameSlice(admitted.powers, binding.metadata.powers) or !sameSlice(admitted.denominators, binding.metadata.denominators)) return error.InvalidSecureInvocation;
        const shape = ir.layout(self.kind);
        const output = try exact(session, buffers.output, try wordsFor(self.rows, if (ir.isFraction(self.kind)) shape.roots * 4 else 4));
        var reads: [8]layout.DeviceRange = undefined;
        var read_count: usize = 0;
        var trees: [3]?[*]u32 = @splat(null);
        for (buffers.trees, 0..) |tree, index| {
            const cols = switch (index) {
                0 => shape.fixed,
                1 => shape.main,
                2 => shape.interaction,
                else => unreachable,
            };
            if (cols == 0) {
                if (tree != null) return error.InvalidSecureInvocation;
                continue;
            }
            const descriptor = tree orelse return error.InvalidSecureInvocation;
            if (descriptor.column_stride_words != self.rows or descriptor.storage.len != try wordsFor(self.rows, cols)) return error.InvalidSecureInvocation;
            const validated = try layout.wordMatrix(session, descriptor, self.rows);
            trees[index] = validated.pointer;
            reads[read_count] = validated.range;
            read_count += 1;
        }
        const offsets = try exactTyped(session, u64, binding.metadata.offsets, self.offsets.len);
        const params = try exact(session, binding.metadata.parameters, self.parameters.len);
        const powers = try exact(session, binding.metadata.powers, self.powers.len);
        const denoms = try exact(session, binding.metadata.denominators, self.denominators.len);
        for ([_]layout.DeviceRange{ try rangeOf(u64, binding.metadata.offsets), try rangeOf(u32, binding.metadata.parameters), try rangeOf(u32, binding.metadata.powers), try rangeOf(u32, binding.metadata.denominators) }) |r| {
            reads[read_count] = r;
            read_count += 1;
        }
        var inverses: ?[*]u32 = null;
        if (self.range_z) |z| {
            const t = table orelse return error.SecureRangeTableAbsent;
            if (!t.z.eql(z)) return error.SecureRangeChallengeMismatch;
            inverses = try exact(session, t.storage, TABLE_WORDS);
            reads[read_count] = try rangeOf(u32, t.storage);
            read_count += 1;
        } else if (table != null) return error.InvalidSecureInvocation;
        const status_ptr = try exact(session, status.word, 1);
        try layout.requireDisjoint(&.{ try rangeOf(u32, buffers.output), try rangeOf(u32, status.word) }, reads[0..read_count]);
        var args = .{ trees[0], trees[1], trees[2], offsets, params, powers, output, status_ptr, self.rows, denoms, self.denominator_count, inverses };
        var pointers = argumentPointers(&args);
        try session.launchKernel(try kernel(self.entry, self.name, .constraint_evaluation, self.rows, 1), &pointers);
        return .{ .columns = buffers.output, .status = status.word, .status_id = status.id, .invocation = self.invocation };
    }
};
pub const RangeTable = struct { storage: Words, z: Q };
pub const RangeTablePlan = struct {
    z: Q,
    z_words: [4]u32,
    uploaded: ?Words = null,
    generated: bool = false,
    pub fn init(z: Q) !RangeTablePlan {
        var words: [4]u32 = undefined;
        for (z.toM31Array(), &words) |value, *out| {
            out.* = value.toU32();
            if (out.* >= core.fields.m31.Modulus) return error.NonCanonicalSecureValue;
        }
        return .{ .z = z, .z_words = words };
    }
    /// Keep this plan at a stable address until ingress transfers are joined.
    pub fn upload(self: *RangeTablePlan, session: anytype, destination: Words) !void {
        try common.requireStage(session, .ingress);
        if (self.uploaded != null) return error.SecurePlanAlreadyUploaded;
        _ = try exact(session, destination, 4);
        try session.context.uploadSlice(u32, destination, &self.z_words);
        self.uploaded = destination;
    }
    pub fn generate(self: *RangeTablePlan, session: anytype, catalog: *const registry.Catalog, destination: Words, limits: Limits) !RangeTable {
        try common.requireStage(session, .constraint_evaluation);
        if (self.generated) return error.SecureRangeTableAlreadyGenerated;
        const z = self.uploaded orelse return error.SecurePlanNotUploaded;
        if (TABLE_WORDS * 4 > limits.max_resident_bytes) return error.SecureResidentCap;
        const z_pointer = try exact(session, z, 4);
        const output = try exact(session, destination, TABLE_WORDS);
        try layout.requireDisjoint(&.{try rangeOf(u32, destination)}, &.{try rangeOf(u32, z)});
        var args = .{ z_pointer, output };
        try launchHelper(session, catalog, .range_inverse, .constraint_evaluation, 65536, 1, &args);
        self.generated = true;
        return .{ .storage = destination, .z = self.z };
    }
};
pub const ScanBuffers = struct {
    levels: [MAX_SCAN_LEVELS]?Words = @splat(null),
    totals: Words,
};
/// Inclusive secure prefixes in logical committed-row order, then independent
/// mean centering. Scratch levels are caller-owned and deterministic; every
/// intermediate stays resident. No O(rows) host arrays or serial host scans.
pub fn scanAndCenter(session: anytype, catalog: *const registry.Catalog, pending: Pending, trace_log: u32, batches: u32, buffers: ScanBuffers, status: *const ProofStatus, limits: Limits) !Pending {
    try common.requireStage(session, .constraint_evaluation);
    try status.requirePending(session);
    if (pending.status_id != status.id or !sameSlice(pending.status, status.word) or pending.totals != null) return error.SecureStatusBindingMismatch;
    const g = try Geometry.fractions(trace_log, batches, limits);
    _ = try exact(session, pending.columns, g.output_words);
    _ = try exact(session, buffers.totals, g.totals_words);
    var writes: [MAX_SCAN_LEVELS + 2]layout.DeviceRange = undefined;
    writes[0] = try rangeOf(u32, pending.columns);
    writes[1] = try rangeOf(u32, buffers.totals);
    for (buffers.levels, 0..) |level, i| {
        if (i >= g.levels) {
            if (level != null) return error.InvalidSecureScanGeometry;
            continue;
        }
        const value = level orelse return error.InvalidSecureScanGeometry;
        _ = try exact(session, value, g.scan_words[i]);
        writes[i + 2] = try rangeOf(u32, value);
    }
    try layout.requireDisjoint(writes[0 .. g.levels + 2], &.{try rangeOf(u32, status.word)});
    var current = pending.columns;
    var rows = g.rows;
    for (0..g.levels) |i| {
        const next = buffers.levels[i].?;
        var args = .{ try exact(session, current, current.len), try exact(session, next, next.len), rows, batches, @as(u32, if (i == 0) 1 else 0) };
        try launchHelper(session, catalog, .scan_block, .constraint_evaluation, rows, batches, &args);
        current = next;
        rows = g.scan_rows[i];
    }
    // The top source has <=256 rows and its inclusive prefixes are final.
    // Propagate carries from that source down to the original row layout.
    var i = g.levels;
    while (i > 0) {
        i -= 1;
        const data = if (i == 0) pending.columns else buffers.levels[i - 1].?;
        const source = buffers.levels[i].?;
        const n = if (i == 0) g.rows else g.scan_rows[i - 1];
        var args = .{ try exact(session, data, data.len), try exact(session, source, source.len), n, batches, @as(u32, if (i == 0) 1 else 0) };
        try launchHelper(session, catalog, .scan_carry, .constraint_evaluation, n, batches, &args);
    }
    var totals_args = .{ try exact(session, pending.columns, g.output_words), try exact(session, buffers.totals, g.totals_words), g.rows, batches };
    try launchHelper(session, catalog, .totals, .constraint_evaluation, batches, 1, &totals_args);
    var mean_args = .{ try exact(session, pending.columns, g.output_words), try exact(session, buffers.totals, g.totals_words), g.rows, batches };
    try launchHelper(session, catalog, .mean, .constraint_evaluation, g.rows, batches, &mean_args);
    return .{ .columns = pending.columns, .totals = buffers.totals, .status = pending.status, .status_id = pending.status_id, .invocation = pending.invocation };
}
pub const WordClaim = struct {
    words: [25]u32,
    pub fn validate(self: WordClaim, limits: Limits) !u32 {
        const rows = try admittedRows(self.words[5], limits);
        const first = @as(u64, self.words[0]) | @as(u64, self.words[1]) << 32;
        const total = @as(u64, self.words[2]) | @as(u64, self.words[3]) << 32;
        if (self.words[4] == 0 or self.words[4] > rows or first >= total or @as(u64, self.words[4]) > total - first or self.words[6] > 1 or (self.words[6] != 0) != (first != 0) or self.words[13] > 1 or self.words[19] > 1 or (self.words[6] != 0 and self.words[7] > 1)) return error.InvalidSecureWitness;
        if (self.words[6] == 0) for (self.words[7..13]) |word| if (word != 0) return error.InvalidSecureWitness;
        return rows;
    }
};
pub const WitnessPlan = struct {
    claim: WordClaim,
    destination_claim: ?Words = null,
    pub fn init(claim: WordClaim, limits: Limits) !WitnessPlan {
        _ = try claim.validate(limits);
        return .{ .claim = claim };
    }
    pub fn upload(self: *WitnessPlan, session: anytype, destination: Words) !void {
        try common.requireStage(session, .ingress);
        if (self.destination_claim != null) return error.SecurePlanAlreadyUploaded;
        _ = try exact(session, destination, 25);
        try session.context.uploadSlice(u32, destination, &self.claim.words);
        self.destination_claim = destination;
    }
    pub fn generate(self: *const WitnessPlan, session: anytype, catalog: *const registry.Catalog, records: Words, output: Words, status: *const ProofStatus, limits: Limits) !Pending {
        try common.requireStage(session, .trace_generation);
        try status.requirePending(session);
        const rows = try self.claim.validate(limits);
        const claim = self.destination_claim orelse return error.SecurePlanNotUploaded;
        const out_words = try wordsFor(rows, 39);
        if (try std.math.mul(usize, out_words, 4) > limits.max_resident_bytes) return error.SecureResidentCap;
        var args = .{ try exact(session, records, try wordsFor(self.claim.words[4], 6)), try exact(session, claim, 25), try exact(session, output, out_words), try exact(session, status.word, 1), rows };
        try layout.requireDisjoint(&.{ try rangeOf(u32, output), try rangeOf(u32, status.word) }, &.{ try rangeOf(u32, records), try rangeOf(u32, claim) });
        try launchHelper(session, catalog, .word_witness, .trace_generation, rows, 1, &args);
        return .{ .columns = output, .status = status.word, .status_id = status.id, .invocation = witnessIdentity(self.claim.words) };
    }
};
pub fn rangeWitness(session: anytype, catalog: *const registry.Catalog, multiplicities: Words, output: Words, status: *const ProofStatus, limits: Limits) !Pending {
    try common.requireStage(session, .trace_generation);
    try status.requirePending(session);
    if (65536 * 8 > limits.max_resident_bytes) return error.SecureResidentCap;
    var args = .{ try exact(session, multiplicities, 65536), try exact(session, output, 65536 * 2), try exact(session, status.word, 1) };
    try layout.requireDisjoint(&.{ try rangeOf(u32, output), try rangeOf(u32, status.word) }, &.{try rangeOf(u32, multiplicities)});
    try launchHelper(session, catalog, .range_witness, .trace_generation, 65536, 1, &args);
    return .{ .columns = output, .status = status.word, .status_id = status.id, .invocation = codegen.helperIdentity(.range_witness) };
}
fn launchHelper(session: anytype, catalog: *const registry.Catalog, helper: codegen.Helper, stage: Stage, rows: u32, batches: u32, args: anytype) !void {
    try requireDevice(catalog, session);
    const entry = try catalog.entry(codegen.helperIdentity(helper));
    var pointers = argumentPointers(args);
    try session.launchKernel(try kernel(entry, codegen.name(helper), stage, rows, batches), &pointers);
}
fn kernel(entry: registry.Entry, name: [:0]const u8, stage: Stage, rows: u32, batches: u32) !Kernel {
    if (rows == 0 or rows > (@as(u32, 1) << 27) or batches == 0 or batches > 23) return error.InvalidSecureInvocation;
    return .{ .stage = stage, .abi_schema = entry.abi_schema, .cache_key = entry.cache_key, .name = name, .grid = .{ (rows + 255) / 256, batches, 1 }, .block = .{ 256, 1, 1 }, .argument_count = entry.argument_count, .expected_cubin_sha256 = entry.cubin_sha256, .expected_cubin_bytes = entry.cubin_bytes };
}
fn argumentPointers(args: anytype) [@typeInfo(@TypeOf(args.*)).@"struct".fields.len]?*anyopaque {
    const fields = @typeInfo(@TypeOf(args.*)).@"struct".fields;
    var result: [fields.len]?*anyopaque = undefined;
    inline for (fields, 0..) |f, i| result[i] = @ptrCast(&@field(args.*, f.name));
    return result;
}
fn exact(session: anytype, slice: Words, count: usize) ![*]u32 {
    return exactTyped(session, u32, slice, count);
}
fn exactTyped(session: anytype, comptime F: type, slice: column.DeviceSlice(F), count: usize) ![*]F {
    if (count == 0 or slice.len != count) return error.InvalidSecureInvocation;
    return session.context.deviceSlicePointer(F, slice, count);
}
fn rangeOf(comptime F: type, slice: column.DeviceSlice(F)) !layout.DeviceRange {
    return layout.elementRange(slice.address, slice.len, @sizeOf(F));
}
fn sameSlice(a: Words, b: Words) bool {
    return sameTypedSlice(u32, a, b);
}
fn sameTypedSlice(comptime F: type, a: column.DeviceSlice(F), b: column.DeviceSlice(F)) bool {
    return a.address == b.address and a.len == b.len and a.owner == b.owner and a.generation == b.generation;
}
fn requireDevice(catalog: *const registry.Catalog, session: anytype) !void {
    if (catalog.sm_major != session.device.sm_major or catalog.sm_minor != session.device.sm_minor) return error.InvalidSecureAotCatalog;
}
fn wordsFor(rows: u32, cols: u32) !usize {
    return std.math.mul(usize, rows, cols);
}
fn admittedRows(log: u32, limits: Limits) !u32 {
    if (log == 0 or log > limits.max_trace_log or log > 25) return error.InvalidSecureInvocation;
    return @as(u32, 1) << @intCast(log);
}
fn fieldWords(a: std.mem.Allocator, fields: []const Q) ![]u32 {
    const words = try a.alloc(u32, @max(1, try std.math.mul(usize, fields.len, 4)));
    errdefer a.free(words);
    @memset(words, 0);
    for (fields, 0..) |field, i| for (field.toM31Array(), 0..) |value, limb| {
        words[4 * i + limb] = value.toU32();
        if (words[4 * i + limb] >= core.fields.m31.Modulus) return error.NonCanonicalSecureValue;
    };
    return words;
}
fn witnessIdentity(words: [25]u32) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(&codegen.helperIdentity(.word_witness));
    for (words) |word| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, word, .little);
        h.update(&bytes);
    }
    return h.finalResult();
}

fn planInvocation(program: *const ir.Program, log: u32, powers: []const u32) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo/cuda/secure-resident-invocation/v1\x00");
    h.update(&program.invocationDigest(log));
    for (powers) |power| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, power, .little);
        h.update(&bytes);
    }
    return h.finalResult();
}
