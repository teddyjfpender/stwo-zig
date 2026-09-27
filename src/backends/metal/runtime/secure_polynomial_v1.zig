//! Authenticated AOT-only resident execution of the secure typed AIR export.
//! One owner serializes catalog installation/commands; no production JIT.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
pub const ir = @import("stwo_prover_engine").air.secure_polynomial_program_v1;
const codegen = @import("secure_polynomial_codegen_v1.zig");
const runtime = @import("../runtime.zig");
const quotient = @import("polynomial_quotient_geometry.zig");
const external = @import("stwo_prover_engine").shared_external_memory;
const resident_budget = @import("resident_budget_v1.zig");
extern fn stwo_zig_secure_polynomial_register_aot(*anyopaque, [*]const u8, usize, [*]const [*]const u8, [*]const usize, u32) u32;
extern fn stwo_zig_secure_interaction_prepare(*anyopaque, [*]const u8, usize, [*]const u32, u32, u32, u32, u32, u32) ?*anyopaque;
extern fn stwo_zig_secure_interaction_destroy(*anyopaque) void;
extern fn stwo_zig_secure_interaction_generate(*anyopaque, ?*anyopaque, ?*anyopaque, *anyopaque, [*]const u32, [*]const u64, u32, [*]const u32, u32, [*]const u32, u32, u32, u32, *?*anyopaque, *?*anyopaque, *usize, *f64) u32;
extern fn stwo_zig_secure_range_inverse_table(*anyopaque, [*]const u32, usize, *?*anyopaque, *?*anyopaque, *usize, *f64) u32;
extern fn stwo_zig_secure_witness_generate(*anyopaque, u32, *anyopaque, ?[*]const u32, u32, u32, usize, *?*anyopaque, *?*anyopaque, *usize, *f64) u32;
extern fn stwo_zig_secure_equations_evaluate(*anyopaque, ?*anyopaque, ?*anyopaque, ?*anyopaque, [*]const u64, u32, [*]const u32, u32, [*]const u32, u32, u32, [*]const u32, u32, *anyopaque, usize, *f64) u32;
pub const MAX_METALLIB_BYTES = 128 * 1024 * 1024;

/// The expected binary SHA comes from an independent trusted build catalog.
/// Programs come from independently admitted typed Specs, never a proof wire.
/// Binary identity alone does not authorize any proof acceptance.
pub fn installAot(a: std.mem.Allocator, metal: *runtime.Runtime, image: []const u8, expected_sha256: [32]u8, programs: []const *const ir.Program) !void {
    if (image.len == 0 or image.len > MAX_METALLIB_BYTES or programs.len == 0 or programs.len > codegen.MAX_ENTRIES or std.mem.allEqual(u8, &expected_sha256, 0)) return error.InvalidSecureAotCatalog;
    var sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(image, &sha, .{});
    if (!std.mem.eql(u8, &sha, &expected_sha256)) return error.SecureAotImageHashMismatch;
    var names: [codegen.MAX_ENTRIES + 8][]const u8 = undefined;
    var owned_count: usize = 0;
    defer for (names[0..owned_count]) |name| a.free(name);
    var fractions = false;
    for (programs) |program| {
        try program.validate();
        const name = try codegen.kernelName(a, program);
        var duplicate = false;
        for (names[0..owned_count]) |prior| if (std.mem.eql(u8, name, prior)) {
            duplicate = true;
            break;
        };
        if (duplicate) a.free(name) else {
            names[owned_count] = name;
            owned_count += 1;
        }
        fractions = fractions or ir.isFraction(program.kind);
    }
    var count = owned_count;
    if (fractions) for (codegen.scan_symbols) |name| {
        names[count] = name;
        count += 1;
    };
    for (codegen.witness_symbols) |name| {
        names[count] = name;
        count += 1;
    }
    var pointers: [codegen.MAX_ENTRIES + 8][*]const u8 = undefined;
    var lengths: [codegen.MAX_ENTRIES + 8]usize = undefined;
    for (names[0..count], pointers[0..count], lengths[0..count]) |name, *pointer, *length| {
        pointer.* = name.ptr;
        length.* = name.len;
    }
    if (stwo_zig_secure_polynomial_register_aot(metal.handle, image.ptr, image.len, &pointers, &lengths, @intCast(count)) != 0) return error.SecureAotCatalogUnavailable;
}
pub const Tree = struct { buffer: *const runtime.ResidentBuffer, column_offsets: []const u64 };
pub const Limits = struct {
    max_resident_bytes: usize,
    /// Canonical resident producer supplies its actual SharedHostBudget
    /// allocator. Null keeps legacy explicitly unbudgeted raw contracts.
    budget_allocator: ?std.mem.Allocator = null,
};
fn reserveExternal(limits: Limits, bytes: usize) !external.Reservation {
    if (limits.budget_allocator) |a| return external.reserve(a, bytes, .require_shared_budget);
    return .unbudgeted(bytes);
}
pub const RangeInverseTable = struct {
    resident: runtime.ResidentBuffer,
    z: Q,
    gpu_milliseconds: f64,
    pub const BYTE_LENGTH = 65536 * 20;
    pub fn init(metal: *runtime.Runtime, z: Q, limits: Limits) !RangeInverseTable {
        if (limits.max_resident_bytes < BYTE_LENGTH + 16) return error.SecureRangeInverseCap;
        var reservation = try reserveExternal(limits, BYTE_LENGTH + 16);
        defer reservation.deinit();
        var z_words: [4]u32 = undefined;
        for (z.toM31Array(), &z_words) |coordinate, *out| {
            out.* = coordinate.toU32();
            if (out.* >= core.fields.m31.Modulus) return error.InvalidSecureRangeChallenge;
        }
        var handle: ?*anyopaque = null;
        var contents: ?*anyopaque = null;
        var bytes: usize = 0;
        var gpu_ms: f64 = 0;
        if (stwo_zig_secure_range_inverse_table(metal.handle, &z_words, limits.max_resident_bytes, &handle, &contents, &bytes, &gpu_ms) != 0) return error.SecureRangeInverseExecutionFailed;
        var resident = runtime.ResidentBuffer{ .handle = handle.?, .contents = contents.?, .byte_length = bytes };
        errdefer resident.deinit();
        if (bytes != BYTE_LENGTH) return error.InvalidSecureRangeInverseOutput;
        try reservation.resize(bytes);
        resident.external_reservation = reservation.take();
        return .{ .resident = resident, .z = z, .gpu_milliseconds = gpu_ms };
    }
    pub fn deinit(self: *RangeInverseTable) void {
        self.resident.deinit();
        self.* = undefined;
    }
    pub fn require(self: *const RangeInverseTable, z: Q) !void {
        if (!self.z.eql(z) or self.resident.byte_length != BYTE_LENGTH) return error.SecureRangeChallengeMismatch;
    }
};
pub const WitnessResult = struct {
    resident: runtime.ResidentBuffer,
    rows: usize,
    columns: usize,
    gpu_milliseconds: f64,
    pub fn deinit(self: *WitnessResult) void {
        self.resident.deinit();
        self.* = undefined;
    }
};
/// Raw contract used only through an independently validated typed claim
/// adapter. Records stay resident; output is direct column-major committed-row
/// fixed/main storage, with device-checked sorting/endpoints/carry generation.
pub fn generateWitness(metal: *runtime.Runtime, source: *const runtime.ResidentBuffer, word_claim: ?*const [25]u32, trace_log: u32, limits: Limits) !WitnessResult {
    if (trace_log < 1 or trace_log > 24 or limits.max_resident_bytes == 0 or (word_claim == null and trace_log != 16)) return error.InvalidSecureWitnessGeometry;
    const rows = @as(usize, 1) << @intCast(trace_log);
    const columns: usize = if (word_claim != null) 39 else 2;
    const output_bytes = try std.math.mul(usize, try std.math.mul(usize, rows, columns), 4);
    if (try std.math.add(usize, output_bytes, if (word_claim != null) @as(usize, 104) else 8) > limits.max_resident_bytes) return error.SecureWitnessResidentCap;
    var reservation = try reserveExternal(limits, try std.math.add(usize, output_bytes, if (word_claim != null) @as(usize, 104) else 8));
    defer reservation.deinit();
    var handle: ?*anyopaque = null;
    var contents: ?*anyopaque = null;
    var bytes: usize = 0;
    var gpu_ms: f64 = 0;
    const status = stwo_zig_secure_witness_generate(metal.handle, @intFromBool(word_claim == null), source.handle, if (word_claim) |claim| claim else null, if (word_claim == null) 0 else 25, @intCast(rows), limits.max_resident_bytes, &handle, &contents, &bytes, &gpu_ms);
    if (status != 0) return if (status == 2) error.InvalidSecureWitnessSource else if (status == 4) error.NoncanonicalSecureWitnessSource else error.SecureWitnessExecutionFailed;
    var resident = runtime.ResidentBuffer{ .handle = handle.?, .contents = contents.?, .byte_length = bytes };
    errdefer resident.deinit();
    if (bytes != output_bytes) return error.InvalidSecureWitnessOutput;
    try reservation.resize(bytes);
    resident.external_reservation = reservation.take();
    return .{ .resident = resident, .rows = rows, .columns = columns, .gpu_milliseconds = gpu_ms };
}
/// Canonical lane metadata uses the same25 scalar words as the legacy
/// emitter, but word5 is actual physical row_log and capacity is2*rows.
pub fn generateLaneWitness(metal: *runtime.Runtime, source: *const runtime.ResidentBuffer, claim: *const [25]u32, trace_log: u32, limits: Limits) !WitnessResult {
    if (trace_log < 1 or trace_log > 24 or claim[5] != trace_log or claim[4] == 0 or claim[4] > (@as(u32, 2) << @intCast(trace_log)) or source.byte_length != try std.math.mul(usize, claim[4], 24)) return error.InvalidSecureWitnessGeometry;
    const rows = @as(usize, 1) << @intCast(trace_log);
    const output_bytes = try std.math.mul(usize, try std.math.mul(usize, rows, 78), 4);
    if (try std.math.add(usize, output_bytes, 104) > limits.max_resident_bytes) return error.SecureWitnessResidentCap;
    var reservation = try reserveExternal(limits, try std.math.add(usize, output_bytes, 104));
    defer reservation.deinit();
    var handle: ?*anyopaque = null;
    var contents: ?*anyopaque = null;
    var bytes_out: usize = 0;
    var gpu_ms: f64 = 0;
    const status = stwo_zig_secure_witness_generate(metal.handle, 2, source.handle, claim, 25, @intCast(rows), limits.max_resident_bytes, &handle, &contents, &bytes_out, &gpu_ms);
    if (status != 0) return if (status == 2) error.InvalidSecureWitnessSource else if (status == 4) error.NoncanonicalSecureWitnessSource else error.SecureWitnessExecutionFailed;
    var resident = runtime.ResidentBuffer{ .handle = handle.?, .contents = contents.?, .byte_length = bytes_out };
    errdefer resident.deinit();
    if (bytes_out != output_bytes) return error.InvalidSecureWitnessOutput;
    try reservation.resize(bytes_out);
    resident.external_reservation = reservation.take();
    return .{ .resident = resident, .rows = rows, .columns = 78, .gpu_milliseconds = gpu_ms };
}
const Snapshot = struct {
    a: std.mem.Allocator,
    identity: [32]u8,
    kind: ir.Kind,
    inputs: []ir.Input,
    name: []u8,
    parameters: usize,
    roots: usize,
    fn init(a: std.mem.Allocator, program: *const ir.Program) !Snapshot {
        try program.validate();
        const inputs = try a.dupe(ir.Input, program.inputs);
        errdefer a.free(inputs);
        return .{ .a = a, .identity = program.identity, .kind = program.kind, .inputs = inputs, .name = try codegen.kernelName(a, program), .parameters = program.parameters.len, .roots = program.roots.len };
    }
    fn deinit(self: *Snapshot) void {
        self.a.free(self.inputs);
        self.a.free(self.name);
        self.* = undefined;
    }
    fn require(self: *const Snapshot, program: *const ir.Program, log: u32) !usize {
        try program.validate();
        if (!std.mem.eql(u8, &self.identity, &program.identity) or self.kind != program.kind or self.parameters != program.parameters.len or log < 1 or log > 24 or ((self.kind == .range16_equations_v4 or self.kind == .range16_fractions_v4) and log != 16)) return error.InvalidSecureInvocation;
        return @as(usize, 1) << @intCast(log);
    }
    fn resolve(self: *const Snapshot, trees: []const ?Tree, rows: usize, offsets: []u64, tags: []u32) !void {
        const l = ir.layout(self.kind);
        for (self.inputs, offsets, tags) |input, *offset, *tag| {
            if (input.tree >= trees.len) return error.InvalidSecureResidentTree;
            const tree = trees[input.tree] orelse return error.InvalidSecureResidentTree;
            const columns: usize = switch (input.tree) {
                0 => l.fixed,
                1 => l.main,
                2 => l.interaction,
                else => unreachable,
            };
            if (tree.column_offsets.len != columns or tree.buffer.byte_length % 4 != 0 or @intFromPtr(tree.buffer.contents) % 4 != 0) return error.InvalidSecureResidentTree;
            offset.* = tree.column_offsets[input.column];
            tag.* = input.tree;
            if (offset.* > tree.buffer.byte_length / 4 or rows > tree.buffer.byte_length / 4 - offset.*) return error.InvalidSecureResidentTree;
        }
    }
};
fn words(a: std.mem.Allocator, values: []const Q) ![]u32 {
    const out = try a.alloc(u32, try std.math.mul(usize, values.len, 4));
    for (values, 0..) |value, i| {
        for (value.toM31Array(), 0..) |coordinate, k| out[4 * i + k] = coordinate.toU32();
    }
    return out;
}
pub const EquationPlan = struct {
    snapshot: Snapshot,
    handle: ?runtime.FrameworkPolynomialPlan = null,
    pub fn init(a: std.mem.Allocator, program: *const ir.Program) !EquationPlan {
        if (ir.isFraction(program.kind)) return error.InvalidSecureEquationKind;
        return .{ .snapshot = try .init(a, program) };
    }
    pub fn deinit(self: *EquationPlan) void {
        if (self.handle) |*handle| handle.deinit();
        self.snapshot.deinit();
        self.* = undefined;
    }
    pub fn prepare(self: *EquationPlan, metal: *runtime.Runtime) !void {
        if (self.handle != null) return error.SecurePlanAlreadyPrepared;
        var tags: [ir.MAX_INPUTS]u32 = undefined;
        for (self.snapshot.inputs, tags[0..self.snapshot.inputs.len]) |input, *tag| tag.* = input.tree;
        self.handle = try metal.prepareFrameworkPolynomialAot(self.snapshot.name, tags[0..self.snapshot.inputs.len], @intCast(self.snapshot.parameters * 4), 4, @intCast(self.snapshot.roots * 4));
    }
    /// Expanded tree arenas and additive output are proof-owner resident
    /// buffers; no LDE/trace rows are copied or silently allocated here.
    pub fn evaluate(self: *const EquationPlan, program: *const ir.Program, trace_log: u32, trees: [3]?Tree, coefficient_powers: []const Q, output: *const runtime.ResidentBuffer, limits: Limits) !f64 {
        _ = try self.snapshot.require(program, trace_log);
        const eval_log = trace_log + ir.layout(program.kind).expansion_bits;
        const eval_rows = @as(usize, 1) << @intCast(eval_log);
        if (eval_log > 27 or coefficient_powers.len != self.snapshot.roots or output.byte_length != try std.math.mul(usize, eval_rows, 16)) return error.InvalidSecureInvocation;
        const metadata_bytes = try std.math.add(usize, try std.math.add(usize, try std.math.mul(usize, self.snapshot.inputs.len, 8), @max(@as(usize, 4), try std.math.mul(usize, self.snapshot.parameters, 16))), try std.math.add(usize, try std.math.mul(usize, self.snapshot.roots, 16), 16));
        if (metadata_bytes > limits.max_resident_bytes) return error.SecureEquationMetadataCap;
        const handle = self.handle orelse return error.SecurePlanNotPrepared;
        var offsets: [ir.MAX_INPUTS]u64 = undefined;
        var tags: [ir.MAX_INPUTS]u32 = undefined;
        try self.snapshot.resolve(&trees, eval_rows, offsets[0..self.snapshot.inputs.len], tags[0..self.snapshot.inputs.len]);
        const profile = try words(self.snapshot.a, program.parameters);
        defer self.snapshot.a.free(profile);
        const powers = try words(self.snapshot.a, coefficient_powers);
        defer self.snapshot.a.free(powers);
        const denominators = try quotient.derive(trace_log, eval_log);
        const inverse_words = quotient.words(denominators);
        var reservation = try reserveExternal(limits, metadata_bytes);
        defer reservation.deinit();
        var gpu_ms: f64 = 0;
        const status = stwo_zig_secure_equations_evaluate(handle.handle, if (trees[0]) |tree| tree.buffer.handle else null, if (trees[1]) |tree| tree.buffer.handle else null, if (trees[2]) |tree| tree.buffer.handle else null, &offsets, @intCast(self.snapshot.inputs.len), profile.ptr, @intCast(profile.len), powers.ptr, @intCast(powers.len), @intCast(eval_rows), &inverse_words, denominators.count, output.handle, limits.max_resident_bytes, &gpu_ms);
        if (status != 0) return error.SecureEquationExecutionFailed;
        return gpu_ms;
    }
};
pub const InteractionResult = @import("framework_interaction.zig").Result;
pub const FractionPlan = struct {
    snapshot: Snapshot,
    limits: Limits,
    handle: ?*anyopaque = null,
    pub fn init(a: std.mem.Allocator, program: *const ir.Program, limits: Limits) !FractionPlan {
        if (!ir.isFraction(program.kind) or limits.max_resident_bytes == 0) return error.InvalidSecureFractionKind;
        _ = (try program.rangeChallenge()) orelse return error.InvalidSecureRangeChallenge;
        return .{ .snapshot = try .init(a, program), .limits = limits };
    }
    pub fn deinit(self: *FractionPlan) void {
        if (self.handle) |handle| stwo_zig_secure_interaction_destroy(handle);
        self.snapshot.deinit();
        self.* = undefined;
    }
    pub fn prepare(self: *FractionPlan, metal: *runtime.Runtime) !void {
        if (self.handle != null) return error.SecurePlanAlreadyPrepared;
        var tags: [ir.MAX_INPUTS]u32 = undefined;
        for (self.snapshot.inputs, tags[0..self.snapshot.inputs.len]) |input, *tag| tag.* = input.tree;
        self.handle = stwo_zig_secure_interaction_prepare(metal.handle, self.snapshot.name.ptr, self.snapshot.name.len, &tags, @intCast(self.snapshot.inputs.len), @intCast(self.snapshot.parameters * 4), 4, @intCast(self.snapshot.roots), 0) orelse return error.SecureAotCatalogUnavailable;
    }
    pub fn generate(self: *const FractionPlan, program: *const ir.Program, trace_log: u32, trees: [2]?Tree, range_table: *const RangeInverseTable) !InteractionResult {
        const rows = try self.snapshot.require(program, trace_log);
        try range_table.require((try program.rangeChallenge()) orelse return error.InvalidSecureRangeChallenge);
        const batches = self.snapshot.roots;
        const extent = try resident_budget.interaction(rows, batches, self.snapshot.inputs.len, self.snapshot.parameters);
        const output_bytes = extent.retained_bytes;
        const peak = extent.peak_bytes;
        if (peak > self.limits.max_resident_bytes) return error.SecureInteractionResidentCap;
        const handle = self.handle orelse return error.SecurePlanNotPrepared;
        var offsets: [ir.MAX_INPUTS]u64 = undefined;
        var tags: [ir.MAX_INPUTS]u32 = undefined;
        try self.snapshot.resolve(&trees, rows, offsets[0..self.snapshot.inputs.len], tags[0..self.snapshot.inputs.len]);
        const profile = try words(self.snapshot.a, program.parameters);
        defer self.snapshot.a.free(profile);
        var reservation = try reserveExternal(self.limits, peak);
        defer reservation.deinit();
        var result_handle: ?*anyopaque = null;
        var contents: ?*anyopaque = null;
        var byte_len: usize = 0;
        var gpu_ms: f64 = 0;
        const reserved = [_]u32{0} ** 4;
        const status = stwo_zig_secure_interaction_generate(handle, if (trees[0]) |tree| tree.buffer.handle else null, if (trees[1]) |tree| tree.buffer.handle else null, range_table.resident.handle, &tags, &offsets, @intCast(self.snapshot.inputs.len), profile.ptr, @intCast(profile.len), &reserved, 4, @intCast(rows), @intCast(batches), &result_handle, &contents, &byte_len, &gpu_ms);
        if (status != 0) return if (status == 1) error.SecureInteractionZeroDenominator else error.SecureInteractionExecutionFailed;
        var resident = runtime.ResidentBuffer{ .handle = result_handle.?, .contents = contents.?, .byte_length = byte_len };
        errdefer resident.deinit();
        if (byte_len != output_bytes) return error.InvalidSecureInteractionOutput;
        try reservation.resize(byte_len);
        resident.external_reservation = reservation.take();
        return .{ .resident = resident, .rows = rows, .batches = batches, .claim_count = batches, .gpu_milliseconds = gpu_ms };
    }
};
