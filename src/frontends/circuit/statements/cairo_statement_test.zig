//! Structural tests of the `CairoStatement` port through a recording builder
//! facade. They pin what the port controls without the builder: guess
//! order and counts, the `set_outputs` wires, the aux-data parse, the
//! `claims_to_mix` groups, the `verify_builtins` component choice and the
//! public parameters. The last tests run the same port over the builder
//! (`cairo_statement_builder.BuilderFacade`): `claims_to_mix` on the R6
//! synthetic claim must mix to upstream's `FlatClaim::mix_into` digest, and
//! the value and topology builds must emit the same gates. Gate-level parity
//! with upstream's leaf circuit (R6 circuit hash) needs the whole leaf build.

const std = @import("std");
const core = @import("stwo_core");
const statement = @import("cairo_statement.zig");
const BuilderFacade = @import("cairo_statement_builder.zig").BuilderFacade;
const builder = @import("../builder/mod.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const layout = core.cairo_air_layout;

const checkpoint_path = "vectors/circuit/r6/cairo_statement.json";
const topology_path = "vectors/circuit/r6/topology.json";

/// Records every facade call; vars are numbered in call order after the
/// reserved zero and one, and constants are interned in first-use order.
const Recorder = struct {
    pub const Var = u32;
    pub const Simd = struct { vars: []const u32, len: usize };
    pub const Op = enum {
        constant,
        guess_m31,
        guess_u32,
        set_outputs,
        add,
        sub,
        mul,
        eq,
        pack,
        unpack,
        sub_simd,
        mul_simd,
        combine_bits,
        extract_bits,
        m31_to_u32,
        blake2s,
        logup,
    };
    pub const Context = struct {
        arena: std.heap.ArenaAllocator,
        next: u32 = 2,
        ops: std.ArrayList(Op) = .empty,
        constants: std.AutoArrayHashMapUnmanaged([4]u32, u32) = .empty,
        guessed_m31: std.ArrayList(M31) = .empty,
        outputs: []const u32 = &.{},
        eq_with_zero: usize = 0,
        /// The words of every `constHash`, in call order.
        const_hashes: std.ArrayList([8]u32) = .empty,

        fn init() Context {
            return .{ .arena = std.heap.ArenaAllocator.init(std.testing.allocator) };
        }

        fn deinit(self: *Context) void {
            self.arena.deinit();
        }

        fn allocator(self: *Context) std.mem.Allocator {
            return self.arena.allocator();
        }

        fn fresh(self: *Context, op: Op) !u32 {
            try self.ops.append(self.allocator(), op);
            defer self.next += 1;
            return self.next;
        }

        fn count(self: *const Context, op: Op) usize {
            var n: usize = 0;
            for (self.ops.items) |item| n += @intFromBool(item == op);
            return n;
        }
    };

    pub fn zero(_: *Context) u32 {
        return 0;
    }
    pub fn one(_: *Context) u32 {
        return 1;
    }
    pub fn constant(ctx: *Context, value: QM31) !u32 {
        const key = [4]u32{ value.toM31Array()[0].v, value.toM31Array()[1].v, value.toM31Array()[2].v, value.toM31Array()[3].v };
        if (std.mem.eql(u32, &key, &.{ 0, 0, 0, 0 })) return 0;
        if (std.mem.eql(u32, &key, &.{ 1, 0, 0, 0 })) return 1;
        const entry = try ctx.constants.getOrPut(ctx.allocator(), key);
        if (!entry.found_existing) entry.value_ptr.* = try ctx.fresh(.constant);
        return entry.value_ptr.*;
    }
    pub fn constU32(ctx: *Context, value: u32) !u32 {
        return constant(ctx, QM31.fromU32Unchecked(value & 0xffff, value >> 16, 0, 0));
    }
    pub fn constHash(ctx: *Context, words: [8]u32) ![8]u32 {
        try ctx.const_hashes.append(ctx.allocator(), words);
        var vars: [8]u32 = undefined;
        for (&vars, words) |*v, word| v.* = try constU32(ctx, word);
        return vars;
    }
    pub fn guessM31(ctx: *Context, value: M31) !u32 {
        try ctx.guessed_m31.append(ctx.allocator(), value);
        return ctx.fresh(.guess_m31);
    }
    pub fn guessHash(ctx: *Context, _: ?[8]u32) ![8]u32 {
        var vars: [8]u32 = undefined;
        for (&vars) |*v| v.* = try ctx.fresh(.guess_u32);
        return vars;
    }
    pub fn setOutputs(ctx: *Context, vars: []const u32) !void {
        try ctx.ops.append(ctx.allocator(), .set_outputs);
        ctx.outputs = try ctx.allocator().dupe(u32, vars);
    }
    pub fn add(ctx: *Context, _: u32, _: u32) !u32 {
        return ctx.fresh(.add);
    }
    pub fn sub(ctx: *Context, _: u32, _: u32) !u32 {
        return ctx.fresh(.sub);
    }
    pub fn mul(ctx: *Context, _: u32, _: u32) !u32 {
        return ctx.fresh(.mul);
    }
    pub fn eq(ctx: *Context, _: u32, b: u32) !void {
        if (b == 0) ctx.eq_with_zero += 1;
        try ctx.ops.append(ctx.allocator(), .eq);
    }
    pub fn simdFromPacked(ctx: *Context, vars: []const u32, len: usize) !Simd {
        return .{ .vars = try ctx.allocator().dupe(u32, vars), .len = len };
    }
    pub fn simdPack(ctx: *Context, vars: []const u32) !Simd {
        const packed_vars = try ctx.allocator().alloc(u32, (vars.len + 3) / 4);
        for (packed_vars) |*v| v.* = try ctx.fresh(.pack);
        return .{ .vars = packed_vars, .len = vars.len };
    }
    pub fn simdUnpack(ctx: *Context, simd: Simd) ![]u32 {
        const vars = try ctx.allocator().alloc(u32, simd.len);
        for (vars) |*v| v.* = try ctx.fresh(.unpack);
        return vars;
    }
    pub fn simdUnpackIdx(ctx: *Context, _: Simd, _: usize) !u32 {
        return ctx.fresh(.unpack);
    }
    pub fn simdSub(ctx: *Context, a: Simd, _: Simd) !Simd {
        return .{ .vars = try ctx.allocator().dupe(u32, &.{try ctx.fresh(.sub_simd)}), .len = a.len };
    }
    pub fn simdMul(ctx: *Context, a: Simd, _: Simd) !Simd {
        return .{ .vars = try ctx.allocator().dupe(u32, &.{try ctx.fresh(.mul_simd)}), .len = a.len };
    }
    pub fn combineBits(ctx: *Context, bits: []const Simd) !Simd {
        return .{ .vars = try ctx.allocator().dupe(u32, &.{try ctx.fresh(.combine_bits)}), .len = bits[0].len };
    }
    pub fn extractBits(ctx: *Context, simd: Simd, n_bits: u32) ![]Simd {
        const bits = try ctx.allocator().alloc(Simd, n_bits);
        for (bits) |*bit| bit.* = .{ .vars = try ctx.allocator().dupe(u32, &.{try ctx.fresh(.extract_bits)}), .len = simd.len };
        return bits;
    }
    pub fn m31ToU32(ctx: *Context, _: u32) !u32 {
        return ctx.fresh(.m31_to_u32);
    }
    pub fn blake2sU32s(ctx: *Context, _: []const u32, _: usize) ![8]u32 {
        var vars: [8]u32 = undefined;
        for (&vars) |*v| v.* = try ctx.fresh(.blake2s);
        return vars;
    }
    pub fn logupUseTerm(ctx: *Context, _: []const u32, _: [2]u32) !u32 {
        return ctx.fresh(.logup);
    }
};

const Statement = statement.CairoStatement(Recorder);

const Fixture = struct {
    parsed: std.json.Parsed(std.json.Value),
    slot_names: [][]const u8,
    enabled_bits: []bool,
    constants: statement.Constants,
    relation_uses_num_rows_shift: u32,
    root: [8]u32,

    fn load(allocator: std.mem.Allocator) !Fixture {
        const bytes = try std.fs.cwd().readFileAlloc(allocator, checkpoint_path, 4 * 1024 * 1024);
        defer allocator.free(bytes);
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
        errdefer parsed.deinit();
        const body = parsed.value.object.get("body").?.object;
        const arena = parsed.arena.allocator();
        const names = body.get("all_components").?.array.items;
        const slot_names = try arena.alloc([]const u8, names.len);
        for (names, slot_names) |name, *slot| slot.* = name.string;
        var bits: []bool = &.{};
        for (body.get("variants").?.array.items) |variant| {
            if (!std.mem.eql(u8, variant.object.get("variant").?.string, "canonical_small")) continue;
            const items = variant.object.get("enabled_bits").?.array.items;
            bits = try arena.alloc(bool, items.len);
            for (items, bits) |item, *bit| bit.* = item.bool;
        }
        const c = body.get("constants").?.object;
        const get = struct {
            fn u(object: std.json.ObjectMap, key: []const u8) u32 {
                return @intCast(object.get(key).?.integer);
            }
        }.u;
        // The leaf's Cairo root: canonical_small at log blowup 1.
        const topology_bytes = try std.fs.cwd().readFileAlloc(allocator, topology_path, 4 * 1024 * 1024);
        defer allocator.free(topology_bytes);
        const topology = try std.json.parseFromSlice(std.json.Value, allocator, topology_bytes, .{});
        defer topology.deinit();
        var root: ?[8]u32 = null;
        for (topology.value.object.get("body").?.object.get("cairo_preprocessed_roots").?.array.items) |entry| {
            if (entry.object.get("log_blowup_factor").?.integer != 1) continue;
            var words: [8]u32 = undefined;
            for (&words, entry.object.get("preprocessed_root").?.array.items) |*word, value| word.* = @intCast(value.integer);
            root = words;
        }
        return .{
            .parsed = parsed,
            .slot_names = slot_names,
            .enabled_bits = bits,
            .constants = .{
                .opcodes_relation_id = get(c, "opcodes_relation_id"),
                .memory_address_to_id_relation_id = get(c, "memory_address_to_id_relation_id"),
                .memory_id_to_big_relation_id = get(c, "memory_id_to_big_relation_id"),
                .memory = .{
                    .memory_address_to_id_split = get(c, "memory_address_to_id_split"),
                    .max_sequence_log_size = get(c, "max_sequence_log_size"),
                    .large_memory_value_id_base = get(c, "large_memory_value_id_base"),
                },
            },
            .relation_uses_num_rows_shift = get(c, "relation_uses_num_rows_shift"),
            .root = root orelse return error.MissingCairoRoot,
        };
    }

    fn deinit(self: *Fixture) void {
        self.parsed.deinit();
    }

    fn fixedLen(self: *const Fixture) usize {
        return @intCast(self.parsed.value.object.get("body").?.object.get("constants").?.object.get("aux_data_fixed_len").?.integer);
    }
};

fn syntheticProgram(allocator: std.mem.Allocator, len: usize) ![]layout.ProgramFelt {
    const program = try allocator.alloc(layout.ProgramFelt, len);
    for (program, 0..) |*felt, i| {
        for (felt, 0..) |*limb, j| limb.* = M31.fromCanonical(@intCast((i * 31 + j * 7) % 512));
    }
    return program;
}

test "cairo statement: constants and layout agree with the R6 checkpoint" {
    var fixture = try Fixture.load(std.testing.allocator);
    defer fixture.deinit();
    try std.testing.expectEqual(fixture.fixedLen(), layout.aux_data_fixed_len);
    try fixture.constants.validate();
    const verify = @import("../stark_verifier/verify.zig");
    try std.testing.expectEqual(fixture.relation_uses_num_rows_shift, verify.RELATION_USES_NUM_ROWS_SHIFT);
    try std.testing.expectEqual(@as(usize, 83), fixture.slot_names.len);
    var bits: [83]bool = undefined;
    try std.testing.expectEqual(@as(usize, 79), try layout.leafEnabledBits(.canonical_small, fixture.slot_names, &bits));
    try std.testing.expectEqualSlices(bool, fixture.enabled_bits, &bits);
}

test "cairo statement: new guesses the output digest, then every aux word, in order" {
    var fixture = try Fixture.load(std.testing.allocator);
    defer fixture.deinit();
    var ctx = Recorder.Context.init();
    defer ctx.deinit();
    const allocator = ctx.allocator();
    const program = try syntheticProgram(allocator, 5);
    const aux_len = layout.aux_data_fixed_len + program.len + 79;
    const aux = try allocator.alloc(M31, aux_len);
    for (aux, 0..) |*word, i| word.* = M31.fromCanonical(@intCast(i + 100));

    const s = try Statement.init(allocator, &ctx, .{
        .constants = fixture.constants,
        .serialized_aux_data = aux,
        .output_hash = null,
        .program = program,
        .slot_names = fixture.slot_names,
        .enabled_bits = fixture.enabled_bits,
        .preprocessed_root = fixture.root,
        .variant = .canonical_small,
    });
    // The eight digest words are guessed first and become the outputs.
    try std.testing.expectEqualSlices(Recorder.Op, &([_]Recorder.Op{.guess_u32} ** 8 ++ [_]Recorder.Op{.set_outputs}), ctx.ops.items[0..9]);
    try std.testing.expectEqualSlices(u32, &.{ 2, 3, 4, 5, 6, 7, 8, 9 }, ctx.outputs);
    // Every aux word is guessed once, in serialized order.
    try std.testing.expectEqual(aux_len, ctx.count(.guess_m31));
    for (aux, ctx.guessed_m31.items) |want, got| try std.testing.expectEqual(want.v, got.v);
    try std.testing.expectEqual(@as(usize, 79), s.components.len);
    try std.testing.expectEqual(@as(usize, 79), s.aux_data.component_log_sizes.len);
    try std.testing.expectEqual(program.len, s.aux_data.program_ids.len);
    // Limbs past the 128 bits of each half are the zero constant.
    for (s.outputs) |cell| for (cell[15..]) |limb| try std.testing.expectEqual(@as(u32, 0), limb);
    // 64 extract calls x 16 bits and 15 limbs per half.
    try std.testing.expectEqual(@as(usize, 8 * 32), ctx.count(.extract_bits));
    try std.testing.expectEqual(@as(usize, 2 * 15), ctx.count(.combine_bits));

    const wrong = aux[0 .. aux_len - 1];
    var other = Recorder.Context.init();
    defer other.deinit();
    try std.testing.expectError(error.InvalidAuxData, Statement.init(other.allocator(), &other, .{
        .constants = fixture.constants,
        .serialized_aux_data = wrong,
        .output_hash = null,
        .program = program,
        .slot_names = fixture.slot_names,
        .enabled_bits = fixture.enabled_bits,
        .preprocessed_root = fixture.root,
        .variant = .canonical_small,
    }));
}

test "cairo statement: claims_to_mix groups, public params and builtin checks" {
    var fixture = try Fixture.load(std.testing.allocator);
    defer fixture.deinit();
    var ctx = Recorder.Context.init();
    defer ctx.deinit();
    const allocator = ctx.allocator();
    const program = try syntheticProgram(allocator, 5);
    const aux = try allocator.alloc(M31, layout.aux_data_fixed_len + program.len + 79);
    @memset(aux, M31.zero());
    const s = try Statement.init(allocator, &ctx, .{
        .constants = fixture.constants,
        .serialized_aux_data = aux,
        .output_hash = null,
        .program = program,
        .slot_names = fixture.slot_names,
        .enabled_bits = fixture.enabled_bits,
        .preprocessed_root = fixture.root,
        .variant = .canonical_small,
    });

    const groups = try s.claimsToMix(&ctx);
    const expected_lengths = [_]usize{ 4, 84, 80, 4, std.mem.alignForward(usize, layout.aux_data_fixed_len + program.len, 4), 8, 8 };
    for (groups, expected_lengths) |group, len| try std.testing.expectEqual(len, group.len);

    const params = s.publicParams();
    try std.testing.expectEqualStrings("output_segment_start", params[0].name);
    try std.testing.expectEqualStrings("mul_mod_builtin_segment_start", params[10].name);
    for (params, s.aux_data.segment_ranges) |param, range| try std.testing.expectEqual(range.start.value, param.value);

    // Builtins without a leaf component must have zero uses; with
    // canonical_small the narrow-window Pedersen component is present.
    var missing: usize = 0;
    for (layout.verify_builtins_order) |builtin| {
        const name = builtin.componentName(.canonical_small);
        var found = false;
        for (s.components) |component| found = found or std.mem.eql(u8, component, name);
        missing += @intFromBool(!found);
    }
    const sizes = try allocator.alloc(u32, s.components.len);
    for (sizes, 0..) |*v, i| v.* = @intCast(1000 + i);
    const zero_checks_before = ctx.eq_with_zero;
    try s.verifyClaim(&ctx, sizes, 1);
    try std.testing.expectEqual(missing, ctx.eq_with_zero - zero_checks_before);

    const root = try s.getPreprocessedRoot(&ctx);
    try std.testing.expectEqual(@as(usize, 8), root.len);
    var ids: [layout.max_preprocessed_columns]layout.ColumnId = undefined;
    try std.testing.expectEqual(@as(usize, 156), (try s.getPreprocessedColumnIds(&ids)).len);
    _ = try s.publicLogupSum(&ctx, .{ 1, 1 });
    // States (2), safe-call cells (2 x 2), segments (11 x 2 x 2), outputs (2 x 2), program (5 x 2).
    try std.testing.expectEqual(@as(usize, 2 + 4 + 44 + 4 + 10), ctx.count(.logup));
}

test "cairo statement: enabled bits over the projection's slot order match the R6 checkpoint" {
    const projection_mod = @import("../air_eval/projection.zig");
    const allocator = std.testing.allocator;
    var fixture = try Fixture.load(allocator);
    defer fixture.deinit();
    const bytes = try std.fs.cwd().readFileAlloc(allocator, "vectors/circuit/official/compiled_air_constraints_v1.bin", 64 * 1024 * 1024);
    defer allocator.free(bytes);
    var projection = try projection_mod.parse(allocator, bytes);
    defer projection.deinit();
    const source = projection.source("cairo").?;
    const slot_ids = projection.nameList(source.slots);
    const names = try allocator.alloc([]const u8, slot_ids.len);
    defer allocator.free(names);
    for (slot_ids, names) |id, *name| name.* = projection.str(id);
    try std.testing.expectEqual(fixture.slot_names.len, names.len);
    for (fixture.slot_names, names) |want, got| try std.testing.expectEqualStrings(want, got);

    var bits: [83]bool = undefined;
    try std.testing.expectEqual(@as(usize, 79), try layout.leafEnabledBits(.canonical_small, names, &bits));
    try std.testing.expectEqualSlices(bool, fixture.enabled_bits, &bits);

    // The projection header (through the evaluator table) and the statement checkpoint
    // agree on the memory constants the statement uses.
    const cairo_components = @import("../air_eval/cairo_components.zig");
    var table = try cairo_components.build(allocator, &projection);
    defer table.deinit();
    try std.testing.expectEqual(fixture.constants.memory, table.constants);
}

test "cairo statement: claims_to_mix interns the oracle's program hash" {
    var fixture = try Fixture.load(std.testing.allocator);
    defer fixture.deinit();
    const record = fixture.parsed.value.object.get("body").?.object.get("program").?.object;
    // The two-felt program [first felt, last felt] of the leaf test program.
    var program: [2]layout.ProgramFelt = undefined;
    for (&program, [_][]const u8{ "first_felt_limbs", "last_felt_limbs" }) |*felt, key| {
        for (felt, record.get(key).?.array.items) |*limb, value| limb.* = M31.fromCanonical(@intCast(value.integer));
    }
    var expected: [8]u32 = undefined;
    for (&expected, record.get("edge_felts_program_hash").?.array.items) |*word, value| word.* = @intCast(value.integer);

    var ctx = Recorder.Context.init();
    defer ctx.deinit();
    const allocator = ctx.allocator();
    const aux = try allocator.alloc(M31, layout.aux_data_fixed_len + program.len + 79);
    @memset(aux, M31.zero());
    const s = try Statement.init(allocator, &ctx, .{
        .constants = fixture.constants,
        .serialized_aux_data = aux,
        .output_hash = null,
        .program = &program,
        .slot_names = fixture.slot_names,
        .enabled_bits = fixture.enabled_bits,
        .preprocessed_root = fixture.root,
        .variant = .canonical_small,
    });
    const hashes_before = ctx.const_hashes.items.len;
    _ = try s.claimsToMix(&ctx);
    // `claims_to_mix` interns exactly one hash constant: the program hash.
    try std.testing.expectEqual(hashes_before + 1, ctx.const_hashes.items.len);
    try std.testing.expectEqual(expected, ctx.const_hashes.items[hashes_before]);
}

/// The R6 synthetic claim as `CairoStatement::new` inputs.
const SyntheticInputs = struct {
    aux: []M31,
    program: []layout.ProgramFelt,
    output_hash: [8]u32,
    log_sizes: []u32,
    mix_digest_m31: []const u8,

    fn load(allocator: std.mem.Allocator, fixture: *const Fixture) !SyntheticInputs {
        const claim = fixture.parsed.value.object.get("body").?.object.get("synthetic_claim").?.object;
        const words = struct {
            fn of(a: std.mem.Allocator, value: std.json.Value) ![]u32 {
                const out = try a.alloc(u32, value.array.items.len);
                for (out, value.array.items) |*w, v| w.* = @intCast(v.integer);
                return out;
            }
        }.of;
        const serialized = try words(allocator, claim.get("serialized_aux_data").?);
        const aux = try allocator.alloc(M31, serialized.len);
        for (aux, serialized) |*m, w| m.* = M31.fromCanonical(w);
        const limbs = try words(allocator, claim.get("program_claim").?);
        const program = try allocator.alloc(layout.ProgramFelt, limbs.len / layout.memory_values_limbs);
        for (program, 0..) |*felt, f| {
            for (felt, limbs[f * layout.memory_values_limbs ..][0..layout.memory_values_limbs]) |*limb, w| limb.* = M31.fromCanonical(w);
        }
        // `output_hash_from_output_cells`: the low four words of each cell.
        var output_hash: [8]u32 = undefined;
        for (claim.get("output").?.array.items, 0..) |cell, index| {
            for (output_hash[index * 4 ..][0..4], cell.object.get("value").?.array.items[0..4]) |*w, v| w.* = @intCast(v.integer);
        }
        return .{
            .aux = aux,
            .program = program,
            .output_hash = output_hash,
            .log_sizes = try words(allocator, claim.get("component_log_sizes").?),
            .mix_digest_m31 = claim.get("mix_digest_blake2s_m31").?.string,
        };
    }
};

/// Builds `CairoStatement::new`, `claims_to_mix`, `verify_claim` and
/// `public_logup_sum` over the builder; returns the context.
fn buildOverBuilder(comptime V: type, gpa: std.mem.Allocator, fixture: *const Fixture, inputs: SyntheticInputs, groups_out: ?*[7][]const builder.Var) !builder.Context(V) {
    const B = BuilderFacade(V);
    var ctx = try B.Context.init(gpa, 8);
    errdefer ctx.deinit();
    const allocator = ctx.scratch();
    const aux = if (V == QM31) inputs.aux else blk: {
        const zeros = try allocator.alloc(M31, inputs.aux.len);
        @memset(zeros, M31.zero());
        break :blk zeros;
    };
    const s = try statement.CairoStatement(B).init(allocator, &ctx, .{
        .constants = fixture.constants,
        .serialized_aux_data = aux,
        .output_hash = if (V == QM31) inputs.output_hash else null,
        .program = inputs.program,
        .slot_names = fixture.slot_names,
        .enabled_bits = fixture.enabled_bits,
        .preprocessed_root = fixture.root,
        .variant = .canonical_small,
    });
    const groups = try s.claimsToMix(&ctx);
    if (groups_out) |out| out.* = groups;
    const sizes = try allocator.alloc(builder.Var, s.components.len);
    for (sizes, inputs.log_sizes) |*v, log_size| v.* = try B.constU32(&ctx, @as(u32, 1) << @intCast(log_size));
    try s.verifyClaim(&ctx, sizes, try B.constU32(&ctx, 1));
    const z = try ctx.guess(builder.ivalue.fromQm31(V, QM31.fromU32Unchecked(3, 5, 7, 11)));
    const alpha = try ctx.guess(builder.ivalue.fromQm31(V, QM31.fromU32Unchecked(13, 17, 19, 23)));
    _ = try s.publicLogupSum(&ctx, .{ z, alpha });
    return ctx;
}

test "cairo statement over the builder: claims_to_mix mixes to FlatClaim::mix_into" {
    const gpa = std.testing.allocator;
    var fixture = try Fixture.load(gpa);
    defer fixture.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const inputs = try SyntheticInputs.load(arena.allocator(), &fixture);

    var groups: [7][]const builder.Var = undefined;
    var ctx = try buildOverBuilder(QM31, gpa, &fixture, inputs, &groups);
    defer ctx.deinit();
    // The verifier mixes each group with `channel.mix_u32s`; the host
    // Blake2sM31 channel over the same words must reach upstream's digest.
    var channel = core.channel.blake2s.Blake2sM31Channel{};
    for (groups) |group| {
        const words = try arena.allocator().alloc(u32, group.len);
        for (words, group) |*w, v| w.* = builder.ivalue.unpackU32(QM31, ctx.get(v));
        channel.mixU32s(words);
    }
    const hex = std.fmt.bytesToHex(channel.digestBytes(), .lower);
    try std.testing.expectEqualStrings(inputs.mix_digest_m31, &hex);
}

test "cairo statement over the builder: value and topology builds emit the same gates" {
    const gpa = std.testing.allocator;
    var fixture = try Fixture.load(gpa);
    defer fixture.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const inputs = try SyntheticInputs.load(arena.allocator(), &fixture);

    var values = try buildOverBuilder(QM31, gpa, &fixture, inputs, null);
    defer values.deinit();
    var topology = try buildOverBuilder(builder.NoValue, gpa, &fixture, inputs, null);
    defer topology.deinit();
    const a = try builder.debug_format.circuitText(gpa, &values.circuit);
    defer gpa.free(a);
    const b = try builder.debug_format.circuitText(gpa, &topology.circuit);
    defer gpa.free(b);
    try std.testing.expectEqualStrings(a, b);
    try std.testing.expect(values.circuit.n_vars > 10_000);
}
