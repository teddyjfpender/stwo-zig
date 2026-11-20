//! Circuit-AIR composition DAG dump + differential vectors.
//!
//! The in-circuit composition evaluation (`constraint_eval.
//! computeCompositionPolynomial` with the 11-component circuit table) is an
//! interpreter over the committed projection data. This tool flattens its
//! denotation into one arithmetic DAG over the composition inputs (sampled
//! values and challenges) by replaying the table's evaluators and the
//! accumulator through a recording context, and emits:
//!
//!  1. `CircuitAirData.lean`: the DAG (atoms, constants, add/sub/mul/inv
//!     nodes), the `eq` side conditions (the generated fixed-size checks and
//!     the Seq one-hot), the preprocessed id order and the discovered
//!     n-instances-bit atoms, as generated Lean arrays. The Lean spec
//!     evaluates this DAG to instantiate `Air.evalComposition`; the final
//!     division by the trace coset's vanishing polynomial stays in Lean
//!     (it depends on the proof's log trace size).
//!  2. `airvectors.json`: differential vectors. Each vector's expected
//!     output comes from the REAL `computeCompositionPolynomial` running
//!     eagerly over `builder.Context(QM31)` — code the recording never
//!     touches — so the vectors check the mirrored loop, the recording and
//!     the Lean evaluation against the shipping implementation.
//!
//! The DAG is profile-independent: the 45 preprocessed column ids are
//! static, only `seq_16` exists among the Seq candidates, and every
//! n-instances bit the evaluators read is <= 20, so any circuit proof
//! (log trace >= 20) evaluates the same DAG.
//!
//! Build (from the repo root):
//!   zig build-exe formal/in-circuit-verifier/harness/airdump.zig \
//!     --dep stwo_core --dep stwo_circuit_frontend \
//!     -Mroot=formal/in-circuit-verifier/harness/airdump.zig \
//!     --dep stwo_core --dep stwo_prover_engine \
//!     -Mstwo_circuit_frontend=src/frontends/circuit/mod.zig \
//!     --dep stwo_core --dep stwo_backend_contracts --dep stwo_prover_api \
//!     -Mstwo_prover_engine=src/prover/mod.zig \
//!     --dep stwo_core -Mstwo_backend_contracts=src/backend/mod.zig \
//!     --dep stwo_core -Mstwo_prover_api=src/prover_api/mod.zig \
//!     -Mstwo_core=src/core/mod.zig -O ReleaseSafe
//!
//! Run (from the repo root):
//!   ./airdump formal/in-circuit-verifier/StwoVerifier/CircuitAirData.lean \
//!             formal/in-circuit-verifier/harness/airvectors.json

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const component_list = circuit.common.component_list;
const preprocessed = circuit.common.preprocessed;
const constraint_eval = circuit.stark_verifier.constraint_eval;
const circle = circuit.stark_verifier.circle;
const projection_mod = circuit.air_eval.projection;
const circuit_components = circuit.air_eval.circuit_components;
const component_table = circuit.air_eval.component_table;
const circuit_statement = circuit.statements.circuit_statement;
const builder = circuit.builder;

const N_COMPONENTS = component_list.N_COMPONENTS;
const bundle_path = "vectors/circuit/official/compiled_air_constraints_v1.bin";

// ---------------------------------------------------------------------------
// Canonical input layout. Atoms reference flat indices into one input vector;
// the order here is the contract between this tool, the vectors and Lean.
// ---------------------------------------------------------------------------

const PP_IDS: [preprocessed.N_PREPROCESSED_COLUMNS][]const u8 = blk: {
    var ids: [preprocessed.N_PREPROCESSED_COLUMNS][]const u8 = undefined;
    var at: usize = 0;
    for (preprocessed.EQ_COLUMN_IDS) |id| {
        ids[at] = id;
        at += 1;
    }
    for (preprocessed.QM31_OPS_COLUMN_IDS) |id| {
        ids[at] = id;
        at += 1;
    }
    for (preprocessed.TRIPLE_XOR_COLUMN_IDS) |id| {
        ids[at] = id;
        at += 1;
    }
    for (preprocessed.M31_TO_U32_COLUMN_IDS) |id| {
        ids[at] = id;
        at += 1;
    }
    for (preprocessed.BLAKE_G_GATE_COLUMN_IDS) |id| {
        ids[at] = id;
        at += 1;
    }
    for (preprocessed.FIXED_COLUMNS) |fixed| {
        ids[at] = fixed.id;
        at += 1;
    }
    break :blk ids;
};

const N_PP = preprocessed.N_PREPROCESSED_COLUMNS;

fn totalTraceColumns() usize {
    var total: usize = 0;
    for (component_list.component_facts.toArray()) |facts| total += facts.trace_columns;
    return total;
}

fn totalInteractionColumns() usize {
    var total: usize = 0;
    for (component_list.component_facts.toArray()) |facts| total += facts.interaction_columns;
    return total;
}

const N_TRACE = totalTraceColumns();
const N_INTER = totalInteractionColumns();
const N_PREV = N_COMPONENTS * 4;

const at_ptx: usize = 0;
const at_pp: usize = 1;
const at_trace: usize = at_pp + N_PP;
const at_inter: usize = at_trace + N_TRACE;
const at_prev: usize = at_inter + N_INTER;
const at_coeff: usize = at_prev + N_PREV;
const at_z: usize = at_coeff + 1;
const at_alpha: usize = at_z + 1;
const at_claimed: usize = at_alpha + 1;
const at_size: usize = at_claimed + N_COMPONENTS;
const at_nbit: usize = at_size + N_COMPONENTS;

// ---------------------------------------------------------------------------
// Recording context: Var = node index, ops append nodes, eq records a side
// condition. Satisfies the Ctx surface the interpreter, the accumulator,
// logup and seqOfComponentSize use.
// ---------------------------------------------------------------------------

const Node = union(enum) {
    atom: u32,
    constant: QM31,
    add: [2]u32,
    sub: [2]u32,
    mul: [2]u32,
    inv: u32,
};

const RecCtx = struct {
    pub const Var = u32;

    gpa: std.mem.Allocator,
    nodes: std.ArrayList(Node) = .empty,
    eqs: std.ArrayList([2]u32) = .empty,
    const_map: std.AutoHashMapUnmanaged(u128, u32) = .empty,
    zero_v: u32 = undefined,
    one_v: u32 = undefined,

    fn init(gpa: std.mem.Allocator) !RecCtx {
        var self = RecCtx{ .gpa = gpa };
        self.zero_v = try self.constant(QM31.zero());
        self.one_v = try self.constant(QM31.one());
        return self;
    }

    fn push(self: *RecCtx, node: Node) !u32 {
        const id: u32 = @intCast(self.nodes.items.len);
        try self.nodes.append(self.gpa, node);
        return id;
    }

    pub fn zero(self: *const RecCtx) u32 {
        return self.zero_v;
    }

    pub fn one(self: *const RecCtx) u32 {
        return self.one_v;
    }

    pub fn constant(self: *RecCtx, value: QM31) !u32 {
        const key = builder.context.constantKey(value);
        if (self.const_map.get(key)) |id| return id;
        const id = try self.push(.{ .constant = value });
        try self.const_map.put(self.gpa, key, id);
        return id;
    }

    pub fn add(self: *RecCtx, a: u32, b: u32) !u32 {
        return self.push(.{ .add = .{ a, b } });
    }

    pub fn sub(self: *RecCtx, a: u32, b: u32) !u32 {
        return self.push(.{ .sub = .{ a, b } });
    }

    pub fn mul(self: *RecCtx, a: u32, b: u32) !u32 {
        return self.push(.{ .mul = .{ a, b } });
    }

    pub fn inv(self: *RecCtx, a: u32) !u32 {
        return self.push(.{ .inv = a });
    }

    pub fn eq(self: *RecCtx, a: u32, b: u32) !void {
        try self.eqs.append(self.gpa, .{ a, b });
    }

    fn atom(self: *RecCtx, index: usize) !u32 {
        return self.push(.{ .atom = @intCast(index) });
    }
};

/// Discovered `(component, bit)` n-instances-bit atoms, in first-use order.
const NbitRegistry = struct {
    gpa: std.mem.Allocator,
    map: std.AutoHashMapUnmanaged(u32, u32) = .empty,
    list: std.ArrayList([2]u32) = .empty,

    fn node(self: *NbitRegistry, ctx: *RecCtx, component: usize, bit: usize) !u32 {
        const key: u32 = @intCast(component << 8 | bit);
        if (self.map.get(key)) |id| return id;
        const flat = at_nbit + self.list.items.len;
        const id = try ctx.atom(flat);
        try self.map.put(self.gpa, key, id);
        try self.list.append(self.gpa, .{ @intCast(component), @intCast(bit) });
        return id;
    }
};

/// The component-data surface over recording atoms.
const RecData = struct {
    trace: []const u32,
    n_instances: u32,
    index: usize,
    reg: *NbitRegistry,

    pub fn traceColumns(self: *const RecData) []const u32 {
        return self.trace;
    }

    pub fn nInstances(self: *const RecData) u32 {
        return self.n_instances;
    }

    pub fn getNInstancesBit(self: *const RecData, ctx: *RecCtx, bit: usize) !u32 {
        return self.reg.node(ctx, self.index, bit);
    }

    pub fn maxComponentSizeBits(_: *const RecData) usize {
        // Only bit presence matters for the recorded DAG: every bit the
        // evaluators read is <= 20 and only `seq_16` exists, so any bound
        // above 20 records the same DAG. A real proof has log_trace + 1.
        return 31;
    }
};

const Recorded = struct {
    ctx: RecCtx,
    nbits: NbitRegistry,
    /// The accumulated constraint sum, before the vanishing division.
    sum: u32,
};

/// Mirror of `computeCompositionPolynomial`'s loop over the recording
/// context, stopping before the vanishing division (Lean's side).
fn record(gpa: std.mem.Allocator, table: *const component_table.Table) !Recorded {
    var ctx = try RecCtx.init(gpa);
    var nbits = NbitRegistry{ .gpa = gpa };

    var pp_map: constraint_eval.ColumnMap(u32) = .empty;
    for (PP_IDS, 0..) |id, i| try pp_map.put(gpa, id, try ctx.atom(at_pp + i));
    var params: constraint_eval.ColumnMap(u32) = .empty;

    var trace_atoms: [N_TRACE]u32 = undefined;
    for (&trace_atoms, 0..) |*v, i| v.* = try ctx.atom(at_trace + i);
    var inter_atoms: [N_INTER]u32 = undefined;
    for (&inter_atoms, 0..) |*v, i| v.* = try ctx.atom(at_inter + i);
    var prev_atoms: [N_PREV]u32 = undefined;
    for (&prev_atoms, 0..) |*v, i| v.* = try ctx.atom(at_prev + i);
    const coeff = try ctx.atom(at_coeff);
    const z = try ctx.atom(at_z);
    const alpha = try ctx.atom(at_alpha);
    var claimed: [N_COMPONENTS]u32 = undefined;
    for (&claimed, 0..) |*v, i| v.* = try ctx.atom(at_claimed + i);
    var sizes: [N_COMPONENTS]u32 = undefined;
    for (&sizes, 0..) |*v, i| v.* = try ctx.atom(at_size + i);

    var acc = constraint_eval.CompositionConstraintAccumulator(RecCtx).init(
        gpa,
        &ctx,
        &pp_map,
        &params,
        coeff,
        .{ z, alpha },
    );

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var trace_at: usize = 0;
    var inter_at: usize = 0;
    for (circuit_statement.circuit_component_shapes, 0..) |shape, index| {
        const data = RecData{
            .trace = trace_atoms[trace_at..][0..shape.trace_columns],
            .n_instances = sizes[index],
            .index = index,
            .reg = &nbits,
        };
        try table.evaluate(index, RecCtx, &ctx, &data, &acc, arena_state.allocator());
        const interaction = try gpa.alloc(constraint_eval.InteractionAtOods(u32), shape.interaction_columns);
        for (interaction, 0..) |*column, i| {
            column.* = .{ .at_oods = inter_atoms[inter_at + i] };
            if (i >= shape.interaction_columns - 4) {
                const prev_index = index * 4 + (i - (shape.interaction_columns - 4));
                column.at_prev = prev_atoms[prev_index];
            }
        }
        try acc.finalizeLogupInPairs(&ctx, interaction, &data, claimed[index]);
        trace_at += shape.trace_columns;
        inter_at += shape.interaction_columns;
        _ = arena_state.reset(.retain_capacity);
    }
    std.debug.assert(trace_at == N_TRACE and inter_at == N_INTER);

    return .{ .ctx = ctx, .nbits = nbits, .sum = acc.finalize() };
}

// ---------------------------------------------------------------------------
// Reference evaluation: the real computeCompositionPolynomial over
// builder.Context(QM31), inputs as constants/packed Simds.
// ---------------------------------------------------------------------------

const RefStatement = struct {
    table: *const component_table.Table,
    ids: [N_PP][]const u8,

    pub fn preprocessedColumnIds(self: *const RefStatement) []const []const u8 {
        return &self.ids;
    }

    pub fn publicParams(_: *const RefStatement, _: *builder.Context(QM31), _: *constraint_eval.ColumnMap(builder.Var)) !void {}

    pub fn nComponents(_: *const RefStatement) usize {
        return N_COMPONENTS;
    }

    pub fn evaluateComponent(
        self: *const RefStatement,
        index: usize,
        ctx: *builder.Context(QM31),
        data: *const constraint_eval.ComponentData(QM31),
        acc: *constraint_eval.CompositionConstraintAccumulator(builder.Context(QM31)),
    ) !void {
        try self.table.evaluate(index, builder.Context(QM31), ctx, data, acc, ctx.scratch());
    }
};

const Vector = struct {
    log_trace: u32,
    inputs: []QM31,
    expected: QM31,
    valid: bool,
};

fn referenceRun(
    gpa: std.mem.Allocator,
    table: *const component_table.Table,
    n_nbits: usize,
    nbit_list: []const [2]u32,
    log_trace: u32,
    log_sizes: [N_COMPONENTS]u32,
    seed: u64,
) !Vector {
    const n_inputs = at_nbit + n_nbits;
    const inputs = try gpa.alloc(QM31, n_inputs);

    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();
    for (inputs) |*v| {
        v.* = QM31.fromU32Unchecked(
            rand.uintLessThan(u32, 2147483647),
            rand.uintLessThan(u32, 2147483647),
            rand.uintLessThan(u32, 2147483647),
            rand.uintLessThan(u32, 2147483647),
        );
    }
    // Component sizes and their bit lanes are structural, not random.
    for (log_sizes, 0..) |log_size, i| {
        inputs[at_size + i] = QM31.fromBase(M31.fromCanonical(@as(u32, 1) << @intCast(log_size)));
    }
    for (nbit_list, 0..) |cb, i| {
        const is_set = log_sizes[cb[0]] == cb[1];
        inputs[at_nbit + i] = if (is_set) QM31.one() else QM31.zero();
    }

    var ctx = try builder.Context(QM31).init(gpa, component_list.N_RESERVED);
    defer ctx.deinit();

    const vars = try gpa.alloc(builder.Var, n_inputs);
    defer gpa.free(vars);
    // Guess, not constant: constants dedupe, and the reference must not
    // accidentally alias two inputs that happen to collide.
    for (vars, inputs) |*v, value| v.* = try ctx.guess(value);

    const interaction = try gpa.alloc(constraint_eval.InteractionAtOods(builder.Var), N_INTER);
    defer gpa.free(interaction);
    {
        var inter_at: usize = 0;
        for (circuit_statement.circuit_component_shapes, 0..) |shape, index| {
            for (0..shape.interaction_columns) |i| {
                interaction[inter_at + i] = .{ .at_oods = vars[at_inter + inter_at + i] };
                if (i >= shape.interaction_columns - 4) {
                    const prev_index = index * 4 + (i - (shape.interaction_columns - 4));
                    interaction[inter_at + i].at_prev = vars[at_prev + prev_index];
                }
            }
            inter_at += shape.interaction_columns;
        }
    }

    // n_instances_bits: bit b of every component's size, 11 lanes packed
    // four to a QM31 wire, log_trace + 1 bits as the real verifier builds.
    const n_bits: usize = @intCast(log_trace + 1);
    const bit_simds = try gpa.alloc(builder.simd.Simd, n_bits);
    defer gpa.free(bit_simds);
    for (bit_simds, 0..) |*simd_reg, b| {
        const n_wires = (N_COMPONENTS + 3) / 4;
        const wires = try ctx.scratch().alloc(builder.Var, n_wires);
        for (wires, 0..) |*wire, w| {
            var lane_bits: [4]u32 = .{ 0, 0, 0, 0 };
            for (0..4) |j| {
                const lane = 4 * w + j;
                if (lane < N_COMPONENTS and log_sizes[lane] == b) lane_bits[j] = 1;
            }
            wire.* = try ctx.guess(QM31.fromU32Unchecked(lane_bits[0], lane_bits[1], lane_bits[2], lane_bits[3]));
        }
        simd_reg.* = .fromPacked(wires, N_COMPONENTS);
    }

    const statement = RefStatement{ .table = table, .ids = PP_IDS };
    const pt_y = try ctx.guess(QM31.zero());
    const out = try constraint_eval.computeCompositionPolynomial(
        QM31,
        &ctx,
        circuit_statement.circuit_component_shapes,
        &statement,
        .{
            .preprocessed_columns = vars[at_pp..][0..N_PP],
            .trace = vars[at_trace..][0..N_TRACE],
            .interaction = interaction,
            .pt = .{ .x = vars[at_ptx], .y = pt_y },
            .log_domain_size = @intCast(log_trace),
            .composition_polynomial_coeff = vars[at_coeff],
            .interaction_elements = .{ vars[at_z], vars[at_alpha] },
            .claimed_sums = vars[at_claimed..][0..N_COMPONENTS],
            .component_sizes = vars[at_size..][0..N_COMPONENTS],
            .n_instances_bits = bit_simds,
        },
    );

    const expected = ctx.values()[out.idx];
    const valid = try ctx.isCircuitValid();
    return .{ .log_trace = log_trace, .inputs = inputs, .expected = expected, .valid = valid };
}

// ---------------------------------------------------------------------------
// Output writers.
// ---------------------------------------------------------------------------

fn limbs(value: QM31) [4]u32 {
    const coords = value.toM31Array();
    return .{ coords[0].v, coords[1].v, coords[2].v, coords[3].v };
}

fn writeLean(gpa: std.mem.Allocator, path: []const u8, rec: *const Recorded) !void {
    var consts: std.ArrayList(QM31) = .empty;
    defer consts.deinit(gpa);
    var const_index = std.AutoHashMapUnmanaged(u32, u32).empty;
    defer const_index.deinit(gpa);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const w = out.writer(gpa);

    try w.writeAll(
        \\/-
        \\GENERATED by harness/airdump.zig -- do not edit.
        \\
        \\The circuit-AIR composition DAG: the flattened denotation of
        \\`computeCompositionPolynomial` with the 11-component circuit table
        \\(projection `vectors/circuit/official/compiled_air_constraints_v1.bin`),
        \\up to (not including) the division by the trace coset's vanishing
        \\polynomial. Node encoding: `(tag, a, b)` with tag 0 = constant
        \\(a indexes `consts`), 1 = atom (a is the flat input index), 2 = add,
        \\3 = sub, 4 = mul, 5 = inv (of a). `eqs` are the recorded side
        \\conditions (generated fixed-size checks, Seq one-hot). Valid for any
        \\circuit proof: the preprocessed ids are static and log trace >= 20.
        \\-/
        \\
        \\set_option maxRecDepth 100000
        \\
        \\namespace StwoVerifier.CircuitAirData
        \\
        \\
    );

    try w.print("/-- Flat input layout. -/\ndef atomPtX : Nat := {d}\n", .{at_ptx});
    try w.print("def atomPp : Nat := {d}\ndef nPp : Nat := {d}\n", .{ at_pp, N_PP });
    try w.print("def atomTrace : Nat := {d}\ndef nTrace : Nat := {d}\n", .{ at_trace, N_TRACE });
    try w.print("def atomInter : Nat := {d}\ndef nInter : Nat := {d}\n", .{ at_inter, N_INTER });
    try w.print("def atomPrev : Nat := {d}\ndef nPrev : Nat := {d}\n", .{ at_prev, N_PREV });
    try w.print("def atomCoeff : Nat := {d}\ndef atomZ : Nat := {d}\ndef atomAlpha : Nat := {d}\n", .{ at_coeff, at_z, at_alpha });
    try w.print("def atomClaimed : Nat := {d}\ndef atomSize : Nat := {d}\ndef atomNbit : Nat := {d}\n", .{ at_claimed, at_size, at_nbit });
    try w.print("def nInputs : Nat := {d}\n\n", .{at_nbit + rec.nbits.list.items.len});

    try w.writeAll("/-- Preprocessed column ids, in flat-input order. -/\ndef ppIds : Array String := #[");
    for (PP_IDS, 0..) |id, i| {
        if (i != 0) try w.writeAll(", ");
        try w.print("\"{s}\"", .{id});
    }
    try w.writeAll("]\n\n");

    try w.writeAll("/-- `(component, bit)` of each n-instances-bit atom, in atom order. -/\ndef nbitAtoms : Array (Nat \u{d7} Nat) := #[");
    for (rec.nbits.list.items, 0..) |cb, i| {
        if (i != 0) try w.writeAll(", ");
        try w.print("({d}, {d})", .{ cb[0], cb[1] });
    }
    try w.writeAll("]\n\n");

    try w.writeAll("/-- Trace / interaction column counts per component, `ComponentList` order. -/\ndef traceShape : Array Nat := #[");
    for (component_list.component_facts.toArray(), 0..) |facts, i| {
        if (i != 0) try w.writeAll(", ");
        try w.print("{d}", .{facts.trace_columns});
    }
    try w.writeAll("]\ndef interShape : Array Nat := #[");
    for (component_list.component_facts.toArray(), 0..) |facts, i| {
        if (i != 0) try w.writeAll(", ");
        try w.print("{d}", .{facts.interaction_columns});
    }
    try w.writeAll("]\n\n");

    // Assign constant indices in node order.
    for (rec.ctx.nodes.items) |node| {
        if (node == .constant) {
            const id: u32 = @intCast(consts.items.len);
            // Re-keyed below by node position during node emission; collect
            // in encounter order here.
            _ = id;
            try consts.append(gpa, node.constant);
        }
    }
    try w.writeAll("/-- Constant pool, as M31 limb quadruples. -/\ndef consts : Array (Nat \u{d7} Nat \u{d7} Nat \u{d7} Nat) := #[");
    for (consts.items, 0..) |value, i| {
        if (i != 0) try w.writeAll(", ");
        const l = limbs(value);
        try w.print("({d}, {d}, {d}, {d})", .{ l[0], l[1], l[2], l[3] });
    }
    try w.writeAll("]\n\n");

    try w.print("/-- The DAG, in evaluation order ({d} nodes). -/\ndef nodes : Array (Nat \u{d7} Nat \u{d7} Nat) := #[", .{rec.ctx.nodes.items.len});
    var next_const: u32 = 0;
    for (rec.ctx.nodes.items, 0..) |node, i| {
        if (i != 0) try w.writeAll(", ");
        switch (node) {
            .constant => {
                try w.print("(0, {d}, 0)", .{next_const});
                next_const += 1;
            },
            .atom => |index| try w.print("(1, {d}, 0)", .{index}),
            .add => |ab| try w.print("(2, {d}, {d})", .{ ab[0], ab[1] }),
            .sub => |ab| try w.print("(3, {d}, {d})", .{ ab[0], ab[1] }),
            .mul => |ab| try w.print("(4, {d}, {d})", .{ ab[0], ab[1] }),
            .inv => |a| try w.print("(5, {d}, 0)", .{a}),
        }
    }
    try w.writeAll("]\n\n");

    try w.writeAll("/-- `eq` side conditions: node pairs that must agree. -/\ndef eqs : Array (Nat \u{d7} Nat) := #[");
    for (rec.ctx.eqs.items, 0..) |pair, i| {
        if (i != 0) try w.writeAll(", ");
        try w.print("({d}, {d})", .{ pair[0], pair[1] });
    }
    try w.writeAll("]\n\n");

    try w.print("/-- The accumulated constraint sum (before the vanishing division). -/\ndef output : Nat := {d}\n\nend StwoVerifier.CircuitAirData\n", .{rec.sum});

    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = out.items });
}

fn writeVectors(gpa: std.mem.Allocator, path: []const u8, vectors: []const Vector) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const w = out.writer(gpa);

    try w.writeAll("{\n  \"vectors\": [\n");
    for (vectors, 0..) |vec, i| {
        try w.print("    {{\"logTrace\": {d}, \"valid\": {}, \"expected\": ", .{ vec.log_trace, vec.valid });
        const e = limbs(vec.expected);
        try w.print("[{d}, {d}, {d}, {d}], \"inputs\": [", .{ e[0], e[1], e[2], e[3] });
        for (vec.inputs, 0..) |value, j| {
            if (j != 0) try w.writeAll(", ");
            const l = limbs(value);
            try w.print("[{d}, {d}, {d}, {d}]", .{ l[0], l[1], l[2], l[3] });
        }
        try w.writeAll("]}");
        try w.writeAll(if (i + 1 == vectors.len) "\n" else ",\n");
    }
    try w.writeAll("  ]\n}\n");

    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = out.items });
}

// ---------------------------------------------------------------------------

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa = gpa_state.allocator();

    var args = std.process.args();
    _ = args.next();
    const lean_path = args.next() orelse "formal/in-circuit-verifier/StwoVerifier/CircuitAirData.lean";
    const json_path = args.next() orelse "formal/in-circuit-verifier/harness/airvectors.json";

    const bytes = try std.fs.cwd().readFileAlloc(gpa, bundle_path, 1 << 28);
    var projection = try projection_mod.parse(gpa, bytes);
    var table = try circuit_components.build(gpa, &projection);
    defer table.deinit();

    var rec = try record(gpa, &table);
    std.debug.print(
        "recorded: {d} nodes, {d} eq conditions, {d} nbit atoms, sum node {d}\n",
        .{ rec.ctx.nodes.items.len, rec.ctx.eqs.items.len, rec.nbits.list.items.len, rec.sum },
    );

    try writeLean(gpa, lean_path, &rec);

    // Vector profiles: consistent size assignments (fixed tables at their
    // fixed log sizes) plus two deliberately inconsistent ones.
    const base_sizes = [N_COMPONENTS]u32{ 20, 23, 20, 21, 23, 16, 20, 8, 14, 18, 16 };
    const small_sizes = [N_COMPONENTS]u32{ 18, 22, 19, 20, 22, 16, 20, 8, 14, 18, 16 };
    var bad_xor4 = base_sizes;
    bad_xor4[7] = 9; // verify_bitwise_xor_4 away from its fixed log size 8
    var bad_rc16 = base_sizes;
    bad_rc16[10] = 17; // range_check_16 away from seq_16

    var vectors: std.ArrayList(Vector) = .empty;
    const n_nbits = rec.nbits.list.items.len;
    const nbit_list = rec.nbits.list.items;
    try vectors.append(gpa, try referenceRun(gpa, &table, n_nbits, nbit_list, 23, base_sizes, 1001));
    try vectors.append(gpa, try referenceRun(gpa, &table, n_nbits, nbit_list, 22, small_sizes, 1002));
    try vectors.append(gpa, try referenceRun(gpa, &table, n_nbits, nbit_list, 23, base_sizes, 1003));
    try vectors.append(gpa, try referenceRun(gpa, &table, n_nbits, nbit_list, 23, base_sizes, 1004));
    try vectors.append(gpa, try referenceRun(gpa, &table, n_nbits, nbit_list, 23, base_sizes, 1005));
    try vectors.append(gpa, try referenceRun(gpa, &table, n_nbits, nbit_list, 23, bad_xor4, 1006));
    try vectors.append(gpa, try referenceRun(gpa, &table, n_nbits, nbit_list, 23, bad_rc16, 1007));

    try writeVectors(gpa, json_path, vectors.items);
    std.debug.print("wrote {s} and {s} ({d} vectors)\n", .{ lean_path, json_path, vectors.items.len });
}
