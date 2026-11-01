//! Raw local rational authority over the actual Word16 MAIN row projections.
//! The same functions serve native row queries and authenticated point/circuit
//! evaluation. A sink receives (relation, tuple, base-field signed weight).
//! No challenge draw, inverse, MAIN reconstruction or global obligation lives here.
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const X = A.word16_execution;
const B = A.word16_v1;
const LS = A.memory.load_store_v2;
pub const Relation = enum {
    register,
    rom,
    function,
    owner,
    range16,
    range8,
    and_,
    shift,
    selection,
    pub fn arity(self: Relation) usize {
        return switch (self) {
            .register => 6,
            .rom => X.layout.rom.COUNT,
            .function => 13,
            .owner => 19,
            .range16, .range8 => 1,
            .and_ => 3,
            .shift => 6,
            .selection => 5,
        };
    }
};
pub const MAX_ARITY = X.layout.rom.COUNT;
/// All six REG terms are kept distinct, including zero-weight poles. Ranges
/// are unit queries on padded rows as well as active rows.
pub fn cpuFor(comptime F: type, fixed: []const F, row: []const F, epoch: F, sink: anytype) void {
    const m = X.layout.main;
    for (0..3) |slot| {
        const w = row[m.enabled + slot];
        sink.emit(.register, X.tuples.register(F, fixed, row, slot, false), w);
        sink.emit(.register, X.tuples.register(F, fixed, row, slot, true), w.neg());
    }
    sink.emit(.function, X.tuples.function(F, row), row[m.function]);
    sink.emit(.rom, X.tuples.rom(F, row), row[m.active]);
    sink.emit(.owner, X.tuples.owner(F, fixed, row, epoch), row[m.active].sub(row[m.function]));
    for (0..3) |slot| sink.emit(.range16, [1]F{row[m.gap16 + slot]}, F.one());
    for (0..3) |slot| sink.emit(.range8, [1]F{row[m.gap8 + slot]}, F.one());
}
pub fn aluFor(comptime F: type, main: []const F, sink: anytype) void {
    const Q = B.alu_experiment.lookup;
    const C = B.alu_experiment.equations;
    const row = Q.rowFromColumnsFor(F, main);
    for (0..C.RANGE_QUERIES) |i| sink.emit(.range16, [1]F{C.rangeValueFor(F, &row, i)}, F.one());
    sink.emit(.function, row.payload, main[C.LOCAL_MAIN].neg());
}
pub fn binaryFor(comptime F: type, main: []const F, sink: anytype) void {
    const C = B.binary;
    const row = B.binary_lookup.rowFromColumnsFor(F, main);
    for (0..C.AND_REQUESTS) |i| sink.emit(.and_, C.andTupleFor(F, &row, i), F.one());
    sink.emit(.function, row.payload, main[C.LOCAL_MAIN].neg());
}
pub fn shiftFor(comptime F: type, main: []const F, sink: anytype) void {
    const C = B.shift_word_packed_experiment.equations;
    const row = C.rowFromColumnsFor(F, main);
    for (0..C.TABLE_QUERIES) |i| sink.emit(.shift, C.tableTupleFor(F, &row, i), F.one());
    for (0..C.RANGE_QUERIES) |i| sink.emit(.range16, [1]F{C.rangeValueFor(F, &row, i)}, F.one());
    sink.emit(.function, row.payload, main[C.LOCAL_MAIN].neg());
}
pub fn jalrFor(comptime F: type, main: []const F, sink: anytype) void {
    const C = X.jalr_equations;
    const weight = main[C.ACTIVE];
    sink.emit(.function, C.request(F, main), weight.neg());
    sink.emit(.function, C.add(F, main), weight);
    sink.emit(.function, C.and_(F, main), weight);
}
pub fn lsFor(comptime F: type, physical_main: []const F, sink: anytype) void {
    const logical = LS.layout.projection.expandFor(F, physical_main);
    sink.emit(.owner, LS.equations.ownerTupleForLogical(F, &logical), logical[0].neg());
    for (LS.layout.LOGICAL_U16) |c| sink.emit(.range16, [1]F{logical[c]}, F.one());
    for (LS.layout.LOGICAL_U8) |c| sink.emit(.range8, [1]F{logical[c]}, F.one());
    sink.emit(.selection, A.memory.load_store_v1.equations.selectionTuple(F, &logical), F.one());
}
pub fn divisionFor(comptime F: type, main: []const F, sink: anytype) void {
    const C = A.arithmetic.division.word16_product.equations;
    const active = C.activeFor(F, main);
    for ([_]?bool{ null, false, true }, 0..) |support, i| sink.emit(.function, C.tupleFor(F, main, support), if (i == 0) active.neg() else active);
    for (C.rangeValuesFor(F, main)) |value| sink.emit(.range16, [1]F{value}, F.one());
}
/// Exact affine inverse of arithmetic_bus's NEGATED byte-coefficient basis:
/// offset+dot(negative byte coefficients,bytes)=offset-dot(word13,limbs).
/// This identity holds at arbitrary point values, not only canonical bytes.
pub fn multiplicationFor(comptime F: type, main: *const [A.arithmetic.multiplication.layout.MAIN]F, sink: anytype) void {
    const C = A.arithmetic.multiplication.provider;
    for (C.byteValuesFor(F, main)) |value| sink.emit(.range8, [1]F{value}, F.one());
    const bytes = C.tupleFor(F, main);
    var word: [13]F = undefined;
    word[0] = bytes[0];
    for (0..12) |i| {
        var high = bytes[2 + 2 * i];
        inline for (0..8) |_| high = high.add(high);
        word[1 + i] = bytes[1 + 2 * i].add(high);
    }
    sink.emit(.function, word, C.activeFor(F, main).neg());
}
pub fn romFor(comptime F: type, fixed: []const F, main: []const F, sink: anytype) void {
    sink.emit(.rom, fixed[0..X.layout.rom.COUNT].*, main[0].neg());
}
pub fn registerBoundaryFor(comptime F: type, fixed: []const F, public: anytype, sink: anytype) void {
    const C = A.word16_cpu.boundary;
    sink.emit(.register, C.tupleWithInputsFor(F, fixed, public, false), F.one().neg());
    sink.emit(.register, C.tupleWithInputsFor(F, fixed, public, true), F.one());
}
pub fn scalarTableFor(comptime F: type, relation: Relation, fixed: []const F, main: []const F, sink: anytype) void {
    sink.emit(relation, [1]F{fixed[0]}, main[0].neg());
}
pub fn andTableFor(comptime F: type, fixed: []const F, main: []const F, sink: anytype) void {
    sink.emit(.and_, fixed[0..3].*, main[0].neg());
}
pub fn shiftTableFor(comptime F: type, fixed: []const F, main: []const F, sink: anytype) void {
    const C = B.shift_word_packed_experiment.table;
    for (0..C.MAIN) |lane| sink.emit(.shift, C.tupleFor(F, fixed, lane), main[lane].neg());
}
pub fn selectionTableFor(comptime F: type, fixed: []const F, main: []const F, sink: anytype) void {
    const C = A.memory.load_store_v1.selection;
    sink.emit(.selection, C.tupleFor(F, fixed, 0), main[0].neg());
    sink.emit(.selection, C.tupleFor(F, fixed, 1), main[1].neg());
}
pub fn keccakBridgeFor(comptime F: type, fixed: []const F, main: []const F, sink: anytype) void {
    const C = A.crypto.keccak.word16_bridge;
    sink.emit(.owner, C.equations.ownerTuple(F, main), main[0].mul(fixed[4]).neg());
    for (C.layout.U16) |c| sink.emit(.range16, [1]F{main[c]}, F.one());
    for (C.layout.U8) |c| sink.emit(.range8, [1]F{main[c]}, F.one());
}
pub fn secpBridgeFor(comptime F: type, kind: A.crypto.secp256k1.word16_bridge.types.Kind, fixed: []const F, main: []const F, sink: anytype) void {
    const C = A.crypto.secp256k1.word16_bridge;
    sink.emit(.owner, C.equations.ownerTuple(F, kind, main), main[0].mul(fixed[4]).neg());
    for (C.layout.U16) |c| sink.emit(.range16, [1]F{main[c]}, F.one());
    for (C.layout.U8) |c| sink.emit(.range8, [1]F{main[c]}, F.one());
}
