//! Arithmetic half of the opt-in initial-input packet bridge. All arguments
//! except packet witnesses are existing authenticated graph values. This
//! helper supplies no host constant substitute for any source obligation.
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const arithmetic = frontend.recursion.arithmetic_circuit;
pub const Air = frontend.recursion.air.ethereum_initial_input_packet_v1;
const QM31 = core.fields.qm31.QM31;
const Value = arithmetic.Value;
pub const INPUT_COUNT = Air.INPUT_COUNT;

/// Returns the streamed native-memory subtotal, to be included exactly once
/// by the caller in the existing authenticated memory-sum equality.
pub fn constrainPackets(builder: *arithmetic.Builder, packets: [INPUT_COUNT]Value, z: Value, alpha: Value, header: [4]Value, program: [18]Value) !Value {
    var coefficients: [6]Value = undefined;
    coefficients[0] = z;
    coefficients[1] = alpha;
    const alpha2 = try builder.mul(alpha, alpha);
    coefficients[2] = try builder.mul(alpha2, alpha);
    for (3..6) |i| coefficients[i] = try builder.mul(coefficients[i - 1], alpha);
    for (coefficients, 0..) |expected, slot| try equal(builder, try join(builder, packets[slot * 4 ..][0..4].*), expected);
    for (header, 0..) |expected, i| try equal(builder, packets[Air.lane.HEADER_SLOT * 4 + i], expected);
    for (program, 0..) |expected, i| try equal(builder, packets[Air.lane.PROGRAM_FIRST_SLOT * 4 + i], expected);
    for (INPUT_COUNT - 2..INPUT_COUNT) |i| try equal(builder, packets[i], Value.zero());
    return join(builder, packets[Air.lane.SUM_SLOT * 4 ..][0..4].*);
}
fn equal(builder: *arithmetic.Builder, actual: Value, expected: Value) !void {
    _ = try builder.markOutput(try builder.sub(actual, expected));
}
pub fn join(builder: *arithmetic.Builder, limbs: [4]Value) !Value {
    var value = Value.zero();
    for (limbs, 0..) |limb, i| {
        var basis = [_]u32{0} ** 4;
        basis[i] = 1;
        value = try builder.add(value, try builder.mul(limb, Value.fromSecure(QM31.fromU32Unchecked(basis[0], basis[1], basis[2], basis[3]))));
    }
    return value;
}

/// Witness serialization only. The same values must populate the lane and
/// bridge; constrainPackets authenticates them against existing graph inputs.
pub fn witnessWords(z: QM31, alpha: QM31, header: [4]core.fields.m31.M31, subtotal: QM31, program: [18]core.fields.m31.M31) [INPUT_COUNT]core.fields.m31.M31 {
    const M31 = core.fields.m31.M31;
    var words = [_]M31{M31.zero()} ** INPUT_COUNT;
    words[0..4].* = z.toM31Array();
    words[4..8].* = alpha.toM31Array();
    var power = alpha.mul(alpha);
    for (2..6) |slot| {
        power = power.mul(alpha);
        words[slot * 4 ..][0..4].* = power.toM31Array();
    }
    words[Air.lane.HEADER_SLOT * 4 ..][0..4].* = header;
    words[Air.lane.SUM_SLOT * 4 ..][0..4].* = subtotal.toM31Array();
    words[Air.lane.PROGRAM_FIRST_SLOT * 4 ..][0..18].* = program;
    return words;
}
