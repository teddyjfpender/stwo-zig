//! Native-width projection of the original circuit lookup tuples.
//! Scalar/OODS authority and lane-major GKR storage are unchanged.
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const Scalar = @import("stwo_circuit_cpu_integration").om31.witness.Elements;
const C = circuit.witness.components;
const T = circuit.witness.trace;
const m31 = core.fields.m31;
const wide = core.fields.packed_om31;

pub const LANES = m31.PACK_WIDTH;
pub const Rows = [LANES][T.RawLookupRows.MAX_LOOKUPS]C.Lookup;
pub const Elements = struct {
    z: wide.PackedOM31,
    powers: [C.MAX_TUPLE]wide.PackedOM31,

    pub fn init(scalar: *const Scalar) Elements {
        var out: Elements = .{ .z = wide.splat(scalar.z), .powers = undefined };
        for (&out.powers, scalar.powers) |*lane_power, value| lane_power.* = wide.splat(value);
        return out;
    }

    pub fn combine(self: *const Elements, rows: *const Rows, lookup: usize) !wide.PackedOM31 {
        if (lookup >= T.RawLookupRows.MAX_LOOKUPS) return error.OuterGkrTupleShape;
        const len = rows[0][lookup].len;
        if (len > C.MAX_TUPLE) return error.OuterGkrTupleShape;
        for (rows) |row| if (row[lookup].len != len) return error.OuterGkrTupleShape;
        if (len == 0) return self.z.neg();
        var values: [LANES]m31.M31 = undefined;
        inline for (0..LANES) |r| values[r] = rows[r][lookup].tuple[0];
        var result = wide.PackedOM31.fromBase(m31.loadPacked(&values));
        for (1..len) |c| {
            inline for (0..LANES) |r| values[r] = rows[r][lookup].tuple[c];
            const base = m31.loadPacked(&values);
            if (@reduce(.Or, base != @as(m31.PackedM31, @splat(0))))
                result = result.add(@call(.always_inline, wide.PackedOM31.mulBase, .{ self.powers[c], base }));
        }
        return result.sub(self.z);
    }
};
