//! Shared Poseidon call data; contains no trace materializer.
pub const WIDTH = @import("poseidon2_layout.zig").WIDTH;

pub const Call = struct {
    input: [WIDTH]u32,
    wide: bool = false,
    io: bool = false,
    /// Narrow output already carried by the Merkle witness. Interaction
    /// generation may use it instead of recomputing 426 main-trace
    /// temporaries. Only the input and one-lane narrow-output relations have
    /// nonzero multiplicity in this mode; the Poseidon lookup AIR still binds
    /// them to the separately committed permutation row and rejects any
    /// disagreement.
    narrow_output: ?u32 = null,

    pub fn narrow(left: u32, right: u32) Call {
        var input = [_]u32{0} ** WIDTH;
        input[0] = left;
        input[1] = right;
        return .{ .input = input };
    }

    pub fn narrowWithOutput(left: u32, right: u32, output_value: u32) Call {
        var call = narrow(left, right);
        call.narrow_output = output_value;
        return call;
    }
};
