//! Resident Metal recipes required by an active Cairo witness closure.

const std = @import("std");
const witness_bundle = @import("stwo_cairo_frontend").witness.bundle;

pub const Requirements = struct {
    verify_instruction: bool = false,
    pedersen: bool = false,
    poseidon: bool = false,
    ec_op: bool = false,

    pub fn fromBundle(bundle: witness_bundle.Bundle) Requirements {
        var result = Requirements{};
        for (bundle.entries) |entry| result.include(entry.label);
        return result;
    }

    pub fn fromLabels(labels: []const []const u8) Requirements {
        var result = Requirements{};
        for (labels) |label| result.include(label);
        return result;
    }

    fn include(self: *Requirements, label: []const u8) void {
        if (std.mem.eql(u8, label, "verify_instruction")) {
            self.verify_instruction = true;
        } else if (std.mem.eql(u8, label, "pedersen_aggregator_window_bits_18")) {
            self.pedersen = true;
        } else if (std.mem.eql(u8, label, "poseidon_aggregator")) {
            self.poseidon = true;
        } else if (std.mem.eql(u8, label, "partial_ec_mul_generic")) {
            self.ec_op = true;
        }
    }
};

test "Cairo Metal recipe requirements follow the active witness closure" {
    const fib = Requirements.fromLabels(&.{
        "add_opcode",
        "verify_instruction",
        "memory_address_to_id",
    });
    try std.testing.expect(fib.verify_instruction);
    try std.testing.expect(!fib.pedersen);
    try std.testing.expect(!fib.poseidon);
    try std.testing.expect(!fib.ec_op);

    const builtin_heavy = Requirements.fromLabels(&.{
        "verify_instruction",
        "pedersen_aggregator_window_bits_18",
        "poseidon_aggregator",
        "partial_ec_mul_generic",
    });
    try std.testing.expect(builtin_heavy.verify_instruction);
    try std.testing.expect(builtin_heavy.pedersen);
    try std.testing.expect(builtin_heavy.poseidon);
    try std.testing.expect(builtin_heavy.ec_op);
}
