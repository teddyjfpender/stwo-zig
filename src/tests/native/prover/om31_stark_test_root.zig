//! Field-selected full-STARK qualification plus retained QM31 integration gates.
test {
    _ = @import("om31_stark_test.zig");
    _ = @import("om31_accumulation_test.zig");
    _ = @import("prove_test.zig");
    _ = @import("om31_wire_test.zig");
}
