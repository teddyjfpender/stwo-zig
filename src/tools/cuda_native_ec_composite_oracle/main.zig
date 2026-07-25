const stwo = @import("stwo_under_test");

pub fn main() !void {
    return stwo.integrations.cairo_cuda.native_ec_oracle_receipt.main();
}
