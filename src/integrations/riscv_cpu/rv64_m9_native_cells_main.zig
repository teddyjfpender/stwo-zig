//! Root for `rv64-m9-native-cells` (build_m9_native_cells.zig). Stream m9-native-cells.
pub fn main() !void {
    return @import("word16_global_execution/services/native_gkr/m9_cells_main.zig").main();
}
test {
    _ = @import("word16_global_execution/services/native_gkr/m9_cells_main.zig");
}
