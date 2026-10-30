//! Genuine caller arithmetic/RAM original proofs; global obligations stay open.
const Support = @import("block_v8_caller_ram_owner_test_support.zig");
test "v8 caller RAM original proof Keccak uses no WORD sidecar" {
    try Support.run(.keccak);
}
test "v8 caller RAM original proof SHA uses no WORD sidecar" {
    try Support.run(.sha);
}
test "v8 caller RAM original proof recovery uses no WORD sidecar" {
    try Support.run(.recovery);
}

test "v8 caller RAM complete projection Keccak closes internal arithmetic" {
    try Support.runComplete(.keccak);
}
test "v8 caller RAM complete projection SHA closes internal arithmetic" {
    try Support.runComplete(.sha);
}
test "v8 caller RAM complete projection recovery closes internal arithmetic" {
    try Support.runComplete(.recovery);
}
