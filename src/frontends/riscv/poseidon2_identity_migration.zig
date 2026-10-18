//! Historical key migration is deliberately retired. Current recursive keys
//! change the transcript, AIR, and fixed Tree 0; copying old commitments into
//! a new manifest cannot produce a valid admission.

pub fn main() !void {
    return error.PreContractKeyMigrationUnsupported;
}

test "pre-contract recursion key migration is unavailable" {
    try @import("std").testing.expectError(error.PreContractKeyMigrationUnsupported, main());
}
