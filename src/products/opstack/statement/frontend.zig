//! OP Stack frontend component: guest ABI and public statement. Shared RV64
//! records keep their native owners; nothing here changes AIR or transcript.
pub const guest_abi = @import("frontend/guest_abi.zig");
pub const statement = @import("frontend/statement.zig");
