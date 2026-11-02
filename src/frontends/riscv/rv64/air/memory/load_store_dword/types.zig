//! LS-D64 shares the CPU proof's RAM14, OWNER19, U16 and U8 challenges with
//! LS32 (the selection challenge is drawn but unused here). Claims are the
//! four physical ledger shares of this component; it has no selection debt.
const V2 = @import("../load_store_v2/types.zig");
const R = @import("../closed_ram/types.zig");
pub const Q = V2.Q;
pub const M = V2.M;
pub const Challenges = V2.Challenges;
pub const Claims = R.Claims;
