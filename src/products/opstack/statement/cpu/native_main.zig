//! `stwo-opstack-native`: native CPU production and fresh reception of one OP
//! Stack guest execution, without recursion dependencies. Subcommands are the
//! pipeline's (`describe-candidate`, `plan-candidate`, `produce-candidate`,
//! `verify-candidate`, `verify-prefix-candidate`); `--security-profile`
//! selects the native PCS profile.
pub fn main() !void {
    try @import("opstack_cpu_component").Pipeline.main();
}
