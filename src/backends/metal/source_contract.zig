//! Backend-owned Objective-C implementation bytes used by source-level
//! architecture assertions outside this package.

pub const runtime = @embedFile("runtime.m");
pub const lifecycle_and_tree = @embedFile("runtime/lifecycle_and_tree.m");
pub const quotients = @embedFile("runtime/quotients.m");
pub const composition = @embedFile("runtime/composition.m");
