//! Exact production-type boundary for extension statement admission.
//!
//! The identity implementation is structurally generic so its isolated tests
//! do not import prover-heavy base component implementations. Production code
//! crosses this file, whose signatures require the unchanged `RiscVStatement`
//! type explicitly.

const base_statement = @import("../statement.zig");
const artifact = @import("artifact_identity.zig");
const statement = @import("statement.zig");

pub fn canonicalStatement(
    core: *const base_statement.RiscVStatement,
    n_guest: u32,
) statement.Error!statement.ExtensionStatement {
    return statement.ExtensionStatement.canonical(core, n_guest);
}

pub fn validateStatement(
    core: *const base_statement.RiscVStatement,
    extension: *const statement.ExtensionStatement,
) statement.Error!void {
    return extension.validate(core);
}

pub fn statementDigest(
    core: *const base_statement.RiscVStatement,
    extension: *const statement.ExtensionStatement,
) statement.Error!statement.Digest {
    return extension.digest(core);
}

pub fn canonicalArtifact(
    core: *const base_statement.RiscVStatement,
    extension: *const statement.ExtensionStatement,
) artifact.Error!artifact.Identity {
    return artifact.Identity.canonical(core, extension);
}

pub fn validateArtifact(
    core: *const base_statement.RiscVStatement,
    extension: *const statement.ExtensionStatement,
    identity: artifact.Identity,
) artifact.Error!void {
    return identity.validate(core, extension);
}
