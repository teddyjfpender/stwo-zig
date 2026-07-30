//! Explicit optional backend capabilities.
//!
//! A backend must publish one value of this type. A `true` bit is a contract:
//! the corresponding operation family is present with the signature checked
//! by `assertBackend`. A `false` bit is also a contract: the operation names
//! must be absent so a no-op placeholder cannot masquerade as an implementation.

pub const Set = struct {
    host_batch_inverse: bool = false,
    fri_folding: bool = false,
    fri_multi_fold: bool = false,

    pub fn validate(comptime self: Set) void {
        if (self.fri_multi_fold and !self.fri_folding) {
            @compileError("`fri_multi_fold` requires `fri_folding`.");
        }
    }
};

pub fn declared(comptime B: type) Set {
    if (!@hasDecl(B, "capabilities")) {
        @compileError("Backend must declare `pub const capabilities: backend.Capabilities`.");
    }
    if (@TypeOf(B.capabilities) != Set) {
        @compileError("Backend `capabilities` must have type `backend.Capabilities`.");
    }
    B.capabilities.validate();
    return B.capabilities;
}
