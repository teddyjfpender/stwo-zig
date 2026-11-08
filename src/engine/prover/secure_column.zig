//! Compatibility aliases for the backend-neutral secure-column representation.

const shared = @import("stwo_backend_contracts").secure_column;

pub const SecureColumnByCoords = shared.SecureColumnByCoords;
pub const SecureColumnByCoordsGeneric = shared.SecureColumnByCoordsGeneric;

pub const SecureColumnByCoordsFor = shared.SecureColumnByCoordsFor;
