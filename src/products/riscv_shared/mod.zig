//! Backend-neutral product shell shared by the focused RISC-V products.
//!
//! Injected into each product as the single named module `riscv_product`, so
//! both products see one instantiation of these types. Mirrors the Cairo
//! precedent (`src/products/cairo/shared/mod.zig`, injected as `cairo_product`).
//!
//! Nothing here names a backend: every product-identifying string arrives
//! through the per-product spec that the product's own binding file supplies.

pub const cli = @import("cli.zig");
