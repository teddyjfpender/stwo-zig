# Source packages

The source tree separates proof protocol, backend capabilities, frontend
semantics, backend-specific integrations, and command-line products. Each
package's `package.contract.json` (where present) defines its public Zig
module, dependencies, and focused CI command. The [repository guide](../README.md)
describes product availability and supported workflows; a package compiling
successfully does not by itself qualify a complete proving product.

| Layer | Responsibility | Package guides |
| :--- | :--- | :--- |
| Protocol and proof engine | Backend-independent protocol, proof wire formats, backend contracts, and proving APIs | [Core](core/README.md), [backend contracts](backend/README.md), [prover API](prover_api/README.md), [prover engine](prover/README.md), [proof wire](interop/proof_wire/README.md), [recursion wire](interop/circuit_recursion/README.md) |
| Compute backends | CPU, Metal, and resident CUDA implementations | [CPU](backends/cpu_scalar/README.md), [Metal](backends/metal/README.md), [CUDA](backends/cuda/README.md) |
| Frontends | Trace semantics, statements, and backend-neutral AIR | [Cairo](frontends/cairo/README.md), [circuit recursion](frontends/circuit/README.md), [RISC-V](frontends/riscv/README.md), [SM83](frontends/sm83/README.md) |
| Cairo integrations | Backend-specific Cairo proving | [CPU](integrations/cairo_cpu/README.md), [Metal](integrations/cairo_metal/README.md), [CUDA](integrations/cairo_cuda/README.md) |
| Circuit recursion integrations | Backend-specific circuit proving and aggregation | [CPU](integrations/circuit_cpu/README.md), [Metal](integrations/circuit_metal/README.md), [CUDA](integrations/circuit_cuda/README.md) |
| RISC-V integrations | Backend-specific RISC-V proving | [CPU](integrations/riscv_cpu/README.md), [Metal](integrations/riscv_metal/README.md), [CUDA](integrations/riscv_cuda/README.md) |
| SM83 integrations | Backend-specific SM83 proving | [CPU](integrations/sm83_cpu/README.md), [Metal](integrations/sm83_metal/README.md) |
| Native and service packages | Native examples, Native CUDA adaptation, persistent artifacts, and Metal sessions | [Examples](examples/README.md), [Native CUDA](integrations/native_cuda/README.md), [artifact store](artifact_store/README.md), [Metal session](tools/metal_session/README.md) |
| Recursion products | User-facing leaf wrap, fold, and verification commands | [CPU](products/circuit_recursion_cpu/README.md), [Metal](products/circuit_recursion_metal/README.md) |

Run documented commands from the repository root unless a guide says
otherwise. For an owner-local test, use the exact `ci.command` in that
package's contract. Hardware qualification, historical measurements, and
release status are distinct: consult the linked receipt for a measured result
and the repository product matrix for current availability.

Ordinary `*_test.zig` files live in a subsystem's `tests/` directory.
Standalone test roots remain at package roots where Zig's module-root import
rules require them. See [Contributing](../CONTRIBUTING.md#test-layout) before
moving a test or changing a package boundary.
