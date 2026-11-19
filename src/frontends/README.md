# Frontends

Frontends own machine or circuit semantics, AIR constraints, and witness
construction. Use the named package module. Its owner guide describes the
public API and the appropriate semantic checks.

| Frontend | Root module |
| --- | --- |
| [Cairo](cairo/README.md) | `stwo_cairo_frontend` |
| [Circuit recursion](circuit/README.md) | `stwo_circuit_frontend` |
| [RISC-V](riscv/README.md) | `stwo_riscv_frontend` with separate [RV32](riscv/rv32/README.md) and [RV64](riscv/rv64/README.md) packages |
| [SM83](sm83/README.md) | `stwo_sm83_frontend` |

[Integrations](../integrations/README.md) own backend-specific assembly.
[Products](../products/README.md) own complete user-facing workflows.
