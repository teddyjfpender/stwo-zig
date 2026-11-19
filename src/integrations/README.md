# Backend integrations

Integrations bind a frontend's AIR and witness interfaces to a concrete
backend. They own the corresponding proving adapters and execution plans.
Product command lines and input protocols live in [products](../products/README.md).

| Family | Public package guides |
| --- | --- |
| Cairo | [CPU](cairo_cpu/README.md), [CUDA](cairo_cuda/README.md), [Metal](cairo_metal/README.md) |
| Circuit recursion | [CPU](circuit_cpu/README.md), [CUDA](circuit_cuda/README.md), [Metal](circuit_metal/README.md) |
| Native | [Shared transaction helpers](native/README.md), [CUDA](native_cuda/README.md) |
| RISC-V | [CPU](riscv_cpu/README.md), [CUDA](riscv_cuda/README.md), [Metal](riscv_metal/README.md), [shared RV64 block pipeline](riscv_cpu/rv64_pipeline/README.md) |
| SM83 | [CPU](sm83_cpu/README.md), [Metal](sm83_metal/README.md) |

Each package guide names the module to import and its supported entry points.
