# Compute backends

Backends implement field, transform, polynomial, commitment and runtime
operations against the [backend contracts](../waist/backend/README.md).
Frontend semantics stay with the frontend. Integration packages assemble
a frontend with a concrete backend.

| Package | Public entry point |
| --- | --- |
| [CPU scalar and SIMD](cpu_scalar/README.md) | `stwo_cpu_backend` |
| [Apple Metal](metal/README.md) | `stwo_metal_backend` |
| [Metal sessions](metal/session/README.md) | `stwo_metal_session` |
| [NVIDIA CUDA](cuda/README.md) | `stwo_cuda_backend` |

Each package guide documents its supported operations, resources and focused
tests. See the [product matrix](../../README.md#product-support) for availability.
