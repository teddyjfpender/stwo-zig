# Cross-package tests

This tree holds test harnesses that assemble multiple packages and fixtures
shared by those harnesses. Owning packages keep their local unit and
contract tests under `src/`.

- [CUDA](cuda/README.md) covers Native product contracts, device smokes,
  runtime checks, Cairo execution, and RV64 proving.
- [Fixtures](fixtures/) contains test-specific inputs shared across runners.
  [Vectors](../vectors/) holds the repository's retained golden and conformance data.

Start with the owning build target or script. [The test layout in Contributing](../CONTRIBUTING.md#test-layout)
explains where to add a test and how to keep its discovery explicit.
