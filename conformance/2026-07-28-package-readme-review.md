# Package README review

**Status:** PASS  
**Review date:** 2026-07-28  
**Scope:** all 18 directories containing `package.contract.json`

This record covers the creation and two independent reviews of the first-party
package owner guides. It is documentation evidence, not a substitute for
package tests or product release gates.

## Acceptance criteria

Every package README must:

1. identify the package version, architectural layer, owner, public module, and
   focused CI host;
2. explain responsibilities, non-responsibilities, and its place in the
   dependency graph;
3. describe every name in the contractual public API surface;
4. list every direct first-party dependency;
5. show a real import or call shape derived from current source;
6. distinguish build, test, and run behavior, including library-only,
   compile-only, device-only, staged, and released states;
7. include the exact owner-local CI command from `package.contract.json`;
8. state its signature and behavioral invariant anchors;
9. give maintainers a package-specific change checklist;
10. link to relevant packages, product guidance, and conformance authority; and
11. use valid CommonMark structure and a Mermaid architecture diagram.

`scripts/check_package_workspace.py` now enforces the objective parts of this
contract: metadata, module import, dependencies, API names, exact command,
required sections, diagram presence, heading hierarchy, minimum substantive
length, balanced fences, and resolvable local links.

## Review 1: technical accuracy

The first review compared every guide against:

- its `package.contract.json`, `build.zig.zon`, and owner-local `build.zig`;
- the complete top-level export list in `mod.zig`;
- representative public function signatures and ownership methods;
- root product descriptors and support states; and
- the source authority and release documents linked by the guide.

All 18 exact owner-local commands were then executed from the repository root.
All passed. This review found and corrected documentation defects in six
examples: RISC-V runner arguments/lifetime, the generic Cairo prover call,
proof-consuming Native verification, Metal-session request ownership, Native
CUDA admission naming, and the Cairo CUDA development compiler entry point.

## Review 2: editorial and Markdown quality

The second review was performed after the technical corrections. It checked:

- one descriptive H1 and a non-skipping heading hierarchy;
- blank-line semantics around headings and tables;
- balanced, language-labelled Zig, shell, and Mermaid fences;
- meaningful link text and resolution of every local path and anchor;
- consistent package, product-state, ownership, and fail-closed terminology;
- readable paragraph/list structure and package-specific rather than generic
  guidance; and
- discoverability from the root README.

The semantic/link review passed for every guide. `git diff --check` also passed,
with no trailing whitespace or patch-format defects.

## Per-package record

| Package guide | Technical review | Editorial review | Package-specific focus |
| :--- | :---: | :---: | :--- |
| [`stwo_core`](../src/core/README.md) | PASS | PASS | Dependency-free protocol/verifier boundary |
| [`stwo_backend_contracts`](../src/backend/README.md) | PASS | PASS | Truthful compile-time capabilities |
| [`stwo_prover_api`](../src/prover_api/README.md) | PASS | PASS | Stable ownership and transaction signatures |
| [`stwo_prover_engine`](../src/prover/README.md) | PASS | PASS | Generic proving implementation |
| [`stwo_proof_wire`](../src/interop/proof_wire/README.md) | PASS | PASS | Codec versus statement/security boundary |
| [`stwo_cpu_backend`](../src/backends/cpu_scalar/README.md) | PASS | PASS | Host slices, thread pool, no fallback role |
| [`stwo_metal_backend`](../src/backends/metal/README.md) | PASS | PASS | Runtime identity and no CPU dependency |
| [`stwo_cuda_backend`](../src/backends/cuda/README.md) | PASS | PASS | Resident, strict-AOT, staged status |
| [`stwo_riscv_frontend`](../src/frontends/riscv/README.md) | PASS | PASS | Sail authority and backend neutrality |
| [`stwo_cairo_frontend`](../src/frontends/cairo/README.md) | PASS | PASS | Authenticated semantics and official verification |
| [`stwo_native_examples`](../src/examples/README.md) | PASS | PASS | Seven real prove/verify applications |
| [`stwo_metal_session`](../src/tools/metal_session/README.md) | PASS | PASS | Host-neutral strict v4 service protocol |
| [`stwo_riscv_cpu_integration`](../src/integrations/riscv_cpu/README.md) | PASS | PASS | Released CPU engine binding |
| [`stwo_riscv_metal_integration`](../src/integrations/riscv_metal/README.md) | PASS | PASS | Device-only, fail-closed binding |
| [`stwo_cairo_cpu_integration`](../src/integrations/cairo_cpu/README.md) | PASS | PASS | Official plain-Blake2s CPU transaction |
| [`stwo_cairo_metal_integration`](../src/integrations/cairo_metal/README.md) | PASS | PASS | Authenticated AOT and persistent process |
| [`stwo_native_cuda_integration`](../src/integrations/native_cuda/README.md) | PASS | PASS | Per-application activation boundaries |
| [`stwo_cairo_cuda_integration`](../src/integrations/cairo_cuda/README.md) | PASS | PASS | Development-only lowering boundary |

## Maintenance rule

A package change that alters metadata, dependencies, exports, test commands, or
support state must update its README in the same change. The workspace checker
prevents contract/API/command drift; reviewers remain responsible for checking
that prose, examples, product status, and security claims remain true.
