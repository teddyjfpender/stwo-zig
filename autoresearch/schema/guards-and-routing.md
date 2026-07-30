# Per-track guards, board routing, and editable paths (TRACKS §8)

Campaign v3 partitions the work into tracks: one board per (frontend, backend)
pair, each with its own basket, era, and scored boundary. Three pieces of
harness machinery were still global and had to follow the partition — the
regression guard portfolio, the diff→board router, and the editable-path set.
This document is the contract for all three.

## 1. Per-group guard registries

`workload_registry.guards` holds **named registries**, and every workload group
names the one bound to it.

```json
"guards": {
  "registries": {
    "native": { "workloads": {…}, "impact_map": {…} },
    "cairo":  { "policy": {…}, "workloads": {…}, "impact_map": {…} },
    "riscv":  { "policy": {…}, "workloads": {…}, "impact_map": {…} }
  },
  "policy": { "budget_upper": 1.05, … }
}
```

```json
"groups": {
  "cairo_cpu": { …, "guard_registry": "cairo" },
  "cuda":      { …, "guard_registry": null,
                    "guard_registry_absent_reason": "…" }
}
```

Guards still execute on the **objective group's own binary** — args are data.
That is precisely why the portfolio has to be per group: the flat portfolio
bound the native AIR `--example` statements to whatever binary was being
scored, which is nonsense for a Cairo or RISC-V objective whose product CLI
cannot even parse them.

| registry | bound to | portfolio |
| --- | --- | --- |
| `native` | `native` (core_cpu), `metal` (core_metal) | the 12 native AIR statements plus the small wide-Fibonacci latency canary |
| `cairo` | `cairo_cpu`, `cairo_metal` | the two committed official statements, `all_opcodes` and `all_builtins` |
| `riscv` | `riscv` | the six `small`-class committed ELF programs (ALU, branch, jump/link, load/store, shift/logic, declared region) |

The Cairo registry is the two committed campaign rows and nothing more: the
rest of the campaign portfolio is host-local (see each group's
`workload_provisioning` block), so it cannot be a guard, and no guard is
invented to hide that.

**Policy resolution.** `guards.policy` is the global fallback; a registry's own
`policy` overrides it key by key. Registries that need it also declare
`wall_clock_cap_seconds` and `command_timeout_seconds` (default 300 s each) —
a Cairo guard proves one statement per cold process and cannot share the native
wall budget. A guard passes when its paired upper CI bound stays at or below
`budget_upper`; a guard whose CI straddles the budget resamples once, then
fails closed.

**Groups with no registry.** `guard_registry: null` requires a
`guard_registry_absent_reason`; validation refuses a silently unguarded track.
`core_cuda` has one (no committed CUDA regression portfolio exists yet) and
`pr6_supremacy` has one (its 18 mandatory cells *are* the regression surface).
Such a run announces the reason rather than passing silently.

**Validation.** Every registry must be non-empty; every impact-map rule must
name guards that exist *in that registry* and a board that exists; every group
must declare `guard_registry`; a registry bound to no group is an error.

A manifest with no `registries` key is the pre-TRACKS-§8 flat portfolio and
resolves unchanged for every group.

## 2. Per-track impact maps

Each registry carries its own `impact_map.rules`, mapping editable-path
prefixes to the guards a diff must exercise. Rules may scope to one `board`, so
a Metal-path rule that spares the CPU board does not spare the Metal board from
its own portfolio.

Selection is **fail-closed** in both directions: a `src/` path that matches no
rule selects *every* guard in the registry, and a rule selecting `"all"` means
that registry's whole portfolio — never another track's.

Generic prover, FRI, PCS, field, crypto, and CPU-backend paths select
everything in every registry: they are under all three products.

## 3. Frontend-aware board auto-routing

`--board` always wins. Without it, the diff picks the two coordinates of a
track independently:

| coordinate | source paths |
| --- | --- |
| frontend `cairo` | `src/frontends/cairo/`, `src/integrations/cairo_cpu/`, `src/integrations/cairo_metal/`, `src/integrations/cairo_cuda/` |
| frontend `riscv` | `src/frontends/riscv/`, `src/integrations/riscv_cpu/`, `src/integrations/riscv_metal/` |
| frontend `native` | `src/integrations/native/`, `src/integrations/native_cuda/` |
| backend `cuda` | `src/backends/cuda/`, `src/integrations/native_cuda/`, `src/integrations/cairo_cuda/` |
| backend `metal` | `src/backends/metal/`, `src/integrations/cairo_metal/`, `src/integrations/riscv_metal/` |

A product integration names **both** coordinates —
`src/integrations/cairo_metal/` is the Cairo frontend on the Metal lane — so
those prefixes appear in both tables. A diff naming no frontend defaults to
`native`; naming no backend defaults to `cpu`. Backends keep the pre-existing
CUDA-over-Metal precedence.

The (frontend, backend) pair resolves to a board through the **manifest's own
group list**, using the board naming convention `<frontend>[_<backend>]`
(`core_cpu`, `core_metal`, `core_cuda`, `cairo_cpu`, `cairo_metal`, `riscv`).
There is no second hand-maintained routing table: a board added to the manifest
is routable the moment it lands.

**Fail-closed cases** — both raise and demand an explicit `--board` rather than
guessing:

- **A diff spanning two frontends.** A submission is scored on exactly one
  track, and no single board can show the effect of a cross-frontend change.
  Routing to "all affected boards" would silently multiply one submission into
  several scored rows.
- **A (frontend, backend) pair the manifest declares no board for** (RISC-V on
  Metal today). Falling back to a neighbouring board would score the change
  somewhere it cannot appear.

## 4. Per-track editable paths

`editable_paths` at the document root is the global set. A group may declare
its own `editable_paths`, which **extend** that set for its track; an entry
whose glob repeats a global glob **overrides** that entry's `min_rung` for the
track. Per-track entries can never re-open a locked path — validation refuses
it, because the locked set is the contract floor.

| track | its own editable paths |
| --- | --- |
| `core_cpu`, `core_metal`, `core_cuda`, `pr6_supremacy` | `src/integrations/native/**` |
| `riscv` | `src/frontends/riscv/**`, `src/integrations/riscv_cpu/**`, `src/integrations/riscv_metal/**` |
| `cairo_cpu` | `src/frontends/cairo/**`, `src/integrations/cairo_cpu/**` |
| `cairo_metal` | `src/frontends/cairo/**`, `src/integrations/cairo_metal/**` |

The point is the scoping, not the widening: a Cairo submission may edit
`src/frontends/cairo/**`, and the identical edit is an out-of-scope **stray**
on a native or RISC-V submission, so its G2 gate fails. The runner resolves the
editable set from the **scored board**; callers that pass no board (the
workflow policy checker, the submitter's locked-path check) get the global set,
exactly as before.

## 5. G3 gates every mechanism-bearing schema

`paired_rounds` computes `mechanism_verified` for every report schema listed in
`STABLE_MECHANISM_FIELDS_BY_SCHEMA` — today `riscv_proof_v2` and
`cairo_proof_v1`. G3 gates all of them from that same table, so a schema whose
telemetry is checked can never have its verdict left ungated. Cairo cannot
promote yet, which is exactly why the gate lands before eligibility flips
rather than after.

## 6. Per-track TASK.md

`stwo-perf task --board <board>` prints a track's brief — state, era, scored
boundary, basket, that track's editable paths, its guard set and impact map,
the pinned oracle, the ladder tiers, and the participate commands — generated
from `MANIFEST.json` and `ledger/epochs.json`. `--write` regenerates the
committed copies (`autoresearch/TASK.md` as the index,
`autoresearch/tasks/TASK.<board>.md` per track); `--check` fails when a
committed brief has drifted from its sources. Output is deterministic: no
timestamps, no host state. The site feed publishes the same document verbatim
as `boards.<board>.task.markdown` (schema/site-feed.md).
