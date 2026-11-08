# Benchmark publication

`bench/` is the presentation boundary for committed stwo-zig performance
evidence. Raw reports, deltas, and proof bundles remain immutable under
`vectors/reports/benchmark_history/`; the site contains only a deterministic,
bounded projection of that archive.

## Layout

```text
bench/
├── README.md
└── site/
    ├── index.html            # Authored semantic shell
    ├── assets/
    │   ├── app.js            # Dependency-free presentation logic
    │   ├── responsive.css    # Narrow viewport adaptations
    │   └── styles.css        # Fixed-viewport dark interface
    └── data/
        └── catalog.json      # Generated, reviewable publication catalog
```

## Evidence contract

A run is publishable only when it carries all of the following:

- a 40-character clean measurement commit;
- an offset-aware ISO-8601 capture time;
- complete machine, OS, GPU, and toolchain identity;
- CPU/SIMD and Metal proof parity for every row;
- successful verification by the pinned Rust Stwo oracle;
- separately identified outer-process RSS and governed request-batch resource
  telemetry (physical footprint, energy, instructions, cycles, and proof bytes)
  when the producing report supports it;
- content hashes that agree with the immutable history index.

Historical runs that predate this contract remain in the archive. The catalog
records them under `excluded_runs` with explicit reasons and never upgrades them
into formal performance evidence.

The measurement commit is distinct from the commit that deploys the site.
Publishing a benchmark never rewrites its source identity.

History deltas are claims only when the archived delta says the report contracts
are compatible. A suite or resource-contract transition remains published with
`status: incomparable`; the site may show an observational same-suite change,
but it must not present that observation as judged promotion evidence.

## Commands

```sh
python3 scripts/bench/benchmark_pages.py
python3 scripts/bench/benchmark_pages.py --validate
python3 -m http.server 8000 --directory bench/site
```

The first command regenerates only `site/data/catalog.json`. HTML, CSS, and
JavaScript are authored assets and are validated separately. Actions publishes
the complete site as a 30-day artifact on relevant `main` updates and checks
nightly for new benchmark or site commits. Pull requests validate the catalog
but never publish or deploy it; the live site changes only after the evidence
reaches `main`.

Live GitHub Pages deployment is additionally enabled when the repository has a
Pages-capable plan and the repository variable `BENCHMARK_PAGES_ENABLED` is
`true`. Artifact publication remains the fail-safe source of the exact
deployable site when Pages is unavailable.
