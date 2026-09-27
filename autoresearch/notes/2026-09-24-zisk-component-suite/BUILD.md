# Reproduction

Use the two commit pins in CATALOG.md under the checkout paths in the build scripts.
Host dependencies: Zig 0.15.2, Homebrew GMP/libomp, Rust/Cargo, Python 3.
The FRI/protocol build also uses nlohmann/json 3.11.3, retained with its checksum
under dependencies/. Rust dependencies are pinned by rust-peer/Cargo.lock.

Every build/run script acquires the repository serialization lock. Run phases in
sequence, on AC power. Copy the note directory before repeating if preserving the
original results; runners overwrite their respective phase's JSON files.

```sh
python3 autoresearch/notes/2026-09-24-zisk-component-suite/build_hashes.py
python3 autoresearch/notes/2026-09-24-zisk-component-suite/run.py
python3 autoresearch/notes/2026-09-24-zisk-component-suite/build_stages.py
python3 autoresearch/notes/2026-09-24-zisk-component-suite/run_stages.py
python3 autoresearch/notes/2026-09-24-zisk-component-suite/build_more.py
python3 autoresearch/notes/2026-09-24-zisk-component-suite/run_more.py
python3 autoresearch/notes/2026-09-24-zisk-component-suite/build_primitives.py
python3 autoresearch/notes/2026-09-24-zisk-component-suite/run_primitives.py
python3 autoresearch/notes/2026-09-24-zisk-component-suite/build_fri.py
python3 autoresearch/notes/2026-09-24-zisk-component-suite/run_fri.py
python3 autoresearch/notes/2026-09-24-zisk-component-suite/build_protocol.py
python3 autoresearch/notes/2026-09-24-zisk-component-suite/run_protocol.py
```

Timing boundaries, field/protocol differences and outstanding stages are in README.md
and CATALOG.md. No aggregate score is meaningful across these heterogeneous cases.
The first phase includes one per-batch peer lookup-counter allocation even for hash
cases; at >=100ms calibrated batches that overhead is amortized, not excluded.
For a future isolated hash-only campaign remove it in both the documented boundary
and source snapshot; do not silently relabel these retained measurements.

The per-phase qualification file, rather than the mere existence of a results JSON,
is the completion marker. A runner interrupted by loss of power may leave partial
results without the qualification file. Never promote those to accepted results.

A separately labelled battery protocol run is available via `run_protocol.py
--allow-battery` (one command line). It writes to `battery-protocol/`, rejects
power-source transitions during the run, and preserves the default AC requirement.
`summarize.py` keeps those four cases separate from the 51 AC cases.
