#!/usr/bin/env python3
"""Generate equivalent S31 and Cairo repeated-square programs for one size."""

import argparse
import json
from pathlib import Path

P = 2**31 - 1
INPUT = [1, 2, 3, 65535]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("rounds", type=int)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 32768:
        parser.error("rounds must be between 1 and 32768")

    root = args.output.resolve()
    cairo = root / "cairo"
    (cairo / "src").mkdir(parents=True, exist_ok=True)
    name = f"square{args.rounds}"
    program = {
        "version": 0,
        "name": name,
        "lanes": 4,
        "input": "x",
        "nodes": [
            {
                "name": "y",
                "op": "repeat_square_add",
                "lhs": "x",
                "constant": 7,
                "rounds": args.rounds,
            }
        ],
        "result": "y",
        "public_abi": "u32x8_input_result",
    }
    (root / f"{name}.s31.json").write_text(json.dumps(program, indent=2) + "\n")

    example = Path(__file__).parent / "examples" / "cairo_square"
    manifest = (example / "Scarb.toml").read_text().replace(
        "s31_square256_cairo", f"s31_{name}_cairo"
    )
    (cairo / "Scarb.toml").write_text(manifest)
    (cairo / "arguments.json").write_bytes((example / "arguments.json").read_bytes())
    source = (example / "src" / "lib.cairo").read_text()
    source = source.split("#[cfg(test)]", 1)[0]
    source = source.replace("square256", name)
    source = source.replace("const ROUNDS: u32 = 256;", f"const ROUNDS: u32 = {args.rounds};")
    (cairo / "src" / "lib.cairo").write_text(source)

    results = INPUT[:]
    for initial in INPUT:
        value = initial
        for _ in range(args.rounds):
            value = (value * value + 7) % P
        results.append(value)
    (root / "public_words.json").write_text(json.dumps(results) + "\n")
    print(f"{name}: public words {results}")


if __name__ == "__main__":
    main()
