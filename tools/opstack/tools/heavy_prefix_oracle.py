"""Observe a bounded, deliberately incomplete run of the existing OP oracle.

Only construction is observed: the actual Unicorn object, instruction engine,
service dispatcher and independent arithmetic are unchanged. The existing full
oracle must refuse completion; endpoint registers are execution evidence only.
"""
import argparse
import hashlib
import json
import time
from pathlib import Path
from unittest.mock import patch


def main():
    import unicorn
    from unicorn import riscv_const as R
    from opstack import oracle

    p = argparse.ArgumentParser()
    p.add_argument("config", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--steps", type=int, default=4_000_000)
    args = p.parse_args()
    if not 2 <= args.steps <= 4_000_000:
        raise ValueError("bounded prefix only")
    config = json.loads(args.config.read_text())
    instances = []
    constructor = unicorn.Uc

    def observe(*pos, **kw):
        uc = constructor(*pos, **kw)
        instances.append(uc)
        return uc

    start = time.monotonic_ns()
    with patch.object(unicorn, "Uc", side_effect=observe):
        try:
            oracle.execute(config, args.steps)
        except ValueError as error:
            if str(error) != "output/count mismatch":
                raise
        else:
            raise AssertionError("prefix unexpectedly completed")
    if len(instances) != 1:
        raise AssertionError("one independent Unicorn instance required")
    uc = instances[0]
    halt = int.from_bytes(uc.mem_read(config["symbols"]["halt_flag"], 4), "little")
    if halt:
        raise AssertionError("prefix has halted")
    result = {
        "schema": "op-heavy-conditional-prefix-unicorn/v1",
        "steps": args.steps,
        "initial_pc": 1024,
        "initial_registers": [config["symbols"]["stack_top"] if i == 2 else 0 for i in range(32)],
        "final_pc": uc.reg_read(R.UC_RISCV_REG_PC),
        "final_registers": [uc.reg_read(getattr(R, f"UC_RISCV_REG_X{i}")) for i in range(32)],
        "halt_flag": halt,
        "elapsed_ns": time.monotonic_ns() - start,
        "elf_sha256": config["elf_sha256"],
        "input_sha256": config["input_sha256"],
        "oracle_sha256": hashlib.sha256(Path(oracle.__file__).read_bytes()).hexdigest(),
        "oracle": "Unicorn 2.1.4; constructor observer only",
        "completed": False,
        "proof_verified": False,
        "block_accepted": False,
    }
    encoded = json.dumps(result, indent=2) + "\n"
    with args.output.open("x") as out:
        out.write(encoded)
    print(encoded)


if __name__ == "__main__":
    main()
