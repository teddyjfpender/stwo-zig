"""Stable contracts behind the RISC-V differential-equivalence command.

`contract` owns the canonical retirement-trace wire format.
`rvfi` owns RVFI-DII v1 framing and connection mechanics.
`sail_identity` verifies the pinned Sail executable against the formal profile.
The executable controller composes these contracts with ELF execution and
Spike comparison; library consumers depend on these modules, never the command.
"""
