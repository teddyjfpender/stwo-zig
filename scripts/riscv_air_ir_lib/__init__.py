"""Stable RISC-V AIR interchange contract shared by independent analyses.

`ir` owns the serialized per-row constraint-system schema and parser.
`tables` owns the independently checked lookup-domain schema. Consumers may
evaluate or solve the resulting model independently, but neither consumer owns
or may privately redefine this boundary.
"""
