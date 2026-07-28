"""ISA-derived operand-class enumeration for the RV32IM proof frontend.

`classes` owns the enumeration and the class predicates, `encoding` the
RV32IM encoders the case bodies are assembled with, `session` the RVFI-DII
transport that lets the pinned Sail model execute a case, `emit` the
generator of the committed Zig corpus, and `audit` the coverage measurement
of what the existing test corpus touches.
"""
