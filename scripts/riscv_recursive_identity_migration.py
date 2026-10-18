#!/usr/bin/env python3
"""Retired: recursive keys must be regenerated from the current AIR and transcript.

The pre-contract migration copied commitments across a semantic-identity edit.
Current changes also alter fixed columns and the native Tree-0 binding, so a
historical key cannot be upgraded safely by rewriting its JSON.
"""

raise SystemExit(
    "Pre-contract RISC-V recursive key migration is unsupported; "
    "run the leaf and parent key-setup pipeline from current source."
)
