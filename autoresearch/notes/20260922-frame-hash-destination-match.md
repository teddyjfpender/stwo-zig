# Routed-frame integration of caller-owned hash destinations

Source inspection: private hash wrapping already transfers G/XOR ownership. The
routed-frame adapter allocates through a returned arena, causing the hash plan and
wire workspace to share that arena's retention lifetime. This is the useful first
integration boundary for prepareInto.

Transfer: build frame shape with backing-owned temporary storage; reserve exact
G/XOR/boundary slices in the frame arena; call prepareInto with backing scratch and
those final slices. The temporary shape is released on all paths. Live witnesses
retain only final row buffers at this boundary. Trusted preprocessing continues
through its independent existing path. Binding/routing construction and removal
of private input boundaries remain unchanged. No new row equations or hash plan.

Qualification: focused routed-frame ownership/partial-allocation test plus native
proof/codec/independent verifier. Shape still builds twice on the live path (caller
reservation and kernel admission); no graph reuse or timing win is claimed.
