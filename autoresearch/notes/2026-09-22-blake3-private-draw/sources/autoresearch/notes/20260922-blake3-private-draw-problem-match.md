# Private state into ordered draws

Exact graph-composition transfer: extend the existing ordered retry builder with
an optional authenticated state producer. Each attempt routes that producer into
the native draw frame using the shared frame witness. Sum actual source-use
counts across attempts; never publish the state bytes in trusted columns.
Keep counters, full-block rejection and scalar consumption unchanged. Reject
producer namespaces overlapping any draw or challenge component. O(attempts)
additional routed frames. No new AIR or cryptographic parameters.

Validation: compare private/live versus placeholder/trusted fixed columns, native
challenge values and summed producer counts. Keep existing public draw proof
passing. A combined producer-to-draw STARK remains the next integration gate.
