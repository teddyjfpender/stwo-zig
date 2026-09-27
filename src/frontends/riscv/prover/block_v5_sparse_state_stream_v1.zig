//! Fallible streaming adapter for the existing full-width sparse BLAKE3 tree.
//! Traversal/default/leaf/node semantics are reused unchanged; no leaf array.
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const topology = @import("../air/memory_commitment/byte_tree_topology.zig");

/// `source.next() !?tree.Leaf` must return a strictly increasing sparse image.
/// Both source errors and malformed order are propagated before a root escapes.
pub fn root(source: anytype, maximum_leaves: u64) !tree.Digest {
    const Cursor = struct {
        input: @TypeOf(source),
        current: ?tree.Leaf = null,
        previous: ?u32 = null,
        count: u64 = 0,
        limit: u64,
        failure: ?anyerror = null,

        fn advance(self: *@This()) void {
            self.current = null;
            const leaf = self.input.next() catch |err| {
                self.failure = err;
                return;
            };
            if (leaf) |value| {
                if (self.count >= self.limit or value.index >= tree.MEMORY_WORD_LIMIT or
                    (self.previous != null and value.index <= self.previous.?))
                {
                    self.failure = error.InvalidV5SparseStateStream;
                    return;
                }
                self.count += 1;
                self.previous = value.index;
                self.current = value;
            }
        }
        pub fn consume(self: *@This()) tree.Leaf {
            const value = self.current.?;
            self.advance();
            return value;
        }
    };
    var cursor = Cursor{ .input = source, .limit = maximum_leaves };
    cursor.advance();
    const hasher = tree.TreeHasher.init(.memory);
    const result = topology.root(&cursor, 0, 0, tree.ADDRESS_LIMIT, &hasher);
    if (cursor.failure) |err| return err;
    if (cursor.current != null) return error.InvalidV5SparseStateStream;
    return result;
}
