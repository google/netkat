# Manager-Handle Pattern

Our code makes heavy use of a manager-handle pattern that we describe and
motivate here, using `packet_set.h` as a running example.

The underlying technique is commonly known as "hash-consing" or "interning", and
also makes use of the "flyweight" and "arena allocation" patterns.

## The Pattern

Instead of defining a single class `PacketSet`, `packet_set.h` defines two
classes:

*   a "handle" class `PacketSetHandle`
*   a "manager" class `PacketSetManager`

(In general, we have a file `foo.h` declaring classes `FooHandle` and
`FooManager` that together provide the functionality of what might typically be
a single class `Foo`.)

To a first approximation, think of a `PacketSetHandle` as a stable reference to
an immutable `PacketSet` object that is owned by the manager class. Without the
help of the manager, handles can be hashed and compared but are otherwise opaque
blackboxes. To do anything nontrivial with handles, such as constructing one,
combining them, or inspecting the underlying sets, one must call methods on the
manager class, which acts as an arena allocator that owns all memory associated
with the handles.

For example: ``` // We need a manager to construct handles. PacketSetManager
manager; PacketSetHandle a = manager.EmptySet() PacketSetHandle b =
manager.Match("src_mac", 0xFF'FF'FF'FF);

// Handles can be compared and hashed without the help of the manager, // but
that's about it. CHECK(a != b); absl::flat_hash_map<PacketSetHandle> ab_set{a,
b};

// To do interesting things with the handles, we need the manager.
PacketSetHandle c = manager.And(a, b); // The set union of `a` and `b`.
PacketSetHandle not_c = manager.Not(c); // The set complement of `c`. if
(manager.Contains(c, packet)) { CHECK(!manager.Contains(not_c, packet)); } else
{ CHECK(manager.Contains(not_c, packet)); } ```

## Motivation for Using the Pattern

We use the pattern to achieve vastly improved computational and memory
efficiency. Some of these efficiency gains are obvious, but the full story is
subtle.

### The Obvious

Starting from the obvious, handles are cheap to copy, store, hash, and compare
(whereas doing the same for large sets directly would be expensive). In memory,
a handle is just a 32-bit integer, no matter the size of the set, whereas a
direct set representation would have a memory footprint that grows with the size
of the set.

We would get similar benefits by using `const PacketSet *` directly as a handle,
but that would require that we never invalidate pointers, and would also take
twice as much memory.

### The Subtle: Canonicity and Hash-consing

Internally, the `PacketSetManager` represents all sets using a single, shared,
directed acyclic graph (DAG) encoding, with each node representing a set. The
manager employs *hash-consing* -- a generic technique for sharing structurally
identical, immutable data -- to the DAG nodes: when a new DAG node is to be
created, a hash of its contents is computed. This hash is then used to look up
the node in a "unique table" owned by the manager. If a structurally identical
node already exists, a handle to the existing one is returned, preventing the
allocation of redundant memory. As a result, all sets can share a single,
compressed memory representation without redundancy.

A key benefit of this approach is that it makes equality checking a simple and
fast pointer comparison, as any two structurally equal objects will occupy the
same memory location.

But it gets better!

The data structure we use is *canonical* in the following sense: each set has a
unique DAG representation. Thus, semantically equal sets are always represented
by structurally equal nodes, which occupy the same memory location thanks to
hash-coning. Thus, checking semantic set equality is just a pointer
comparison -- O(1) instead of O(size of set)!

### The Critical: Memoization

A critical optimization for BDD-like data structures such as `PacketSet` is
memoization, which reduces the asymptotic complexity of many binary set
operations such as set union from exponential to polynomial.

At a high-level, this is because such operations are implemented by recursively
traversing the two input DAGs along each root-to-leaf path, and there can be
O(2^k) such paths for a DAG of k nodes. But the number of recursive subproblems
is no more than O(k^2), one for each pair of nodes, and so the naive recursion
can be sped up from O(2^k) to (k^2) by memoizing the subproblem results and
avoiding recomputation.

### Summary of Benefits

*   Light representation: Since `PacketSetHandle`s are simply integers in
    memory, they are cheap to store, copy, compare, and hash.
*   Canonicity: Semantically identical `PacketSetHandle` are represented by the
    same handle, making semantic `PacketSetHandle` comparison O(1) (just
    comparing two integers)!
*   Memory efficiency: The graph structures used to encode packet sets are
    maximally shared across all sets, avoiding redundant copies of isomorphic
    subgraphs.
*   Cache friendliness: Storing all data in contiguous arrays within the manager
    improves data locality and thus cache utilization.
*   Memoization: Thanks to canonicity and lightness of representation,
    computations on `PacketSetHandle`s can be memoized efficiently in the
    manager object. For example, a binary function of type PacketSetHandle,
    PacketSetHandle -> PacketSetHandle can be memoized as a lookup table of type
    (int, int) -> int. Such memoization reduces the asymptotic complexity of
    important operations from exponential to polynomial.

## Downsides and Subtleties When Using the Pattern

We summarize the most important downsides of using the manager-handle pattern:

*   Code complexity: The resulting APIs are split across two classes, which is
    less readable and ergonomic.
*   Undefined behavior: Handles are implicitly associated with the manager
    object that created them. Using a handle with a different manager object is
    undefined behavior.
